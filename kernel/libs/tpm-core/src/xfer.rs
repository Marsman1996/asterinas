use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::chip::lemma_be32_forms_agree;
use crate::cmd::{
    CC_CONTEXT_LOAD, CC_CONTEXT_SAVE, CC_FLUSH_CONTEXT, CC_GET_CAPABILITY, CC_GET_RANDOM,
    CC_PCR_EXTEND, CC_PCR_READ, CC_SELF_TEST, CC_SHUTDOWN, CC_STARTUP,
};
#[cfg(verus_keep_ghost)]
use crate::cursor::spec_be32_at;
use crate::msg::TPM_HEADER_LEN;
use crate::phy::TisPhy;
#[cfg(verus_keep_ghost)]
use crate::rewrite::be32_at;
use crate::rewrite::read_be32;
use crate::tis::{TisErr, budget_of};
use crate::tis_core::Tis;

verus! {

// ===========================================================================
// 本层职责
// ===========================================================================
//
// 传输层只管把字节送出去、把字节收回来，它对报文内容一无所知；命令层只管
// 拼装与解析报文，它对总线一无所知。两者之间还剩三件事没人做，本层做这三件：
//
// 1. **命令自述长度与实际缓冲区的一致性**。命令头里的长度字段是后续所有
//    编解码的依据，必须在字节离开本机之前就卡住，而不是等对端报错。
// 2. **返回码提取**。它落在响应头的固定偏移上，取值本身不需要解析报文体，
//    因此放在这里比放进命令层更早、更便宜。
// 3. **可重试返回码的重传**。器件在自检或资源紧张时会要求稍后再来，这类
//    应答不是错误，也不该让上层每个调用点各自处理。
//
// 本层**不做**的事：不解析报文体、不做授权、不碰句柄。这三件都需要知道
// 具体命令的语义，属于更上层。

// ===========================================================================
// 返回码
// ===========================================================================
//
// 取值出自 TPM 2.0 Part 2 的返回码表。这里只列本层需要**据以决策**的几个，
// 其余返回码原样上交，由调用方判断。

pub const RC_SUCCESS: u32 = 0x0000_0000;

/// 警告类返回码的基址。位 11 置位表示「不是失败，是暂时不能办」。
pub const RC_WARN_BASE: u32 = 0x0000_0900;

/// 器件正在自检，被请求的功能尚未就绪。
pub const RC_TESTING: u32 = 0x0000_090A;

/// 器件当前忙，请稍后重发同一条命令。
pub const RC_RETRY: u32 = 0x0000_0922;

/// 器件主动让出，命令未执行。语义上与 [`RC_RETRY`] 同类，但它由器件的调度
/// 策略触发而非资源短缺，重发一次通常就能过。
pub const RC_YIELDED: u32 = 0x0000_0908;

// ===========================================================================
// 重传策略
// ===========================================================================
//
// 退避从一个很短的间隔起步，每轮翻倍，到上限为止。翻倍而不是定间隔，是为了
// 让「器件刚好在下一毫秒就绪」和「器件要忙好几秒」两种情况都不吃亏：前者只
// 多等一个最小间隔，后者的重发次数是对数级而不是线性级。
//
// 次数上限与单次等待上限**都**要有：只限次数，遇上退避封顶后就成了固定间隔
// 的长时间死磕；只限时长，则每次重发都要重新计算已耗时间，而时间域正是本项
// 目刻意回避的东西（见轮询预算的说明）。两个上限一起给，总等待时间的界就是
// 一个常数，不需要读时钟也能说清楚。

/// 首次退避的时长（毫秒）。
pub const RETRY_FIRST_MS: u32 = 20;

/// 单次退避的时长上限（毫秒）。
pub const RETRY_CAP_MS: u32 = 2000;

/// 重传次数上限。取到这个数之后仍是可重试返回码，就把它原样交给调用方——
/// 本层不把「等了很久还是忙」翻译成错误，那是调用方该拿的判断。
pub const RETRY_MAX: u32 = 8;

// ===========================================================================
// 命令时长表
// ===========================================================================
//
// 不同命令的执行时长相差三个数量级：读一个 PCR 是微秒级，生成一对密钥可以
// 到几十秒。用同一个等待预算去等两者，要么慢命令被误判超时，要么快命令的
// 故障要等到很久以后才暴露。
//
// 表里的数字是**上界**，不是期望值，取值宁大勿小：估小了会把正常执行判成
// 超时，那是功能故障；估大了只是故障时多等一会儿。未列出的命令一律取保守
// 默认值。

pub const DURATION_SHORT_MS: u32 = 750;

pub const DURATION_MEDIUM_MS: u32 = 2000;

pub const DURATION_LONG_MS: u32 = 30000;

/// 未列出命令的默认上界。取得很大是有意的：一条本层不认识的命令，本层也就
/// 没有依据说它该多快。
pub const DURATION_DEFAULT_MS: u32 = 120000;

/// 命令码 → 执行时长上界（毫秒）。
///
/// 返回值恒为正，因此 [`budget_of`] 折算出的轮询预算恒不为零。
pub fn duration_ms(cc: u32) -> (r: u32)
    ensures
        r >= 1,
{
    if cc == CC_STARTUP || cc == CC_SHUTDOWN || cc == CC_PCR_READ || cc == CC_PCR_EXTEND || cc
        == CC_GET_CAPABILITY {
        DURATION_SHORT_MS
    } else if cc == CC_CONTEXT_LOAD || cc == CC_CONTEXT_SAVE || cc == CC_FLUSH_CONTEXT {
        // 上下文换入换出要动器件内部存储，比纯寄存器读写慢一档。
        DURATION_SHORT_MS
    } else if cc == CC_GET_RANDOM {
        // 熵池不足时器件会等待累积，时长不由命令本身决定。
        DURATION_MEDIUM_MS
    } else if cc == CC_SELF_TEST {
        DURATION_LONG_MS
    } else {
        DURATION_DEFAULT_MS
    }
}

/// 命令码 → 等待响应的轮询预算。
pub fn poll_budget(cc: u32) -> (r: u32)
    ensures
        r >= 1,
{
    budget_of(duration_ms(cc))
}

// ===========================================================================
// 错误
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
pub enum XferErr {
    /// 传输层报错。字节没能完整走完一个来回。
    Bus(TisErr),
    /// 命令自身不成立：长度字段与缓冲区对不上。命令一个字节都没有发出。
    BadCommand,
}

// ===========================================================================
// 格式良好性
// ===========================================================================

/// 一条可以发送的命令：长度字段等于调用方声称的长度，且这段字节确实在
/// 缓冲区里。
///
/// 两个条件缺一不可。只查前者，缓冲区可能根本没那么长；只查后者，发出去的
/// 字节数与器件按长度字段预期收到的字节数会对不上，器件将一直等着后半截，
/// 而本端已经在等响应了——双方各等各的，直到超时。
pub open spec fn spec_cmd_wf(cmd: Seq<u8>, len: int) -> bool {
    &&& TPM_HEADER_LEN <= len
    &&& len <= cmd.len()
    &&& spec_be32_at(cmd, 2) == len
}

/// 大端 u32 读取，同时给出两种规约写法下的值。
///
/// 报文头由命令层生成（规约用乘加形式），句柄区由重写层读取（规约用移位或
/// 形式），本层横跨两者，读一次就把两种形式都摆出来，免得每个调用点各自
/// 引一遍桥引理。
pub fn peek_be32(b: &[u8], off: usize) -> (r: u32)
    requires
        off + 4 <= b.len(),
    ensures
        r == spec_be32_at(b@, off as int),
        r == be32_at(b@, off as int),
{
    proof {
        lemma_be32_forms_agree(b@, off as int);
    }
    read_be32(b, off)
}

pub fn cmd_wf(cmd: &[u8], len: usize) -> (r: bool)
    ensures
        r == spec_cmd_wf(cmd@, len as int),
{
    if len < TPM_HEADER_LEN {
        return false;
    }
    if len > cmd.len() {
        return false;
    }
    let d = peek_be32(cmd, 2);
    d as usize == len
}

/// 响应体（报文头之后的部分）不短于 `min_body`。
///
/// 单独列出来是因为它是**解析前的最后一道闸**：解析函数一律以「体长足够」
/// 为前置条件，闸没关上，越界读取就从解析函数的内部实现细节变成了调用方的
/// 责任，而调用方通常忘了。
pub fn body_at_least(n: usize, min_body: usize) -> (r: bool)
    requires
        n >= TPM_HEADER_LEN,
    ensures
        r ==> n - TPM_HEADER_LEN >= min_body,
{
    n - TPM_HEADER_LEN >= min_body
}

// ===========================================================================
// 编排器
// ===========================================================================

pub struct Xfer<P: TisPhy> {
    pub tis: Tis<P>,
    /// 剩余可用的重传次数上限。做成字段而不是常量，是为了让引导阶段（器件
    /// 刚上电、自检未完）与稳态使用同一套代码而取不同的耐心。
    pub retries: u32,
}

impl<P: TisPhy> Xfer<P> {
    pub open spec fn wf(&self) -> bool {
        self.tis.wf()
    }

    /// 可以开始下一条命令：locality 未被持有。
    pub open spec fn idle(&self) -> bool {
        self.tis.quiescent()
    }

    pub fn new(tis: Tis<P>) -> (r: Self)
        ensures
            r.tis == tis,
            r.retries == RETRY_MAX,
    {
        Xfer { tis, retries: RETRY_MAX }
    }

    /// 运行时自检：状态是否满足发起命令的前提。
    ///
    /// 存在的理由是接口边界——本层被一个不带前置条件的接口调用（那个接口的
    /// 签名由更上层的验证需要决定，改不动），而本层的方法有前置条件。差额只
    /// 能在运行时补上：查一次，不满足就直接报错，不让不满足前提的调用继续
    /// 往下走。
    pub fn ready(&self) -> (r: bool)
        ensures
            r ==> self.wf() && self.idle(),
    {
        self.tis.locality < crate::tis::MAX_LOCALITY && !self.tis.held
    }

    // =======================================================================
    // 退避
    // =======================================================================

    /// 等待 `ticks` 个轮询间隔。
    ///
    /// 用轮询间隔的整数倍表示等待时长，而不是接一个睡眠接口：本层不引入
    /// 时间概念，等待的实际长度由物理层的节流实现决定。这条循环的终止性
    /// 因此直接来自计数器。
    fn backoff(&mut self, ticks: u32)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).tis.held == old(self).tis.held,
            final(self).tis.locality == old(self).tis.locality,
            final(self).retries == old(self).retries,
    {
        let mut left = ticks;
        while left > 0
            invariant
                self.wf(),
                self.tis.held == old(self).tis.held,
                self.tis.locality == old(self).tis.locality,
                self.retries == old(self).retries,
            decreases left,
        {
            self.tis.phy.delay();
            left = left - 1;
        }
    }

    // =======================================================================
    // 单次尝试
    // =======================================================================

    /// 发一条命令，收一条响应，并取出返回码。
    ///
    /// 返回码取自响应头的固定偏移，取值不依赖任何报文体解析——响应长度已由
    /// 传输层保证不小于一个报文头，因此这次读取无条件成立。
    fn attempt(&mut self, cmd: &[u8], len: usize, rsp: &mut [u8]) -> (r: Result<
        (usize, u32),
        XferErr,
    >)
        requires
            old(self).wf(),
            old(self).idle(),
            spec_cmd_wf(cmd@, len as int),
            TPM_HEADER_LEN <= old(rsp).len(),
        ensures
            final(self).wf(),
            final(self).idle(),
            final(self).retries == old(self).retries,
            final(rsp).len() == old(rsp).len(),
            r matches Ok((n, rc)) ==> {
                &&& TPM_HEADER_LEN <= n
                &&& n <= final(rsp).len()
                &&& spec_be32_at(final(rsp)@, 2) == n
                &&& rc == spec_be32_at(final(rsp)@, 6)
                &&& rc == be32_at(final(rsp)@, 6)
            },
    {
        let n = match self.tis.transmit(cmd, len, rsp) {
            Ok(v) => v,
            Err(e) => return Err(XferErr::Bus(e)),
        };
        let rc = peek_be32(&*rsp, 6);
        Ok((n, rc))
    }

    // =======================================================================
    // 带重传的一次往返
    // =======================================================================

    /// 值得重发的返回码。
    ///
    /// 自检命令遇到「正在自检」是个例外：这条命令问的**就是**自检状态，
    /// 「还在测」是一个有效答案而非需要规避的应答。把它当作可重试会把一次
    /// 状态查询变成一段阻塞等待，引导阶段尤其不该这样。
    pub fn retryable(rc: u32, cc: u32) -> (r: bool) {
        if rc == RC_RETRY || rc == RC_YIELDED {
            true
        } else if rc == RC_TESTING {
            cc != CC_SELF_TEST
        } else {
            false
        }
    }

    /// 发一条命令，必要时重发，返回响应长度与返回码。
    ///
    /// 三条性质在签名里写死：
    ///
    /// - **命令没通过自检就一个字节都不发**。格式不良的命令在这里被挡下，
    ///   器件永远见不到它。
    /// - **无论走哪条出口，locality 都不再被持有**。这一条由传输层逐次保证，
    ///   重传只是把那个保证串起来——每次尝试都是一次完整的申请与归还，而不是
    ///   握着 locality 循环。多等几毫秒换整段等待期间其他 locality 可用，这笔
    ///   账是划算的。
    /// - **返回码就是响应头里的那个值**。本层不改写、不吞掉、不翻译；重传次数
    ///   耗尽之后仍是可重试返回码的，原样上交。
    ///
    /// 重发是安全的，因为命令缓冲区是只读的：本层拿到的是一个不可变切片，
    /// 从头到尾没有任何一步会修改它，所以第二次发送的字节与第一次逐字节相同。
    /// 若换成收发共用一个缓冲区，这一点就不再成立，重发前必须先恢复原文——
    /// 那是一个容易漏掉且很难在事后察觉的错误，分开两个缓冲区从根上避免了它。
    pub fn run(&mut self, cmd: &[u8], len: usize, rsp: &mut [u8]) -> (r: Result<
        (usize, u32),
        XferErr,
    >)
        requires
            old(self).wf(),
            old(self).idle(),
            TPM_HEADER_LEN <= old(rsp).len(),
        ensures
            final(self).wf(),
            final(self).idle(),
            final(rsp).len() == old(rsp).len(),
            r matches Ok((n, rc)) ==> {
                &&& TPM_HEADER_LEN <= n
                &&& n <= final(rsp).len()
                &&& spec_be32_at(final(rsp)@, 2) == n
                &&& rc == spec_be32_at(final(rsp)@, 6)
                &&& rc == be32_at(final(rsp)@, 6)
            },
    {
        if !cmd_wf(cmd, len) {
            return Err(XferErr::BadCommand);
        }
        // 长度已过闸，命令码所在的四个字节必然在缓冲区内。
        let cc = peek_be32(cmd, 6);

        let cap = budget_of(RETRY_CAP_MS);
        let mut ticks = budget_of(RETRY_FIRST_MS);
        let mut left = self.retries;

        while left > 0
            invariant
                self.wf(),
                self.idle(),
                rsp.len() == old(rsp).len(),
                TPM_HEADER_LEN <= rsp.len(),
                spec_cmd_wf(cmd@, len as int),
            decreases left,
        {
            match self.attempt(cmd, len, rsp) {
                Ok((n, rc)) => {
                    if !Self::retryable(rc, cc) {
                        return Ok((n, rc));
                    }
                },
                Err(e) => return Err(e),
            }

            self.backoff(ticks);
            // 翻倍前先看上限，避免在计数器上做会溢出的乘法。
            if ticks < cap {
                if ticks <= cap - ticks {
                    ticks = ticks + ticks;
                } else {
                    ticks = cap;
                }
            }
            left = left - 1;
        }

        // 次数用尽。最后再发一次，结果不再过滤——「等了这么久还是忙」是一个
        // 需要让调用方看见的事实，把它藏成本层的超时错误，上层就再也分不清
        // 器件是忙还是坏了。
        self.attempt(cmd, len, rsp)
    }
}

} // verus!
