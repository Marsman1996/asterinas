use vstd::prelude::*;
use vstd::array::*;
use vstd::slice::*;

use crate::chip::MSG_MAX;
use crate::cmd::{CAP_TPM_PROPERTIES, CC_GET_CAPABILITY, CC_SELF_TEST, CC_SHUTDOWN, CC_STARTUP,
    SU_CLEAR, SU_STATE};
use crate::cursor::{be16_bytes, be32_bytes};
#[cfg(verus_keep_ghost)]
use crate::cursor::{spec_be16_at, spec_be32_at};
use crate::msg::{ParseError, RC_SUCCESS, ST_NO_SESSIONS, TPM_HEADER_LEN, build_header,
    parse_response};
use crate::phy::TisPhy;
use crate::rsp::parse_tpm_property;
use crate::xfer::{Xfer, XferErr};

verus! {

// ===========================================================================
// 本层职责
// ===========================================================================
//
// 器件从上电到「可以承载正常业务」之间有一段固定序列：宣告本端启动方式、
// 触发自检、问清器件的容量。这段序列的特点是**必须按顺序发生，且只能发生
// 一次**，因此它既不属于传输层（那里没有顺序概念），也不属于会话层（会话
// 本身要等这段序列走完才建立得起来）。单独成层，理由就是这两条。
//
// 这里只用无会话命令。引导阶段还没有可用的会话密钥，握手所需的随机数与
// 摘要能力也未必就绪，硬要给引导命令加授权，等于把「自检是否通过」这个
// 问题的答案，压在「自检若未通过则不可用」的设施上。
//
// 本层不碰句柄，也不产生任何需要释放的资源。这是有意的：引导若在中途失败，
// 调用方直接丢弃整个实例即可，不必先跑一遍清理——而清理路径恰恰是最难写对、
// 又最少被执行到的那类代码。
//
// ---------------------------------------------------------------------------
// 与后续各层的交接
// ---------------------------------------------------------------------------
//
// 传输链路在整个驱动里只有一份，它同一时刻只能被一个上层持有：要么交给
// 无会话的编排路径，要么交给受保护的授权往返。所有权在这里表达了这条约束——
// [`Boot::finish`] 消耗掉 `Boot` 并交出链路，此后引导层的方法再也调不到。
// 换成「持有引用、大家都能用」的写法，「引导只跑一次」就退化成一条注释。

// ===========================================================================
// 返回码
// ===========================================================================

/// 器件尚未初始化，或者反过来——已经初始化过了。
///
/// 它出现在启动命令的响应里时，含义是「这条命令来晚了，器件早已启动」。
/// 引导层把它按成功处理，见 [`Boot::startup`] 的说明。
pub const RC_INITIALIZE: u32 = 0x0000_0100;

/// 自检正在后台进行。
pub const RC_TESTING: u32 = 0x0000_090A;

// ===========================================================================
// 属性标识（TPM 2.0 Part 2，固定属性组）
// ===========================================================================

/// 器件能接收的最长命令。
pub const PT_MAX_COMMAND_SIZE: u32 = 0x0000_011E;

/// 器件能产生的最长响应。
pub const PT_MAX_RESPONSE_SIZE: u32 = 0x0000_011F;

/// 单个对象备份块的最大长度。
pub const PT_MAX_OBJECT_CONTEXT: u32 = 0x0000_0121;

/// 单个会话备份块的最大长度。
pub const PT_MAX_SESSION_CONTEXT: u32 = 0x0000_0122;

// ===========================================================================
// 自检范围
// ===========================================================================

const SELF_TEST_FULL: u8 = 1;
const SELF_TEST_INCREMENTAL: u8 = 0;

// ===========================================================================
// 缓冲区容量
// ===========================================================================

/// 引导命令的最长者：报文头 10 字节 + 能力查询的三个 u32。
pub const BOOT_CMD_MAX: usize = 22;

/// 引导响应的容量。单条属性的应答是报文头 10 + 定长前缀 9 + 一对键值 8 =
/// 27 字节；取 128 留出余量，同时把这块暂存区压得足够小，可以安心放在栈上。
pub const BOOT_RSP_MAX: usize = 128;

// ===========================================================================
// 错误
// ===========================================================================

// 派生集合被内层类型卡住：解析错误只提供了相等性，这里也就只能到相等性为止。
#[derive(PartialEq, Eq, Structural)]
pub enum BootErr {
    /// 宿主提供的密码学接口与本驱动的假设对不上。
    Abi,
    /// 链路不处于可以发起命令的状态。
    NotReady,
    /// 字节没能走完一个来回。
    Bus(XferErr),
    /// 器件给出了非零返回码。
    Rc(u32),
    /// 响应到了，但解析不通过。
    Parse(ParseError),
    /// 器件自述的容量超出本驱动静态预留的空间。
    Capacity,
}

// ===========================================================================
// 器件容量
// ===========================================================================

/// 引导期问出来的四个尺寸。
///
/// 问它们不是为了记录，而是为了**对账**：本驱动的缓冲区都是定长的，尺寸在
/// 编译期就定死了；器件若要求更大的报文，或者产出的备份块比预留空间长，那
/// 是一个必须在引导期就暴露的不匹配。拖到运行期，症状是某条特定命令偶发
/// 截断，与容量二字毫无表面联系。
pub struct Limits {
    pub max_command: u32,
    pub max_response: u32,
    pub max_object_context: u32,
    pub max_session_context: u32,
}

// ===========================================================================
// 引导器
// ===========================================================================

pub struct Boot<P: TisPhy> {
    x: Xfer<P>,
    /// 命令暂存区。私有：本层对报文长度字段的全部保证，都建立在外部改不动
    /// 它之上。
    cbuf: [u8; BOOT_CMD_MAX],
    rbuf: [u8; BOOT_RSP_MAX],
}

impl<P: TisPhy> Boot<P> {
    pub fn new(x: Xfer<P>) -> (r: Self) {
        Boot { x, cbuf: [0u8; BOOT_CMD_MAX], rbuf: [0u8; BOOT_RSP_MAX] }
    }

    /// 交出链路，结束引导阶段。
    pub fn finish(self) -> (r: Xfer<P>) {
        self.x
    }

    // =======================================================================
    // 报文拼装
    // =======================================================================

    /// 写入报文头。
    ///
    /// 长度字段在这里一次性写死，之后不再回填。引导命令的载荷长度全部是编译期
    /// 常量，没有「先写载荷、再看写了多长」的必要——而回填恰恰是长度字段与实际
    /// 字节数走散的唯一入口。
    fn put_header(&mut self, cc: u32, total: usize)
        requires
            TPM_HEADER_LEN <= total,
            total <= BOOT_CMD_MAX,
        ensures
            final(self).x == old(self).x,
            final(self).rbuf@ == old(self).rbuf@,
            final(self).cbuf@.len() == BOOT_CMD_MAX,
            spec_be32_at(final(self).cbuf@, 2) == total as u32,
            spec_be32_at(final(self).cbuf@, 6) == cc,
    {
        let hdr = build_header(ST_NO_SESSIONS, cc, total as u32);
        let mut k: usize = 0;
        while k < TPM_HEADER_LEN
            invariant
                k <= TPM_HEADER_LEN,
                self.cbuf@.len() == BOOT_CMD_MAX,
                hdr@.len() == TPM_HEADER_LEN,
                spec_be32_at(hdr@, 2) == total as u32,
                spec_be32_at(hdr@, 6) == cc,
                forall|j: int| #![trigger self.cbuf@[j]] 0 <= j < k ==> self.cbuf@[j] == hdr@[j],
                self.x == old(self).x,
                self.rbuf@ == old(self).rbuf@,
            decreases TPM_HEADER_LEN - k,
        {
            self.cbuf[k] = hdr[k];
            k += 1;
        }
        proof {
            assert(self.cbuf@[2] == hdr@[2]);
            assert(self.cbuf@[3] == hdr@[3]);
            assert(self.cbuf@[4] == hdr@[4]);
            assert(self.cbuf@[5] == hdr@[5]);
            assert(self.cbuf@[6] == hdr@[6]);
            assert(self.cbuf@[7] == hdr@[7]);
            assert(self.cbuf@[8] == hdr@[8]);
            assert(self.cbuf@[9] == hdr@[9]);
        }
    }

    /// 写一个字节的载荷。
    fn put_u8(&mut self, off: usize, v: u8)
        requires
            TPM_HEADER_LEN <= off,
            off < BOOT_CMD_MAX,
        ensures
            final(self).x == old(self).x,
            final(self).rbuf@ == old(self).rbuf@,
            final(self).cbuf@.len() == BOOT_CMD_MAX,
            final(self).cbuf@[off as int] == v,
            forall|j: int|
                #![trigger final(self).cbuf@[j]]
                0 <= j < BOOT_CMD_MAX && j != off ==> final(self).cbuf@[j] == old(self).cbuf@[j],
    {
        self.cbuf[off] = v;
    }

    /// 写一个大端 u16 载荷。
    fn put_be16(&mut self, off: usize, v: u16)
        requires
            TPM_HEADER_LEN <= off,
            off + 2 <= BOOT_CMD_MAX,
        ensures
            final(self).x == old(self).x,
            final(self).rbuf@ == old(self).rbuf@,
            final(self).cbuf@.len() == BOOT_CMD_MAX,
            spec_be16_at(final(self).cbuf@, off as int) == v,
            forall|j: int|
                #![trigger final(self).cbuf@[j]]
                0 <= j < BOOT_CMD_MAX && (j < off || j >= off + 2) ==> final(self).cbuf@[j]
                    == old(self).cbuf@[j],
    {
        let b = be16_bytes(v);
        self.cbuf[off] = b[0];
        self.cbuf[off + 1] = b[1];
    }

    /// 写一个大端 u32 载荷。
    fn put_be32(&mut self, off: usize, v: u32)
        requires
            TPM_HEADER_LEN <= off,
            off + 4 <= BOOT_CMD_MAX,
        ensures
            final(self).x == old(self).x,
            final(self).rbuf@ == old(self).rbuf@,
            final(self).cbuf@.len() == BOOT_CMD_MAX,
            spec_be32_at(final(self).cbuf@, off as int) == v,
            forall|j: int|
                #![trigger final(self).cbuf@[j]]
                0 <= j < BOOT_CMD_MAX && (j < off || j >= off + 4) ==> final(self).cbuf@[j]
                    == old(self).cbuf@[j],
    {
        let b = be32_bytes(v);
        self.cbuf[off] = b[0];
        self.cbuf[off + 1] = b[1];
        self.cbuf[off + 2] = b[2];
        self.cbuf[off + 3] = b[3];
    }

    // =======================================================================
    // 一次往返
    // =======================================================================

    /// 把已拼好的命令发出去，取回响应长度与返回码。
    ///
    /// 前置条件里那句「长度字段等于 `len`」不是形式上的讲究：链路层会对着这个
    /// 字段决定往总线上推多少字节，字段与实参一旦不符，器件与本端就会各等各的，
    /// 一直等到超时。在这里写成前置条件，等于把这件事交给拼装函数的后置条件去
    /// 保证，而不是寄望于每个调用点自己记得。
    fn exec(&mut self, len: usize) -> (r: Result<(usize, u32), BootErr>)
        requires
            TPM_HEADER_LEN <= len,
            len <= BOOT_CMD_MAX,
            spec_be32_at(old(self).cbuf@, 2) == len as u32,
        ensures
            final(self).cbuf@ == old(self).cbuf@,
            final(self).rbuf@.len() == BOOT_RSP_MAX,
            r matches Ok((n, _rc)) ==> {
                &&& TPM_HEADER_LEN <= n
                &&& n <= BOOT_RSP_MAX
                &&& spec_be32_at(final(self).rbuf@, 2) == n
            },
    {
        // 接口那头不带状态前提，前提只能在这里补。不满足就直接回绝：一条在
        // 错误状态下发出的命令，最好的结果也只是浪费一次往返。
        if !self.x.ready() {
            return Err(BootErr::NotReady);
        }
        match self.x.run(&self.cbuf, len, &mut self.rbuf) {
            Ok((n, rc)) => Ok((n, rc)),
            Err(e) => Err(BootErr::Bus(e)),
        }
    }

    // =======================================================================
    // 启动
    // =======================================================================

    /// 宣告本端的启动方式。
    ///
    /// 「已经启动过了」按成功处理。器件的启动状态由上电周期决定，而本端可能
    /// 是在器件已被更早的一段固件初始化之后才接手的——这种情形下重发一条启动
    /// 命令得到的拒绝，说的是「你要的状态已经成立」，把它当失败会让驱动在一类
    /// 完全正常的平台上直接拒绝加载。
    ///
    /// 反过来，其余任何非零返回码都如实上报，不做二次解释。
    pub fn startup(&mut self, su: u16) -> (r: Result<(), BootErr>)
        requires
            su == SU_CLEAR || su == SU_STATE,
    {
        let total = TPM_HEADER_LEN + 2;
        self.put_header(CC_STARTUP, total);
        self.put_be16(TPM_HEADER_LEN, su);
        match self.exec(total) {
            Ok((_n, rc)) => {
                if rc == RC_SUCCESS || rc == RC_INITIALIZE {
                    Ok(())
                } else {
                    Err(BootErr::Rc(rc))
                }
            },
            Err(e) => Err(e),
        }
    }

    /// 关机。
    ///
    /// 与启动不同，这里不放过任何非零返回码：关机若没成功，器件下次上电会
    /// 认为上一轮是异常断电，进而重置一部分状态。这件事调用方必须知道。
    pub fn shutdown(&mut self, su: u16) -> (r: Result<(), BootErr>)
        requires
            su == SU_CLEAR || su == SU_STATE,
    {
        let total = TPM_HEADER_LEN + 2;
        self.put_header(CC_SHUTDOWN, total);
        self.put_be16(TPM_HEADER_LEN, su);
        match self.exec(total) {
            Ok((_n, rc)) => {
                if rc == RC_SUCCESS {
                    Ok(())
                } else {
                    Err(BootErr::Rc(rc))
                }
            },
            Err(e) => Err(e),
        }
    }

    // =======================================================================
    // 自检
    // =======================================================================

    /// 触发自检。`full` 为真时要求重测全部算法，否则只测尚未测过的部分。
    ///
    /// 「正在测」按成功处理，理由与启动那条不同：这条命令的语义本就是「开始测」
    /// 而非「测完了」，器件回一句还在测，恰恰说明命令生效了。真正的自检结论要
    /// 另行查询，本层不代劳——把「已开始」与「已通过」混成一个返回值，会让调用
    /// 方以为拿到了后者。
    pub fn self_test(&mut self, full: bool) -> (r: Result<(), BootErr>) {
        let total = TPM_HEADER_LEN + 1;
        self.put_header(CC_SELF_TEST, total);
        let arg = if full {
            SELF_TEST_FULL
        } else {
            SELF_TEST_INCREMENTAL
        };
        self.put_u8(TPM_HEADER_LEN, arg);
        match self.exec(total) {
            Ok((_n, rc)) => {
                if rc == RC_SUCCESS || rc == RC_TESTING {
                    Ok(())
                } else {
                    Err(BootErr::Rc(rc))
                }
            },
            Err(e) => Err(e),
        }
    }

    // =======================================================================
    // 属性查询
    // =======================================================================

    /// 问一个固定属性的值。
    ///
    /// 一次只问一个。批量查询能省几次往返，但应答里的键值对顺序由器件决定，
    /// 逐条对号入座的代码要处理缺项、乱序、重复三种情况，而引导期一共只问
    /// 四个属性——省下的往返换不来这些分支。
    pub fn property(&mut self, pt: u32) -> (r: Result<u32, BootErr>) {
        let total = TPM_HEADER_LEN + 12;
        self.put_header(CC_GET_CAPABILITY, total);
        self.put_be32(TPM_HEADER_LEN, CAP_TPM_PROPERTIES);
        self.put_be32(TPM_HEADER_LEN + 4, pt);
        // 计数取一。器件允许一次返回多条，但本层只读第一条，多要的部分只是
        // 白白占用响应缓冲区。
        self.put_be32(TPM_HEADER_LEN + 8, 1);

        let n = match self.exec(total) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(BootErr::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };

        // 报文按自述长度截断后再解析。解析层判断字段边界的依据是切片本身的
        // 长度，暂存区末尾那截无关字节若一起交上去，越界的读取就会变成合法的
        // 读取，读到的是上一条响应的残留。
        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response(raw) {
            Ok(v) => v,
            Err(e) => return Err(BootErr::Parse(e)),
        };
        match parse_tpm_property(rsp.body) {
            Ok(v) => Ok(v),
            Err(e) => Err(BootErr::Parse(e)),
        }
    }

    /// 问齐四个尺寸，并与本驱动的静态预留对账。
    ///
    /// 对账不通过就报错，不做降级。降级意味着运行期存在一条「缓冲区不够，
    /// 于是分片 / 截断 / 跳过」的路径，而那条路径在容量充足的机器上永远不会
    /// 被执行到，也就永远不会被测到。宁可在这里拒绝加载。
    pub fn probe_limits(&mut self) -> (r: Result<Limits, BootErr>) {
        let max_command = match self.property(PT_MAX_COMMAND_SIZE) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let max_response = match self.property(PT_MAX_RESPONSE_SIZE) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let max_object_context = match self.property(PT_MAX_OBJECT_CONTEXT) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let max_session_context = match self.property(PT_MAX_SESSION_CONTEXT) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        // 报文缓冲区两个方向都要装得下。这里比的是**器件的上界**与本端的容量：
        // 器件声称能收 8 KiB 而本端只留了 4 KiB，本身不算错——本端只要不发那么
        // 长的命令即可。真正致命的是反过来：器件产出的响应可能比本端的暂存区
        // 长，那样每一条超长响应都会被截断。
        if max_response as usize > MSG_MAX {
            return Err(BootErr::Capacity);
        }
        // 备份块整块进出，没有分片的余地，两个方向都得留够。
        if max_object_context as usize > MSG_MAX {
            return Err(BootErr::Capacity);
        }
        if max_session_context as usize > MSG_MAX {
            return Err(BootErr::Capacity);
        }

        Ok(
            Limits {
                max_command,
                max_response,
                max_object_context,
                max_session_context,
            },
        )
    }
}

// ===========================================================================
// 完整序列
// ===========================================================================

/// 从一条刚建立的链路走到「可以承载业务」，顺带交出器件容量。
///
/// 顺序由依赖关系定死，不是习惯：
///
/// 1. **宿主接口自检的结果**由调用方通过 `abi_ok` 给入,在这里最先裁决。
///    自检本身不需要器件参与,也不属于本层职责——它触及外部接口,该由落地层
///    去做;本层只负责「接口对不上就别往下走」。之所以排最前,是因为接口对不上
///    时后面每一步都会以难以归因的方式出错,不如在一个字节都还没发出去的时候
///    就停下。
/// 2. **启动**。器件在收到启动命令之前，对绝大多数命令的应答都是拒绝。
/// 3. **自检**。要在有业务命令进来之前触发，让它与后续操作并行进行。
/// 4. **容量对账**。放在最后，因为它是唯一一个需要解析应答载荷的步骤，
///    而载荷解析要求器件已经处于正常工作状态。
///
/// 中途任何一步失败都直接返回，链路随之被丢弃。这一层没有「部分成功」这种
/// 状态——引导没走完的器件，本端说不出它现在处于哪里。
pub fn bring_up<P: TisPhy>(x: Xfer<P>, su: u16, abi_ok: bool) -> (r: Result<
    (Xfer<P>, Limits),
    BootErr,
>)
    requires
        su == SU_CLEAR || su == SU_STATE,
{
    // 宿主接口是否可用,由落地层查好后作为事实传入;本层只据此裁决,不去
    // 触碰任何外部接口——那会让本 crate 反向依赖落地层,破坏单向依赖。
    if !abi_ok {
        return Err(BootErr::Abi);
    }

    let mut b = Boot::new(x);

    match b.startup(su) {
        Ok(()) => {},
        Err(e) => return Err(e),
    }
    // 增量自检而非全量：全量自检会把已经测过的算法重测一遍，在引导路径上是
    // 一段可观的、没有新信息的等待。要全量重测的场合（比如从低功耗状态恢复
    // 后的合规要求）由调用方另行调用。
    match b.self_test(false) {
        Ok(()) => {},
        Err(e) => return Err(e),
    }
    let lim = match b.probe_limits() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok((b.finish(), lim))
}

} // verus!