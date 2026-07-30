use vstd::prelude::*;
use vstd::array::*;
use vstd::slice::*;

#[cfg(verus_keep_ghost)]
use crate::cursor::spec_be32_at;
use crate::phy::TisPhy;
use crate::tpm1::cmd::{
    build_continue_selftest, build_get_random, build_getcap, build_pcr_extend, build_pcr_read,
    build_save_state, build_startup, CMD_MAX, SHA1_DIGEST_LEN,
};
use crate::tpm1::msg::{parse_response1, Parse1Error, HEADER_LEN, RC_SUCCESS};
use crate::tpm1::rsp::{
    parse_cap_u32, parse_cap_u32_quad, parse_cap_u32_triple, parse_get_random, parse_pcr_read,
};
use crate::tpm1::timeout::{scale_durations, scale_timeouts, Durations, Timeouts};
use crate::xfer::{Xfer, XferErr};

verus! {

// ===========================================================================
// 本层职责
// ===========================================================================
//
// 器件从上电到「可以承载业务」之间有一段固定序列:宣告启动、触发自检、等自检
// 退场。这段序列与 2.0 路径同形,但用的是另一套命令编号与另一套应用层重试码,
// 因此单独成层,不与 2.0 的引导层共享代码。
//
// 传输层只认得它自己那套「稍后再来」的返回码;本路径的「正在自检」「暂时忙」
// 是另外的取值,传输层认不出,会原样上交。于是这里的自检轮询、休眠重试必须由
// 本层自己做——传输层帮不上忙,也不该帮。
//
// 本层不碰授权、不碰句柄、不产生需要释放的资源:引导中途失败,调用方丢掉整个
// 实例即可,没有清理路径。

// ===========================================================================
// 返回码
// ===========================================================================

/// 自检仍在后台进行。轮询遇到它就继续等,不当错误。
pub const WARN_DOING_SELFTEST: u32 = 0x0000_0802;

/// 器件忙,稍后重发。
pub const WARN_RETRY: u32 = 0x0000_0800;

/// 器件已被停用。对休眠/恢复这类操作它仍能正确应答,所以引导可以继续。
pub const ERR_DEACTIVATED: u32 = 0x0000_0006;

/// 器件已被禁用。同上,引导可继续。
pub const ERR_DISABLED: u32 = 0x0000_0007;

/// 命令在错误的初始化阶段发出——通常意味着器件已被更早的固件启动过。启动
/// 命令遇到它按「目标状态已成立」处理。
pub const ERR_INVALID_POSTINIT: u32 = 0x0000_0026;

/// 自检未通过。器件可能需要固件升级;这是一个要让调用方看见的结论。
pub const ERR_FAILEDSELFTEST: u32 = 0x0000_001C;

// ===========================================================================
// 能力类目
// ===========================================================================

/// 属性类查询。
pub const CAP_PROPERTY: u32 = 0x0000_0005;

/// 子项:器件拥有的 PCR 数。
pub const PROP_PCR: u32 = 0x0000_0101;

/// 子项:三档命令时长。
pub const PROP_DURATION: u32 = 0x0000_0120;

/// 子项:四档 TIS 超时。
pub const PROP_TIS_TIMEOUT: u32 = 0x0000_0115;

// ===========================================================================
// 单位修正的默认值与阈值(微秒)
// ===========================================================================
//
// 器件某档报 0 时用这里的默认值回填,时长短得不可信时用这里的地板值托底。取值
// 是驱动对 TIS 规范量级的保守估计,全部为正——正是修正后各档恒为正的来源。

/// 四档超时默认值:A/C/D 各 0.75 秒,B 档 4 秒。
pub const TO_DEF_A_US: u32 = 750_000;
pub const TO_DEF_B_US: u32 = 4_000_000;
pub const TO_DEF_C_US: u32 = 750_000;
pub const TO_DEF_D_US: u32 = 750_000;

/// 三档时长默认值。
pub const DUR_DEF_SHORT_US: u32 = 750_000;
pub const DUR_DEF_MEDIUM_US: u32 = 2_000_000;
pub const DUR_DEF_LONG_US: u32 = 30_000_000;

/// 短档时长的可信下界。低于它判定为毫秒误写微秒。
pub const DUR_SHORT_THRESHOLD_US: u32 = 10_000;

/// 触发修正后,短档托底到的值。
pub const DUR_SHORT_FLOOR_US: u32 = 1_000_000;

// ===========================================================================
// 缓冲区容量
// ===========================================================================

/// 响应暂存区。最长的响应是取随机数:报文头 10 + 长度前缀 4 + 数据 128。取 256
/// 留出余量,同时压得足够小,可以放在栈上。
pub const RSP1_MAX: usize = 256;

/// 自检轮询的最大轮数。每轮之间等一个退避间隔,轮数封顶保证轮询必然终止——
/// 器件若一直不退出自检,本层等到轮数用尽就报超时,而不是无限等下去。
pub const SELFTEST_LOOPS: u32 = 300;

// ===========================================================================
// 错误
// ===========================================================================

#[derive(PartialEq, Eq, Structural)]
pub enum Boot1Err {
    /// 链路不处于可以发起命令的状态。
    NotReady,
    /// 字节没能走完一个来回。
    Bus(XferErr),
    /// 器件给出了非零返回码。
    Rc(u32),
    /// 响应到了,但解析不通过。
    Parse(Parse1Error),
    /// 自检轮询到轮数用尽仍未退场。
    SelfTestTimeout,
    /// 调用方给的出参缓冲区装不下结果。
    Capacity,
}

// ===========================================================================
// 引导器
// ===========================================================================

pub struct Boot1<P: TisPhy> {
    x: Xfer<P>,
    /// 命令暂存区。私有:本层对长度字段的保证建立在外部改不动它之上。
    cbuf: [u8; CMD_MAX],
    rbuf: [u8; RSP1_MAX],
}

impl<P: TisPhy> Boot1<P> {
    pub fn new(x: Xfer<P>) -> (r: Self) {
        Boot1 { x, cbuf: [0u8; CMD_MAX], rbuf: [0u8; RSP1_MAX] }
    }

    /// 交出链路,结束引导阶段。
    pub fn finish(self) -> (r: Xfer<P>) {
        self.x
    }

    // =======================================================================
    // 一次往返
    // =======================================================================

    /// 把已拼好的命令发出去,取回响应长度与返回码。
    ///
    /// 前置条件里「长度字段等于 `len`」由拼装函数的后置条件供给:链路层照这个
    /// 字段决定往总线上推多少字节,字段与实参不符则双方各等各的,直到超时。
    ///
    /// 返回码原样带出,不在这里按成功/失败分流——不同命令对同一个返回码的
    /// 解读不同(自检的「正在测」是有效答案,别处则是要重试的信号),分流交给
    /// 各个方法。
    fn exec(&mut self, len: usize) -> (r: Result<(usize, u32), Boot1Err>)
        requires
            HEADER_LEN <= len,
            len <= CMD_MAX,
            spec_be32_at(old(self).cbuf@, 2) == len as u32,
        ensures
            final(self).cbuf@ == old(self).cbuf@,
            final(self).rbuf@.len() == RSP1_MAX,
            r matches Ok((n, _rc)) ==> {
                &&& HEADER_LEN <= n
                &&& n <= RSP1_MAX
                &&& spec_be32_at(final(self).rbuf@, 2) == n
            },
    {
        if !self.x.ready() {
            return Err(Boot1Err::NotReady);
        }
        match self.x.run(&self.cbuf, len, &mut self.rbuf) {
            Ok((n, rc)) => Ok((n, rc)),
            Err(e) => Err(Boot1Err::Bus(e)),
        }
    }

    /// 退避一个轮询间隔。等待长度由物理层决定,本层只表达「等一下再问」。
    ///
    /// 只动物理层,命令与响应暂存区不受影响——这一点要留在后置条件里,轮询
    /// 循环靠它维持「复发的是同一条命令」这个不变量。
    fn nap(&mut self)
        ensures
            final(self).cbuf@ == old(self).cbuf@,
            final(self).rbuf@ == old(self).rbuf@,
    {
        self.x.tis.phy.delay();
    }

    // =======================================================================
    // 启动
    // =======================================================================

    /// 宣告启动方式。「已经启动过了」按成功处理:器件的启动状态由上电周期决定,
    /// 本端可能是在更早一段固件已初始化之后才接手的,这种情形下的拒绝说的是
    /// 「你要的状态已成立」。
    pub fn startup(&mut self, startup_type: u16) -> (r: Result<(), Boot1Err>) {
        let len = build_startup(&mut self.cbuf, startup_type);
        match self.exec(len) {
            Ok((_n, rc)) => {
                if rc == RC_SUCCESS || rc == ERR_INVALID_POSTINIT {
                    Ok(())
                } else {
                    Err(Boot1Err::Rc(rc))
                }
            },
            Err(e) => Err(e),
        }
    }

    // =======================================================================
    // 自检
    // =======================================================================

    /// 触发一次增量自检并返回器件的即时返回码,不做解读。
    fn continue_selftest(&mut self) -> (r: Result<u32, Boot1Err>) {
        let len = build_continue_selftest(&mut self.cbuf);
        match self.exec(len) {
            Ok((_n, rc)) => Ok(rc),
            Err(e) => Err(e),
        }
    }

    /// 触发自检,并轮询到器件可以接收后续命令为止。
    ///
    /// 触发之后不断读 PCR 0 试探:读通了说明器件已就绪;器件回「正在测」就退避
    /// 再试;回「已停用/已禁用」则器件虽不完整但仍能应答休眠恢复,引导照常
    /// 继续;其余非零返回码如实上报。
    ///
    /// 轮询轮数由 [`SELFTEST_LOOPS`] 封顶,循环必然终止——这是本方法唯一需要
    /// 证明的性质,也是它相对「照抄一个 `while(1)`」的全部价值:器件卡在自检里
    /// 不退场时,本层等到轮数用尽就报超时,不会把调用方拖进无限等待。
    pub fn do_selftest(&mut self) -> (r: Result<(), Boot1Err>) {
        // 触发。触发命令自身的返回码:成功或「已过初始化阶段」都放行,其余
        // 非零码在这里就是硬错误,不必进轮询。
        let trc = match self.continue_selftest() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if trc != RC_SUCCESS && trc != ERR_INVALID_POSTINIT {
            return Err(Boot1Err::Rc(trc));
        }

        // 轮询用的命令拼一次,之后每轮复发同一条——它是只读的,复发逐字节相同。
        let len = build_pcr_read(&mut self.cbuf, 0);

        let mut loops: u32 = SELFTEST_LOOPS;
        while loops > 0
            invariant
                spec_be32_at(self.cbuf@, 2) == len as u32,
                HEADER_LEN <= len,
                len <= CMD_MAX,
            decreases loops,
        {
            let rc = match self.exec(len) {
                Ok((_n, rc)) => rc,
                Err(e) => return Err(e),
            };

            if rc == RC_SUCCESS {
                return Ok(());
            }
            if rc == ERR_DISABLED || rc == ERR_DEACTIVATED {
                // 器件不完整,但休眠/恢复仍走得通,放行。
                return Ok(());
            }
            if rc != WARN_DOING_SELFTEST {
                // 其余任何非零码都是结论性的(含自检失败),上交。
                return Err(Boot1Err::Rc(rc));
            }

            self.nap();
            loops = loops - 1;
        }

        Err(Boot1Err::SelfTestTimeout)
    }

    // =======================================================================
    // PCR
    // =======================================================================

    /// 读一个 PCR 的当前值,写入 `out` 的前 20 字节。
    pub fn pcr_read(&mut self, pcr_idx: u32, out: &mut [u8]) -> (r: Result<(), Boot1Err>)
        requires
            old(out).len() >= SHA1_DIGEST_LEN,
        ensures
            final(out).len() == old(out).len(),
    {
        let len = build_pcr_read(&mut self.cbuf, pcr_idx);
        let n = match self.exec(len) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(Boot1Err::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };

        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response1(raw) {
            Ok(v) => v,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        let digest = match parse_pcr_read(rsp.body) {
            Ok(s) => s,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };

        // digest 长度恒为 20(解析后置条件),out 至少 20(前置条件),逐字节拷。
        let mut i: usize = 0;
        while i < SHA1_DIGEST_LEN
            invariant
                i <= SHA1_DIGEST_LEN,
                digest@.len() == SHA1_DIGEST_LEN,
                out.len() == old(out).len(),
                out.len() >= SHA1_DIGEST_LEN,
            decreases SHA1_DIGEST_LEN - i,
        {
            out[i] = digest[i];
            i += 1;
        }
        Ok(())
    }

    /// 向一个 PCR 累加一段 20 字节摘要。
    pub fn pcr_extend(&mut self, pcr_idx: u32, digest: &[u8]) -> (r: Result<(), Boot1Err>)
        requires
            digest.len() == SHA1_DIGEST_LEN,
    {
        let len = build_pcr_extend(&mut self.cbuf, pcr_idx, digest);
        match self.exec(len) {
            Ok((_n, rc)) => {
                if rc == RC_SUCCESS {
                    Ok(())
                } else {
                    Err(Boot1Err::Rc(rc))
                }
            },
            Err(e) => Err(e),
        }
    }

    // =======================================================================
    // 随机数
    // =======================================================================

    /// 取一批随机字节,写入 `out`,返回实际取回的字节数。
    ///
    /// 器件一次可以少给,本方法只发一次请求;要填满一个更大的缓冲区由调用方
    /// 循环处理。少给不是错误,给多了才是——那由解析层按格式错误挡下。
    pub fn get_random(&mut self, out: &mut [u8]) -> (r: Result<usize, Boot1Err>)
        requires
            old(out).len() <= 65535,
        ensures
            final(out).len() == old(out).len(),
    {
        let want = out.len();
        let len = build_get_random(&mut self.cbuf, want as u32);
        let n = match self.exec(len) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(Boot1Err::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };

        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response1(raw) {
            Ok(v) => v,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        let bytes = match parse_get_random(rsp.body, want as u16) {
            Ok(s) => s,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };

        // 解析后置条件保证 bytes.len() <= want == out.len(),拷贝不会越界。
        let got = bytes.len();
        let mut i: usize = 0;
        while i < got
            invariant
                i <= got,
                got == bytes@.len(),
                out.len() == old(out).len(),
                got <= out.len(),
            decreases got - i,
        {
            out[i] = bytes[i];
            i += 1;
        }
        Ok(got)
    }

    // =======================================================================
    // 能力查询
    // =======================================================================

    /// 问一项返回值为 u32 的属性。
    pub fn get_property(&mut self, subcap: u32) -> (r: Result<u32, Boot1Err>) {
        let len = build_getcap(&mut self.cbuf, CAP_PROPERTY, subcap);
        let n = match self.exec(len) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(Boot1Err::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };

        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response1(raw) {
            Ok(v) => v,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        match parse_cap_u32(rsp.body) {
            Ok(v) => Ok(v),
            Err(e) => Err(Boot1Err::Parse(e)),
        }
    }

    /// 问三档命令时长(短/中/长),单位由器件决定。用于把编号的时长档换算成
    /// 具体等待时长。
    pub fn get_durations(&mut self) -> (r: Result<(u32, u32, u32), Boot1Err>) {
        let len = build_getcap(&mut self.cbuf, CAP_PROPERTY, PROP_DURATION);
        let n = match self.exec(len) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(Boot1Err::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };

        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response1(raw) {
            Ok(v) => v,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        match parse_cap_u32_triple(rsp.body) {
            Ok(t) => Ok(t),
            Err(e) => Err(Boot1Err::Parse(e)),
        }
    }

    /// 问齐四档超时与三档时长,并就地做单位修正。
    ///
    /// 两次查询、两次修正。返回的每一档都保证为正——这一点由修正函数的后置条件
    /// 与本方法传入的正默认值共同给出,于是结果可以直接喂给按命令编号取时长的
    /// 映射,不必调用方再各自兜底。
    ///
    /// 与逐项 `get_property` 不同,超时/时长是成组的定长结构,一次取回四个/三个
    /// u32,因此走专门的四元/三元解析而非单值解析。
    pub fn probe_timeouts(&mut self) -> (r: Result<(Timeouts, Durations), Boot1Err>)
        ensures
            r matches Ok((to, dur)) ==> {
                &&& to.a >= 1
                &&& to.b >= 1
                &&& to.c >= 1
                &&& to.d >= 1
                &&& dur.short >= 1
                &&& dur.medium >= 1
                &&& dur.long >= 1
            },
    {
        // ---- 四档超时 ----
        let len = build_getcap(&mut self.cbuf, CAP_PROPERTY, PROP_TIS_TIMEOUT);
        let n = match self.exec(len) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(Boot1Err::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };
        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response1(raw) {
            Ok(v) => v,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        let (ta, tb, tc, td) = match parse_cap_u32_quad(rsp.body) {
            Ok(q) => q,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        let timeouts = scale_timeouts(
            Timeouts { a: ta, b: tb, c: tc, d: td },
            Timeouts { a: TO_DEF_A_US, b: TO_DEF_B_US, c: TO_DEF_C_US, d: TO_DEF_D_US },
        );

        // ---- 三档时长 ----
        let len = build_getcap(&mut self.cbuf, CAP_PROPERTY, PROP_DURATION);
        let n = match self.exec(len) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    return Err(Boot1Err::Rc(rc));
                }
                n
            },
            Err(e) => return Err(e),
        };
        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let rsp = match parse_response1(raw) {
            Ok(v) => v,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        let (ds, dm, dl) = match parse_cap_u32_triple(rsp.body) {
            Ok(t) => t,
            Err(e) => return Err(Boot1Err::Parse(e)),
        };
        let durations = scale_durations(
            Durations { short: ds, medium: dm, long: dl },
            Durations {
                short: DUR_DEF_SHORT_US,
                medium: DUR_DEF_MEDIUM_US,
                long: DUR_DEF_LONG_US,
            },
            DUR_SHORT_THRESHOLD_US,
            DUR_SHORT_FLOOR_US,
        );

        Ok((timeouts, durations))
    }

    // =======================================================================
    // 休眠
    // =======================================================================

    /// 保存易失状态,为休眠做准备。不放过任何非零返回码:保存若没成功,器件
    /// 下次上电会当作异常断电,重置一部分状态——这件事调用方必须知道。
    pub fn save_state(&mut self) -> (r: Result<(), Boot1Err>) {
        let len = build_save_state(&mut self.cbuf);
        match self.exec(len) {
            Ok((_n, rc)) => {
                if rc == RC_SUCCESS {
                    Ok(())
                } else {
                    Err(Boot1Err::Rc(rc))
                }
            },
            Err(e) => Err(e),
        }
    }
}

// ===========================================================================
// 完整序列
// ===========================================================================

/// 从一条刚建立的链路走到「可以承载业务」。
///
/// 顺序由依赖关系定死:先启动(器件在启动前拒绝绝大多数命令),再自检(要在
/// 业务命令进来之前触发,并等它退场)。中途任何一步失败都直接返回,链路随之
/// 被丢弃——没有「部分成功」这种状态。
///
/// 与 2.0 序列相比少了容量对账:本路径的命令载荷都是定长小报文,不存在需要与
/// 器件上界对账的大块传输。
pub fn bring_up1<P: TisPhy>(x: Xfer<P>, startup_type: u16) -> (r: Result<Xfer<P>, Boot1Err>) {
    let mut b = Boot1::new(x);

    match b.startup(startup_type) {
        Ok(()) => {},
        Err(e) => return Err(e),
    }
    match b.do_selftest() {
        Ok(()) => {},
        Err(e) => return Err(e),
    }

    Ok(b.finish())
}

} // verus!
