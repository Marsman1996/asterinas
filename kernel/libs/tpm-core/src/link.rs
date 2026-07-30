use vstd::prelude::*;
use vstd::set::Set;

use crate::chip::{ChipTransport, RC_SUCCESS};
use crate::cmd::{CC_CONTEXT_LOAD, CC_FLUSH_CONTEXT};
#[cfg(verus_keep_ghost)]
use crate::handle::valid_phandle;
use crate::module::IoErr;
use crate::phy::TisPhy;
#[cfg(verus_keep_ghost)]
use crate::rewrite::be32_at;
use crate::rewrite::HEADER_SIZE;
use crate::xfer::{Xfer, XferErr, peek_be32};

verus! {

// ===========================================================================
// 这一层是做什么的
// ===========================================================================
//
// 编排层要求的接触面是「一次往返，外加芯片持有哪些句柄」；传输链路给出的是
// 「一次往返」。差的那半句——句柄集合——是**芯片内部的状态**，本端观察不到，
// 只能假设。
//
// 假设不可避免，但可以关得很小。本模块把它压缩成一个零大小的幽灵账本：它在
// 运行时不存在，编译后不占一个字节，唯一的作用是承载那句说不出口的话——
// 「芯片刚刚报上来的句柄，此前不曾有效」。除此之外的每一步（长度校验、命令
// 码分派、错误映射）都是普通的可验证代码。
//
// 于是信任基的增量就是下面三个函数的后置条件，不多不少。

// ===========================================================================
// 幽灵账本（信任基）
// ===========================================================================

/// 芯片当前持有的句柄集合。
///
/// 只有幽灵字段，运行时是零大小类型。所有修改它的方法都不含可执行代码——
/// 它们不是在「记录」什么，而是在**声明本端对芯片行为的假设**。
pub struct LiveSet {
    #[cfg(verus_keep_ghost)]
    pub ghost s: Set<u32>,
}

impl LiveSet {
    pub open spec fn view(&self) -> Set<u32> {
        self.s
    }

    #[verifier::external_body]
    pub fn new() -> (r: Self)
        ensures
            r.view() == Set::<u32>::empty(),
    {
        LiveSet {
            #[cfg(verus_keep_ghost)]
            s: Set::<u32>::empty(),
        }
    }

    /// 记下芯片新装载的句柄。
    ///
    /// **信任条款（一）**：`valid_phandle(h)`。
    /// 依据：规范规定装载类命令成功时返回的句柄落在瞬态对象区间内，零与
    /// 保留值都不是合法返回。
    ///
    /// **信任条款（二）**：`!old(self).view().contains(h)`。
    /// 依据：一个句柄在被显式释放或换出之前唯一标识一个已装载对象，芯片不会
    /// 把仍然有效的句柄再次分配出去。
    ///
    /// 第二条是**整条证明链里最实质的一条假设**：上层句柄表的单射性、两个
    /// 句柄空间之间的隔离性，最终都归结到它。它也是唯一一条无法靠本端的任何
    /// 检查加固的假设——本端若能自行验证句柄是新的，就不需要假设了。
    ///
    /// 调用纪律：只能用刚刚从装载类命令的成功响应里读出的句柄调用，且该响应
    /// 必须已经通过长度校验。任何其他调用方式都会让上述两条从假设变成谎言。
    #[verifier::external_body]
    pub fn observe_load(&mut self, _h: u32)
        ensures
            valid_phandle(_h),
            !old(self).view().contains(_h),
            final(self).view() == old(self).view().insert(_h),
    {
    }

    /// 记下句柄已不再由本端追踪。
    ///
    /// **信任条款（三）**：集合按 `h` 收缩。
    ///
    /// 句柄取幽灵值而非运行时值：这一步在运行时什么都不做，取值只用于证明。
    /// 这样即使命令缓冲区短到读不出句柄字段，账仍然记得下——而不必为了记账
    /// 去给命令缓冲区补一条本不需要的长度前提。
    ///
    /// 注意这里**不假设芯片真的释放了**。释放命令若因总线故障没能送达，那份
    /// 资源会一直占着芯片直到复位。这是已知且无从补救的泄漏，写在账上只会
    /// 让本端永远背着一个再也用不上的句柄。
    #[verifier::external_body]
    pub fn observe_flush(&mut self, _h: Ghost<u32>)
        ensures
            final(self).view() == old(self).view().remove(_h@),
    {
    }
}

// ===========================================================================
// 链路
// ===========================================================================

pub struct ChipLink<P: TisPhy> {
    pub x: Xfer<P>,
    pub ledger: LiveSet,
}

impl<P: TisPhy> ChipLink<P> {
    pub fn new(x: Xfer<P>) -> (r: Self)
        ensures
            r.ledger.view() == Set::<u32>::empty(),
    {
        ChipLink { x, ledger: LiveSet::new() }
    }
}

impl<P: TisPhy> ChipTransport for ChipLink<P> {
    open spec fn live(&self) -> Set<u32> {
        self.ledger.view()
    }

    fn exec(&mut self, cmd: &[u8], rsp: &mut [u8]) -> (r: Result<usize, IoErr>) {
        // 命令码取自报文头的固定偏移。这一读无条件成立：接口前置条件已经
        // 保证缓冲区不短于一个报文头。
        let cc = peek_be32(cmd, 6);
        let ghost fh = be32_at(cmd@, HEADER_SIZE as int);

        // 释放命令的账**先记，且记在所有提前返回之前**。接触面对释放命令的
        // 规约不以传输成功为条件：传输失败时本端无从得知芯片是否已经释放，
        // 与其两边都不确定，不如统一按「本端不再追踪」处理。这条账要是落在
        // 某个 `return` 后面，那条路径就会留下一个语义上早已放弃、本端却仍在
        // 追踪的句柄。
        if cc == CC_FLUSH_CONTEXT {
            self.ledger.observe_flush(Ghost(fh));
        }

        // 接口签名不带状态前提，前提只能在这里补。不满足就直接回绝：一条在
        // 错误状态下发出的命令，最好的结果也只是浪费一次往返。
        if !self.x.ready() {
            return Err(IoErr::Fatal);
        }

        // 命令有多长以报文头的自述为准，而不是以缓冲区容量为准——上层传下来
        // 的往往是一整块暂存区，末尾大片是无关字节，照缓冲区长度发送等于把
        // 垃圾一起送进器件。
        let declared = peek_be32(cmd, 2);
        if declared < HEADER_SIZE as u32 {
            return Err(IoErr::Fatal);
        }
        let len = declared as usize;
        if len > cmd.len() {
            return Err(IoErr::Fatal);
        }

        let n = match self.x.run(cmd, len, rsp) {
            Ok((n, rc)) => {
                if cc == CC_CONTEXT_LOAD && rc == RC_SUCCESS {
                    // 装载成功却装不下一个句柄，说明响应与命令对不上号。这种
                    // 响应不能采信，也就不能记账——代价是万一芯片确实装载了，
                    // 那个句柄就此泄漏。宁可泄漏一个句柄，也不能把一个来路不明
                    // 的数值当作句柄记进表里。
                    if n < HEADER_SIZE + 4 {
                        return Err(IoErr::Fatal);
                    }
                    let h = peek_be32(&*rsp, HEADER_SIZE);
                    self.ledger.observe_load(h);
                }
                n
            },
            Err(e) => {
                return Err(map_err(e));
            },
        };

        Ok(n)
    }
}

/// 链路错误 → 编排层错误。
///
/// 一律映射到不可恢复：链路层的失败说的是「字节没走完一个来回」，它不携带
/// 任何关于芯片状态的信息。编排层的可恢复分类（目标不存在、备份放不下）全都
/// 依据返回码得出，而走到这里恰恰意味着没有返回码可读。把总线故障混进可恢复
/// 分类，上层就会据此修改自己的表，而修改的依据并不存在。
pub fn map_err(e: XferErr) -> (r: IoErr) {
    match e {
        XferErr::Bus(_) => IoErr::Fatal,
        XferErr::BadCommand => IoErr::Fatal,
    }
}

} // verus!
