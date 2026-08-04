#[cfg(verus_keep_ghost)]
use crate::handle::valid_phandle;
#[cfg(verus_keep_ghost)]
use crate::rewrite::be32_at;
use crate::{
    chip::{ChipTransport, RC_SUCCESS},
    cmd::{CC_CONTEXT_LOAD, CC_FLUSH_CONTEXT},
    module::IoErr,
    phy::TisPhy,
    rewrite::HEADER_SIZE,
    xfer::{Xfer, XferErr, peek_be32},
};

/// 芯片当前持有的句柄集合。
///
/// 只有幽灵字段，运行时是零大小类型。所有修改它的方法都不含可执行代码——
/// 它们不是在「记录」什么，而是在**声明本端对芯片行为的假设**。
pub struct LiveSet;
impl LiveSet {
    pub fn new() -> Self {
        Self
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
    pub fn observe_load(&mut self, _h: u32) {}
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
    pub fn observe_flush(&mut self) {}
}
pub struct ChipLink<P: TisPhy> {
    pub x: Xfer<P>,
    pub ledger: LiveSet,
}
impl<P: TisPhy> ChipLink<P> {
    pub fn new(x: Xfer<P>) -> Self {
        ChipLink {
            x,
            ledger: LiveSet::new(),
        }
    }
}
impl<P: TisPhy> ChipTransport for ChipLink<P> {
    fn exec(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, IoErr> {
        let cc = peek_be32(cmd, 6);
        if cc == CC_FLUSH_CONTEXT {
            self.ledger.observe_flush();
        }
        if !self.x.ready() {
            return Err(IoErr::Fatal);
        }
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
                    if n < HEADER_SIZE + 4 {
                        return Err(IoErr::Fatal);
                    }
                    let h = peek_be32(&*rsp, HEADER_SIZE);
                    self.ledger.observe_load(h);
                }
                n
            }
            Err(e) => {
                return Err(map_err(e));
            }
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
pub fn map_err(e: XferErr) -> IoErr {
    match e {
        XferErr::Bus(_) => IoErr::Fatal,
        XferErr::BadCommand => IoErr::Fatal,
    }
}
