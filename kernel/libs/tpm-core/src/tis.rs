use vstd::prelude::*;

verus! {

// ===========================================================================
// 建模范围
// ===========================================================================
//
// 本层按 TCG PC Client Platform TPM Profile 的寄存器语义建模，不按任何具体
// 器件的实际行为建模。以下三类兼容开关**明确排除在外**：
//
// - 不置 `DATA_EXPECT` 的器件。排除它意味着写入过程中的 `DATA_EXPECT` 检查
//   是无条件的，比放行更严格。
// - 时钟门控开关。它属于平台南桥而非本接口，混进来会让寄存器语义不再自洽。
// - `STS_VALID` 需要重试的器件。它把「超时」和「再试一次」混成同一个返回码，
//   而本层要求超时预算是单调消耗的。
//
// 排除不等于这些器件不存在。要支持它们，应当在本层之外单独建模，并各自写清
// 楚偏离规范的具体条款——把妥协混进主状态机，会让规约同时描述两套互相矛盾的
// 硬件。

// ===========================================================================
// 访问寄存器位
// ===========================================================================

pub const ACCESS_VALID: u8 = 0x80;
pub const ACCESS_ACTIVE_LOCALITY: u8 = 0x20;
pub const ACCESS_REQUEST_PENDING: u8 = 0x04;
pub const ACCESS_REQUEST_USE: u8 = 0x02;

// ===========================================================================
// 状态寄存器位
// ===========================================================================

pub const STS_VALID: u8 = 0x80;
pub const STS_COMMAND_READY: u8 = 0x40;
pub const STS_GO: u8 = 0x20;
pub const STS_DATA_AVAIL: u8 = 0x10;
pub const STS_DATA_EXPECT: u8 = 0x08;
pub const STS_RESPONSE_RETRY: u8 = 0x02;

// ===========================================================================
// 地址
// ===========================================================================

/// locality 取值范围。
pub const MAX_LOCALITY: u8 = 5;

/// locality 号占据地址的第 12 位起。
pub open spec fn spec_reg(base: u32, l: u8) -> u32 {
    (base as int + (l as int) * 4096) as u32
}

pub fn reg_access(l: u8) -> (r: u32)
    requires
        l < MAX_LOCALITY,
    ensures
        r == spec_reg(0x0000, l),
{
    0x0000u32 + (l as u32) * 4096u32
}

pub fn reg_sts(l: u8) -> (r: u32)
    requires
        l < MAX_LOCALITY,
    ensures
        r == spec_reg(0x0018, l),
{
    0x0018u32 + (l as u32) * 4096u32
}

pub fn reg_data_fifo(l: u8) -> (r: u32)
    requires
        l < MAX_LOCALITY,
    ensures
        r == spec_reg(0x0024, l),
{
    0x0024u32 + (l as u32) * 4096u32
}

pub fn reg_did_vid(l: u8) -> (r: u32)
    requires
        l < MAX_LOCALITY,
    ensures
        r == spec_reg(0x0F00, l),
{
    0x0F00u32 + (l as u32) * 4096u32
}

// ===========================================================================
// 轮询预算
// ===========================================================================
//
// 原始规范用毫秒表达超时，实现里则是「读一次寄存器，睡一小会儿，再读」。把
// 超时折算成**轮询次数**而不是留在时间域，有两个好处：
//
// - 每个轮询循环都能用剩余次数作 `decreases`，终止性直接可证。时间域没有这
//   个性质——`jiffies` 会绕回，「还没到点」这个条件在时钟回绕时可以永真。
// - 预算是显式参数，调用点必须写出自己愿意等多久，不能沿用一个全局默认值。
//
// 折算在构造时一次完成：预算 = 超时毫秒数 / 单次轮询间隔毫秒数，向上取整且
// 至少为一。

/// 单次轮询间隔（毫秒）。
pub const POLL_INTERVAL_MS: u32 = 1;

/// 规范给出的四档超时（毫秒）。
pub const TIMEOUT_A_MS: u32 = 750;
pub const TIMEOUT_B_MS: u32 = 4000;
pub const TIMEOUT_C_MS: u32 = 750;
pub const TIMEOUT_D_MS: u32 = 750;

/// 把毫秒超时折算成轮询次数。
///
/// 至少返回一次：预算为零的循环一次寄存器都不读就宣告超时，那是配置错误，
/// 不该表现为运行时的偶发失败。
pub fn budget_of(timeout_ms: u32) -> (r: u32)
    ensures
        r >= 1,
{
    let n = timeout_ms / POLL_INTERVAL_MS;
    if n == 0 {
        1
    } else {
        n
    }
}

// ===========================================================================
// 错误
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
pub enum TisErr {
    /// 物理层报错。总线本身出了问题，重试没有意义。
    Phy,
    /// 轮询预算耗尽。
    Timeout,
    /// 器件状态与规范不符。
    Protocol,
    /// 对端声明的长度小于一个报文头，或超出接收缓冲区。
    BadLength,
}

} // verus!
