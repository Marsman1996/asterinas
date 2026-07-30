use vstd::prelude::*;

verus! {

/// 上下文表与会话表的槽位数。
pub const SLOTS: usize = 3;

/// 句柄类型由最高字节区分。
pub const HANDLE_TYPE_MASK: u32 = 0xFF00_0000;

pub const HT_HMAC_SESSION: u32 = 0x0200_0000;
pub const HT_POLICY_SESSION: u32 = 0x0300_0000;
pub const HT_TRANSIENT: u32 = 0x8000_0000;

/// 上下文表里表示「已保存、尚未装载」的哨兵值。
pub const CTX_SAVED_SENTINEL: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// 编码规约
// ---------------------------------------------------------------------------

/// 槽位 `i` 对应的虚拟句柄。
pub open spec fn vhandle_of(i: int) -> u32 {
    (0x80FF_FFFF - i) as u32
}

/// 从虚拟句柄反解槽位号。对非法输入返回的值会落在 `[0, SLOTS)` 之外。
pub open spec fn slot_of(v: u32) -> int {
    0xFF_FFFF - ((v & 0xFF_FFFF) as int)
}

/// 是否属于瞬态对象句柄空间。
pub open spec fn is_transient(h: u32) -> bool {
    (h & HANDLE_TYPE_MASK) == HT_TRANSIENT
}

/// 是否属于会话句柄空间（HMAC 或策略）。会话句柄**不做虚拟化**，
/// 表里只登记它们以便统一保存 / 装载 / 释放。
pub open spec fn is_session(h: u32) -> bool {
    (h & HANDLE_TYPE_MASK) == HT_HMAC_SESSION
        || (h & HANDLE_TYPE_MASK) == HT_POLICY_SESSION
}

/// 可以被登记进上下文表的物理句柄：既不是空槽标记也不是哨兵。
pub open spec fn valid_phandle(h: u32) -> bool {
    h != 0 && h != CTX_SAVED_SENTINEL
}

// ---------------------------------------------------------------------------
// 引理
// ---------------------------------------------------------------------------

/// 虚拟句柄一定是瞬态类型。
pub proof fn lemma_vhandle_is_transient(i: int)
    requires
        0 <= i < SLOTS,
    ensures
        is_transient(vhandle_of(i)),
{
    assert(SLOTS == 3);
    if i == 0 {
        assert(is_transient(0x80FF_FFFFu32)) by (bit_vector);
    } else if i == 1 {
        assert(is_transient(0x80FF_FFFEu32)) by (bit_vector);
    } else {
        assert(is_transient(0x80FF_FFFDu32)) by (bit_vector);
    }
}

/// 编码 / 解码往返一致。
pub proof fn lemma_slot_roundtrip(i: int)
    requires
        0 <= i < SLOTS,
    ensures
        slot_of(vhandle_of(i)) == i,
{
    assert(SLOTS == 3);
    if i == 0 {
        assert((0x80FF_FFFFu32 & 0xFF_FFFFu32) == 0xFF_FFFFu32) by (bit_vector);
    } else if i == 1 {
        assert((0x80FF_FFFEu32 & 0xFF_FFFFu32) == 0xFF_FFFEu32) by (bit_vector);
    } else {
        assert((0x80FF_FFFDu32 & 0xFF_FFFFu32) == 0xFF_FFFDu32) by (bit_vector);
    }
}

/// **双射性的算术核心**：类型位与槽位位拼起来就是整个句柄，
/// 所以两个瞬态句柄只要槽位相同就必然相等。
///
/// 上层的「虚实映射是单射」直接由它推出，不必再碰位运算。
pub proof fn lemma_transient_slot_injective(a: u32, b: u32)
    requires
        is_transient(a),
        is_transient(b),
        slot_of(a) == slot_of(b),
    ensures
        a == b,
{
    assert((a & 0xFF_FFFFu32) == (b & 0xFF_FFFFu32));
    assert(
        ((a & 0xFF00_0000u32) == (b & 0xFF00_0000u32)
            && (a & 0x00FF_FFFFu32) == (b & 0x00FF_FFFFu32)) ==> a == b
    ) by (bit_vector);
}

// ---------------------------------------------------------------------------
// 可执行版本
// ---------------------------------------------------------------------------

pub fn vhandle_of_exec(i: usize) -> (r: u32)
    requires
        i < SLOTS,
    ensures
        r == vhandle_of(i as int),
        is_transient(r),
{
    proof {
        lemma_vhandle_is_transient(i as int);
    }
    0x80FF_FFFFu32 - (i as u32)
}

/// 反解槽位号。返回 `usize`，越界由调用方用 `< SLOTS` 判断。
pub fn slot_of_exec(v: u32) -> (r: usize)
    ensures
        r as int == slot_of(v),
{
    assert((v & 0xFF_FFFFu32) <= 0xFF_FFFFu32) by (bit_vector);
    (0xFF_FFFFu32 - (v & 0xFF_FFFFu32)) as usize
}

pub fn is_transient_exec(h: u32) -> (r: bool)
    ensures
        r == is_transient(h),
{
    (h & HANDLE_TYPE_MASK) == HT_TRANSIENT
}

pub fn is_session_exec(h: u32) -> (r: bool)
    ensures
        r == is_session(h),
{
    let t = h & HANDLE_TYPE_MASK;
    t == HT_HMAC_SESSION || t == HT_POLICY_SESSION
}

pub fn valid_phandle_exec(h: u32) -> (r: bool)
    ensures
        r == valid_phandle(h),
{
    h != 0 && h != CTX_SAVED_SENTINEL
}

} // verus!
