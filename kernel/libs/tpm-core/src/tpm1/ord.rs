
pub const ORD_EXTEND: u32 = 20;
pub const ORD_PCR_READ: u32 = 21;
pub const ORD_GET_RANDOM: u32 = 70;
pub const ORD_GET_CAPABILITY: u32 = 101;
pub const ORD_CONTINUE_SELF_TEST: u32 = 83;
pub const ORD_SAVE_STATE: u32 = 152;
pub const ORD_STARTUP: u32 = 153;
pub const DUR_SHORT: u8 = 0;
pub const DUR_MEDIUM: u8 = 1;
pub const DUR_LONG: u8 = 2;
/// 该编号没有登记时长档。落到这一档的命令用调用方给的兜底时长等待。
pub const DUR_UNDEFINED: u8 = 3;
/// 登记了时长档的编号上界。超过它的编号一律按未登记处理。
pub const MAX_ORDINAL: usize = 243;
/// 编号 → 时长档。
///
/// 表里只覆盖那些执行时间可预期的命令。取值为 [`DUR_UNDEFINED`] 的位置有两类:
/// 一类是该编号根本不存在,一类是它的耗时不由命令本身决定(例如依赖熵池或
/// 外部条件),两类都交给兜底时长,不在这里区分。
const ORDINAL_DURATION: [u8; MAX_ORDINAL] = [
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 1, 2, 2, 1, 0, 0, 1, 2, 0, 0, 1, 1, 1, 0, 0, 1,
    0, 0, 1, 2, 1, 0, 0, 0, 1, 1, 3, 3, 1, 2, 1, 0, 0, 0, 0, 0, 0, 2, 1, 1, 3, 3, 3, 3,
    3, 3, 3, 3, 1, 1, 1, 0, 0, 1, 3, 3, 3, 3, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 2, 3, 1, 2,
    0, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 1, 0, 0, 3, 3, 3, 3, 3, 3, 3, 0, 0,
    0, 0, 0, 0, 0, 0, 3, 3, 2, 2, 1, 3, 0, 0, 0, 2, 0, 0, 0, 1, 3, 0, 1, 3, 3, 3, 3, 3,
    0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 0, 1, 1, 0, 0, 3, 3, 3, 3, 3, 0, 0, 0, 0, 3, 3, 3, 3,
    3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 0, 1, 1, 1, 1, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 0, 3, 3, 3, 0, 0, 0, 0, 0, 0, 1, 3, 1, 1, 1, 3, 1, 3, 3, 0, 0, 0, 0, 0,
    0, 3, 3, 3, 3, 3, 0, 2, 1, 3, 3, 3, 3, 3, 3, 3, 0, 3, 1,
];
/// 查出一个编号的时长档。
///
/// 越界的编号直接判未登记,不触碰数组——边界检查在取值之前完成,这是全函数
/// 唯一的安全论据。
pub fn duration_class(ord: u32) -> u8 {
    if ord >= MAX_ORDINAL as u32 {
        DUR_UNDEFINED
    } else {
        ORDINAL_DURATION[ord as usize]
    }
}
/// 编号 → 等待时长(毫秒)。
///
/// 三个档位的毫秒数与兜底值都由调用方给出,且都要求为正,因此返回值恒为正:
/// 未登记或档位取值异常的命令一律落到兜底档,而兜底值本身已被前置条件卡在
/// 正数上。返回值为正是上层轮询预算不为零的前提。
pub fn ordinal_timeout_ms(
    ord: u32,
    short_ms: u32,
    medium_ms: u32,
    long_ms: u32,
    fallback_ms: u32,
) -> u32 {
    let cls = duration_class(ord);
    if cls == DUR_SHORT {
        short_ms
    } else if cls == DUR_MEDIUM {
        medium_ms
    } else if cls == DUR_LONG {
        long_ms
    } else {
        fallback_ms
    }
}
