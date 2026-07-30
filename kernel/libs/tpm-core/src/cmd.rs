use vstd::prelude::*;
use vstd::array::*;

use crate::crypto::SHA256_LEN;
use crate::cursor::*;
use crate::rsp::ALG_SHA256;

verus! {

// ===================== 命令码（TPM 2.0 Part 2 §6.5.2） =====================

pub const CC_SELF_TEST: u32 = 0x0000_0143;
pub const CC_STARTUP: u32 = 0x0000_0144;
pub const CC_SHUTDOWN: u32 = 0x0000_0145;
pub const CC_CONTEXT_LOAD: u32 = 0x0000_0161;
pub const CC_CONTEXT_SAVE: u32 = 0x0000_0162;
pub const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub const CC_GET_RANDOM: u32 = 0x0000_017B;
pub const CC_PCR_READ: u32 = 0x0000_017E;
pub const CC_PCR_EXTEND: u32 = 0x0000_0182;

// ===================== 能力类别（Part 2 §6.12） =====================

pub const CAP_HANDLES: u32 = 0x0000_0001;
pub const CAP_COMMANDS: u32 = 0x0000_0002;
pub const CAP_PCRS: u32 = 0x0000_0005;
pub const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

// ===================== 关机类型（Part 2 §6.9） =====================

pub const SU_CLEAR: u16 = 0x0000;
pub const SU_STATE: u16 = 0x0001;

// ===================== 平台参数 =====================

/// PC Client 平台固定 24 个 PCR（TCG PC Client PFP）。
pub const PLATFORM_PCR: u32 = 24;

/// 覆盖 24 个 PCR 所需的选择位图字节数：ceil(24 / 8)。
pub const PCR_SELECT_MIN: usize = 3;

/// 单次取随机数的上限。超过这个量要分多次取。
pub const MAX_RNG_DATA: u16 = 128;

// ===================== PCR 选择位图 =====================

/// 位号 `n`（0..8）对应的掩码值。
///
/// 写成分支而不是移位：移位需要位向量求解器介入，而这里取值域只有
/// 八个，直接枚举既显然又不给证明添负担。
pub open spec fn spec_bit_value(n: u32) -> u8
    recommends
        n < 8,
{
    if n == 0 {
        1u8
    } else if n == 1 {
        2u8
    } else if n == 2 {
        4u8
    } else if n == 3 {
        8u8
    } else if n == 4 {
        16u8
    } else if n == 5 {
        32u8
    } else if n == 6 {
        64u8
    } else {
        128u8
    }
}

fn bit_value(n: u32) -> (r: u8)
    requires
        n < 8,
    ensures
        r == spec_bit_value(n),
        r != 0,
{
    if n == 0 {
        1
    } else if n == 1 {
        2
    } else if n == 2 {
        4
    } else if n == 3 {
        8
    } else if n == 4 {
        16
    } else if n == 5 {
        32
    } else if n == 6 {
        64
    } else {
        128
    }
}

/// 生成只选中单个 PCR 的选择位图。
///
/// 索引拆分用除法与取余而非移位与掩码：两者在 24 以内完全等价，
/// 而除法形式可以直接进入整数推理，不必切换到位向量求解器。
pub fn pcr_select_bitmap(pcr_idx: u32) -> (r: [u8; PCR_SELECT_MIN])
    requires
        pcr_idx < PLATFORM_PCR,
    ensures
        r@.len() == PCR_SELECT_MIN,
        // 选中位所在的那个字节非零
        r@[(pcr_idx / 8) as int] == spec_bit_value(pcr_idx % 8),
        r@[(pcr_idx / 8) as int] != 0,
        // 其余字节一律为零：位图里有且仅有一个 PCR 被选中
        forall|k: int| 0 <= k < PCR_SELECT_MIN && k != pcr_idx / 8 ==> r@[k] == 0,
{
    let byte_idx = pcr_idx / 8;
    let mask = bit_value(pcr_idx % 8);

    // pcr_idx < 24 蕴含 byte_idx < 3，三分支已穷尽
    if byte_idx == 0 {
        [mask, 0, 0]
    } else if byte_idx == 1 {
        [0, mask, 0]
    } else {
        [0, 0, mask]
    }
}

// ===================== PCR 句柄 =====================

/// PCR 的句柄值。
///
/// PCR 的句柄类型编号为 0，因此句柄值就是 PCR 序号本身。单独成函数不是
/// 为了那句 `r == pcr_idx`，而是为了带上这条注释：这一类句柄的「名字」
/// 即句柄自身的四个字节，算命令摘要时不需要再去查任何名字表——写摘要
/// 输入的那一处很容易在这里多绕一圈，绕错了不会被任何长度检查发现。
pub fn pcr_handle(pcr_idx: u32) -> (r: u32)
    requires
        pcr_idx < PLATFORM_PCR,
    ensures
        r == pcr_idx,
        r < PLATFORM_PCR,
{
    pcr_idx
}

// ===================== 各命令载荷 =====================

/// `TPM2_PCR_Read` 载荷（Part 3 §22.4）。
///
/// ```text
/// count        u32 = 1        只问一个 bank
/// hashAlg      u16            摘要算法
/// sizeofSelect u8  = 3
/// pcrSelect    u8[3]
/// ```
pub fn pcr_read_payload(alg_id: u16, pcr_idx: u32) -> (r: [u8; 10])
    requires
        pcr_idx < PLATFORM_PCR,
    ensures
        r@.len() == 10,
        spec_be32_at(r@, 0) == 1u32,
        spec_be16_at(r@, 4) == alg_id,
        r@[6] == PCR_SELECT_MIN as u8,
        r@[7 + (pcr_idx / 8) as int] == spec_bit_value(pcr_idx % 8),
{
    let cnt = be32_bytes(1);
    let alg = be16_bytes(alg_id);
    let sel = pcr_select_bitmap(pcr_idx);

    [cnt[0], cnt[1], cnt[2], cnt[3], alg[0], alg[1], PCR_SELECT_MIN as u8, sel[0], sel[1], sel[2]]
}

/// `TPM2_PCR_Extend` 的参数区长度：count(4) + hashAlg(2) + digest(32)。
pub const PCR_EXTEND_PARM_LEN: usize = 6 + SHA256_LEN;

/// `TPM2_PCR_Extend` 的**参数区**（Part 3 §22.2）。
///
/// ```text
/// count    u32 = 1        只写一个 bank
/// hashAlg  u16
/// digest   u8[32]
/// ```
///
/// 这条命令与只读那条的形态不同，值得说清楚：它带一个句柄、且必须授权，
/// 于是整条报文是
///
/// ```text
/// 报文头 10 | pcrHandle 4 | authSize 4 | 授权区 | 参数区
/// ```
///
/// 本函数只产出最后那一段。句柄不放进来是刻意的：句柄位于授权区**之前**，
/// 而命令摘要覆盖的是授权区**之后**那一段。两者若混在同一个数组里，拼装方
/// 迟早会把整块当作参数区喂给摘要——那种错误不触发任何长度检查，症状只是
/// 校验恒不通过，排查起来要一路回溯到偏移的定义。
///
/// 算法标识做成入参而不是写死的常量，是为了让前置条件把它和摘要长度绑在
/// 一起：这里收的是定长 32 字节，声称成别的算法就是在报文里说了谎。想支持
/// 第二种算法，摘要参数的类型必须同时改，改不动一半。
pub fn pcr_extend_payload(alg_id: u16, digest: &[u8; SHA256_LEN]) -> (r: [u8; PCR_EXTEND_PARM_LEN])
    requires
        alg_id == ALG_SHA256,
    ensures
        r@.len() == PCR_EXTEND_PARM_LEN,
        spec_be32_at(r@, 0) == 1u32,
        spec_be16_at(r@, 4) == alg_id,
        forall|k: int| #![trigger r@[6 + k]] 0 <= k < SHA256_LEN ==> r@[6 + k] == digest@[k],
{
    let cnt = be32_bytes(1);
    let alg = be16_bytes(alg_id);

    let mut out = [0u8; PCR_EXTEND_PARM_LEN];
    out[0] = cnt[0];
    out[1] = cnt[1];
    out[2] = cnt[2];
    out[3] = cnt[3];
    out[4] = alg[0];
    out[5] = alg[1];

    // 循环只写偏移 6 及以后，前缀两个字段原样保留。不变式按字节写而不是
    // 直接背着两条大端等式走：前缀不变这件事是逐字节的，让求解器每轮重新
    // 拆一次大端定义没有必要，收尾时拆一次就够。
    let mut i: usize = 0;
    while i < SHA256_LEN
        invariant
            i <= SHA256_LEN,
            cnt@.len() == 4,
            alg@.len() == 2,
            spec_be32_at(cnt@, 0) == 1u32,
            spec_be16_at(alg@, 0) == alg_id,
            out@.len() == PCR_EXTEND_PARM_LEN,
            out@[0] == cnt@[0],
            out@[1] == cnt@[1],
            out@[2] == cnt@[2],
            out@[3] == cnt@[3],
            out@[4] == alg@[0],
            out@[5] == alg@[1],
            forall|k: int| #![trigger out@[6 + k]] 0 <= k < i ==> out@[6 + k] == digest@[k],
        decreases SHA256_LEN - i,
    {
        out[6 + i] = *array_index_get(digest, i);
        i = i + 1;
    }

    proof {
        assert(spec_be32_at(out@, 0) == spec_be32_at(cnt@, 0));
        assert(spec_be16_at(out@, 4) == spec_be16_at(alg@, 0));
    }

    out
}

/// `TPM2_GetCapability` 载荷（Part 3 §30.2）。
///
/// ```text
/// capability     u32
/// property       u32
/// propertyCount  u32
/// ```
pub fn get_capability_payload(capability: u32, property: u32, count: u32) -> (r: [u8; 12])
    ensures
        r@.len() == 12,
        spec_be32_at(r@, 0) == capability,
        spec_be32_at(r@, 4) == property,
        spec_be32_at(r@, 8) == count,
{
    let a = be32_bytes(capability);
    let b = be32_bytes(property);
    let c = be32_bytes(count);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3]]
}

/// `TPM2_GetRandom` 载荷（Part 3 §16.1）。
///
/// 上限在类型层面挡住：一次要不到超过 `MAX_RNG_DATA` 的量，
/// 调用方必须自己分批，而不是指望对端截断。
pub fn get_random_payload(bytes_requested: u16) -> (r: [u8; 2])
    requires
        bytes_requested > 0,
        bytes_requested <= MAX_RNG_DATA,
    ensures
        r@.len() == 2,
        spec_be16_at(r@, 0) == bytes_requested,
{
    be16_bytes(bytes_requested)
}

/// `TPM2_Shutdown` 载荷（Part 3 §9.4）。
pub fn shutdown_payload(shutdown_type: u16) -> (r: [u8; 2])
    requires
        shutdown_type == SU_CLEAR || shutdown_type == SU_STATE,
    ensures
        r@.len() == 2,
        spec_be16_at(r@, 0) == shutdown_type,
{
    be16_bytes(shutdown_type)
}

/// `TPM2_FlushContext` 载荷（Part 3 §28.4）。句柄在头部之后、无授权区。
pub fn flush_context_payload(handle: u32) -> (r: [u8; 4])
    ensures
        r@.len() == 4,
        spec_be32_at(r@, 0) == handle,
{
    be32_bytes(handle)
}

} // verus!