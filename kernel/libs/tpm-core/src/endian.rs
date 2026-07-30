use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// 编码方向：整数 -> 字节序列
// ---------------------------------------------------------------------------

/// `v` 的大端序第 `i` 个字节（i ∈ [0,2)）。
pub open spec fn be16_byte(v: u16, i: int) -> u8 {
    if i == 0 {
        ((v >> 8) & 0xff) as u8
    } else {
        (v & 0xff) as u8
    }
}

/// `v` 的大端序第 `i` 个字节（i ∈ [0,4)）。
pub open spec fn be32_byte(v: u32, i: int) -> u8 {
    if i == 0 {
        ((v >> 24) & 0xff) as u8
    } else if i == 1 {
        ((v >> 16) & 0xff) as u8
    } else if i == 2 {
        ((v >> 8) & 0xff) as u8
    } else {
        (v & 0xff) as u8
    }
}

/// `u16 -> [u8; 2]` 的规约。用 `Seq::new` 而非 `seq![..]`，
/// 这样 `be16_bytes(v)[k] == be16_byte(v, k)` 直接来自 vstd 公理。
pub open spec fn be16_bytes(v: u16) -> Seq<u8> {
    Seq::new(2, |i: int| be16_byte(v, i))
}

/// `u32 -> [u8; 4]` 的规约。
pub open spec fn be32_bytes(v: u32) -> Seq<u8> {
    Seq::new(4, |i: int| be32_byte(v, i))
}

// ---------------------------------------------------------------------------
// 解码方向：字节 -> 整数
// ---------------------------------------------------------------------------

pub open spec fn be16_of(b0: u8, b1: u8) -> u16 {
    ((b0 as u16) << 8) | (b1 as u16)
}

pub open spec fn be32_of(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
}

// ---------------------------------------------------------------------------
// 往返一致性（指南阶段 1 待证不变量之一：u32 -> be bytes -> u32 恒等）
// ---------------------------------------------------------------------------

pub proof fn lemma_be16_roundtrip(v: u16)
    ensures
        be16_of(be16_byte(v, 0), be16_byte(v, 1)) == v,
{
    let b0 = ((v >> 8) & 0xff) as u8;
    let b1 = (v & 0xff) as u8;
    assert(((b0 as u16) << 8) | (b1 as u16) == v) by (bit_vector)
        requires
            b0 == ((v >> 8) & 0xff) as u8,
            b1 == (v & 0xff) as u8,
    ;
}

pub proof fn lemma_be32_roundtrip(v: u32)
    ensures
        be32_of(be32_byte(v, 0), be32_byte(v, 1), be32_byte(v, 2), be32_byte(v, 3)) == v,
{
    let b0 = ((v >> 24) & 0xff) as u8;
    let b1 = ((v >> 16) & 0xff) as u8;
    let b2 = ((v >> 8) & 0xff) as u8;
    let b3 = (v & 0xff) as u8;
    assert(((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32) == v)
        by (bit_vector)
        requires
            b0 == ((v >> 24) & 0xff) as u8,
            b1 == ((v >> 16) & 0xff) as u8,
            b2 == ((v >> 8) & 0xff) as u8,
            b3 == (v & 0xff) as u8,
    ;
}

/// 反方向：先解码再编码，还原出原来的字节。
/// 解析路径（阶段 2 的响应解码）会用到。
pub proof fn lemma_be32_of_roundtrip(b0: u8, b1: u8, b2: u8, b3: u8)
    ensures
        be32_byte(be32_of(b0, b1, b2, b3), 0) == b0,
        be32_byte(be32_of(b0, b1, b2, b3), 1) == b1,
        be32_byte(be32_of(b0, b1, b2, b3), 2) == b2,
        be32_byte(be32_of(b0, b1, b2, b3), 3) == b3,
{
    let v = ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
    assert(((v >> 24) & 0xff) as u8 == b0) by (bit_vector)
        requires v == ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
    assert(((v >> 16) & 0xff) as u8 == b1) by (bit_vector)
        requires v == ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
    assert(((v >> 8) & 0xff) as u8 == b2) by (bit_vector)
        requires v == ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
    assert((v & 0xff) as u8 == b3) by (bit_vector)
        requires v == ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
}

// ---------------------------------------------------------------------------
// exec 侧：与规约逐字对应，无 external_body
// ---------------------------------------------------------------------------

pub fn be16_of_exec(b0: u8, b1: u8) -> (r: u16)
    ensures
        r == be16_of(b0, b1),
{
    ((b0 as u16) << 8) | (b1 as u16)
}

pub fn be32_of_exec(b0: u8, b1: u8, b2: u8, b3: u8) -> (r: u32)
    ensures
        r == be32_of(b0, b1, b2, b3),
{
    ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
}

} // verus!
