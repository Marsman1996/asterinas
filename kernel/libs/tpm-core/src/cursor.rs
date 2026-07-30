use vstd::prelude::*;
use vstd::slice::*;

verus! {

// ===================== 字节序规约 =====================
//
// 报文一律大端（TPM 2.0 Part 1, "Data Marshaling"）。这里给出**唯一权威**
// 的序列化规约，编码侧与解码侧都对照它证明，杜绝两处代码对字节序理解
// 不一致。若工程中已有统一的字节序规约模块，把这三个 spec fn 换成对该
// 模块的 re-export 即可，切勿并存两份定义。

/// 序列 `s` 中偏移 `i` 处的大端 u16。
pub open spec fn spec_be16_at(s: Seq<u8>, i: int) -> u16
    recommends
        0 <= i,
        i + 2 <= s.len(),
{
    (s[i] as u16 * 256 + s[i + 1] as u16) as u16
}

/// 序列 `s` 中偏移 `i` 处的大端 u32。
pub open spec fn spec_be32_at(s: Seq<u8>, i: int) -> u32
    recommends
        0 <= i,
        i + 4 <= s.len(),
{
    (s[i] as u32 * 16777216 + s[i + 1] as u32 * 65536 + s[i + 2] as u32 * 256 + s[i + 3] as u32)
        as u32
}

// ===================== 拆分-重组引理 =====================
//
// 编码侧把整数拆成字节，解码侧按上面的规约把字节重组回整数。两者互逆
// 是整个编解码层的地基，这里一次证清楚，之后所有命令构造直接引用。
//
// 拆分用除法与取余而非移位与掩码：在 u16/u32 上两者完全等价，而除法
// 形式留在整数理论内，不必让位向量求解器介入整条证明链。

pub proof fn lemma_be16_split(v: u16)
    ensures
        (((v / 256) as u8) as u16 * 256 + ((v % 256) as u8) as u16) as u16 == v,
{
    assert(v / 256 < 256) by (bit_vector);
    assert(v % 256 < 256) by (bit_vector);
    assert(v == (v / 256) * 256 + v % 256) by (bit_vector);
}

pub proof fn lemma_be32_split(v: u32)
    ensures
        (((v / 16777216) as u8) as u32 * 16777216 + (((v / 65536) % 256) as u8) as u32 * 65536 + ((
        (v / 256) % 256) as u8) as u32 * 256 + ((v % 256) as u8) as u32) as u32 == v,
{
    assert(v / 16777216 < 256) by (bit_vector);
    assert((v / 65536) % 256 < 256) by (bit_vector);
    assert((v / 256) % 256 < 256) by (bit_vector);
    assert(v % 256 < 256) by (bit_vector);
    assert(v == (v / 16777216) * 16777216 + ((v / 65536) % 256) * 65536 + ((v / 256) % 256) * 256
        + v % 256) by (bit_vector);
}

/// 整数 → 大端字节。与 `spec_be16_at` 互为逆运算。
pub fn be16_bytes(v: u16) -> (r: [u8; 2])
    ensures
        r@.len() == 2,
        r@[0] == (v / 256) as u8,
        r@[1] == (v % 256) as u8,
        spec_be16_at(r@, 0) == v,
{
    proof {
        lemma_be16_split(v);
    }
    [(v / 256) as u8, (v % 256) as u8]
}

/// 整数 → 大端字节。与 `spec_be32_at` 互为逆运算。
pub fn be32_bytes(v: u32) -> (r: [u8; 4])
    ensures
        r@.len() == 4,
        r@[0] == (v / 16777216) as u8,
        r@[1] == ((v / 65536) % 256) as u8,
        r@[2] == ((v / 256) % 256) as u8,
        r@[3] == (v % 256) as u8,
        spec_be32_at(r@, 0) == v,
{
    proof {
        lemma_be32_split(v);
    }
    [
        (v / 16777216) as u8,
        ((v / 65536) % 256) as u8,
        ((v / 256) % 256) as u8,
        (v % 256) as u8,
    ]
}

// ===================== 游标 =====================

/// 只读解析游标。字段公开，规约函数因此可以保持 `open`，
/// 跨模块推理时不必额外准备引理。
pub struct Cursor {
    pub pos: usize,
}

impl Cursor {
    /// 类型不变量：偏移不超过被解析序列的长度。
    pub open spec fn wf(self, len: nat) -> bool {
        self.pos <= len
    }

    /// 从当前位置起还能不能再取 `n` 字节。
    pub open spec fn can_read(self, len: nat, n: nat) -> bool {
        self.pos + n <= len
    }

    pub fn new() -> (r: Cursor)
        ensures
            r.pos == 0,
    {
        Cursor { pos: 0 }
    }

    /// 从指定偏移开始解析（用于跳过已由上层校验过的固定前缀）。
    pub fn at(pos: usize) -> (r: Cursor)
        ensures
            r.pos == pos,
    {
        Cursor { pos }
    }

    pub fn remaining(&self, data: &[u8]) -> (r: usize)
        requires
            self.wf(data@.len()),
        ensures
            r == data@.len() - self.pos,
    {
        data.len() - self.pos
    }

    /// 剩余字节是否恰好读完。用于"响应尾部不得有多余数据"这类检查。
    pub fn is_exhausted(&self, data: &[u8]) -> (r: bool)
        requires
            self.wf(data@.len()),
        ensures
            r == (self.pos == data@.len()),
    {
        self.pos == data.len()
    }

    pub fn read_u8(&mut self, data: &[u8]) -> (r: Option<u8>)
        requires
            old(self).wf(data@.len()),
        ensures
            final(self).wf(data@.len()),
            old(self).can_read(data@.len(), 1) ==> {
                &&& r == Some(data@[old(self).pos as int])
                &&& final(self).pos == old(self).pos + 1
            },
            !old(self).can_read(data@.len(), 1) ==> {
                &&& r == Option::<u8>::None
                &&& final(self).pos == old(self).pos
            },
    {
        if self.pos < data.len() {
            let v = data[self.pos];
            self.pos = self.pos + 1;
            Some(v)
        } else {
            None
        }
    }

    pub fn read_be16(&mut self, data: &[u8]) -> (r: Option<u16>)
        requires
            old(self).wf(data@.len()),
        ensures
            final(self).wf(data@.len()),
            old(self).can_read(data@.len(), 2) ==> {
                &&& r == Some(spec_be16_at(data@, old(self).pos as int))
                &&& final(self).pos == old(self).pos + 2
            },
            !old(self).can_read(data@.len(), 2) ==> {
                &&& r == Option::<u16>::None
                &&& final(self).pos == old(self).pos
            },
    {
        let n = data.len();
        if n >= 2 && self.pos <= n - 2 {
            let hi = data[self.pos];
            let lo = data[self.pos + 1];
            self.pos = self.pos + 2;
            Some(hi as u16 * 256 + lo as u16)
        } else {
            None
        }
    }

    pub fn read_be32(&mut self, data: &[u8]) -> (r: Option<u32>)
        requires
            old(self).wf(data@.len()),
        ensures
            final(self).wf(data@.len()),
            old(self).can_read(data@.len(), 4) ==> {
                &&& r == Some(spec_be32_at(data@, old(self).pos as int))
                &&& final(self).pos == old(self).pos + 4
            },
            !old(self).can_read(data@.len(), 4) ==> {
                &&& r == Option::<u32>::None
                &&& final(self).pos == old(self).pos
            },
    {
        let n = data.len();
        if n >= 4 && self.pos <= n - 4 {
            let b0 = data[self.pos];
            let b1 = data[self.pos + 1];
            let b2 = data[self.pos + 2];
            let b3 = data[self.pos + 3];
            self.pos = self.pos + 4;
            Some(b0 as u32 * 16777216 + b1 as u32 * 65536 + b2 as u32 * 256 + b3 as u32)
        } else {
            None
        }
    }

    /// 借出接下来的 `n` 字节。这是变长字段（`TPM2B`、PCR 选择位图）
    /// 唯一的取用方式——长度来自报文本身，因此边界检查必须在这里发生。
    pub fn read_bytes<'a>(&mut self, data: &'a [u8], n: usize) -> (r: Option<&'a [u8]>)
        requires
            old(self).wf(data@.len()),
        ensures
            final(self).wf(data@.len()),
            old(self).can_read(data@.len(), n as nat) ==> {
                &&& r matches Some(s)
                &&& s@ == data@.subrange(old(self).pos as int, old(self).pos + n)
                &&& s@.len() == n
                &&& final(self).pos == old(self).pos + n
            },
            !old(self).can_read(data@.len(), n as nat) ==> {
                &&& r is None
                &&& final(self).pos == old(self).pos
            },
    {
        let len = data.len();
        if n <= len && self.pos <= len - n {
            let start = self.pos;
            let end = self.pos + n;
            let s = slice_subrange(data, start, end);
            self.pos = end;
            Some(s)
        } else {
            None
        }
    }

    /// 跳过 `n` 字节。用于忽略当前阶段不关心但格式已知的字段。
    pub fn skip(&mut self, data: &[u8], n: usize) -> (r: bool)
        requires
            old(self).wf(data@.len()),
        ensures
            final(self).wf(data@.len()),
            r == old(self).can_read(data@.len(), n as nat),
            r ==> final(self).pos == old(self).pos + n,
            !r ==> final(self).pos == old(self).pos,
    {
        let len = data.len();
        if n <= len && self.pos <= len - n {
            self.pos = self.pos + n;
            true
        } else {
            false
        }
    }
}

// ===================== 辅助谓词 =====================

/// 切片中是否存在非零字节。
///
/// PCR 分配解析要靠它判断某个 bank 是否真的被分配（选择位图全零即未分配）。
pub fn any_nonzero(s: &[u8]) -> (r: bool)
    ensures
        r == exists|k: int| 0 <= k < s@.len() && s@[k] != 0,
{
    let n = s.len();
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n,
            n == s@.len(),
            forall|k: int| 0 <= k < i ==> s@[k] == 0,
        decreases n - i,
    {
        if s[i] != 0 {
            proof {
                assert(0 <= i < s@.len() && s@[i as int] != 0);
            }
            return true;
        }
        i = i + 1;
    }
    false
}

} // verus!
