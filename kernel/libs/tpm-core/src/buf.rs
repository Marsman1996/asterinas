//! 定长命令缓冲区。
//!
//! yufan：**本类型当前不在命令拼装路径上。** 引导阶段的命令由 `boot` 就地写进
//! 自己的定长暂存区,带授权的命令由 `secure::CmdLayout` 描述分区,两条路
//! 都不经过这里。它保留下来是因为「先写载荷、再回填长度」这种拼装方式
//! 迟早会有需要,而不是因为有现成的调用方。
//!
//! 因此在给它找到确定用途之前,新命令请照着上述两条路写,不要以它为样板:
//! 它的错误模型是 `overflow` / `boundary_error` 两个粘滞标志、末尾统一收,
//! 与其余各层就地返回 `Result` 的做法不是一回事;字节序也走 `endian`
//! 而非 `cursor`。两种做法并存已经够了,不宜再多一处。
use vstd::prelude::*;
use vstd::array::*;
use vstd::slice::*;

use crate::endian::*;
use crate::types::TpmTag;

verus! {

/// `struct tpm_header` 的大小：tag(2) + length(4) + ordinal/return_code(4)。
pub const TPM_HEADER_SIZE: usize = 10;

/// TPM2B 首部：仅一个 16 位 size 字段。
pub const TPM2B_HEADER_SIZE: usize = 2;

// ===========================================================================
// 圈层 B：存储获取（唯一的 external_body）
// ===========================================================================

/// 内核胶水层应把它重新实现为页分配并 **Box 化**，避免 4 KiB 落在内核栈上；
/// 这里的默认实现只用于 host 侧差分测试。
#[verifier::external_body]
pub fn alloc_zeroed_storage<const N: usize>() -> (r: [u8; N])
    ensures
        r@.len() == N,
        forall|i: int| 0 <= i < N ==> r@[i] == 0u8,
{
    [0u8; N]
}

// ===========================================================================
// 缓冲区
// ===========================================================================

/// 它与 `overflow`/`boundary_error` 的区别在于：种类在构造时确定、此后不变，
#[derive(Clone, Copy)]
pub enum BufKind {
    /// 普通命令缓冲区，首部为 `struct tpm_header`
    Command,
    /// TPM2B 缓冲区，首部为 2 字节 size
    Tpm2b,
}

pub struct TpmBuf<const N: usize> {
    pub data: [u8; N],
    pub length: usize,
    pub kind: BufKind,
    pub overflow: bool,
    pub boundary_error: bool,
    pub handles: u8,
}

impl<const N: usize> TpmBuf<N> {
    // -----------------------------------------------------------------
    // 规约层
    // -----------------------------------------------------------------

    pub closed spec fn spec_is_tpm2b(self) -> bool {
        match self.kind {
            BufKind::Tpm2b => true,
            BufKind::Command => false,
        }
    }

    /// 首部长度：TPM2B 为 2，命令为 10。
    pub open spec fn hdr_len(self) -> int {
        if self.spec_is_tpm2b() {
            TPM2B_HEADER_SIZE as int
        } else {
            TPM_HEADER_SIZE as int
        }
    }

    /// 缓冲区**自身字节里编码的**总长度。
    /// 注意 TPM2B 的 size 字段不含它自己的 2 字节，故 `+2`。
    pub open spec fn encoded_len(self) -> int {
        if self.spec_is_tpm2b() {
            be16_of(self.data@[0], self.data@[1]) as int + 2
        } else {
            be32_of(self.data@[2], self.data@[3], self.data@[4], self.data@[5]) as int
        }
    }

    /// 核心不变量。
    pub open spec fn wf(self) -> bool {
        &&& self.data@.len() == N
        &&& self.hdr_len() <= N as int
        &&& N as int <= 0xffff
        &&& self.hdr_len() <= self.length as int
        &&& self.length as int <= N as int
        &&& self.encoded_len() == self.length as int
    }

    /// 首部之后的有效载荷。
    pub open spec fn payload(self) -> Seq<u8> {
        self.data@.subrange(self.hdr_len(), self.length as int)
    }

    /// 会真正交给硬件的线上字节序列。
    pub open spec fn wire(self) -> Seq<u8> {
        self.data@.subrange(0, self.length as int)
    }

    pub open spec fn spec_len(self) -> int {
        self.length as int
    }

    pub open spec fn spec_overflow(self) -> bool {
        self.overflow
    }

    pub open spec fn spec_boundary_error(self) -> bool {
        self.boundary_error
    }

    pub open spec fn spec_handles(self) -> int {
        self.handles as int
    }

    /// 「内容完全没变」——用于表达 no-op 与只读操作。
    pub open spec fn content_eq(self, other: TpmBuf<N>) -> bool {
        &&& self.data@ =~= other.data@
        &&& self.length == other.length
        &&& self.spec_is_tpm2b() == other.spec_is_tpm2b()
        &&& self.handles == other.handles
    }

    /// 从 `offset` 起还能安全读出 `count` 字节。
    pub open spec fn can_read(self, offset: int, count: int) -> bool {
        &&& !self.boundary_error
        &&& 0 <= offset
        &&& offset + count <= self.length as int
    }

    // -----------------------------------------------------------------
    // 内部：定点写入
    // -----------------------------------------------------------------

    fn put_be16(&mut self, at: usize, v: u16)
        requires
            old(self).data@.len() == N,
            at + 2 <= N,
        ensures
            final(self).data@.len() == N,
            final(self).data@[at as int] == be16_byte(v, 0),
            final(self).data@[at as int + 1] == be16_byte(v, 1),
            forall|i: int|
                0 <= i < N && !(at <= i < at + 2) ==> final(self).data@[i] == old(self).data@[i],
            final(self).length == old(self).length,
            final(self).kind == old(self).kind,
            final(self).overflow == old(self).overflow,
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
    {
        self.data[at] = ((v >> 8) & 0xff) as u8;
        self.data[at + 1] = (v & 0xff) as u8;
    }

    fn put_be32(&mut self, at: usize, v: u32)
        requires
            old(self).data@.len() == N,
            at + 4 <= N,
        ensures
            final(self).data@.len() == N,
            final(self).data@[at as int] == be32_byte(v, 0),
            final(self).data@[at as int + 1] == be32_byte(v, 1),
            final(self).data@[at as int + 2] == be32_byte(v, 2),
            final(self).data@[at as int + 3] == be32_byte(v, 3),
            forall|i: int|
                0 <= i < N && !(at <= i < at + 4) ==> final(self).data@[i] == old(self).data@[i],
            final(self).length == old(self).length,
            final(self).kind == old(self).kind,
            final(self).overflow == old(self).overflow,
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
    {
        self.data[at] = ((v >> 24) & 0xff) as u8;
        self.data[at + 1] = ((v >> 16) & 0xff) as u8;
        self.data[at + 2] = ((v >> 8) & 0xff) as u8;
        self.data[at + 3] = (v & 0xff) as u8;
    }

    /// 把 `self.length` 回写进首部的长度字段。
    fn sync_length(&mut self)
        requires
            old(self).data@.len() == N,
            old(self).hdr_len() <= N as int,
            N as int <= 0xffff,
            old(self).hdr_len() <= old(self).length as int,
            old(self).length as int <= N as int,
        ensures
            final(self).wf(),
            final(self).length == old(self).length,
            final(self).kind == old(self).kind,
            final(self).overflow == old(self).overflow,
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
            forall|i: int|
                old(self).hdr_len() <= i < N ==> final(self).data@[i] == old(self).data@[i],
    {
        match self.kind {
            BufKind::Tpm2b => {
                // length >= 2 由前置条件保证，故减法不下溢；
                // length <= N <= 0xffff 故转 u16 无截断。
                let sz: u16 = (self.length - TPM2B_HEADER_SIZE) as u16;
                self.put_be16(0, sz);
                proof {
                    lemma_be16_roundtrip(sz);
                }
            },
            BufKind::Command => {
                let l: u32 = self.length as u32;
                self.put_be32(2, l);
                proof {
                    lemma_be32_roundtrip(l);
                }
            },
        }
    }

    // -----------------------------------------------------------------
    // 构造与复位
    // -----------------------------------------------------------------

    /// 对应 `tpm_buf_reset()`：在既有存储上原地初始化一条命令。
    pub fn reset_command(&mut self, tag: TpmTag, ordinal: u32)
        requires
            old(self).data@.len() == N,
            TPM_HEADER_SIZE <= N,
            N as int <= 0xffff,
        ensures
            final(self).wf(),
            !final(self).spec_is_tpm2b(),
            final(self).length == TPM_HEADER_SIZE,
            final(self).payload() =~= Seq::<u8>::empty(),
            !final(self).overflow,
            !final(self).boundary_error,
            final(self).handles == 0,
            be16_of(final(self).data@[0], final(self).data@[1]) == tag.spec_code(),
            be32_of(
                final(self).data@[6],
                final(self).data@[7],
                final(self).data@[8],
                final(self).data@[9],
            ) == ordinal,
    {
        self.kind = BufKind::Command;
        self.overflow = false;
        self.boundary_error = false;
        self.handles = 0;
        self.length = TPM_HEADER_SIZE;

        let t = tag.code();
        self.put_be16(0, t);
        self.put_be32(2, TPM_HEADER_SIZE as u32);
        self.put_be32(6, ordinal);

        proof {
            lemma_be16_roundtrip(t);
            lemma_be32_roundtrip(TPM_HEADER_SIZE as u32);
            lemma_be32_roundtrip(ordinal);
        }
    }

    /// 对应 `tpm_buf_reset_sized()`。
    pub fn reset_sized(&mut self)
        requires
            old(self).data@.len() == N,
            TPM2B_HEADER_SIZE <= N,
            N as int <= 0xffff,
        ensures
            final(self).wf(),
            final(self).spec_is_tpm2b(),
            final(self).length == TPM2B_HEADER_SIZE,
            final(self).payload() =~= Seq::<u8>::empty(),
            !final(self).overflow,
            !final(self).boundary_error,
            final(self).handles == 0,
    {
        self.kind = BufKind::Tpm2b;
        self.overflow = false;
        self.boundary_error = false;
        self.handles = 0;
        self.length = TPM2B_HEADER_SIZE;

        self.put_be16(0, 0u16);
        proof {
            lemma_be16_roundtrip(0u16);
        }
    }

    /// 对应 `tpm_buf_init()`：分配 + 初始化。
    pub fn new_command(tag: TpmTag, ordinal: u32) -> (r: Self)
        requires
            TPM_HEADER_SIZE <= N,
            N as int <= 0xffff,
        ensures
            r.wf(),
            !r.spec_is_tpm2b(),
            r.length == TPM_HEADER_SIZE,
            r.payload() =~= Seq::<u8>::empty(),
            !r.overflow,
            !r.boundary_error,
            r.handles == 0,
    {
        let mut buf = TpmBuf {
            data: alloc_zeroed_storage::<N>(),
            length: 0,
            kind: BufKind::Command,
            overflow: false,
            boundary_error: false,
            handles: 0,
        };
        buf.reset_command(tag, ordinal);
        buf
    }

    /// 对应 `tpm_buf_init_sized()`。
    pub fn new_sized() -> (r: Self)
        requires
            TPM2B_HEADER_SIZE <= N,
            N as int <= 0xffff,
        ensures
            r.wf(),
            r.spec_is_tpm2b(),
            r.length == TPM2B_HEADER_SIZE,
            r.payload() =~= Seq::<u8>::empty(),
            !r.overflow,
            !r.boundary_error,
            r.handles == 0,
    {
        let mut buf = TpmBuf {
            data: alloc_zeroed_storage::<N>(),
            length: 0,
            kind: BufKind::Tpm2b,
            overflow: false,
            boundary_error: false,
            handles: 0,
        };
        buf.reset_sized();
        buf
    }

    // `tpm_buf_destroy()` 无对应物：所有权与 Drop 自动处理。

    // -----------------------------------------------------------------
    // 写入
    // -----------------------------------------------------------------

    /// 对应 `tpm_buf_append()`。
    pub fn append(&mut self, src: &[u8])
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).spec_is_tpm2b() == old(self).spec_is_tpm2b(),
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
            // (1) 已溢出：完全 no-op
            old(self).overflow ==> (final(self).overflow && final(self).content_eq(*old(self))),
            // (2) 装得下：内容追加，长度字段同步
            (!old(self).overflow && src@.len() + old(self).length as int <= N as int) ==> (
                !final(self).overflow
                && final(self).length as int == old(self).length as int + src@.len()
                && final(self).payload() =~= old(self).payload() + src@
            ),
            // (3) 装不下：置标志，一字节不改
            (!old(self).overflow && src@.len() + old(self).length as int > N as int) ==> (
                final(self).overflow && final(self).content_eq(*old(self))
            ),
    {
        if self.overflow {
            return;
        }
        let avail: usize = N - self.length;
        if src.len() > avail {
            self.overflow = true;
            return;
        }

        let start: usize = self.length;
        let ghost old_data = self.data@;
        let ghost n_src = src@.len();

        let mut i: usize = 0;
        while i < src.len()
            invariant
                i <= src.len(),
                src@.len() == n_src,
                start == old(self).length,
                start as int + n_src <= N as int,
                self.data@.len() == N,
                self.length == start,
                self.kind == old(self).kind,
                self.overflow == false,
                self.boundary_error == old(self).boundary_error,
                self.handles == old(self).handles,
                old_data =~= old(self).data@,
                forall|j: int| 0 <= j < i ==> self.data@[start + j] == src@[j],
                forall|j: int| #![auto]
                    0 <= j < N && !(start <= j < start + n_src) ==> self.data@[j] == old_data[j],
            decreases src.len() - i,
        {
            let b: u8 = *slice_index_get(src, i);
            self.data[start + i] = b;
            i = i + 1;
        }

        self.length = start + src.len();
        self.sync_length();

        proof {
            // payload 起点在 hdr_len，sync_length 只动 [0, hdr_len)，
            // 循环只动 [start, start + n_src)，两段不交叠。
            assert(self.payload() =~= old(self).payload() + src@);
        }
    }

    pub fn append_u8(&mut self, v: u8)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).spec_is_tpm2b() == old(self).spec_is_tpm2b(),
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
            old(self).overflow ==> (final(self).overflow && final(self).content_eq(*old(self))),
            (!old(self).overflow && old(self).length as int + 1 <= N as int) ==> (
                !final(self).overflow
                && final(self).length as int == old(self).length as int + 1
                && final(self).payload() =~= old(self).payload().push(v)
            ),
            (!old(self).overflow && old(self).length as int + 1 > N as int) ==> (
                final(self).overflow && final(self).content_eq(*old(self))
            ),
    {
        if self.overflow {
            return;
        }
        if self.length >= N {
            self.overflow = true;
            return;
        }
        let start = self.length;
        self.data[start] = v;
        self.length = start + 1;
        self.sync_length();
        proof {
            assert(self.payload() =~= old(self).payload().push(v));
        }
    }

    pub fn append_u16(&mut self, v: u16)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).spec_is_tpm2b() == old(self).spec_is_tpm2b(),
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
            old(self).overflow ==> (final(self).overflow && final(self).content_eq(*old(self))),
            (!old(self).overflow && old(self).length as int + 2 <= N as int) ==> (
                !final(self).overflow
                && final(self).length as int == old(self).length as int + 2
                && final(self).payload() =~= old(self).payload() + be16_bytes(v)
            ),
            (!old(self).overflow && old(self).length as int + 2 > N as int) ==> (
                final(self).overflow && final(self).content_eq(*old(self))
            ),
    {
        if self.overflow {
            return;
        }
        if N - self.length < 2 {
            self.overflow = true;
            return;
        }
        let start = self.length;
        self.put_be16(start, v);
        self.length = start + 2;
        self.sync_length();
        proof {
            assert(self.payload() =~= old(self).payload() + be16_bytes(v));
        }
    }

    pub fn append_u32(&mut self, v: u32)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).spec_is_tpm2b() == old(self).spec_is_tpm2b(),
            final(self).boundary_error == old(self).boundary_error,
            final(self).handles == old(self).handles,
            old(self).overflow ==> (final(self).overflow && final(self).content_eq(*old(self))),
            (!old(self).overflow && old(self).length as int + 4 <= N as int) ==> (
                !final(self).overflow
                && final(self).length as int == old(self).length as int + 4
                && final(self).payload() =~= old(self).payload() + be32_bytes(v)
            ),
            (!old(self).overflow && old(self).length as int + 4 > N as int) ==> (
                final(self).overflow && final(self).content_eq(*old(self))
            ),
    {
        if self.overflow {
            return;
        }
        if N - self.length < 4 {
            self.overflow = true;
            return;
        }
        let start = self.length;
        self.put_be32(start, v);
        self.length = start + 4;
        self.sync_length();
        proof {
            assert(self.payload() =~= old(self).payload() + be32_bytes(v));
        }
    }

    /// 对应 `tpm_buf_append_handle()`。
    pub fn append_handle(&mut self, handle: u32) -> (r: bool)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).spec_is_tpm2b() == old(self).spec_is_tpm2b(),
            final(self).boundary_error == old(self).boundary_error,
            r ==> (
                !final(self).spec_is_tpm2b()
                && !final(self).overflow
                && final(self).handles == old(self).handles + 1
                && final(self).length as int == old(self).length as int + 4
                && final(self).payload() =~= old(self).payload() + be32_bytes(handle)
            ),
            !r ==> final(self).handles == old(self).handles,
    {
        if self.is_tpm2b() {
            return false;
        }
        if self.handles == 255 {
            return false;
        }
        if self.overflow {
            return false;
        }
        if N - self.length < 4 {
            self.overflow = true;
            return false;
        }
        self.append_u32(handle);
        self.handles = self.handles + 1;
        true
    }

    // -----------------------------------------------------------------
    // 读取
    // -----------------------------------------------------------------

    /// 对应 `tpm_buf_read_u8()`。
    pub fn read_u8(&mut self, offset: &mut usize) -> (r: u8)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).content_eq(*old(self)),
            final(self).overflow == old(self).overflow,
            old(self).can_read(*old(offset) as int, 1) ==> (
                !final(self).boundary_error
                && *final(offset) == *old(offset) + 1
                && r == final(self).data@[*old(offset) as int]
            ),
            !old(self).can_read(*old(offset) as int, 1) ==> (
                final(self).boundary_error && *final(offset) == *old(offset) && r == 0
            ),
    {
        if self.boundary_error {
            return 0;
        }
        if *offset > self.length || self.length - *offset < 1 {
            self.boundary_error = true;
            return 0;
        }
        let v = *array_index_get(&self.data, *offset);
        *offset = *offset + 1;
        v
    }

    /// 对应 `tpm_buf_read_u16()`。
    pub fn read_u16(&mut self, offset: &mut usize) -> (r: u16)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).content_eq(*old(self)),
            final(self).overflow == old(self).overflow,
            old(self).can_read(*old(offset) as int, 2) ==> (
                !final(self).boundary_error
                && *final(offset) == *old(offset) + 2
                && r == be16_of(
                    final(self).data@[*old(offset) as int],
                    final(self).data@[*old(offset) as int + 1],
                )
            ),
            !old(self).can_read(*old(offset) as int, 2) ==> (
                final(self).boundary_error && *final(offset) == *old(offset) && r == 0
            ),
    {
        if self.boundary_error {
            return 0;
        }
        if *offset > self.length || self.length - *offset < 2 {
            self.boundary_error = true;
            return 0;
        }
        let o = *offset;
        let b0 = *array_index_get(&self.data, o);
        let b1 = *array_index_get(&self.data, o + 1);
        *offset = o + 2;
        be16_of_exec(b0, b1)
    }

    /// 对应 `tpm_buf_read_u32()`。
    pub fn read_u32(&mut self, offset: &mut usize) -> (r: u32)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).content_eq(*old(self)),
            final(self).overflow == old(self).overflow,
            old(self).can_read(*old(offset) as int, 4) ==> (
                !final(self).boundary_error
                && *final(offset) == *old(offset) + 4
                && r == be32_of(
                    final(self).data@[*old(offset) as int],
                    final(self).data@[*old(offset) as int + 1],
                    final(self).data@[*old(offset) as int + 2],
                    final(self).data@[*old(offset) as int + 3],
                )
            ),
            !old(self).can_read(*old(offset) as int, 4) ==> (
                final(self).boundary_error && *final(offset) == *old(offset) && r == 0
            ),
    {
        if self.boundary_error {
            return 0;
        }
        if *offset > self.length || self.length - *offset < 4 {
            self.boundary_error = true;
            return 0;
        }
        let o = *offset;
        let b0 = *array_index_get(&self.data, o);
        let b1 = *array_index_get(&self.data, o + 1);
        let b2 = *array_index_get(&self.data, o + 2);
        let b3 = *array_index_get(&self.data, o + 3);
        *offset = o + 4;
        be32_of_exec(b0, b1, b2, b3)
    }

    // -----------------------------------------------------------------
    // 访问器（`&self`，无 old/final 之分）
    // -----------------------------------------------------------------

    /// 对应 `tpm_buf_length()`。
    pub fn len(&self) -> (r: usize)
        ensures
            r as int == self.spec_len(),
    {
        self.length
    }

    pub fn is_tpm2b(&self) -> (r: bool)
        ensures
            r == self.spec_is_tpm2b(),
    {
        match self.kind {
            BufKind::Tpm2b => true,
            BufKind::Command => false,
        }
    }

    pub fn has_overflow(&self) -> (r: bool)
        ensures
            r == self.spec_overflow(),
    {
        self.overflow
    }

    pub fn has_boundary_error(&self) -> (r: bool)
        ensures
            r == self.spec_boundary_error(),
    {
        self.boundary_error
    }

    pub fn handle_count(&self) -> (r: u8)
        ensures
            r as int == self.spec_handles(),
    {
        self.handles
    }

    /// 交给传输层的线上字节。**没有溢出时才有意义**，故要求 `!overflow`。
    pub fn as_wire(&self) -> (r: &[u8])
        requires
            self.wf(),
            !self.spec_overflow(),
        ensures
            r@ =~= self.wire(),
            r@.len() == self.spec_len(),
    {
        slice_subrange(array_as_slice(&self.data), 0, self.length)
    }
}

} // verus!