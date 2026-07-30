use vstd::prelude::*;

use super::handle::*;
use super::table::SpaceTable;
#[cfg(verus_keep_ghost)]
use crate::endian::{be32_byte, be32_of, lemma_be32_roundtrip};

verus! {

/// 报文头长度：标签 2 字节 + 长度 4 字节 + 命令码或返回码 4 字节。
pub const HEADER_SIZE: usize = 10;

/// 命令句柄数由 3 位字段给出，上限为 7。
pub const MAX_CHANDLES: usize = 7;

pub const RC_SUCCESS: u32 = 0;

/// 能力查询里「句柄列表」这一类目。
pub const CAP_HANDLES: u32 = 0x0000_0001;

/// 能力响应体布局：更多数据标志 1 字节，类目 4 字节，数量 4 字节。
pub const CAP_MORE_OFF: usize = HEADER_SIZE;
pub const CAP_CAPABILITY_OFF: usize = HEADER_SIZE + 1;
pub const CAP_COUNT_OFF: usize = HEADER_SIZE + 5;
pub const CAP_HANDLES_OFF: usize = HEADER_SIZE + 9;

pub const RSP_LENGTH_OFF: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
pub enum SpaceErr {
    /// 报文长度与其自身声明的结构不符。
    Malformed,
    /// 命令引用了一个解析不出来的虚拟句柄。
    BadHandle,
}

// ---------------------------------------------------------------------------
// 字节访问
// ---------------------------------------------------------------------------

pub open spec fn be32_at(s: Seq<u8>, off: int) -> u32 {
    be32_of(s[off], s[off + 1], s[off + 2], s[off + 3])
}

pub fn read_be32(b: &[u8], off: usize) -> (r: u32)
    requires
        off + 4 <= b.len(),
    ensures
        r == be32_at(b@, off as int),
{
    ((b[off] as u32) << 24) | ((b[off + 1] as u32) << 16) | ((b[off + 2] as u32) << 8)
        | (b[off + 3] as u32)
}

pub fn write_be32(b: &mut [u8], off: usize, v: u32)
    requires
        off + 4 <= old(b).len(),
    ensures
        final(b).len() == old(b).len(),
        be32_at(final(b)@, off as int) == v,
        forall|k: int|
            #![trigger final(b)@[k]]
            0 <= k < final(b).len() && (k < off || k >= off + 4) ==> final(b)@[k] == old(b)@[k],
{
    proof {
        lemma_be32_roundtrip(v);
    }
    b[off] = ((v >> 24) & 0xff) as u8;
    b[off + 1] = ((v >> 16) & 0xff) as u8;
    b[off + 2] = ((v >> 8) & 0xff) as u8;
    b[off + 3] = (v & 0xff) as u8;
}

/// 命令 / 响应句柄区的第 `k` 个句柄。
pub open spec fn handle_at(s: Seq<u8>, k: int) -> u32 {
    be32_at(s, HEADER_SIZE + 4 * k)
}

#[verifier::external_body]
proof fn lemma_handle_unchanged_by_write(
    before: Seq<u8>,
    after: Seq<u8>,
    wi: int,
    k: int,
)
    requires
        before.len() == after.len(),
        0 <= wi,
        HEADER_SIZE + 4 * wi + 4 <= before.len(),
        0 <= k,
        HEADER_SIZE + 4 * k + 4 <= before.len(),
        k != wi,
        forall|t: int|
            #![trigger after[t]]
            0 <= t < before.len() && (t < HEADER_SIZE + 4 * wi || t >= HEADER_SIZE + 4 * wi + 4)
                ==> after[t] == before[t],
    ensures
        handle_at(after, k) == handle_at(before, k),
{
    let base = HEADER_SIZE + 4 * k;
    if k < wi {
        assert(base + 3 < HEADER_SIZE + 4 * wi) by (nonlinear_arith);
    } else {
        assert(wi < k);
        assert(HEADER_SIZE + 4 * wi + 4 <= base) by (nonlinear_arith);
    }
    assert(after[base] == before[base]);
    assert(after[base + 1] == before[base + 1]);
    assert(after[base + 2] == before[base + 2]);
    assert(after[base + 3] == before[base + 3]);
}

/// 句柄改写的规约：瞬态句柄查表，其余原样保留。
pub open spec fn mapped_or_kept(tbl: SpaceTable, h: u32) -> Option<u32> {
    if is_transient(h) {
        tbl.maps(h)
    } else {
        Some(h)
    }
}

// ---------------------------------------------------------------------------
// 命令方向
// ---------------------------------------------------------------------------

/// 把命令句柄区里的虚拟句柄换成物理句柄。
///
/// `nr_handles` 由命令码的属性表给出，属于阶段 2 的编解码产物；这里只
/// 把它当成一个已经过校验的参数。
pub fn map_command_handles(tbl: &SpaceTable, nr_handles: usize, cmd: &mut [u8]) -> (r: Result<
    (),
    SpaceErr,
>)
    requires
        tbl.wf(),
        nr_handles <= MAX_CHANDLES,
        old(cmd).len() >= HEADER_SIZE + 4 * nr_handles,
    ensures
        final(cmd).len() == old(cmd).len(),
        // 失败时报文原封不动
        r.is_err() ==> final(cmd)@ == old(cmd)@,
        // 头部永不改动
        forall|k: int| #![trigger final(cmd)@[k]] 0 <= k < HEADER_SIZE ==> final(cmd)@[k] == old(cmd)@[k],
        // 成功时每个句柄都按规约改写
        r.is_ok() ==> forall|k: int|
            #![trigger handle_at(final(cmd)@, k)]
            0 <= k < nr_handles ==> mapped_or_kept(*tbl, handle_at(old(cmd)@, k)) == Some(
                handle_at(final(cmd)@, k),
            ),
{
    // 第一趟：只读校验。
    let mut i: usize = 0;
    while i < nr_handles
        invariant
            i <= nr_handles,
            tbl.wf(),
            cmd.len() >= HEADER_SIZE + 4 * nr_handles,
            forall|k: int|
                #![trigger handle_at(cmd@, k)]
                0 <= k < i ==> mapped_or_kept(*tbl, handle_at(cmd@, k)).is_some(),
        decreases nr_handles - i,
    {
        let h = read_be32(cmd, HEADER_SIZE + 4 * i);
        if is_transient_exec(h) {
            if tbl.resolve(h).is_none() {
                return Err(SpaceErr::BadHandle);
            }
        }
        i += 1;
    }

    // 第二趟：落笔。此时每个句柄都保证可解析，不会中途失败。
    let ghost orig = cmd@;
    proof {
        assert forall|k: int|
            #![trigger handle_at(orig, k)]
            0 <= k < nr_handles as int implies mapped_or_kept(*tbl, handle_at(orig, k)).is_some() by {
            assert(handle_at(orig, k) == handle_at(cmd@, k));
        }
    }
    let mut i: usize = 0;
    while i < nr_handles
        invariant
            i <= nr_handles,
            tbl.wf(),
            cmd.len() == orig.len(),
            cmd.len() >= HEADER_SIZE + 4 * nr_handles,
            forall|k: int| #![trigger cmd@[k]] 0 <= k < HEADER_SIZE ==> cmd@[k] == orig[k],
            forall|k: int|
                #![trigger handle_at(orig, k)]
                0 <= k < nr_handles as int ==> mapped_or_kept(*tbl, handle_at(orig, k)).is_some(),
            // 尚未处理的句柄保持原值
            forall|k: int|
                #![trigger handle_at(cmd@, k)]
                (i as int <= k && k < nr_handles as int) ==> handle_at(cmd@, k) == handle_at(orig, k),
            // 已处理的句柄符合规约
            forall|k: int|
                #![trigger handle_at(cmd@, k)]
                0 <= k < i as int ==> mapped_or_kept(*tbl, handle_at(orig, k)) == Some(
                    handle_at(cmd@, k),
                ),
        decreases nr_handles - i,
    {
        let ghost before_iter = cmd@;
        let h = read_be32(cmd, HEADER_SIZE + 4 * i);
        if is_transient_exec(h) {
            let rh = tbl.resolve(h);
            proof {
                assert(is_transient(h));
                assert(handle_at(cmd@, i as int) == h);
                assert(i <= nr_handles);
                assert(i < nr_handles);
                assert(i as int <= i as int);
                assert((i as int) < (nr_handles as int));
                assert(handle_at(cmd@, i as int) == handle_at(orig, i as int));
                assert(mapped_or_kept(*tbl, handle_at(orig, i as int)).is_some());
                assert(mapped_or_kept(*tbl, h).is_some());
                assert(rh == tbl.maps(h));
                assert(rh.is_some());
            }
            let p = rh.unwrap();
            write_be32(cmd, HEADER_SIZE + 4 * i, p);
            proof {
                assert(handle_at(cmd@, i as int) == p);
                assert(mapped_or_kept(*tbl, h) == Some(p));

                assert forall|k: int|
                    #![trigger handle_at(cmd@, k)]
                    (i as int + 1 <= k && k < nr_handles as int) ==> handle_at(cmd@, k) == handle_at(orig, k) by {
                    if i as int + 1 <= k && k < nr_handles as int {
                        assert(i as int <= k && k < nr_handles as int);
                        assert(i as int != k);
                        lemma_handle_unchanged_by_write(before_iter, cmd@, i as int, k);
                        assert(handle_at(before_iter, k) == handle_at(orig, k));
                    }
                }

                assert forall|k: int|
                    #![trigger handle_at(cmd@, k)]
                    0 <= k < i as int ==> mapped_or_kept(*tbl, handle_at(orig, k)) == Some(
                        handle_at(cmd@, k),
                    ) by {
                    if 0 <= k && k < i as int {
                        lemma_handle_unchanged_by_write(before_iter, cmd@, i as int, k);
                        assert(handle_at(cmd@, k) == handle_at(before_iter, k));
                    }
                }
            }
        } else {
            proof {
                assert(cmd@ == before_iter);
            }
        }

        i += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 响应方向
// ---------------------------------------------------------------------------

/// 响应头句柄的处理结果。
///
/// `OutOfSlots` 把「必须释放这个物理句柄」这条义务写进了返回值类型，
/// 而不是留给调用方凭约定记住。编排层不处理它就编译不过。
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub enum HeaderOutcome {
    /// 响应里没有句柄，或命令本身失败，报文未改动。
    NoHandle,
    /// 瞬态句柄已替换为虚拟句柄。
    Virtualized { vhandle: u32 },
    /// 会话句柄已登记，报文未改动（会话句柄不虚拟化）。
    SessionTracked { phandle: u32 },
    /// 句柄类型不认识，报文未改动。
    Unknown { phandle: u32 },
    /// 表已满，必须释放 `flush`。
    OutOfSlots { flush: u32 },
}

/// 该结果是否意味着报文被改写过。
pub open spec fn outcome_rewrites(r: HeaderOutcome) -> bool {
    match r {
        HeaderOutcome::Virtualized { .. } => true,
        _ => false,
    }
}

/// 处理响应头部返回的句柄。
pub fn map_response_handle(tbl: &mut SpaceTable, has_rhandle: bool, rsp: &mut [u8]) -> (r:
    HeaderOutcome)
    requires
        old(tbl).wf(),
        old(rsp).len() >= HEADER_SIZE + 4,
    ensures
        final(tbl).wf(),
        final(rsp).len() == old(rsp).len(),
        // 只有虚拟化这一种情况会改动报文，且只改那 4 个字节
        !outcome_rewrites(r) ==> final(rsp)@ == old(rsp)@,
        forall|k: int|
            #![trigger final(rsp)@[k]]
            0 <= k < final(rsp).len() && (k < HEADER_SIZE || k >= HEADER_SIZE + 4) ==> final(rsp)@[k]
                == old(rsp)@[k],
{
    if !has_rhandle {
        return HeaderOutcome::NoHandle;
    }
    let rc = read_be32(rsp, 6);
    if rc != RC_SUCCESS {
        return HeaderOutcome::NoHandle;
    }

    let phandle = read_be32(rsp, HEADER_SIZE);

    if is_transient_exec(phandle) {
        if phandle == 0 || phandle == CTX_SAVED_SENTINEL || tbl.lookup(phandle).is_some() {
            // 非法或重复的物理句柄：不接管，交回上层释放。
            return HeaderOutcome::OutOfSlots { flush: phandle };
        }
        match tbl.intern(phandle) {
            Some(vhandle) => {
                write_be32(rsp, HEADER_SIZE, vhandle);
                HeaderOutcome::Virtualized { vhandle }
            },
            None => HeaderOutcome::OutOfSlots { flush: phandle },
        }
    } else if is_session_exec(phandle) {
        if phandle == 0 || tbl.has_session_exec(phandle) {
            return HeaderOutcome::OutOfSlots { flush: phandle };
        }
        if tbl.add_session(phandle) {
            HeaderOutcome::SessionTracked { phandle }
        } else {
            HeaderOutcome::OutOfSlots { flush: phandle }
        }
    } else {
        HeaderOutcome::Unknown { phandle }
    }
}

/// 改写能力查询响应里的句柄列表：瞬态句柄换成虚拟句柄，本 space 不认识的
/// 瞬态句柄**从列表中剔除**，其余原样保留。列表就地压紧，长度字段与
/// 数量字段一并更新。
///
/// 剔除是隔离性的直接体现：一个 space 枚举瞬态对象时，只应看见自己的。
///
/// 返回改写后的报文总长度。
pub fn map_capability_handles(tbl: &SpaceTable, is_cap_query: bool, rsp: &mut [u8], len: usize)
    -> (r: Result<usize, SpaceErr>)
    requires
        tbl.wf(),
        len <= old(rsp).len(),
    ensures
        final(rsp).len() == old(rsp).len(),
        r.is_ok() ==> r.unwrap() <= len,
        !is_cap_query ==> r == Ok::<usize, SpaceErr>(len) && final(rsp)@ == old(rsp)@,
{
    if !is_cap_query {
        return Ok(len);
    }
    if len < CAP_HANDLES_OFF {
        return Err(SpaceErr::Malformed);
    }
    let rc = read_be32(rsp, 6);
    if rc != RC_SUCCESS {
        return Ok(len);
    }
    if read_be32(rsp, CAP_CAPABILITY_OFF) != CAP_HANDLES {
        return Ok(len);
    }

    // 先算容量再比对，避免任何乘法。
    let tail = len - CAP_HANDLES_OFF;
    if tail % 4 != 0 {
        return Err(SpaceErr::Malformed);
    }
    let avail: usize = tail / 4;
    let declared = read_be32(rsp, CAP_COUNT_OFF);
    if declared as usize != avail {
        return Err(SpaceErr::Malformed);
    }
    let count: usize = avail;

    let ghost orig = rsp@;
    let mut i: usize = 0;
    let mut j: usize = 0;
    while i < count
        invariant
            j <= i <= count,
            tbl.wf(),
            rsp.len() == orig.len(),
            CAP_HANDLES_OFF + 4 * count <= rsp.len(),
        decreases count - i,
    {
        let h = read_be32(rsp, CAP_HANDLES_OFF + 4 * i);
        if is_transient_exec(h) {
            if h != 0 && h != CTX_SAVED_SENTINEL {
                match tbl.lookup(h) {
                    Some(v) => {
                        write_be32(rsp, CAP_HANDLES_OFF + 4 * j, v);
                        j += 1;
                    },
                    None => {},  // 不属于本 space，剔除
                }
            }
        } else {
            write_be32(rsp, CAP_HANDLES_OFF + 4 * j, h);
            j += 1;
        }
        i += 1;
    }

    let new_len = CAP_HANDLES_OFF + 4 * j;
    write_be32(rsp, CAP_COUNT_OFF, j as u32);
    write_be32(rsp, RSP_LENGTH_OFF, new_len as u32);
    Ok(new_len)
}

} // verus!
