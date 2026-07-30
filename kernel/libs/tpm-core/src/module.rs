use vstd::prelude::*;
use vstd::set::Set;

#[cfg(verus_keep_ghost)]
pub use crate::handle::{SLOTS, is_session, is_transient, valid_phandle};
#[cfg(not(verus_keep_ghost))]
pub use crate::handle::{
    SLOTS,
    is_session_exec as is_session,
    is_transient_exec as is_transient,
    valid_phandle_exec as valid_phandle,
};
pub use crate::rewrite::{HeaderOutcome, SpaceErr};
#[cfg(verus_keep_ghost)]
pub use crate::table::{CtxSlot, SpaceTable, live_handle};
#[cfg(not(verus_keep_ghost))]
pub use crate::table::{CtxSlot, SpaceTable};

use crate::handle::*;
use crate::table::*;

verus! {

#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
pub enum IoErr {
    /// 目标已不存在：上下文被外部释放，或计数器不匹配。可恢复——
    /// 对应槽位直接遗忘即可。
    NotFound,
    /// 备份数据完整性校验失败。
    Integrity,
    /// 备份缓冲区放不下。
    NoSpace,
    /// 其余不可恢复错误。
    Fatal,
}

// ---------------------------------------------------------------------------
// 芯片侧接口（可信规约）
// ---------------------------------------------------------------------------

/// 上下文存取的抽象接口。
///
/// 实现由外层提供：它内部会做报文构造、传输、返回码分类，那些属于编解码
/// 层的职责。本模块只依赖这里写下的前后置条件。
pub trait ContextIo {
    /// 芯片当前持有、尚未释放的句柄集合。仅用于证明，不占运行时开销。
    spec fn outstanding(&self) -> Set<u32>;

    /// 从 `blob[off..]` 装载一份上下文，返回新句柄与消耗的字节数。
    fn load(&mut self, blob: &[u8], off: usize) -> (r: Result<(u32, usize), IoErr>)
        requires
            off <= blob.len(),
        ensures
            r.is_ok() ==> {
                let (h, used) = r.unwrap();
                &&& valid_phandle(h)
                &&& off + used <= blob.len()
                &&& used > 0
                &&& !old(self).outstanding().contains(h)
                &&& final(self).outstanding() == old(self).outstanding().insert(h)
            },
            r.is_err() ==> final(self).outstanding() == old(self).outstanding(),
    ;

    /// 把 `h` 的上下文保存到 `out[off..]`，返回写入字节数。
    ///
    /// 保存本身不释放句柄，释放要显式调用 [`ContextIo::flush`]。
    fn save(&mut self, h: u32, out: &mut [u8], off: usize) -> (r: Result<usize, IoErr>)
        requires
            off <= old(out).len(),
        ensures
            final(out).len() == old(out).len(),
            final(self).outstanding() == old(self).outstanding(),
            r.is_ok() ==> off + r.unwrap() <= final(out).len(),
    ;

    /// 释放芯片上的句柄。幂等，不返回错误——释放失败无从补救，
    /// 且调用点全在错误处理路径上。
    fn flush(&mut self, h: u32)
        ensures
            final(self).outstanding() == old(self).outstanding().remove(h),
    ;
}

/// 表中所有活跃句柄都在芯片持有集合内。这是编排层的核心不变量：
/// 它保证「表里记着的东西真的存在」，也保证下一次装载拿到的句柄是新的。
pub open spec fn table_backed<I: ContextIo>(tbl: SpaceTable, io: I) -> bool {
    forall|i: int|
        #![trigger tbl.slot(i)]
        0 <= i < SLOTS && live_handle(tbl.slot(i)).is_some() ==> io.outstanding().contains(
            live_handle(tbl.slot(i)).unwrap(),
        )
}

// ---------------------------------------------------------------------------
// 事务
// ---------------------------------------------------------------------------

/// 使用者可见的句柄空间。备份缓冲区不放在这里——本层不做分配，
/// 由外层按需提供切片。
pub struct Space {
    tbl: SpaceTable,
}

/// 一次请求期间的工作副本。只有 [`Space::commit`] 会把它写回。
///
/// 没有实现 `Clone`，也没有公开构造函数：拿到它的唯一途径是
/// [`Space::begin`]，丢弃它的唯一后果就是回滚。
pub struct Transaction {
    work: SpaceTable,
}

impl Space {
    pub closed spec fn wf(&self) -> bool {
        self.tbl.wf()
    }

    pub closed spec fn view(&self) -> SpaceTable {
        self.tbl
    }

    pub fn new() -> (r: Self)
        ensures
            r.wf(),
    {
        Space { tbl: SpaceTable::new() }
    }

    /// 取一份工作副本。使用者可见的状态在此期间保持不变。
    pub fn begin(&self) -> (r: Transaction)
        requires
            self.wf(),
        ensures
            r.wf(),
            r.view() == self.view(),
    {
        Transaction { work: self.tbl }
    }

    /// 把工作副本写回。只在整条路径都成功时调用。
    pub fn commit(&mut self, t: Transaction)
        requires
            t.wf(),
        ensures
            final(self).wf(),
            final(self).view() == t.view(),
    {
        self.tbl = t.work;
    }
}

impl Transaction {
    pub closed spec fn wf(&self) -> bool {
        self.work.wf()
    }

    pub closed spec fn view(&self) -> SpaceTable {
        self.work
    }

    pub fn table(&mut self) -> (r: &mut SpaceTable)
        ensures
            *r == old(self).view(),
    {
        &mut self.work
    }

    /// 事务失败时的收尾：释放芯片上的残留，然后丢弃副本。
    ///
    /// 取走 `self` 而不是借用——收尾之后这个事务不可能再被提交。
    pub fn abort<I: ContextIo>(self, io: &mut I)
        requires
            self.wf(),
    {
        let mut t = self;
        flush_all(&mut t.work, io);
    }
}

// ---------------------------------------------------------------------------
// 批量装载 / 保存 / 释放
// ---------------------------------------------------------------------------

/// 释放表中所有活跃句柄与所有会话，并清空两张表。
///
/// 这是错误路径的收尾动作：调用之后芯片上不再残留本 space 的任何东西。
pub fn flush_all<I: ContextIo>(tbl: &mut SpaceTable, io: &mut I)
    requires
        old(tbl).wf(),
    ensures
        final(tbl).wf(),
        forall|i: int| 0 <= i < SLOTS ==> final(tbl).slot(i) == CtxSlot::Empty,
        forall|i: int| 0 <= i < SLOTS ==> final(tbl).session(i) == 0u32,
{
    let mut i: usize = 0;
    while i < SLOTS
        invariant
            i <= SLOTS,
            tbl.wf(),
            forall|k: int| 0 <= k < i ==> tbl.slot(k) == CtxSlot::Empty,
        decreases SLOTS - i,
    {
        match tbl.slot_at(i) {
            CtxSlot::Live(h) => {
                io.flush(h);
                tbl.set_slot_free(i, false);
            },
            _ => {
                tbl.set_slot_free(i, false);
            },
        }
        i += 1;
    }

    let mut i: usize = 0;
    while i < SLOTS
        invariant
            i <= SLOTS,
            tbl.wf(),
            forall|k: int| 0 <= k < SLOTS ==> tbl.slot(k) == CtxSlot::Empty,
            forall|k: int| 0 <= k < i ==> tbl.session(k) == 0u32,
        decreases SLOTS - i,
    {
        let h = tbl.session_at(i);
        if h != 0 {
            io.flush(h);
            tbl.clear_session(i);
        }
        i += 1;
    }
}

/// 把备份缓冲区里的上下文全部装载回芯片。
///
/// 成功返回后表中不再有「已保存」状态的槽位——每个非空槽位都对应一个
/// 芯片上真实存在的句柄。
///
/// 会话的处理与对象不同：装载失败的会话被直接遗忘（清空槽位）而不是
/// 让整个操作失败。会话本来就可能被外部释放，这是正常情形。
pub fn load_space<I: ContextIo>(
    tbl: &mut SpaceTable,
    io: &mut I,
    ctx_buf: &[u8],
    ses_buf: &[u8],
) -> (r: Result<(), IoErr>)
    requires
        old(tbl).wf(),
        table_backed(*old(tbl), *old(io)),
    ensures
        final(tbl).wf(),
        table_backed(*final(tbl), *final(io)),
        r.is_ok() ==> forall|i: int| 0 <= i < SLOTS ==> final(tbl).slot(i) != CtxSlot::Saved,
{
    let mut i: usize = 0;
    let mut off: usize = 0;
    while i < SLOTS
        invariant
            i <= SLOTS,
            off <= ctx_buf.len(),
            tbl.wf(),
            table_backed(*tbl, *io),
            forall|k: int| 0 <= k < i ==> tbl.slot(k) != CtxSlot::Saved,
        decreases SLOTS - i,
    {
        match tbl.slot_at(i) {
            CtxSlot::Empty => {},
            CtxSlot::Live(_) => {
                // 装载前不该有活跃句柄：表与备份缓冲区已经不同步。
                flush_all(tbl, io);
                return Err(IoErr::Fatal);
            },
            CtxSlot::Saved => {
                match io.load(ctx_buf, off) {
                    Ok((h, used)) => {
                        tbl.set_slot_live(i, h);
                        off = off + used;
                    },
                    Err(e) => {
                        flush_all(tbl, io);
                        return Err(e);
                    },
                }
            },
        }
        i += 1;
    }

    let mut i: usize = 0;
    let mut off: usize = 0;
    while i < SLOTS
        invariant
            i <= SLOTS,
            off <= ses_buf.len(),
            tbl.wf(),
            table_backed(*tbl, *io),
            forall|k: int| 0 <= k < SLOTS ==> tbl.slot(k) != CtxSlot::Saved,
        decreases SLOTS - i,
    {
        if tbl.session_at(i) != 0 {
            match io.load(ses_buf, off) {
                Ok((h, used)) => {
                    if h != tbl.session_at(i) {
                        // 会话换了身份，说明备份与芯片状态对不上。
                        flush_all(tbl, io);
                        return Err(IoErr::Fatal);
                    }
                    off = off + used;
                },
                Err(IoErr::NotFound) => {
                    tbl.clear_session(i);
                },
                Err(e) => {
                    flush_all(tbl, io);
                    return Err(e);
                },
            }
        }
        i += 1;
    }
    Ok(())
}

/// 把芯片上属于本 space 的东西全部保存回备份缓冲区并释放。
///
/// 成功返回后表中不再有活跃槽位，芯片上不再持有本 space 的瞬态对象——
/// 这正是「事务结束后芯片是干净的」这条性质。
pub fn save_space<I: ContextIo>(
    tbl: &mut SpaceTable,
    io: &mut I,
    ctx_buf: &mut [u8],
    ses_buf: &mut [u8],
) -> (r: Result<(), IoErr>)
    requires
        old(tbl).wf(),
        table_backed(*old(tbl), *old(io)),
    ensures
        final(tbl).wf(),
        r.is_ok() ==> forall|i: int|
            #![trigger final(tbl).slot(i)]
            0 <= i < SLOTS ==> live_handle(final(tbl).slot(i)).is_none(),
{
    let mut i: usize = 0;
    let mut off: usize = 0;
    while i < SLOTS
        invariant
            i <= SLOTS,
            off <= ctx_buf.len(),
            tbl.wf(),
            table_backed(*tbl, *io),
            forall|k: int|
                #![trigger tbl.slot(k)]
                0 <= k < i ==> live_handle(tbl.slot(k)).is_none(),
        decreases SLOTS - i,
    {
        match tbl.slot_at(i) {
            CtxSlot::Live(h) => {
                match io.save(h, ctx_buf, off) {
                    Ok(used) => {
                        io.flush(h);
                        tbl.set_slot_free(i, true);
                        off = off + used;
                    },
                    Err(IoErr::NotFound) => {
                        // 对象已被外部释放，忘掉它。
                        tbl.set_slot_free(i, false);
                    },
                    Err(e) => {
                        flush_all(tbl, io);
                        return Err(e);
                    },
                }
            },
            _ => {},
        }
        i += 1;
    }

    let mut i: usize = 0;
    let mut off: usize = 0;
    while i < SLOTS
        invariant
            i <= SLOTS,
            off <= ses_buf.len(),
            tbl.wf(),
            forall|k: int|
                #![trigger tbl.slot(k)]
                0 <= k < SLOTS ==> live_handle(tbl.slot(k)).is_none(),
        decreases SLOTS - i,
    {
        let h = tbl.session_at(i);
        if h != 0 {
            match io.save(h, ses_buf, off) {
                Ok(used) => {
                    off = off + used;
                },
                Err(IoErr::NotFound) => {
                    tbl.clear_session(i);
                },
                Err(e) => {
                    flush_all(tbl, io);
                    return Err(e);
                },
            }
        }
        i += 1;
    }
    Ok(())
}

} // verus!
