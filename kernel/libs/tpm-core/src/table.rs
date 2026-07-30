use vstd::prelude::*;

use super::handle::*;

verus! {

/// 上下文表的槽位状态。
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub enum CtxSlot {
    /// 空闲槽位。
    Empty,
    /// 对象内容已保存到备份缓冲区，芯片上无对应句柄。
    Saved,
    /// 槽位持有一个活跃的物理句柄。
    Live(u32),
}

/// 活跃槽位的物理句柄。
pub open spec fn live_handle(s: CtxSlot) -> Option<u32> {
    match s {
        CtxSlot::Live(h) => Some(h),
        _ => None,
    }
}

/// 表的抽象状态。字段全公开，供上层写规约。
pub struct TableView {
    pub ctx: Seq<CtxSlot>,
    pub sessions: Seq<u32>,
}

#[derive(Clone, Copy)]
pub struct SpaceTable {
    ctx: [CtxSlot; SLOTS],
    /// `0` 表示空槽。
    sessions: [u32; SLOTS],
}

impl SpaceTable {
    pub closed spec fn abs(&self) -> TableView {
        TableView { ctx: self.ctx@, sessions: self.sessions@ }
    }

    // -----------------------------------------------------------------------
    // 不变量
    // -----------------------------------------------------------------------

    pub open spec fn wf(&self) -> bool {
        let v = self.abs();
        &&& v.ctx.len() == SLOTS
        &&& v.sessions.len() == SLOTS
        // 活跃槽位持有的句柄必须是合法物理句柄
        &&& forall|i: int|
            #![trigger v.ctx[i]]
            0 <= i < SLOTS && live_handle(v.ctx[i]).is_some()
                ==> valid_phandle(live_handle(v.ctx[i]).unwrap())
        // 活跃槽位之间物理句柄两两不等 —— 单射性的来源
        &&& forall|i: int, j: int|
            #![trigger v.ctx[i], v.ctx[j]]
            0 <= i < SLOTS && 0 <= j < SLOTS && i != j
                && live_handle(v.ctx[i]).is_some()
                ==> live_handle(v.ctx[i]) != live_handle(v.ctx[j])
        // 已登记的会话句柄两两不等
        &&& forall|i: int, j: int|
            #![trigger v.sessions[i], v.sessions[j]]
            0 <= i < SLOTS && 0 <= j < SLOTS && i != j && v.sessions[i] != 0u32
                ==> v.sessions[i] != v.sessions[j]
    }

    // -----------------------------------------------------------------------
    // 规约层查询
    // -----------------------------------------------------------------------

    pub open spec fn slot(&self, i: int) -> CtxSlot {
        self.abs().ctx[i]
    }

    pub open spec fn session(&self, i: int) -> u32 {
        self.abs().sessions[i]
    }

    /// 表中是否已经登记了物理句柄 `p`。
    pub open spec fn has_phandle(&self, p: u32) -> bool {
        exists|i: int|
            #![trigger self.slot(i)]
            0 <= i < SLOTS && live_handle(self.slot(i)) == Some(p)
    }

    /// 虚拟句柄到物理句柄的映射。整个模块的语义核心。
    pub open spec fn maps(&self, v: u32) -> Option<u32> {
        let i = slot_of(v);
        if is_transient(v) && 0 <= i < SLOTS {
            live_handle(self.slot(i))
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // 存在量词的展开引理
    //
    // `has_phandle` / `has_session` 是存在量词形式，便于上层书写；而维护
    // 不变量时需要的是「逐槽位都不等」的全称形式。这两条引理是两种形式
    // 之间唯一的桥，写入槽位的三个函数都从它们起步。
    // -----------------------------------------------------------------------

    pub proof fn lemma_no_phandle_pointwise(&self, p: u32)
        requires
            !self.has_phandle(p),
        ensures
            forall|k: int| #![trigger self.slot(k)] 0 <= k < SLOTS ==> live_handle(self.slot(k)) != Some(p),
    {
        assert forall|k: int| 0 <= k < SLOTS implies live_handle(#[trigger] self.slot(k)) != Some(p) by {
            if live_handle(self.slot(k)) == Some(p) {
                assert(self.has_phandle(p));
            }
        }
    }

    pub proof fn lemma_no_session_pointwise(&self, h: u32)
        requires
            !self.has_session(h),
        ensures
            forall|k: int| #![trigger self.session(k)] 0 <= k < SLOTS ==> self.session(k) != h,
    {
        assert forall|k: int| 0 <= k < SLOTS implies #[trigger] self.session(k) != h by {
            if self.session(k) == h {
                assert(self.has_session(h));
            }
        }
    }

    // -----------------------------------------------------------------------
    // 双射性
    // -----------------------------------------------------------------------

    /// 映射是单射：两个不同的虚拟句柄不可能指向同一个物理句柄。
    ///
    /// space 之间的隔离性最终要归约到这条性质：一个 space 的表里拿不出
    /// 另一个 space 持有的物理句柄，因为它的每个虚拟句柄都只能解析到
    /// 自己表内某个槽位。
    pub proof fn lemma_maps_injective(&self, a: u32, b: u32)
        requires
            self.wf(),
            self.maps(a).is_some(),
            self.maps(a) == self.maps(b),
        ensures
            a == b,
    {
        let ia = slot_of(a);
        let ib = slot_of(b);
        assert(is_transient(a) && 0 <= ia < SLOTS);
        assert(is_transient(b) && 0 <= ib < SLOTS);
        if ia != ib {
            assert(live_handle(self.slot(ia)).is_some());
            assert(live_handle(self.slot(ia)) != live_handle(self.slot(ib)));
            assert(false);
        }
        lemma_transient_slot_injective(a, b);
    }

    /// 登记后立刻解析回原物理句柄。
    pub proof fn lemma_intern_resolve(&self, i: int, p: u32)
        requires
            0 <= i < SLOTS,
            self.slot(i) == CtxSlot::Live(p),
        ensures
            self.maps(vhandle_of(i)) == Some(p),
    {
        lemma_slot_roundtrip(i);
        lemma_vhandle_is_transient(i);
    }

    // -----------------------------------------------------------------------
    // 构造与槽位写入
    // -----------------------------------------------------------------------

    pub fn new() -> (r: Self)
        ensures
            r.wf(),
            forall|i: int| 0 <= i < SLOTS ==> r.slot(i) == CtxSlot::Empty,
            forall|i: int| 0 <= i < SLOTS ==> r.session(i) == 0u32,
    {
        SpaceTable { ctx: [CtxSlot::Empty; SLOTS], sessions: [0u32; SLOTS] }
    }

    /// 把槽位置为空闲或已保存。这两种状态不携带句柄，永远不破坏不变量。
    pub fn set_slot_free(&mut self, i: usize, saved: bool)
        requires
            old(self).wf(),
            i < SLOTS,
        ensures
            final(self).wf(),
            final(self).slot(i as int) == if saved { CtxSlot::Saved } else { CtxSlot::Empty },
            forall|k: int| #![trigger final(self).slot(k)] 0 <= k < SLOTS && k != i as int ==> final(self).slot(k) == old(self).slot(k),
            forall|k: int| #![trigger final(self).session(k)] 0 <= k < SLOTS ==> final(self).session(k) == old(self).session(k),
    {
        self.ctx[i] = if saved { CtxSlot::Saved } else { CtxSlot::Empty };
    }

    /// 把槽位置为活跃。要求句柄合法且未被登记过。
    ///
    /// 「未被登记过」是前置条件而不是运行时检查：调用点（`intern`、
    /// 装载路径）本来就已经查过一遍表，再查一次纯属浪费。单射性由此
    /// 条前置条件承接，不引入任何信任假设。
    pub fn set_slot_live(&mut self, i: usize, p: u32)
        requires
            old(self).wf(),
            i < SLOTS,
            valid_phandle(p),
            !old(self).has_phandle(p),
        ensures
            final(self).wf(),
            final(self).slot(i as int) == CtxSlot::Live(p),
            forall|k: int| #![trigger final(self).slot(k)] 0 <= k < SLOTS && k != i as int ==> final(self).slot(k) == old(self).slot(k),
            forall|k: int| #![trigger final(self).session(k)] 0 <= k < SLOTS ==> final(self).session(k) == old(self).session(k),
    {
        let ghost before = self.ctx@;
        proof {
            assert(old(self).wf());
            old(self).lemma_no_phandle_pointwise(p);
        }

        self.ctx[i] = CtxSlot::Live(p);

        proof {
            assert(self.ctx@ =~= before.update(i as int, CtxSlot::Live(p)));
            assert(self.sessions@ =~= old(self).sessions@);
            assert(self.abs().ctx.len() == SLOTS);
            assert(self.abs().sessions.len() == SLOTS);
            assert(old(self).wf());

            // 合法性：新槽位由前置条件保证，其余槽位沿用旧值。
            assert forall|a: int|
                0 <= a < SLOTS && live_handle(#[trigger] self.slot(a)).is_some()
                implies valid_phandle(live_handle(self.slot(a)).unwrap()) by {
                if a == i as int {
                    assert(self.slot(a) == CtxSlot::Live(p));
                    assert(live_handle(self.slot(a)).unwrap() == p);
                    assert(valid_phandle(p));
                } else {
                    assert(self.slot(a) == old(self).slot(a));
                    assert(live_handle(self.slot(a)) == live_handle(old(self).slot(a)));
                    assert(live_handle(old(self).slot(a)).is_some());
                    assert(valid_phandle(live_handle(old(self).slot(a)).unwrap())) by {
                        assert(old(self).wf());
                    }
                }
            }

            // 单射性：三种情况，每种都归到「旧槽位的句柄不等于 p」。
            assert forall|a: int, b: int|
                0 <= a < SLOTS && 0 <= b < SLOTS && a != b
                    && live_handle(#[trigger] self.slot(a)).is_some()
                implies live_handle(self.slot(a)) != live_handle(#[trigger] self.slot(b)) by {
                if a == i as int {
                    assert(live_handle(self.slot(a)) == Some(p));
                    assert(self.slot(b) == old(self).slot(b));
                    assert(live_handle(old(self).slot(b)) != Some(p));
                    assert(live_handle(self.slot(b)) == live_handle(old(self).slot(b)));
                } else if b == i as int {
                    assert(live_handle(self.slot(b)) == Some(p));
                    assert(self.slot(a) == old(self).slot(a));
                    assert(live_handle(old(self).slot(a)) != Some(p));
                    assert(live_handle(self.slot(a)) == live_handle(old(self).slot(a)));
                } else {
                    assert(self.slot(a) == old(self).slot(a));
                    assert(self.slot(b) == old(self).slot(b));
                    assert(live_handle(self.slot(a)) == live_handle(old(self).slot(a)));
                    assert(live_handle(self.slot(b)) == live_handle(old(self).slot(b)));
                }
            }

            assert forall|a: int, b: int|
                #![trigger self.session(a), self.session(b)]
                0 <= a < SLOTS && 0 <= b < SLOTS && a != b && self.session(a) != 0u32
                implies self.session(a) != self.session(b) by {
                assert(self.session(a) == old(self).session(a));
                assert(self.session(b) == old(self).session(b));
                assert(old(self).wf());
            }

            assert(self.wf()) by {
                let v = self.abs();
                assert(v.ctx.len() == SLOTS);
                assert(v.sessions.len() == SLOTS);

                assert forall|a: int|
                    #![trigger v.ctx[a]]
                    0 <= a < SLOTS && live_handle(v.ctx[a]).is_some()
                    implies valid_phandle(live_handle(v.ctx[a]).unwrap()) by {
                    assert(v.ctx[a] == self.slot(a));
                    assert(live_handle(self.slot(a)).is_some());
                    assert(valid_phandle(live_handle(self.slot(a)).unwrap()));
                }

                assert forall|a: int, b: int|
                    #![trigger v.ctx[a], v.ctx[b]]
                    0 <= a < SLOTS && 0 <= b < SLOTS && a != b && live_handle(v.ctx[a]).is_some()
                    implies live_handle(v.ctx[a]) != live_handle(v.ctx[b]) by {
                    assert(v.ctx[a] == self.slot(a));
                    assert(v.ctx[b] == self.slot(b));
                    assert(live_handle(self.slot(a)).is_some());
                    assert(live_handle(self.slot(a)) != live_handle(self.slot(b)));
                }

                assert forall|a: int, b: int|
                    #![trigger v.sessions[a], v.sessions[b]]
                    0 <= a < SLOTS && 0 <= b < SLOTS && a != b && v.sessions[a] != 0u32
                    implies v.sessions[a] != v.sessions[b] by {
                    assert(v.sessions[a] == self.session(a));
                    assert(v.sessions[b] == self.session(b));
                    assert(self.session(a) != 0u32);
                    assert(self.session(a) != self.session(b));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 查询与分配
    // -----------------------------------------------------------------------

    /// 虚拟句柄 → 物理句柄。
    pub fn resolve(&self, v: u32) -> (r: Option<u32>)
        requires
            self.wf(),
        ensures
            r == self.maps(v),
    {
        if !is_transient_exec(v) {
            return None;
        }
        let i = slot_of_exec(v);
        if i >= SLOTS {
            return None;
        }
        match self.ctx[i] {
            CtxSlot::Live(p) => Some(p),
            _ => None,
        }
    }

    /// 物理句柄 → 虚拟句柄，仅查询，不分配。
    pub fn lookup(&self, p: u32) -> (r: Option<u32>)
        requires
            self.wf(),
            valid_phandle(p),
        ensures
            r.is_some() ==> self.maps(r.unwrap()) == Some(p),
            r.is_none() ==> !self.has_phandle(p),
    {
        let mut i: usize = 0;
        while i < SLOTS
            invariant
                i <= SLOTS,
                self.wf(),
                valid_phandle(p),
                forall|k: int| #![trigger self.slot(k)] 0 <= k < i ==> live_handle(self.slot(k)) != Some(p),
            decreases SLOTS - i,
        {
            if self.ctx[i] == CtxSlot::Live(p) {
                proof {
                    self.lemma_intern_resolve(i as int, p);
                }
                return Some(vhandle_of_exec(i));
            }
            i += 1;
        }
        None
    }

    /// 为物理句柄分配一个空闲槽位，返回对应虚拟句柄。
    ///
    /// 表满时返回 `None`；此时调用方**有义务**把这个物理句柄在芯片上释放，
    /// 否则它会一直占着芯片资源且再也无法被引用。
    pub fn intern(&mut self, p: u32) -> (r: Option<u32>)
        requires
            old(self).wf(),
            valid_phandle(p),
            !old(self).has_phandle(p),
        ensures
            final(self).wf(),
            forall|k: int| #![trigger final(self).session(k)] 0 <= k < SLOTS ==> final(self).session(k) == old(self).session(k),
            r.is_some() ==> final(self).maps(r.unwrap()) == Some(p),
            r.is_none() ==> final(self).abs() == old(self).abs(),
    {
        let mut i: usize = 0;
        while i < SLOTS
            invariant
                i <= SLOTS,
                self.wf(),
                valid_phandle(p),
                !self.has_phandle(p),
                self.abs() == old(self).abs(),
            decreases SLOTS - i,
        {
            if self.ctx[i] == CtxSlot::Empty {
                self.set_slot_live(i, p);
                proof {
                    self.lemma_intern_resolve(i as int, p);
                }
                return Some(vhandle_of_exec(i));
            }
            i += 1;
        }
        None
    }

    // -----------------------------------------------------------------------
    // 会话表
    // -----------------------------------------------------------------------

    pub open spec fn has_session(&self, h: u32) -> bool {
        exists|i: int| #![trigger self.session(i)] 0 <= i < SLOTS && self.session(i) == h
    }

    /// 登记一个会话句柄。表满时返回 `false`，调用方同样负有释放义务。
    pub fn add_session(&mut self, h: u32) -> (r: bool)
        requires
            old(self).wf(),
            h != 0u32,
            !old(self).has_session(h),
        ensures
            final(self).wf(),
            forall|k: int| #![trigger final(self).slot(k)] 0 <= k < SLOTS ==> final(self).slot(k) == old(self).slot(k),
            r ==> final(self).has_session(h),
            !r ==> final(self).abs() == old(self).abs(),
    {
        let mut i: usize = 0;
        while i < SLOTS
            invariant
                i <= SLOTS,
                self.wf(),
                h != 0u32,
                !self.has_session(h),
                self.abs() == old(self).abs(),
            decreases SLOTS - i,
        {
            if self.sessions[i] == 0 {
                let ghost before = self.sessions@;
                let ghost prev = *self;
                proof {
                    assert(prev.wf());
                    prev.lemma_no_session_pointwise(h);
                }

                self.sessions[i] = h;

                proof {
                    assert(self.sessions@ =~= before.update(i as int, h));
                    assert(self.ctx@ =~= prev.ctx@);
                    assert(self.abs().ctx.len() == SLOTS);
                    assert(self.abs().sessions.len() == SLOTS);
                    assert(prev.wf());

                    assert forall|k: int| #![trigger prev.session(k)] 0 <= k < SLOTS ==> prev.session(k) != h by {
                        assert(!prev.has_session(h));
                        prev.lemma_no_session_pointwise(h);
                    }

                    assert forall|a: int|
                        0 <= a < SLOTS && live_handle(#[trigger] self.slot(a)).is_some()
                        implies valid_phandle(live_handle(self.slot(a)).unwrap()) by {
                        assert(self.slot(a) == prev.slot(a));
                        assert(live_handle(prev.slot(a)).is_some());
                        assert(live_handle(self.slot(a)) == live_handle(prev.slot(a)));
                        assert(live_handle(prev.slot(a)).is_some());
                        assert(valid_phandle(live_handle(prev.slot(a)).unwrap())) by {
                            assert(prev.wf());
                        }
                    }

                    assert forall|a: int, b: int|
                        #![trigger self.slot(a), self.slot(b)]
                        0 <= a < SLOTS && 0 <= b < SLOTS && a != b
                            && live_handle(self.slot(a)).is_some()
                        implies live_handle(self.slot(a)) != live_handle(self.slot(b)) by {
                        assert(self.slot(a) == prev.slot(a));
                        assert(self.slot(b) == prev.slot(b));
                        assert(prev.wf());
                    }

                    // 两两不等：新写入的 h 与任何旧值都不同，旧值之间沿用旧不变量。
                    assert forall|a: int, b: int|
                        0 <= a < SLOTS && 0 <= b < SLOTS && a != b && #[trigger] self.session(a) != 0u32
                        implies self.session(a) != #[trigger] self.session(b) by {
                        if a == i as int {
                            assert(self.session(b) == prev.session(b));
                            assert(prev.session(b) != h);
                        } else if b == i as int {
                            assert(self.session(a) == prev.session(a));
                            assert(prev.session(a) != h);
                        } else {
                            assert(self.session(a) == prev.session(a));
                            assert(self.session(b) == prev.session(b));
                        }
                    }
                    // 存在性见证：槽位 i 就是。
                    assert(self.session(i as int) == h);
                    assert(self.has_session(h));

                    assert(self.wf()) by {
                        let v = self.abs();
                        assert(v.ctx.len() == SLOTS);
                        assert(v.sessions.len() == SLOTS);

                        assert forall|a: int|
                            #![trigger v.ctx[a]]
                            0 <= a < SLOTS && live_handle(v.ctx[a]).is_some()
                            implies valid_phandle(live_handle(v.ctx[a]).unwrap()) by {
                            assert(v.ctx[a] == self.slot(a));
                            assert(live_handle(self.slot(a)).is_some());
                            assert(valid_phandle(live_handle(self.slot(a)).unwrap()));
                        }

                        assert forall|a: int, b: int|
                            #![trigger v.ctx[a], v.ctx[b]]
                            0 <= a < SLOTS && 0 <= b < SLOTS && a != b && live_handle(v.ctx[a]).is_some()
                            implies live_handle(v.ctx[a]) != live_handle(v.ctx[b]) by {
                            assert(v.ctx[a] == self.slot(a));
                            assert(v.ctx[b] == self.slot(b));
                            assert(live_handle(self.slot(a)).is_some());
                            assert(live_handle(self.slot(a)) != live_handle(self.slot(b)));
                        }

                        assert forall|a: int, b: int|
                            #![trigger v.sessions[a], v.sessions[b]]
                            0 <= a < SLOTS && 0 <= b < SLOTS && a != b && v.sessions[a] != 0u32
                            implies v.sessions[a] != v.sessions[b] by {
                            assert(v.sessions[a] == self.session(a));
                            assert(v.sessions[b] == self.session(b));
                            assert(self.session(a) != 0u32);
                            assert(self.session(a) != self.session(b));
                        }
                    }
                }
                return true;
            }
            i += 1;
        }
        false
    }

    pub fn has_session_exec(&self, h: u32) -> (r: bool)
        requires
            self.wf(),
        ensures
            r == self.has_session(h),
    {
        let mut i: usize = 0;
        while i < SLOTS
            invariant
                i <= SLOTS,
                self.wf(),
                forall|k: int| #![trigger self.session(k)] 0 <= k < i ==> self.session(k) != h,
            decreases SLOTS - i,
        {
            if self.sessions[i] == h {
                proof {
                    assert(self.session(i as int) == h);
                    assert(self.has_session(h));
                }
                return true;
            }
            i += 1;
        }
        proof {
            assert forall|k: int| 0 <= k < SLOTS implies #[trigger] self.session(k) != h by {}
        }
        false
    }

    pub fn session_at(&self, i: usize) -> (r: u32)
        requires
            self.wf(),
            i < SLOTS,
        ensures
            r == self.session(i as int),
    {
        self.sessions[i]
    }

    pub fn clear_session(&mut self, i: usize)
        requires
            old(self).wf(),
            i < SLOTS,
        ensures
            final(self).wf(),
            final(self).session(i as int) == 0u32,
            forall|k: int| #![trigger final(self).session(k)] 0 <= k < SLOTS && k != i as int ==> final(self).session(k) == old(self).session(k),
            forall|k: int| #![trigger final(self).slot(k)] 0 <= k < SLOTS ==> final(self).slot(k) == old(self).slot(k),
    {
        self.sessions[i] = 0;
    }

    pub fn slot_at(&self, i: usize) -> (r: CtxSlot)
        requires
            self.wf(),
            i < SLOTS,
        ensures
            r == self.slot(i as int),
    {
        self.ctx[i]
    }
}

} // verus!