use vstd::prelude::*;

use crate::cursor::Cursor;
#[cfg(verus_keep_ghost)]
use crate::cursor::spec_be32_at;
use crate::msg::TPM_HEADER_LEN;
use crate::phy::TisPhy;
use crate::tis::*;

verus! {

// ===========================================================================
// 驱动状态
// ===========================================================================
//
// 只保留轮询路径。中断路径不在本层：中断处理器与命令路径并发访问同一组寄存
// 器，要证下来得引入并发框架，成本按数倍估计；而本接口本来就带完整的轮询回
// 退，砍掉中断不损失功能，只损失一点吞吐。
//
// 并发同样不在本层。所有方法都要求 `&mut Self` 独占引用，加锁由未验证的胶水
// 层负责。这样「同一时刻只有一条命令在途」不是一条需要证明的性质，而是类型
// 系统直接给出的事实。

pub struct Tis<P: TisPhy> {
    pub phy: P,
    /// 本驱动使用的 locality 号。
    pub locality: u8,
    /// 是否已申请到 locality 且尚未归还。
    ///
    /// 这是本层唯一的持久状态。把它单列出来而不是每次去读器件，是因为要证的
    /// 性质是「驱动自己有没有落下归还动作」，那属于本端的账，读器件读不出来。
    pub held: bool,
}

impl<P: TisPhy> Tis<P> {
    pub open spec fn wf(self) -> bool {
        self.locality < MAX_LOCALITY
    }

    /// 不持有 locality。
    pub open spec fn quiescent(self) -> bool {
        !self.held
    }

    // =======================================================================
    // 寄存器读取
    // =======================================================================

    fn status(&mut self) -> (r: Result<u8, TisErr>)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).held == old(self).held,
            final(self).locality == old(self).locality,
            final(self).phy.fifo_written() =~= old(self).phy.fifo_written(),
    {
        let addr = reg_sts(self.locality);
        self.phy.read8(addr)
    }

    /// 轮询状态寄存器，直到 `mask` 里的位全部置起。
    ///
    /// 预算是轮询次数，`decreases` 直接用它——这就是把超时从时间域搬到次数域的
    /// 全部收益：终止性不需要任何关于时钟的假设。
    fn wait_status(&mut self, mask: u8, budget: u32) -> (r: Result<u8, TisErr>)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).held == old(self).held,
            final(self).locality == old(self).locality,
            final(self).phy.fifo_written() =~= old(self).phy.fifo_written(),
            r matches Ok(s) ==> (s & mask) == mask,
    {
        let mut left = budget;
        while left > 0
            invariant
                self.wf(),
                self.held == old(self).held,
                self.locality == old(self).locality,
                self.phy.fifo_written() =~= old(self).phy.fifo_written(),
            decreases left,
        {
            let s = match self.status() {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            if (s & mask) == mask {
                return Ok(s);
            }
            self.phy.delay();
            left = left - 1;
        }
        Err(TisErr::Timeout)
    }

    /// 读取本轮可以连续搬运的字节数。
    ///
    /// 返回值保证非零。零意味着器件还没准备好，那种情况在这里表现为继续轮询
    /// 或超时，而不是返回一个「搬零个字节」的成功——后者会让上层的搬运循环原
    /// 地打转，且这个空转不会被任何超时预算兜住。
    fn burstcount(&mut self, budget: u32) -> (r: Result<u16, TisErr>)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).held == old(self).held,
            final(self).locality == old(self).locality,
            final(self).phy.fifo_written() =~= old(self).phy.fifo_written(),
            r matches Ok(b) ==> b >= 1,
    {
        let mut left = budget;
        while left > 0
            invariant
                self.wf(),
                self.held == old(self).held,
                self.locality == old(self).locality,
                self.phy.fifo_written() =~= old(self).phy.fifo_written(),
            decreases left,
        {
            let addr = reg_sts(self.locality);
            let v = match self.phy.read32(addr) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            assert(((v >> 8u32) & 0xFFFFu32) <= 0xFFFFu32) by (bit_vector);
            let b = ((v >> 8u32) & 0xFFFFu32) as u16;
            if b >= 1 {
                return Ok(b);
            }
            self.phy.delay();
            left = left - 1;
        }
        Err(TisErr::Timeout)
    }

    // =======================================================================
    // locality
    // =======================================================================

    /// 器件是否已经把 locality 判给本端。
    ///
    /// 三位一起看：仅 `ACTIVE` 置起不够，还要 `VALID` 置起表示寄存器内容有效，
    /// 且 `REQUEST_USE` 已落下表示申请动作已经处理完。少看任何一位都会在竞争
    /// 场景下把「申请正在处理中」误判成「已经拿到」。
    fn check_locality(&mut self) -> (r: Result<bool, TisErr>)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).held == old(self).held,
            final(self).locality == old(self).locality,
            final(self).phy.fifo_written() =~= old(self).phy.fifo_written(),
    {
        let addr = reg_access(self.locality);
        let a = match self.phy.read8(addr) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let want = ACCESS_ACTIVE_LOCALITY | ACCESS_VALID;
        let mask = want | ACCESS_REQUEST_USE;
        Ok((a & mask) == want)
    }

    /// 申请 locality。
    ///
    /// 失败时保证不持有——申请一半失败却把标志留成「持有」，会让后续的归还去
    /// 释放一个从未拿到的资源。
    pub fn request_locality(&mut self, budget: u32) -> (r: Result<(), TisErr>)
        requires
            old(self).wf(),
            old(self).quiescent(),
        ensures
            final(self).wf(),
            final(self).locality == old(self).locality,
            final(self).phy.fifo_written() =~= old(self).phy.fifo_written(),
            r is Ok ==> final(self).held,
            r is Err ==> final(self).quiescent(),
    {
        match self.check_locality() {
            Ok(true) => {
                self.held = true;
                return Ok(());
            },
            Ok(false) => {},
            Err(e) => return Err(e),
        }

        let addr = reg_access(self.locality);
        match self.phy.write8(addr, ACCESS_REQUEST_USE) {
            Ok(()) => {},
            Err(e) => return Err(e),
        }

        let mut left = budget;
        while left > 0
            invariant
                self.wf(),
                !self.held,
                self.locality == old(self).locality,
                self.phy.fifo_written() =~= old(self).phy.fifo_written(),
            decreases left,
        {
            match self.check_locality() {
                Ok(true) => {
                    self.held = true;
                    return Ok(());
                },
                Ok(false) => {},
                Err(e) => return Err(e),
            }
            self.phy.delay();
            left = left - 1;
        }
        Err(TisErr::Timeout)
    }

    /// 归还 locality。
    ///
    /// 无论寄存器写入成功与否，本端的持有标志都要清掉。写失败说明总线已经出了
    /// 问题，此时把标志留成「持有」只会让驱动认定自己永远握着资源，再也不肯发
    /// 起下一条命令——一个可恢复的总线故障因此变成永久性的功能丧失。
    pub fn relinquish_locality(&mut self)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).quiescent(),
            final(self).locality == old(self).locality,
            final(self).phy.fifo_written() =~= old(self).phy.fifo_written(),
    {
        let addr = reg_access(self.locality);
        let _ = self.phy.write8(addr, ACCESS_ACTIVE_LOCALITY);
        self.held = false;
    }

    // =======================================================================
    // 发送
    // =======================================================================

    /// 把命令送进数据口。
    ///
    /// 成功时数据口收到的字节**恰好是命令本身**——不多不少，顺序一致。失败时
    /// 数据口一定被清空，绝不会留下半条命令：器件那边若残留半条命令，下一次
    /// 发送就会拼出一条谁也没写过的报文。
    pub fn send_data(&mut self, cmd: &[u8], len: usize) -> (r: Result<(), TisErr>)
        requires
            old(self).wf(),
            old(self).held,
            1 <= len,
            len <= cmd.len(),
            old(self).phy.fifo_written().len() == 0,
        ensures
            final(self).wf(),
            final(self).held,
            final(self).locality == old(self).locality,
            r is Ok ==> final(self).phy.fifo_written() =~= cmd@.subrange(0, len as int),
            r is Err ==> final(self).phy.fifo_written().len() == 0,
    {
        let res = self.send_data_inner(cmd, len);
        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                let sts_addr = reg_sts(self.locality);
                self.phy.reset_fifo(sts_addr);
                Err(e)
            },
        }
    }

    fn send_data_inner(&mut self, cmd: &[u8], len: usize) -> (r: Result<(), TisErr>)
        requires
            old(self).wf(),
            old(self).held,
            1 <= len,
            len <= cmd.len(),
            old(self).phy.fifo_written().len() == 0,
        ensures
            final(self).wf(),
            final(self).held,
            final(self).locality == old(self).locality,
            r is Ok ==> final(self).phy.fifo_written() =~= cmd@.subrange(0, len as int),
    {
        let sts_addr = reg_sts(self.locality);
        let fifo_addr = reg_data_fifo(self.locality);

        // 先确认器件处于命令就绪态。不就绪就中止当前命令再等——这一步同时把
        // 上一条命令可能残留的字节清掉。
        let s0 = match self.status() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if (s0 & STS_COMMAND_READY) == 0 {
            self.phy.reset_fifo(sts_addr);
            match self.wait_status(STS_COMMAND_READY, budget_of(TIMEOUT_B_MS)) {
                Ok(_) => {},
                Err(e) => return Err(e),
            }
        }

        // 末字节单独处理：写完它器件就认为命令收完，`DATA_EXPECT` 应当落下。
        // 若把它混在循环里，「还要继续给」与「给够了」这两个判断就得共用一段
        // 代码，而它们期望的状态位恰好相反。
        let last = len - 1;
        let mut count: usize = 0;

        while count < last
            invariant
                count <= last,
                last == len - 1,
                1 <= len,
                len <= cmd.len(),
                self.wf(),
                self.held,
                self.locality == old(self).locality,
                self.phy.fifo_written() =~= cmd@.subrange(0, count as int),
            decreases last - count,
        {
            let b = match self.burstcount(budget_of(TIMEOUT_A_MS)) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            // 与剩余字节取小。器件报的可搬运量是它自己的缓冲余量，跟本次要发
            // 的长度没有任何关系，不取小就会把 `cmd` 之外的内存读出去。
            let rem = last - count;
            let bs = b as usize;
            let n = if bs < rem {
                bs
            } else {
                rem
            };

            match self.phy.write_fifo(fifo_addr, cmd, count, n) {
                Ok(()) => {},
                Err(e) => return Err(e),
            }

            proof {
                assert(cmd@.subrange(0, count as int) + cmd@.subrange(
                    count as int,
                    count + n,
                ) =~= cmd@.subrange(0, count + n));
            }

            let next = match count.checked_add(n) {
                Some(v) => v,
                None => return Err(TisErr::Protocol),
            };
            count = next;

            match self.wait_status(STS_VALID, budget_of(TIMEOUT_C_MS)) {
                Ok(_) => {},
                Err(e) => return Err(e),
            }
            let s1 = match self.status() {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            // 还没写完，器件必须表示还要继续收。
            if (s1 & STS_DATA_EXPECT) == 0 {
                return Err(TisErr::Protocol);
            }
        }

        // 末字节
        match self.phy.write_fifo(fifo_addr, cmd, count, 1) {
            Ok(()) => {},
            Err(e) => return Err(e),
        }
        proof {
            assert(cmd@.subrange(0, last as int) + cmd@.subrange(last as int, last + 1)
                =~= cmd@.subrange(0, len as int));
        }

        match self.wait_status(STS_VALID, budget_of(TIMEOUT_C_MS)) {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        let s2 = match self.status() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        // 写完了，器件必须表示不再要更多——还要更多说明双方对命令长度的理解
        // 不一致，此时发令等于让器件去执行一条被截断的命令。
        if (s2 & STS_DATA_EXPECT) != 0 {
            return Err(TisErr::Protocol);
        }

        Ok(())
    }

    // =======================================================================
    // 接收
    // =======================================================================

    /// 从数据口取 `count` 字节到 `out[off..]`。
    fn recv_data(&mut self, out: &mut [u8], off: usize, count: usize) -> (r: Result<(), TisErr>)
        requires
            old(self).wf(),
            old(self).held,
            off + count <= old(out).len(),
        ensures
            final(self).wf(),
            final(self).held,
            final(self).locality == old(self).locality,
            final(out).len() == old(out).len(),
            forall|k: int|
                #![trigger final(out)@[k]]
                0 <= k < final(out).len() && (k < off || k >= off + count) ==> final(out)@[k]
                    == old(out)@[k],
    {
        let fifo_addr = reg_data_fifo(self.locality);
        let mut got: usize = 0;

        while got < count
            invariant
                got <= count,
                off + count <= out.len(),
                out.len() == old(out).len(),
                self.wf(),
                self.held,
                self.locality == old(self).locality,
                forall|k: int|
                    #![trigger out@[k]]
                    0 <= k < out.len() && (k < off || k >= off + count) ==> out@[k] == old(out)@[k],
            decreases count - got,
        {
            match self.wait_status(STS_DATA_AVAIL | STS_VALID, budget_of(TIMEOUT_C_MS)) {
                Ok(_) => {},
                Err(e) => return Err(e),
            }

            let b = match self.burstcount(budget_of(TIMEOUT_A_MS)) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            // 同样与剩余字节取小。这里不取小的后果是直接写出接收缓冲区之外。
            let rem = count - got;
            let bs = b as usize;
            let n = if bs < rem {
                bs
            } else {
                rem
            };

            // 在 read_fifo 修改 out 之前，把循环不变量固化到 out_pre。
            let ghost out_pre = out@;

            match self.phy.read_fifo(fifo_addr, out, off + got, n) {
                Ok(()) => {},
                Err(e) => return Err(e),
            }

            // 重建循环不变量。read_fifo 保证 k < off+got 或 k >= off+got+n 时 out@[k] == out_pre[k]。
            // 而 n <= rem = count-got，所以 off+got+n <= off+count，即条件 k >= off+count 时自动满足。
            // 条件 k < off 同样由 k < off+got 蕴含。故 out@[k] == out_pre[k] == old(out)@[k]。
            proof {
                assert forall|k: int|
                    #![trigger out@[k]]
                    0 <= k < out.len() && (k < off || k >= off + count)
                        implies out@[k] == old(out)@[k]
                by {
                    // Verus 需要看到 out@[k] == out_pre[k]（来自 read_fifo）和 out_pre[k] == old(out)@[k]（来自循环不变量）
                    assert(out_pre[k] == old(out)@[k]);  // 触发旧循环不变量（触发器 out_pre[k]）
                    assert(n <= count - got);            // 边界关系
                };
            }

            let next = match got.checked_add(n) {
                Some(v) => v,
                None => return Err(TisErr::Protocol),
            };
            got = next;
        }
        Ok(())
    }

    /// 收取一条完整响应，返回其字节数。
    ///
    /// 返回值同时是**下一层解码的入口条件**：成功时 `out[0..n]` 的长度字段与
    /// `n` 相等，也就是满足报文层的格式良好性。解码层因此不必再校验一遍长度，
    /// 两层对「一条响应有多长」的理解由这条后置条件焊死。
    pub fn recv(&mut self, out: &mut [u8]) -> (r: Result<usize, TisErr>)
        requires
            old(self).wf(),
            old(self).held,
            TPM_HEADER_LEN <= old(out).len(),
        ensures
            final(self).wf(),
            final(self).held,
            final(self).locality == old(self).locality,
            final(out).len() == old(out).len(),
            r matches Ok(n) ==> {
                &&& TPM_HEADER_LEN <= n
                &&& n <= final(out).len()
                &&& spec_be32_at(final(out)@, 2) == n
            },
    {
        // 先取报文头。长度字段在里面，取到之前无从知道还要收多少。
        match self.recv_data(out, 0, TPM_HEADER_LEN) {
            Ok(()) => {},
            Err(e) => return Err(e),
        }

        let mut c = Cursor::at(2);
        let expected = match c.read_be32(&*out) {
            Some(v) => v,
            None => return Err(TisErr::BadLength),
        };

        // 长度字段完全由对端给出，两侧都要卡死：小于一个报文头说明它连自己的
        // 头都装不下，大于缓冲区说明再收下去就要越界。
        let n = expected as usize;
        if n < TPM_HEADER_LEN {
            return Err(TisErr::BadLength);
        }
        if n > out.len() {
            return Err(TisErr::BadLength);
        }

        let ghost after_hdr = out@;

        assert(n >= TPM_HEADER_LEN);
        assert(n <= out.len());
        match self.recv_data(out, TPM_HEADER_LEN, n - TPM_HEADER_LEN) {
            Ok(()) => {},
            Err(e) => return Err(e),
        }

        // 第二段落在报文头之后，长度字段所在的四个字节没被动过。
        proof {
            assert(out@[2] == after_hdr[2]);
            assert(out@[3] == after_hdr[3]);
            assert(out@[4] == after_hdr[4]);
            assert(out@[5] == after_hdr[5]);
            assert(spec_be32_at(out@, 2) == spec_be32_at(after_hdr, 2));
            assert(spec_be32_at(after_hdr, 2) == expected);
            assert(n as int == expected as int);
            assert(spec_be32_at(out@, 2) == n);
        }

        match self.wait_status(STS_VALID, budget_of(TIMEOUT_C_MS)) {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        let s = match self.status() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        // 还有数据可读说明器件准备的响应比它自己声明的长。多出来的部分是什么
        // 无从判断，只能整条作废——按声明长度截断会让上层收到一条被裁过的报文
        // 却毫无察觉。
        if (s & STS_DATA_AVAIL) != 0 {
            return Err(TisErr::Protocol);
        }

        Ok(n)
    }

    // =======================================================================
    // 一次完整往返
    // =======================================================================

    /// 发一条命令，收一条响应。
    ///
    /// **locality 的归还只有一处，而且不在任何条件分支里。** 申请之后立刻把全
    /// 部可能失败的动作收进一个内部函数，让归还成为无条件的收尾语句——于是
    /// 「任何路径退出时 locality 均被释放」不需要逐条路径去查，它是控制流的形
    /// 状直接给出的。这也是本层唯一一处刻意为了可证性而调整的结构。
    pub fn transmit(&mut self, cmd: &[u8], len: usize, out: &mut [u8]) -> (r: Result<usize, TisErr>)
        requires
            old(self).wf(),
            old(self).quiescent(),
            TPM_HEADER_LEN <= len,
            len <= cmd.len(),
            TPM_HEADER_LEN <= old(out).len(),
        ensures
            final(self).wf(),
            // ★ 成功、失败、超时，三种出口都不再持有 locality
            final(self).quiescent(),
            final(self).locality == old(self).locality,
            final(out).len() == old(out).len(),
            r matches Ok(n) ==> {
                &&& TPM_HEADER_LEN <= n
                &&& n <= final(out).len()
                &&& spec_be32_at(final(out)@, 2) == n
            },
    {
        match self.request_locality(budget_of(TIMEOUT_A_MS)) {
            Ok(()) => {},
            Err(e) => return Err(e),
        }

        let res = self.exchange(cmd, len, out);
        self.relinquish_locality();
        res
    }

    fn exchange(&mut self, cmd: &[u8], len: usize, out: &mut [u8]) -> (r: Result<usize, TisErr>)
        requires
            old(self).wf(),
            old(self).held,
            TPM_HEADER_LEN <= len,
            len <= cmd.len(),
            TPM_HEADER_LEN <= old(out).len(),
        ensures
            final(self).wf(),
            final(self).held,
            final(self).locality == old(self).locality,
            final(out).len() == old(out).len(),
            r matches Ok(n) ==> {
                &&& TPM_HEADER_LEN <= n
                &&& n <= final(out).len()
                &&& spec_be32_at(final(out)@, 2) == n
            },
    {
        let sts_addr = reg_sts(self.locality);

        // 进场先清干净，不假设上一次是怎么退出的。
        self.phy.reset_fifo(sts_addr);

        match self.send_data(cmd, len) {
            Ok(()) => {},
            Err(e) => return Err(e),
        }

        // 发令。到这一步器件才开始执行。
        match self.phy.write8(sts_addr, STS_GO) {
            Ok(()) => {},
            Err(e) => {
                self.phy.reset_fifo(sts_addr);
                return Err(e);
            },
        }

        // 等待响应就绪。这里用的是统一的长超时；按命令码区分执行时长是一项
        // 独立的优化，它需要一张命令到时长的表，不影响本层的任何性质。
        match self.wait_status(STS_DATA_AVAIL | STS_VALID, budget_of(TIMEOUT_B_MS)) {
            Ok(_) => {},
            Err(e) => {
                self.phy.reset_fifo(sts_addr);
                return Err(e);
            },
        }

        let n = match self.recv(out) {
            Ok(v) => v,
            Err(e) => {
                self.phy.reset_fifo(sts_addr);
                return Err(e);
            },
        };

        // 收完主动中止，让器件回到命令就绪态。
        self.phy.reset_fifo(sts_addr);
        Ok(n)
    }
}

} // verus!
