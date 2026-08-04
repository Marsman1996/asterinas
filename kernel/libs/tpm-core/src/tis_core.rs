use crate::{cursor::Cursor, msg::TPM_HEADER_LEN, phy::TisPhy, tis::*};

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
    fn status(&mut self) -> Result<u8, TisErr> {
        let addr = reg_sts(self.locality);
        self.phy.read8(addr)
    }
    /// 轮询状态寄存器，直到 `mask` 里的位全部置起。
    ///
    /// 预算是轮询次数，`decreases` 直接用它——这就是把超时从时间域搬到次数域的
    /// 全部收益：终止性不需要任何关于时钟的假设。
    fn wait_status(&mut self, mask: u8, budget: u32) -> Result<u8, TisErr> {
        let mut left = budget;
        while left > 0 {
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
    fn burstcount(&mut self, budget: u32) -> Result<u16, TisErr> {
        let mut left = budget;
        while left > 0 {
            let addr = reg_sts(self.locality);
            let v = match self.phy.read32(addr) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            {};
            let b = ((v >> 8u32) & 0xFFFFu32) as u16;
            if b >= 1 {
                return Ok(b);
            }
            self.phy.delay();
            left = left - 1;
        }
        Err(TisErr::Timeout)
    }
    /// 器件是否已经把 locality 判给本端。
    ///
    /// 三位一起看：仅 `ACTIVE` 置起不够，还要 `VALID` 置起表示寄存器内容有效，
    /// 且 `REQUEST_USE` 已落下表示申请动作已经处理完。少看任何一位都会在竞争
    /// 场景下把「申请正在处理中」误判成「已经拿到」。
    fn check_locality(&mut self) -> Result<bool, TisErr> {
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
    pub fn request_locality(&mut self, budget: u32) -> Result<(), TisErr> {
        match self.check_locality() {
            Ok(true) => {
                self.held = true;
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => return Err(e),
        }
        let addr = reg_access(self.locality);
        match self.phy.write8(addr, ACCESS_REQUEST_USE) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        let mut left = budget;
        while left > 0 {
            match self.check_locality() {
                Ok(true) => {
                    self.held = true;
                    return Ok(());
                }
                Ok(false) => {}
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
    pub fn relinquish_locality(&mut self) {
        let addr = reg_access(self.locality);
        let _ = self.phy.write8(addr, ACCESS_ACTIVE_LOCALITY);
        self.held = false;
    }
    /// 把命令送进数据口。
    ///
    /// 成功时数据口收到的字节**恰好是命令本身**——不多不少，顺序一致。失败时
    /// 数据口一定被清空，绝不会留下半条命令：器件那边若残留半条命令，下一次
    /// 发送就会拼出一条谁也没写过的报文。
    pub fn send_data(&mut self, cmd: &[u8], len: usize) -> Result<(), TisErr> {
        let res = self.send_data_inner(cmd, len);
        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                let sts_addr = reg_sts(self.locality);
                self.phy.reset_fifo(sts_addr);
                Err(e)
            }
        }
    }
    fn send_data_inner(&mut self, cmd: &[u8], len: usize) -> Result<(), TisErr> {
        let sts_addr = reg_sts(self.locality);
        let fifo_addr = reg_data_fifo(self.locality);
        let s0 = match self.status() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if (s0 & STS_COMMAND_READY) == 0 {
            self.phy.reset_fifo(sts_addr);
            match self.wait_status(STS_COMMAND_READY, budget_of(TIMEOUT_B_MS)) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        let last = len - 1;
        let mut count: usize = 0;
        while count < last {
            let b = match self.burstcount(budget_of(TIMEOUT_A_MS)) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            let rem = last - count;
            let bs = b as usize;
            let n = if bs < rem { bs } else { rem };
            match self.phy.write_fifo(fifo_addr, cmd, count, n) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            {}
            let next = match count.checked_add(n) {
                Some(v) => v,
                None => return Err(TisErr::Protocol),
            };
            count = next;
            match self.wait_status(STS_VALID, budget_of(TIMEOUT_C_MS)) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            let s1 = match self.status() {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            if (s1 & STS_DATA_EXPECT) == 0 {
                return Err(TisErr::Protocol);
            }
        }
        match self.phy.write_fifo(fifo_addr, cmd, count, 1) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        {}
        match self.wait_status(STS_VALID, budget_of(TIMEOUT_C_MS)) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        let s2 = match self.status() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if (s2 & STS_DATA_EXPECT) != 0 {
            return Err(TisErr::Protocol);
        }
        Ok(())
    }
    /// 从数据口取 `count` 字节到 `out[off..]`。
    fn recv_data(&mut self, out: &mut [u8], off: usize, count: usize) -> Result<(), TisErr> {
        let fifo_addr = reg_data_fifo(self.locality);
        let mut got: usize = 0;
        while got < count {
            match self.wait_status(STS_DATA_AVAIL | STS_VALID, budget_of(TIMEOUT_C_MS)) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            let b = match self.burstcount(budget_of(TIMEOUT_A_MS)) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            let rem = count - got;
            let bs = b as usize;
            let n = if bs < rem { bs } else { rem };
            match self.phy.read_fifo(fifo_addr, out, off + got, n) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            {}
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
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize, TisErr> {
        match self.recv_data(out, 0, TPM_HEADER_LEN) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        let mut c = Cursor::at(2);
        let expected = match c.read_be32(&*out) {
            Some(v) => v,
            None => return Err(TisErr::BadLength),
        };
        let n = expected as usize;
        if n < TPM_HEADER_LEN {
            return Err(TisErr::BadLength);
        }
        if n > out.len() {
            return Err(TisErr::BadLength);
        }
        {};
        {};
        match self.recv_data(out, TPM_HEADER_LEN, n - TPM_HEADER_LEN) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        {}
        match self.wait_status(STS_VALID, budget_of(TIMEOUT_C_MS)) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        let s = match self.status() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if (s & STS_DATA_AVAIL) != 0 {
            return Err(TisErr::Protocol);
        }
        Ok(n)
    }
    /// 发一条命令，收一条响应。
    ///
    /// **locality 的归还只有一处，而且不在任何条件分支里。** 申请之后立刻把全
    /// 部可能失败的动作收进一个内部函数，让归还成为无条件的收尾语句——于是
    /// 「任何路径退出时 locality 均被释放」不需要逐条路径去查，它是控制流的形
    /// 状直接给出的。这也是本层唯一一处刻意为了可证性而调整的结构。
    pub fn transmit(&mut self, cmd: &[u8], len: usize, out: &mut [u8]) -> Result<usize, TisErr> {
        match self.request_locality(budget_of(TIMEOUT_A_MS)) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        let res = self.exchange(cmd, len, out);
        self.relinquish_locality();
        res
    }
    fn exchange(&mut self, cmd: &[u8], len: usize, out: &mut [u8]) -> Result<usize, TisErr> {
        let sts_addr = reg_sts(self.locality);
        self.phy.reset_fifo(sts_addr);
        match self.send_data(cmd, len) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
        match self.phy.write8(sts_addr, STS_GO) {
            Ok(()) => {}
            Err(e) => {
                self.phy.reset_fifo(sts_addr);
                return Err(e);
            }
        }
        match self.wait_status(STS_DATA_AVAIL | STS_VALID, budget_of(TIMEOUT_B_MS)) {
            Ok(_) => {}
            Err(e) => {
                self.phy.reset_fifo(sts_addr);
                return Err(e);
            }
        }
        let n = match self.recv(out) {
            Ok(v) => v,
            Err(e) => {
                self.phy.reset_fifo(sts_addr);
                return Err(e);
            }
        };
        self.phy.reset_fifo(sts_addr);
        Ok(n)
    }
}
