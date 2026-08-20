use core::ops::Range;

use ostd::{
    io::IoMem,
    mm::{Paddr, VmIoOnce},
    task::Task,
};
use tpm_core::{phy::TisPhy, tis::TisErr};

pub struct TisMmio {
    /// ostd 发放的 MMIO 句柄。所有寄存器/数据口访问都以它为基址,偏移即
    /// `TPM_ACCESS(l)` 等地址里已折进 `l << 12` 的那个值。
    mmio: IoMem,
    polls_since_yield: u8,
}
impl TisMmio {
    /// 向 ostd 申领一段 MMIO 区并建立句柄。
    ///
    /// `phys` 是寄存器窗口的物理地址范围,长度须覆盖所有 locality 窗口（从 0 到
    /// `MAX_LOCALITY - 1` 共 5 个窗口，至少需要 `0x5000` 字节）。
    /// 映射、对齐、以及「这段区域确属 I/O 内存」由 ostd 的分配器核验;申领不到
    /// (地址不在允许的 MMIO 区、已被占用)返回 [`TisErr::Phy`]。
    ///
    pub fn acquire(phys: Range<Paddr>) -> Result<Self, TisErr> {
        match IoMem::acquire(phys) {
            Ok(mmio) => Ok(TisMmio {
                mmio,
                polls_since_yield: 0,
            }),
            Err(_) => Err(TisErr::Phy),
        }
    }
}
impl TisPhy for TisMmio {
    fn read8(&mut self, addr: u32) -> Result<u8, TisErr> {
        self.mmio
            .read_once::<u8>(addr as usize)
            .map_err(|_| TisErr::Phy)
    }
    fn read32(&mut self, addr: u32) -> Result<u32, TisErr> {
        self.mmio
            .read_once::<u32>(addr as usize)
            .map_err(|_| TisErr::Phy)
    }
    fn write8(&mut self, addr: u32, value: u8) -> Result<(), TisErr> {
        self.mmio
            .write_once::<u8>(addr as usize, &value)
            .map_err(|_| TisErr::Phy)
    }
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), TisErr> {
        self.mmio
            .write_once::<u32>(addr as usize, &value)
            .map_err(|_| TisErr::Phy)
    }
    fn read_fifo(&mut self, addr: u32, out: &mut [u8], off: usize, n: usize) -> Result<(), TisErr> {
        let mut i = 0usize;
        while i < n {
            match self.mmio.read_once::<u8>(addr as usize) {
                Ok(b) => {
                    out[off + i] = b;
                }
                Err(_) => return Err(TisErr::Phy),
            }
            i += 1;
        }
        Ok(())
    }
    fn write_fifo(&mut self, addr: u32, data: &[u8], off: usize, n: usize) -> Result<(), TisErr> {
        let mut i = 0usize;
        let mut failed = false;
        while i < n {
            match self.mmio.write_once::<u8>(addr as usize, &data[off + i]) {
                Ok(()) => {
                    i += 1;
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        {}
        if failed { Err(TisErr::Phy) } else { Ok(()) }
    }
    /// 写入命令就绪位(0x40)并把累积量清零。
    ///
    /// 常量不从 `tis.rs` 引入:那些常量描述「寄存器里哪一位是什么含义」,属于
    /// 设备语义,该待在圈层 A;这里只把已经决定要写的字节放上总线。复位若失败
    /// 无从补救,故忽略返回值——这与 trait 上 `reset_fifo` 无返回值的设计一致。
    fn reset_fifo(&mut self, addr: u32) {
        let _ = self.mmio.write_once::<u8>(addr as usize, &0x40u8);
        {}
    }
    /// Back off between TIS status checks.
    ///
    /// Most checks return immediately so that short TPM state transitions are
    /// observed without a fixed delay. After a bounded polling burst, yield
    /// once to avoid monopolizing the CPU while a long TPM command is running.
    fn delay(&mut self) {
        const POLLS_BEFORE_YIELD: u8 = 64;

        self.polls_since_yield += 1;
        if self.polls_since_yield < POLLS_BEFORE_YIELD {
            core::hint::spin_loop();
            return;
        }

        self.polls_since_yield = 0;
        if Task::current().is_some() {
            Task::yield_now();
        } else {
            core::hint::spin_loop();
        }
    }
}
