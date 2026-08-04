use core::ops::Range;

use ostd::{
    io::IoMem,
    mm::{Paddr, VmIoOnce},
};
use tpm_core::{phy::TisPhy, tis::TisErr};

pub struct TisMmio {
    /// ostd 发放的 MMIO 句柄。所有寄存器/数据口访问都以它为基址,偏移即
    /// `TPM_ACCESS(l)` 等地址里已折进 `l << 12` 的那个值。
    mmio: IoMem,
    /// 每次 [`TisPhy::delay`] 空转的圈数。不是时长——轮询驱动的等待粒度取决于
    /// 目标 CPU 主频,调用方按平台校准。ostd 没有裸机忙等原语;若要以真实时基
    /// 约束轮询,改从 `ostd::timer` / TSC 取时间,与这里的圈数二选一。
    spin: u32,
}
impl TisMmio {
    /// 向 ostd 申领一段 MMIO 区并建立句柄。
    ///
    /// `phys` 是寄存器窗口的物理地址范围,长度须覆盖所有 locality 窗口(典型
    /// 布局每个 locality 占 4 KiB,窗口至少 `MAX_LOCALITY * 0x1000` 字节)。
    /// 映射、对齐、以及「这段区域确属 I/O 内存」由 ostd 的分配器核验;申领不到
    /// (地址不在允许的 MMIO 区、已被占用)返回 [`TisErr::Phy`]。
    ///
    /// `spin` 是每次 [`TisPhy::delay`] 的空转圈数,给零也不违反任何已证性质,
    /// 只是退化成不等待。
    pub fn acquire(phys: Range<Paddr>, spin: u32) -> Result<Self, TisErr> {
        match IoMem::acquire(phys) {
            Ok(mmio) => Ok(TisMmio { mmio, spin }),
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
    /// 一次轮询间隔。真实间隔不影响任何被证明的性质(见 `phy.rs` 对应文档),
    /// 只影响真实耗时。
    fn delay(&mut self) {
        let mut k = 0u32;
        while k < self.spin {
            core::hint::spin_loop();
            k += 1;
        }
    }
}
