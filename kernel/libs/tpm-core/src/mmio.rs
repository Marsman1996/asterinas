use crate::{phy::TisPhy, tis::TisErr};

pub trait TisMmioBackend {
    fn read8(&mut self, addr: u32) -> Result<u8, TisErr>;
    fn read32(&mut self, addr: u32) -> Result<u32, TisErr>;
    fn write8(&mut self, addr: u32, value: u8) -> Result<(), TisErr>;
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), TisErr>;
}
pub struct TisMmio<B: TisMmioBackend> {
    backend: B,
    /// 每次 [`TisPhy::delay`] 空转的圈数。不是时长，真实间隔取决于目标 CPU 主频。
    spin: u32,
}
impl<B: TisMmioBackend> TisMmio<B> {
    pub fn new(backend: B, spin: u32) -> Self {
        TisMmio { backend, spin }
    }
}
impl<B: TisMmioBackend> TisPhy for TisMmio<B> {
    fn read8(&mut self, addr: u32) -> Result<u8, TisErr> {
        self.backend.read8(addr)
    }
    fn read32(&mut self, addr: u32) -> Result<u32, TisErr> {
        let v = self.backend.read32(addr)?;
        Ok(u32::from_le(v))
    }
    fn write8(&mut self, addr: u32, value: u8) -> Result<(), TisErr> {
        self.backend.write8(addr, value)
    }
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), TisErr> {
        self.backend.write32(addr, value.to_le())
    }
    fn read_fifo(&mut self, addr: u32, out: &mut [u8], off: usize, n: usize) -> Result<(), TisErr> {
        let mut i = 0usize;
        while i < n {
            out[off + i] = self.backend.read8(addr)?;
            i += 1;
        }
        Ok(())
    }
    fn write_fifo(&mut self, addr: u32, data: &[u8], off: usize, n: usize) -> Result<(), TisErr> {
        let mut i = 0usize;
        while i < n {
            self.backend.write8(addr, data[off + i])?;
            i += 1;
        }
        Ok(())
    }
    /// 写入 `TPM_STS_COMMAND_READY`（0x40）。
    fn reset_fifo(&mut self, addr: u32) {
        let _ = self.backend.write8(addr, 0x40u8);
    }
    fn delay(&mut self) {
        for _ in 0..self.spin {
            core::hint::spin_loop();
        }
    }
}
