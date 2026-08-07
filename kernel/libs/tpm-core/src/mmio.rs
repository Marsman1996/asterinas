use alloc::vec::Vec;

use crate::tis::TisErr;
use crate::phy::TisPhy;

/// 一段内存映射寄存器窗口的起始地址。
///
/// 页大小取决于目标平台；调用方（探测/绑定代码，圈层 C）负责把这段区域
/// 映射好、确保它在 `TisMmio` 存活期间不被解除映射、且没有其他别名同时
/// 访问它。这三条是本类型存在的全部前提，`TisMmio` 自己无法验证任何一条。
pub struct TisMmio {
    base: *mut u8,
    /// 每次 [`TisPhy::delay`] 空转的圈数。不是时长——no_std 环境没有统一的
    /// 睡眠原语，真实间隔取决于目标 CPU 的主频，调用方按平台校准这个数字。
    spin: u32,
    /// 幽灵累积量，供 `phy.rs` 的规约引用。运行时零开销：`Ghost<T>` 编译后
    /// 不占内存，这里的赋值只是让文档与断言保持字面一致，不改变任何行为。
    #[allow(dead_code)]
    written: Vec<u8>,
}
impl TisMmio {
    /// # Safety
    ///
    /// 调用方必须保证：
    /// - `base` 指向一段已经映射、长度覆盖所有 locality 窗口
    ///   （典型布局是每个 locality 占 4 KiB，`TPM_ACCESS(l)` 等地址已把
    ///   `l << 12` 折进偏移，因此窗口至少要有 `(MAX_LOCALITY) * 0x1000` 字节）
    ///   的 MMIO 区域；
    /// - 该区域在返回值的生命周期内不被解除映射、不被其他代码同时访问；
    /// - `base` 按最大访问宽度（4 字节）对齐。
    ///
    /// `spin` 是每次 [`TisPhy::delay`] 的空转圈数，由调用方按目标平台的
    /// 主频校准；给零也不违反任何已证性质，只是退化成不等待。
    pub unsafe fn new(_base: *mut u8, _spin: u32) -> Self {
        unimplemented!()
    }
}
impl TisPhy for TisMmio {
    fn read8(&mut self, addr: u32) -> Result<u8, TisErr> {
        let v = unsafe { core::ptr::read_volatile(self.base.add(addr as usize)) };
        Ok(v)
    }
    fn read32(&mut self, addr: u32) -> Result<u32, TisErr> {
        let ptr = unsafe { self.base.add(addr as usize) } as *mut u32;
        let v = unsafe { core::ptr::read_volatile(ptr) };
        Ok(u32::from_le(v))
    }
    fn write8(&mut self, addr: u32, value: u8) -> Result<(), TisErr> {
        unsafe { core::ptr::write_volatile(self.base.add(addr as usize), value) };
        Ok(())
    }
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), TisErr> {
        let ptr = unsafe { self.base.add(addr as usize) } as *mut u32;
        unsafe { core::ptr::write_volatile(ptr, value.to_le()) };
        Ok(())
    }
    fn read_fifo(
        &mut self,
        addr: u32,
        out: &mut [u8],
        off: usize,
        n: usize,
    ) -> Result<(), TisErr> {
        let mut i = 0usize;
        while i < n {
            let b = unsafe { core::ptr::read_volatile(self.base.add(addr as usize)) };
            out[off + i] = b;
            i += 1;
        }
        Ok(())
    }
    fn write_fifo(
        &mut self,
        addr: u32,
        data: &[u8],
        off: usize,
        n: usize,
    ) -> Result<(), TisErr> {
        let mut i = 0usize;
        while i < n {
            unsafe {
                core::ptr::write_volatile(self.base.add(addr as usize), data[off + i])
            };
            i += 1;
        }
        Ok(())
    }
    /// 写入 `TPM_STS_COMMAND_READY`（0x40）。
    ///
    /// 常量没有从 `tis.rs` 引入：那些常量描述的是"寄存器里哪一位是什么
    /// 含义"，属于设备语义，理应待在圈层 A；这里只是把已经决定要写的那个
    /// 字节值放到总线上，与语义层再牵一条依赖没有必要。
    fn reset_fifo(&mut self, addr: u32) {
        unsafe { core::ptr::write_volatile(self.base.add(addr as usize), 0x40u8) };
    }
    /// 一次轮询间隔。
    ///
    /// no_std 环境里没有统一的睡眠原语，具体等待方式由调用方通过 `spin`
    /// 参数决定，本函数只负责空转够 `spin` 圈——真实间隔长度不影响任何一条
    /// 被证明的性质（见 `phy.rs` 对应文档），只影响真实耗时。
    fn delay(&mut self) {
        for _ in 0..self.spin {
            core::hint::spin_loop();
        }
    }
}
