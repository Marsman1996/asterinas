use vstd::prelude::*;

use crate::tis::TisErr;
use crate::phy::TisPhy;

verus! {

// ===========================================================================
// 圈层 B：可信规约的落地
// ===========================================================================
//
// 本文件是 `TisPhy` 的唯一具体实现，也是全项目里"寄存器地址会不会算错"这类
// 错误唯一可能藏身的地方。`phy.rs` 里的每条 `ensures` 从这一刻起不再是待证明
// 的性质，而是对这份实现的**假设**——Verus 不会检查方法体是否真的满足它们，
// 责任转移给了对照硬件手册的人工核对。
//
// 因此这个文件刻意写得很薄：能挪到 `tis_core.rs`（已验证）里做的判断，一律
// 挪过去，这里只留"取一个字节""放一个字节"这类不能再往下分的动作。薄一分，
// 人工核对的工作量就少一分。

// ---------------------------------------------------------------------------
// 寄存器窗口
// ---------------------------------------------------------------------------

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
    #[cfg(verus_keep_ghost)]
    ghost written: Seq<u8>,
}

// `*mut u8` 使 `TisMmio` 默认不是 `Send`；驱动的调用规范本就要求同一时刻
// 只有一路代码持有它（等价于圈层 C 里的 chip mutex）。因此这里保持默认，
// 不提供 `Send` 实现，避免把并发约束从类型层面悄悄拿掉。

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
    #[verifier::external_body]
    pub unsafe fn new(_base: *mut u8, _spin: u32) -> (r: Self)
        ensures
            r.fifo_written() =~= Seq::<u8>::empty(),
    {
        TisMmio {
            base: _base,
            spin: _spin,
            #[cfg(verus_keep_ghost)]
            written: Seq::<u8>::empty(),
        }
    }
}

impl TisPhy for TisMmio {
    closed spec fn fifo_written(&self) -> Seq<u8> {
        self.written
    }

    // -----------------------------------------------------------------------
    // 寄存器
    // -----------------------------------------------------------------------

    #[verifier::external_body]
    fn read8(&mut self, addr: u32) -> (r: Result<u8, TisErr>) {
        // SAFETY：见 `TisMmio::new` 的前提；`addr` 由 tis_core.rs 里已验证的
        // `reg_*` 函数产生，落在映射窗口之内。
        let v = unsafe { core::ptr::read_volatile(self.base.add(addr as usize)) };
        Ok(v)
    }

    #[verifier::external_body]
    fn read32(&mut self, addr: u32) -> (r: Result<u32, TisErr>) {
        // 寄存器按小端读出——这是 TIS 规范规定的总线字节序，与报文体的大端
        // 编码是两件独立的事，不要在这里搞混。
        let ptr = unsafe { self.base.add(addr as usize) } as *mut u32;
        let v = unsafe { core::ptr::read_volatile(ptr) };
        Ok(u32::from_le(v))
    }

    #[verifier::external_body]
    fn write8(&mut self, addr: u32, value: u8) -> (r: Result<(), TisErr>) {
        unsafe { core::ptr::write_volatile(self.base.add(addr as usize), value) };
        Ok(())
    }

    #[verifier::external_body]
    fn write32(&mut self, addr: u32, value: u32) -> (r: Result<(), TisErr>) {
        let ptr = unsafe { self.base.add(addr as usize) } as *mut u32;
        unsafe { core::ptr::write_volatile(ptr, value.to_le()) };
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 数据口
    // -----------------------------------------------------------------------
    //
    // 数据口是一个 FIFO：同一个地址连续读写多次，每次取到/放进的是队列里的
    // 下一个字节，不是同一个寄存器的重复值。因此这里逐字节 `read8`/`write8`
    // 是唯一正确的访问方式，不能像某些实现那样在 `n` 是 4 的倍数时改用一次
    // `read32`/`write32`——那样做会把四个独立的 FIFO 字节读成小端拼出来的
    // 一个数，语义完全不对。

    #[verifier::external_body]
    fn read_fifo(&mut self, addr: u32, out: &mut [u8], off: usize, n: usize) -> (r: Result<
        (),
        TisErr,
    >) {
        let mut i = 0usize;
        while i < n {
            let b = unsafe { core::ptr::read_volatile(self.base.add(addr as usize)) };
            out[off + i] = b;
            i += 1;
        }
        Ok(())
    }

    #[verifier::external_body]
    fn write_fifo(&mut self, addr: u32, data: &[u8], off: usize, n: usize) -> (r: Result<
        (),
        TisErr,
    >) {
        let mut i = 0usize;
        while i < n {
            unsafe { core::ptr::write_volatile(self.base.add(addr as usize), data[off + i]) };
            i += 1;
        }
        // 幽灵累积量随每个成功写入的字节增长，即便中途失败也不回退——这与
        // `phy.rs` 里"失败时累积量只增不减"的规约一致。这里没有真实的失败
        // 路径（MMIO 写入本身不报错），因此这个赋值恒为全量写入后的状态。
        //
        // `off as int` 里的 `int` 是纯幽灵类型，对它的计算必须发生在
        // `proof` 块内——`external_body` 只让 Verus 不去检查函数体是否满足
        // 后置条件，不代表函数体不再区分幽灵代码与可执行代码。
        proof {
            self.written = self.written + data@.subrange(off as int, off + n as int);
        }
        Ok(())
    }

    /// 写入 `TPM_STS_COMMAND_READY`（0x40）。
    ///
    /// 常量没有从 `tis.rs` 引入：那些常量描述的是"寄存器里哪一位是什么
    /// 含义"，属于设备语义，理应待在圈层 A；这里只是把已经决定要写的那个
    /// 字节值放到总线上，与语义层再牵一条依赖没有必要。
    #[verifier::external_body]
    fn reset_fifo(&mut self, addr: u32) {
        unsafe { core::ptr::write_volatile(self.base.add(addr as usize), 0x40u8) };
        proof {
            self.written = self.written.subrange(0, 0);
        }
    }

    // -----------------------------------------------------------------------
    // 节流
    // -----------------------------------------------------------------------

    /// 一次轮询间隔。
    ///
    /// no_std 环境里没有统一的睡眠原语，具体等待方式由调用方通过 `spin`
    /// 参数决定，本函数只负责空转够 `spin` 圈——真实间隔长度不影响任何一条
    /// 被证明的性质（见 `phy.rs` 对应文档），只影响真实耗时。
    #[verifier::external_body]
    fn delay(&mut self) {
        for _ in 0..self.spin {
            core::hint::spin_loop();
        }
    }
}

} // verus!
