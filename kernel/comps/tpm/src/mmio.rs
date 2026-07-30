use core::ops::Range;

use vstd::prelude::*;

use ostd::io::IoMem;
use ostd::mm::{Paddr, VmIoOnce};

use tpm_core::phy::TisPhy;
use tpm_core::tis::TisErr;

verus! {

// ===========================================================================
// 可信规约的落地:TisPhy over ostd MMIO
// ===========================================================================
//
// 本文件是 `TisPhy` 的唯一具体实现,也是全项目里「寄存器地址会不会算错」这类
// 错误唯一可能藏身的地方。`phy.rs` 里的每条 `ensures` 从这一刻起不再是待证明
// 的性质,而是对这份实现的**假设**——Verus 不检查方法体是否真的满足它们,责任
// 转移给了对照硬件手册的人工核对。因此这个文件刻意写得很薄。
//
// 与裸指针版的两点不同,都来自 ostd 把 MMIO 收进了安全接口:
//
//   1. 不再持有 `*mut u8`,改持 `IoMem`——它由 I/O 内存分配器发放,内部记录
//      物理范围、映射后的内核虚地址与缓存策略。取窗口的动作从「调用方在别处
//      ioremap 好、把裸指针递进来」变成本类型自己 `acquire`,映射的正确性由
//      ostd 保证,不再是一条要人工守的前提。
//
//   2. 读写走 `VmIoOnce::read_once` / `write_once`:带边界检查与对齐检查、返回
//      `Result`、且是**安全**调用。寄存器路径上因此一处 `unsafe` 都不剩;越界
//      不再是未定义行为,而是一个 `Err`。
//
// `IoMem` 是 `Arc<KVirtArea>` 背书的,可 `Clone`、可跨线程,不像裸指针那样天然
// 不是 `Send`。因此「同一时刻只有一路代码持有寄存器窗口」这条不变量不再靠类型
// 自动兜底,须由圈层 C 显式提供:把 `Tis<TisMmio>` 整个塞进 `ostd::sync::SpinLock`
// (自旋锁会正确关抢占/中断,契合轮询驱动)。这与原先「等价于 chip mutex」的
// 约束是同一件事,只是现在落在锁上而非指针类型上。

// ---------------------------------------------------------------------------
// 寄存器窗口
// ---------------------------------------------------------------------------

pub struct TisMmio {
    /// ostd 发放的 MMIO 句柄。所有寄存器/数据口访问都以它为基址,偏移即
    /// `TPM_ACCESS(l)` 等地址里已折进 `l << 12` 的那个值。
    mmio: IoMem,
    /// 每次 [`TisPhy::delay`] 空转的圈数。不是时长——轮询驱动的等待粒度取决于
    /// 目标 CPU 主频,调用方按平台校准。ostd 没有裸机忙等原语;若要以真实时基
    /// 约束轮询,改从 `ostd::timer` / TSC 取时间,与这里的圈数二选一。
    spin: u32,
    /// 幽灵累积量,供 `phy.rs` 的规约引用。运行时零开销,只让文档与断言保持
    /// 字面一致,不改变行为。
    #[cfg(verus_keep_ghost)]
    ghost written: Seq<u8>,
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
    #[verifier::external_body]
    pub fn acquire(phys: Range<Paddr>, spin: u32) -> (r: Result<Self, TisErr>)
        ensures
            r matches Ok(m) ==> m.fifo_written() =~= Seq::<u8>::empty(),
    {
        match IoMem::acquire(phys) {
            Ok(mmio) => Ok(TisMmio {
                mmio,
                spin,
                #[cfg(verus_keep_ghost)]
                written: Seq::empty(),
            }),
            Err(_) => Err(TisErr::Phy),
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
        // 单次非撕裂读。`addr` 由 tis_core.rs 里已验证的 `reg_*` 函数产生,落在
        // 窗口之内;真出界了 read_once 会返回 Err 而不是踩内存。
        self.mmio.read_once::<u8>(addr as usize).map_err(|_| TisErr::Phy)
    }

    #[verifier::external_body]
    fn read32(&mut self, addr: u32) -> (r: Result<u32, TisErr>) {
        // 寄存器按小端排布(这是接触面规范规定的总线字节序,与报文体的大端编码
        // 是两件独立的事)。`read_once::<u32>` 做的是一次 CPU 原生宽度加载,ostd
        // 目标(x86_64 / riscv64)都是小端,原生加载得到的正是寄存器的小端值,
        // 无需再转换。
        self.mmio.read_once::<u32>(addr as usize).map_err(|_| TisErr::Phy)
    }

    #[verifier::external_body]
    fn write8(&mut self, addr: u32, value: u8) -> (r: Result<(), TisErr>) {
        self.mmio.write_once::<u8>(addr as usize, &value).map_err(|_| TisErr::Phy)
    }

    #[verifier::external_body]
    fn write32(&mut self, addr: u32, value: u32) -> (r: Result<(), TisErr>) {
        // 同 read32:小端目标上原生宽度写出即是寄存器要的小端布局。
        self.mmio.write_once::<u32>(addr as usize, &value).map_err(|_| TisErr::Phy)
    }

    // -----------------------------------------------------------------------
    // 数据口
    // -----------------------------------------------------------------------
    //
    // 数据口是一个 FIFO:同一个地址连续读写多次,每次取到/放进的是队列里的下一个
    // 字节,不是同一寄存器的重复值。因此这里必须逐字节 read_once/write_once 且
    // **地址恒定**。绝不能改用 `VmIo::read_bytes` / `write_bytes`——那两个按 offset
    // 递增地址,会把 n 个 FIFO 字节散到 n 个不同寄存器上,语义完全错。

    #[verifier::external_body]
    fn read_fifo(&mut self, addr: u32, out: &mut [u8], off: usize, n: usize) -> (r: Result<
        (),
        TisErr,
    >) {
        let mut i = 0usize;
        while i < n {
            match self.mmio.read_once::<u8>(addr as usize) {
                Ok(b) => { out[off + i] = b; }
                Err(_) => return Err(TisErr::Phy),
            }
            i += 1;
        }
        Ok(())
    }

    #[verifier::external_body]
    fn write_fifo(&mut self, addr: u32, data: &[u8], off: usize, n: usize) -> (r: Result<
        (),
        TisErr,
    >) {
        // 逐字节压入,记住实际压进去了几个:中途失败时 `i` 停在已写入的字节数,
        // 幽灵累积量随之只长到那个前缀——与 `phy.rs`「失败时累积量只增不减」的
        // 规约一致。成功时 `i == n`,累积整段。
        let mut i = 0usize;
        let mut failed = false;
        while i < n {
            match self.mmio.write_once::<u8>(addr as usize, &data[off + i]) {
                Ok(()) => { i += 1; }
                Err(_) => { failed = true; break; }
            }
        }
        // `int` 是纯幽灵类型,对它的计算必须在 proof 块内;external_body 只让
        // Verus 不去检查函数体是否满足后置条件,不代表函数体不再区分幽灵与可执行。
        proof {
            self.written = self.written + data@.subrange(off as int, off + i as int);
        }
        if failed { Err(TisErr::Phy) } else { Ok(()) }
    }

    /// 写入命令就绪位(0x40)并把累积量清零。
    ///
    /// 常量不从 `tis.rs` 引入:那些常量描述「寄存器里哪一位是什么含义」,属于
    /// 设备语义,该待在圈层 A;这里只把已经决定要写的字节放上总线。复位若失败
    /// 无从补救,故忽略返回值——这与 trait 上 `reset_fifo` 无返回值的设计一致。
    #[verifier::external_body]
    fn reset_fifo(&mut self, addr: u32) {
        let _ = self.mmio.write_once::<u8>(addr as usize, &0x40u8);
        proof {
            self.written = Seq::empty();
        }
    }

    // -----------------------------------------------------------------------
    // 节流
    // -----------------------------------------------------------------------

    /// 一次轮询间隔。真实间隔不影响任何被证明的性质(见 `phy.rs` 对应文档),
    /// 只影响真实耗时。
    #[verifier::external_body]
    fn delay(&mut self) {
        let mut k = 0u32;
        while k < self.spin {
            core::hint::spin_loop();
            k += 1;
        }
    }
}

} // verus!
