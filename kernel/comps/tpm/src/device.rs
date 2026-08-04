// 只可能待在 hal 里的两段东西:
//
//   1. 给硬件加一把锁——防止两拨代码同时去碰同一组寄存器。
//   2. 开机胶水——找到芯片、申领它的地址、把地址交给 mmio,再走一遍引导。
//
// 都是纯 Rust,不进 Verus:这一层只是"把已验证的 core 拼起来、接上真实宿主",
// 拼装本身没有要证明的性质。被调用的 core 函数各自带着前后置条件,但从这里
// 调用时它们就是普通函数——前提由本层负责满足(比如只传合法的 su 值)。

use core::ops::Range;

use ostd::{mm::Paddr, sync::SpinLock};
use tpm_core::chip::ChipTransport; // exec() 来自这个 trait,要在作用域里才能调
use tpm_core::{
    BootErr, ChipLink, Limits, Tis, Xfer, bring_up, cmd::SU_CLEAR, module::IoErr, tis::TisErr,
};

use crate::{extcrypto::check_abi, mmio::TisMmio};

// ===========================================================================
// 芯片在总线上的位置
// ===========================================================================
//
// TPM(TIS 接口)的寄存器窗口在 x86 上是一段固定物理地址:基址 0xFED4_0000,
// 往后 5 个 locality、每个占 0x1000,合计 0x5000 字节。
//
// 严格来讲这个地址应当从 ACPI 的 TPM2 表里读(固件填的),Asterinas 的 ACPI
// 解析在 ostd 的 arch/x86 acpi 模块里。这里先用业界标准基址,做成常量便于将来
// 换成"从 ACPI 读出来"而不改其它代码。

/// TIS 寄存器窗口物理基址。
pub const TPM_TIS_BASE: Paddr = 0xFED4_0000;

/// 窗口大小:5 个 locality × 每个 0x1000。
pub const TPM_TIS_SIZE: usize = 0x5000;

/// 每次轮询间隔的空转圈数。粗调值,按目标 CPU 主频校准;给不准也只影响真实
/// 耗时,不影响正确性(超时是用轮询次数算的,不是用时钟)。
const POLL_SPIN: u32 = 1000;

// ===========================================================================
// 第一段:给硬件加锁
// ===========================================================================
//
// 为什么需要锁:寄存器和数据口是有状态的——发一半命令、读一半响应的中途,
// 若另一路代码插进来读写同一组寄存器,两边的传输会彼此踩乱。core 里的状态机
// 假定"同一时刻只有我一个人在碰芯片",这条假定必须由这一层用锁兑现。
//
// 用 ostd::sync::SpinLock 而不是自带自旋锁:它会在持锁期间正确关抢占(需要时
// 还能 .disable_irq() 连中断一起关),与内核调度协调;裸自旋锁做不到这点。
// 轮询驱动本就不睡眠,自旋锁是合适的选择。

/// 一块已经引导完成、可承载业务命令的 TPM。
///
/// 内部把运行态门面 `ChipLink` 锁了起来。业务侧只能通过 [`TpmDevice::exec`]
/// 访问,而那个方法一进门就抢锁——于是"独占访问寄存器"从一条要靠人守的纪律,
/// 变成了类型层面绕不过去的事实。
///
/// 设计上只创建一次,放进某个全局(如 `Once`)里,各处按引用共享。SpinLock
/// 在内容可跨线程时本身就是 Send + Sync,共享是安全的。
pub struct TpmDevice {
    inner: SpinLock<ChipLink<TisMmio>>,
    /// 引导时对账出来的器件容量,只读,不需要进锁。
    limits: Limits,
}

impl TpmDevice {
    /// 发一条命令、收回响应,返回响应字节数。
    ///
    /// 抢锁 → 独占芯片 → 一来一回 → 出作用域自动解锁。锁的持有区间恰好覆盖
    /// 整条命令的往返,中途没有任何缝隙让别的代码插进来碰寄存器。
    pub fn exec(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, IoErr> {
        let mut link = self.inner.lock();
        link.exec(cmd, rsp)
        // 这里锁随 `link` 一起 Drop,自动释放——即便 exec 中途返回 Err 也一样。
    }

    /// 引导时读到的器件容量。
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

// ===========================================================================
// 第二段:开机胶水
// ===========================================================================

/// 初始化失败的原因。
pub enum TpmInitErr {
    /// 申领寄存器窗口失败:地址不在允许的 MMIO 区,或已被占用。
    Mmio(TisErr),
    /// 引导序列失败:接口自检、启动、自检或容量对账中的某一步没过。
    Boot(BootErr),
}

/// 找到芯片、接好线、走完引导,交出一块可用的 [`TpmDevice`]。
///
/// 步骤顺序是被依赖关系定死的:
///
/// 0. **宿主密码学接口自检**——不碰芯片,排最前。接口对不上时后面每步都会以
///    难归因的方式出错,不如在一个字节都没发之前就知道。
/// 1. **申领 MMIO 窗口**——向 ostd 要那段固定物理地址,拿到安全句柄。
/// 2. **组装 core 链路**——物理层(TisMmio)→ 硬件状态机(Tis)→ 传输层(Xfer)。
/// 3. **引导**——bring_up 里做启动、自检、容量对账,返回运行态与容量。
/// 4. **上锁**——把运行态门面塞进 SpinLock,此后业务代码只能隔着锁碰它。
pub fn probe() -> Result<TpmDevice, TpmInitErr> {
    // 0. 接口自检。真正"停不停"的判断收在 core 的 bring_up 里(它按 abi_ok
    //    决定是否返回 BootErr::Abi),这里只在不一致时留一行日志,不重复判断。
    let abi_ok = check_abi();
    if !abi_ok {
        ostd::warn!("tpm: host crypto ABI mismatch, boot will abort");
    }

    // 1. 申领寄存器窗口。这是唯一"把物理地址交给 mmio"的地方。
    let phys: Range<Paddr> = TPM_TIS_BASE..TPM_TIS_BASE + TPM_TIS_SIZE;
    let mmio = TisMmio::acquire(phys, POLL_SPIN).map_err(TpmInitErr::Mmio)?;

    // 2. 组装。locality 用 0(驱动默认使用的 locality),尚未持有。
    let tis = Tis {
        phy: mmio,
        locality: 0,
        held: false,
    };
    let x = Xfer::new(tis);

    // 3. 引导。SU_CLEAR = 冷启动;需要从保存状态恢复时改用 SU_STATE。
    let (x, limits) = bring_up(x, SU_CLEAR, abi_ok).map_err(TpmInitErr::Boot)?;

    // 4. 上锁,交付。
    let device = TpmDevice {
        inner: SpinLock::new(ChipLink::new(x)),
        limits,
    };
    ostd::info!("tpm: ready");
    Ok(device)
}
