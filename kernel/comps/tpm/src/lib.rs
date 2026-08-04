// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]

use component::{ComponentInitError, init_component};
use spin::Once;

macro_rules! __log_prefix {
    () => {
        "tpm: "
    };
}

// 抽象宿主的落地层。tpm-core 里每一条 external_body 规约、每一个未解释的
// trait,都在这里对接真实设施:
//   - 寄存器窗口   -> ostd::io::IoMem(见 mmio)
//   - 密码学/随机源 -> 宿主符号(见 extcrypto;ostd 不含密码学子系统)
//
// 本层不进 Verus 证明主体:tpm-core 那侧把这里当作「假设成立」的边界,责任
// 转移给对照硬件手册 / 算法规范核对实现的人。因此文件都刻意写得薄——能挪进
// tpm-core(已验证)做的判断一律挪过去,这里只留不能再分的单步动作。
//
// 不定义 #[panic_handler]、不注册全局分配器:那两样是全局唯一项,由 ostd
// 之上的内核二进制提供(#[ostd::panic_handler] / #[ostd::global_heap_allocator])。
// 需要中止时走 ostd::panic::abort;需要日志走 ostd::log 宏;需要锁走
// ostd::sync,别自带一套。

pub mod extcrypto;
pub mod mmio;

// 只可能待在 hal 的两段:硬件锁 + 开机探测胶水。都是纯 Rust,不进 Verus。
pub mod device;

pub use device::{TPM_TIS_BASE, TPM_TIS_SIZE, TpmDevice, TpmInitErr, probe};
pub use extcrypto::{ExtAesCfb, ExtHmacSha256, ExtRng, ExtSha256, HASH_CTX_CAP, check_abi};
pub use mmio::TisMmio;

static DEVICE: Once<TpmDevice> = Once::new();

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    match probe() {
        Ok(device) => {
            DEVICE.call_once(|| device);
        }
        Err(_error) => ostd::warn!("TPM initialization failed"),
    }
    Ok(())
}

pub fn device() -> Option<&'static TpmDevice> {
    DEVICE.get()
}
