// SPDX-License-Identifier: MPL-2.0

use alloc::string::ToString;

use aster_framebuffer::{CONSOLE_NAME, FRAMEBUFFER_CONSOLE};
use log::{info, warn};
use spin::Once;

/// Wrapper type for parsing hex addresses from command line.
/// Accepts both decimal and hex (0x...) formats.
#[derive(Debug, Clone, Copy)]
pub struct HexAddr(pub u64);

impl core::str::FromStr for HexAddr {
    type Err = core::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).map(HexAddr)
        } else {
            s.parse::<u64>().map(HexAddr)
        }
    }
}

/// TPM base address from command line parameter.
/// Example: tpm_base=0xfed40000
pub static TPM_BASE_ADDR: Once<HexAddr> = Once::new();

aster_cmdline::define_kv_param!("tpm_base", TPM_BASE_ADDR);

/// Standard QEMU/VM TPM CRB base address.
const QEMU_TPM_BASE: u64 = 0xfed40000;

/// CRB MMIO region size.
const CRB_REGION_SIZE: usize = 0x10000;

pub fn init() {
    for device in aster_input::all_devices() {
        info!("Found an input device, name:{}", device.name());
    }

    // FIXME: Currently, we have to do this manually to ensure the crates containing the input
    // devices are linked and their `#[init_component]` hooks can run to register the devices with
    // the input core. We should find a way to avoid this in the future.
    #[expect(unused_imports)]
    use aster_i8042::*;

    if let Some(console) = FRAMEBUFFER_CONSOLE.get() {
        aster_console::register_device(CONSOLE_NAME.to_string(), console.clone());
    }

    // Initialize TPM subsystem.
    // Priority: command line parameter > default QEMU address
    let tpm_base = if let Some(hex_addr) = TPM_BASE_ADDR.get() {
        hex_addr.0
    } else {
        // Try standard QEMU TPM address if not specified
        QEMU_TPM_BASE
    };

    if tpm_base != 0 {
        info!("TPM: probing CRB device at 0x{:016x}", tpm_base);
        match aster_tpm::init(tpm_base, CRB_REGION_SIZE) {
            Ok(()) => {
                info!("TPM: initialization successful");
            }
            Err(e) => {
                warn!("TPM: initialization failed: {:?}", e);
                warn!("TPM: use tpm_base=<addr> to specify a different address");
            }
        }
    }
}
