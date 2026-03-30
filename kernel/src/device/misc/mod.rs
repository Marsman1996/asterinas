// SPDX-License-Identifier: MPL-2.0

//! Misc devices.
//!
//! Character device with major number 10.

use device_id::MajorId;
use log::{debug, info};
use spin::Once;

use super::registry::char::{MajorIdOwner, acquire_major};

#[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))]
pub mod tdxguest;
pub mod tpm;
pub mod tpmrm;

static MISC_MAJOR: Once<MajorIdOwner> = Once::new();

pub(super) fn init_in_first_kthread() {
    MISC_MAJOR.call_once(|| acquire_major(MajorId::new(10)).unwrap());

    #[cfg(target_arch = "x86_64")]
    ostd::if_tdx_enabled!({
        super::registry::char::register(tdxguest::TdxGuest::new()).unwrap();
    });

    // Register TPM device if a TPM chip is available.
    debug!("TPM: checking for chip availability");
    if let Some(chip) = aster_tpm::get_chip() {
        info!("TPM: chip found, registering /dev/tpm0");
        let tpm_device = tpm::TpmDevice::new();
        tpm::TpmDevice::register_chip(chip.clone());
        match super::registry::char::register(tpm_device) {
            Ok(()) => {
                info!("TPM: /dev/tpm0 registered successfully");
            }
            Err(e) => {
                log::warn!("TPM: failed to register /dev/tpm0: {:?}", e);
            }
        }

        // Also register TPM resource manager device.
        info!("TPM: registering /dev/tpmrm0");
        let tpmrm_device = tpmrm::TpmRmDevice::new();
        tpmrm::TpmRmDevice::register_chip(chip);
        match super::registry::char::register(tpmrm_device) {
            Ok(()) => {
                info!("TPM: /dev/tpmrm0 registered successfully");
            }
            Err(e) => {
                log::warn!("TPM: failed to register /dev/tpmrm0: {:?}", e);
            }
        }
    } else {
        debug!("TPM: no chip found, skipping /dev/tpm0 registration");
        debug!("TPM: use tpm_base=<addr> kernel parameter to enable TPM");
    }
}
