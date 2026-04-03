// SPDX-License-Identifier: MPL-2.0

//! TPM (Trusted Platform Module) subsystem for Asterinas.
//!
//! This crate provides a Rust-native TPM 2.0 subsystem with:
//! - `TpmChip` abstraction for TPM device management
//! - `TpmTransport` trait for pluggable hardware communication backends
//! - CRB (Command Response Buffer) transport for MMIO-based TPM 2.0 devices
//! - TIS (TPM Interface Specification) FIFO transport for legacy TPM devices
//! - TPM 2.0 command encoding/decoding and header parsing
//! - Resource management and TPM 2.0 space abstractions
//! - Session foundations for future HMAC/policy support

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod chip;
pub mod error;
pub mod protocol;
pub mod resource;
pub mod session;
pub mod space;
pub mod transport;

use alloc::sync::Arc;

pub use chip::TpmChip;
pub use error::TpmError;
use log::{error, info, warn};
use ostd::io::IoMem;
pub use space::{TpmSpace, TpmSpaceManager};
use spin::Once;
pub use transport::TpmTransport;
use transport::tis::TisTransport;

/// Global TPM chip instance.
static TPM_CHIP: Once<Arc<TpmChip>> = Once::new();

/// Initializes the TPM subsystem by discovering and initializing a TPM device.
///
/// Currently supports TIS (TPM Interface Specification) which is the default
/// interface used by QEMU's tpm-tis device.
///
/// # Arguments
/// * `base_addr` - Physical base address of the TPM MMIO region (typically 0xFED40000)
/// * `size` - Size of the MMIO region
pub fn init(base_addr: u64, size: usize) -> Result<(), TpmError> {
    info!("TPM: subsystem init entered");

    // Acquire MMIO region for the TPM device.
    info!(
        "TPM: probing MMIO region (base=0x{:016x}, size={})",
        base_addr, size
    );

    let Ok(start) = usize::try_from(base_addr) else {
        error!(
            "TPM: invalid MMIO base address (does not fit in usize): 0x{:016x}",
            base_addr
        );
        return Err(TpmError::Transport(
            crate::error::TransportError::MmioAccess,
        ));
    };

    let Some(end) = start.checked_add(size) else {
        error!(
            "TPM: invalid MMIO region (base=0x{:016x}, size={}) - address overflow",
            base_addr, size
        );
        return Err(TpmError::Transport(
            crate::error::TransportError::MmioAccess,
        ));
    };

    let io_mem = match IoMem::acquire(start..end) {
        Ok(mem) => mem,
        Err(e) => {
            error!("TPM: MMIO acquire failed: {:?}", e);
            return Err(TpmError::Transport(
                crate::error::TransportError::MmioAccess,
            ));
        }
    };

    // Try TIS interface (used by QEMU's tpm-tis device).
    info!("TPM: trying TIS/FIFO interface");
    let tis_transport = TisTransport::new(io_mem);

    if !tis_transport.is_device_valid()? {
        error!("TPM: TIS device not valid");
        return Err(TpmError::Transport(
            crate::error::TransportError::DeviceNotResponding,
        ));
    }

    let (did, vid) = tis_transport.get_did_vid()?;
    info!(
        "TPM: TIS device detected (DID=0x{:04x}, VID=0x{:04x})",
        did, vid
    );

    // Create TPM chip with TIS transport.
    let chip = Arc::new(TpmChip::new(tis_transport));

    // Send startup command to initialize the TPM.
    // If it fails, force the chip to initialized state anyway -
    // the TPM might already be initialized by firmware.
    info!("TPM: sending startup command");
    if let Err(e) = chip.startup() {
        warn!("TPM: startup failed (forcing initialized state): {:?}", e);
    }
    // Always ensure chip is in initialized state
    chip.force_initialized();

    // Store global chip instance.
    TPM_CHIP.call_once(|| chip);
    info!("TPM: chip registered");

    Ok(())
}

/// Returns the global TPM chip instance, if initialized.
pub fn get_chip() -> Option<Arc<TpmChip>> {
    TPM_CHIP.get().cloned()
}
