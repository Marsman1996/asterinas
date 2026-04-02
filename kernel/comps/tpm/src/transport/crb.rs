// SPDX-License-Identifier: MPL-2.0

//! CRB (Command Response Buffer) transport for TPM 2.0.
//!
//! This module implements the TPM 2.0 CRB interface, which provides
//! MMIO-based communication with TPM devices.
//!
//! Reference: Linux kernel drivers/char/tpm/tpm_crb.c

use alloc::{vec, vec::Vec};

use ostd::{io::IoMem, mm::VmIoOnce};

use crate::{
    error::{TpmError, TransportError},
    transport::TpmTransport,
};

/// CRB register offsets (from Linux tpm_crb.c).
mod reg {
    /// Locality 0 registers base offset.
    pub const LOCALITY_0: usize = 0x0000;
    /// CRB control area offset.
    pub const CTRL_AREA: usize = 0x0040;
    /// CRB control request register offset.
    pub const CTRL_REQUEST: usize = 0x0040;
    /// CRB control status register offset.
    pub const CTRL_STS: usize = 0x004C;
    /// CRB control cancel register offset.
    pub const CTRL_CANCEL: usize = 0x0050;
    /// CRB control start register offset.
    pub const CTRL_START: usize = 0x0058;
    /// CRB command buffer size register offset.
    pub const CTRL_CMD_SIZE: usize = 0x005C;
    /// CRB command buffer address register offset (low 32 bits).
    pub const CTRL_CMD_PA_LOW: usize = 0x0060;
    /// CRB command buffer address register offset (high 32 bits).
    pub const CTRL_CMD_PA_HIGH: usize = 0x0064;
    /// CRB response buffer address register offset (low 32 bits).
    pub const CTRL_RSP_PA_LOW: usize = 0x0068;
    /// CRB response buffer address register offset (high 32 bits).
    pub const CTRL_RSP_PA_HIGH: usize = 0x006C;
    /// CRB response buffer size register offset.
    pub const CTRL_RSP_SIZE: usize = 0x0070;
}

/// CRB control status register bits (from Linux tpm_crb.h).
mod sts {
    /// TPM is in idle state.
    pub const TPM_IDLE: u32 = 0x00000001;
    /// Locality is assigned.
    pub const LOCALITY_ASSIGNED: u32 = 0x00000002;
    /// TpmRegValidSts - register space is valid.
    pub const TPM_REG_VALID_STS: u32 = 0x00000080;
    /// Command is ready for response.
    pub const TPM_STS_READY: u32 = 0x00000040;
}

/// CRB control request register values.
mod req {
    /// Request locality 0.
    pub const GO_IDLE: u32 = 0x00000002;
    /// Request locality 0.
    pub const LOCALITY_0: u32 = 0x00000001;
    /// Relinquish locality (go idle).
    pub const RELINQUISH: u32 = 0x00000000;
}

/// CRB control start register bits.
mod start {
    /// Start command execution.
    pub const START: u32 = 0x00000001;
}

/// Maximum number of polling iterations for timeout.
/// This gives approximately 5 seconds at typical CPU speeds.
const MAX_POLL_ITERATIONS: u64 = 50_000_000;

/// CRB data buffer offset within MMIO region.
const CRB_DATA_BUFFER_OFFSET: usize = 0x80;

/// CRB transport implementation.
///
/// This implements the TPM 2.0 CRB (Command Response Buffer) interface
/// which provides MMIO-based communication with TPM devices.
pub struct CrbTransport {
    /// MMIO region for CRB registers.
    io_mem: IoMem,
}

impl core::fmt::Debug for CrbTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CrbTransport").finish_non_exhaustive()
    }
}

impl CrbTransport {
    /// Creates a new CRB transport from an MMIO region.
    ///
    /// # Arguments
    /// * `io_mem` - MMIO region for CRB registers
    pub fn new(io_mem: IoMem) -> Self {
        Self { io_mem }
    }

    /// Reads a 32-bit register at the given offset.
    fn read_reg32(&self, offset: usize) -> Result<u32, TpmError> {
        self.io_mem
            .read_once::<u32>(offset)
            .map_err(|_| TpmError::Transport(TransportError::MmioAccess))
    }

    /// Writes a 32-bit register at the given offset.
    fn write_reg32(&self, offset: usize, value: u32) -> Result<(), TpmError> {
        self.io_mem
            .write_once::<u32>(offset, &value)
            .map_err(|_| TpmError::Transport(TransportError::MmioAccess))
    }

    /// Checks if the TPM device is present and valid.
    ///
    /// Returns true if the TPM_REG_VALID_STS bit is set in the status register.
    pub fn is_device_valid(&self) -> Result<bool, TpmError> {
        let sts = self.read_reg32(reg::CTRL_STS)?;
        Ok(sts & sts::TPM_REG_VALID_STS != 0)
    }

    /// Requests locality 0 for command execution.
    ///
    /// In CRB mode, locality 0 is typically always available.
    fn request_locality(&self) -> Result<(), TpmError> {
        // Check if TPM register space is valid.
        if !self.is_device_valid()? {
            return Err(TpmError::Transport(TransportError::DeviceNotResponding));
        }

        // In CRB mode, check if we're already in idle state.
        // If not idle, try to go idle first.
        let sts = self.read_reg32(reg::CTRL_STS)?;
        if sts & sts::TPM_IDLE == 0 {
            // Not idle, try to request locality.
            self.write_reg32(reg::CTRL_REQUEST, req::LOCALITY_0)?;

            // Wait for locality to be assigned.
            for _ in 0..MAX_POLL_ITERATIONS {
                let sts = self.read_reg32(reg::CTRL_STS)?;
                if sts & sts::LOCALITY_ASSIGNED != 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
            return Err(TpmError::Transport(TransportError::LocalityTimeout));
        }

        // Already idle, just request locality.
        self.write_reg32(reg::CTRL_REQUEST, req::LOCALITY_0)?;

        // Wait for locality to be assigned.
        for _ in 0..MAX_POLL_ITERATIONS {
            let sts = self.read_reg32(reg::CTRL_STS)?;
            if sts & sts::LOCALITY_ASSIGNED != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(TpmError::Transport(TransportError::LocalityTimeout))
    }

    /// Releases locality 0.
    fn release_locality(&self) {
        // Request to go idle.
        let _ = self.write_reg32(reg::CTRL_REQUEST, req::GO_IDLE);
    }

    /// Waits for the TPM to be in idle state.
    fn wait_for_idle(&self) -> Result<(), TpmError> {
        for _ in 0..MAX_POLL_ITERATIONS {
            let sts = self.read_reg32(reg::CTRL_STS)?;
            if sts & sts::TPM_IDLE != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(TpmError::Transport(TransportError::DeviceNotResponding))
    }

    /// Writes command data to the command buffer.
    fn write_command(&self, cmd: &[u8]) -> Result<(), TpmError> {
        let cmd_size = self.read_reg32(reg::CTRL_CMD_SIZE)? as usize;

        if cmd.len() > cmd_size {
            return Err(TpmError::Transport(TransportError::Generic(
                "Command too large for CRB buffer",
            )));
        }

        // Wait for TPM to be idle before writing command.
        self.wait_for_idle()?;

        // Write command to CRB data buffer.
        for (i, &byte) in cmd.iter().enumerate() {
            self.io_mem
                .write_once::<u8>(CRB_DATA_BUFFER_OFFSET + i, &byte)
                .map_err(|_| TpmError::Transport(TransportError::MmioAccess))?;
        }

        Ok(())
    }

    /// Triggers command execution.
    fn trigger_start(&self) -> Result<(), TpmError> {
        self.write_reg32(reg::CTRL_START, start::START)
    }

    /// Waits for command completion.
    fn wait_completion(&self) -> Result<(), TpmError> {
        // After triggering start, wait for TPM to return to idle.
        for _ in 0..MAX_POLL_ITERATIONS {
            let sts = self.read_reg32(reg::CTRL_STS)?;
            // TPM returns to idle when command completes.
            if sts & sts::TPM_IDLE != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(TpmError::Transport(TransportError::DeviceNotResponding))
    }

    /// Reads response data from the response buffer.
    fn read_response(&self) -> Result<Vec<u8>, TpmError> {
        // Get response buffer size.
        let rsp_size = self.read_reg32(reg::CTRL_RSP_SIZE)? as usize;

        if rsp_size == 0 {
            return Err(TpmError::Transport(TransportError::Generic(
                "No response available",
            )));
        }

        // Read response header to get actual response size.
        let mut header_buf = [0u8; 10];
        for (i, byte) in header_buf.iter_mut().enumerate() {
            *byte = self
                .io_mem
                .read_once::<u8>(CRB_DATA_BUFFER_OFFSET + i)
                .map_err(|_| TpmError::Transport(TransportError::MmioAccess))?;
        }

        // Parse response size from header (big-endian u32 at offset 2).
        let actual_size =
            u32::from_be_bytes([header_buf[2], header_buf[3], header_buf[4], header_buf[5]])
                as usize;

        // Validate response size.
        if actual_size < 10 {
            return Err(TpmError::Transport(TransportError::Generic(
                "Response too small",
            )));
        }

        if actual_size > rsp_size {
            return Err(TpmError::Transport(TransportError::Generic(
                "Response size exceeds buffer",
            )));
        }

        // Read full response.
        let mut response = vec![0u8; actual_size];
        for (i, byte) in response.iter_mut().enumerate() {
            *byte = self
                .io_mem
                .read_once::<u8>(CRB_DATA_BUFFER_OFFSET + i)
                .map_err(|_| TpmError::Transport(TransportError::MmioAccess))?;
        }

        Ok(response)
    }
}

impl TpmTransport for CrbTransport {
    fn send(&self, cmd: &[u8]) -> Result<(), TpmError> {
        // Acquire locality.
        self.request_locality()?;

        let result = (|| {
            // Write command.
            self.write_command(cmd)?;

            // Trigger execution.
            self.trigger_start()?;

            Ok(())
        })();

        if result.is_err() {
            self.release_locality();
        }

        result
    }

    fn recv(&self) -> Result<Vec<u8>, TpmError> {
        let result = (|| {
            // Wait for completion.
            self.wait_completion()?;

            // Read response.
            self.read_response()
        })();

        self.release_locality();

        result
    }
}

impl Drop for CrbTransport {
    fn drop(&mut self) {
        self.release_locality();
    }
}
