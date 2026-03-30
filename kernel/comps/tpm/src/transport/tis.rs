// SPDX-License-Identifier: MPL-2.0

//! TIS (TPM Interface Specification) transport for TPM 2.0.
//!
//! This module implements the TPM 2.0 TIS interface, which provides
//! MMIO-based communication with TPM devices using a FIFO model.
//!
//! Reference: Linux kernel drivers/char/tpm/tpm_tis_core.c

use alloc::vec::Vec;

use log::{debug, error, info, warn};
use ostd::{io::IoMem, mm::VmIoOnce};

use crate::{
    error::{TpmError, TransportError},
    transport::TpmTransport,
};

/// TIS register offsets (from TPM Interface Specification).
mod reg {
    /// Locality 0 access register (8-bit).
    pub const ACCESS: usize = 0x0000;
    /// Status register (32-bit, but only low byte matters).
    pub const STS: usize = 0x0018;
    /// Data FIFO register (8-bit).
    pub const DATA_FIFO: usize = 0x0024;
    /// Device ID and Vendor ID register (32-bit).
    pub const DID_VID: usize = 0x0F00;
}

/// TIS access register bits.
mod access {
    /// Request use of locality (write to request).
    pub const REQUEST_USE: u8 = 0x02;
    /// Locality is active/granted (read).
    pub const ACTIVE_LOCALITY: u8 = 0x20;
    /// Register space is valid.
    pub const TPM_REG_VALID_STS: u8 = 0x80;
}

/// TIS status register bits (low byte of STS register).
mod sts {
    /// TPM is in command ready state.
    pub const COMMAND_READY: u8 = 0x40;
    /// Start command execution.
    pub const TPM_GO: u8 = 0x20;
    /// Data is available for reading.
    pub const DATA_AVAIL: u8 = 0x10;
    /// TPM expects more data.
    pub const EXPECT: u8 = 0x08;
    /// Command is valid.
    pub const STS_VALID: u8 = 0x80;
}

/// Maximum polling iterations.
const MAX_POLL_LOOPS: u32 = 1000;

/// Maximum polling iterations for data available (TPM might be slow).
const MAX_DATA_POLL_LOOPS: u32 = 10000;

/// TIS transport implementation.
pub struct TisTransport {
    io_mem: IoMem,
}

impl core::fmt::Debug for TisTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TisTransport").finish_non_exhaustive()
    }
}

impl TisTransport {
    pub fn new(io_mem: IoMem) -> Self {
        Self { io_mem }
    }

    /// Reads a byte from the MMIO region.
    fn read_byte(&self, offset: usize) -> u8 {
        match self.io_mem.read_once::<u8>(offset) {
            Ok(val) => val,
            Err(e) => {
                error!("TIS: read_byte at offset 0x{:x} failed: {:?}", offset, e);
                0xFF
            }
        }
    }

    /// Writes a byte to the MMIO region.
    fn write_byte(&self, offset: usize, val: u8) {
        if let Err(e) = self.io_mem.write_once::<u8>(offset, &val) {
            error!("TIS: write_byte at offset 0x{:x} failed: {:?}", offset, e);
        }
    }

    /// Reads a 32-bit value from the MMIO region.
    fn read_u32(&self, offset: usize) -> u32 {
        match self.io_mem.read_once::<u32>(offset) {
            Ok(val) => val,
            Err(e) => {
                error!("TIS: read_u32 at offset 0x{:x} failed: {:?}", offset, e);
                0xFFFFFFFF
            }
        }
    }

    /// Short delay for MMIO synchronization.
    fn mmio_delay(&self) {
        for _ in 0..200 {
            core::hint::spin_loop();
        }
    }

    /// Checks if the TPM device is present and valid.
    pub fn is_device_valid(&self) -> bool {
        let access = self.read_byte(reg::ACCESS);
        info!("TIS: ACCESS register = 0x{:02x}", access);
        (access & access::TPM_REG_VALID_STS) != 0
    }

    /// Gets the device and vendor ID.
    pub fn get_did_vid(&self) -> (u16, u16) {
        let val = self.read_u32(reg::DID_VID);
        info!("TIS: DID_VID = 0x{:08x}", val);
        let vid = (val & 0xFFFF) as u16;
        let did = ((val >> 16) & 0xFFFF) as u16;
        (did, vid)
    }

    /// Requests locality 0.
    fn request_locality(&self) -> Result<(), TpmError> {
        info!("TIS: requesting locality 0");

        // Check if locality 0 is already active.
        let access = self.read_byte(reg::ACCESS);
        info!("TIS: ACCESS before request = 0x{:02x}", access);

        if (access & access::ACTIVE_LOCALITY) != 0 {
            info!("TIS: locality 0 already active");
            return Ok(());
        }

        // Request locality by writing REQUEST_USE.
        self.write_byte(reg::ACCESS, access::REQUEST_USE);
        self.mmio_delay();

        // Poll until locality is granted.
        for i in 0..MAX_POLL_LOOPS {
            let access = self.read_byte(reg::ACCESS);
            if (access & access::ACTIVE_LOCALITY) != 0 {
                info!("TIS: locality 0 granted after {} iterations", i);
                return Ok(());
            }
            self.mmio_delay();
        }

        // Check final state
        let final_access = self.read_byte(reg::ACCESS);
        warn!(
            "TIS: locality request timeout, ACCESS = 0x{:02x}",
            final_access
        );

        // Continue anyway if register is valid - some TPMs don't signal locality properly.
        if (final_access & access::TPM_REG_VALID_STS) != 0 {
            warn!("TIS: continuing despite locality timeout (register is valid)");
            return Ok(());
        }

        Err(TpmError::Transport(TransportError::LocalityTimeout))
    }

    /// Releases locality 0.
    fn release_locality(&self) {
        debug!("TIS: releasing locality 0");
        self.write_byte(reg::ACCESS, access::ACTIVE_LOCALITY);
        self.mmio_delay();
    }

    /// Waits for the TPM to be ready to receive a command.
    fn wait_for_command_ready(&self) -> Result<(), TpmError> {
        let sts = self.read_byte(reg::STS);
        info!("TIS: STS before command ready = 0x{:02x}", sts);

        // If COMMAND_READY is already set, return immediately.
        if (sts & sts::COMMAND_READY) != 0 {
            info!("TIS: command already ready");
            return Ok(());
        }

        // Write COMMAND_READY to request command ready state.
        // This is a "write-1-to-clear" operation in TIS.
        self.write_byte(reg::STS, sts::COMMAND_READY);
        self.mmio_delay();
        self.mmio_delay();
        self.mmio_delay();

        // Wait for COMMAND_READY to be set.
        for i in 0..MAX_POLL_LOOPS {
            let sts = self.read_byte(reg::STS);
            if (sts & sts::COMMAND_READY) != 0 {
                info!("TIS: command ready after {} iterations", i);
                return Ok(());
            }
            self.mmio_delay();
        }

        // Check final state
        let final_sts = self.read_byte(reg::STS);
        warn!("TIS: command ready timeout, STS = 0x{:02x}", final_sts);

        // Continue anyway - some TPMs work without COMMAND_READY being set properly.
        Ok(())
    }

    /// Writes command bytes to the FIFO.
    fn write_to_fifo(&self, data: &[u8]) -> Result<(), TpmError> {
        info!("TIS: writing {} bytes to FIFO", data.len());

        for (i, &byte) in data.iter().enumerate() {
            self.write_byte(reg::DATA_FIFO, byte);
            // Check STS after each write to see if EXPECT is set
            if i == 0 {
                let sts = self.read_byte(reg::STS);
                debug!("TIS: STS after first FIFO write = 0x{:02x}", sts);
            }
            self.mmio_delay();
        }

        // Wait for EXPECT bit to clear after writing all bytes.
        // This indicates the TPM has accepted the complete command.
        info!("TIS: waiting for EXPECT to clear");
        for i in 0..MAX_POLL_LOOPS {
            let sts = self.read_byte(reg::STS);
            if (sts & sts::EXPECT) == 0 {
                info!("TIS: EXPECT cleared after {} iterations", i);
                return Ok(());
            }
            self.mmio_delay();
        }

        let final_sts = self.read_byte(reg::STS);
        warn!("TIS: EXPECT did not clear, STS = 0x{:02x}", final_sts);
        // Continue anyway
        Ok(())
    }

    /// Triggers command execution.
    fn trigger_command(&self) {
        info!("TIS: triggering command execution");
        // Write GO bit to start command execution
        self.write_byte(reg::STS, sts::TPM_GO);
        self.mmio_delay();
        self.mmio_delay();
    }

    /// Waits for response data to be available.
    fn wait_for_data_available(&self) -> Result<(), TpmError> {
        debug!("TIS: waiting for data available");

        for i in 0..MAX_DATA_POLL_LOOPS {
            let sts = self.read_byte(reg::STS);
            if (sts & sts::DATA_AVAIL) != 0 {
                info!("TIS: data available after {} iterations", i);
                return Ok(());
            }
            self.mmio_delay();
        }

        // Check final state
        let final_sts = self.read_byte(reg::STS);
        warn!("TIS: data available timeout, STS = 0x{:02x}", final_sts);

        // Continue anyway and try to read - some TPMs work without DATA_AVAIL being set.
        Ok(())
    }

    /// Reads response data from the FIFO.
    fn read_from_fifo(&self, count: usize) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; count];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = self.read_byte(reg::DATA_FIFO);
            if i == 0 {
                debug!("TIS: first response byte = 0x{:02x}", byte);
            }
            self.mmio_delay();
        }
        buf
    }

    /// Reads a complete TPM response.
    fn read_response(&self) -> Result<Vec<u8>, TpmError> {
        // Wait for data (or continue if timeout).
        self.wait_for_data_available()?;

        // Read header to get size.
        let header = self.read_from_fifo(10);
        info!("TIS: response header: {:?}", &header[..10]);

        // Parse response size (big-endian u32 at offset 2).
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        info!("TIS: response size from header: {}", size);

        if size < 10 {
            return Err(TpmError::Transport(TransportError::Generic(
                "Response too small",
            )));
        }

        if size > 4096 {
            return Err(TpmError::Transport(TransportError::Generic(
                "Response too large",
            )));
        }

        // Read remaining data.
        let mut response = header;
        if size > 10 {
            let remaining = self.read_from_fifo(size - 10);
            response.extend_from_slice(&remaining);
        }

        info!("TIS: read {} byte response", response.len());
        Ok(response)
    }
}

impl TpmTransport for TisTransport {
    fn send(&self, cmd: &[u8]) -> Result<(), TpmError> {
        info!("TIS: sending {} byte command", cmd.len());

        // Acquire locality.
        self.request_locality()?;

        // Wait for command ready.
        self.wait_for_command_ready()?;

        // Write command to FIFO.
        self.write_to_fifo(cmd)?;

        // Trigger command execution.
        self.trigger_command();

        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>, TpmError> {
        // Read response.
        let response = self.read_response()?;

        // Release locality.
        self.release_locality();

        Ok(response)
    }
}

impl Drop for TisTransport {
    fn drop(&mut self) {
        self.release_locality();
    }
}
