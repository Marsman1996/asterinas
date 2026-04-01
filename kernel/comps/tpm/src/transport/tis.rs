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
    /// Retry reading the current response.
    pub const RESPONSE_RETRY: u8 = 0x02;
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
/// Maximum polling iterations for FIFO burst count.
const MAX_BURST_POLL_LOOPS: u32 = 10000;
/// Maximum retries for rereading a response after a transfer error.
const MAX_RESPONSE_RETRIES: usize = 3;
/// Upper bound for a TPM response buffer.
///
/// `TPM2_ContextSave` can legitimately return several kilobytes of context
/// data, so a fixed 4 KiB cap is too small and makes valid responses fail as
/// transport errors.
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

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

    /// Returns the current TIS status register value.
    fn read_status(&self) -> u32 {
        self.read_u32(reg::STS)
    }

    /// Returns the current low-byte TIS status bits.
    fn read_status_byte(&self) -> u8 {
        self.read_status() as u8
    }

    /// Returns the FIFO burst count from the TIS status register.
    fn burst_count(&self) -> usize {
        ((self.read_status() >> 8) & 0xFFFF) as usize
    }

    /// Waits until all requested status bits are set.
    fn wait_for_status(&self, mask: u8, max_loops: u32) -> Result<u8, TpmError> {
        for _ in 0..max_loops {
            let sts = self.read_status_byte();
            if (sts & mask) == mask {
                return Ok(sts);
            }
            self.mmio_delay();
        }

        Err(TpmError::Transport(TransportError::DeviceNotResponding))
    }

    /// Waits until the FIFO burst count is nonzero.
    fn wait_for_burst_count(&self) -> Result<usize, TpmError> {
        for _ in 0..MAX_BURST_POLL_LOOPS {
            let burst = self.burst_count();
            if burst != 0 {
                return Ok(burst);
            }
            self.mmio_delay();
        }

        Err(TpmError::Transport(TransportError::DeviceNotResponding))
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

    /// Forces the TPM back to command-ready state.
    fn ready(&self) {
        self.write_byte(reg::STS, sts::COMMAND_READY);
        self.mmio_delay();
    }

    /// Waits for the TPM to be ready to receive a command.
    fn wait_for_command_ready(&self) -> Result<(), TpmError> {
        let sts = self.read_status_byte();
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

        match self.wait_for_status(sts::COMMAND_READY, MAX_POLL_LOOPS) {
            Ok(sts) => {
                info!("TIS: command ready reached, STS = 0x{:02x}", sts);
                Ok(())
            }
            Err(err) => {
                warn!(
                    "TIS: command ready timeout, STS = 0x{:02x}",
                    self.read_status_byte()
                );
                Err(err)
            }
        }
    }

    /// Writes command bytes to the FIFO.
    fn write_to_fifo(&self, data: &[u8]) -> Result<(), TpmError> {
        info!("TIS: writing {} bytes to FIFO", data.len());

        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        let last_byte_index = data.len() - 1;

        while offset < last_byte_index {
            let burst = self.wait_for_burst_count()?;
            let chunk_len = core::cmp::min(burst, last_byte_index - offset);
            for &byte in &data[offset..offset + chunk_len] {
                self.write_byte(reg::DATA_FIFO, byte);
                self.mmio_delay();
            }
            offset += chunk_len;

            let sts = self.wait_for_status(sts::STS_VALID, MAX_POLL_LOOPS)?;
            if offset != 0 {
                debug!("TIS: STS after FIFO chunk = 0x{:02x}", sts);
            }
            if (sts & sts::EXPECT) == 0 {
                return Err(TpmError::Transport(TransportError::Generic(
                    "TPM stopped accepting command bytes before final byte",
                )));
            }
        }

        self.wait_for_burst_count()?;
        self.write_byte(reg::DATA_FIFO, data[last_byte_index]);
        self.mmio_delay();

        info!("TIS: waiting for EXPECT to clear");
        let sts = self.wait_for_status(sts::STS_VALID, MAX_POLL_LOOPS)?;
        if (sts & sts::EXPECT) != 0 {
            warn!(
                "TIS: EXPECT still set after final byte, STS = 0x{:02x}",
                sts
            );
            return Err(TpmError::Transport(TransportError::Generic(
                "TPM still expects command data after final byte",
            )));
        }

        info!("TIS: EXPECT cleared, STS = 0x{:02x}", sts);
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

        match self.wait_for_status(sts::DATA_AVAIL | sts::STS_VALID, MAX_DATA_POLL_LOOPS) {
            Ok(sts) => {
                info!("TIS: data available, STS = 0x{:02x}", sts);
                Ok(())
            }
            Err(err) => {
                warn!(
                    "TIS: data available timeout, STS = 0x{:02x}",
                    self.read_status_byte()
                );
                Err(err)
            }
        }
    }

    /// Reads response data from the FIFO.
    fn read_from_fifo(&self, count: usize) -> Result<Vec<u8>, TpmError> {
        let mut buf = alloc::vec![0u8; count];
        let mut offset = 0;

        while offset < count {
            self.wait_for_status(sts::DATA_AVAIL | sts::STS_VALID, MAX_DATA_POLL_LOOPS)?;
            let burst = self.wait_for_burst_count()?;
            let chunk_len = core::cmp::min(burst, count - offset);
            for i in 0..chunk_len {
                let byte = self.read_byte(reg::DATA_FIFO);
                if offset == 0 && i == 0 {
                    debug!("TIS: first response byte = 0x{:02x}", byte);
                }
                buf[offset + i] = byte;
                self.mmio_delay();
            }
            offset += chunk_len;
        }

        Ok(buf)
    }

    /// Reads a complete TPM response.
    fn read_response(&self) -> Result<Vec<u8>, TpmError> {
        // Wait for data (or continue if timeout).
        self.wait_for_data_available()?;

        // Read header to get size.
        let header = self.read_from_fifo(10)?;
        info!("TIS: response header: {:?}", &header[..10]);

        // Parse response size (big-endian u32 at offset 2).
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        info!("TIS: response size from header: {}", size);

        if size < 10 {
            return Err(TpmError::Transport(TransportError::Generic(
                "Response too small",
            )));
        }

        if size > MAX_RESPONSE_SIZE {
            return Err(TpmError::Transport(TransportError::Generic(
                "Response too large",
            )));
        }

        // Read remaining data.
        let mut response = header;
        if size > 10 {
            let remaining = self.read_from_fifo(size - 10)?;
            response.extend_from_slice(&remaining);
        }

        let sts = self.wait_for_status(sts::STS_VALID, MAX_DATA_POLL_LOOPS)?;
        if (sts & sts::DATA_AVAIL) != 0 {
            return Err(TpmError::Transport(TransportError::Generic(
                "Unread response data left in FIFO",
            )));
        }

        // Return the TPM to command-ready state before the next command.
        // Some command sequences issued by tpm2-tss perform immediate follow-up
        // commands or resubmissions on the same file descriptor; leaving the TIS
        // state machine in the completed-command state can cause the next send to
        // fail spuriously.
        self.ready();
        self.wait_for_command_ready()?;

        info!("TIS: read {} byte response", response.len());
        Ok(response)
    }
}

impl TpmTransport for TisTransport {
    fn send(&self, cmd: &[u8]) -> Result<(), TpmError> {
        info!("TIS: sending {} byte command", cmd.len());

        let result = (|| {
            self.request_locality()?;
            self.wait_for_command_ready()?;
            self.write_to_fifo(cmd)?;
            self.trigger_command();
            Ok(())
        })();

        if result.is_err() {
            self.ready();
            self.release_locality();
        }

        result
    }

    fn recv(&self) -> Result<Vec<u8>, TpmError> {
        let mut last_error = None;

        for attempt in 0..MAX_RESPONSE_RETRIES {
            match self.read_response() {
                Ok(response) => {
                    self.release_locality();
                    return Ok(response);
                }
                Err(err) => {
                    warn!(
                        "TIS: response read failed on attempt {}: {:?}",
                        attempt + 1,
                        err
                    );
                    last_error = Some(err);
                    if attempt + 1 < MAX_RESPONSE_RETRIES {
                        self.write_byte(reg::STS, sts::RESPONSE_RETRY);
                        self.mmio_delay();
                    }
                }
            }
        }

        self.ready();
        self.release_locality();
        Err(last_error.unwrap())
    }
}

impl Drop for TisTransport {
    fn drop(&mut self) {
        self.release_locality();
    }
}
