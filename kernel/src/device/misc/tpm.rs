// SPDX-License-Identifier: MPL-2.0

//! TPM (Trusted Platform Module) device bridge.
//!
//! Exposes `/dev/tpm0` as a character device for userspace TPM command submission.
//! Command serialization is handled at the chip level, not via exclusive open.
//!
//! Implements Linux-compatible partial-read semantics for tpm2-tss compatibility.

use alloc::{sync::Arc, vec::Vec};

use aster_tpm::TpmChip;
use device_id::{DeviceId, MinorId};
use log::{debug, info, warn};
use ostd::mm::{Infallible, VmReader, VmWriter};

use crate::{
    device::{Device, DeviceType},
    events::IoEvents,
    fs::{
        file::{FileIo, StatusFlags},
        vfs::inode::InodeIo,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
};

/// Minor device number for TPM devices.
const TPM_MINOR: u32 = 0;
/// Upper bound for a TPM command submitted through the character device.
const MAX_TPM_COMMAND_SIZE: usize = 64 * 1024;

/// Global TPM chip instance.
static TPM_CHIP: spin::Once<Arc<TpmChip>> = spin::Once::new();

/// TPM response buffer with partial read support.
///
/// This implements Linux tpm-dev-common style response buffering:
/// - Full response is stored after command execution
/// - Partial reads advance an offset without clearing the buffer
/// - Poll/read readiness remains while unread bytes exist
/// - Buffer is cleared only after full consumption or new command
pub struct TpmResponseBuffer {
    /// The response data.
    response: Option<Vec<u8>>,
    /// Current read offset into the response.
    offset: usize,
}

impl TpmResponseBuffer {
    /// Creates a new empty response buffer.
    pub fn new() -> Self {
        Self {
            response: None,
            offset: 0,
        }
    }

    /// Sets a new response, clearing any previous state.
    pub fn set_response(&mut self, data: Vec<u8>) {
        self.response = Some(data);
        self.offset = 0;
    }

    /// Reads bytes from the current offset and advances the offset.
    ///
    /// Returns the number of bytes read into the writer.
    pub fn read_partial(&mut self, writer: &mut VmWriter) -> Result<usize> {
        let Some(ref data) = self.response else {
            return Ok(0);
        };

        if self.offset >= data.len() {
            // All data consumed
            return Ok(0);
        }

        let remaining = &data[self.offset..];
        let mut reader: VmReader<Infallible> = remaining.into();
        let read_len = writer.write_fallible(&mut reader)?;

        self.offset += read_len;

        // Clear buffer if fully consumed
        if self.offset >= data.len() {
            self.response = None;
            self.offset = 0;
        }

        Ok(read_len)
    }

    /// Returns the number of unread bytes remaining.
    pub fn remaining(&self) -> usize {
        match &self.response {
            Some(data) => data.len().saturating_sub(self.offset),
            None => 0,
        }
    }

    /// Returns true if the response has been fully consumed.
    pub fn is_complete(&self) -> bool {
        self.response.is_none() || self.offset >= self.response.as_ref().unwrap().len()
    }

    /// Clears the response buffer.
    pub fn clear(&mut self) {
        self.response = None;
        self.offset = 0;
    }
}

impl core::fmt::Debug for TpmResponseBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmResponseBuffer")
            .field("has_response", &self.response.is_some())
            .field("remaining", &self.remaining())
            .finish()
    }
}

/// The `/dev/tpm0` device.
#[derive(Debug)]
pub struct TpmDevice {
    id: DeviceId,
}

impl TpmDevice {
    /// Creates a new TPM device.
    pub fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        let minor = MinorId::new(TPM_MINOR);

        let id = DeviceId::new(major, minor);
        Arc::new(Self { id })
    }

    /// Registers the TPM chip for this device.
    pub fn register_chip(chip: Arc<TpmChip>) {
        TPM_CHIP.call_once(|| chip);
        info!("TPM: /dev/tpm0 registered");
    }
}

impl Device for TpmDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn devtmpfs_path(&self) -> Option<String> {
        Some("tpm0".into())
    }

    fn open(&self) -> Result<Box<dyn FileIo>> {
        // No exclusive access - command serialization is per-chip via mutex.
        debug!("TPM: /dev/tpm0 opened");
        Ok(Box::new(TpmFile::new()?))
    }
}

/// File handle for TPM device I/O.
///
/// Tracks sessions created through this file handle for cleanup on close.
struct TpmFile {
    /// Response buffer with partial read support.
    response_buffer: spin::Mutex<TpmResponseBuffer>,
    /// Session handles created through this file.
    sessions: spin::Mutex<alloc::collections::BTreeSet<u32>>,
    /// Poll notification state for response-buffer transitions.
    pollee: Pollee,
}

impl core::fmt::Debug for TpmFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmFile").finish()
    }
}

impl TpmFile {
    fn new() -> Result<Self> {
        Ok(Self {
            response_buffer: spin::Mutex::new(TpmResponseBuffer::new()),
            sessions: spin::Mutex::new(alloc::collections::BTreeSet::new()),
            pollee: Pollee::new(),
        })
    }

    /// Tracks a session handle.
    fn track_session(&self, handle: u32) {
        self.sessions.lock().insert(handle);
        debug!("TPM: tracking session 0x{:08x} on /dev/tpm0", handle);
    }

    /// Flushes all tracked sessions.
    fn flush_sessions(&self) {
        let sessions: Vec<u32> = self.sessions.lock().iter().copied().collect();
        for handle in sessions {
            if let Some(chip) = TPM_CHIP.get() {
                debug!("TPM: flushing session 0x{:08x} on /dev/tpm0 close", handle);
                if let Err(e) = chip.flush_context(handle) {
                    warn!("TPM: failed to flush session 0x{:08x}: {:?}", handle, e);
                }
            }
        }
        self.sessions.lock().clear();
    }

    /// Returns the currently available I/O events.
    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::OUT;
        if self.response_buffer.lock().remaining() > 0 {
            events |= IoEvents::IN;
        }
        events
    }

    /// Clears any buffered TPM response and invalidates readable events if needed.
    fn clear_response(&self) {
        let mut response = self.response_buffer.lock();
        let had_bytes = response.remaining() > 0;
        response.clear();
        drop(response);

        if had_bytes {
            self.pollee.invalidate();
        }
    }

    /// Stores a new TPM response and wakes readers.
    fn store_response(&self, data: Vec<u8>) {
        self.response_buffer.lock().set_response(data);
        self.pollee.notify(IoEvents::IN);
    }

    /// Attempts to read bytes from the buffered TPM response.
    fn try_read_response(&self, writer: &mut VmWriter) -> Result<usize> {
        let mut response = self.response_buffer.lock();
        if response.remaining() == 0 {
            return_errno_with_message!(Errno::EAGAIN, "no TPM response available");
        }

        let read_len = response.read_partial(writer)?;
        let has_remaining = response.remaining() > 0;
        drop(response);

        if has_remaining {
            self.pollee.notify(IoEvents::IN);
        } else {
            self.pollee.invalidate();
        }

        Ok(read_len)
    }
}

impl Drop for TpmFile {
    fn drop(&mut self) {
        self.flush_sessions();
    }
}

impl Pollable for TpmFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl InodeIo for TpmFile {
    fn read_at(
        &self,
        _offset: usize,
        writer: &mut VmWriter,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        if writer.avail() == 0 {
            return Ok(0);
        }

        if status_flags.contains(StatusFlags::O_NONBLOCK) {
            self.try_read_response(writer)
        } else {
            self.wait_events(IoEvents::IN, None, || self.try_read_response(writer))
        }
    }

    fn write_at(
        &self,
        _offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let chip = TPM_CHIP
            .get()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "No TPM chip registered"))?;

        // Clear previous response before new command.
        self.clear_response();

        if reader.remain() > MAX_TPM_COMMAND_SIZE {
            return Err(Error::with_message(
                Errno::EMSGSIZE,
                "TPM command exceeds the supported size limit",
            ));
        }

        // Read command buffer from userspace.
        let mut cmd_buf = alloc::vec![0u8; reader.remain()];
        let read_len = reader.read_fallible(&mut cmd_buf.as_mut_slice().into())?;

        // Validate TPM header (minimum 10 bytes).
        if read_len < 10 {
            return Err(Error::with_message(
                Errno::EINVAL,
                "Command buffer too short for TPM header",
            ));
        }

        // Execute command - serialization is handled by TpmChip.
        debug!("TPM: executing {} byte command from userspace", read_len);
        let response = chip.execute_command(&cmd_buf[..read_len]).map_err(|e| {
            warn!("TPM: command failed: {:?}", e);
            Error::with_message(Errno::EIO, "TPM command execution failed")
        })?;

        // Check if this was a StartAuthSession command and track the session handle.
        // TPM2_StartAuthSession command code is 0x00000176
        if read_len >= 10 {
            let cmd_code = u32::from_be_bytes([cmd_buf[6], cmd_buf[7], cmd_buf[8], cmd_buf[9]]);
            if cmd_code == 0x00000176 && response.len() >= 14 {
                let resp_code =
                    u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
                if resp_code == 0 {
                    // Parse session handle from response (first 4 bytes of body)
                    let handle = u32::from_be_bytes([
                        response[10],
                        response[11],
                        response[12],
                        response[13],
                    ]);
                    if handle != 0 {
                        self.track_session(handle);
                    }
                }
            }
        }

        // Store response for subsequent read.
        debug!("TPM: storing {} byte response", response.len());
        self.store_response(response);

        Ok(read_len)
    }
}

impl FileIo for TpmFile {
    fn check_seekable(&self) -> Result<()> {
        Err(Error::with_message(Errno::ESPIPE, "seek is not supported"))
    }

    fn is_offset_aware(&self) -> bool {
        false
    }
}
