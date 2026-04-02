// SPDX-License-Identifier: MPL-2.0

//! TPM Resource Manager device bridge.
//!
//! Exposes `/dev/tpmrm0` as a character device for resource-managed TPM access.
//! Each open creates its own TPM space with isolated resource context.
//!
//! Implements Linux-compatible partial-read semantics for tpm2-tss compatibility.

use alloc::{sync::Arc, vec::Vec};

use aster_tpm::{TpmChip, TpmSpace, TpmSpaceManager};
use device_id::{DeviceId, MinorId};
use log::{debug, error, info, warn};
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

/// Minor device number for TPM resource manager.
const TPMRM_MINOR: u32 = 1;
/// Upper bound for a TPM command submitted through the resource-manager device.
const MAX_TPM_COMMAND_SIZE: usize = 64 * 1024;
/// TPM2_CreatePrimary command code.
const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
/// TPM2_Load command code.
const TPM2_CC_LOAD: u32 = 0x0000_0157;
/// TPM2_StartAuthSession command code.
const TPM2_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
/// TPM2_FlushContext command code.
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
/// TPM2_ContextLoad command code.
const TPM2_CC_CONTEXT_LOAD: u32 = 0x0000_0161;
/// Start of the HMAC session handle range.
const TPM_HMAC_SESSION_HANDLE_START: u32 = 0x0200_0000;
/// End of the HMAC session handle range.
const TPM_HMAC_SESSION_HANDLE_END: u32 = 0x02FF_FFFF;
/// Start of the policy session handle range.
const TPM_POLICY_SESSION_HANDLE_START: u32 = 0x0300_0000;
/// End of the policy session handle range.
const TPM_POLICY_SESSION_HANDLE_END: u32 = 0x03FF_FFFF;
/// Start of the transient object handle range.
const TPM_TRANSIENT_HANDLE_START: u32 = 0x8000_0000;
/// End of the transient object handle range.
const TPM_TRANSIENT_HANDLE_END: u32 = 0x80FF_FFFF;

/// Global TPM chip instance for resource manager.
static TPMRM_CHIP: spin::Once<Arc<TpmChip>> = spin::Once::new();

/// Global space manager for resource manager device.
static SPACE_MANAGER: spin::Once<TpmSpaceManager> = spin::Once::new();

/// TPM response buffer with partial read support.
///
/// This implements Linux tpm-dev-common style response buffering:
/// - Full response is stored after command execution
/// - Partial reads advance an offset without clearing the buffer
/// - Poll/read readiness remains while unread bytes exist
/// - Buffer is cleared only after full consumption or new command
pub struct TpmRmResponseBuffer {
    /// The response data.
    response: Option<Vec<u8>>,
    /// Current read offset into the response.
    offset: usize,
}

impl TpmRmResponseBuffer {
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

    /// Clears the response buffer.
    pub fn clear(&mut self) {
        self.response = None;
        self.offset = 0;
    }
}

impl core::fmt::Debug for TpmRmResponseBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmRmResponseBuffer")
            .field("has_response", &self.response.is_some())
            .field("remaining", &self.remaining())
            .finish()
    }
}

/// The `/dev/tpmrm0` device.
#[derive(Debug)]
pub struct TpmRmDevice {
    id: DeviceId,
}

impl TpmRmDevice {
    /// Creates a new TPM resource manager device.
    pub fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        let minor = MinorId::new(TPMRM_MINOR);

        let id = DeviceId::new(major, minor);
        Arc::new(Self { id })
    }

    /// Registers the TPM chip for this device.
    pub fn register_chip(chip: Arc<TpmChip>) {
        TPMRM_CHIP.call_once(|| chip);
        SPACE_MANAGER.call_once(aster_tpm::TpmSpaceManager::new);
        info!("TPM: /dev/tpmrm0 registered");
    }
}

impl Device for TpmRmDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn devtmpfs_path(&self) -> Option<String> {
        Some("tpmrm0".into())
    }

    fn open(&self) -> Result<Box<dyn FileIo>> {
        debug!("TPM: /dev/tpmrm0 opened");

        // Create a new space for this open.
        let space_manager = SPACE_MANAGER
            .get()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "TPM not initialized"))?;

        let space = space_manager.create_space();
        let space_id = space.id();

        debug!("TPM: created space {} for /dev/tpmrm0", space_id);
        Ok(Box::new(TpmRmFile::new(space)?))
    }
}

/// File handle for TPM resource manager I/O.
struct TpmRmFile {
    /// The TPM space for this file handle.
    space: Arc<TpmSpace>,
    /// Response buffer with partial read support.
    response_buffer: spin::Mutex<TpmRmResponseBuffer>,
    /// Poll notification state for response-buffer transitions.
    pollee: Pollee,
}

impl core::fmt::Debug for TpmRmFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmRmFile")
            .field("space_id", &self.space.id())
            .finish()
    }
}

impl TpmRmFile {
    fn new(space: Arc<TpmSpace>) -> Result<Self> {
        Ok(Self {
            space,
            response_buffer: spin::Mutex::new(TpmRmResponseBuffer::new()),
            pollee: Pollee::new(),
        })
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

impl Drop for TpmRmFile {
    fn drop(&mut self) {
        if let Some(chip) = TPMRM_CHIP.get() {
            chip.close_space(&self.space);
        }

        // Dispose the space and clean up resources.
        debug!(
            "TPM: disposing space {} on /dev/tpmrm0 close",
            self.space.id()
        );
        self.space.dispose();

        // Also remove from space manager if available.
        if let Some(space_manager) = SPACE_MANAGER.get() {
            space_manager.dispose_space(self.space.id());
        }
    }
}

impl Pollable for TpmRmFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl InodeIo for TpmRmFile {
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
        let chip = TPMRM_CHIP
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

        // Execute command in the context of this space.
        debug!(
            "TPM: executing {} byte command in space {} from /dev/tpmrm0",
            read_len,
            self.space.id()
        );

        // Use space-aware command execution.
        let response = chip
            .execute_command_in_space(&cmd_buf[..read_len], &self.space)
            .map_err(|e| {
                let cmd_code = u32::from_be_bytes([cmd_buf[6], cmd_buf[7], cmd_buf[8], cmd_buf[9]]);
                error!(
                    "TPM: /dev/tpmrm0 command 0x{:08x} failed in space {}: {:?}",
                    cmd_code,
                    self.space.id(),
                    e
                );
                Error::with_message(Errno::EIO, "TPM command execution failed")
            })?;

        // Check if this was a StartAuthSession command and track the session handle.
        // TPM2_StartAuthSession command code is 0x00000176
        if read_len >= 10 {
            let cmd_code = u32::from_be_bytes([cmd_buf[6], cmd_buf[7], cmd_buf[8], cmd_buf[9]]);
            let response_code = if response.len() >= 10 {
                Some(u32::from_be_bytes([
                    response[6],
                    response[7],
                    response[8],
                    response[9],
                ]))
            } else {
                None
            };

            if response_code == Some(0) {
                if cmd_code == TPM2_CC_START_AUTH_SESSION && response.len() >= 14 {
                    // Parse session handle from response (first 4 bytes of body)
                    let handle = u32::from_be_bytes([
                        response[10],
                        response[11],
                        response[12],
                        response[13],
                    ]);
                    if handle != 0 {
                        self.space.track_session(handle);
                    }
                }

                if (cmd_code == TPM2_CC_CREATE_PRIMARY
                    || cmd_code == TPM2_CC_LOAD
                    || cmd_code == TPM2_CC_CONTEXT_LOAD)
                    && response.len() >= 14
                {
                    let handle = u32::from_be_bytes([
                        response[10],
                        response[11],
                        response[12],
                        response[13],
                    ]);
                    if (TPM_TRANSIENT_HANDLE_START..=TPM_TRANSIENT_HANDLE_END).contains(&handle) {
                        self.space.track_object(handle);
                    } else if (TPM_HMAC_SESSION_HANDLE_START..=TPM_HMAC_SESSION_HANDLE_END)
                        .contains(&handle)
                        || (TPM_POLICY_SESSION_HANDLE_START..=TPM_POLICY_SESSION_HANDLE_END)
                            .contains(&handle)
                    {
                        self.space.track_session(handle);
                    }
                }
            }

            // Check if this was a FlushContext command and untrack the flushed handle.
            if cmd_code == TPM2_CC_FLUSH_CONTEXT
                && read_len >= 14
                && response_code == Some(0)
            {
                // Parse handle from command (bytes 10-13)
                let handle =
                    u32::from_be_bytes([cmd_buf[10], cmd_buf[11], cmd_buf[12], cmd_buf[13]]);
                self.space.untrack_session(handle);
                self.space.untrack_object(handle);
            }
        }

        // Store response for subsequent read.
        debug!("TPM: storing {} byte response", response.len());
        self.store_response(response);

        debug!(
            "TPM: command executed successfully in space {}",
            self.space.id()
        );
        Ok(read_len)
    }
}

impl FileIo for TpmRmFile {
    fn check_seekable(&self) -> Result<()> {
        Err(Error::with_message(Errno::ESPIPE, "seek is not supported"))
    }

    fn is_offset_aware(&self) -> bool {
        false
    }
}
