// SPDX-License-Identifier: MPL-2.0

//! TPM character-device bridge — Linux-compatible /dev/tpm0 and /dev/tpmrm0.

use alloc::vec;
use core::sync::atomic::{AtomicBool, Ordering};

use device_id::{DeviceId, MinorId};
use spin::Mutex;

use crate::{
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

const TPM_MINOR: u32 = 224;
const TPMRM_MINOR: u32 = 225;

/// Linux `tpm_common_write`: `size < 6` → EINVAL.
const TPM_MIN_WRITE: usize = 6;
const TPM_HEADER_SIZE: usize = 10;
const TPM2_RC_SIZE_RESPONSE: [u8; TPM_HEADER_SIZE] = [
    0x80, 0x01, // TPM2_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0a, // response size
    0x00, 0x00, 0x00, 0x95, // TPM2_RC_SIZE
];

static TPM0_OPEN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// /dev/tpm0
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TpmDev(DeviceId);

impl TpmDev {
    fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        Arc::new(Self(DeviceId::new(major, MinorId::new(TPM_MINOR))))
    }
}

impl Device for TpmDev {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }
    fn id(&self) -> DeviceId {
        self.0
    }
    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("tpm0"))
    }
    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        if TPM0_OPEN.swap(true, Ordering::Acquire) {
            return_errno_with_message!(Errno::EBUSY, "/dev/tpm0 is already open");
        }
        Ok(Box::new(TpmFile::new()))
    }
}

struct TpmFile {
    response: Mutex<(Vec<u8>, usize)>,
    response_read: AtomicBool,
    pending_cmd: Mutex<Option<Vec<u8>>>,
}

impl TpmFile {
    fn new() -> Self {
        Self {
            response: Mutex::new((Vec::new(), 0)),
            response_read: AtomicBool::new(true),
            pending_cmd: Mutex::new(None),
        }
    }

    fn drain_pending(&self) -> Result<()> {
        let mut pending = self.pending_cmd.lock();
        if let Some(cmd) = pending.take() {
            drop(pending);
            // Linux accepts writes as short as the six-byte common header and
            // lets the TPM reject an incomplete TPM2 header. The verified
            // transport requires all ten header bytes before it may inspect
            // the command code, so reproduce that observable TPM response at
            // this adapter boundary instead of violating its precondition.
            if cmd.len() < TPM_HEADER_SIZE {
                *self.response.lock() = (TPM2_RC_SIZE_RESPONSE.to_vec(), 0);
                self.response_read.store(false, Ordering::Release);
                return Ok(());
            }
            let device = aster_tpm::device()
                .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
            let max_rsp = device.limits().max_response as usize;
            let mut bytes = vec![0u8; max_rsp];
            let len = device
                .exec(&cmd, &mut bytes)
                .map_err(|_| Error::with_message(Errno::EIO, "TPM command failed"))?;
            bytes.truncate(len);
            *self.response.lock() = (bytes, 0);
            self.response_read.store(false, Ordering::Release);
        }
        Ok(())
    }
}

impl Drop for TpmFile {
    fn drop(&mut self) {
        TPM0_OPEN.store(false, Ordering::Release);
    }
}

impl Pollable for TpmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let _ = self.drain_pending();
        let response = self.response.lock();
        if response.1 < response.0.len() {
            IoEvents::IN & mask
        } else {
            IoEvents::OUT & mask
        }
    }
}

impl FileOps for TpmFile {
    fn read_at(&self, _offset: usize, writer: &mut VmWriter, _flags: StatusFlags) -> Result<usize> {
        self.drain_pending()?;
        let mut response = self.response.lock();
        if response.1 >= response.0.len() {
            return Ok(0);
        }
        let offset = response.1;
        let copied = writer.write_fallible(&mut VmReader::from(&response.0[offset..]))?;
        response.1 += copied;
        // Linux: set response_read on ANY successful read (partial or full),
        // allowing a new write to discard remaining unread response data.
        if copied > 0 {
            self.response_read.store(true, Ordering::Release);
        }
        if response.1 == response.0.len() || copied == 0 {
            response.0.clear();
            response.1 = 0;
        }
        Ok(copied)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader, flags: StatusFlags) -> Result<usize> {
        let device = aster_tpm::device()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
        let command_len = reader.remain();

        if command_len < TPM_MIN_WRITE {
            return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
        }

        // Linux: size > TPM_BUFSIZE → E2BIG (before header validation)
        let max_cmd = device.limits().max_command as usize;
        if command_len > max_cmd {
            return_errno_with_message!(Errno::E2BIG, "TPM command too large");
        }

        let mut command = vec![0u8; command_len];
        reader.read_fallible(&mut VmWriter::from(&mut command[..]))?;

        if command_len >= 6 {
            let declared =
                u32::from_be_bytes([command[2], command[3], command[4], command[5]]) as usize;
            if command_len < declared {
                return_errno_with_message!(Errno::EINVAL, "command size mismatch with header");
            }
        }

        // Linux: (!response_read && response_length) || command_enqueued → EBUSY
        {
            let response = self.response.lock();
            if !self.response_read.load(Ordering::Acquire) && response.1 < response.0.len() {
                return_errno_with_message!(
                    Errno::EBUSY,
                    "TPM response data has not been fully read"
                );
            }
        }
        if self.pending_cmd.lock().is_some() {
            return_errno_with_message!(Errno::EBUSY, "a TPM command is already pending");
        }

        if flags.contains(StatusFlags::O_NONBLOCK) {
            *self.pending_cmd.lock() = Some(command);
            return Ok(command_len);
        }

        if command_len < TPM_HEADER_SIZE {
            *self.response.lock() = (TPM2_RC_SIZE_RESPONSE.to_vec(), 0);
            self.response_read.store(false, Ordering::Release);
            return Ok(command_len);
        }

        let max_rsp = device.limits().max_response as usize;
        let mut bytes = vec![0u8; max_rsp];
        let len = device
            .exec(&command, &mut bytes)
            .map_err(|_| Error::with_message(Errno::EIO, "TPM command failed"))?;
        bytes.truncate(len);
        *self.response.lock() = (bytes, 0);
        self.response_read.store(false, Ordering::Release);
        Ok(command_len)
    }
}

impl PerOpenFileOps for TpmFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "the TPM device is not seekable");
    }
    fn is_offset_aware(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// /dev/tpmrm0
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TpmRmDev(DeviceId);

impl TpmRmDev {
    fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        Arc::new(Self(DeviceId::new(major, MinorId::new(TPMRM_MINOR))))
    }
}

impl Device for TpmRmDev {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }
    fn id(&self) -> DeviceId {
        self.0
    }
    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("tpmrm0"))
    }
    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let device = aster_tpm::device()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
        Ok(Box::new(TpmRmFile::new(device)))
    }
}

struct TpmRmFile {
    device: &'static aster_tpm::TpmDevice,
    space: Mutex<aster_tpm::Space>,
    ctx_buf: Mutex<Vec<u8>>,
    ses_buf: Mutex<Vec<u8>>,
    response: Mutex<(Vec<u8>, usize)>,
    response_read: AtomicBool,
}

impl TpmRmFile {
    fn new(device: &'static aster_tpm::TpmDevice) -> Self {
        Self {
            device,
            space: Mutex::new(aster_tpm::Space::new()),
            ctx_buf: Mutex::new(vec![0u8; aster_tpm::SPACE_BUF]),
            ses_buf: Mutex::new(vec![0u8; aster_tpm::SPACE_BUF]),
            response: Mutex::new((Vec::new(), 0)),
            response_read: AtomicBool::new(true),
        }
    }
}

impl Drop for TpmRmFile {
    fn drop(&mut self) {
        let mut space = self.space.lock();
        self.device.close_space(&mut *space);
    }
}

impl Pollable for TpmRmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let response = self.response.lock();
        if response.1 < response.0.len() {
            IoEvents::IN & mask
        } else {
            IoEvents::OUT & mask
        }
    }
}

impl FileOps for TpmRmFile {
    fn read_at(&self, _offset: usize, writer: &mut VmWriter, _flags: StatusFlags) -> Result<usize> {
        let mut response = self.response.lock();
        if response.1 >= response.0.len() {
            return Ok(0);
        }
        let offset = response.1;
        let copied = writer.write_fallible(&mut VmReader::from(&response.0[offset..]))?;
        response.1 += copied;
        if copied > 0 {
            self.response_read.store(true, Ordering::Release);
        }
        if response.1 == response.0.len() || copied == 0 {
            response.0.clear();
            response.1 = 0;
        }
        Ok(copied)
    }

    fn write_at(
        &self,
        _offset: usize,
        reader: &mut VmReader,
        _flags: StatusFlags,
    ) -> Result<usize> {
        let command_len = reader.remain();
        if command_len < TPM_MIN_WRITE {
            return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
        }
        let max_cmd = self.device.limits().max_command as usize;
        if command_len > max_cmd {
            return_errno_with_message!(Errno::E2BIG, "TPM command too large");
        }
        let mut cmd = vec![0u8; command_len];
        reader.read_fallible(&mut VmWriter::from(&mut cmd[..]))?;
        if command_len >= 6 {
            let declared = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize;
            if command_len < declared {
                return_errno_with_message!(Errno::EINVAL, "command size mismatch with header");
            }
        }
        {
            let response = self.response.lock();
            if !self.response_read.load(Ordering::Acquire) && response.1 < response.0.len() {
                return_errno_with_message!(
                    Errno::EBUSY,
                    "TPM response data has not been fully read"
                );
            }
        }
        let max_rsp = self.device.limits().max_response as usize;
        let mut rsp = vec![0u8; max_rsp];

        let mut space = self.space.lock();
        let mut ctx_buf = self.ctx_buf.lock();
        let mut ses_buf = self.ses_buf.lock();
        let result = self.device.transmit_space(
            &mut *space,
            &mut *ctx_buf,
            &mut *ses_buf,
            &mut cmd,
            command_len,
            &mut rsp,
        );
        let len = match result {
            Ok(len) => len,
            Err(aster_tpm::XmitErr::Unsupported) => {
                // Linux tpm_dev_transmit() turns an unsupported command into
                // a resource-manager-layer TPM2_RC_COMMAND_CODE response.
                rsp[..10]
                    .copy_from_slice(&[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x01, 0x43]);
                10
            }
            Err(error) => {
                let errno = match error {
                    aster_tpm::XmitErr::Malformed | aster_tpm::XmitErr::BadHandle => Errno::EINVAL,
                    aster_tpm::XmitErr::Unsupported => unreachable!(),
                    aster_tpm::XmitErr::NoSlots
                    | aster_tpm::XmitErr::Io(aster_tpm::IoErr::NoSpace) => Errno::ENOMEM,
                    aster_tpm::XmitErr::Io(_) => Errno::EIO,
                };
                return Err(Error::with_message(
                    errno,
                    "TPM resource-manager command failed",
                ));
            }
        };
        rsp.truncate(len);
        *self.response.lock() = (rsp, 0);
        self.response_read.store(false, Ordering::Release);
        Ok(command_len)
    }
}

impl PerOpenFileOps for TpmRmFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "the TPM device is not seekable");
    }
    fn is_offset_aware(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub(super) fn init_in_first_kthread() {
    if aster_tpm::device().is_some() {
        char::register(TpmDev::new()).unwrap();
        char::register(TpmRmDev::new()).unwrap();
    }
}
