// SPDX-License-Identifier: MPL-2.0

//! TPM character-device bridge.

use alloc::vec;

use device_id::{DeviceId, MinorId};

use crate::{
    device::{registry::char, Device, DeviceType, DevtmpfsInodeMeta},
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

const TPM_MINOR: u32 = 224;
// ChipTransport::exec trait requires cmd.len() >= HEADER_SIZE + 4 (=14)
// and rsp.len() >= HEADER_SIZE + 4 (=14).
// 出处：Formal/code/tpm-core/src/chip.rs:151-152
/// 命令/响应缓冲区最小安全长度。
/// Linux: `tpm_common_write` 要求 `size >= 6` 且 `size >= header->length`，
/// 有效最小值为 TPM_HEADER_SIZE(10)。这里取 10，匹配 `peek_be32(cmd,6)` 的安全要求。
const TPM_MIN_BUF: usize = 10;

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
        Ok(Box::new(TpmFile::new()))
    }
}

struct TpmFile {
    response: Mutex<(Vec<u8>, usize)>,
}

impl TpmFile {
    fn new() -> Self {
        Self { response: Mutex::new((Vec::new(), 0)) }
    }
}

impl Pollable for TpmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let response = self.response.lock();
        let readable = response.1 < response.0.len();
        (IoEvents::OUT
            | if readable { IoEvents::IN } else { IoEvents::empty() })
            & mask
    }
}

impl FileOps for TpmFile {
    fn read_at(&self, _offset: usize, writer: &mut VmWriter, _flags: StatusFlags) -> Result<usize> {
        if writer.avail() == 0 {
            return Ok(0);
        }
        let mut response = self.response.lock();
        if response.1 >= response.0.len() {
            return_errno_with_message!(Errno::EAGAIN, "no TPM response is available");
        }
        let offset = response.1;
        let copied = writer.write_fallible(&mut VmReader::from(&response.0[offset..]))?;
        response.1 += copied;
        if response.1 == response.0.len() {
            response.0.clear();
            response.1 = 0;
        }
        Ok(copied)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader, _flags: StatusFlags) -> Result<usize> {
        let device = aster_tpm::device()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
        let command_len = reader.remain();
        if command_len < TPM_MIN_BUF {
            return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
        }
        if command_len > device.limits().max_command as usize {
            return_errno_with_message!(Errno::EMSGSIZE, "TPM command too large");
        }
        {
            let response = self.response.lock();
            if response.1 < response.0.len() {
                return_errno_with_message!(Errno::EBUSY, "TPM response data has not been fully read");
            }
        }
        let mut command = vec![0; command_len];
        reader.read_fallible(&mut VmWriter::from(&mut command[..]))?;
        let max_rsp = device.limits().max_response as usize;
        if max_rsp < TPM_MIN_BUF {
            return_errno_with_message!(Errno::EIO, "TPM device reported invalid max_response");
        }
        let mut bytes = vec![0; max_rsp];
        let len = device.exec(&command, &mut bytes)
            .map_err(|_| Error::with_message(Errno::EIO, "TPM command failed"))?;
        bytes.truncate(len);
        *self.response.lock() = (bytes, 0);
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
// /dev/tpmrm0 — 资源管理器，多客户端共享
// ---------------------------------------------------------------------------

const TPMRM_MINOR: u32 = 225;

#[derive(Debug)]
struct TpmRmDev(DeviceId);

impl TpmRmDev {
    fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        Arc::new(Self(DeviceId::new(major, MinorId::new(TPMRM_MINOR))))
    }
}

impl Device for TpmRmDev {
    fn type_(&self) -> DeviceType { DeviceType::Char }
    fn id(&self) -> DeviceId { self.0 }
    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("tpmrm0"))
    }
    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(TpmRmFile::new()))
    }
}

struct TpmRmFile {
    response: Mutex<(Vec<u8>, usize)>,
}

impl TpmRmFile {
    fn new() -> Self {
        Self { response: Mutex::new((Vec::new(), 0)) }
    }
}

impl Pollable for TpmRmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let response = self.response.lock();
        let readable = response.1 < response.0.len();
        (IoEvents::OUT
            | if readable { IoEvents::IN } else { IoEvents::empty() })
            & mask
    }
}

impl FileOps for TpmRmFile {
    fn read_at(&self, _offset: usize, writer: &mut VmWriter, _flags: StatusFlags) -> Result<usize> {
        if writer.avail() == 0 { return Ok(0); }
        let mut response = self.response.lock();
        if response.1 >= response.0.len() {
            return_errno_with_message!(Errno::EAGAIN, "no TPM response is available");
        }
        let offset = response.1;
        let copied = writer.write_fallible(&mut VmReader::from(&response.0[offset..]))?;
        response.1 += copied;
        if response.1 == response.0.len() {
            response.0.clear();
            response.1 = 0;
        }
        Ok(copied)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader, _flags: StatusFlags) -> Result<usize> {
        let device = aster_tpm::device()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
        let command_len = reader.remain();
        if command_len < TPM_MIN_BUF {
            return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
        }
        if command_len > device.limits().max_command as usize {
            return_errno_with_message!(Errno::EMSGSIZE, "TPM command too large");
        }
        let max_rsp = device.limits().max_response as usize;
        if max_rsp < TPM_MIN_BUF {
            return_errno_with_message!(Errno::EIO, "TPM device reported invalid max_response");
        }
        {
            let response = self.response.lock();
            if response.1 < response.0.len() {
                return_errno_with_message!(Errno::EBUSY, "TPM response data has not been fully read");
            }
        }
        let mut command = vec![0; command_len];
        reader.read_fallible(&mut VmWriter::from(&mut command[..]))?;
        let mut bytes = vec![0; max_rsp];
        let len = device.exec(&command, &mut bytes)
            .map_err(|_| Error::with_message(Errno::EIO, "TPM command failed"))?;
        bytes.truncate(len);
        *self.response.lock() = (bytes, 0);
        Ok(command_len)
    }
}

impl PerOpenFileOps for TpmRmFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "the TPM device is not seekable");
    }
    fn is_offset_aware(&self) -> bool { false }
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
