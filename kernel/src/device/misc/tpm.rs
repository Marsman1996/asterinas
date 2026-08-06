// SPDX-License-Identifier: MPL-2.0

//! Minimal TPM character-device bridge.

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

/// TPM 报文头长度（标签 2 + 长度 4 + 命令码/返回码 4）。
/// 与 `tpm_core::rewrite::HEADER_SIZE` 和 `tpm_core::msg::TPM_HEADER_LEN` 一致。
const TPM_HEADER_SIZE: usize = 10;

/// 命令/响应缓冲区的最小安全长度。
///
/// `/dev/tpm0` 是原始透传接口，不经 CtxIo，因此不需要满足
/// `ChipTransport::exec` trait 为 CtxIo 设定的 `HEADER_SIZE + 4`(=14) 约束。
/// 本路径的实际前置条件来自：
///
/// - `peek_be32(cmd, 6)` → `cmd.len() >= 10`
///   (Formal/code/tpm-core/src/xfer.rs:170)
/// - `spec_cmd_wf` → `len >= TPM_HEADER_LEN` (=10)
///   (Formal/code/tpm-core/src/xfer.rs:159)
/// - `Xfer::run` → `rsp.len() >= TPM_HEADER_LEN` (=10)
///   (Formal/code/tpm-core/src/xfer.rs:365)
const TPM_MIN_BUF_SIZE: usize = TPM_HEADER_SIZE; // = 10

#[derive(Debug)]
struct TpmDevice(DeviceId);

impl TpmDevice {
    fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        Arc::new(Self(DeviceId::new(major, MinorId::new(TPM_MINOR))))
    }
}

impl Device for TpmDevice {
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
        Self {
            response: Mutex::new((Vec::new(), 0)),
        }
    }
}

impl Pollable for TpmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let response = self.response.lock();
        let readable = response.1 < response.0.len();
        (IoEvents::OUT
            | if readable {
                IoEvents::IN
            } else {
                IoEvents::empty()
            })
            & mask
    }
}

impl FileOps for TpmFile {
    fn read_at(
        &self,
        _offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let mut response = self.response.lock();
        // Linux tpm_common_read: min(size, response_length).
        // size==0 → min(0, N)==0 → clear state, return 0.
        if writer.avail() == 0 {
            response.0.clear();
            response.1 = 0;
            return Ok(0);
        }
        if response.1 >= response.0.len() {
            return_errno_with_message!(Errno::EAGAIN, "no TPM response is available");
        }
        let offset = response.1;
        let copied = writer.write_fallible(&mut response.0[offset..].into())?;
        response.1 += copied;
        if response.1 == response.0.len() {
            response.0.clear();
            response.1 = 0;
        }
        Ok(copied)
    }

    fn write_at(
        &self,
        _offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let device = aster_tpm::device()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
        let command_len = reader.remain();
        // Linux tpm_common_write:
        //   size > TPM_BUFSIZE → E2BIG
        //   size < 6 || size < header->length → EINVAL
        // 这里用 HEADER_SIZE(=10) 作为下界，对齐 peek_be32(cmd,6) 的安全要求。
        if command_len < TPM_MIN_BUF_SIZE {
            return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
        }
        if command_len > device.limits().max_command as usize {
            return_errno_with_message!(Errno::EMSGSIZE, "TPM command too large");
        }
        let mut command = vec![0; command_len];
        reader.read_fallible(&mut command.as_mut_slice().into())?;
        let max_rsp = device.limits().max_response as usize;
        if max_rsp < TPM_MIN_BUF_SIZE {
            return_errno_with_message!(Errno::EIO, "TPM device reported invalid max_response");
        }
        // Linux tpm_common_write: (!response_read && response_length) → EBUSY.
        //   即上一次响应尚未被用户态读完时，拒绝写入新命令。
        {
            let response = self.response.lock();
            if response.1 < response.0.len() {
                return_errno_with_message!(Errno::EBUSY, "TPM response data has not been fully read");
            }
        }
        let mut bytes = vec![0; max_rsp];
        let len = device
            .exec(&command, &mut bytes)
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

pub(super) fn init_in_first_kthread() {
    if aster_tpm::device().is_some() {
        char::register(TpmDevice::new()).unwrap();
    }
}
