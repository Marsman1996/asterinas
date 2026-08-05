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
        if command_len == 0 || command_len > device.limits().max_command as usize {
            return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
        }
        let mut command = vec![0; command_len];
        reader.read_fallible(&mut command.as_mut_slice().into())?;
        let mut bytes = vec![0; device.limits().max_response as usize];
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
