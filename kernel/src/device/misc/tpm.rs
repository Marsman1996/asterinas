// SPDX-License-Identifier: MPL-2.0

//! Linux-compatible /dev/tpm0 and /dev/tpmrm0 character-device bridge.

use alloc::vec;
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use device_id::{DeviceId, MinorId};
use ostd::sync::WaitQueue;

use crate::{
    device::{registry::char, Device, DeviceType, DevtmpfsInodeMeta},
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    thread::work_queue::{submit_work_func, WorkPriority},
    time::{
        clocks::MonotonicClock,
        timer::{Timeout, TimerGuard},
        Timer,
    },
};

const TPM_MINOR: u32 = 224;
const TPMRM_MINOR: u32 = 225;
const TPM_MIN_WRITE: usize = 6;
const TPM_HEADER_SIZE: usize = 10;
const TPM2_RC_SIZE_RESPONSE: [u8; TPM_HEADER_SIZE] = [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0, 0x95];
const TPM2_RC_COMMAND_CODE_RESPONSE: [u8; TPM_HEADER_SIZE] =
    [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0x0b, 0x01, 0x43];

static TPM0_OPEN: AtomicBool = AtomicBool::new(false);

struct FileState {
    response: Vec<u8>,
    offset: usize,
    response_read: bool,
    command_enqueued: bool,
    pending_cmd: Option<Vec<u8>>,
    async_error: Option<Errno>,
}

impl FileState {
    fn new() -> Self {
        Self {
            response: Vec::new(),
            offset: 0,
            response_read: true,
            command_enqueued: false,
            pending_cmd: None,
            async_error: None,
        }
    }
    fn busy(&self) -> bool {
        self.command_enqueued
            || (!self.response_read
                && (self.offset < self.response.len() || self.async_error.is_some()))
    }
    fn has_response(&self) -> bool {
        self.async_error.is_some() || self.offset < self.response.len()
    }
    fn events(&self) -> IoEvents {
        if self.has_response() {
            IoEvents::IN
        } else {
            IoEvents::OUT
        }
    }
    fn prepare(&mut self) {
        self.response.clear();
        self.offset = 0;
        self.response_read = false;
        self.async_error = None;
        self.command_enqueued = true;
    }
    fn complete(&mut self, result: core::result::Result<Vec<u8>, Errno>) {
        self.command_enqueued = false;
        self.pending_cmd = None;
        self.response.clear();
        self.offset = 0;
        self.async_error = None;
        match result {
            Ok(response) => {
                self.response = response;
                self.response_read = false;
            }
            Err(errno) => {
                self.async_error = Some(errno);
                self.response_read = false;
            }
        }
    }
    fn read(&mut self, writer: &mut VmWriter) -> Result<usize> {
        if let Some(errno) = self.async_error.take() {
            self.response_read = true;
            return Err(Error::with_message(
                errno,
                "asynchronous TPM command failed",
            ));
        }
        if self.offset >= self.response.len() {
            return Ok(0);
        }
        let copied = match writer.write_fallible(&mut VmReader::from(&self.response[self.offset..]))
        {
            Ok(copied) => copied,
            Err(error) => {
                // Linux discards the complete response after copy_to_user() fails.
                self.response.clear();
                self.offset = 0;
                self.response_read = true;
                return Err(error.0.into());
            }
        };
        self.offset += copied;
        if copied > 0 {
            self.response_read = true;
        }
        if self.offset == self.response.len() || copied == 0 {
            self.response.clear();
            self.offset = 0;
        }
        Ok(copied)
    }
}

fn validate_command(device: &aster_tpm::TpmDevice, command: &[u8]) -> Result<()> {
    if command.len() < TPM_MIN_WRITE {
        return_errno_with_message!(Errno::EINVAL, "invalid TPM command length");
    }
    if command.len() > device.limits().max_command as usize {
        return_errno_with_message!(Errno::E2BIG, "TPM command too large");
    }
    let declared = u32::from_be_bytes([command[2], command[3], command[4], command[5]]) as usize;
    if command.len() < declared {
        return_errno_with_message!(Errno::EINVAL, "command size mismatch with header");
    }
    Ok(())
}

fn execute_raw(command: &[u8]) -> core::result::Result<Vec<u8>, Errno> {
    if command.len() < TPM_HEADER_SIZE {
        return Ok(TPM2_RC_SIZE_RESPONSE.to_vec());
    }
    let device = aster_tpm::device().ok_or(Errno::ENODEV)?;
    let mut response = vec![0u8; device.limits().max_response as usize];
    let len = device
        .exec(command, &mut response)
        .map_err(|_| Errno::EIO)?;
    response.truncate(len);
    Ok(response)
}

struct TpmFileShared {
    state: Mutex<FileState>,
    pollee: Pollee,
    async_wait: WaitQueue,
    timer: Arc<Timer>,
}
impl TpmFileShared {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|weak: &Weak<Self>| {
            let weak = weak.clone();
            let timer = MonotonicClock::timer_manager().create_timer(move |_guard: TimerGuard| {
                if let Some(shared) = weak.upgrade() {
                    submit_work_func(move || shared.expire_response(), WorkPriority::Normal);
                }
            });
            Self {
                state: Mutex::new(FileState::new()),
                pollee: Pollee::new(),
                async_wait: WaitQueue::new(),
                timer,
            }
        })
    }
    fn arm_timeout(&self) {
        if self.state.lock().has_response() {
            self.timer
                .lock()
                .set_timeout(Timeout::After(Duration::from_secs(120)));
        }
    }
    fn expire_response(&self) {
        let mut state = self.state.lock();
        if state.has_response() {
            state.response.clear();
            state.offset = 0;
            state.async_error = None;
            state.response_read = true;
        }
        drop(state);
        self.pollee.notify(IoEvents::OUT);
    }
    fn process_pending(&self) {
        let command = self.state.lock().pending_cmd.take();
        let Some(command) = command else { return };
        let result = execute_raw(&command);
        self.state.lock().complete(result);
        self.async_wait.wake_all();
        self.arm_timeout();
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR);
    }
}
impl Drop for TpmFileShared {
    fn drop(&mut self) {
        TPM0_OPEN.store(false, Ordering::Release);
    }
}
struct TpmFile {
    shared: Arc<TpmFileShared>,
}
impl Drop for TpmFile {
    fn drop(&mut self) {
        self.shared
            .async_wait
            .wait_until(|| (!self.shared.state.lock().command_enqueued).then_some(()));
        self.shared.timer.lock().cancel();
    }
}

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
        Ok(Box::new(TpmFile {
            shared: TpmFileShared::new(),
        }))
    }
}
impl Pollable for TpmFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.shared
            .pollee
            .poll_with(mask, poller, || self.shared.state.lock().events())
    }
}
impl FileOps for TpmFile {
    fn read_at(&self, _offset: usize, writer: &mut VmWriter, _flags: StatusFlags) -> Result<usize> {
        let (result, drained) = {
            let mut state = self.shared.state.lock();
            let result = state.read(writer);
            let drained = !state.has_response();
            (result, drained)
        };
        if drained {
            self.shared.timer.lock().cancel();
        }
        self.shared.pollee.invalidate();
        result
    }
    fn write_at(&self, _offset: usize, reader: &mut VmReader, flags: StatusFlags) -> Result<usize> {
        let device = aster_tpm::device()
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no TPM device is available"))?;
        let command_len = reader.remain();
        let mut command = vec![0u8; command_len];
        reader.read_fallible(&mut VmWriter::from(&mut command[..]))?;
        validate_command(device, &command)?;
        let mut state = self.shared.state.lock();
        if state.busy() {
            return_errno_with_message!(Errno::EBUSY, "TPM file is busy");
        }
        state.prepare();
        if flags.contains(StatusFlags::O_NONBLOCK) {
            state.pending_cmd = Some(command);
            drop(state);
            let shared = self.shared.clone();
            submit_work_func(move || shared.process_pending(), WorkPriority::Normal);
            self.shared.pollee.notify(IoEvents::OUT);
            return Ok(command_len);
        }
        let result = execute_raw(&command);
        state.complete(result);
        let error = state.async_error.take();
        drop(state);
        self.shared.arm_timeout();
        self.shared
            .pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR);
        if let Some(errno) = error {
            return Err(Error::with_message(errno, "TPM command failed"));
        }
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

struct TpmRmInner {
    file: FileState,
    space: aster_tpm::Space,
    ctx_buf: Vec<u8>,
    ses_buf: Vec<u8>,
}
impl TpmRmInner {
    fn new() -> Self {
        Self {
            file: FileState::new(),
            space: aster_tpm::Space::new(),
            ctx_buf: vec![0u8; aster_tpm::SPACE_BUF],
            ses_buf: vec![0u8; aster_tpm::SPACE_BUF],
        }
    }
}
struct TpmRmShared {
    device: &'static aster_tpm::TpmDevice,
    inner: Mutex<TpmRmInner>,
    pollee: Pollee,
    async_wait: WaitQueue,
    timer: Arc<Timer>,
}
impl TpmRmShared {
    fn new(device: &'static aster_tpm::TpmDevice) -> Arc<Self> {
        Arc::new_cyclic(|weak: &Weak<Self>| {
            let weak = weak.clone();
            let timer = MonotonicClock::timer_manager().create_timer(move |_guard: TimerGuard| {
                if let Some(shared) = weak.upgrade() {
                    submit_work_func(move || shared.expire_response(), WorkPriority::Normal);
                }
            });
            Self {
                device,
                inner: Mutex::new(TpmRmInner::new()),
                pollee: Pollee::new(),
                async_wait: WaitQueue::new(),
                timer,
            }
        })
    }
    fn arm_timeout(&self) {
        if self.inner.lock().file.has_response() {
            self.timer
                .lock()
                .set_timeout(Timeout::After(Duration::from_secs(120)));
        }
    }
    fn expire_response(&self) {
        let mut inner = self.inner.lock();
        if inner.file.has_response() {
            inner.file.response.clear();
            inner.file.offset = 0;
            inner.file.async_error = None;
            inner.file.response_read = true;
        }
        drop(inner);
        self.pollee.notify(IoEvents::OUT);
    }
    fn execute_locked(
        &self,
        inner: &mut TpmRmInner,
        mut command: Vec<u8>,
    ) -> core::result::Result<Vec<u8>, Errno> {
        let mut response = vec![0u8; self.device.limits().max_response as usize];
        let command_len = command.len();
        let TpmRmInner {
            space,
            ctx_buf,
            ses_buf,
            ..
        } = inner;
        let result = self.device.transmit_space(
            space,
            ctx_buf,
            ses_buf,
            &mut command,
            command_len,
            &mut response,
        );
        let len = match result {
            Ok(len) => len,
            Err(aster_tpm::XmitErr::Unsupported) => {
                response[..TPM_HEADER_SIZE].copy_from_slice(&TPM2_RC_COMMAND_CODE_RESPONSE);
                TPM_HEADER_SIZE
            }
            Err(aster_tpm::XmitErr::Malformed | aster_tpm::XmitErr::BadHandle) => {
                return Err(Errno::EINVAL);
            }
            Err(
                aster_tpm::XmitErr::NoSlots | aster_tpm::XmitErr::Io(aster_tpm::IoErr::NoSpace),
            ) => {
                return Err(Errno::ENOMEM);
            }
            Err(aster_tpm::XmitErr::Io(_)) => return Err(Errno::EIO),
        };
        response.truncate(len);
        Ok(response)
    }
    fn process_pending(&self) {
        let mut inner = self.inner.lock();
        let command = inner.file.pending_cmd.take();
        let Some(command) = command else { return };
        let result = self.execute_locked(&mut inner, command);
        inner.file.complete(result);
        drop(inner);
        self.async_wait.wake_all();
        self.arm_timeout();
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR);
    }
}
impl Drop for TpmRmShared {
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        self.device.close_space(&mut inner.space);
    }
}
struct TpmRmFile {
    shared: Arc<TpmRmShared>,
}
impl Drop for TpmRmFile {
    fn drop(&mut self) {
        self.shared
            .async_wait
            .wait_until(|| (!self.shared.inner.lock().file.command_enqueued).then_some(()));
        self.shared.timer.lock().cancel();
    }
}

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
        Ok(Box::new(TpmRmFile {
            shared: TpmRmShared::new(device),
        }))
    }
}
impl Pollable for TpmRmFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.shared
            .pollee
            .poll_with(mask, poller, || self.shared.inner.lock().file.events())
    }
}
impl FileOps for TpmRmFile {
    fn read_at(&self, _offset: usize, writer: &mut VmWriter, _flags: StatusFlags) -> Result<usize> {
        let (result, drained) = {
            let mut inner = self.shared.inner.lock();
            let result = inner.file.read(writer);
            let drained = !inner.file.has_response();
            (result, drained)
        };
        if drained {
            self.shared.timer.lock().cancel();
        }
        self.shared.pollee.invalidate();
        result
    }
    fn write_at(&self, _offset: usize, reader: &mut VmReader, flags: StatusFlags) -> Result<usize> {
        let command_len = reader.remain();
        let mut command = vec![0u8; command_len];
        reader.read_fallible(&mut VmWriter::from(&mut command[..]))?;
        validate_command(self.shared.device, &command)?;
        let mut inner = self.shared.inner.lock();
        if inner.file.busy() {
            return_errno_with_message!(Errno::EBUSY, "TPM resource-manager file is busy");
        }
        inner.file.prepare();
        if flags.contains(StatusFlags::O_NONBLOCK) {
            inner.file.pending_cmd = Some(command);
            drop(inner);
            let shared = self.shared.clone();
            submit_work_func(move || shared.process_pending(), WorkPriority::Normal);
            self.shared.pollee.notify(IoEvents::OUT);
            return Ok(command_len);
        }
        let result = self.shared.execute_locked(&mut inner, command);
        inner.file.complete(result);
        let error = inner.file.async_error.take();
        drop(inner);
        self.shared.arm_timeout();
        self.shared
            .pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR);
        if let Some(errno) = error {
            return Err(Error::with_message(
                errno,
                "TPM resource-manager command failed",
            ));
        }
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
pub(super) fn init_in_first_kthread() {
    if aster_tpm::device().is_some() {
        char::register(TpmDev::new()).unwrap();
        char::register(TpmRmDev::new()).unwrap();
    }
}
