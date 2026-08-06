//! 两个设备文件的读写状态机：一次只处理一条挂起的命令，响应未读完
//! 之前拒绝新的写入；传输失败时清空挂起缓冲区。

#![allow(dead_code)]

extern crate alloc;
use alloc::boxed::Box;
use spin::Mutex;

use tpm_core::chip::{ChipTransport, CtxIo};
use tpm_core::module::Space;

use crate::space_io::{space_transmit, CcTable, XmitErr};

/// 单次收发暂存区上限，与芯片侧命令/响应缓冲区同量级。
pub const XFER_BUF: usize = 4096;

/// space 私有备份缓冲区上限：对象上下文与会话上下文各一份。
pub const SPACE_BUF: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevErr {
    /// 上一条响应还没读完，不能发新命令。
    Busy,
    /// 写入字节数超过单条命令暂存区容量。
    TooLarge,
    /// 报文长度字段非法，或短到连报文头都不够。
    BadLength,
    Xmit(XmitErr),
}

impl From<XmitErr> for DevErr {
    fn from(e: XmitErr) -> Self {
        DevErr::Xmit(e)
    }
}

/// 挂起响应暂存区，支持分次 read。
struct Buffer {
    data: [u8; XFER_BUF],
    pending: usize,
    read_off: usize,
}

impl Buffer {
    const fn new() -> Self {
        Buffer {
            data: [0u8; XFER_BUF],
            pending: 0,
            read_off: 0,
        }
    }

    fn reset(&mut self) {
        self.pending = 0;
        self.read_off = 0;
    }
}

/// 校验、发送一条命令，并把响应缓存到 `buf`。
/// `xmit` 负责实际下发：独占设备与隔离设备在这里分叉。
fn do_write<F>(buf: &mut Buffer, input: &[u8], xmit: F) -> Result<usize, DevErr>
where
    F: FnOnce(&mut [u8], usize, &mut [u8]) -> Result<usize, XmitErr>,
{
    if input.len() > XFER_BUF {
        return Err(DevErr::TooLarge);
    }
    if buf.pending != 0 {
        return Err(DevErr::Busy);
    }
    if input.len() < 6 {
        return Err(DevErr::BadLength);
    }
    let declared = u32::from_be_bytes([input[2], input[3], input[4], input[5]]) as usize;
    if declared < 10 || input.len() < declared {
        return Err(DevErr::BadLength);
    }

    let mut cmd = Box::new([0u8; XFER_BUF]);
    cmd[..input.len()].copy_from_slice(input);
    let mut rsp = Box::new([0u8; XFER_BUF]);

    match xmit(&mut *cmd, input.len(), &mut *rsp) {
        Ok(n) => {
            buf.data[..n].copy_from_slice(&rsp[..n]);
            buf.pending = n;
            buf.read_off = 0;
            Ok(input.len())
        }
        Err(e) => {
            buf.reset();
            Err(e.into())
        }
    }
}

fn do_read(buf: &mut Buffer, out: &mut [u8]) -> usize {
    if buf.pending == 0 {
        return 0;
    }
    let n = core::cmp::min(out.len(), buf.pending);
    out[..n].copy_from_slice(&buf.data[buf.read_off..buf.read_off + n]);
    buf.read_off += n;
    buf.pending -= n;
    if buf.pending == 0 {
        buf.read_off = 0;
    }
    n
}

/// (可读, 可写) 对应轮询接口两个方向。
fn poll_mask(buf: &Buffer) -> (bool, bool) {
    if buf.pending != 0 {
        (true, false)
    } else {
        (false, true)
    }
}

// ---------------------------------------------------------------------------
// /dev/tpmX: 独占、不做资源隔离
// ---------------------------------------------------------------------------

pub struct TpmFile<T: ChipTransport> {
    chip: Mutex<CtxIo<T>>,
    buf: Mutex<Buffer>,
}

impl<T: ChipTransport> TpmFile<T> {
    pub fn new(chip: CtxIo<T>) -> Self {
        TpmFile {
            chip: Mutex::new(chip),
            buf: Mutex::new(Buffer::new()),
        }
    }

    pub fn write(&self, input: &[u8]) -> Result<usize, DevErr> {
        let mut buf = self.buf.lock();
        let mut chip = self.chip.lock();
        do_write(&mut buf, input, |cmd, len, rsp| {
            chip.exec_raw(&cmd[..len], rsp).map_err(XmitErr::Io)
        })
    }

    pub fn read(&self, out: &mut [u8]) -> usize {
        do_read(&mut self.buf.lock(), out)
    }

    pub fn poll(&self) -> (bool, bool) {
        poll_mask(&self.buf.lock())
    }
}

// ---------------------------------------------------------------------------
// /dev/tpmrmX: 每次打开一份独立资源命名空间
// ---------------------------------------------------------------------------

pub struct TpmRmFile<'a, T: ChipTransport> {
    chip: &'a Mutex<CtxIo<T>>,
    cc_table: &'a CcTable,
    space: Mutex<Space>,
    ctx_buf: Mutex<Box<[u8; SPACE_BUF]>>,
    ses_buf: Mutex<Box<[u8; SPACE_BUF]>>,
    buf: Mutex<Buffer>,
}

impl<'a, T: ChipTransport> TpmRmFile<'a, T> {
    /// `chip`/`cc_table` 由设备级别共享。
    pub fn new(chip: &'a Mutex<CtxIo<T>>, cc_table: &'a CcTable) -> Self {
        TpmRmFile {
            chip,
            cc_table,
            space: Mutex::new(Space::new()),
            ctx_buf: Mutex::new(Box::new([0u8; SPACE_BUF])),
            ses_buf: Mutex::new(Box::new([0u8; SPACE_BUF])),
            buf: Mutex::new(Buffer::new()),
        }
    }

    pub fn write(&self, input: &[u8]) -> Result<usize, DevErr> {
        let mut buf = self.buf.lock();
        let mut chip = self.chip.lock();
        let mut space = self.space.lock();
        let mut ctx_buf = self.ctx_buf.lock();
        let mut ses_buf = self.ses_buf.lock();
        do_write(&mut buf, input, |cmd, len, rsp| {
            space_transmit(
                &mut space,
                &mut *chip,
                self.cc_table,
                &mut **ctx_buf,
                &mut **ses_buf,
                cmd,
                len,
                rsp,
            )
        })
    }

    pub fn read(&self, out: &mut [u8]) -> usize {
        do_read(&mut self.buf.lock(), out)
    }

    pub fn poll(&self) -> (bool, bool) {
        poll_mask(&self.buf.lock())
    }
}

impl<'a, T: ChipTransport> Drop for TpmRmFile<'a, T> {
    /// 关闭时冲掉该 space 在芯片上残留的一切。
    fn drop(&mut self) {
        let mut space = self.space.lock();
        let mut chip = self.chip.lock();
        let txn = space.begin();
        txn.abort(&mut *chip);
    }
}
