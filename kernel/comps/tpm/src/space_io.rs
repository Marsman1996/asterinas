//! 按 TPM 资源命名空间转发命令：从虚拟句柄改写到物理句柄、往返芯片、
//! 再把响应改写回虚拟句柄，全程维持不同虚拟句柄空间互不可见的隔离性质。
//!
//! 本文件不参与 Verus 证明——它只是按固定顺序调用 tpm-core 里已经证明过
//! 的编排原语。正确性来自那些原语各自的后置条件，以及这里对调用顺序、
//! 失败收尾的人工审查。

#![allow(dead_code)]

use alloc::vec::Vec;

use tpm_core::{
    chip::{ChipTransport, CtxIo},
    module::{ContextIo, IoErr, Space},
    rewrite::{
        HEADER_SIZE, HeaderOutcome, SpaceErr, map_capability_handles, map_command_handles,
        map_response_handle, read_be32,
    },
};

/// GetCapability 的命令码——响应体里的句柄列表要按 space 过滤。
const CC_GET_CAPABILITY: u32 = 0x0000_017A;

/// 一条命令在 space 隔离下需要知道的两件事：命令句柄区占几个槽位、
/// 响应头部是否带一个新分配的句柄。
#[derive(Clone, Copy)]
pub struct CcAttrs {
    pub nr_chandles: usize,
    pub has_rhandle: bool,
}

pub(super) const TPMA_CC_COMMAND_INDEX_MASK: u32 = 0x0000_ffff;
pub(super) const TPMA_CC_VENDOR: u32 = 1 << 29;
pub(super) const TPMA_CC_CHANDLES_SHIFT: u32 = 25;
pub(super) const TPMA_CC_CHANDLES_MASK: u32 = 0x7;
pub(super) const TPMA_CC_RHANDLE: u32 = 1 << 28;

pub(super) fn command_code(attr: u32) -> u32 {
    (attr & TPMA_CC_COMMAND_INDEX_MASK) | (attr & TPMA_CC_VENDOR)
}

/// Per-open resource-space backing capacity for object and session contexts.
pub const SPACE_BUF: usize = 16384;

/// 命令码 -> 属性的动态查找表。引导期按 TPM 报告的命令总数填好，此后只读。
pub struct CcTable {
    attrs: Vec<u32>,
}

impl CcTable {
    pub(super) fn with_capacity(capacity: usize) -> Result<Self, IoErr> {
        let mut attrs = Vec::new();
        attrs
            .try_reserve_exact(capacity)
            .map_err(|_| IoErr::NoSpace)?;
        Ok(Self { attrs })
    }

    pub(super) fn push(&mut self, attr: u32) {
        self.attrs.push(attr);
    }

    pub fn lookup(&self, cc: u32) -> Option<CcAttrs> {
        self.attrs
            .iter()
            .copied()
            .find(|attr| command_code(*attr) == cc)
            .map(|attr| CcAttrs {
                nr_chandles: ((attr >> TPMA_CC_CHANDLES_SHIFT) & TPMA_CC_CHANDLES_MASK) as usize,
                has_rhandle: attr & TPMA_CC_RHANDLE != 0,
            })
    }

    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }
}

/// 一次转发可能失败的地方，映射到调用方可读的错误分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmitErr {
    /// 命令连报文头都放不下，或句柄区被声明长度截断。
    Malformed,
    /// 命令码不在能力表里。
    Unsupported,
    /// 命令引用了本 space 里解析不出来的虚拟句柄。
    BadHandle,
    /// 响应带回的物理句柄在 space 表里放不下。
    NoSlots,
    /// 底层传输或上下文存取失败。
    Io(IoErr),
}

impl From<SpaceErr> for XmitErr {
    fn from(e: SpaceErr) -> Self {
        match e {
            SpaceErr::Malformed => XmitErr::Malformed,
            SpaceErr::BadHandle => XmitErr::BadHandle,
        }
    }
}

impl From<IoErr> for XmitErr {
    fn from(e: IoErr) -> Self {
        XmitErr::Io(e)
    }
}

/// 按 space 转发一条命令。
///
/// `ctx_buf`/`ses_buf` 是该 space 私有的备份缓冲区，跨调用持久化；
/// `cmd`/`rsp` 是本次调用暂存区，用完即弃。
#[expect(clippy::too_many_arguments)]
pub fn space_transmit<T: ChipTransport>(
    space: &mut Space,
    io: &mut CtxIo<T>,
    cc_table: &CcTable,
    ctx_buf: &mut [u8],
    ses_buf: &mut [u8],
    work_ctx: &mut [u8],
    work_ses: &mut [u8],
    cmd: &mut [u8],
    cmd_len: usize,
    rsp: &mut [u8],
) -> Result<usize, XmitErr> {
    if cmd_len > cmd.len() {
        return Err(XmitErr::Malformed);
    }
    if cmd_len < HEADER_SIZE {
        return Err(XmitErr::Malformed);
    }
    if work_ctx.len() != ctx_buf.len() || work_ses.len() != ses_buf.len() {
        return Err(XmitErr::Io(IoErr::NoSpace));
    }
    let cc = read_be32(cmd, 6);
    let attrs = cc_table.lookup(cc).ok_or(XmitErr::Unsupported)?;
    if cmd_len < HEADER_SIZE + 4 * attrs.nr_chandles {
        return Err(XmitErr::Malformed);
    }

    let mut txn = space.begin();
    // Match Linux work_space: table and backing buffers are all private to
    // this request and are committed together only after every step succeeds.
    work_ctx.copy_from_slice(ctx_buf);
    work_ses.copy_from_slice(ses_buf);

    // 1. 把该 space 挂起的瞬态对象 / 会话装回芯片。
    if let Err(e) = tpm_core::module::load_space(txn.table(), io, work_ctx, work_ses) {
        txn.abort(io);
        return Err(e.into());
    }

    // 2. 命令句柄区：虚拟句柄换成刚装回来的物理句柄。
    if let Err(e) = map_command_handles(&*txn.table(), attrs.nr_chandles, &mut cmd[..cmd_len]) {
        // BadHandle → 调用方应返回 EINVAL（foreign handle）
        txn.abort(io);
        return Err(e.into());
    }

    // 3. 真正的收发。
    let n = match io.exec_raw(&cmd[..cmd_len], rsp) {
        Ok(n) => n,
        Err(e) => {
            txn.abort(io);
            return Err(e.into());
        }
    };
    if n < HEADER_SIZE {
        txn.abort(io);
        return Err(XmitErr::Io(IoErr::Protocol));
    }
    let response_code = read_be32(&rsp[..n], 6);

    // 4. 响应头部句柄：新分配的物理句柄登记 / 虚拟化。
    // TPM error responses may contain only the 10-byte header. Call the
    // formally verified mapper only when its 14-byte precondition holds.
    let outcome = if response_code == 0 && attrs.has_rhandle {
        if n < HEADER_SIZE + 4 {
            txn.abort(io);
            return Err(XmitErr::Io(IoErr::Protocol));
        }
        map_response_handle(txn.table(), true, &mut rsp[..n])
    } else {
        HeaderOutcome::NoHandle
    };
    if let HeaderOutcome::OutOfSlots { flush } = outcome {
        // Match Linux tpm2_commit_space(): flush the untracked new handle,
        // discard the loaded work space, and leave the persistent table and
        // context buffers untouched.
        io.flush(flush);
        txn.abort(io);
        return Err(XmitErr::NoSlots);
    }

    // 5. GetCapability 响应体里的句柄列表按同样规则改写、裁剪。
    let is_cap_query = cc == CC_GET_CAPABILITY;
    let n = if response_code == 0 && is_cap_query {
        match map_capability_handles(&*txn.table(), true, rsp, n) {
            Ok(n) => n,
            Err(_) => {
                txn.abort(io);
                return Err(XmitErr::Io(IoErr::Protocol));
            }
        }
    } else {
        n
    };

    // 6. 把事务期间产生的瞬态状态存回备份缓冲区，并从芯片上卸载。
    if let Err(e) = tpm_core::module::save_space(txn.table(), io, work_ctx, work_ses) {
        txn.abort(io);
        return Err(e.into());
    }

    ctx_buf.copy_from_slice(work_ctx);
    ses_buf.copy_from_slice(work_ses);
    space.commit(txn);
    Ok(n)
}
