//! 按 TPM 资源命名空间转发命令：从虚拟句柄改写到物理句柄、往返芯片、
//! 再把响应改写回虚拟句柄，全程维持不同虚拟句柄空间互不可见的隔离性质。
//!
//! 本文件不参与 Verus 证明——它只是按固定顺序调用 tpm-core 里已经证明过
//! 的编排原语。正确性来自那些原语各自的后置条件，以及这里对调用顺序、
//! 失败收尾的人工审查。

#![allow(dead_code)]

use tpm_core::{
    chip::{ChipTransport, CtxIo},
    module::{ContextIo, IoErr, Space},
    rewrite::{
        map_capability_handles, map_command_handles, map_response_handle, read_be32, HeaderOutcome,
        SpaceErr, HEADER_SIZE,
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

/// 命令属性表容量上限。
pub const MAX_COMMANDS: usize = 256;

/// Per-open resource-space backing capacity for object and session contexts.
pub const SPACE_BUF: usize = 16384;

/// 命令码 -> 属性的定长查找表。引导期一次性填好，此后只读。
pub struct CcTable {
    cc: [u32; MAX_COMMANDS],
    attrs: [CcAttrs; MAX_COMMANDS],
    len: usize,
}

impl CcTable {
    pub const fn empty() -> Self {
        CcTable {
            cc: [0; MAX_COMMANDS],
            attrs: [CcAttrs {
                nr_chandles: 0,
                has_rhandle: false,
            }; MAX_COMMANDS],
            len: 0,
        }
    }

    /// 登记一条命令属性；表满时返回 false。
    pub fn push(&mut self, cc: u32, attrs: CcAttrs) -> bool {
        if self.len == MAX_COMMANDS {
            return false;
        }
        self.cc[self.len] = cc;
        self.attrs[self.len] = attrs;
        self.len += 1;
        true
    }

    pub fn lookup(&self, cc: u32) -> Option<CcAttrs> {
        (0..self.len)
            .find(|&i| self.cc[i] == cc)
            .map(|i| self.attrs[i])
    }

    pub fn len(&self) -> usize {
        self.len
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
    if attrs.has_rhandle && n < HEADER_SIZE + 4 {
        txn.abort(io);
        return Err(XmitErr::Io(IoErr::Protocol));
    }

    // 4. 响应头部句柄：新分配的物理句柄登记 / 虚拟化。
    let outcome = map_response_handle(txn.table(), attrs.has_rhandle, &mut rsp[..n]);
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
    let n = match map_capability_handles(&*txn.table(), is_cap_query, rsp, n) {
        Ok(n) => n,
        Err(e) => {
            txn.abort(io);
            return Err(e.into());
        }
    };

    // 6. 把事务期间产生的瞬态状态存回备份缓冲区，并从芯片上卸载。
    if let Err(e) = tpm_core::module::save_space(txn.table(), io, work_ctx, work_ses) {
        txn.abort(io);
        return Err(e.into());
    }

    ctx_buf.copy_from_slice(&work_ctx);
    ses_buf.copy_from_slice(&work_ses);
    space.commit(txn);
    Ok(n)
}
