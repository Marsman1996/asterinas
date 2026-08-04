#![no_std]
#![allow(unused_imports)]

pub fn array_as_slice<T, const N: usize>(a: &[T; N]) -> &[T] {
    &a[..]
}
pub fn slice_subrange<T>(s: &[T], start: usize, end: usize) -> &[T] {
    &s[start..end]
}
pub fn array_index_get<T, const N: usize>(a: &[T; N], index: usize) -> &T {
    &a[index]
}
pub fn slice_index_get<T>(s: &[T], index: usize) -> &T {
    &s[index]
}

pub mod buf;
pub mod chip;
pub mod cmd;
pub mod cursor;
pub mod endian;
pub mod handle;
pub mod module;
pub mod msg;
pub mod probe;
pub mod rewrite;
pub mod rsp;
pub mod table;
pub mod tpm1;
pub mod types;

// 会话授权层：可信密码学规约 -> 授权区编解码 -> 会话状态机
pub mod auth;
pub mod crypto;
pub mod session;

// 硬件层：寄存器语义 -> 物理接触面 -> 硬件状态机
pub mod mmio;
pub mod phy;
pub mod tis;
pub mod tis_core;

// 编排层：长度校验、重传、返回码提取 -> 幽灵账本与链路接合
pub mod link;
pub mod xfer;

// 授权往返：把「响应必须先过 MAC 校验」变成类型层面的事实
pub mod secure;

// 引导序列：宿主接口自检 -> 启动 -> 自检 -> 容量对账
pub mod boot;

// 阶段移交：链路在无会话路径与授权路径之间易手，账本一路随行
pub mod handoff;

pub use auth::{AuthErr, RspAuth, SA_CONTINUE_SESSION, SA_DECRYPT, SA_ENCRYPT};
pub use boot::{Boot, BootErr, Limits, bring_up};
pub use buf::{BufKind, TPM_HEADER_SIZE, TPM2B_HEADER_SIZE, TpmBuf};
pub use crypto::{AesCfb, HmacSha256Ctx, NONCE_LEN, NonceSource, SHA256_LEN, Sha256Ctx};
pub use handoff::{attach, close_ctx, open_ctx, to_auth, to_plain};
pub use link::{ChipLink, LiveSet};
pub use mmio::TisMmio;
pub use phy::TisPhy;
pub use secure::{Authenticated, CmdLayout, Guarded, SecErr};
pub use session::{AuthSession, SessionState};
pub use tis::{MAX_LOCALITY, TisErr};
pub use tis_core::Tis;
pub use types::{TpmRc, TpmTag};
pub use xfer::{Xfer, XferErr};
