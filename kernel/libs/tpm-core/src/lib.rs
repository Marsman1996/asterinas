#![no_std]
#![allow(unused_imports)]

pub mod tpm1;
pub mod probe;
pub mod buf;
pub mod endian;
pub mod types;
pub mod cursor;
pub mod msg;
pub mod cmd;
pub mod rsp;
pub mod handle;
pub mod module;
pub mod rewrite;
pub mod table;
pub mod chip;

// 会话授权层：可信密码学规约 -> 授权区编解码 -> 会话状态机
pub mod crypto;
pub mod auth;
pub mod session;

// 硬件层：寄存器语义 -> 物理接触面 -> 硬件状态机
pub mod tis;
pub mod phy;
pub mod mmio;
pub mod tis_core;

// 编排层：长度校验、重传、返回码提取 -> 幽灵账本与链路接合
pub mod xfer;
pub mod link;

// 授权往返：把「响应必须先过 MAC 校验」变成类型层面的事实
pub mod secure;

// 引导序列：宿主接口自检 -> 启动 -> 自检 -> 容量对账
pub mod boot;

// 阶段移交：链路在无会话路径与授权路径之间易手，账本一路随行
pub mod handoff;

pub use buf::{BufKind, TpmBuf, TPM2B_HEADER_SIZE, TPM_HEADER_SIZE};
pub use types::{TpmRc, TpmTag};
pub use auth::{AuthErr, RspAuth, SA_CONTINUE_SESSION, SA_DECRYPT, SA_ENCRYPT};
pub use crypto::{AesCfb, HmacSha256Ctx, NonceSource, Sha256Ctx, NONCE_LEN, SHA256_LEN};
pub use session::{AuthSession, SessionState};
pub use tis::{TisErr, MAX_LOCALITY};
pub use tis_core::Tis;
pub use phy::TisPhy;
pub use mmio::TisMmio;
pub use xfer::{Xfer, XferErr};
pub use link::{ChipLink, LiveSet};
pub use secure::{Authenticated, CmdLayout, Guarded, SecErr};
pub use boot::{bring_up, Boot, BootErr, Limits};
pub use handoff::{attach, close_ctx, open_ctx, to_auth, to_plain};