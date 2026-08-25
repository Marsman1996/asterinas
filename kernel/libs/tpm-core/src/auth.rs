use crate::{crypto::*, cursor::Cursor};

const _: () = ();
/// 标签 2 字节 + 长度 4 字节 + 命令码或返回码 4 字节。
pub const HEADER_LEN: usize = 10;
/// 带授权区的报文标签。授权区只在这个标签下存在。
pub const ST_SESSIONS: u16 = 0x8002;
/// 会话属性位。
pub const SA_CONTINUE_SESSION: u8 = 0x01;
pub const SA_DECRYPT: u8 = 0x20;
pub const SA_ENCRYPT: u8 = 0x40;
/// 授权区里最多允许出现的会话数。
///
/// 规范上限是 3。本实现只追加自己那一个，但响应里可能夹带调用方另行附加
/// 的会话，解析侧仍要能跳过它们——跳过的轮数必须有上界，否则一条精心
/// 构造的响应就能把解析循环拖住。
pub const MAX_SESSIONS: usize = 3;
pub const SESS_HANDLE_OFF: usize = 0;
pub const SESS_NONCE_SIZE_OFF: usize = 4;
pub const SESS_NONCE_OFF: usize = 6;
pub const SESS_ATTRS_OFF: usize = SESS_NONCE_OFF + NONCE_LEN;
pub const SESS_HMAC_SIZE_OFF: usize = SESS_ATTRS_OFF + 1;
pub const SESS_HMAC_OFF: usize = SESS_HMAC_SIZE_OFF + 2;
/// 单个命令侧会话占用的字节数。
pub const CMD_SESSION_LEN: usize = SESS_HMAC_OFF + NONCE_LEN;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthErr {
    /// 报文结构与其自身声明的长度对不上。
    Malformed,
    /// 授权区里定位不到本会话。
    NoSession,
    /// nonce 或 HMAC 字段长度不是约定的摘要长度。这两个长度是对端可控的，
    /// 放行任意值等于把后续所有偏移推理交给对端决定。
    BadField,
    /// 重算出的 HMAC 与收到的不符。
    HmacMismatch,
}
pub fn auth_hmac<H: HmacSha256Ctx>(
    key: &[u8],
    digest: &[u8; SHA256_LEN],
    newer: &[u8; NONCE_LEN],
    older: &[u8; NONCE_LEN],
    attrs: u8,
) -> [u8; SHA256_LEN] {
    let mut h = H::with_key(key);
    let tail: [u8; 1] = [attrs];
    h.update(&digest[..]);
    h.update(&newer[..]);
    h.update(&older[..]);
    h.update(&tail[..]);
    h.finish()
}
pub fn rp_hash<S: Sha256Ctx>(rc: u32, ordinal: u32, parms: &[u8]) -> [u8; SHA256_LEN] {
    let mut s = S::new();
    let rc_b = be32_arr(rc);
    let ord_b = be32_arr(ordinal);
    s.update(&rc_b[..]);
    s.update(&ord_b[..]);
    s.update(parms);
    s.finish()
}
/// `names` 是各授权句柄名字的顺序拼接，由会话层准备。
pub fn cp_hash<S: Sha256Ctx>(ordinal: u32, names: &[u8], parms: &[u8]) -> [u8; SHA256_LEN] {
    let mut s = S::new();
    let ord_b = be32_arr(ordinal);
    s.update(&ord_b[..]);
    s.update(names);
    s.update(parms);
    s.finish()
}
/// 在 `out[off..]` 处铺开一个会话，HMAC 字段先留空。
///
/// 留空而不是填随机字节：占位内容参与不了任何校验，但会被写进最终报文。
/// 万一后续的 [`patch_hmac`] 因错误路径没跑到，留下的应当是一望而知的全
/// 零，而不是看起来像真 MAC 的东西。
pub fn write_cmd_session(
    out: &mut [u8],
    off: usize,
    handle: u32,
    nonce: &[u8; NONCE_LEN],
    attrs: u8,
) {
    let h = be32_arr(handle);
    let n = be16_arr(NONCE_LEN as u16);
    out[off + SESS_HANDLE_OFF] = h[0];
    out[off + SESS_HANDLE_OFF + 1] = h[1];
    out[off + SESS_HANDLE_OFF + 2] = h[2];
    out[off + SESS_HANDLE_OFF + 3] = h[3];
    out[off + SESS_NONCE_SIZE_OFF] = n[0];
    out[off + SESS_NONCE_SIZE_OFF + 1] = n[1];
    let mut i: usize = 0;
    while i < NONCE_LEN {
        out[off + SESS_NONCE_OFF + i] = nonce[i];
        i = i + 1;
    }
    out[off + SESS_ATTRS_OFF] = attrs;
    out[off + SESS_HMAC_SIZE_OFF] = n[0];
    out[off + SESS_HMAC_SIZE_OFF + 1] = n[1];
    let mut j: usize = 0;
    while j < NONCE_LEN {
        out[off + SESS_HMAC_OFF + j] = 0;
        j = j + 1;
    }
}
/// 把算好的 MAC 填进占位处。
pub fn patch_hmac(out: &mut [u8], off: usize, mac: &[u8; SHA256_LEN]) {
    let mut i: usize = 0;
    while i < SHA256_LEN {
        out[off + SESS_HMAC_OFF + i] = mac[i];
        i = i + 1;
    }
}
/// 一条响应里与本会话有关的位置信息。
///
/// 只记偏移不复制内容：参数区可能有几千字节，而校验只需要能指到它。
/// nonce 例外——它要跨轮次留存，必须复制出来。
#[derive(Clone, Copy)]
pub struct RspAuth {
    /// 参数区起点。
    pub parm_off: usize,
    /// 参数区长度。
    pub parm_len: usize,
    /// 本会话 nonce 字段起点。
    pub nonce_off: usize,
    /// 本会话 HMAC 字段起点。
    pub hmac_off: usize,
    /// 对端回报的会话属性。
    pub attrs: u8,
    /// 对端本轮的 nonce。
    pub tpm_nonce: [u8; NONCE_LEN],
}
impl RspAuth {}
/// 取出偏移 `off` 起的一段 nonce。
fn read_nonce(raw: &[u8], off: usize) -> [u8; NONCE_LEN] {
    let mut out: [u8; NONCE_LEN] = [0u8; NONCE_LEN];
    let mut i: usize = 0;
    while i < NONCE_LEN {
        out[i] = raw[off + i];
        i = i + 1;
    }
    out
}
/// 在响应里定位第 `index` 个会话（从零计数）。
///
/// `rhandles` 是本条响应携带的句柄个数，取值只有零或一，来自命令属性表；
/// 它不是从报文里读出来的，因为报文本身并不标注这一点。
///
/// 三处检查值得单独说明：
///
/// - **本会话必须是最后一个。** 若它后面还有别的会话，`hmac_off + 32` 就
///   不等于报文长度。本实现追加会话时总是追加在最后，所以这条既是格式
///   检查，也是「拿到的确实是自己那一个」的旁证。
/// - **nonce 与 HMAC 长度必须恰为摘要长度。** 这两个长度由对端给出，一旦
///   放行任意值，后面所有偏移就都由对端说了算。
/// - **长度字段必须与实到字节数相等。** 少一字节意味着解析会读到不属于本
///   条响应的数据，多一字节意味着上层截断有误。
pub fn parse_rsp_auth(raw: &[u8], rhandles: usize, index: usize) -> Result<RspAuth, AuthErr> {
    if raw.len() < HEADER_LEN {
        return Err(AuthErr::Malformed);
    }
    let mut c = Cursor::new();
    let tag = match c.read_be16(raw) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    let size = match c.read_be32(raw) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    if !c.skip(raw, 4) {
        return Err(AuthErr::Malformed);
    }
    if tag != ST_SESSIONS {
        return Err(AuthErr::Malformed);
    }
    if size as usize != raw.len() {
        return Err(AuthErr::Malformed);
    }
    if !c.skip(raw, rhandles * 4) {
        return Err(AuthErr::Malformed);
    }
    let parm_len_u32 = match c.read_be32(raw) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    if parm_len_u32 as usize > raw.len() {
        return Err(AuthErr::Malformed);
    }
    let parm_len = parm_len_u32 as usize;
    let parm_off = c.pos;
    if !c.skip(raw, parm_len) {
        return Err(AuthErr::Malformed);
    }
    let mut i: usize = 0;
    while i < index {
        let nl = match c.read_be16(raw) {
            Some(v) => v,
            None => return Err(AuthErr::Malformed),
        };
        if !c.skip(raw, nl as usize) {
            return Err(AuthErr::Malformed);
        }
        if !c.skip(raw, 1) {
            return Err(AuthErr::Malformed);
        }
        let hl = match c.read_be16(raw) {
            Some(v) => v,
            None => return Err(AuthErr::Malformed),
        };
        if !c.skip(raw, hl as usize) {
            return Err(AuthErr::Malformed);
        }
        i = i + 1;
    }
    let nonce_len = match c.read_be16(raw) {
        Some(v) => v,
        None => return Err(AuthErr::NoSession),
    };
    if nonce_len as usize != NONCE_LEN {
        return Err(AuthErr::BadField);
    }
    let nonce_off = c.pos;
    if !c.skip(raw, NONCE_LEN) {
        return Err(AuthErr::Malformed);
    }
    let tpm_nonce = read_nonce(raw, nonce_off);
    let attrs = match c.read_u8(raw) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    let hmac_len = match c.read_be16(raw) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    if hmac_len as usize != SHA256_LEN {
        return Err(AuthErr::BadField);
    }
    let hmac_off = c.pos;
    let hmac_end = match hmac_off.checked_add(SHA256_LEN) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    if hmac_end != raw.len() {
        return Err(AuthErr::Malformed);
    }
    let parm_end = match parm_off.checked_add(parm_len) {
        Some(v) => v,
        None => return Err(AuthErr::Malformed),
    };
    if parm_end > nonce_off {
        return Err(AuthErr::Malformed);
    }
    Ok(RspAuth {
        parm_off,
        parm_len,
        nonce_off,
        hmac_off,
        attrs,
        tpm_nonce,
    })
}
/// 逐字节比较，不提前返回。
///
/// 提前返回会让比较耗时随首个不同字节的位置变化，等于把「猜对了几个字节」
/// 告诉能计时的一方。MAC 比较必须是定时的。
pub fn ct_eq32(a: &[u8; SHA256_LEN], b: &[u8]) -> bool {
    let mut acc: u8 = 0;
    let mut i: usize = 0;
    while i < SHA256_LEN {
        acc = acc | (a[i] ^ b[i]);
        i = i + 1;
    }
    acc == 0
}
