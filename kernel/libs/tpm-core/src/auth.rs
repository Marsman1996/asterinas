use vstd::prelude::*;
use vstd::array::*;

use crate::crypto::*;
use crate::cursor::Cursor;
#[cfg(verus_keep_ghost)]
use crate::cursor::{spec_be16_at, spec_be32_at};

verus! {

broadcast use group_crypto_axioms;

// ===========================================================================
// 报文常量
// ===========================================================================

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

// ===========================================================================
// 命令侧授权区布局
// ===========================================================================
//
// ```text
// authHandle    u32
// nonceSize     u16 = 32
// nonceCaller   u8[32]
// attributes    u8
// hmacSize      u16 = 32
// hmac          u8[32]
// ```

pub const SESS_HANDLE_OFF: usize = 0;
pub const SESS_NONCE_SIZE_OFF: usize = 4;
pub const SESS_NONCE_OFF: usize = 6;
pub const SESS_ATTRS_OFF: usize = SESS_NONCE_OFF + NONCE_LEN;
pub const SESS_HMAC_SIZE_OFF: usize = SESS_ATTRS_OFF + 1;
pub const SESS_HMAC_OFF: usize = SESS_HMAC_SIZE_OFF + 2;

/// 单个命令侧会话占用的字节数。
pub const CMD_SESSION_LEN: usize = SESS_HMAC_OFF + NONCE_LEN;

// ===========================================================================
// 错误
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
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

// ===========================================================================
// 哈希输入规约
// ===========================================================================
//
// 三条拼接规则，编码侧与校验侧共用同一份定义。所有关于「算出来的摘要是
// 什么」的推理最终都归约到这里，两侧对字段顺序理解不一致的可能性因此被
// 消除。

/// 命令摘要的输入：命令码 ‖ 各句柄名字 ‖ 参数区。
pub open spec fn spec_cp_input(ordinal: u32, names: Seq<u8>, parms: Seq<u8>) -> Seq<u8> {
    be32_seq(ordinal) + names + parms
}

/// 响应摘要的输入：返回码 ‖ 命令码 ‖ 参数区。
///
/// 返回码在这里恒为零——只有成功的响应才走到校验——但它仍要参与摘要。
pub open spec fn spec_rp_input(rc: u32, ordinal: u32, parms: Seq<u8>) -> Seq<u8> {
    be32_seq(rc) + be32_seq(ordinal) + parms
}

/// 会话 HMAC 的输入：摘要 ‖ 较新的 nonce ‖ 较旧的 nonce ‖ 属性字节。
///
/// 两个 nonce 的先后是有方向的：命令方向本端 nonce 在前，响应方向对端
/// nonce 在前。写反不会被任何长度检查发现，只表现为校验恒不通过，所以
/// 顺序做成参数由调用点显式给出，而不是藏在函数体里。
pub open spec fn spec_auth_input(
    digest: Seq<u8>,
    newer: Seq<u8>,
    older: Seq<u8>,
    attrs: u8,
) -> Seq<u8> {
    digest + newer + older + seq![attrs]
}

// ===========================================================================
// 摘要与 HMAC 的可执行侧
// ===========================================================================

pub fn auth_hmac<H: HmacSha256Ctx>(
    key: &[u8],
    digest: &[u8; SHA256_LEN],
    newer: &[u8; NONCE_LEN],
    older: &[u8; NONCE_LEN],
    attrs: u8,
) -> (r: [u8; SHA256_LEN])
    ensures
        r@ =~= spec_hmac_sha256(key@, spec_auth_input(digest@, newer@, older@, attrs)),
{
    let mut h = H::with_key(key);
    let tail: [u8; 1] = [attrs];

    h.update(array_as_slice(digest));
    h.update(array_as_slice(newer));
    h.update(array_as_slice(older));
    h.update(array_as_slice(&tail));

    proof {
        assert(tail@ =~= seq![attrs]);
        assert(h.absorbed() =~= spec_auth_input(digest@, newer@, older@, attrs));
    }

    h.finish()
}

pub fn rp_hash<S: Sha256Ctx>(rc: u32, ordinal: u32, parms: &[u8]) -> (r: [u8; SHA256_LEN])
    ensures
        r@ =~= spec_sha256(spec_rp_input(rc, ordinal, parms@)),
{
    let mut s = S::new();
    let rc_b = be32_arr(rc);
    let ord_b = be32_arr(ordinal);

    s.update(array_as_slice(&rc_b));
    s.update(array_as_slice(&ord_b));
    s.update(parms);

    proof {
        assert(s.absorbed() =~= spec_rp_input(rc, ordinal, parms@));
    }

    s.finish()
}

/// `names` 是各授权句柄名字的顺序拼接，由会话层准备。
pub fn cp_hash<S: Sha256Ctx>(ordinal: u32, names: &[u8], parms: &[u8]) -> (r: [u8; SHA256_LEN])
    ensures
        r@ =~= spec_sha256(spec_cp_input(ordinal, names@, parms@)),
{
    let mut s = S::new();
    let ord_b = be32_arr(ordinal);

    s.update(array_as_slice(&ord_b));
    s.update(names);
    s.update(parms);

    proof {
        assert(s.absorbed() =~= spec_cp_input(ordinal, names@, parms@));
    }

    s.finish()
}

// ===========================================================================
// 命令侧：写出授权区
// ===========================================================================

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
)
    requires
        off + CMD_SESSION_LEN <= old(out).len(),
    ensures
        final(out).len() == old(out).len(),
        spec_be32_at(final(out)@, off + SESS_HANDLE_OFF) == handle,
        spec_be16_at(final(out)@, off + SESS_NONCE_SIZE_OFF) == NONCE_LEN as u16,
        final(out)@.subrange(off + SESS_NONCE_OFF, off + SESS_NONCE_OFF + NONCE_LEN) =~= nonce@,
        final(out)@[off + SESS_ATTRS_OFF] == attrs,
        spec_be16_at(final(out)@, off + SESS_HMAC_SIZE_OFF) == NONCE_LEN as u16,
        forall|k: int|
            #![trigger final(out)@[k]]
            0 <= k < final(out).len() && (k < off || k >= off + CMD_SESSION_LEN) ==> final(out)@[k]
                == old(out)@[k],
{
    let ghost before = out@;
    let h = be32_arr(handle);
    let n = be16_arr(NONCE_LEN as u16);

    out[off + SESS_HANDLE_OFF] = h[0];
    out[off + SESS_HANDLE_OFF + 1] = h[1];
    out[off + SESS_HANDLE_OFF + 2] = h[2];
    out[off + SESS_HANDLE_OFF + 3] = h[3];

    out[off + SESS_NONCE_SIZE_OFF] = n[0];
    out[off + SESS_NONCE_SIZE_OFF + 1] = n[1];

    let mut i: usize = 0;
    while i < NONCE_LEN
        invariant
            i <= NONCE_LEN,
            off + CMD_SESSION_LEN <= out.len(),
            out.len() == before.len(),
            spec_be32_at(out@, off + SESS_HANDLE_OFF) == handle,
            spec_be16_at(out@, off + SESS_NONCE_SIZE_OFF) == NONCE_LEN as u16,
            forall|k: int| 0 <= k < i ==> out@[off + SESS_NONCE_OFF + k] == nonce@[k],
            forall|k: int|
                #![trigger out@[k]]
                0 <= k < out.len() && (k < off || k >= off + CMD_SESSION_LEN) ==> out@[k]
                    == before[k],
        decreases NONCE_LEN - i,
    {
        out[off + SESS_NONCE_OFF + i] = nonce[i];
        i = i + 1;
    }

    out[off + SESS_ATTRS_OFF] = attrs;
    out[off + SESS_HMAC_SIZE_OFF] = n[0];
    out[off + SESS_HMAC_SIZE_OFF + 1] = n[1];

    let mut j: usize = 0;
    while j < NONCE_LEN
        invariant
            j <= NONCE_LEN,
            off + CMD_SESSION_LEN <= out.len(),
            out.len() == before.len(),
            spec_be32_at(out@, off + SESS_HANDLE_OFF) == handle,
            spec_be16_at(out@, off + SESS_NONCE_SIZE_OFF) == NONCE_LEN as u16,
            spec_be16_at(out@, off + SESS_HMAC_SIZE_OFF) == NONCE_LEN as u16,
            out@[off + SESS_ATTRS_OFF] == attrs,
            out@.subrange(off + SESS_NONCE_OFF, off + SESS_NONCE_OFF + NONCE_LEN) =~= nonce@,
            forall|k: int|
                #![trigger out@[k]]
                0 <= k < out.len() && (k < off || k >= off + CMD_SESSION_LEN) ==> out@[k]
                    == before[k],
        decreases NONCE_LEN - j,
    {
        out[off + SESS_HMAC_OFF + j] = 0;
        j = j + 1;
    }
}

/// 把算好的 MAC 填进占位处。
pub fn patch_hmac(out: &mut [u8], off: usize, mac: &[u8; SHA256_LEN])
    requires
        off + CMD_SESSION_LEN <= old(out).len(),
    ensures
        final(out).len() == old(out).len(),
        final(out)@.subrange(off + SESS_HMAC_OFF, off + SESS_HMAC_OFF + SHA256_LEN) =~= mac@,
        forall|k: int|
            #![trigger final(out)@[k]]
            0 <= k < final(out).len() && (k < off + SESS_HMAC_OFF || k >= off + CMD_SESSION_LEN)
                ==> final(out)@[k] == old(out)@[k],
{
    let ghost before = out@;
    let mut i: usize = 0;
    while i < SHA256_LEN
        invariant
            i <= SHA256_LEN,
            off + CMD_SESSION_LEN <= out.len(),
            out.len() == before.len(),
            forall|k: int| 0 <= k < i ==> out@[off + SESS_HMAC_OFF + k] == mac@[k],
            forall|k: int|
                #![trigger out@[k]]
                0 <= k < out.len() && (k < off + SESS_HMAC_OFF || k >= off + CMD_SESSION_LEN)
                    ==> out@[k] == before[k],
        decreases SHA256_LEN - i,
    {
        out[off + SESS_HMAC_OFF + i] = mac[i];
        i = i + 1;
    }
}

// ===========================================================================
// 响应侧：定位授权区
// ===========================================================================

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

impl RspAuth {
    /// 定位结果自洽：各段互不重叠且都落在报文内，本会话的 HMAC 一直顶到
    /// 报文末尾。
    pub open spec fn wf(self, raw: Seq<u8>) -> bool {
        &&& HEADER_LEN <= self.parm_off
        &&& self.parm_off + self.parm_len <= self.nonce_off
        &&& self.nonce_off + NONCE_LEN + 3 == self.hmac_off
        &&& self.hmac_off + SHA256_LEN == raw.len()
    }

    pub open spec fn parms(self, raw: Seq<u8>) -> Seq<u8> {
        raw.subrange(self.parm_off as int, self.parm_off + self.parm_len)
    }

    pub open spec fn mac(self, raw: Seq<u8>) -> Seq<u8> {
        raw.subrange(self.hmac_off as int, self.hmac_off + SHA256_LEN)
    }
}

/// 取出偏移 `off` 起的一段 nonce。
fn read_nonce(raw: &[u8], off: usize) -> (r: [u8; NONCE_LEN])
    requires
        off + NONCE_LEN <= raw.len(),
    ensures
        r@ =~= raw@.subrange(off as int, off + NONCE_LEN),
{
    let mut out: [u8; NONCE_LEN] = [0u8; NONCE_LEN];
    let mut i: usize = 0;
    while i < NONCE_LEN
        invariant
            i <= NONCE_LEN,
            off + NONCE_LEN <= raw.len(),
            out@.len() == NONCE_LEN,
            forall|k: int| 0 <= k < i ==> out@[k] == raw@[off + k],
        decreases NONCE_LEN - i,
    {
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
pub fn parse_rsp_auth(raw: &[u8], rhandles: usize, index: usize) -> (r: Result<RspAuth, AuthErr>)
    requires
        rhandles <= 1,
        index < MAX_SESSIONS,
    ensures
        r matches Ok(a) ==> {
            &&& a.wf(raw@)
            &&& a.tpm_nonce@ =~= raw@.subrange(a.nonce_off as int, a.nonce_off + NONCE_LEN)
        },
{
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
    // 返回码字段跳过：只有成功的响应会走到这里，校验用的返回码按规范以
    // 零参与摘要，不必从报文里取。
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

    // 跳过排在前面的会话。轮数由 `index` 封顶，循环必然终止。
    let mut i: usize = 0;
    while i < index
        invariant
            i <= index,
            index < MAX_SESSIONS,
            c.wf(raw@.len()),
        decreases index - i,
    {
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

    Ok(RspAuth { parm_off, parm_len, nonce_off, hmac_off, attrs, tpm_nonce })
}

// ===========================================================================
// 定时比较
// ===========================================================================

proof fn lemma_or_xor_zero(acc: u8, x: u8, y: u8)
    ensures
        (acc | (x ^ y)) == 0 <==> (acc == 0 && x == y),
{
    assert((acc | (x ^ y)) == 0 <==> (acc == 0 && x == y)) by (bit_vector);
}

/// 逐字节比较，不提前返回。
///
/// 提前返回会让比较耗时随首个不同字节的位置变化，等于把「猜对了几个字节」
/// 告诉能计时的一方。MAC 比较必须是定时的。
pub fn ct_eq32(a: &[u8; SHA256_LEN], b: &[u8]) -> (r: bool)
    requires
        b.len() == SHA256_LEN,
    ensures
        r == (a@ =~= b@),
{
    let mut acc: u8 = 0;
    let mut i: usize = 0;
    while i < SHA256_LEN
        invariant
            i <= SHA256_LEN,
            b.len() == SHA256_LEN,
            (acc == 0) <==> (forall|k: int| 0 <= k < i ==> a@[k] == b@[k]),
        decreases SHA256_LEN - i,
    {
        proof {
            lemma_or_xor_zero(acc, a@[i as int], b@[i as int]);
        }
        acc = acc | (a[i] ^ b[i]);
        i = i + 1;
    }
    acc == 0
}

} // verus!