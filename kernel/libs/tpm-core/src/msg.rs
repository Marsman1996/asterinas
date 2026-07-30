use vstd::prelude::*;
use vstd::array::*;
use vstd::slice::*;

use crate::cursor::*;

verus! {

pub const TPM_HEADER_LEN: usize = 10;

/// 无会话响应标签。
pub const ST_NO_SESSIONS: u16 = 0x8001;
/// 带会话（授权区）响应标签。
pub const ST_SESSIONS: u16 = 0x8002;

/// 成功返回码。
pub const RC_SUCCESS: u32 = 0x0000;

// ===================== 解析错误 =====================

#[derive(PartialEq, Eq, Structural)]
pub enum ParseError {
    /// 字节数不足以取出下一个字段。
    Truncated,
    /// 长度字段与实际字节数不符，或字段取值超出规范允许范围。
    Malformed,
    /// 计数超出本实现的静态容量上限。
    Capacity,
    /// 语法合法但本实现不支持（未知算法、未预期的响应形态）。
    Unsupported,
    /// TPM 报告了非零返回码。
    TpmError(u32),
}

// ===================== 头部规约 =====================

/// 报文头的抽象视图。`code` 在请求方向是命令码，在响应方向是返回码。
pub struct HeaderView {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

pub open spec fn spec_header(s: Seq<u8>) -> HeaderView
    recommends
        s.len() >= TPM_HEADER_LEN,
{
    HeaderView { tag: spec_be16_at(s, 0), size: spec_be32_at(s, 2), code: spec_be32_at(s, 6) }
}

/// 一条响应"格式良好"：装得下头部，且长度字段与实到字节数逐字节一致。
///
/// 这是整个解码层的锚点性质。传输层交上来的切片若不满足它，解析根本
/// 不会启动，因此后续所有偏移推理都可以放心地以 `s.len()` 为界。
pub open spec fn spec_rsp_wf(s: Seq<u8>) -> bool {
    &&& s.len() >= TPM_HEADER_LEN
    &&& spec_header(s).size as nat == s.len()
}

// ===================== 响应视图 =====================

/// 已校验的响应：头部三字段 + 去掉头部的载荷。
pub struct Response<'a> {
    pub tag: u16,
    pub rc: u32,
    pub body: &'a [u8],
}

impl<'a> Response<'a> {
    pub open spec fn wf(self, raw: Seq<u8>) -> bool {
        &&& spec_rsp_wf(raw)
        &&& self.tag == spec_header(raw).tag
        &&& self.rc == spec_header(raw).code
        &&& self.body@ == raw.subrange(TPM_HEADER_LEN as int, raw.len() as int)
        &&& self.body@.len() == raw.len() - TPM_HEADER_LEN
    }

    pub fn is_success(&self) -> (r: bool)
        ensures
            r == (self.rc == RC_SUCCESS),
    {
        self.rc == RC_SUCCESS
    }
}

/// 校验并拆解一条响应。
///
/// 拒绝三类输入：长度不足一个头部、`size` 字段与实到字节数不符、
/// 标签不是两个合法响应标签之一。返回码非零时不再往下解析载荷——
/// 失败响应的载荷内容按规范是未定义的。
pub fn parse_response(raw: &[u8]) -> (r: Result<Response<'_>, ParseError>)
    ensures
        r matches Ok(rsp) ==> {
            &&& rsp.wf(raw@)
            &&& rsp.rc == RC_SUCCESS
            &&& rsp.tag == ST_NO_SESSIONS || rsp.tag == ST_SESSIONS
        },
{
    if raw.len() < TPM_HEADER_LEN {
        return Err(ParseError::Truncated);
    }

    let mut c = Cursor::new();

    let tag = match c.read_be16(raw) {
        Some(v) => v,
        None => return Err(ParseError::Truncated),
    };
    let size = match c.read_be32(raw) {
        Some(v) => v,
        None => return Err(ParseError::Truncated),
    };
    let rc = match c.read_be32(raw) {
        Some(v) => v,
        None => return Err(ParseError::Truncated),
    };

    // 长度字段必须精确等于实到字节数：多一字节意味着上层截断有误，
    // 少一字节意味着后续解析会读到不属于本条响应的数据。
    if size as usize != raw.len() {
        return Err(ParseError::Malformed);
    }
    if tag != ST_NO_SESSIONS && tag != ST_SESSIONS {
        return Err(ParseError::Malformed);
    }
    if rc != RC_SUCCESS {
        return Err(ParseError::TpmError(rc));
    }

    let body = slice_subrange(raw, TPM_HEADER_LEN, raw.len());
    Ok(Response { tag, rc, body })
}

// ===================== 请求头 =====================

/// 请求头的字节形态。命令载荷由 `cmd` 模块构造，两者拼接即整条请求。
///
/// `size` 需要在载荷长度确定后回填，因此这里只提供"给定总长度生成
/// 头部"的纯函数，由缓冲区层在收尾时调用。
pub fn build_header(tag: u16, code: u32, total_size: u32) -> (r: [u8; 10])
    ensures
        r@.len() == 10,
        spec_be16_at(r@, 0) == tag,
        spec_be32_at(r@, 2) == total_size,
        spec_be32_at(r@, 6) == code,
{
    let t = be16_bytes(tag);
    let s = be32_bytes(total_size);
    let c = be32_bytes(code);
    [t[0], t[1], s[0], s[1], s[2], s[3], c[0], c[1], c[2], c[3]]
}

} // verus!
