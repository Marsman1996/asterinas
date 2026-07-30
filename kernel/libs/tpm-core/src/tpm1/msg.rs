use vstd::prelude::*;
use vstd::slice::*;

use crate::cursor::*;

verus! {

// ===========================================================================
// 报文外壳
// ===========================================================================
//
// 头部的字节布局与 2.0 相同:标签 2 字节、总长 4 字节、编号/返回码 4 字节。
// 但标签取值是另一套,响应解析的判定规则也因此不同,不能借用 2.0 侧的解析器。
// 本模块只处理外壳(标签、长度、返回码),报文体的解析在 `rsp` 模块。

pub const HEADER_LEN: usize = 10;

/// 请求标签。本驱动只构造这一种——它不参与任何需要授权会话的操作,因此永远
/// 不会用到带授权区的请求标签。
pub const TAG_RQU_COMMAND: u16 = 0x00C1;

/// 期望的响应标签。器件对一条无授权请求的应答固定用它;收到别的标签说明
/// 应答与请求不配对,按格式错误处理。
pub const TAG_RSP_COMMAND: u16 = 0x00C4;

pub const RC_SUCCESS: u32 = 0x0000_0000;

// ===========================================================================
// 解析错误
// ===========================================================================

#[derive(PartialEq, Eq, Structural)]
pub enum Parse1Error {
    /// 字节数不足以取出下一个字段。
    Truncated,
    /// 长度字段与实到字节数不符,或标签不是预期值。
    Malformed,
    /// 器件报告了非零返回码。
    TpmError(u32),
}

// ===========================================================================
// 头部规约
// ===========================================================================

/// 一条响应格式良好:装得下头部,且长度字段与实到字节数逐字节一致。
///
/// 这是后续所有偏移推理的锚点。不满足它,解析不会启动,因此下游可以放心以
/// 切片自身的长度为边界。
pub open spec fn spec_rsp1_wf(s: Seq<u8>) -> bool {
    &&& s.len() >= HEADER_LEN
    &&& spec_be32_at(s, 2) as nat == s.len()
}

/// 已校验的响应:返回码 + 去掉头部的载荷。
///
/// 标签不进入这个结构——它只在解析时用来判定配对,判过之后对上层无用。
pub struct Response1<'a> {
    pub rc: u32,
    pub body: &'a [u8],
}

impl<'a> Response1<'a> {
    pub open spec fn wf(self, raw: Seq<u8>) -> bool {
        &&& spec_rsp1_wf(raw)
        &&& self.rc == spec_be32_at(raw, 6)
        &&& self.body@ == raw.subrange(HEADER_LEN as int, raw.len() as int)
        &&& self.body@.len() == raw.len() - HEADER_LEN
    }
}

/// 校验并拆解一条响应。
///
/// 拒绝四类输入:长度不足一个头部、长度字段与实到字节数不符、标签不是预期的
/// 应答标签、返回码非零。返回码非零时不再往下解析载荷——失败应答的载荷内容
/// 无从约束。
pub fn parse_response1(raw: &[u8]) -> (r: Result<Response1<'_>, Parse1Error>)
    ensures
        r matches Ok(rsp) ==> {
            &&& rsp.wf(raw@)
            &&& rsp.rc == RC_SUCCESS
        },
{
    if raw.len() < HEADER_LEN {
        return Err(Parse1Error::Truncated);
    }

    let mut c = Cursor::new();

    let tag = match c.read_be16(raw) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let size = match c.read_be32(raw) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let rc = match c.read_be32(raw) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };

    if size as usize != raw.len() {
        return Err(Parse1Error::Malformed);
    }
    if tag != TAG_RSP_COMMAND {
        return Err(Parse1Error::Malformed);
    }
    if rc != RC_SUCCESS {
        return Err(Parse1Error::TpmError(rc));
    }

    let body = slice_subrange(raw, HEADER_LEN, raw.len());
    Ok(Response1 { rc, body })
}

// ===========================================================================
// 请求头
// ===========================================================================

/// 给定编号与总长度,生成 10 字节请求头。
///
/// 标签写死为请求标签,长度字段一次写定。命令层的载荷长度都是编译期常量,
/// 没有「先写载荷再回填长度」的必要,而回填正是长度字段与实际字节数走散的
/// 唯一入口。
pub fn build_header1(ordinal: u32, total_size: u32) -> (r: [u8; 10])
    ensures
        r@.len() == 10,
        spec_be16_at(r@, 0) == TAG_RQU_COMMAND,
        spec_be32_at(r@, 2) == total_size,
        spec_be32_at(r@, 6) == ordinal,
{
    let t = be16_bytes(TAG_RQU_COMMAND);
    let s = be32_bytes(total_size);
    let c = be32_bytes(ordinal);
    [t[0], t[1], s[0], s[1], s[2], s[3], c[0], c[1], c[2], c[3]]
}

} // verus!
