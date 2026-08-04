use crate::{cursor::*, tpm1::msg::Parse1Error};

/// 随机数一次能取回的上界。器件可以少给,但给多了说明它没遵守请求里的上限,
/// 按格式错误处理。
pub const RANDOM_MAX: usize = 128;
/// 解析一项返回值为 u32 的能力。
///
/// 体布局:`respSize u32` 后跟 `respSize` 字节。这里只取「值是一个 u32」的形态:
/// 先读长度前缀,确认它至少覆盖 4 字节,再取那 4 字节。长度前缀不足 4 时报格式
/// 错误,而不是去读前缀之外的字节。
pub fn parse_cap_u32(body: &[u8]) -> Result<u32, Parse1Error> {
    let mut c = Cursor::new();
    let resp_size = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    if resp_size < 4 {
        return Err(Parse1Error::Malformed);
    }
    match c.read_be32(body) {
        Some(v) => Ok(v),
        None => Err(Parse1Error::Truncated),
    }
}
/// 解析一项返回值为字节串的能力。
///
/// 返回借用而非拷贝,长度由长度前缀给出,并卡在 `RANDOM_MAX` 之内——对端声明
/// 的长度不能超过本层愿意暴露的上界,否则按格式错误处理。返回的切片保证落在
/// 载荷内、长度不超过声明值。
pub fn parse_cap_bytes(body: &[u8], max: usize) -> Result<&[u8], Parse1Error> {
    let mut c = Cursor::new();
    let resp_size = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    if resp_size as usize > max {
        return Err(Parse1Error::Malformed);
    }
    match c.read_bytes(body, resp_size as usize) {
        Some(s) => Ok(s),
        None => Err(Parse1Error::Truncated),
    }
}
/// 解析一项返回三个 u32 的能力(时长三档、或超时四档的前三个)。
///
/// 体布局:`respSize u32` 后跟若干 u32。这里要三个,因此长度前缀必须至少覆盖
/// 12 字节;不足则报格式错误,不去读前缀之外的字节。
pub fn parse_cap_u32_triple(body: &[u8]) -> Result<(u32, u32, u32), Parse1Error> {
    let mut c = Cursor::new();
    let resp_size = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    if resp_size < 12 {
        return Err(Parse1Error::Malformed);
    }
    let a = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let b = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let d = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    Ok((a, b, d))
}
/// 解析一项返回四个 u32 的能力(四档 TIS 超时)。
///
/// 体布局:`respSize u32` 后跟四个 u32。长度前缀必须至少覆盖 16 字节;不足则报
/// 格式错误,不去读前缀之外的字节。
pub fn parse_cap_u32_quad(body: &[u8]) -> Result<(u32, u32, u32, u32), Parse1Error> {
    let mut c = Cursor::new();
    let resp_size = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    if resp_size < 16 {
        return Err(Parse1Error::Malformed);
    }
    let a = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let b = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let d = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    let e = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    Ok((a, b, d, e))
}
/// 摘要长度。1.2 的 PCR 一律是这个宽度。
pub const PCR_DIGEST_LEN: usize = 20;
/// 解析一次 PCR 读取。
///
/// 体就是摘要本身,无长度前缀。取固定宽度即可;体不足这个宽度说明响应被截断。
pub fn parse_pcr_read(body: &[u8]) -> Result<&[u8], Parse1Error> {
    let mut c = Cursor::new();
    match c.read_bytes(body, PCR_DIGEST_LEN) {
        Some(s) => Ok(s),
        None => Err(Parse1Error::Truncated),
    }
}
/// 解析一次取随机数。
///
/// 体布局:`size u32` 后跟 `size` 字节。对端给的字节数超过请求上限同样按异常
/// 处理——那说明它没有遵守请求里的界。返回的切片保证落在载荷内、长度不超过
/// `max`。
pub fn parse_get_random(body: &[u8], max: u16) -> Result<&[u8], Parse1Error> {
    let mut c = Cursor::new();
    let size = match c.read_be32(body) {
        Some(v) => v,
        None => return Err(Parse1Error::Truncated),
    };
    if size > max as u32 {
        return Err(Parse1Error::Malformed);
    }
    match c.read_bytes(body, size as usize) {
        Some(s) => Ok(s),
        None => Err(Parse1Error::Truncated),
    }
}
