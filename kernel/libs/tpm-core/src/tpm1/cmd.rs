
use crate::cursor::*;
use crate::tpm1::msg::{build_header1, HEADER_LEN, TAG_RQU_COMMAND};
use crate::tpm1::ord::{
    ORD_CONTINUE_SELF_TEST, ORD_EXTEND, ORD_GET_CAPABILITY, ORD_GET_RANDOM, ORD_PCR_READ,
    ORD_SAVE_STATE, ORD_STARTUP,
};

pub const SHA1_DIGEST_LEN: usize = 20;
/// 摘要长度 20、编号 4、能力查询三字段的最大形态,决定了任一命令所需的最小
/// 缓冲区。调用方按它备缓冲区即可容纳本模块构造的任何一条命令。
pub const CMD_MAX: usize = HEADER_LEN + 24;
/// 写入 10 字节请求头,载荷区(偏移 10 之后)保持不动。
fn put_header1(buf: &mut [u8], ordinal: u32, total: usize) {
    let hdr = build_header1(ordinal, total as u32);
    let mut k: usize = 0;
    while k < HEADER_LEN {
        buf[k] = hdr[k];
        k += 1;
    }
}
/// 写一个大端 u32 载荷,其余字节不动。
fn put_be32_at(buf: &mut [u8], off: usize, v: u32) {
    let b = be32_bytes(v);
    buf[off] = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}
/// 写一个大端 u16 载荷,其余字节不动。
fn put_be16_at(buf: &mut [u8], off: usize, v: u16) {
    let b = be16_bytes(v);
    buf[off] = b[0];
    buf[off + 1] = b[1];
}
/// 把 `src` 逐字节写到偏移 `off`,其余字节不动。
fn put_bytes_at(buf: &mut [u8], off: usize, src: &[u8]) {
    let n = src.len();
    let mut i: usize = 0;
    while i < n {
        buf[off + i] = src[i];
        i += 1;
    }
}
/// 读一个 PCR。载荷是被读的 PCR 序号。
pub fn build_pcr_read(buf: &mut [u8], pcr_idx: u32) -> usize {
    let total = HEADER_LEN + 4;
    put_header1(buf, ORD_PCR_READ, total);
    put_be32_at(buf, HEADER_LEN, pcr_idx);
    total
}
/// 向一个 PCR 累加一段摘要。载荷是 PCR 序号加 20 字节摘要。
pub fn build_pcr_extend(buf: &mut [u8], pcr_idx: u32, digest: &[u8]) -> usize {
    let total = HEADER_LEN + 4 + SHA1_DIGEST_LEN;
    put_header1(buf, ORD_EXTEND, total);
    put_be32_at(buf, HEADER_LEN, pcr_idx);
    put_bytes_at(buf, HEADER_LEN + 4, digest);
    total
}
/// 取随机字节。载荷是希望取回的字节数;器件可少给,不会多给。
pub fn build_get_random(buf: &mut [u8], num_bytes: u32) -> usize {
    let total = HEADER_LEN + 4;
    put_header1(buf, ORD_GET_RANDOM, total);
    put_be32_at(buf, HEADER_LEN, num_bytes);
    total
}
/// 查询一项能力。载荷是能力类目、子项字节数、子项本身。
///
/// 只支持「子项是一个 u32」这一形态——本驱动问到的每一项能力都落在这个形态里,
/// 把子项字节数固定成 4 因此没有损失,也省掉了一个变长分支。
pub fn build_getcap(buf: &mut [u8], cap: u32, subcap: u32) -> usize {
    let total = HEADER_LEN + 12;
    put_header1(buf, ORD_GET_CAPABILITY, total);
    put_be32_at(buf, HEADER_LEN, cap);
    put_be32_at(buf, HEADER_LEN + 4, 4);
    put_be32_at(buf, HEADER_LEN + 8, subcap);
    total
}
/// 触发一次增量自检:只测尚未测过的部分。这条命令无载荷。
pub fn build_continue_selftest(buf: &mut [u8]) -> usize {
    let total = HEADER_LEN;
    put_header1(buf, ORD_CONTINUE_SELF_TEST, total);
    total
}
/// 保存易失状态,为休眠做准备。这条命令无载荷。
pub fn build_save_state(buf: &mut [u8]) -> usize {
    let total = HEADER_LEN;
    put_header1(buf, ORD_SAVE_STATE, total);
    total
}
/// 宣告启动方式。载荷是启动类型。固件通常已经启动过器件,这条命令是模拟器等
/// 场景下的兜底。
pub fn build_startup(buf: &mut [u8], startup_type: u16) -> usize {
    let total = HEADER_LEN + 2;
    put_header1(buf, ORD_STARTUP, total);
    put_be16_at(buf, HEADER_LEN, startup_type);
    total
}
