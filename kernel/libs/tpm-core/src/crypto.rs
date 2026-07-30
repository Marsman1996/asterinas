use vstd::prelude::*;
use vstd::array::*;

verus! {

// ===========================================================================
// 尺寸常量
// ===========================================================================

/// SHA-256 摘要长度。本层的 nonce、会话密钥、HMAC 字段一律取这个长度。
pub const SHA256_LEN: usize = 32;

/// 会话 nonce 长度。规范允许在 16 到摘要长度之间取值，这里取上限：
/// nonce 越长重放窗口越小，代价只是报文里多几十个字节。
pub const NONCE_LEN: usize = SHA256_LEN;

pub const AES_KEY_LEN: usize = 16;
pub const AES_BLOCK_LEN: usize = 16;

/// 参数加解密所需的密钥材料：一段 AES 密钥紧跟一个初始向量。
///
/// 它恰好等于一个摘要块长度，这一点被 [`kdfa32`] 用来把派生过程固定成
/// 单轮，见那里的说明。
pub const CFB_MATERIAL_LEN: usize = AES_KEY_LEN + AES_BLOCK_LEN;

/// 口令在会话结构里的存放上限。
pub const PASSPHRASE_MAX: usize = SHA256_LEN;

/// HMAC 密钥材料上限：会话密钥后面拼接口令。
pub const KEY_MATERIAL_MAX: usize = SHA256_LEN + PASSPHRASE_MAX;

// ===========================================================================
// 大端序列
// ===========================================================================
//
// 这里的两个 spec fn 不是新的字节序约定，而是把 `cursor::be16_bytes` /
// `cursor::be32_bytes` 的后置条件抬到序列层——哈希输入天然是序列拼接，
// 用数组形式写规约会让每条等式都拖着一个 `@`。两者逐字节一致，由下面
// 两个包装函数的证明保证。

pub open spec fn be16_seq(v: u16) -> Seq<u8> {
    seq![(v / 256) as u8, (v % 256) as u8]
}

pub open spec fn be32_seq(v: u32) -> Seq<u8> {
    seq![
        (v / 16777216) as u8,
        ((v / 65536) % 256) as u8,
        ((v / 256) % 256) as u8,
        (v % 256) as u8,
    ]
}

pub fn be16_arr(v: u16) -> (r: [u8; 2])
    ensures
        r@ =~= be16_seq(v),
{
    crate::cursor::be16_bytes(v)
}

pub fn be32_arr(v: u32) -> (r: [u8; 4])
    ensures
        r@ =~= be32_seq(v),
{
    crate::cursor::be32_bytes(v)
}

// ===========================================================================
// 未解释的密码学函数
// ===========================================================================
//
// 这四个函数刻意不给定义：本层要证的性质里没有一条依赖它们的内部结构。
// 「响应通过校验」这件事的形式内容是**逐字节相等**——收到的 MAC 与本地
// 用同一密钥、同一 nonce 对重算出的 MAC 相同——这条性质在把哈希当成任
// 意函数时同样成立，因此不必把 SHA-256 的压缩函数拖进证明。
//
// 反过来说，"攻击者伪造不出 MAC" 不在本层的证明范围内，它是密码学假设，
// 属于信任基的一部分，应当写进 TCB 文档而不是当成定理。

pub uninterp spec fn spec_sha256(msg: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn spec_hmac_sha256(key: Seq<u8>, msg: Seq<u8>) -> Seq<u8>;

/// `encrypt` 为真表示加密方向，为假表示解密方向。
pub uninterp spec fn spec_aes_cfb(
    key: Seq<u8>,
    iv: Seq<u8>,
    input: Seq<u8>,
    encrypt: bool,
) -> Seq<u8>;

/// 第 `gen` 次抽取得到的随机串。
///
/// 世代号是**唯一**被建模的性质：它让「本轮 nonce 不是上一轮那个」成为可
/// 证的语法事实。至于两次抽取的取值确实不同，那是随机源的概率性质，不
/// 在这里断言。
pub uninterp spec fn spec_draw(gen: nat) -> Seq<u8>;

// ===========================================================================
// 可信公理
// ===========================================================================
//
// 只声明长度与可逆性。任何超出这两类的断言都会让 TCB 悄悄变厚。

#[verifier::external_body]
pub broadcast proof fn axiom_sha256_len(msg: Seq<u8>)
    ensures
        #[trigger] spec_sha256(msg).len() == SHA256_LEN as nat,
{
}

#[verifier::external_body]
pub broadcast proof fn axiom_hmac_len(key: Seq<u8>, msg: Seq<u8>)
    ensures
        #[trigger] spec_hmac_sha256(key, msg).len() == SHA256_LEN as nat,
{
}

#[verifier::external_body]
pub broadcast proof fn axiom_draw_len(gen: nat)
    ensures
        #[trigger] spec_draw(gen).len() == NONCE_LEN as nat,
{
}

/// 流密码不改变长度。参数区是原地加解密的，缓冲区布局因此不受影响——
/// 这条是布局推理的前提，不是密码学性质。
#[verifier::external_body]
pub broadcast proof fn axiom_cfb_len(key: Seq<u8>, iv: Seq<u8>, input: Seq<u8>, enc: bool)
    ensures
        #[trigger] spec_aes_cfb(key, iv, input, enc).len() == input.len(),
{
}

/// 同密钥同初始向量下，解密是加密的左逆。
#[verifier::external_body]
pub broadcast proof fn axiom_cfb_roundtrip(key: Seq<u8>, iv: Seq<u8>, input: Seq<u8>)
    ensures
        #[trigger] spec_aes_cfb(key, iv, spec_aes_cfb(key, iv, input, true), false) == input,
{
}

pub broadcast group group_crypto_axioms {
    axiom_sha256_len,
    axiom_hmac_len,
    axiom_draw_len,
    axiom_cfb_len,
    axiom_cfb_roundtrip,
}

// ===========================================================================
// 增量摘要接口
// ===========================================================================
//
// 做成上下文而不是「一次喂一整块」，是因为命令摘要的输入由命令码、若干
// 句柄名字、整个参数区拼成，参数区可以有几千字节。若要求先拼出完整输入
// 再哈希，就得在无分配器的环境里备一块同样大的缓冲区，纯属浪费。
//
// 规约用 `absorbed()` 记录已吸收的字节序列，拼接语义因此是显式的，调用
// 顺序写错会在证明阶段暴露而不是等到跟真实器件对不上账。

pub trait Sha256Ctx: Sized {
    spec fn absorbed(&self) -> Seq<u8>;

    fn new() -> (r: Self)
        ensures
            r.absorbed() =~= Seq::<u8>::empty(),
    ;

    fn update(&mut self, data: &[u8])
        ensures
            final(self).absorbed() =~= old(self).absorbed() + data@,
    ;

    fn finish(self) -> (r: [u8; SHA256_LEN])
        ensures
            r@ =~= spec_sha256(self.absorbed()),
    ;
}

pub trait HmacSha256Ctx: Sized {
    spec fn key(&self) -> Seq<u8>;

    spec fn absorbed(&self) -> Seq<u8>;

    fn with_key(key: &[u8]) -> (r: Self)
        ensures
            r.key() =~= key@,
            r.absorbed() =~= Seq::<u8>::empty(),
    ;

    fn update(&mut self, data: &[u8])
        ensures
            final(self).key() =~= old(self).key(),
            final(self).absorbed() =~= old(self).absorbed() + data@,
    ;

    fn finish(self) -> (r: [u8; SHA256_LEN])
        ensures
            r@ =~= spec_hmac_sha256(self.key(), self.absorbed()),
    ;
}

// ===========================================================================
// 随机源
// ===========================================================================

pub trait NonceSource {
    /// 已抽取次数。只在证明里出现，运行时不占空间。
    ///
    /// 不叫 `gen`：那是 2024 版次的保留字。
    spec fn draws(&self) -> nat;

    fn nonce(&mut self) -> (r: [u8; NONCE_LEN])
        ensures
            final(self).draws() == old(self).draws() + 1,
            r@ =~= spec_draw(old(self).draws()),
    ;
}

// ===========================================================================
// 参数加解密
// ===========================================================================

pub trait AesCfb {
    /// 原地加密。`material` 前半是密钥、后半是初始向量。
    fn encrypt(&self, material: &[u8; CFB_MATERIAL_LEN], data: &mut [u8])
        ensures
            final(data)@ =~= spec_aes_cfb(
                material@.subrange(0, AES_KEY_LEN as int),
                material@.subrange(AES_KEY_LEN as int, CFB_MATERIAL_LEN as int),
                old(data)@,
                true,
            ),
            final(data).len() == old(data).len(),
    ;

    fn decrypt(&self, material: &[u8; CFB_MATERIAL_LEN], data: &mut [u8])
        ensures
            final(data)@ =~= spec_aes_cfb(
                material@.subrange(0, AES_KEY_LEN as int),
                material@.subrange(AES_KEY_LEN as int, CFB_MATERIAL_LEN as int),
                old(data)@,
                false,
            ),
            final(data).len() == old(data).len(),
    ;
}

// ===========================================================================
// 密钥派生
// ===========================================================================

/// 派生函数的一轮输入：计数器 ‖ 标签 ‖ 上下文 U ‖ 上下文 V ‖ 总位数。
///
/// 标签按规范要求带尾零。这里约定**调用方传入的标签已含尾零**，而不是
/// 在函数内部补——补零意味着要么额外准备缓冲区，要么多喂一次单字节，
/// 两者都会在规约里留下一个容易写反的拼接项。
pub open spec fn spec_kdfa_msg(label: Seq<u8>, u: Seq<u8>, v: Seq<u8>, bits: u32) -> Seq<u8> {
    be32_seq(1) + label + u + v + be32_seq(bits)
}

pub open spec fn spec_kdfa32(key: Seq<u8>, label: Seq<u8>, u: Seq<u8>, v: Seq<u8>) -> Seq<u8> {
    spec_hmac_sha256(key, spec_kdfa_msg(label, u, v, 256))
}

/// 会话密钥派生标签（含尾零）。
pub const LABEL_ATH: [u8; 4] = [0x41, 0x54, 0x48, 0x00];

/// 参数加解密密钥派生标签（含尾零）。
pub const LABEL_CFB: [u8; 4] = [0x43, 0x46, 0x42, 0x00];

/// 派生 32 字节密钥材料。
///
/// 计数器只走一轮。本层要派生的两样东西——会话密钥、参数加解密的密钥
/// 加初始向量——长度都恰好是一个摘要块，所以通用的多轮循环在这里没有
/// 调用者。固定成单轮之后，循环不变量与终止性都不必再证，规约也只剩
/// 一条等式。若将来需要更长的输出，应当另写一个带 `decreases` 的多轮
/// 版本，而不是把这个函数改成循环——那会让现有调用点的证明全部重来。
pub fn kdfa32<H: HmacSha256Ctx>(
    key: &[u8],
    label: &[u8],
    u: &[u8],
    v: &[u8],
) -> (r: [u8; SHA256_LEN])
    ensures
        r@ =~= spec_kdfa32(key@, label@, u@, v@),
{
    let mut h = H::with_key(key);

    let counter = be32_arr(1);
    let bits = be32_arr(256);

    h.update(array_as_slice(&counter));
    h.update(label);
    h.update(u);
    h.update(v);
    h.update(array_as_slice(&bits));

    proof {
        assert(h.absorbed() =~= spec_kdfa_msg(label@, u@, v@, 256));
    }

    h.finish()
}

} // verus!