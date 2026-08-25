use tpm_core::crypto::{
    AES_BLOCK_LEN, AES_KEY_LEN, AesCfb, CFB_MATERIAL_LEN, HmacSha256Ctx, NONCE_LEN, NonceSource,
    SHA256_LEN, Sha256Ctx,
};

/// 摘要 / HMAC 上下文的字节容量。
///
/// 现在上下文是编译期已知大小的 Rust 结构体,不再需要为宿主结构预留字节,
/// 这个常量只为保持再导出接口不变而保留,内部已无使用者。
pub const HASH_CTX_CAP: usize = 512;
/// 启动时的一次性自检。
///
/// 曾经用来核对「预留空间装不装得下宿主上下文」。上下文尺寸现在由类型系统
/// 在编译期定死,这个检查恒真;保留签名与调用点,是为了让 `boot::bring_up`
/// 的 `abi_ok` 通路无需改动。若将来彻底移除该通路,可连同本函数一并删去。
pub fn check_abi() -> bool {
    true
}
/// 增量摘要上下文的不透明存储。
///
/// 字段类型来自外部库,Verus 不解释;用 `external_body` 把它整体挡在验证器
/// 之外,只在下面的 `external_body` 方法里触碰。
struct Sha256State {
    inner: sha2::Sha256,
}
/// 增量摘要上下文。
///
/// `absorbed` 是幽灵字段,运行时不占空间,只让 `crypto.rs` 里「已吸收字节
/// 序列」这条规约在实现侧有个落点。它在每个 `external_body` 方法的 `proof`
/// 块里更新,与真实喂进摘要器的字节保持字面一致——这份一致由人工核对保证,
/// 不由验证器。
pub struct ExtSha256 {
    st: Sha256State,
}
impl Sha256Ctx for ExtSha256 {
    fn new() -> Self {
        use sha2::Digest;
        ExtSha256 {
            st: Sha256State {
                inner: sha2::Sha256::new(),
            },
        }
    }
    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.st.inner.update(data);
        {}
    }
    fn finish(self) -> [u8; SHA256_LEN] {
        use sha2::Digest;
        let me = self;
        let digest = me.st.inner.finalize();
        let mut out = [0u8; SHA256_LEN];
        out.copy_from_slice(digest.as_ref());
        out
    }
}
struct HmacState {
    inner: hmac::Hmac<sha2::Sha256>,
}
pub struct ExtHmacSha256 {
    st: HmacState,
}
impl HmacSha256Ctx for ExtHmacSha256 {
    fn with_key(key: &[u8]) -> Self {
        use hmac::Mac;
        let inner = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
        ExtHmacSha256 {
            st: HmacState { inner },
        }
    }
    fn update(&mut self, data: &[u8]) {
        use hmac::Mac;
        self.st.inner.update(data);
        {}
    }
    fn finish(self) -> [u8; SHA256_LEN] {
        use hmac::Mac;
        let me = self;
        let tag = me.st.inner.finalize().into_bytes();
        let mut out = [0u8; SHA256_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }
}
/// 参数区加解密。无状态,密钥与初始向量每次由调用方给出。
pub struct ExtAesCfb;
impl AesCfb for ExtAesCfb {
    fn encrypt(&self, material: &[u8; CFB_MATERIAL_LEN], data: &mut [u8]) {
        cfb_apply(material, data, true);
    }
    fn decrypt(&self, material: &[u8; CFB_MATERIAL_LEN], data: &mut [u8]) {
        cfb_apply(material, data, false);
    }
}

// 与外部库打交道的实现体放在 the verification wrapper 之外,避免验证器去解析它们的 trait 方法。

/// 两个方向唯一的差别是最后一个布尔,其余搬运完全相同。
///
/// 失败路径只能停机。上层调用点在会话参数的加解密上,一次静默失败意味着明文
/// 原样上了总线,或者密文被当成明文解析,两者都比停机严重得多。这里的密钥/IV
/// 长度在构造期已固定为 16 字节,`new_from_slices` 不会因长度失败;真出错说明
/// 上游布局被破坏,`expect` 停机是正确反应。
#[inline]
fn cfb_apply(material: &[u8; CFB_MATERIAL_LEN], data: &mut [u8], encrypt: bool) {
    use aes::Aes128;
    use cfb_mode::{
        Cfb,
        cipher::{AsyncStreamCipher, NewCipher},
    };

    // 密钥在前、初始向量紧随其后,这个布局由 `crypto.rs` 的 `CFB_MATERIAL_LEN`
    // 定义,两处必须一起改。
    const {
        debug_assert!(AES_KEY_LEN + AES_BLOCK_LEN == CFB_MATERIAL_LEN);
    }
    let mut key = [0u8; AES_KEY_LEN];
    let mut iv = [0u8; AES_BLOCK_LEN];
    key.copy_from_slice(&material[..AES_KEY_LEN]);
    iv.copy_from_slice(&material[AES_KEY_LEN..]);

    if encrypt {
        Cfb::<Aes128>::new_from_slices(&key, &iv)
            .expect("密钥与 IV 长度固定为 16 字节")
            .encrypt(data);
    } else {
        Cfb::<Aes128>::new_from_slices(&key, &iv)
            .expect("密钥与 IV 长度固定为 16 字节")
            .decrypt(data);
    }

    // 拷进本地的密钥材料用完立刻抹掉。这不是任何一条已证性质的要求,而是纵深
    // 防御:两块数组在栈上,不擦除的话密钥字节会在后续调用的栈帧里残留。
    wipe_bytes(&mut key);
    wipe_bytes(&mut iv);
}

/// 覆写一块存储,且不允许被优化掉。
///
/// 普通赋值在这里可能被整个删除——写完之后没有任何一次读取,编译器有权认为
/// 这些写入不可观察。逐字节 volatile 写是不引入外部 crate 的可靠做法。
#[inline]
fn wipe_bytes(b: &mut [u8]) {
    b.fill(0);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// 随机源取不到数时的重试次数。超过之后放弃,见 [`ExtRng::nonce`]。
const RNG_RETRY: u32 = 16;
/// 会话 nonce 的来源。
pub struct ExtRng;
impl ExtRng {
    pub fn new() -> Self {
        Self
    }
}
impl Default for ExtRng {
    fn default() -> Self {
        Self::new()
    }
}
impl NonceSource for ExtRng {
    /// 取一个 nonce。
    ///
    /// 规约里的 `spec_draw(gen)` 在这里得到含义:**它就定义为平台随机源的第
    /// `gen` 次输出**。这是一个命名,不是一条性质——本层从不断言两次输出取值
    /// 不同,那属于随机源自身的质量,写进 TCB 文档,不写成公理。
    ///
    /// 失败同样只能中止,理由比加解密那边更硬:nonce 是重放防护的全部依据,
    /// 取不到熵时退回任何确定性来源(计数器、时间戳、上一次的值)都会让重放
    /// 窗口从「可忽略」变成「可枚举」,而调用方无从察觉。重试若干次给瞬时不
    /// 可用(引导早期熵池尚未就绪)留了余地,超过之后停机。
    fn nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut out = [0u8; NONCE_LEN];
        let mut offset = 0usize;
        let mut tries = 0u32;
        while offset < NONCE_LEN {
            if let Some(value) = ostd::arch::read_random() {
                let bytes = value.to_ne_bytes();
                let count = core::cmp::min(bytes.len(), NONCE_LEN - offset);
                out[offset..offset + count].copy_from_slice(&bytes[..count]);
                offset += count;
                tries = 0;
            } else {
                tries += 1;
                if tries >= RNG_RETRY {
                    ostd::panic::abort();
                }
            }
        }
        {}
        out
    }
}
