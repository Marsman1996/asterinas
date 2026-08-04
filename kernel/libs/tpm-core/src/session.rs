use crate::{auth::*, crypto::*};

const _: () = ();
/// 会话生命周期。
///
/// `Pending` 用元组变体而非具名字段：带花括号的结构体字面量在 `ensures`
/// 子句里会被解析成函数体的开始，规约里只要提一次状态就报语法错。元组
/// 形式写出来是调用式，没有这个歧义。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionState {
    /// 会话可用，等待下一条命令。
    Idle,
    /// 命令已定型，等待响应。载荷是本会话在授权区里的序号。
    Pending(usize),
    /// 会话已作废。句柄还需要释放一次，之后本结构不得再参与任何运算。
    Closed,
}
/// 一个 HMAC 授权会话。
///
/// 结构体本身携带密钥材料，因此不实现 `Clone`——多一份副本就多一处需要
/// 擦除的地方。它也不实现 `Debug`：把会话密钥打进日志是最容易犯、也最难
/// 察觉的错误之一。
pub struct AuthSession {
    pub handle: u32,
    /// 本端本轮 nonce。
    pub our_nonce: [u8; NONCE_LEN],
    /// 对端最近一轮 nonce。
    pub tpm_nonce: [u8; NONCE_LEN],
    pub session_key: [u8; SHA256_LEN],
    pub passphrase: [u8; PASSPHRASE_MAX],
    pub passphrase_len: usize,
    /// 本轮命令使用的会话属性。
    pub attrs: u8,
    /// 本轮命令码。响应摘要要用到它，而响应报文里并不携带命令码，所以必须
    /// 由本端记住——这也正是响应无法被挪用到另一条命令上的原因。
    pub ordinal: u32,
    pub state: SessionState,
}
impl AuthSession {
    /// 把会话密钥与口令拼进一块定长缓冲区，返回有效长度。
    fn key_buf(&self) -> ([u8; KEY_MATERIAL_MAX], usize) {
        let mut buf: [u8; KEY_MATERIAL_MAX] = [0u8; KEY_MATERIAL_MAX];
        let mut i: usize = 0;
        while i < SHA256_LEN {
            buf[i] = self.session_key[i];
            i = i + 1;
        }
        let mut j: usize = 0;
        while j < self.passphrase_len {
            buf[SHA256_LEN + j] = self.passphrase[j];
            j = j + 1;
        }
        (buf, SHA256_LEN + self.passphrase_len)
    }
    /// 由协商出的共享秘密与双方 nonce 导出会话密钥。
    ///
    /// 共享秘密只在这一步用到，之后本结构不再持有它——密钥派生是单向的，
    /// 会话密钥泄露也推不回秘密本身。
    pub fn open_session<H: HmacSha256Ctx>(
        handle: u32,
        salt: &[u8],
        our_nonce: [u8; NONCE_LEN],
        tpm_nonce: [u8; NONCE_LEN],
    ) -> AuthSession {
        let key = kdfa32::<H>(
            salt,
            crate::array_as_slice(&LABEL_ATH),
            crate::array_as_slice(&tpm_nonce),
            crate::array_as_slice(&our_nonce),
        );
        AuthSession {
            handle,
            our_nonce,
            tpm_nonce,
            session_key: key,
            passphrase: [0u8; PASSPHRASE_MAX],
            passphrase_len: 0,
            attrs: 0,
            ordinal: 0,
            state: SessionState::Idle,
        }
    }
    /// 设置本轮口令。尾部零字节按规范先行剥除。
    ///
    /// 剥除这一步不能省：同一个口令带不带尾零会算出不同的 MAC，而调用方传
    /// 进来的往往是定长缓冲区。
    pub fn set_passphrase(&mut self, pw: &[u8]) {
        let mut n = pw.len();
        while n > 0 && pw[n - 1] == 0 {
            n = n - 1;
        }
        let mut i: usize = 0;
        while i < n {
            self.passphrase[i] = pw[i];
            i = i + 1;
        }
        self.passphrase_len = n;
    }
    /// 为下一条命令换一枚新 nonce。
    ///
    /// 前置条件 `nonce_gen < rng.draws()` 与后置条件一起构成一条链：每轮的
    /// nonce 世代严格大于上一轮，因此不可能出现两轮复用同一枚 nonce。取值
    /// 层面的不可预测性是随机源的责任，不在这里断言。
    ///
    /// 属性里强行补上「会话延续」位：会话是跨命令复用的资源，若某一轮忘了置
    /// 这一位，对端会在该轮结束后单方面销毁它，而本端毫不知情，下一轮的失败
    /// 点会离真正的原因很远。
    pub fn begin<R: NonceSource>(&mut self, rng: &mut R, ordinal: u32, attrs: u8) {
        self.our_nonce = rng.nonce();
        self.ordinal = ordinal;
        self.attrs = attrs | SA_CONTINUE_SESSION;
    }
    /// 算出命令 MAC 并填进授权区。
    ///
    /// 调用时机是**唯一**的：所有参数都已写入之后。参数区哪怕再动一个字节，
    /// 算出的 MAC 就作废了。若本轮要加密首个参数，加密也必须发生在本函数之
    /// 前——摘要覆盖的是密文，不是明文。
    ///
    /// `names` 是各授权句柄名字的顺序拼接。它由调用方按句柄类型准备：可持久化
    /// 的对象用「算法标识 ‖ 摘要」形式的名字，其余用四字节句柄本身。
    pub fn finalize<S: Sha256Ctx, H: HmacSha256Ctx>(
        &mut self,
        buf: &mut [u8],
        sess_off: usize,
        index: usize,
        names: &[u8],
        parm_off: usize,
        parm_len: usize,
    ) {
        let parms = crate::slice_subrange(&*buf, parm_off, parm_off + parm_len);
        let cph = cp_hash::<S>(self.ordinal, names, parms);
        let (kb, klen) = self.key_buf();
        let key = crate::slice_subrange(crate::array_as_slice(&kb), 0, klen);
        let mac = auth_hmac::<H>(key, &cph, &self.our_nonce, &self.tpm_nonce, self.attrs);
        patch_hmac(buf, sess_off, &mac);
        self.state = SessionState::Pending(index);
    }
    /// 校验响应 MAC。
    ///
    /// **这是本模块存在的理由。** 返回 `Ok` 意味着：报文里那段 MAC 与用本会话
    /// 密钥、本轮两枚 nonce、本轮命令码重算出来的值逐字节相同。后置条件把这句
    /// 话原样写了出来，所以任何绕过校验直接采信响应的写法都通不过。
    ///
    /// 命令码取自本端记录而非报文——响应报文根本不携带命令码。这一点让「把甲
    /// 命令的响应塞给乙命令」这类挪用在摘要层面就对不上。
    ///
    /// 任何一条失败路径都把会话置为作废。会话失败之后继续用同一把密钥重试，
    /// 等于给对面多一次猜测机会。
    pub fn check_response<S: Sha256Ctx, H: HmacSha256Ctx>(
        &mut self,
        raw: &[u8],
        rhandles: usize,
    ) -> Result<RspAuth, AuthErr> {
        let index = match self.state {
            SessionState::Pending(i) => i,
            _ => {
                self.state = SessionState::Closed;
                return Err(AuthErr::NoSession);
            }
        };
        let a = match parse_rsp_auth(raw, rhandles, index) {
            Ok(a) => a,
            Err(e) => {
                self.state = SessionState::Closed;
                return Err(e);
            }
        };
        let parm_end = match a.parm_off.checked_add(a.parm_len) {
            Some(v) => v,
            None => {
                self.state = SessionState::Closed;
                return Err(AuthErr::Malformed);
            }
        };
        let parms = crate::slice_subrange(raw, a.parm_off, parm_end);
        let rph = rp_hash::<S>(0, self.ordinal, parms);
        let (kb, klen) = self.key_buf();
        let key = crate::slice_subrange(crate::array_as_slice(&kb), 0, klen);
        let expect = auth_hmac::<H>(key, &rph, &a.tpm_nonce, &self.our_nonce, self.attrs);
        let hmac_end = match a.hmac_off.checked_add(SHA256_LEN) {
            Some(v) => v,
            None => {
                self.state = SessionState::Closed;
                return Err(AuthErr::Malformed);
            }
        };
        let got = crate::slice_subrange(raw, a.hmac_off, hmac_end);
        if !ct_eq32(&expect, got) {
            self.state = SessionState::Closed;
            return Err(AuthErr::HmacMismatch);
        }
        self.tpm_nonce = a.tpm_nonce;
        self.state = SessionState::Idle;
        Ok(a)
    }
    /// 主动作废会话。错误处理路径绕过 [`AuthSession::check_response`] 时用它收尾。
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }
}
/// 推导本轮参数加解密所需的密钥与初始向量。
///
/// 两枚 nonce 的先后决定了方向：命令方向本端 nonce 在前，响应方向对端 nonce 在
/// 前。两个方向的材料不同，这正是同一条会话上两个方向不会撞用同一段密钥流的
/// 原因。
pub fn cfb_material<H: HmacSha256Ctx>(
    session: &AuthSession,
    newer: &[u8; NONCE_LEN],
    older: &[u8; NONCE_LEN],
) -> [u8; CFB_MATERIAL_LEN] {
    let (kb, klen) = session.key_buf();
    let key = crate::slice_subrange(crate::array_as_slice(&kb), 0, klen);
    kdfa32::<H>(
        key,
        crate::array_as_slice(&LABEL_CFB),
        crate::array_as_slice(newer),
        crate::array_as_slice(older),
    )
}
/// 原地加密命令的首个参数。必须在 [`AuthSession::finalize`] 之前调用。
pub fn encrypt_parm<A: AesCfb>(aes: &A, material: &[u8; CFB_MATERIAL_LEN], parm: &mut [u8]) {
    aes.encrypt(material, parm);
}
/// 原地解密响应的首个参数。必须在 [`AuthSession::check_response`] 返回 `Ok` 之后
/// 调用——对未经校验的字节做解密，等于把对端塞进来的任意数据当成明文交给上层。
pub fn decrypt_parm<A: AesCfb>(aes: &A, material: &[u8; CFB_MATERIAL_LEN], parm: &mut [u8]) {
    aes.decrypt(material, parm);
}
