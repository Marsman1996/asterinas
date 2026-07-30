use vstd::prelude::*;
use vstd::array::*;
use vstd::slice::*;

use crate::auth::*;
use crate::crypto::*;

verus! {

broadcast use group_crypto_axioms;

// ===========================================================================
// 状态
// ===========================================================================

/// 会话生命周期。
///
/// `Pending` 用元组变体而非具名字段：带花括号的结构体字面量在 `ensures`
/// 子句里会被解析成函数体的开始，规约里只要提一次状态就报语法错。元组
/// 形式写出来是调用式，没有这个歧义。
#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
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
    /// 本轮 nonce 的抽取世代。只在证明里出现。
    pub nonce_gen: Ghost<nat>,
}

impl AuthSession {
    pub open spec fn wf(self) -> bool {
        &&& self.passphrase_len <= PASSPHRASE_MAX
        &&& match self.state {
            SessionState::Pending(i) => i < MAX_SESSIONS,
            _ => true,
        }
    }

    /// 是否处于「已发出命令、等待响应」的阶段。
    ///
    /// 写成 `match` 而不是 `matches` 表达式：规约里出现的每一处状态判断都
    /// 走这个谓词，调用点就不必再碰模式语法。
    pub open spec fn pending(self) -> bool {
        match self.state {
            SessionState::Pending(_) => true,
            _ => false,
        }
    }

    /// HMAC 密钥材料：会话密钥后面紧跟口令。
    ///
    /// 两段必须相邻且顺序固定——规范把它们当成一整条密钥看待。
    pub open spec fn key_material(self) -> Seq<u8> {
        self.session_key@ + self.passphrase@.subrange(0, self.passphrase_len as int)
    }

    /// 本会话是否还能承接命令。
    pub open spec fn usable(self) -> bool {
        self.state == SessionState::Idle
    }

    // -----------------------------------------------------------------------
    // 密钥材料的可执行侧
    // -----------------------------------------------------------------------

    /// 把会话密钥与口令拼进一块定长缓冲区，返回有效长度。
    fn key_buf(&self) -> (r: ([u8; KEY_MATERIAL_MAX], usize))
        requires
            self.wf(),
        ensures
            r.1 == SHA256_LEN + self.passphrase_len,
            r.1 <= KEY_MATERIAL_MAX,
            r.0@.subrange(0, r.1 as int) =~= self.key_material(),
    {
        let mut buf: [u8; KEY_MATERIAL_MAX] = [0u8; KEY_MATERIAL_MAX];

        let mut i: usize = 0;
        while i < SHA256_LEN
            invariant
                i <= SHA256_LEN,
                buf@.len() == KEY_MATERIAL_MAX,
                forall|k: int| #![auto] 0 <= k < i ==> buf@[k] == self.session_key@[k],
            decreases SHA256_LEN - i,
        {
            buf[i] = self.session_key[i];
            i = i + 1;
        }

        let mut j: usize = 0;
        while j < self.passphrase_len
            invariant
                j <= self.passphrase_len,
                self.passphrase_len <= PASSPHRASE_MAX,
                buf@.len() == KEY_MATERIAL_MAX,
                forall|k: int| #![auto] 0 <= k < SHA256_LEN ==> buf@[k] == self.session_key@[k],
                forall|k: int| #![auto] 0 <= k < j ==> buf@[SHA256_LEN + k] == self.passphrase@[k],
            decreases self.passphrase_len - j,
        {
            buf[SHA256_LEN + j] = self.passphrase[j];
            j = j + 1;
        }

        (buf, SHA256_LEN + self.passphrase_len)
    }

    // -----------------------------------------------------------------------
    // 建立
    // -----------------------------------------------------------------------

    /// 由协商出的共享秘密与双方 nonce 导出会话密钥。
    ///
    /// 共享秘密只在这一步用到，之后本结构不再持有它——密钥派生是单向的，
    /// 会话密钥泄露也推不回秘密本身。
    pub fn open_session<H: HmacSha256Ctx>(
        handle: u32,
        salt: &[u8],
        our_nonce: [u8; NONCE_LEN],
        tpm_nonce: [u8; NONCE_LEN],
        nonce_generation: Ghost<nat>,
    ) -> (r: AuthSession)
        ensures
            r.wf(),
            r.state == SessionState::Idle,
            r.handle == handle,
            r.our_nonce@ =~= our_nonce@,
            r.tpm_nonce@ =~= tpm_nonce@,
            r.passphrase_len == 0,
            r.key_material() =~= r.session_key@,
            r.session_key@ =~= spec_kdfa32(salt@, LABEL_ATH@, tpm_nonce@, our_nonce@),
            r.nonce_gen@ == nonce_generation@,
    {
        let key = kdfa32::<H>(
            salt,
            array_as_slice(&LABEL_ATH),
            array_as_slice(&tpm_nonce),
            array_as_slice(&our_nonce),
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
            nonce_gen: nonce_generation,
        }
    }

    /// 设置本轮口令。尾部零字节按规范先行剥除。
    ///
    /// 剥除这一步不能省：同一个口令带不带尾零会算出不同的 MAC，而调用方传
    /// 进来的往往是定长缓冲区。
    pub fn set_passphrase(&mut self, pw: &[u8])
        requires
            old(self).wf(),
            pw.len() <= PASSPHRASE_MAX,
        ensures
            final(self).wf(),
            final(self).passphrase_len <= pw.len(),
            final(self).handle == old(self).handle,
            final(self).our_nonce@ =~= old(self).our_nonce@,
            final(self).tpm_nonce@ =~= old(self).tpm_nonce@,
            final(self).session_key@ =~= old(self).session_key@,
            final(self).state == old(self).state,
            final(self).ordinal == old(self).ordinal,
            final(self).attrs == old(self).attrs,
            final(self).nonce_gen@ == old(self).nonce_gen@,
    {
        let mut n = pw.len();
        while n > 0 && pw[n - 1] == 0
            invariant
                n <= pw.len(),
            decreases n,
        {
            n = n - 1;
        }

        let mut i: usize = 0;
        while i < n
            invariant
                i <= n,
                n <= pw.len(),
                n <= PASSPHRASE_MAX,
                self.passphrase@.len() == PASSPHRASE_MAX,
            decreases n - i,
        {
            self.passphrase[i] = pw[i];
            i = i + 1;
        }
        self.passphrase_len = n;
    }

    // -----------------------------------------------------------------------
    // 每轮开始
    // -----------------------------------------------------------------------

    /// 为下一条命令换一枚新 nonce。
    ///
    /// 前置条件 `nonce_gen < rng.draws()` 与后置条件一起构成一条链：每轮的
    /// nonce 世代严格大于上一轮，因此不可能出现两轮复用同一枚 nonce。取值
    /// 层面的不可预测性是随机源的责任，不在这里断言。
    ///
    /// 属性里强行补上「会话延续」位：会话是跨命令复用的资源，若某一轮忘了置
    /// 这一位，对端会在该轮结束后单方面销毁它，而本端毫不知情，下一轮的失败
    /// 点会离真正的原因很远。
    pub fn begin<R: NonceSource>(&mut self, rng: &mut R, ordinal: u32, attrs: u8)
        requires
            old(self).wf(),
            old(self).usable(),
            old(self).nonce_gen@ < old(rng).draws(),
        ensures
            final(self).wf(),
            final(self).usable(),
            final(self).ordinal == ordinal,
            final(self).attrs == attrs | SA_CONTINUE_SESSION,
            final(self).our_nonce@ =~= spec_draw(old(rng).draws()),
            final(self).nonce_gen@ == old(rng).draws(),
            final(self).nonce_gen@ > old(self).nonce_gen@,
            final(self).nonce_gen@ < final(rng).draws(),
            final(self).handle == old(self).handle,
            final(self).tpm_nonce@ =~= old(self).tpm_nonce@,
            final(self).session_key@ =~= old(self).session_key@,
            final(self).passphrase_len == old(self).passphrase_len,
            final(self).key_material() =~= old(self).key_material(),
    {
        let ghost g = rng.draws();
        self.our_nonce = rng.nonce();
        self.nonce_gen = Ghost(g);
        self.ordinal = ordinal;
        self.attrs = attrs | SA_CONTINUE_SESSION;
    }

    // -----------------------------------------------------------------------
    // 命令定型
    // -----------------------------------------------------------------------

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
    )
        requires
            old(self).wf(),
            old(self).usable(),
            index < MAX_SESSIONS,
            sess_off + CMD_SESSION_LEN <= old(buf).len(),
            parm_off + parm_len <= old(buf).len(),
            sess_off + CMD_SESSION_LEN <= parm_off,
        ensures
            final(self).wf(),
            final(self).state == SessionState::Pending(index),
            final(self).pending(),
            final(buf).len() == old(buf).len(),
            final(self).ordinal == old(self).ordinal,
            final(self).attrs == old(self).attrs,
            final(self).our_nonce@ =~= old(self).our_nonce@,
            final(self).tpm_nonce@ =~= old(self).tpm_nonce@,
            final(self).key_material() =~= old(self).key_material(),
            final(self).nonce_gen@ == old(self).nonce_gen@,
            // 写进报文的 MAC 就是规约说的那一个
            final(buf)@.subrange(
                sess_off + SESS_HMAC_OFF,
                sess_off + SESS_HMAC_OFF + SHA256_LEN,
            ) =~= spec_hmac_sha256(
                old(self).key_material(),
                spec_auth_input(
                    spec_sha256(
                        spec_cp_input(
                            old(self).ordinal,
                            names@,
                            old(buf)@.subrange(parm_off as int, parm_off + parm_len),
                        ),
                    ),
                    old(self).our_nonce@,
                    old(self).tpm_nonce@,
                    old(self).attrs,
                ),
            ),
            // 除 MAC 字段外报文一字未改
            forall|k: int|
                #![trigger final(buf)@[k]]
                0 <= k < final(buf).len() && (k < sess_off + SESS_HMAC_OFF || k >= sess_off
                    + CMD_SESSION_LEN) ==> final(buf)@[k] == old(buf)@[k],
    {
        let parms = slice_subrange(&*buf, parm_off, parm_off + parm_len);
        let cph = cp_hash::<S>(self.ordinal, names, parms);

        let (kb, klen) = self.key_buf();
        let key = slice_subrange(array_as_slice(&kb), 0, klen);

        let mac = auth_hmac::<H>(key, &cph, &self.our_nonce, &self.tpm_nonce, self.attrs);

        patch_hmac(buf, sess_off, &mac);
        self.state = SessionState::Pending(index);
    }

    // -----------------------------------------------------------------------
    // 响应校验
    // -----------------------------------------------------------------------

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
    ) -> (r: Result<RspAuth, AuthErr>)
        requires
            old(self).wf(),
            old(self).pending(),
            rhandles <= 1,
        ensures
            final(self).wf(),
            final(self).handle == old(self).handle,
            final(self).our_nonce@ =~= old(self).our_nonce@,
            final(self).key_material() =~= old(self).key_material(),
            final(self).nonce_gen@ == old(self).nonce_gen@,
            r matches Ok(a) ==> {
                &&& a.wf(raw@)
                &&& a.mac(raw@) =~= spec_hmac_sha256(
                    old(self).key_material(),
                    spec_auth_input(
                        spec_sha256(spec_rp_input(0, old(self).ordinal, a.parms(raw@))),
                        a.tpm_nonce@,
                        old(self).our_nonce@,
                        old(self).attrs,
                    ),
                )
                &&& final(self).tpm_nonce@ =~= a.tpm_nonce@
                &&& final(self).state == SessionState::Idle
            },
            r is Err ==> final(self).state == SessionState::Closed,
    {
        let index = match self.state {
            SessionState::Pending(i) => i,
            _ => {
                self.state = SessionState::Closed;
                return Err(AuthErr::NoSession);
            },
        };

        let a = match parse_rsp_auth(raw, rhandles, index) {
            Ok(a) => a,
            Err(e) => {
                self.state = SessionState::Closed;
                return Err(e);
            },
        };

        let parm_end = match a.parm_off.checked_add(a.parm_len) {
            Some(v) => v,
            None => {
                self.state = SessionState::Closed;
                return Err(AuthErr::Malformed);
            },
        };
        let parms = slice_subrange(raw, a.parm_off, parm_end);
        let rph = rp_hash::<S>(0, self.ordinal, parms);

        let (kb, klen) = self.key_buf();
        let key = slice_subrange(array_as_slice(&kb), 0, klen);

        let expect = auth_hmac::<H>(key, &rph, &a.tpm_nonce, &self.our_nonce, self.attrs);
        let hmac_end = match a.hmac_off.checked_add(SHA256_LEN) {
            Some(v) => v,
            None => {
                self.state = SessionState::Closed;
                return Err(AuthErr::Malformed);
            },
        };
        let got = slice_subrange(raw, a.hmac_off, hmac_end);

        if !ct_eq32(&expect, got) {
            self.state = SessionState::Closed;
            return Err(AuthErr::HmacMismatch);
        }

        // 校验通过才推进状态。对端 nonce 在此刻才被采信，未通过校验的报文无法
        // 把任何东西留在会话里。
        self.tpm_nonce = a.tpm_nonce;
        self.state = SessionState::Idle;
        Ok(a)
    }

    /// 主动作废会话。错误处理路径绕过 [`AuthSession::check_response`] 时用它收尾。
    pub fn close(&mut self)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            final(self).state == SessionState::Closed,
            final(self).handle == old(self).handle,
    {
        self.state = SessionState::Closed;
    }
}

// ===========================================================================
// 参数加解密
// ===========================================================================
//
// 加解密与校验之间的先后是有讲究的，两个方向恰好相反：
//
// - 命令方向先加密后算 MAC，摘要覆盖密文；
// - 响应方向先验 MAC 后解密，同样是对密文验。
//
// 两个函数因此都以「本轮密钥材料由 KDF 现推」的形式给出，不缓存派生结果：密钥
// 随 nonce 每轮变化，缓存一个跨轮次的副本只会制造用错版本的机会。

/// 推导本轮参数加解密所需的密钥与初始向量。
///
/// 两枚 nonce 的先后决定了方向：命令方向本端 nonce 在前，响应方向对端 nonce 在
/// 前。两个方向的材料不同，这正是同一条会话上两个方向不会撞用同一段密钥流的
/// 原因。
pub fn cfb_material<H: HmacSha256Ctx>(
    session: &AuthSession,
    newer: &[u8; NONCE_LEN],
    older: &[u8; NONCE_LEN],
) -> (r: [u8; CFB_MATERIAL_LEN])
    requires
        session.wf(),
    ensures
        r@ =~= spec_kdfa32(session.key_material(), LABEL_CFB@, newer@, older@),
{
    let (kb, klen) = session.key_buf();
    let key = slice_subrange(array_as_slice(&kb), 0, klen);
    kdfa32::<H>(key, array_as_slice(&LABEL_CFB), array_as_slice(newer), array_as_slice(older))
}

/// 原地加密命令的首个参数。必须在 [`AuthSession::finalize`] 之前调用。
pub fn encrypt_parm<A: AesCfb>(aes: &A, material: &[u8; CFB_MATERIAL_LEN], parm: &mut [u8])
    ensures
        final(parm).len() == old(parm).len(),
        final(parm)@ =~= spec_aes_cfb(
            material@.subrange(0, AES_KEY_LEN as int),
            material@.subrange(AES_KEY_LEN as int, CFB_MATERIAL_LEN as int),
            old(parm)@,
            true,
        ),
{
    aes.encrypt(material, parm);
}

/// 原地解密响应的首个参数。必须在 [`AuthSession::check_response`] 返回 `Ok` 之后
/// 调用——对未经校验的字节做解密，等于把对端塞进来的任意数据当成明文交给上层。
pub fn decrypt_parm<A: AesCfb>(aes: &A, material: &[u8; CFB_MATERIAL_LEN], parm: &mut [u8])
    ensures
        final(parm).len() == old(parm).len(),
        final(parm)@ =~= spec_aes_cfb(
            material@.subrange(0, AES_KEY_LEN as int),
            material@.subrange(AES_KEY_LEN as int, CFB_MATERIAL_LEN as int),
            old(parm)@,
            false,
        ),
{
    aes.decrypt(material, parm);
}

} // verus!
