#[cfg(verus_keep_ghost)]
use crate::auth::{spec_auth_input, spec_rp_input};
#[cfg(verus_keep_ghost)]
use crate::crypto::{spec_hmac_sha256, spec_sha256};
use crate::{
    auth::{AuthErr, CMD_SESSION_LEN, MAX_SESSIONS, RspAuth, write_cmd_session},
    chip::MSG_MAX,
    compat::*,
    crypto::{HmacSha256Ctx, NonceSource, Sha256Ctx},
    msg::TPM_HEADER_LEN,
    phy::TisPhy,
    session::AuthSession,
    xfer::{RC_SUCCESS, Xfer, XferErr},
};

/// 一条带授权的命令在缓冲区里的分区。
///
/// 由调用方给出而不是由本层推算：分区取决于具体命令有几个句柄、参数怎么排，
/// 那是命令层的知识。本层只负责**核对这些分区互不冲突**，然后照着填。
pub struct CmdLayout {
    /// 命令总长度。必须与报文头里的长度字段一致，这一点由链路层复核。
    pub len: usize,
    /// 授权区起点。
    pub sess_off: usize,
    /// 本会话在授权区里的序号。
    pub index: usize,
    /// 参数区起点。
    pub parm_off: usize,
    /// 参数区长度。
    pub parm_len: usize,
    /// 响应里的句柄个数。摘要覆盖的是句柄之后的部分，数错一个，整段偏移全错。
    pub rhandles: usize,
}
impl CmdLayout {}
/// 一枚「这段响应的 MAC 已经对上」的凭证。
///
/// `seal` 是一个私有的零大小字段，作用只有一个：**本模块之外连构造这个类型
/// 都做不到**——不是难做，是语言层面不允许，任何结构体字面量都会因为够不着
/// 这个字段而被拒绝。凭证因此只能由 [`Guarded::invoke`] 在校验通过之后铸造，
/// 于是持有一枚凭证这件事本身就是校验发生过的证据。
///
/// 定位结果 `a` 反而可以公开：读几个偏移不构成任何能力，能力在于凭证本身。
/// 它也不怕被改——[`Guarded::parms`] 要求出示 [`Authenticated::certified`]，
/// 而那条性质是就 `a` 说的，改一个偏移就再也证不出来。
///
/// 其余字段是幽灵值，记下铸造时刻的密钥材料、命令码、本端 nonce 与属性。
/// 它们不参与运行时计算，只是让 [`Authenticated::certified`] 能把那条 MAC
/// 等式完整地写出来——凭证若说不清自己证的是什么，就退化成了一个标记。
pub struct Authenticated {
    pub a: RspAuth,
    /// 封印。本模块之外无法赋值，因而无法构造本类型。
    #[allow(dead_code)]
    seal: (),
}
impl Authenticated {}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecErr {
    /// 字节没能走完一个来回。
    Bus(XferErr),
    /// 器件返回了非零返回码。这类响应不带授权区，无从校验。
    Rc(u32),
    /// 响应到了，但授权校验没过。
    Auth(AuthErr),
}
pub struct Guarded<P: TisPhy> {
    pub x: Xfer<P>,
    pub sess: AuthSession,
    /// 响应暂存区。**私有**——本层的全部保证都建立在模块之外拿不到它之上。
    rbuf: [u8; MSG_MAX],
    /// 暂存区里有效字节数。公开无妨：长度不是能力，而改动它只会让
    /// [`Guarded::parms`] 的前置条件证不出来。
    pub rlen: usize,
}
impl<P: TisPhy> Guarded<P> {
    pub fn new(x: Xfer<P>, sess: AuthSession) -> Self {
        Guarded {
            x,
            sess,
            rbuf: [0u8; MSG_MAX],
            rlen: 0,
        }
    }
    /// 发一条带授权的命令，只有 MAC 对上才返回。
    ///
    /// 调用方需要事先把报文头、句柄区、参数区写好，并按 `lay` 留出授权区。
    /// 授权区由本函数填写——它含有本轮 nonce，而 nonce 要到换取那一刻才产生，
    /// 调用方提前填不了。
    ///
    /// 失败路径一律作废会话。会话失败之后拿同一把密钥重试，等于给对面多一次
    /// 猜测机会；作废之后要重新握手，代价是一次往返，换来的是猜测机会不累积。
    pub fn invoke<S: Sha256Ctx, H: HmacSha256Ctx, R: NonceSource>(
        &mut self,
        rng: &mut R,
        cmd: &mut [u8],
        lay: CmdLayout,
        names: &[u8],
        ordinal: u32,
        attrs: u8,
    ) -> Result<Authenticated, SecErr> {
        self.sess.begin(rng, ordinal, attrs);
        let handle = self.sess.handle;
        let nonce = self.sess.our_nonce;
        let sattrs = self.sess.attrs;
        write_cmd_session(cmd, lay.sess_off, handle, &nonce, sattrs);
        self.sess.finalize::<S, H>(
            cmd,
            lay.sess_off,
            lay.index,
            names,
            lay.parm_off,
            lay.parm_len,
        );
        let n = match self.x.run(&*cmd, lay.len, &mut self.rbuf) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    self.sess.close();
                    return Err(SecErr::Rc(rc));
                }
                n
            }
            Err(e) => {
                self.sess.close();
                return Err(SecErr::Bus(e));
            }
        };
        self.rlen = n;
        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let a = match self.sess.check_response::<S, H>(raw, lay.rhandles) {
            Ok(a) => a,
            Err(e) => return Err(SecErr::Auth(e)),
        };
        {}
        Ok(Authenticated { a, seal: () })
    }
    /// 取出响应的参数区。
    ///
    /// 这是响应字节离开本结构体的**唯一出口**。前置条件要出示一枚与当前
    /// 暂存区内容匹配的凭证：没有凭证拿不到字节，凭证过期也拿不到。
    pub fn parms<'a>(&'a self, t: &Authenticated) -> &'a [u8] {
        let off = t.a.parm_off;
        let len = t.a.parm_len;
        {}
        slice_subrange(array_as_slice(&self.rbuf), off, off + len)
    }
    /// 响应参数区的长度。凭证已经把它固定下来，读取前不必再解析一次报文。
    pub fn parm_len(&self, t: &Authenticated) -> usize {
        t.a.parm_len
    }
    /// 交回链路，结束授权阶段。
    ///
    /// 会话随 `self` 一起消失，这正是想要的：一个不再持有链路的会话，nonce
    /// 链条已经断了，留着只会让「拿旧会话继续说话」在类型上看起来可行。
    /// 响应暂存区一并释放，此前铸出的凭证也就再没有对应的报文可读——那些
    /// 凭证的前置条件要求报文与铸造时刻逐字节相同，而报文已经不在了。
    pub fn release(self) -> Xfer<P> {
        self.x
    }
}
