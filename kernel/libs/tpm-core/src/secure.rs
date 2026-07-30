use vstd::prelude::*;
use vstd::array::*;
use vstd::slice::*;

use crate::auth::{
    AuthErr, CMD_SESSION_LEN, MAX_SESSIONS, RspAuth, write_cmd_session,
};
#[cfg(verus_keep_ghost)]
use crate::auth::{spec_auth_input, spec_rp_input};
use crate::chip::MSG_MAX;
use crate::crypto::{HmacSha256Ctx, NonceSource, Sha256Ctx};
#[cfg(verus_keep_ghost)]
use crate::crypto::{spec_hmac_sha256, spec_sha256};
use crate::msg::TPM_HEADER_LEN;
use crate::phy::TisPhy;
use crate::session::AuthSession;
use crate::xfer::{RC_SUCCESS, Xfer, XferErr};

verus! {

// ===========================================================================
// 本层要挡住的是什么
// ===========================================================================
//
// 会话层已经能证明「MAC 对上了」，但那只是**提供**了一个校验函数。校验函数
// 存在，不等于响应一定经过它——调用方完全可以发一条命令、拿到字节、直接解析，
// 一路上没有任何东西提醒他漏了一步。会话层最有价值的那条性质因此停留在「可以
// 成立」，而不是「必然成立」。
//
// 本层把它变成后者，靠的不是文档也不是断言，而是**可见性**：
//
// - 响应缓冲区是本结构体的私有字段，模块之外拿不到它的引用；
// - 读取响应参数的唯一函数要求出示一枚 [`Authenticated`]；
// - [`Authenticated`] 含私有字段，本模块之外无法构造，而本模块只在 MAC 校验
//   通过之后才铸造它。
//
// 三条合起来，「未经校验的响应字节」在类型层面不可达。这不是一条需要证明的
// 定理，是一条不需要证明的事实——它由 Rust 的可见性规则给出，验证器甚至不必
// 参与。会绕过它的写法压根编译不过。

// ===========================================================================
// 命令布局
// ===========================================================================

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

impl CmdLayout {
    /// `cap` 是命令缓冲区容量。
    ///
    /// 「授权区整体位于参数区之前」这一条是报文格式本身规定的顺序，写进这里
    /// 有一个额外的好处：它同时保证了填写授权区的动作不会碰到参数区，于是
    /// 「摘要覆盖的参数就是调用方写下的参数」不需要另外论证。
    pub open spec fn wf(self, cap: int) -> bool {
        &&& TPM_HEADER_LEN <= self.sess_off
        &&& self.sess_off + CMD_SESSION_LEN <= self.parm_off
        &&& self.parm_off + self.parm_len <= self.len
        &&& TPM_HEADER_LEN <= self.len
        &&& self.len <= cap
        &&& self.index < MAX_SESSIONS
        &&& self.rhandles <= 1
    }
}

// ===========================================================================
// 凭证
// ===========================================================================

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
    pub raw: Ghost<Seq<u8>>,
    pub key: Ghost<Seq<u8>>,
    pub ordinal: Ghost<u32>,
    pub our_nonce: Ghost<Seq<u8>>,
    pub attrs: Ghost<u8>,
    /// 封印。本模块之外无法赋值，因而无法构造本类型。
    #[allow(dead_code)]
    seal: (),
}

impl Authenticated {
    pub closed spec fn view(self) -> RspAuth {
        self.a
    }

    pub closed spec fn raw(self) -> Seq<u8> {
        self.raw@
    }

    pub closed spec fn key_material(self) -> Seq<u8> {
        self.key@
    }

    pub closed spec fn ordinal(self) -> u32 {
        self.ordinal@
    }

    pub closed spec fn our_nonce(self) -> Seq<u8> {
        self.our_nonce@
    }

    pub closed spec fn attrs(self) -> u8 {
        self.attrs@
    }

    /// 凭证所断言的全部内容：报文分区自洽，且报文里那段 MAC 等于用记下的
    /// 密钥材料、两枚 nonce、命令码重算出来的值。
    ///
    /// 命令码来自本端记录而非报文——响应报文不携带命令码。这正是「把甲命令的
    /// 响应挪给乙命令」在摘要层面就对不上的原因。
    pub closed spec fn certified(self) -> bool {
        &&& self.view().wf(self.raw())
        &&& self.view().mac(self.raw()) =~= spec_hmac_sha256(
            self.key_material(),
            spec_auth_input(
                spec_sha256(spec_rp_input(0, self.ordinal(), self.view().parms(self.raw()))),
                self.view().tpm_nonce@,
                self.our_nonce(),
                self.attrs(),
            ),
        )
    }
}

// ===========================================================================
// 错误
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
pub enum SecErr {
    /// 字节没能走完一个来回。
    Bus(XferErr),
    /// 器件返回了非零返回码。这类响应不带授权区，无从校验。
    Rc(u32),
    /// 响应到了，但授权校验没过。
    Auth(AuthErr),
}

// ===========================================================================
// 受保护的往返
// ===========================================================================

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
    pub closed spec fn xfer(&self) -> Xfer<P> {
        self.x
    }

    pub closed spec fn session(&self) -> AuthSession {
        self.sess
    }

    pub closed spec fn rsp_len(&self) -> usize {
        self.rlen
    }

    pub closed spec fn idle(&self) -> bool {
        self.xfer().idle()
    }

    pub closed spec fn usable(&self) -> bool {
        self.session().usable()
    }

    pub closed spec fn nonce_gen(&self) -> nat {
        self.session().nonce_gen@
    }

    pub closed spec fn session_key_material(&self) -> Seq<u8> {
        self.session().key_material()
    }

    pub closed spec fn wf(&self) -> bool {
        &&& self.x.wf()
        &&& self.sess.wf()
        &&& self.rlen <= MSG_MAX
    }

    /// 最近一次响应的有效字节。
    ///
    /// 只在规约里出现。凭证记下了铸造时刻的这段序列，读取参数时要求两者相等，
    /// 于是「拿旧凭证去读新响应」这种用法在前置条件那一步就被挡住了——不需要
    /// 版本号，也不需要运行时检查。
    pub closed spec fn rsp_view(&self) -> Seq<u8> {
        self.rbuf@.subrange(0, self.rlen as int)
    }

    pub fn new(x: Xfer<P>, sess: AuthSession) -> (r: Self)
        ensures
            r.xfer() == x,
            r.session() == sess,
            r.rsp_len() == 0,
            r.rsp_view() =~= Seq::<u8>::empty(),
    {
        Guarded { x, sess, rbuf: [0u8; MSG_MAX], rlen: 0 }
    }

    // =======================================================================
    // 唯一入口
    // =======================================================================

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
    ) -> (r: Result<Authenticated, SecErr>)
        requires
            old(self).wf(),
            old(self).idle(),
            old(self).usable(),
            old(self).nonce_gen() < old(rng).draws(),
            lay.wf(old(cmd).len() as int),
        ensures
            final(self).wf(),
            final(self).idle(),
            final(cmd).len() == old(cmd).len(),
            r matches Ok(t) ==> {
                // ★ 凭证只可能在校验通过之后铸造，因此这一条等价于
                //   「本函数返回 Ok 当且仅当响应经过了 MAC 校验」
                &&& t.certified()
                &&& t.raw() =~= final(self).rsp_view()
                &&& t.key_material() =~= old(self).session_key_material()
                &&& t.ordinal() == ordinal
                &&& final(self).usable()
            },
    {
        let ghost key0 = self.sess.key_material();

        // ---- 1. 换 nonce，锁定本轮命令码与属性 ----
        self.sess.begin(rng, ordinal, attrs);
        let ghost nonce0 = self.sess.our_nonce@;
        let ghost attrs0 = self.sess.attrs;

        // ---- 2. 填授权区骨架：句柄、本轮 nonce、属性，MAC 字段留空 ----
        let handle = self.sess.handle;
        let nonce = self.sess.our_nonce;
        let sattrs = self.sess.attrs;
        write_cmd_session(cmd, lay.sess_off, handle, &nonce, sattrs);

        // ---- 3. 定型：算 MAC 填进去 ----
        //
        // 必须在参数写完之后、发送之前，且中间不能再动报文一个字节。授权区
        // 整体位于参数区之前，上一步的写入落不到参数区里——这一点由布局的
        // 格式良好性给出，不必逐字节论证。
        self.sess.finalize::<S, H>(
            cmd,
            lay.sess_off,
            lay.index,
            names,
            lay.parm_off,
            lay.parm_len,
        );

        // ---- 4. 往返 ----
        let n = match self.x.run(&*cmd, lay.len, &mut self.rbuf) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    // 非零返回码的响应不带授权区，没有可校验的东西。它也不该
                    // 被当作「校验失败」——那两件事对调用方的意义完全不同。
                    self.sess.close();
                    return Err(SecErr::Rc(rc));
                }
                n
            },
            Err(e) => {
                self.sess.close();
                return Err(SecErr::Bus(e));
            },
        };
        self.rlen = n;

        // ---- 5. 校验 ----
        //
        // 报文按自述长度截断后交给校验：授权区的自洽性判断以「MAC 一直顶到
        // 报文末尾」为准，多带一个字节的暂存区尾巴就会让这条判断落空。
        let raw = slice_subrange(array_as_slice(&self.rbuf), 0, n);
        let a = match self.sess.check_response::<S, H>(raw, lay.rhandles) {
            Ok(a) => a,
            Err(e) => return Err(SecErr::Auth(e)),
        };

        proof {
            assert(raw@ =~= self.rsp_view());
        }

        Ok(
            Authenticated {
                a,
                raw: Ghost(raw@),
                key: Ghost(key0),
                ordinal: Ghost(ordinal),
                our_nonce: Ghost(nonce0),
                attrs: Ghost(attrs0),
                seal: (),
            },
        )
    }

    // =======================================================================
    // 取用响应
    // =======================================================================

    /// 取出响应的参数区。
    ///
    /// 这是响应字节离开本结构体的**唯一出口**。前置条件要出示一枚与当前
    /// 暂存区内容匹配的凭证：没有凭证拿不到字节，凭证过期也拿不到。
    pub fn parms<'a>(&'a self, t: &Authenticated) -> (r: &'a [u8])
        requires
            self.wf(),
            t.certified(),
            t.raw() =~= self.rsp_view(),
        ensures
            r@ =~= t.view().parms(t.raw()),
    {
        let off = t.a.parm_off;
        let len = t.a.parm_len;

        proof {
            // 分区自洽给出参数区落在有效字节之内，于是在整块暂存区上取同一段
            // 与在有效字节上取同一段是同一件事。
            assert(off + len <= self.rlen);
            assert(self.rbuf@.subrange(off as int, off + len) =~= t.raw().subrange(
                off as int,
                off + len,
            ));
        }

        slice_subrange(array_as_slice(&self.rbuf), off, off + len)
    }

    /// 响应参数区的长度。凭证已经把它固定下来，读取前不必再解析一次报文。
    pub fn parm_len(&self, t: &Authenticated) -> (r: usize)
        ensures
            r == t.view().parm_len,
    {
        t.a.parm_len
    }

    /// 交回链路，结束授权阶段。
    ///
    /// 会话随 `self` 一起消失，这正是想要的：一个不再持有链路的会话，nonce
    /// 链条已经断了，留着只会让「拿旧会话继续说话」在类型上看起来可行。
    /// 响应暂存区一并释放，此前铸出的凭证也就再没有对应的报文可读——那些
    /// 凭证的前置条件要求报文与铸造时刻逐字节相同，而报文已经不在了。
    pub fn release(self) -> (r: Xfer<P>)
        ensures
            r == self.xfer(),
    {
        self.x
    }
}

} // verus!