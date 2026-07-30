use vstd::prelude::*;
use vstd::set::Set;

use crate::cmd::{CC_CONTEXT_LOAD, CC_CONTEXT_SAVE, CC_FLUSH_CONTEXT};
#[cfg(verus_keep_ghost)]
use crate::cursor::spec_be32_at;
#[cfg(verus_keep_ghost)]
use crate::endian::be32_of;
#[cfg(verus_keep_ghost)]
use crate::handle::valid_phandle;
use crate::module::{ContextIo, IoErr};
use crate::msg::{ST_NO_SESSIONS, build_header};
#[cfg(verus_keep_ghost)]
use crate::rewrite::be32_at;
use crate::rewrite::{HEADER_SIZE, read_be32, write_be32};

verus! {

// ---------------------------------------------------------------------------
// 返回码
// ---------------------------------------------------------------------------

pub const RC_SUCCESS: u32 = 0x0000_0000;

/// 位 7 置位表示「格式一」返回码：低 6 位是错误号，位 8..11 是出错的
/// 句柄 / 参数 / 会话序号。分类时必须先把序号位抹掉。
pub const RC_FMT1_BIT: u32 = 0x0000_0080;

pub const RC_HANDLE: u32 = 0x0000_008B;
pub const RC_INTEGRITY: u32 = 0x0000_009F;
pub const RC_CONTEXT_GAP: u32 = 0x0000_0901;
pub const RC_OBJECT_MEMORY: u32 = 0x0000_0902;
pub const RC_SESSION_MEMORY: u32 = 0x0000_0903;
pub const RC_MEMORY: u32 = 0x0000_0904;
pub const RC_REFERENCE_H0: u32 = 0x0000_0910;

/// 抹掉格式一返回码里的序号位，得到可比较的错误号。
pub open spec fn spec_rc_value(rc: u32) -> u32 {
    if rc & RC_FMT1_BIT == RC_FMT1_BIT {
        rc & 0xFFu32
    } else {
        rc
    }
}

pub fn rc_value(rc: u32) -> (r: u32)
    ensures
        r == spec_rc_value(rc),
{
    if rc & RC_FMT1_BIT == RC_FMT1_BIT {
        rc & 0xFFu32
    } else {
        rc
    }
}

/// 返回码 → 编排层错误。
///
/// 分类的语义边界只有一条要紧：什么算 [`IoErr::NotFound`]。它表示「目标
/// 已不存在」，编排层据此把对应槽位直接遗忘而不是让整条路径失败——所以
/// 这里只能放真正表示「引用了不存在的对象」的两个返回码，放宽会让状态
/// 不一致被静默吞掉。
pub fn classify_rc(rc: u32) -> (r: IoErr) {
    let v = rc_value(rc);
    if v == RC_HANDLE || v == RC_REFERENCE_H0 {
        IoErr::NotFound
    } else if v == RC_INTEGRITY {
        IoErr::Integrity
    } else if v == RC_CONTEXT_GAP || v == RC_OBJECT_MEMORY || v == RC_SESSION_MEMORY || v
        == RC_MEMORY {
        IoErr::NoSpace
    } else {
        IoErr::Fatal
    }
}

// ---------------------------------------------------------------------------
// 备份块布局
// ---------------------------------------------------------------------------

/// 备份块的定长前缀：序号 8 字节、句柄 4 字节、层级 4 字节、数据长度 2 字节。
pub const CTX_FIXED: usize = 18;

/// 数据长度字段在备份块内的偏移。
pub const CTX_SIZE_OFF: usize = 16;

/// 备份缓冲区中从 `off` 开始的那一块占多少字节。
pub open spec fn spec_ctx_len(s: Seq<u8>, off: int) -> int {
    CTX_FIXED + (s[off + CTX_SIZE_OFF] as int) * 256 + (s[off + CTX_SIZE_OFF + 1] as int)
}

// ---------------------------------------------------------------------------
// 字节序两种写法的桥
// ---------------------------------------------------------------------------

/// `endian` 用移位或、`cursor` 用乘加，两者是同一个函数的两种写法。
///
/// 报文头由 `build_header` 生成（规约用乘加形式），而句柄区由
/// `rewrite::read_be32` 读取（规约用移位或形式），跨模块推理时必须先过
/// 这条引理。**这是重复定义的代价**，合并规约之后它就可以删掉。
pub proof fn lemma_be32_forms_agree(s: Seq<u8>, off: int)
    requires
        0 <= off,
        off + 4 <= s.len(),
    ensures
        be32_at(s, off) == spec_be32_at(s, off),
{
    let b0 = s[off];
    let b1 = s[off + 1];
    let b2 = s[off + 2];
    let b3 = s[off + 3];
    assert(be32_of(b0, b1, b2, b3) == (b0 as u32) * 16777216 + (b1 as u32) * 65536 + (b2 as u32)
        * 256 + (b3 as u32)) by (bit_vector);
}

// ---------------------------------------------------------------------------
// 芯片接触面（信任基）
// ---------------------------------------------------------------------------

/// 一次完整的命令 / 响应往返。
///
/// 这是本层与芯片之间唯一的接触点。实现方要么把假设直接摆在自己的
/// `external_body` 里，要么像链路层那样把假设收进一个零大小的幽灵账本；
/// 无论哪种，下面写下的后置条件都是本模块**据以推理的全部依据**。它们按命令
/// 码分情况给出，而不是笼统地断言「句柄是新的」——这样每条假设都能指到具体
/// 的规范条款上。
///
/// TRUST 1：响应写入不越过 `rsp` 容量，且至少包含一个完整报文头。
/// 依据：传输层按声明长度收字节，不足即报错。
///
/// TRUST 2：ContextLoad 成功时返回的句柄不在 `live()` 中。
/// 依据：句柄在被显式释放或换出之前唯一标识一个已装载对象，芯片不会把
/// 一个仍然有效的句柄再次分配出去。**这是本模块单射性的最终来源**，
/// 也是整个 TCB 里最实质的一条。
///
/// TRUST 3：`live()` 只随 ContextLoad 成功而增长、随 FlushContext 而收缩，
/// 其余命令不改变它。
///
/// 关于释放命令的那条例外：它**不以传输成功为条件**。传输失败时本端无从得知
/// 芯片是否已经释放，与其两边都不确定，不如统一按「本端不再追踪」处理——芯片
/// 若确实没释放，那份资源会占到复位为止，这是已知且无从补救的泄漏。因此
/// 「失败即无副作用」那条必须把释放命令排除在外，否则两条同时要求
/// `live == old` 与 `live == old.remove(h)`，只有 `h` 本就不在集合里时才能
/// 同时满足，实现方一个也做不出来。
pub trait ChipTransport {
    /// 芯片当前持有的句柄集合。纯幽灵状态，无运行时开销。
    spec fn live(&self) -> Set<u32>;

    fn exec(&mut self, cmd: &[u8], rsp: &mut [u8]) -> (r: Result<usize, IoErr>)
        requires
            cmd.len() >= HEADER_SIZE + 4,
            old(rsp).len() >= HEADER_SIZE + 4,
        ensures
            final(rsp).len() == old(rsp).len(),
            r.is_ok() ==> HEADER_SIZE <= r.unwrap() <= final(rsp).len(),
            // 传输失败：无副作用。释放命令除外，见上面的说明。
            (r.is_err() && be32_at(cmd@, 6) != CC_FLUSH_CONTEXT) ==> final(self).live() == old(
                self,
            ).live(),
            // ContextLoad 成功且返回码为零
            (r.is_ok() && be32_at(cmd@, 6) == CC_CONTEXT_LOAD && be32_at(final(rsp)@, 6)
                == RC_SUCCESS) ==> {
                &&& r.unwrap() >= HEADER_SIZE + 4
                &&& valid_phandle(be32_at(final(rsp)@, HEADER_SIZE as int))
                &&& !old(self).live().contains(be32_at(final(rsp)@, HEADER_SIZE as int))
                &&& final(self).live() == old(self).live().insert(
                    be32_at(final(rsp)@, HEADER_SIZE as int),
                )
            },
            // ContextLoad 未成功
            (be32_at(cmd@, 6) == CC_CONTEXT_LOAD && (r.is_err() || be32_at(final(rsp)@, 6)
                != RC_SUCCESS)) ==> final(self).live() == old(self).live(),
            // FlushContext：无论传输层是否报错，该句柄都不再被追踪
            be32_at(cmd@, 6) == CC_FLUSH_CONTEXT ==> final(self).live() == old(self).live().remove(
                be32_at(cmd@, HEADER_SIZE as int),
            ),
            // 其余命令
            (be32_at(cmd@, 6) != CC_CONTEXT_LOAD && be32_at(cmd@, 6) != CC_FLUSH_CONTEXT)
                ==> final(self).live() == old(self).live(),
    ;
}

// ---------------------------------------------------------------------------
// 适配器
// ---------------------------------------------------------------------------

/// 命令与响应暂存区的容量。上下文数据块可以接近一页，两个缓冲区
/// 内联在结构体里共 8 KiB；若目标平台栈紧张，把它们换成调用方提供的
/// 切片即可，本模块的证明不依赖它们的存储方式。
pub const MSG_MAX: usize = 4096;

/// 把 [`ChipTransport`] 抬成编排层要的 [`ContextIo`]。
///
/// 这一层是完全验证的：它做的全部事情是长度校验、报文组装、返回码分类。
/// 幽灵集合直接透传给传输层，本层不引入任何新的假设——这一点要靠三个方法
/// 都没有 `external_body` 来保证，一旦有一个被标上，上面那句话就不再成立，
/// 而编排层的单射性正是建立在这句话之上。
pub struct CtxIo<T: ChipTransport> {
    tx: T,
    cbuf: [u8; MSG_MAX],
    rbuf: [u8; MSG_MAX],
}

impl<T: ChipTransport> CtxIo<T> {
    pub fn new(tx: T) -> (r: Self)
        ensures
            r.tx_live() == tx.live(),
    {
        CtxIo { tx, cbuf: [0u8; MSG_MAX], rbuf: [0u8; MSG_MAX] }
    }

    pub closed spec fn tx_live(&self) -> Set<u32> {
        self.tx.live()
    }

    /// 把 10 字节报文头落到命令缓冲区开头。
    ///
    /// 后置条件里那句「幽灵集合不变」不是形式主义：组装报文与芯片状态无关，
    /// 把这一点写下来，后面每个方法才能把「进入函数时的集合」一路带到发送
    /// 那一刻，而不必在中途重新为它找依据。
    fn put_header(&mut self, code: u32, total: usize)
        requires
            total <= MSG_MAX,
        ensures
            final(self).cbuf@.len() == MSG_MAX,
            be32_at(final(self).cbuf@, 6) == code,
            final(self).tx_live() == old(self).tx_live(),
    {
        let hdr = build_header(ST_NO_SESSIONS, code, total as u32);
        let mut k: usize = 0;
        while k < HEADER_SIZE
            invariant
                k <= HEADER_SIZE,
                self.cbuf@.len() == MSG_MAX,
                self.tx_live() == old(self).tx_live(),
                forall|j: int| #![trigger self.cbuf@[j]] 0 <= j < k ==> self.cbuf@[j] == hdr@[j],
            decreases HEADER_SIZE - k,
        {
            self.cbuf[k] = hdr[k];
            k += 1;
        }
        proof {
            lemma_be32_forms_agree(self.cbuf@, 6);
            assert(self.cbuf@.subrange(0, HEADER_SIZE as int) =~= hdr@);
        }
    }
    /// 交回底层传输，结束上下文往返阶段。
    ///
    /// 取走 `self`，两块暂存区随之释放，幽灵集合原样落到返回值上。后置条件
    /// 里那句相等是阶段移交的依据：适配器代管期间对芯片做过什么，交回去的
    /// 传输层照单全收，不重算也不清零。
    pub fn release(self) -> (r: T)
        ensures
            r.live() == self.tx_live(),
    {
        self.tx
    }
}

impl<T: ChipTransport> ContextIo for CtxIo<T> {
    open spec fn outstanding(&self) -> Set<u32> {
        self.tx_live()
    }

    fn load(&mut self, blob: &[u8], off: usize) -> (r: Result<(u32, usize), IoErr>) {
        let ghost live0 = self.tx_live();

        // ---- 长度校验：先定长前缀，再变长数据 ----
        if off > blob.len() || blob.len() - off < CTX_FIXED {
            return Err(IoErr::Integrity);
        }
        let size = (blob[off + CTX_SIZE_OFF] as usize) * 256 + (blob[off + CTX_SIZE_OFF + 1]
            as usize);
        let used = CTX_FIXED + size;
        if blob.len() - off < used {
            return Err(IoErr::Integrity);
        }
        if MSG_MAX - HEADER_SIZE < used {
            return Err(IoErr::NoSpace);
        }

        // ---- 组装：头部 + 原样搬运备份块 ----
        self.put_header(CC_CONTEXT_LOAD, HEADER_SIZE + used);
        let mut k: usize = 0;
        while k < used
            invariant
                k <= used,
                off + used <= blob.len(),
                HEADER_SIZE + used <= MSG_MAX,
                self.cbuf@.len() == MSG_MAX,
                be32_at(self.cbuf@, 6) == CC_CONTEXT_LOAD,
                self.tx_live() == live0,
            decreases used - k,
        {
            self.cbuf[HEADER_SIZE + k] = blob[off + k];
            k += 1;
        }

        // ---- 往返 ----
        //
        // 命令码此刻必须仍是装载：接触面的后置条件按命令码分情况给出，命令码
        // 对不上，那些条件一条也用不上。搬运循环写的是报文头之后的区域，头部
        // 四个字节没被碰过，这一点由循环不变量一路带到这里。
        proof {
            assert(be32_at(self.cbuf@, 6) == CC_CONTEXT_LOAD);
        }
        let _n = match self.tx.exec(&self.cbuf, &mut self.rbuf) {
            Ok(n) => n,
            Err(e) => {
                return Err(e);
            },
        };
        let rc = read_be32(&self.rbuf, 6);
        if rc != RC_SUCCESS {
            return Err(classify_rc(rc));
        }
        let h = read_be32(&self.rbuf, HEADER_SIZE);
        Ok((h, used))
    }

    fn save(&mut self, h: u32, out: &mut [u8], off: usize) -> (r: Result<usize, IoErr>) {
        let ghost live0 = self.tx_live();
        let out_len = out.len();

        self.put_header(CC_CONTEXT_SAVE, HEADER_SIZE + 4);
        write_be32_arr(&mut self.cbuf, HEADER_SIZE, h);
        // 句柄写在报文头之后，头部四个字节不在写入区间内。
        proof {
            assert(be32_at(self.cbuf@, 6) == CC_CONTEXT_SAVE);
        }

        let n = match self.tx.exec(&self.cbuf, &mut self.rbuf) {
            Ok(n) => n,
            Err(e) => {
                return Err(e);
            },
        };
        let rc = read_be32(&self.rbuf, 6);
        if rc != RC_SUCCESS {
            return Err(classify_rc(rc));
        }

        // 响应体即备份块本身，原样落到备份缓冲区。
        let body = n - HEADER_SIZE;
        if off > out.len() || out.len() - off < body {
            return Err(IoErr::NoSpace);
        }
        let mut k: usize = 0;
        while k < body
            invariant
                k <= body,
                out.len() == out_len,
                off + body <= out.len(),
                HEADER_SIZE + body <= self.rbuf@.len(),
                self.tx_live() == live0,
            decreases body - k,
        {
            out[off + k] = self.rbuf[HEADER_SIZE + k];
            k += 1;
        }
        assert(out.len() == out_len);
        Ok(body)
    }

    fn flush(&mut self, h: u32) {
        let ghost live0 = self.tx_live();

        self.put_header(CC_FLUSH_CONTEXT, HEADER_SIZE + 4);
        write_be32_arr(&mut self.cbuf, HEADER_SIZE, h);
        proof {
            assert(be32_at(self.cbuf@, 6) == CC_FLUSH_CONTEXT);
            assert(be32_at(self.cbuf@, HEADER_SIZE as int) == h);
        }

        // 返回值刻意丢弃：释放失败无从补救，且调用点全在错误处理路径上。
        // 幽灵集合的收缩不依赖这个返回值——接触面对释放命令的规约本就不以
        // 传输成功为条件。
        let _ = self.tx.exec(&self.cbuf, &mut self.rbuf);
    }
}

/// [`write_be32`] 的定长数组版本。切片版要求 `&mut [u8]`，而这里操作的是
/// 结构体里的数组字段，重借用会让 Verus 多出一层义务，直接写更省事。
fn write_be32_arr(b: &mut [u8; MSG_MAX], off: usize, v: u32)
    requires
        off + 4 <= MSG_MAX,
    ensures
        be32_at(final(b)@, off as int) == v,
        forall|k: int|
            #![trigger final(b)@[k]]
            0 <= k < MSG_MAX && (k < off || k >= off + 4) ==> final(b)@[k] == old(b)@[k],
{
    proof {
        crate::endian::lemma_be32_roundtrip(v);
    }
    b[off] = ((v >> 24) & 0xff) as u8;
    b[off + 1] = ((v >> 16) & 0xff) as u8;
    b[off + 2] = ((v >> 8) & 0xff) as u8;
    b[off + 3] = (v & 0xff) as u8;
}

} // verus!