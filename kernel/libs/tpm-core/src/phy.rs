use vstd::prelude::*;

use crate::tis::TisErr;

verus! {

// ===========================================================================
// 物理层：信任基
// ===========================================================================
//
// 这是本驱动与硬件之间唯一的接触面。所有实现（内存映射、SPI、I2C）都以
// `#[verifier::external_body]` 提供，因此**下面写下的每一条后置条件都是假设，
// 不是定理**。它们应当逐条对照接口规范核对，而不是对照某个已有实现反推。
//
// 做成泛型参数而不是回调结构：验证器不支持 trait object，且单态化之后每个后
// 端的规约各自独立，一个后端的假设不会悄悄地被另一个后端继承。
//
// 寄存器读写与数据口读写分成两组方法，是因为二者的**副作用性质完全不同**：
// 前者是幂等的取值，后者会推进器件内部的传输状态。混用一组方法会让「写进去
// 了多少字节」这件事无法在规约里表达。

pub trait TisPhy {
    /// 自上次数据口复位以来，写进数据口的字节序列。
    ///
    /// 只在证明里出现，运行时不占空间。它的唯一用途是让「发送写入的字节恰好
    /// 是命令本身，不多不少」成为一条可以写出来的性质——没有这个累积量，发送
    /// 路径就只能声称自己返回了成功，而说不出到底往总线上放了什么。
    spec fn fifo_written(&self) -> Seq<u8>;

    // -----------------------------------------------------------------------
    // 寄存器
    // -----------------------------------------------------------------------

    fn read8(&mut self, addr: u32) -> (r: Result<u8, TisErr>)
        ensures
            final(self).fifo_written() =~= old(self).fifo_written(),
    ;

    fn read32(&mut self, addr: u32) -> (r: Result<u32, TisErr>)
        ensures
            final(self).fifo_written() =~= old(self).fifo_written(),
    ;

    fn write8(&mut self, addr: u32, value: u8) -> (r: Result<(), TisErr>)
        ensures
            final(self).fifo_written() =~= old(self).fifo_written(),
    ;

    fn write32(&mut self, addr: u32, value: u32) -> (r: Result<(), TisErr>)
        ensures
            final(self).fifo_written() =~= old(self).fifo_written(),
    ;

    // -----------------------------------------------------------------------
    // 数据口
    // -----------------------------------------------------------------------

    /// 从数据口取 `n` 字节，落到 `out[off..off + n]`。
    ///
    /// 取到的内容是器件给的，规约里说不出它是什么，只能保证**落点正确**：
    /// 区间之外一字未动，缓冲区长度不变。防越界的责任因此完全落在调用方给出
    /// 的 `off + n <= out.len()` 上，而这一条由类型检查强制。
    fn read_fifo(&mut self, addr: u32, out: &mut [u8], off: usize, n: usize) -> (r: Result<
        (),
        TisErr,
    >)
        requires
            off + n <= old(out).len(),
        ensures
            final(out).len() == old(out).len(),
            final(self).fifo_written() =~= old(self).fifo_written(),
            forall|k: int|
                #![trigger final(out)@[k]]
                0 <= k < final(out).len() && (k < off || k >= off + n) ==> final(out)@[k]
                    == old(out)@[k],
    ;

    /// 把 `data[off..off + n]` 写进数据口。
    ///
    /// 失败时器件可能已经吃进了一段前缀——总线传输不是原子的。规约如实写成
    /// 「累积量只增不减」而不是「原封不动」：后者是假的，写成假的会让基于它的
    /// 推理全部无效。调用方在任何失败路径上都必须复位数据口，复位之后这点不
    /// 精确就无关紧要了。
    fn write_fifo(&mut self, addr: u32, data: &[u8], off: usize, n: usize) -> (r: Result<
        (),
        TisErr,
    >)
        requires
            off + n <= data.len(),
        ensures
            r is Ok ==> final(self).fifo_written() =~= old(self).fifo_written() + data@.subrange(
                off as int,
                off + n,
            ),
            r is Err ==> old(self).fifo_written().is_prefix_of(final(self).fifo_written()),
    ;

    /// 中止当前命令并清空数据口。
    ///
    /// 对应写入「命令就绪」位。它既是发送前的准备动作，也是所有错误路径的收尾
    /// 动作——半条命令留在器件里，比什么都没写更危险。
    ///
    /// 没有返回值：复位失败无从补救，而调用点全在错误处理路径上，多一个要处理
    /// 的错误只会让那些路径更容易写漏。
    fn reset_fifo(&mut self, addr: u32)
        ensures
            final(self).fifo_written() =~= Seq::<u8>::empty(),
    ;

    // -----------------------------------------------------------------------
    // 节流
    // -----------------------------------------------------------------------

    /// 两次轮询之间的等待。
    ///
    /// 时长由实现决定，规约里不出现——本层的超时是用轮询次数表达的，等待多久
    /// 只影响真实耗时，不影响任何一条被证明的性质。
    fn delay(&mut self)
        ensures
            final(self).fifo_written() =~= old(self).fifo_written(),
    ;
}

} // verus!
