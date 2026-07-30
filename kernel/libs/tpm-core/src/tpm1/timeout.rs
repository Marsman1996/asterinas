use vstd::prelude::*;

verus! {

// ===========================================================================
// 超时与时长的单位修正
// ===========================================================================
//
// 器件报出的四档 TIS 超时与三档命令时长,单位应当是微秒。但有两类器件报错了:
// 一类某档报 0(根本没填),一类把毫秒当微秒报(数值小了三个数量级)。两类都
// 不能直接用——0 会让对应的等待预算变成「一次都不轮询就超时」,小三个数量级
// 会让正常执行被判超时。本模块在这两处做修正。
//
// 修正后的值最终要喂给按档取时长的映射,而那里要求时长恒为正(预算为零是配置
// 错误,不该表现为运行期偶发失败)。因此本模块的核心契约就一条:**只要默认值
// 与地板值为正,修正后的每一档都为正**。零回填在乘法之前就把值托到正数上,
// 乘法保正,契约随之成立。
//
// 单位一律微秒。jiffies 换算、厂商 override 回调都是宿主设施,不在这里——它们
// 一旦介入,本模块的输入就是它们的输出,契约不受影响。

/// 全 1 的 u32,做饱和上限用。写成 u64 常量,避免在乘法里现算。
const U32_MAX_U64: u64 = 0xFFFF_FFFF;

/// TIS 超时 A 档的合理量级在几十万微秒。报出的值虽非零却小于这个界,只可能是
/// 把毫秒当微秒写了——正常的微秒读数不会落到这么小。
pub const TIMEOUT_USEC_THRESHOLD: u32 = 1000;

// ===========================================================================
// 饱和乘 1000
// ===========================================================================

/// 乘 1000,溢出则钉在 u32 上限。
///
/// 用 u64 中转,乘法本身不可能溢出(u32 最大值乘 1000 仍远在 u64 之内),因此
/// 这是个全函数。两条后置条件:结果不小于输入(缩放只会放大),且输入为正则
/// 结果为正(乘法保正)——后者是上层「时长恒为正」契约的下半截。
pub fn sat_mul_1000(v: u32) -> (r: u32)
    ensures
        r >= v,
        v >= 1 ==> r >= 1,
{
    let w: u64 = (v as u64) * 1000;
    proof {
        // 乘一个 ≥ 1 的常数不会变小;显式给出,免得求解器在此卡壳。
        assert((v as u64) * 1000 >= v as u64) by (nonlinear_arith);
    }
    if w > U32_MAX_U64 {
        // 溢出 u32:钉在上限。极大的等待时长语义上无害,只是等得久。
        0xFFFF_FFFF
    } else {
        w as u32
    }
}

// ===========================================================================
// 四档超时
// ===========================================================================

/// 四档 TIS 超时(微秒)。
pub struct Timeouts {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

/// 修正器件报出的四档超时。
///
/// 两步:先把报 0 的档用驱动默认值回填(默认值恒正,回填后该档恒正);再看 A
/// 档是否落在毫秒误写微秒的区间,是则四档同乘 1000。乘法保正,故修正后四档
/// 恒正——这正是等待预算不为零的前提。
pub fn scale_timeouts(chip: Timeouts, defaults: Timeouts) -> (r: Timeouts)
    requires
        defaults.a >= 1,
        defaults.b >= 1,
        defaults.c >= 1,
        defaults.d >= 1,
    ensures
        r.a >= 1,
        r.b >= 1,
        r.c >= 1,
        r.d >= 1,
{
    // 零回填。器件报 0 说明它没填这一档,用驱动的默认值顶上。
    let mut a = if chip.a != 0 { chip.a } else { defaults.a };
    let mut b = if chip.b != 0 { chip.b } else { defaults.b };
    let mut c = if chip.c != 0 { chip.c } else { defaults.c };
    let mut d = if chip.d != 0 { chip.d } else { defaults.d };

    // 单位修正。判据只看 A 档:它的合理量级最稳定,拿它当四档共同的标尺。
    if a != 0 && a < TIMEOUT_USEC_THRESHOLD {
        a = sat_mul_1000(a);
        b = sat_mul_1000(b);
        c = sat_mul_1000(c);
        d = sat_mul_1000(d);
    }

    Timeouts { a, b, c, d }
}

// ===========================================================================
// 三档时长
// ===========================================================================

/// 三档命令时长(微秒)。
pub struct Durations {
    pub short: u32,
    pub medium: u32,
    pub long: u32,
}

/// 修正器件报出的三档时长。
///
/// 同样两步:报 0 的档用默认值回填;再看短档是否小得不合理(同样是毫秒误写
/// 微秒的征兆),是则把短档托到地板值、中长两档乘 1000。地板值与默认值都要求
/// 为正,故修正后三档恒正,可直接喂给按档取时长的映射。
///
/// 阈值与地板值由调用方给出:它们在 C 里是从 jiffies 常量推来的,换算属于宿主
/// 设施,不进本模块。
pub fn scale_durations(
    chip: Durations,
    defaults: Durations,
    short_threshold: u32,
    short_floor: u32,
) -> (r: Durations)
    requires
        defaults.short >= 1,
        defaults.medium >= 1,
        defaults.long >= 1,
        short_floor >= 1,
    ensures
        r.short >= 1,
        r.medium >= 1,
        r.long >= 1,
{
    let mut s = if chip.short != 0 { chip.short } else { defaults.short };
    let mut m = if chip.medium != 0 { chip.medium } else { defaults.medium };
    let mut l = if chip.long != 0 { chip.long } else { defaults.long };

    if s < short_threshold {
        // 短档小到不可信,整组按毫秒误写微秒处理:短档托到地板,中长各乘 1000。
        s = short_floor;
        m = sat_mul_1000(m);
        l = sat_mul_1000(l);
    }

    Durations { short: s, medium: m, long: l }
}

} // verus!
