use vstd::prelude::*;

use crate::cmd::{CAP_TPM_PROPERTIES, CC_GET_CAPABILITY};
use crate::cursor::be32_bytes;
use crate::msg::{build_header, ST_NO_SESSIONS, TPM_HEADER_LEN};
use crate::phy::TisPhy;
use crate::xfer::Xfer;

verus! {

// ===========================================================================
// 家族探测
// ===========================================================================
//
// 器件是走 1.2 还是 2.0,靠一条命令问出来:发一个 **2.0 帧**的能力查询,然后只
// 看响应头的标签。2.0 器件认得这个标签、用同一套标签答回;1.2 器件不认,答一个
// 别的标签。返回码被有意忽略——器件喜不喜欢这条命令无所谓,重要的是它用哪套
// 标签回话。
//
// 这一层跨在两个家族的协议规则之上,是内核胶水(圈层 C):它不进证明主体,只用
// `external_body` 声明签名,把整段判定当作可信实现。判定本身不改变任何被证明的
// 性质——它只决定接下来把链路交给哪条引导序列。

/// 器件家族。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// 1.2:走 `tpm1` 路径。
    OneTwo,
    /// 2.0:走根部的会话/授权路径。
    TwoZero,
}

/// 探测用的属性子项:器件实现的命令总数。取哪一项无所谓——探测只看响应标签,
/// 不看载荷。
const PT_TOTAL_COMMANDS: u32 = 0x0000_0129;

/// 探测命令总长:头 10 + 三个 u32 载荷。
const PROBE_LEN: usize = TPM_HEADER_LEN + 12;

/// 探测响应暂存区。只读它的前两个字节(标签),给足头部余量即可。
const PROBE_RSP: usize = 64;

/// 判定器件家族。
///
/// 借用链路发一条命令即返回,链路仍归调用方所有,供随后的引导序列接管。链路
/// 若不处于可发命令的状态,保守判为 1.2——即不启用 2.0 专属路径,宁可少认能力
/// 也不误把一个没准备好的器件当成 2.0 去跑授权握手。
#[verifier::external_body]
pub fn probe_family<P: TisPhy>(x: &mut Xfer<P>) -> Family {
    if !x.ready() {
        return Family::OneTwo;
    }

    // 2.0 帧:标签 ST_NO_SESSIONS,命令码 GetCapability。
    let hdr = build_header(ST_NO_SESSIONS, CC_GET_CAPABILITY, PROBE_LEN as u32);
    let a = be32_bytes(CAP_TPM_PROPERTIES);
    let b = be32_bytes(PT_TOTAL_COMMANDS);
    let c = be32_bytes(1);

    let mut cmd = [0u8; PROBE_LEN];
    let mut i = 0;
    while i < TPM_HEADER_LEN {
        cmd[i] = hdr[i];
        i += 1;
    }
    cmd[TPM_HEADER_LEN] = a[0];
    cmd[TPM_HEADER_LEN + 1] = a[1];
    cmd[TPM_HEADER_LEN + 2] = a[2];
    cmd[TPM_HEADER_LEN + 3] = a[3];
    cmd[TPM_HEADER_LEN + 4] = b[0];
    cmd[TPM_HEADER_LEN + 5] = b[1];
    cmd[TPM_HEADER_LEN + 6] = b[2];
    cmd[TPM_HEADER_LEN + 7] = b[3];
    cmd[TPM_HEADER_LEN + 8] = c[0];
    cmd[TPM_HEADER_LEN + 9] = c[1];
    cmd[TPM_HEADER_LEN + 10] = c[2];
    cmd[TPM_HEADER_LEN + 11] = c[3];

    let mut rsp = [0u8; PROBE_RSP];
    match x.run(&cmd, PROBE_LEN, &mut rsp) {
        Ok((_n, _rc)) => {
            // 只看标签,返回码忽略。
            let tag = (rsp[0] as u16) * 256 + (rsp[1] as u16);
            if tag == ST_NO_SESSIONS {
                Family::TwoZero
            } else {
                Family::OneTwo
            }
        },
        // 一个字节都没回来:保守判为 1.2。
        Err(_) => Family::OneTwo,
    }
}

} // verus!
