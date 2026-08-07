use core::ops::Range;

use ostd::mm::Paddr;
use spin::Mutex;
use tpm_core::chip::CtxIo;
use tpm_core::{
    BootErr, ChipLink, Limits, Tis, Xfer, bring_up, cmd::SU_CLEAR, module::IoErr, tis::TisErr,
};

use crate::extcrypto::check_abi;
use crate::mmio::TisMmio;
use crate::space_io::{CcAttrs, CcTable};

pub const TPM_TIS_BASE: Paddr = 0xFED4_0000;
pub const TPM_TIS_SIZE: usize = 0x5000;
const POLL_SPIN: u32 = 1000;

pub enum TpmInitErr {
    Mmio(TisErr),
    Boot(BootErr),
}

pub struct TpmDevice {
    inner: Mutex<CtxIo<ChipLink<TisMmio>>>,
    limits: Limits,
    cc_table: CcTable,
}

impl TpmDevice {
    pub fn exec(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, IoErr> {
        let mut chip = self.inner.lock();
        chip.exec_raw(cmd, rsp)
    }

    pub fn limits(&self) -> &Limits { &self.limits }

    pub fn cc_table(&self) -> &CcTable { &self.cc_table }

    /// 获取底层 Mutex 引用，用于 space_transmit 需要长期持锁的场景。
    pub fn io_mutex(&self) -> &Mutex<CtxIo<ChipLink<TisMmio>>> {
        &self.inner
    }
}

fn build_cc_table() -> CcTable {
    let mut t = CcTable::empty();
    // ContextLoad: 0 handles in, 1 handle out
    t.push(0x0000_0161, CcAttrs { nr_chandles: 0, has_rhandle: true });
    // ContextSave: 1 handle in, 0 handles out
    t.push(0x0000_0162, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // FlushContext: TPM spec says 0 handles, but the handle to flush is at
    // HEADER_SIZE in the parameter area. RM must treat it as 1 handle
    // for virtual→physical mapping to work correctly.
    t.push(0x0000_0165, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // StartAuthSession: 2 handles in, 1 handle out
    t.push(0x0000_0176, CcAttrs { nr_chandles: 2, has_rhandle: true });
    // CreatePrimary: 1 handle in, 1 handle out
    t.push(0x0000_0131, CcAttrs { nr_chandles: 1, has_rhandle: true });
    // Create: 1 handle in, 0 handles out
    t.push(0x0000_0153, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Load: 1 handle in, 1 handle out
    t.push(0x0000_0157, CcAttrs { nr_chandles: 1, has_rhandle: true });
    // Unseal: 1 handle in, 0 handles out
    t.push(0x0000_015E, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // HMAC_Start: 1 handle in, 1 handle out
    t.push(0x0000_015B, CcAttrs { nr_chandles: 1, has_rhandle: true });
    // HashSequenceStart: 0 handles in, 1 handle out
    t.push(0x0000_0186, CcAttrs { nr_chandles: 0, has_rhandle: true });
    // ReadPublic: 1 handle in, 0 handles out
    t.push(0x0000_0173, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Sign: 1 handle in, 0 handles out
    t.push(0x0000_015D, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // VerifySignature: 1 handle in, 0 handles out
    t.push(0x0000_0177, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // HMAC: 1 handle in, 0 handles out
    t.push(0x0000_0155, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // GetCapability: 0 handles in, 0 handles out (response has handle list)
    t.push(0x0000_017A, CcAttrs { nr_chandles: 0, has_rhandle: false });
    // PolicyCommandCode: 1 handle in (session), 0 handles out
    t.push(0x0000_016C, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // PolicyGetDigest: 1 handle in (session), 0 handles out
    t.push(0x0000_0189, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // NV_DefineSpace: 1 handle in (auth), 0 handles out
    t.push(0x0000_012A, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // NV_Write: 2 handles in (auth + nvIndex), 0 handles out
    t.push(0x0000_0137, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // NV_Read: 2 handles in (auth + nvIndex), 0 handles out
    t.push(0x0000_014E, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // NV_UndefineSpace: 2 handles in (auth + nvIndex), 0 handles out
    t.push(0x0000_0122, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // NV_ReadPublic: 1 handle in (nvIndex), 0 handles out
    t.push(0x0000_0169, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Shutdown: 0 handles in, 0 handles out
    t.push(0x0000_0145, CcAttrs { nr_chandles: 0, has_rhandle: false });
    // SelfTest: 0 handles in, 0 handles out
    t.push(0x0000_0143, CcAttrs { nr_chandles: 0, has_rhandle: false });
    // EvictControl: 2 handles in, 0 handles out
    t.push(0x0000_0120, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // EncryptDecrypt: 1 handle in, 0 handles out
    t.push(0x0000_0164, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // RSA_Encrypt: 1 handle in, 0 handles out
    t.push(0x0000_0174, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // RSA_Decrypt: 1 handle in, 0 handles out
    t.push(0x0000_0159, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Certify: 2 handles in, 0 handles out
    t.push(0x0000_0148, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // Quote: 1 handle in, 0 handles out
    t.push(0x0000_0158, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // GetSessionAuditDigest: 3 handles in, 0 handles out
    t.push(0x0000_014D, CcAttrs { nr_chandles: 3, has_rhandle: false });
    // GetTime: 2 handles in, 0 handles out
    t.push(0x0000_014C, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // CertifyCreation: 2 handles in, 0 handles out
    t.push(0x0000_014A, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // HierarchyChangeAuth: 1 handle in, 0 handles out
    t.push(0x0000_0129, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Clear: 1 handle in, 0 handles out
    t.push(0x0000_0126, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // ClearControl: 1 handle in, 0 handles out
    t.push(0x0000_0127, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // HierarchyControl: 1 handle in, 0 handles out
    t.push(0x0000_0121, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // PCR_Event: 1 handle in, 0 handles out
    t.push(0x0000_013C, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // PCR_Reset: 1 handle in, 0 handles out
    t.push(0x0000_013D, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // SequenceComplete: 1 handle in, 0 handles out
    t.push(0x0000_013E, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // SequenceUpdate: 1 handle in, 0 handles out
    t.push(0x0000_015C, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // EventSequenceComplete: 2 handles in, 0 handles out
    t.push(0x0000_0185, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // ActivateCredential: 2 handles in, 0 handles out
    t.push(0x0000_0147, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // MakeCredential: 1 handle in, 0 handles out
    t.push(0x0000_0168, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Import: 1 handle in, 0 handles out
    t.push(0x0000_0156, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Rewrap: 2 handles in, 0 handles out
    t.push(0x0000_0152, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // ECDH_KeyGen: 1 handle in, 0 handles out
    t.push(0x0000_0163, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // ECDH_ZGen: 1 handle in, 0 handles out
    t.push(0x0000_0154, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // ZGen_2Phase: 1 handle in, 0 handles out
    t.push(0x0000_018D, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Commit: 1 handle in, 0 handles out
    t.push(0x0000_018B, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // EC_Ephemeral: 0 handles in, 1 handle out
    t.push(0x0000_018E, CcAttrs { nr_chandles: 0, has_rhandle: true });
    // FlushContext: 0 handles in, 0 handles out (handled specially by space_transmit)
    // LoadExternal: 0 handles in, 1 handle out
    t.push(0x0000_0167, CcAttrs { nr_chandles: 0, has_rhandle: true });
    // ChangeEPS: 1 handle in, 0 handles out
    t.push(0x0000_0124, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // ChangePPS: 1 handle in, 0 handles out
    t.push(0x0000_0125, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // DictionaryAttackLockReset: 1 handle in, 0 handles out
    t.push(0x0000_0139, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // DictionaryAttackParameters: 1 handle in, 0 handles out
    t.push(0x0000_013A, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // PCR_Allocate: 1 handle in, 0 handles out
    t.push(0x0000_012B, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // SetCommandCodeAuditStatus: 1 handle in, 0 handles out
    t.push(0x0000_0140, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // SetPrimaryPolicy: 1 handle in, 0 handles out
    t.push(0x0000_012E, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // StirRandom: 0 handles in, 0 handles out
    t.push(0x0000_0146, CcAttrs { nr_chandles: 0, has_rhandle: false });
    // ClockRateAdjust: 1 handle in, 0 handles out
    t.push(0x0000_0130, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // ClockSet: 1 handle in, 0 handles out
    t.push(0x0000_0128, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // PP_Commands: 1 handle in, 0 handles out
    t.push(0x0000_012D, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // SetAlgorithmSet: 1 handle in, 0 handles out
    t.push(0x0000_013F, CcAttrs { nr_chandles: 1, has_rhandle: false });
    // Duplicate: 2 handles in, 0 handles out
    t.push(0x0000_014B, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // ObjectChangeAuth: 2 handles in, 0 handles out
    t.push(0x0000_0150, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // PolicySecret: 2 handles in, 0 handles out
    t.push(0x0000_0151, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // PolicySigned: 2 handles in, 0 handles out
    t.push(0x0000_0160, CcAttrs { nr_chandles: 2, has_rhandle: false });
    // PolicyNV: 3 handles in, 0 handles out
    t.push(0x0000_0149, CcAttrs { nr_chandles: 3, has_rhandle: false });
    // NVCertify: 3 handles in, 0 handles out
    t.push(0x0000_0195, CcAttrs { nr_chandles: 3, has_rhandle: false });
    t
}

pub fn probe() -> Result<TpmDevice, TpmInitErr> {
    let abi_ok = check_abi();
    if !abi_ok {
        ostd::warn!("tpm: host crypto ABI mismatch, boot will abort");
    }

    let phys: Range<Paddr> = TPM_TIS_BASE..TPM_TIS_BASE + TPM_TIS_SIZE;
    let mmio = TisMmio::acquire(phys, POLL_SPIN).map_err(TpmInitErr::Mmio)?;

    let tis = Tis { phy: mmio, locality: 0, held: false };
    let x = Xfer::new(tis);
    let (x, limits) = bring_up(x, SU_CLEAR, abi_ok).map_err(TpmInitErr::Boot)?;

    ostd::info!("tpm: ready");
    Ok(TpmDevice {
        inner: Mutex::new(CtxIo::new(ChipLink::new(x))),
        limits,
        cc_table: build_cc_table(),
    })
}
