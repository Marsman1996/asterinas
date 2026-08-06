use core::ops::Range;

use ostd::mm::Paddr;
use spin::Mutex;
use tpm_core::chip::CtxIo;
use tpm_core::{
    BootErr, ChipLink, Limits, Tis, Xfer, bring_up, cmd::SU_CLEAR, module::IoErr, tis::TisErr,
};

use crate::extcrypto::check_abi;
use crate::mmio::TisMmio;

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
}

impl TpmDevice {
    pub fn exec(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, IoErr> {
        let mut chip = self.inner.lock();
        chip.exec_raw(cmd, rsp)
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }
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
    Ok(TpmDevice { inner: Mutex::new(CtxIo::new(ChipLink::new(x))), limits })
}
