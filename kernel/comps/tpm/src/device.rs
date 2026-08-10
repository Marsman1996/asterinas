use core::ops::Range;

use ostd::mm::Paddr;
use spin::Mutex;
use tpm_core::{
    BootErr, ChipLink, Limits, Tis, Xfer, bring_up,
    chip::{ChipTransport, CtxIo},
    cmd::SU_CLEAR,
    module::{IoErr, Space},
    rewrite::read_be32,
    tis::TisErr,
};

use crate::{
    extcrypto::check_abi,
    mmio::TisMmio,
    space_io::{CcAttrs, CcTable, MAX_COMMANDS, XmitErr, space_transmit},
};

pub const TPM_TIS_BASE: Paddr = 0xFED4_0000;
pub const TPM_TIS_SIZE: usize = 0x5000;
const POLL_SPIN: u32 = 1000;

pub enum TpmInitErr {
    Mmio(TisErr),
    Boot(BootErr),
    Commands(IoErr),
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

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn cc_table(&self) -> &CcTable {
        &self.cc_table
    }

    pub fn transmit_space(
        &self,
        space: &mut Space,
        ctx_buf: &mut [u8],
        ses_buf: &mut [u8],
        cmd: &mut [u8],
        cmd_len: usize,
        rsp: &mut [u8],
    ) -> Result<usize, XmitErr> {
        let mut io = self.inner.lock();
        space_transmit(
            space,
            &mut *io,
            &self.cc_table,
            ctx_buf,
            ses_buf,
            cmd,
            cmd_len,
            rsp,
        )
    }

    pub fn close_space(&self, space: &mut Space) {
        let mut io = self.inner.lock();
        let transaction = space.begin();
        transaction.abort(&mut *io);
    }
}

const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
const TPM_CC_FIRST: u32 = 0x0000_011f;
const TPM_CC_CONTEXT_SAVE: u32 = 0x0000_0162;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPMA_CC_COMMAND_INDEX_MASK: u32 = 0x0000_ffff;
const TPMA_CC_VENDOR: u32 = 1 << 29;
const TPMA_CC_CHANDLES_SHIFT: u32 = 25;
const TPMA_CC_CHANDLES_MASK: u32 = 0x7;
const TPMA_CC_RHANDLE: u32 = 1 << 28;
const GET_CAPABILITY_COMMAND_SIZE: usize = 22;
const GET_CAPABILITY_RESPONSE_PREFIX: usize = 19;
const COMMAND_ATTR_SIZE: usize = 4;

fn build_cc_table<T: ChipTransport>(chip: &mut T) -> Result<CcTable, IoErr> {
    let mut table = CcTable::empty();
    let mut property = TPM_CC_FIRST;
    let mut command = [0u8; GET_CAPABILITY_COMMAND_SIZE];
    let mut response = [0u8; 4096];

    loop {
        command.fill(0);
        command[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        command[2..6].copy_from_slice(&(GET_CAPABILITY_COMMAND_SIZE as u32).to_be_bytes());
        command[6..10].copy_from_slice(&0x0000_017au32.to_be_bytes());
        command[10..14].copy_from_slice(&TPM_CAP_COMMANDS.to_be_bytes());
        command[14..18].copy_from_slice(&property.to_be_bytes());
        command[18..22].copy_from_slice(&(MAX_COMMANDS as u32).to_be_bytes());

        let response_len = chip.exec(&command, &mut response)?;
        if response_len < GET_CAPABILITY_RESPONSE_PREFIX {
            return Err(IoErr::Protocol);
        }
        let declared_len = read_be32(&response, 2) as usize;
        let response_code = read_be32(&response, 6);
        let capability = read_be32(&response, 11);
        let count = read_be32(&response, 15) as usize;
        let attrs_len = count
            .checked_mul(COMMAND_ATTR_SIZE)
            .and_then(|len| GET_CAPABILITY_RESPONSE_PREFIX.checked_add(len))
            .ok_or(IoErr::Protocol)?;
        if response_code != 0
            || capability != TPM_CAP_COMMANDS
            || declared_len != response_len
            || attrs_len != response_len
        {
            return Err(IoErr::Protocol);
        }
        if count == 0 && response[10] != 0 {
            return Err(IoErr::Protocol);
        }

        let mut last_cc = property;
        for index in 0..count {
            let attr = read_be32(
                &response,
                GET_CAPABILITY_RESPONSE_PREFIX + index * COMMAND_ATTR_SIZE,
            );
            let cc = (attr & TPMA_CC_COMMAND_INDEX_MASK) | (attr & TPMA_CC_VENDOR);
            // The TPM command attributes report ContextSave and FlushContext
            // with no command handles even though their first parameter is a
            // handle. Linux applies the same correction before using the
            // attributes for resource-manager handle translation.
            let nr_chandles = if cc == TPM_CC_CONTEXT_SAVE || cc == TPM_CC_FLUSH_CONTEXT {
                1
            } else {
                ((attr >> TPMA_CC_CHANDLES_SHIFT) & TPMA_CC_CHANDLES_MASK) as usize
            };
            let has_rhandle = attr & TPMA_CC_RHANDLE != 0;
            if !table.push(
                cc,
                CcAttrs {
                    nr_chandles,
                    has_rhandle,
                },
            ) {
                return Err(IoErr::NoSpace);
            }
            last_cc = cc;
        }

        if response[10] == 0 {
            break;
        }
        property = last_cc.checked_add(1).ok_or(IoErr::Protocol)?;
    }

    if table.len() == 0 {
        return Err(IoErr::Protocol);
    }
    Ok(table)
}
pub fn probe() -> Result<TpmDevice, TpmInitErr> {
    let abi_ok = check_abi();
    if !abi_ok {
        ostd::warn!("tpm: host crypto ABI mismatch, boot will abort");
    }

    let phys: Range<Paddr> = TPM_TIS_BASE..TPM_TIS_BASE + TPM_TIS_SIZE;
    let mmio = TisMmio::acquire(phys, POLL_SPIN).map_err(TpmInitErr::Mmio)?;

    let tis = Tis {
        phy: mmio,
        locality: 0,
        held: false,
    };
    let x = Xfer::new(tis);
    let (x, limits) = bring_up(x, SU_CLEAR, abi_ok).map_err(TpmInitErr::Boot)?;

    let mut chip = ChipLink::new(x);
    let cc_table = build_cc_table(&mut chip).map_err(TpmInitErr::Commands)?;

    ostd::info!("tpm: ready");
    Ok(TpmDevice {
        inner: Mutex::new(CtxIo::new(chip)),
        limits,
        cc_table,
    })
}
