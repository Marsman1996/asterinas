use crate::device::io_port::{IoPort, WriteOnlyAccess};
use crate::trap::allocate_target_irq;
use crate::trap::IrqAllocateHandle;

use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicBool, AtomicU8};

static MASTER_CMD: IoPort<u8, WriteOnlyAccess> = unsafe { IoPort::new(0x20) };
static MASTER_DATA: IoPort<u8, WriteOnlyAccess> = unsafe { IoPort::new(0x21) };
static SLAVE_CMD: IoPort<u8, WriteOnlyAccess> = unsafe { IoPort::new(0xA0) };
static SLAVE_DATA: IoPort<u8, WriteOnlyAccess> = unsafe { IoPort::new(0xA1) };

const IRQ_OFFSET: u8 = 0x20;

const TIMER_IRQ_NUM: u8 = 32;

use alloc::vec::Vec;
use lazy_static::lazy_static;
use log::info;
use spin::Mutex;

lazy_static! {
    /// store the irq, although we have APIC for manage interrupts
    /// but something like serial still need pic for register interrupts
    static ref IRQ_LOCK : Mutex<Vec<IrqAllocateHandle>> = Mutex::new(Vec::new());
}

static MASK_MASTER: AtomicU8 = AtomicU8::new(0x00);

static MASK_SLAVE: AtomicU8 = AtomicU8::new(0x00);

static CHANGE_LOCK: AtomicBool = AtomicBool::new(false);

/// init the PIC device
pub(crate) fn init() {
    if CHANGE_LOCK.load(Relaxed) {
        return;
    }
    let master_mask = !(MASK_MASTER.load(Relaxed));
    let slave_mask = !(MASK_SLAVE.load(Relaxed));
    info!(
        "PIC init, master mask:{:x} slave_mask:{:x}",
        master_mask, slave_mask
    );
    unsafe {
        set_mask(master_mask, slave_mask);
    }
}

/// allocate irq, for example, if timer need IRQ0, it will return IrqAllocateHandle with irq num: IRQ_OFFSET+0
pub(crate) fn allocate_irq(index: u8) -> Option<IrqAllocateHandle> {
    if index >= 16 {
        return None;
    }
    if let Ok(irq) = allocate_target_irq(IRQ_OFFSET + index) {
        if index >= 8 {
            MASK_SLAVE.fetch_or(1 << (index - 8), Relaxed);
        } else {
            MASK_MASTER.fetch_or(1 << (index), Relaxed);
        }
        Some(irq)
    } else {
        None
    }
}

/// enable the PIC device, this function will permanent enable all the interrupts
#[inline]
pub(crate) unsafe fn enable() {
    CHANGE_LOCK.store(true, Relaxed);
    set_mask(0, 0);
}

/// disable the PIC device, this function will permanent disable all the interrupts
/// the interrupts mask may not exists after calling init function
#[inline]
pub(crate) unsafe fn disable() {
    CHANGE_LOCK.store(true, Relaxed);
    set_mask(0xFF, 0xFF);
}

/// enable the PIC device, this function will allow all the interrupts
/// the interrupts mask may not exists after calling init function
#[inline]
pub(crate) fn enable_temp() {
    unsafe {
        set_mask(0, 0);
    }
}

/// disable the PIC device, this function will disable all the interrupts
/// the interrupts mask may not exists after calling init function
#[inline]
pub(crate) fn disable_temp() {
    unsafe {
        set_mask(0xFF, 0xFF);
    }
}

#[inline(always)]
pub(crate) unsafe fn set_mask(master_mask: u8, slave_mask: u8) {
    // Start initialization
    MASTER_CMD.write(0x11);
    SLAVE_CMD.write(0x11);

    // Set offsets
    // map master PIC vector 0x00~0x07 to 0x20~0x27 IRQ number
    MASTER_DATA.write(IRQ_OFFSET);
    // map slave PIC vector 0x00~0x07 to 0x28~0x2f IRQ number
    SLAVE_DATA.write(IRQ_OFFSET + 0x08);

    // Set up cascade, there is slave at IRQ2
    MASTER_DATA.write(4);
    SLAVE_DATA.write(2);

    // Set up interrupt mode (1 is 8086/88 mode, 2 is auto EOI)
    MASTER_DATA.write(1);
    SLAVE_DATA.write(1);

    // mask interrupts
    MASTER_DATA.write(master_mask);
    SLAVE_DATA.write(slave_mask);
}

#[inline(always)]
pub(crate) fn ack() {
    MASTER_CMD.write(0x20);
}
