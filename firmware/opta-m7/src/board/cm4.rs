//! Read-only observation of STM32H747 CM4 boot authorization.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::sync::atomic::Ordering;

use opta_gateway_contracts::cm4;

use crate::probes::{
    M7_CM4_RCC_APB4ENR_PRE, M7_CM4_RCC_CR_RAW, M7_CM4_RCC_GCR_POST_INIT,
    M7_CM4_RCC_GCR_POST_WW1RSC, M7_CM4_RCC_GCR_PRE_INIT, M7_CM4_STATE, M7_CM4_SYSCFG_UR1_RAW,
};

const RCC_APB4ENR: *mut u32 = 0x5802_44F4 as *mut u32;
const SYSCFG_UR1: *const u32 = 0x5800_0704 as *const u32;
const RCC_CR: *const u32 = 0x5802_4400 as *const u32;
const RCC_GCR: *const u32 = 0x5802_44A0 as *const u32;
const RCC_APB4ENR_SYSCFGEN: u32 = 1 << 1;

#[derive(Clone, Copy)]
pub(crate) struct Cm4BootObservation {
    syscfg_ur1: u32,
}

fn publish_state(syscfg_ur1: u32, rcc_gcr: u32) {
    M7_CM4_STATE.store(
        cm4::authorization_state(syscfg_ur1, rcc_gcr).as_word(),
        Ordering::Relaxed,
    );
}

/// Capture the option-backed CM4 authorization and pre-clock-init RCC state.
///
/// RM0399 Rev 4 section 9.7.47 places `SYSCFGEN` at RCC_APB4ENR bit 1;
/// section 13.3.14 exposes `BCM4` through SYSCFG_UR1 only while that interface
/// clock is available. Section 9.4.8 and Table 58 define CPU2 authorization as
/// BCM4 or a later software-set BOOT_C2. This function only enables the
/// SYSCFG register interface and reads authorization; it never releases CM4.
pub(crate) fn capture_pre_init() -> Cm4BootObservation {
    // Startup owns clock normalization before Embassy enables interrupts. The
    // only write is a narrow RCC_APB4ENR RMW that sets SYSCFGEN.
    // SAFETY: these are the documented STM32H747 RCC/SYSCFG addresses;
    // SYSCFG_UR1, RCC_CR, and RCC_GCR are read-only in this module, so BOOT_C2
    // cannot transition from zero to one here.
    unsafe {
        let apb4enr_pre = RCC_APB4ENR.read_volatile();
        M7_CM4_RCC_APB4ENR_PRE.store(apb4enr_pre, Ordering::Relaxed);
        RCC_APB4ENR.write_volatile(apb4enr_pre | RCC_APB4ENR_SYSCFGEN);
        let _ = RCC_APB4ENR.read_volatile();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        let syscfg_ur1 = SYSCFG_UR1.read_volatile();
        let rcc_cr = RCC_CR.read_volatile();
        let rcc_gcr = RCC_GCR.read_volatile();
        M7_CM4_SYSCFG_UR1_RAW.store(syscfg_ur1, Ordering::Relaxed);
        M7_CM4_RCC_CR_RAW.store(rcc_cr, Ordering::Relaxed);
        M7_CM4_RCC_GCR_PRE_INIT.store(rcc_gcr, Ordering::Relaxed);
        publish_state(syscfg_ur1, rcc_gcr);
        Cm4BootObservation { syscfg_ur1 }
    }
}

fn capture_gcr(observation: &Cm4BootObservation, probe: &core::sync::atomic::AtomicU32) {
    // SAFETY: RCC_GCR is read through a const pointer. RM0399 Rev 4 section
    // 9.7.36 defines BOOT_C2 bit 3; this readback cannot modify it.
    let rcc_gcr = unsafe { RCC_GCR.read_volatile() };
    probe.store(rcc_gcr, Ordering::Relaxed);
    publish_state(observation.syscfg_ur1, rcc_gcr);
}

pub(crate) fn capture_post_init(observation: &Cm4BootObservation) {
    capture_gcr(observation, &M7_CM4_RCC_GCR_POST_INIT);
}

pub(crate) fn capture_post_ww1rsc(observation: &Cm4BootObservation) {
    capture_gcr(observation, &M7_CM4_RCC_GCR_POST_WW1RSC);
}
