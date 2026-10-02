//! Board bring-up helpers: clocking, cache/MPU, warm-launch, and registers.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
mod boot;
mod clock;
mod cm4;
mod interrupts;
mod registers;

#[cfg(not(feature = "product"))]
pub(crate) use boot::normalize_cache_state_for_dma;
pub(crate) use boot::normalize_interrupt_state_for_warm_launch;
#[cfg(feature = "product")]
pub(crate) use boot::{configure_cache_policy_for_dma, STACK_GUARD_MPU_SIZE_BYTES};
pub(crate) use clock::{
    quiesce_inherited_pll1, PRODUCTION_CLOCK_FREQUENCIES, PRODUCTION_CLOCK_PLAN, PRODUCTION_MDIO,
};
pub(crate) use cm4::{
    capture_post_init as capture_cm4_post_init, capture_post_ww1rsc as capture_cm4_post_ww1rsc,
    capture_pre_init as capture_cm4_pre_init,
};
pub(crate) use interrupts::{
    configure_product_interrupt_priorities, prepare_watchdog_executor_interrupt,
};
#[cfg(feature = "diagnostic-pre-clock-stall")]
pub(crate) use registers::read_bootloader_reset_reason_raw;
pub(crate) use registers::{
    clear_reset_flags_raw, enable_backup_domain_writes_raw, ensure_rtc_apb_clock_raw,
    read_reset_flags_raw,
};
