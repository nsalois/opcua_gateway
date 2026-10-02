//! Narrowly scoped raw-register operations for backup domain and reset flags.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
const BACKUP_DOMAIN_WRITE_ENABLE_ATTEMPTS: u32 = 10_000;

pub(crate) fn ensure_rtc_apb_clock_raw() {
    // SAFETY: RCC_APB4ENR is the STM32H747 APB4 peripheral-clock enable
    // register (RM0399 §9.7.47); bit 16 keeps the RTC APB register interface
    // enabled. The register reset value already enables it, but asserting it
    // here makes backup-register access independent of earlier framework state.
    unsafe {
        const RCC_APB4ENR: *mut u32 = 0x5802_44F4 as *mut u32;
        RCC_APB4ENR.write_volatile(RCC_APB4ENR.read_volatile() | (1 << 16));
        let _ = RCC_APB4ENR.read_volatile();
        cortex_m::asm::dsb();
    }
}

pub(crate) fn enable_backup_domain_writes_raw() {
    ensure_rtc_apb_clock_raw();
    // SAFETY: PWR_CR1.DBP (bit 8) is the documented STM32H747 backup-domain
    // write-protection gate (RM0399 §6.4.1). DBP is intentionally left set
    // after this call; clearing it would break later DFU/backup-register
    // writers.
    unsafe {
        const PWR_CR1: *mut u32 = 0x5802_4800 as *mut u32;
        PWR_CR1.write_volatile(PWR_CR1.read_volatile() | (1 << 8));
        for _ in 0..BACKUP_DOMAIN_WRITE_ENABLE_ATTEMPTS {
            if PWR_CR1.read_volatile() & (1 << 8) != 0 {
                break;
            }
        }
        cortex_m::asm::dsb();
    }
}

pub(crate) fn read_reset_flags_raw() -> u32 {
    // SAFETY: RCC_RSR is the STM32H747 reset status register (RM0399 §9.7.52).
    unsafe { (0x5802_44D0 as *const u32).read_volatile() }
}

#[cfg(feature = "diagnostic-pre-clock-stall")]
pub(crate) fn read_bootloader_reset_reason_raw() -> u32 {
    ensure_rtc_apb_clock_raw();
    // RTC_BKP8R is the bootloader-owned STM32H747 backup register at
    // 0x5800_4070. The exact Arduino Opta bootloader installed on the bench
    // writes its Mbed reset-reason classification here before entering the M7
    // application. S3 reads it only as a bootloader handoff; project firmware
    // does not allocate, clear, or write BKP8R.
    // SAFETY: the volatile access is read-only and limited to RTC_BKP8R.
    unsafe { (0x5800_4070 as *const u32).read_volatile() }
}

pub(crate) fn clear_reset_flags_raw() {
    // SAFETY: RCC_RSR.RMVF bit 16 is documented as the software reset-flag
    // clear bit (RM0399 §9.7.52). Writing only RMVF avoids touching reserved
    // low bits and clears the accumulated reset-source flags after capture.
    unsafe {
        const RCC_RSR: *mut u32 = 0x5802_44D0 as *mut u32;
        RCC_RSR.write_volatile(1 << 16);
        cortex_m::asm::dsb();
    }
}
