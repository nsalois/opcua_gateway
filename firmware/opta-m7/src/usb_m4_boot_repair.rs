//! Temporary Board B USB repair overlay; absent from default firmware.
//! Only the exact CM4 alternate boot field can change, on an explicit command.
//! Sources: RM0399 Rev 4 sections 4.4.3, 4.5.1, 4.9.4 and 4.9.20;
//! ES0445 Rev 6 reviewed; retained Board B USB inventory 2026-09-08.
// Firmware policy marker: crate root declares #![no_std].

const OLD: u32 = 0x1000_0810;
const NEW: u32 = 0x0810_0810;
// Address, expected value, meaningful mask. Only volatile Flash lock/program
// width and watchdog reset-scope bits may differ from the retained DFU state.
const GUARDS: &[(usize, u32, u32)] = &[
    (0x1ff1e800, 0x004b0032, 0xffffffff), // UID
    (0x1ff1e804, 0x3033510d, 0xffffffff), // UID
    (0x1ff1e808, 0x34323932, 0xffffffff), // UID
    (0x5c001000, 0x20036450, 0xffffffff), // DBGMCU_IDCODE
    (0x58000700, 0x00aa0000, 0xffffffff), // SYSCFG_UR0
    (0x58000704, 0x00010000, 0xffffffff), // SYSCFG_UR1
    (0x580244a0, 0x00000000, 0x00000008), // RCC_GCR
    (0x5200200c, 0x00000000, 0x000003cc), // FLASH_CR1
    (0x52002010, 0x00000000, 0x17ee000f), // FLASH_SR1
    (0x52002018, 0x00000001, 0xffffffff), // FLASH_OPTCR
    (0x52002118, 0x00000001, 0xffffffff), // FLASH_OPTCR_MIRROR
    (0x5200201c, 0x0b86aaf0, 0xffffffff), // FLASH_OPTSR_CUR
    (0x5200211c, 0x0b86aaf0, 0xffffffff), // FLASH_OPTSR_CUR_MIRROR
    (0x52002020, 0x0b86aaf0, 0xffffffff), // FLASH_OPTSR_PRG
    (0x52002120, 0x0b86aaf0, 0xffffffff), // FLASH_OPTSR_PRG_MIRROR
    (0x52002040, 0x1ff00800, 0xffffffff), // FLASH_BOOT7_CURR
    (0x52002140, 0x1ff00800, 0xffffffff), // FLASH_BOOT7_CURR_MIRROR
    (0x52002044, 0x1ff00800, 0xffffffff), // FLASH_BOOT7_PRGR
    (0x52002144, 0x1ff00800, 0xffffffff), // FLASH_BOOT7_PRGR_MIRROR
    (0x52002048, 0x10000810, 0xffffffff), // FLASH_BOOT4_CURR
    (0x52002148, 0x10000810, 0xffffffff), // FLASH_BOOT4_CURR_MIRROR
    (0x5200204c, 0x10000810, 0xffffffff), // FLASH_BOOT4_PRGR
    (0x5200214c, 0x10000810, 0xffffffff), // FLASH_BOOT4_PRGR_MIRROR
    (0x52002028, 0x000000ff, 0xffffffff), // FLASH_PRAR_CUR_AT_028
    (0x5200202c, 0x000000ff, 0xffffffff), // FLASH_PRAR_PRG_AT_02C
    (0x52002030, 0x000000ff, 0xffffffff), // FLASH_SCAR_CUR_AT_030
    (0x52002034, 0x000000ff, 0xffffffff), // FLASH_SCAR_PRG_AT_034
    (0x52002038, 0x000000ff, 0xffffffff), // FLASH_WPSN_CUR_AT_038
    (0x5200203c, 0x000000ff, 0xffffffff), // FLASH_WPSN_PRG_AT_03C
    (0x5200210c, 0x00000000, 0x000003cc), // FLASH_CR2
    (0x52002110, 0x00000000, 0x17ee000f), // FLASH_SR2
    (0x52002128, 0x000000ff, 0xffffffff), // FLASH_PRAR_CUR_AT_128
    (0x5200212c, 0x000000ff, 0xffffffff), // FLASH_PRAR_PRG_AT_12C
    (0x52002130, 0x000000ff, 0xffffffff), // FLASH_SCAR_CUR_AT_130
    (0x52002134, 0x000000ff, 0xffffffff), // FLASH_SCAR_PRG_AT_134
    (0x52002138, 0x000000ff, 0xffffffff), // FLASH_WPSN_CUR_AT_138
    (0x5200213c, 0x000000ff, 0xffffffff), // FLASH_WPSN_PRG_AT_13C
];

fn boot_register(address: usize) -> bool {
    matches!(address, 0x52002048 | 0x5200204c | 0x52002148 | 0x5200214c)
}

fn check(values: &[u32], corrected: bool) -> Result<(), usize> {
    if values.len() != GUARDS.len() {
        return Err(GUARDS.len());
    }
    for (i, (&value, &(address, expected, mask))) in values.iter().zip(GUARDS).enumerate() {
        let expected = if corrected && boot_register(address) {
            NEW
        } else {
            expected
        };
        if value & mask != expected & mask {
            return Err(i);
        }
    }
    Ok(())
}

#[cfg(target_arch = "arm")]
fn read(address: usize) -> u32 {
    // SAFETY: callers use only the fixed RM0399 CPU-visible UID, Flash, RCC,
    // SYSCFG and DBGMCU register whitelist. No read has a destructive side effect.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

#[cfg(target_arch = "arm")]
fn snapshot() -> [u32; GUARDS.len()] {
    core::array::from_fn(|i| read(GUARDS[i].0))
}

#[cfg(target_arch = "arm")]
pub(crate) fn status() -> Result<(), usize> {
    check(&snapshot(), false)
}

#[cfg(target_arch = "arm")]
pub(crate) fn correct() -> Result<(), &'static str> {
    use core::sync::atomic::{AtomicBool, Ordering};
    use embassy_time::{Duration, Instant};
    static ATTEMPTED: AtomicBool = AtomicBool::new(false);
    // The console is the sole caller and sole Flash writer while this blocking
    // transaction runs. The interrupt watchdog keeps its existing bounded policy.
    if ATTEMPTED.swap(true, Ordering::SeqCst) {
        return Err("already-attempted");
    }
    status().map_err(|_| "precondition")?;
    let _maintenance = crate::watchdog::FlashMaintenanceGuard::enter();
    // SAFETY: all option mirrors/current/programming values, identity, mapping,
    // hold, protection and idle state were checked immediately above. RM0399
    // 4.4.3/4.5.1 specify these keys and this single-field programming sequence.
    // No Flash erase, bank swap, other option, or option reload is requested.
    unsafe {
        core::ptr::write_volatile(0x52002008 as *mut u32, 0x0819_2a3b);
        core::ptr::write_volatile(0x52002008 as *mut u32, 0x4c5d_6e7f);
    }
    if read(0x52002018) != 0 {
        return Err("unlock");
    }
    // SAFETY: the admitted old word is OLD; the only new option word is NEW.
    unsafe {
        core::ptr::write_volatile(0x5200204c as *mut u32, NEW);
    }
    if read(0x5200204c) != NEW || read(0x52002048) != OLD {
        // SAFETY: relock only; no option operation has started.
        unsafe {
            core::ptr::write_volatile(0x52002018 as *mut u32, 1);
        }
        return Err("programming-register");
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    // SAFETY: OPTSTART alone starts the admitted change. MER/SWAP_BANK are zero.
    unsafe {
        core::ptr::write_volatile(0x52002018 as *mut u32, 2);
    }
    cortex_m::asm::dsb();
    while read(0x5200201c) & 1 != 0 || read(0x52002018) & 2 != 0 {
        if Instant::now() >= deadline {
            return Err("timeout-no-retry");
        }
    }
    // SAFETY: operation is idle. Restore only the option lock; do not clear errors.
    unsafe {
        core::ptr::write_volatile(0x52002018 as *mut u32, 1);
    }
    check(&snapshot(), true).map_err(|_| "postcondition-no-retry")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_transition_and_every_guard() {
        let mut values: Vec<u32> = GUARDS.iter().map(|r| r.1).collect();
        assert!(check(&values, false).is_ok());
        assert!(check(&values, true).is_err());
        for i in 0..values.len() {
            let bit = 1 << GUARDS[i].2.trailing_zeros();
            values[i] ^= bit;
            assert_eq!(check(&values, false), Err(i));
            values[i] ^= bit;
        }
        for (value, &(address, _, _)) in values.iter_mut().zip(GUARDS) {
            if boot_register(address) {
                *value = NEW;
            }
        }
        assert!(check(&values, true).is_ok());
        assert!(check(&values, false).is_err());
        assert_eq!(OLD ^ NEW, 0x1810_0000);
    }
}
