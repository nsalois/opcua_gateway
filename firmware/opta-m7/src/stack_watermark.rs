//! Diagnostic-only two-boot MSP high-water bracket.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::sync::atomic::Ordering;

use crate::board::STACK_GUARD_MPU_SIZE_BYTES;
use crate::probes::{
    M7_STACK_GUARD_BASE, M7_STACK_GUARD_BYTES, M7_STACK_WATERMARK_PAINT_END,
    M7_STACK_WATERMARK_PAINT_START, M7_STACK_WATERMARK_PHASE,
};

pub(crate) const MEASUREMENT_ARM_ADDRESS: u32 = 0x2403_FFE0;
pub(crate) const MEASUREMENT_ARM_MAGIC: u32 = 0x5354_4B32; // "STK2"

const PHASE_WAITING_FOR_PAINT: u32 = 1;
const PHASE_MEASUREMENT_BOOT: u32 = 2;

// SAFETY: memory.x defines these boundaries around the complete reserved M7
// stack. This diagnostic takes their addresses only; it never dereferences
// either linker symbol.
unsafe extern "C" {
    static __stack_limit: u8;
    static __stack_top: u8;
}

/// Debugger breakpoint target used to re-arm after reset.
///
/// The preparation boot still writes the SRAM arm word, but the 2026-08-14
/// capture showed that word does not survive the bootloader into `main`. The
/// harness therefore breaks here after `reset run`, writes the magic again,
/// and resumes so this function observes it.
// SAFETY: this stable symbol is named explicitly so the harness can break at
// the measurement-boot entry after reset. It only forwards to the existing
// gate and adds no new memory access.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_STACK_WATERMARK_GATE() {
    measurement_boot_gate();
}

/// Halt the cache-normalized preparation boot, then admit exactly one full
/// measurement boot after the debugger has painted RAM and armed it.
///
/// The debugger launches the first boot only to discard inherited cache state.
/// This gate disables D-cache with the Arm-required clean+invalidate sequence
/// before halting, so the subsequent AHB-AP paint cannot be overwritten by the
/// prior image. The debugger paints the complete linked stack bracket, writes the
/// arm magic below it, and issues a hardware reset. D1 SRAM retains both; the
/// second boot clears the magic and runs normal product initialization.
pub(crate) fn measurement_boot_gate() {
    let paint_start = core::ptr::addr_of!(__stack_limit) as u32;
    let paint_end = core::ptr::addr_of!(__stack_top) as u32;
    M7_STACK_WATERMARK_PAINT_START.store(paint_start, Ordering::Relaxed);
    M7_STACK_WATERMARK_PAINT_END.store(paint_end, Ordering::Relaxed);
    M7_STACK_GUARD_BASE.store(paint_start, Ordering::Relaxed);
    M7_STACK_GUARD_BYTES.store(STACK_GUARD_MPU_SIZE_BYTES, Ordering::Relaxed);

    let arm = unsafe {
        // SAFETY: this feature alone owns one word in otherwise unlinked D1 RAM
        // below the possible 256 KiB escalation bracket and above __sheap.
        // Volatile access is used because the debugger writes the word between
        // the two boots.
        (MEASUREMENT_ARM_ADDRESS as *mut u32).read_volatile()
    };
    if arm == MEASUREMENT_ARM_MAGIC {
        unsafe {
            // SAFETY: same exclusive diagnostic word as the read above. Clear
            // it before continuing so an unrelated later reset cannot bypass
            // the preparation gate.
            (MEASUREMENT_ARM_ADDRESS as *mut u32).write_volatile(0);
        }
        M7_STACK_WATERMARK_PHASE.store(PHASE_MEASUREMENT_BOOT, Ordering::Release);
        // SAFETY: this still runs before interrupt normalization or peripheral
        // initialization, so no other code owns the core peripherals. Publish
        // the cleared arm word and the five probe words to physical SRAM so
        // debugger reads cannot observe their first-boot cache lines.
        let mut cp = unsafe { cortex_m::Peripherals::steal() };
        for probe_address in [
            &M7_STACK_WATERMARK_PHASE as *const _ as usize,
            &M7_STACK_WATERMARK_PAINT_START as *const _ as usize,
            &M7_STACK_WATERMARK_PAINT_END as *const _ as usize,
            &M7_STACK_GUARD_BASE as *const _ as usize,
            &M7_STACK_GUARD_BYTES as *const _ as usize,
        ] {
            cp.SCB.clean_dcache_by_address(probe_address & !31, 32);
        }
        cp.SCB
            .clean_dcache_by_address(MEASUREMENT_ARM_ADDRESS as usize, 32);
        return;
    }

    M7_STACK_WATERMARK_PHASE.store(PHASE_WAITING_FOR_PAINT, Ordering::Release);
    // SAFETY: this diagnostic gate runs before interrupt normalization,
    // peripheral initialization, or task spawning. No other Rust code owns the
    // core peripherals. disable_dcache performs a full clean+invalidate before
    // the debugger is allowed to paint physical SRAM.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB.disable_dcache(&mut cp.CPUID);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    #[cfg(feature = "diagnostic-accelerated-clock")]
    {
        M7_STACK_WATERMARK_PAINT_GATE();
        loop {
            // This preparation is discarded, never an acceptance workload.
            // Remain installable/running until the owned hardware breakpoint
            // stops a fresh boot at PAINT_GATE. Refresh the inherited IWDG1;
            // the second boot still uses the unchanged product watchdog policy.
            crate::watchdog::iwdg1_refresh();
            core::hint::spin_loop();
        }
    }
    #[cfg(not(feature = "diagnostic-accelerated-clock"))]
    loop {
        // Under the authorized debugger this halts without executing further
        // stack-mutating Rust code. The harness resets instead of resuming.
        cortex_m::asm::bkpt();
    }
}

// SAFETY: stable cache-normalized preparation breakpoint for the combined
// diagnostic only. The admitted runner owns the hardware breakpoint at entry.
#[cfg(feature = "diagnostic-accelerated-clock")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_STACK_WATERMARK_PAINT_GATE() {
    core::hint::black_box(M7_STACK_WATERMARK_PHASE.load(Ordering::Acquire));
}

/// Capture only after the external repeated-operation observer has disconnected.
/// This additional gate exists solely in the combined clock/watermark diagnostic.
#[cfg(feature = "diagnostic-accelerated-clock")]
static CAPTURE_REQUESTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "diagnostic-accelerated-clock")]
pub(crate) fn request_completed_workload_capture() {
    CAPTURE_REQUESTED.store(true, Ordering::Release);
}

#[cfg(feature = "diagnostic-accelerated-clock")]
#[embassy_executor::task]
pub(crate) async fn completed_workload_capture_task(runtime: &'static crate::SharedRuntime) -> ! {
    loop {
        embassy_time::Timer::after_millis(100).await;
        if !CAPTURE_REQUESTED.load(Ordering::Acquire) {
            continue;
        }
        let completed = runtime.try_lock().is_ok_and(|data| {
            data.health().buchi_write_completed_count >= 100 && data.write_queue_depth() == 0
        });
        if completed && crate::product_opcua::watermark_listeners_idle() {
            break;
        }
    }
    cortex_m::interrupt::free(|_| {
        // SAFETY: the diagnostic is ending its acceptance window. Interrupts
        // are masked while this sole SCB cache-policy transition runs. Arm's
        // clean+invalidate sequence writes dirty stack lines to physical SRAM;
        // Ethernet DMA remains in the board's noncacheable MPU region. No stack
        // painting or application-state injection occurs on the measurement boot.
        let mut cp = unsafe {
            // SAFETY: exclusive interrupt-masked diagnostic SCB transition;
            // cortex-m disable_dcache follows ST AN4839's clean requirement.
            cortex_m::Peripherals::steal()
        };
        cp.SCB.disable_dcache(&mut cp.CPUID);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    });
    M7_STACK_WATERMARK_PHASE.store(3, Ordering::Release);
    M7_STACK_WATERMARK_CAPTURE_GATE();
    cortex_m::interrupt::free(|_| {
        // SAFETY: sole diagnostic SCB transition with interrupts masked. Cache
        // was fully cleaned and disabled above; enable_dcache invalidates before
        // enabling, as required by ST AN4839. No live state is painted.
        let mut cp = unsafe { cortex_m::Peripherals::steal() };
        cp.SCB.enable_dcache(&mut cp.CPUID);
    });
    loop {
        embassy_time::Timer::after_secs(1).await;
    }
}

// SAFETY: stable diagnostic capture breakpoint. The cache is already disabled
// and the completed workload is quiescent. A hardware breakpoint stops at entry;
// after capture the harness removes it and resumes normal diagnostic service.
#[cfg(feature = "diagnostic-accelerated-clock")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_STACK_WATERMARK_CAPTURE_GATE() {
    core::hint::black_box(M7_STACK_WATERMARK_PHASE.load(Ordering::Acquire));
}
