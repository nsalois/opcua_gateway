//! Opt-in watchdog fault injection; absent from the default product.

// Firmware policy marker: crate root declares #![no_std]; no alloc or std.
#[cfg(any(
    feature = "diagnostic-suppress-net-runner-checkin",
    feature = "diagnostic-suppress-main-heartbeat-checkin",
    feature = "diagnostic-suppress-net-status-checkin",
    feature = "diagnostic-suppress-opcua-listener0-checkin",
))]
use crate::probes::M7_INDUCED_HANG_PROBE;
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
use crate::probes::{
    M7_WATCHDOG_CPU_BUSY_ELAPSED_MS, M7_WATCHDOG_CPU_BUSY_END_REFRESH_COUNT,
    M7_WATCHDOG_CPU_BUSY_PASSED, M7_WATCHDOG_CPU_BUSY_START_REFRESH_COUNT,
    M7_WATCHDOG_REFRESH_COUNT,
};
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
use crate::timebase::uptime_now_ms;
#[cfg(any(
    feature = "diagnostic-suppress-net-runner-checkin",
    feature = "diagnostic-suppress-main-heartbeat-checkin",
    feature = "diagnostic-suppress-net-status-checkin",
    feature = "diagnostic-suppress-opcua-listener0-checkin",
    feature = "diagnostic-watchdog-cpu-busy",
))]
use core::sync::atomic::Ordering;
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
use opta_gateway_contracts::watchdog as watchdog_contract;
#[cfg(any(
    feature = "diagnostic-suppress-net-runner-checkin",
    feature = "diagnostic-suppress-main-heartbeat-checkin",
    feature = "diagnostic-suppress-net-status-checkin",
    feature = "diagnostic-suppress-opcua-listener0-checkin",
))]
use opta_gateway_contracts::watchdog::WatchdogSlot;

#[cfg(feature = "diagnostic-pre-clock-stall")]
const RCC_RSR_IWDG1RSTF: u32 = 1 << 26;
#[cfg(feature = "diagnostic-pre-clock-stall")]
const BOOTLOADER_RESET_REASON_WATCHDOG: u32 = 4;

#[cfg(any(
    feature = "diagnostic-suppress-net-runner-checkin",
    feature = "diagnostic-suppress-main-heartbeat-checkin",
    feature = "diagnostic-suppress-net-status-checkin",
    feature = "diagnostic-suppress-opcua-listener0-checkin",
    feature = "diagnostic-stall-usb-control",
))]
pub(super) const CHECKIN_SUPPRESSION_AFTER_MS: u32 = 5_000;

#[cfg(any(
    feature = "diagnostic-suppress-net-runner-checkin",
    feature = "diagnostic-suppress-main-heartbeat-checkin",
    feature = "diagnostic-suppress-net-status-checkin",
    feature = "diagnostic-suppress-opcua-listener0-checkin",
))]
pub(super) fn suppress_checkin(task: WatchdogSlot, now_ms: u32) -> bool {
    #[cfg(feature = "diagnostic-suppress-net-runner-checkin")]
    {
        if task == WatchdogSlot::NetRunner && now_ms >= CHECKIN_SUPPRESSION_AFTER_MS {
            M7_INDUCED_HANG_PROBE.store(task.mask(), Ordering::Relaxed);
            return true;
        }
    }
    #[cfg(feature = "diagnostic-suppress-main-heartbeat-checkin")]
    {
        if task == WatchdogSlot::MainHeartbeat && now_ms >= CHECKIN_SUPPRESSION_AFTER_MS {
            M7_INDUCED_HANG_PROBE.store(task.mask(), Ordering::Relaxed);
            return true;
        }
    }
    #[cfg(feature = "diagnostic-suppress-net-status-checkin")]
    {
        if task == WatchdogSlot::NetStatus && now_ms >= CHECKIN_SUPPRESSION_AFTER_MS {
            M7_INDUCED_HANG_PROBE.store(task.mask(), Ordering::Relaxed);
            return true;
        }
    }
    #[cfg(feature = "diagnostic-suppress-opcua-listener0-checkin")]
    {
        if task == WatchdogSlot::OpcUaListener0 && now_ms >= CHECKIN_SUPPRESSION_AFTER_MS {
            M7_INDUCED_HANG_PROBE.store(task.mask(), Ordering::Relaxed);
            return true;
        }
    }
    let _ = task;
    let _ = now_ms;
    false
}

/// Diagnostic-only one-shot startup stall for the early-watchdog reset proof.
///
/// RM0399 Rev 4 §9.7.52 defines `RCC_RSR.IWDG1RSTF` at bit 26. The first boot
/// stalls after validated early arming and before config/clock setup. On a
/// normal Opta reset path the board bootloader classifies the cause as Mbed
/// `RESET_REASON_WATCHDOG` (value 4), writes that classification to its own
/// RTC_BKP8R scratch register, and clears RCC_RSR before entering this image.
/// Accepting either the still-live raw flag (a direct debugger launch) or the
/// exact bootloader handoff makes the diagnostic one-shot on both launch paths.
/// The reset-proof harness must establish a non-watchdog bootloader reason on its first
/// boot and prove the raw IWDG flags at the bootloader boundary after the bite.
#[cfg(feature = "diagnostic-pre-clock-stall")]
pub(crate) fn run_pre_clock_stall_probe(boot_reset_flags: u32, bootloader_reset_reason: u32) {
    if boot_reset_flags & RCC_RSR_IWDG1RSTF != 0
        || bootloader_reset_reason == BOOTLOADER_RESET_REASON_WATCHDOG
    {
        return;
    }

    loop {
        core::hint::spin_loop();
    }
}

/// Diagnostic-only proof that TIM7 preempts a CPU-busy thread-mode task.
///
/// Interrupts deliberately remain enabled. TIM2 advances the monotonic
/// timebase and wakes the TIM7 monitor while this function occupies thread
/// mode for one second. The reset-critical deadline remains two seconds.
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
pub(crate) fn run_cpu_busy_preemption_probe() {
    const CPU_BUSY_MS: u32 = 1_000;

    let start_refresh_count = M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Acquire);
    let start_ms = uptime_now_ms();
    M7_WATCHDOG_CPU_BUSY_START_REFRESH_COUNT.store(start_refresh_count, Ordering::Relaxed);
    M7_WATCHDOG_CPU_BUSY_PASSED.store(0, Ordering::Relaxed);

    while uptime_now_ms().wrapping_sub(start_ms) < CPU_BUSY_MS {
        core::hint::spin_loop();
    }

    let elapsed_ms = uptime_now_ms().wrapping_sub(start_ms);
    let end_refresh_count = M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Acquire);
    M7_WATCHDOG_CPU_BUSY_END_REFRESH_COUNT.store(end_refresh_count, Ordering::Relaxed);
    M7_WATCHDOG_CPU_BUSY_ELAPSED_MS.store(elapsed_ms, Ordering::Relaxed);
    let passed = elapsed_ms >= CPU_BUSY_MS
        && elapsed_ms < watchdog_contract::TASK_DEADLINE_MS
        && end_refresh_count.wrapping_sub(start_refresh_count) > 0;
    M7_WATCHDOG_CPU_BUSY_PASSED.store(u32::from(passed), Ordering::Release);
    assert!(passed);
}
