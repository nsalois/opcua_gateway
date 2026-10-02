//! Task check-ins, health snapshots, and IWDG supervision.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "product")]
use core::future::Future;

#[cfg(feature = "product")]
use embassy_futures::select::{select, Either};
#[cfg(feature = "product")]
use embassy_time::with_timeout;
#[cfg(feature = "product")]
use embassy_time::TimeoutError;
use embassy_time::{Duration, Ticker, Timer};
use opta_gateway_contracts::last_fault::LastFaultReason;
use opta_gateway_contracts::watchdog as watchdog_contract;
use opta_gateway_contracts::watchdog::{
    FlashMaintenanceLeaveOutcome, FlashMaintenanceMonitorAction, FlashMaintenanceState,
    WatchdogSlot,
};

use crate::fault::persist_last_fault;
#[cfg(feature = "diagnostic-stall-usb-control")]
use crate::probes::M7_INDUCED_HANG_PROBE;
use crate::probes::{
    M7_EARLY_IWDG_FAILURE_PROBE, M7_WATCHDOG_ARMED, M7_WATCHDOG_LAST_KICK_MS,
    M7_WATCHDOG_OBSERVED_STALE_SLOTS, M7_WATCHDOG_PUBLIC_FRESH_MASK, M7_WATCHDOG_REFRESH_COUNT,
    M7_WATCHDOG_STALE_MASK,
};
#[cfg(feature = "product")]
use crate::probes::{
    M7_USB_BUS_EVENT_COUNT, M7_USB_BUS_EVENT_MASK, M7_USB_CHECKIN_COUNT,
    M7_USB_CONTROL_SETUP_COUNT, M7_USB_LAST_BUS_EVENT,
};
use crate::timebase::{uptime_now_ms, uptime_now_ms_u64};

#[cfg(any(
    feature = "diagnostic-suppress-net-runner-checkin",
    feature = "diagnostic-suppress-main-heartbeat-checkin",
    feature = "diagnostic-suppress-net-status-checkin",
    feature = "diagnostic-suppress-opcua-listener0-checkin",
    feature = "diagnostic-stall-usb-control",
    feature = "diagnostic-watchdog-cpu-busy",
    feature = "diagnostic-pre-clock-stall",
))]
mod fault_injection;

#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
pub(crate) use fault_injection::run_cpu_busy_preemption_probe;
#[cfg(feature = "diagnostic-pre-clock-stall")]
pub(crate) use fault_injection::run_pre_clock_stall_probe;

pub(crate) const WATCHDOG_TASK_DEADLINE: Duration =
    Duration::from_millis(watchdog_contract::TASK_DEADLINE_MS as u64 / 2);
#[cfg(feature = "product")]
const WATCHDOG_CHECKIN_INTERVAL: Duration = Duration::from_millis(250);
const LSI_READY_WAIT_BOUND: u32 = 2_000_000;
const RCC_GCR_WW1RSC: u32 = 1 << 0;
const RCC_CSR_LSION: u32 = 1 << 0;
const IWDG_UPDATE_PENDING_MASK: u32 = 0b111;
const TASK_CHECKIN_COUNT: usize = watchdog_contract::WATCHDOG_SLOT_COUNT;
#[cfg(not(feature = "product"))]
static TASK_CHECKINS_MS: [AtomicU32; TASK_CHECKIN_COUNT] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
#[cfg(feature = "product")]
static TASK_CHECKINS_MS: [AtomicU32; TASK_CHECKIN_COUNT] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
#[cfg(feature = "product")]
static TASK_EXEMPT_MASK: AtomicU32 = AtomicU32::new(WatchdogSlot::UsbDevice.mask());
static FLASH_MAINTENANCE_DEPTH: AtomicU32 = AtomicU32::new(0);
static FLASH_MAINTENANCE_START_MS: AtomicU32 = AtomicU32::new(0);

fn published_flash_maintenance_state() -> FlashMaintenanceState {
    // Entry stores the outermost start before release-publishing nonzero depth.
    // Acquire depth first so an active observation also sees that start value.
    let depth = FLASH_MAINTENANCE_DEPTH.load(Ordering::Acquire);
    let outermost_start_ms = FLASH_MAINTENANCE_START_MS.load(Ordering::Relaxed);
    FlashMaintenanceState::from_published_parts(depth, outermost_start_ms)
}

fn publish_flash_maintenance_state(state: FlashMaintenanceState) {
    // Publish the start first and active depth last. Entry/leave call this in a
    // critical section, so TIM7 can observe only the old or complete new pair.
    FLASH_MAINTENANCE_START_MS.store(state.outermost_start_ms(), Ordering::Relaxed);
    FLASH_MAINTENANCE_DEPTH.store(state.depth(), Ordering::Release);
}

/// Nest-safe RAII scope for one blocking internal-Flash erase or write.
pub(crate) struct FlashMaintenanceGuard;

impl FlashMaintenanceGuard {
    pub(crate) fn enter() -> Self {
        critical_section::with(|_| {
            let now_ms = uptime_now_ms();
            let next = published_flash_maintenance_state().enter(now_ms);
            publish_flash_maintenance_state(next);
        });
        Self
    }
}

impl Drop for FlashMaintenanceGuard {
    fn drop(&mut self) {
        critical_section::with(|_| {
            let now_ms = uptime_now_ms();
            let current = published_flash_maintenance_state();
            let outermost_start_ms = current.outermost_start_ms();
            let transition = current.leave(now_ms);
            if let FlashMaintenanceLeaveOutcome::CompletedWithinBound { excluded_ms } =
                transition.outcome
            {
                // Only deadlines live at outer entry are shifted. A stale or
                // subsequently published check-in remains byte-for-byte intact.
                for slot in TASK_CHECKINS_MS.iter() {
                    let last_checkin_ms = slot.load(Ordering::Relaxed);
                    slot.store(
                        watchdog_contract::rebase_live_checkin_after_maintenance(
                            last_checkin_ms,
                            watchdog_contract::TASK_DEADLINE_MS,
                            outermost_start_ms,
                            excluded_ms,
                        ),
                        Ordering::Relaxed,
                    );
                }
            }
            // At/beyond the bound this clears only the active state. Existing
            // timestamps and stale/fault evidence are deliberately untouched.
            // Nested leave publishes a still-nonzero depth and the same start.
            publish_flash_maintenance_state(transition.state);
        });
    }
}

pub(crate) fn initialize_task_checkins(now_ms: u32) {
    for slot in TASK_CHECKINS_MS.iter() {
        slot.store(now_ms, Ordering::Relaxed);
    }
    #[cfg(feature = "product")]
    TASK_EXEMPT_MASK.store(WatchdogSlot::UsbDevice.mask(), Ordering::Relaxed);
    M7_WATCHDOG_STALE_MASK.store(0, Ordering::Relaxed);
    M7_WATCHDOG_OBSERVED_STALE_SLOTS.store(0, Ordering::Relaxed);
    M7_WATCHDOG_PUBLIC_FRESH_MASK.store(watchdog_contract::ALL_TASKS_MASK, Ordering::Relaxed);
}

fn record_task_checkin(task: WatchdogSlot, now_ms: u32) -> bool {
    #[cfg(any(
        feature = "diagnostic-suppress-net-runner-checkin",
        feature = "diagnostic-suppress-main-heartbeat-checkin",
        feature = "diagnostic-suppress-net-status-checkin",
        feature = "diagnostic-suppress-opcua-listener0-checkin",
    ))]
    if fault_injection::suppress_checkin(task, now_ms) {
        return false;
    }
    TASK_CHECKINS_MS[task.index()].store(now_ms, Ordering::Relaxed);
    #[cfg(feature = "product")]
    if task == WatchdogSlot::UsbConsole {
        M7_USB_CHECKIN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    true
}

pub(crate) fn task_checkin(task: WatchdogSlot) {
    let _ = record_task_checkin(task, uptime_now_ms());
}

#[cfg(feature = "product")]
pub(crate) fn task_progress_expected(task: WatchdogSlot) {
    let task_mask = task.mask();
    if TASK_EXEMPT_MASK.load(Ordering::Relaxed) & task_mask != 0 {
        let _ = record_task_checkin(task, uptime_now_ms());
        // Publish normal resumed progress before making the slot non-exempt.
        // slot_checkin() acquire-loads this mask before reading the timestamp,
        // so it cannot classify that progress using the pre-resume value. A
        // diagnostic induced-hang build still suppresses the store on purpose.
        TASK_EXEMPT_MASK.fetch_and(!task_mask, Ordering::Release);
    }
}

#[cfg(feature = "product")]
pub(crate) fn task_progress_complete(task: WatchdogSlot) {
    if record_task_checkin(task, uptime_now_ms()) {
        TASK_EXEMPT_MASK.fetch_or(task.mask(), Ordering::Relaxed);
    }
}

#[cfg(feature = "product")]
pub(crate) fn net_runner_driver_progress() {
    task_checkin(WatchdogSlot::NetRunner);
}

#[cfg(feature = "product")]
pub(crate) fn usb_device_progress_expected() {
    task_progress_expected(WatchdogSlot::UsbDevice);
}

#[cfg(feature = "product")]
pub(crate) fn usb_device_progress_complete() {
    #[cfg(feature = "diagnostic-stall-usb-control")]
    if M7_INDUCED_HANG_PROBE.load(Ordering::Relaxed) & WatchdogSlot::UsbDevice.mask() != 0 {
        return;
    }
    task_progress_complete(WatchdogSlot::UsbDevice);
}

#[cfg(feature = "product")]
pub(crate) fn usb_device_bus_event(event: u32) {
    M7_USB_LAST_BUS_EVENT.store(event, Ordering::Relaxed);
    M7_USB_BUS_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    if (1..=5).contains(&event) {
        M7_USB_BUS_EVENT_MASK.fetch_or(1u32 << (event - 1), Ordering::Relaxed);
    }
}

#[cfg(feature = "product")]
pub(crate) fn usb_device_control_setup() {
    M7_USB_CONTROL_SETUP_COUNT.fetch_add(1, Ordering::Relaxed);
    task_progress_expected(WatchdogSlot::UsbDevice);
    #[cfg(feature = "diagnostic-stall-usb-control")]
    if uptime_now_ms() >= fault_injection::CHECKIN_SUPPRESSION_AFTER_MS {
        M7_INDUCED_HANG_PROBE.store(WatchdogSlot::UsbDevice.mask(), Ordering::Relaxed);
    }
}

#[cfg(feature = "product")]
pub(crate) async fn task_watchdog_timeout<F>(
    task: WatchdogSlot,
    timeout: Duration,
    future: F,
) -> Result<F::Output, TimeoutError>
where
    F: Future,
{
    let guarded = with_timeout(timeout, future);
    let mut guarded = core::pin::pin!(guarded);
    loop {
        task_checkin(task);
        match select(guarded.as_mut(), Timer::after(WATCHDOG_CHECKIN_INTERVAL)).await {
            Either::First(result) => return result,
            Either::Second(()) => {}
        }
    }
}

fn slot_checkin(task: WatchdogSlot) -> watchdog_contract::WatchdogSlotCheckin {
    #[cfg(feature = "product")]
    // Pairs with task_progress_expected()'s release-clear. Read the mask first
    // so a non-exempt observation makes the preceding timestamp store visible.
    let exempt = TASK_EXEMPT_MASK.load(Ordering::Acquire) & task.mask() != 0;
    let checkin = watchdog_contract::WatchdogSlotCheckin::new(
        task,
        TASK_CHECKINS_MS[task.index()].load(Ordering::Relaxed),
        watchdog_contract::TASK_DEADLINE_MS,
    );
    #[cfg(feature = "product")]
    if exempt {
        return checkin.exempt();
    }
    checkin
}

fn watchdog_snapshot(now_ms: u32) -> watchdog_contract::ClassifiedWatchdogSnapshot {
    #[cfg(not(feature = "product"))]
    let checkins = [
        slot_checkin(WatchdogSlot::MainHeartbeat),
        slot_checkin(WatchdogSlot::MdnsResponder),
        slot_checkin(WatchdogSlot::NetStatus),
        slot_checkin(WatchdogSlot::UsbConsole),
    ];
    #[cfg(feature = "product")]
    let checkins = [
        slot_checkin(WatchdogSlot::MainHeartbeat),
        slot_checkin(WatchdogSlot::MdnsResponder),
        slot_checkin(WatchdogSlot::NetStatus),
        slot_checkin(WatchdogSlot::UsbConsole),
        slot_checkin(WatchdogSlot::BuchiTlsClient),
        slot_checkin(WatchdogSlot::OpcUaListener0),
        slot_checkin(WatchdogSlot::OpcUaListener1),
        slot_checkin(WatchdogSlot::OpcUaListener2),
        slot_checkin(WatchdogSlot::NetRunner),
        slot_checkin(WatchdogSlot::UsbDevice),
    ];
    watchdog_contract::classify_slots(now_ms, &checkins)
}

#[cfg(feature = "product")]
pub(crate) fn snapshot_single_core_health() -> opta_runtime::SingleCoreHealthSnapshot {
    let now_ms_u64 = uptime_now_ms_u64();
    let now_ms = now_ms_u64 as u32;
    let uptime_seconds = opta_gateway_contracts::uptime::seconds_from_monotonic_ms(now_ms_u64);
    let iwdg_last_kick_age_ms = if M7_WATCHDOG_ARMED.load(Ordering::Relaxed) != 0 {
        Some(now_ms.wrapping_sub(M7_WATCHDOG_LAST_KICK_MS.load(Ordering::Relaxed)))
    } else {
        None
    };
    let classified = watchdog_snapshot(now_ms);

    opta_runtime::SingleCoreHealthSnapshot::new(
        uptime_seconds,
        iwdg_last_kick_age_ms,
        M7_WATCHDOG_STALE_MASK.load(Ordering::Relaxed),
        classified.public_registered_mask,
        classified.public_fresh_mask,
        watchdog_contract::TASK_DEADLINE_MS,
        classified.public_age_ms,
    )
}

fn configure_watchdog_reset_errata_guard() -> bool {
    // SAFETY: RM0399 Rev 4 §§9.4.4 and 9.7.36 define IWDG1 as a system reset
    // source and RCC_GCR.WW1RSC bit 0 specifically as the WWDG1 reset-scope
    // control. ES0445 Rev 6 §2.3.1 nevertheless requires setting WW1RSC as the
    // documented workaround for an AXI lock when a watchdog reset is limited
    // to CPU1. This guard does not claim to configure IWDG1 reset scope. The
    // RMW preserves BOOT_C2 and every other bit, then reads WW1RSC back; no
    // option byte, QSPI, backup register, or flash is touched.
    // SAFETY: the volatile RMW is limited to the documented RCC_GCR address.
    unsafe {
        const RCC_GCR: *mut u32 = 0x5802_44A0 as *mut u32;
        RCC_GCR.write_volatile(RCC_GCR.read_volatile() | RCC_GCR_WW1RSC);
        cortex_m::asm::dsb();
        RCC_GCR.read_volatile() & RCC_GCR_WW1RSC != 0
    }
}

fn clear_inherited_iwdg1_debug_freeze() -> bool {
    // OpenOCD's STM32H7 examine hook sets DBGMCU_APB4FZR1.IWDG1 so the
    // watchdog stops while a core is halted. That debug state survives the
    // debugger-driven reset used to launch the installed image. Production
    // startup must not inherit a paused watchdog, so clear only the documented
    // IWDG1 freeze bit and prove the readback before starting IWDG1.
    let freeze = stm32_metapac::DBGMCU.apb4fzr1();
    freeze.modify(|value| value.set_iwdg1(false));
    cortex_m::asm::dsb();
    !freeze.read().iwdg1()
}

fn enable_lsi_and_wait_ready() -> bool {
    // SAFETY: RCC_CSR is the STM32H747 RCC clock control/status register
    // (RM0399 Rev 4 §§9.5.2 and 9.7.26). LSION bit 0 may be set by software;
    // LSIRDY bit 1 is read-only and does not assert until the LSI clock that
    // feeds IWDG1 is stable. The bounded poll is performed before any IWDG
    // configuration write, and both enable and readiness are read back.
    // SAFETY: the volatile accesses are limited to the documented RCC_CSR.
    unsafe {
        const RCC_CSR: *mut u32 = 0x5802_4474 as *mut u32;
        RCC_CSR.write_volatile(RCC_CSR.read_volatile() | RCC_CSR_LSION);
        cortex_m::asm::dsb();
        for _ in 0..LSI_READY_WAIT_BOUND {
            let observation = RCC_CSR.read_volatile();
            if watchdog_contract::lsi_observation_is_ready(observation) {
                cortex_m::asm::dsb();
                return true;
            }
        }
    }
    false
}

/// Arm and validate the independent watchdog before config or clock startup.
///
/// This routine deliberately does not use the TIM2-backed uptime clock. The
/// post-clock telemetry handoff is [`iwdg1_start_uptime_telemetry`]. A `false`
/// result means startup must not continue and `M7_WATCHDOG_ARMED` remains zero.
pub(crate) fn iwdg1_arm_10s_early() -> bool {
    M7_WATCHDOG_ARMED.store(0, Ordering::Relaxed);
    M7_EARLY_IWDG_FAILURE_PROBE.store(0, Ordering::Relaxed);
    if !clear_inherited_iwdg1_debug_freeze() {
        M7_EARLY_IWDG_FAILURE_PROBE.store(
            watchdog_contract::EARLY_IWDG_FAILURE_DEBUG_FREEZE,
            Ordering::Relaxed,
        );
        return false;
    }
    if !configure_watchdog_reset_errata_guard() {
        M7_EARLY_IWDG_FAILURE_PROBE.store(
            watchdog_contract::EARLY_IWDG_FAILURE_RESET_SCOPE,
            Ordering::Relaxed,
        );
        return false;
    }
    if !enable_lsi_and_wait_ready() {
        M7_EARLY_IWDG_FAILURE_PROBE.store(
            watchdog_contract::EARLY_IWDG_FAILURE_LSI_STATE,
            Ordering::Relaxed,
        );
        return false;
    }

    // SAFETY: IWDG1 is at 0x5800_4800 for STM32H747 CM7 (stm32-metapac and
    // RM0399 Rev 4 §§48.3.3 and 48.4.1-5). The no-window sequence starts IWDG
    // with 0xCCCC, unlocks PR/RLR with 0x5555, waits for SR update bits to
    // clear, validates PR/RLR only after PVU/RVU clear, confirms default WINR,
    // then refreshes with 0xAAAA. The exact /256 and 1249 values retain the
    // nominal `(1249 + 1) * 256 / 32000 = 10 s` contract.
    // SAFETY: accesses follow that documented IWDG1 sequence and register map.
    let validated = unsafe {
        const IWDG1_KR: *mut u32 = 0x5800_4800 as *mut u32;
        const IWDG1_PR: *mut u32 = 0x5800_4804 as *mut u32;
        const IWDG1_RLR: *mut u32 = 0x5800_4808 as *mut u32;
        const IWDG1_SR: *const u32 = 0x5800_480C as *const u32;
        const IWDG1_WINR: *const u32 = 0x5800_4810 as *const u32;
        const RCC_GCR: *const u32 = 0x5802_44A0 as *const u32;
        const RCC_CSR: *const u32 = 0x5802_4474 as *const u32;

        IWDG1_KR.write_volatile(0xCCCC);
        IWDG1_KR.write_volatile(0x5555);
        IWDG1_PR.write_volatile(watchdog_contract::IWDG_PR_DIV256_CODE);
        IWDG1_RLR.write_volatile(watchdog_contract::IWDG_RELOAD_10S_DIV256);

        // ST's H7 HAL documents that these flags can take up to five LSI
        // periods divided by the active IWDG prescaler to clear. A fixed
        // number of CPU reads is therefore not a time bound and failed on the
        // Opta at 100_000 reads. IWDG1 is already running here, so a peripheral
        // that never completes the update autonomously resets the system. Do
        // not refresh inside this loop or a stuck update could hang forever.
        let update_status = loop {
            let update_status = IWDG1_SR.read_volatile();
            if update_status & IWDG_UPDATE_PENDING_MASK == 0 {
                break update_status;
            }
        };

        let readback = watchdog_contract::EarlyIwdgReadback {
            rcc_gcr: RCC_GCR.read_volatile(),
            rcc_csr: RCC_CSR.read_volatile(),
            iwdg_sr: update_status,
            iwdg_pr: IWDG1_PR.read_volatile(),
            iwdg_rlr: IWDG1_RLR.read_volatile(),
            iwdg_winr: IWDG1_WINR.read_volatile(),
        };
        let failure_mask = watchdog_contract::early_iwdg_failure_mask(readback);
        if failure_mask != 0 {
            M7_EARLY_IWDG_FAILURE_PROBE.store(failure_mask, Ordering::Relaxed);
            false
        } else {
            IWDG1_KR.write_volatile(0xAAAA);
            cortex_m::asm::dsb();
            true
        }
    };

    if !validated {
        return false;
    }

    // Publish readiness last. Readers can never observe `armed == 1` before
    // the reset errata guard, stable LSI, cleared update state, exact PR/RLR,
    // disabled window, and final counter reload have all succeeded.
    M7_WATCHDOG_ARMED.store(1, Ordering::Release);
    true
}

/// Start TIM2-relative watchdog health telemetry after clock initialization.
pub(crate) fn iwdg1_start_uptime_telemetry() {
    iwdg1_refresh();
    let now_ms = uptime_now_ms();
    M7_WATCHDOG_LAST_KICK_MS.store(now_ms, Ordering::Relaxed);
}

pub(crate) fn iwdg1_refresh() {
    // SAFETY: writing 0xAAAA to IWDG_KR is the documented IWDG counter reload
    // key (RM0399 §48.3.3). No other IWDG register is modified by refresh.
    unsafe {
        const IWDG1_KR: *mut u32 = 0x5800_4800 as *mut u32;
        IWDG1_KR.write_volatile(0xAAAA);
    }
}

#[embassy_executor::task]
pub(crate) async fn watchdog_monitor_task() -> ! {
    let mut ticker = Ticker::every(Duration::from_millis(
        watchdog_contract::MONITOR_INTERVAL_MS as u64,
    ));
    loop {
        ticker.next().await;
        let now_ms_u64 = uptime_now_ms_u64();
        let now_ms = now_ms_u64 as u32;
        if published_flash_maintenance_state().monitor_action(now_ms)
            == FlashMaintenanceMonitorAction::RefreshAndSkipClassification
        {
            // Do not classify or rewrite any stale/fault evidence while the
            // exact pure contract says the active outer scope is under bound.
            iwdg1_refresh();
            M7_WATCHDOG_LAST_KICK_MS.store(now_ms, Ordering::Relaxed);
            M7_WATCHDOG_REFRESH_COUNT.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let snapshot = watchdog_snapshot(now_ms);
        M7_WATCHDOG_OBSERVED_STALE_SLOTS
            .store(snapshot.observed_stale_slots_mask, Ordering::Relaxed);
        M7_WATCHDOG_PUBLIC_FRESH_MASK.store(snapshot.public_fresh_mask, Ordering::Relaxed);
        M7_WATCHDOG_STALE_MASK.store(snapshot.public_reset_critical_stale_mask, Ordering::Relaxed);
        if snapshot.all_reset_critical_fresh {
            iwdg1_refresh();
            M7_WATCHDOG_LAST_KICK_MS.store(now_ms, Ordering::Relaxed);
            M7_WATCHDOG_REFRESH_COUNT.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        persist_last_fault(
            LastFaultReason::IwdgReset,
            opta_gateway_contracts::uptime::seconds_from_monotonic_ms(now_ms_u64),
            snapshot.public_reset_critical_stale_mask,
        );
        loop {
            Timer::after_millis(1_000).await;
        }
    }
}
