// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use crate::cm4::RCC_GCR_WW1RSC;

pub const IWDG_TIMEOUT_MS: u32 = 10_000;
pub const MONITOR_INTERVAL_MS: u32 = 250;
pub const TASK_DEADLINE_MS: u32 = 2_000;
/// Maximum interval for which the interrupt watchdog monitor may suspend task
/// classification around one blocking internal-Flash operation.
///
/// ST DS12930 Rev 3, Table 55 gives a 4 s maximum for one 128-Kbyte sector
/// erase at x8 parallelism. The vendored Embassy H7 blocking writer selects
/// `PSIZE=2` (x32), but its sector-erase path does not set PSIZE and therefore
/// leaves the existing legal value unchanged. Five seconds covers the worst
/// legal erase setting plus one second of margin. DS12930 Rev 3, Table 48
/// bounds LSI at 33.6 kHz, so the nominal ten-second reload is still about
/// 9.52 s at the fastest specified watchdog clock and the maintenance bound
/// remains below it.
pub const FLASH_MAINTENANCE_BOUND_MS: u32 = 5_000;
pub const LSI_HZ_NOMINAL: u32 = 32_000;
pub const IWDG_RELOAD_MAX: u32 = 0x0FFF;
pub const IWDG_WINDOW_DISABLED: u32 = IWDG_RELOAD_MAX;
pub const IWDG_PR_DIV256_CODE: u32 = 6;
pub const IWDG_PR_DIV256: u32 = 256;

/// IWDG1 prescaler/reload chosen from RM0399 IWDG math using 32 kHz
/// nominal LSI. Effective nominal timeout:
/// `(1249 + 1) * 256 / 32000 = 10 s`.
pub const IWDG_RELOAD_10S_DIV256: u32 = 1_249;

const _: () = assert!(FLASH_MAINTENANCE_BOUND_MS > TASK_DEADLINE_MS);
const _: () = assert!(FLASH_MAINTENANCE_BOUND_MS < IWDG_TIMEOUT_MS);

/// Published, nest-safe state for one or more blocking internal-Flash scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlashMaintenanceState {
    depth: u32,
    outermost_start_ms: u32,
}

/// Watchdog action selected from the exact state published by firmware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashMaintenanceMonitorAction {
    /// Run the ordinary task-staleness and containment path.
    OrdinaryContainment,
    /// Refresh IWDG and leave all stale evidence untouched for this monitor tick.
    RefreshAndSkipClassification,
}

/// Outcome of leaving one nested Flash-maintenance scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashMaintenanceLeaveOutcome {
    /// Another enclosing scope remains active, so its start time remains authoritative.
    NestedStillActive,
    /// The outermost scope completed before the exclusive bound.
    CompletedWithinBound { excluded_ms: u32 },
    /// The outermost scope completed at or after the bound.
    CompletedAtOrBeyondBound { elapsed_ms: u32 },
}

/// Pure state transition returned by [`FlashMaintenanceState::leave`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlashMaintenanceLeave {
    pub state: FlashMaintenanceState,
    pub outcome: FlashMaintenanceLeaveOutcome,
}

impl FlashMaintenanceState {
    /// Construct the inactive startup state.
    pub const fn inactive() -> Self {
        Self {
            depth: 0,
            outermost_start_ms: 0,
        }
    }

    /// Reconstruct an interrupt-safe state snapshot from firmware atomics.
    pub const fn from_published_parts(depth: u32, outermost_start_ms: u32) -> Self {
        Self {
            depth,
            outermost_start_ms,
        }
    }

    pub const fn depth(self) -> u32 {
        self.depth
    }

    pub const fn outermost_start_ms(self) -> u32 {
        self.outermost_start_ms
    }

    /// Enter one scope, recording `now_ms` only for the outermost entry.
    pub const fn enter(self, now_ms: u32) -> Self {
        let depth = match self.depth.checked_add(1) {
            Some(depth) => depth,
            None => panic!("Flash-maintenance nesting overflow"),
        };
        Self {
            depth,
            outermost_start_ms: if self.depth == 0 {
                now_ms
            } else {
                self.outermost_start_ms
            },
        }
    }

    /// Select the monitor action with wrap-safe elapsed time.
    ///
    /// The bound is exclusive: at exactly five seconds ordinary containment
    /// resumes and the monitor must not perform a maintenance refresh.
    pub const fn monitor_action(self, now_ms: u32) -> FlashMaintenanceMonitorAction {
        if self.depth != 0
            && now_ms.wrapping_sub(self.outermost_start_ms) < FLASH_MAINTENANCE_BOUND_MS
        {
            FlashMaintenanceMonitorAction::RefreshAndSkipClassification
        } else {
            FlashMaintenanceMonitorAction::OrdinaryContainment
        }
    }

    /// Leave one scope. Only the outermost leave reports a completion outcome.
    pub const fn leave(self, now_ms: u32) -> FlashMaintenanceLeave {
        assert!(self.depth != 0, "unbalanced Flash-maintenance leave");
        if self.depth > 1 {
            return FlashMaintenanceLeave {
                state: Self {
                    depth: self.depth - 1,
                    outermost_start_ms: self.outermost_start_ms,
                },
                outcome: FlashMaintenanceLeaveOutcome::NestedStillActive,
            };
        }

        let elapsed_ms = now_ms.wrapping_sub(self.outermost_start_ms);
        FlashMaintenanceLeave {
            state: Self::inactive(),
            outcome: if elapsed_ms < FLASH_MAINTENANCE_BOUND_MS {
                FlashMaintenanceLeaveOutcome::CompletedWithinBound {
                    excluded_ms: elapsed_ms,
                }
            } else {
                FlashMaintenanceLeaveOutcome::CompletedAtOrBeyondBound { elapsed_ms }
            },
        }
    }
}

/// Exclude one proven-under-bound maintenance interval from a live deadline.
///
/// Only a check-in that was still live at the outermost entry is advanced.
/// Pre-existing stale evidence and a timestamp published after entry are left
/// byte-for-byte unchanged.
pub const fn rebase_live_checkin_after_maintenance(
    last_checkin_ms: u32,
    deadline_ms: u32,
    maintenance_start_ms: u32,
    excluded_ms: u32,
) -> u32 {
    if maintenance_start_ms.wrapping_sub(last_checkin_ms) <= deadline_ms {
        last_checkin_ms.wrapping_add(excluded_ms)
    } else {
        last_checkin_ms
    }
}

const RCC_CSR_LSION: u32 = 1 << 0;
const RCC_CSR_LSIRDY: u32 = 1 << 1;
const IWDG_UPDATE_PENDING_MASK: u32 = 0b111;
const IWDG_PR_MASK: u32 = 0b111;
const IWDG_RLR_MASK: u32 = IWDG_RELOAD_MAX;

pub const EARLY_IWDG_FAILURE_RESET_SCOPE: u32 = 1 << 0;
pub const EARLY_IWDG_FAILURE_LSI_STATE: u32 = 1 << 1;
pub const EARLY_IWDG_FAILURE_UPDATE_PENDING: u32 = 1 << 2;
pub const EARLY_IWDG_FAILURE_PRESCALER: u32 = 1 << 3;
pub const EARLY_IWDG_FAILURE_RELOAD: u32 = 1 << 4;
pub const EARLY_IWDG_FAILURE_WINDOW: u32 = 1 << 5;
pub const EARLY_IWDG_FAILURE_DEBUG_FREEZE: u32 = 1 << 30;

/// Return whether one `RCC_CSR` observation confirms enabled, stable LSI.
pub const fn lsi_observation_is_ready(rcc_csr: u32) -> bool {
    rcc_csr & (RCC_CSR_LSION | RCC_CSR_LSIRDY) == (RCC_CSR_LSION | RCC_CSR_LSIRDY)
}

/// Register values captured after the early IWDG1 configuration transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyIwdgReadback {
    /// `RCC_GCR`, including the full-system watchdog reset-scope bit.
    pub rcc_gcr: u32,
    /// `RCC_CSR`, including LSI enable and ready state.
    pub rcc_csr: u32,
    /// `IWDG_SR`, whose configuration-update bits must all be clear.
    pub iwdg_sr: u32,
    /// `IWDG_PR`, containing the nominal ten-second prescaler code.
    pub iwdg_pr: u32,
    /// `IWDG_RLR`, containing the nominal ten-second reload value.
    pub iwdg_rlr: u32,
    /// `IWDG_WINR`, which must retain the disabled-window value.
    pub iwdg_winr: u32,
}

/// Return one bit per failed early-IWDG register-state requirement.
pub const fn early_iwdg_failure_mask(readback: EarlyIwdgReadback) -> u32 {
    let mut failures = 0;
    if readback.rcc_gcr & RCC_GCR_WW1RSC == 0 {
        failures |= EARLY_IWDG_FAILURE_RESET_SCOPE;
    }
    if !lsi_observation_is_ready(readback.rcc_csr) {
        failures |= EARLY_IWDG_FAILURE_LSI_STATE;
    }
    if readback.iwdg_sr & IWDG_UPDATE_PENDING_MASK != 0 {
        failures |= EARLY_IWDG_FAILURE_UPDATE_PENDING;
    }
    if readback.iwdg_pr & IWDG_PR_MASK != IWDG_PR_DIV256_CODE {
        failures |= EARLY_IWDG_FAILURE_PRESCALER;
    }
    if readback.iwdg_rlr & IWDG_RLR_MASK != IWDG_RELOAD_10S_DIV256 {
        failures |= EARLY_IWDG_FAILURE_RELOAD;
    }
    if readback.iwdg_winr & IWDG_RLR_MASK != IWDG_WINDOW_DISABLED {
        failures |= EARLY_IWDG_FAILURE_WINDOW;
    }
    failures
}

/// Validate the complete register state required before publishing IWDG1 armed.
pub const fn early_iwdg_readback_valid(readback: EarlyIwdgReadback) -> bool {
    early_iwdg_failure_mask(readback) == 0
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskId {
    MainHeartbeat = 0,
    MdnsResponder = 1,
    NetStatus = 2,
    UsbConsole = 3,
    #[cfg(feature = "product")]
    BuchiTlsClient = 4,
    #[cfg(feature = "product")]
    OpcUaServer = 5,
}

impl TaskId {
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::MainHeartbeat),
            1 => Some(Self::MdnsResponder),
            2 => Some(Self::NetStatus),
            3 => Some(Self::UsbConsole),
            #[cfg(feature = "product")]
            4 => Some(Self::BuchiTlsClient),
            #[cfg(feature = "product")]
            5 => Some(Self::OpcUaServer),
            _ => None,
        }
    }

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn mask(self) -> u32 {
        1u32 << (self as u8)
    }
}

#[cfg(not(feature = "product"))]
pub const TASK_COUNT: usize = 4;
#[cfg(feature = "product")]
pub const TASK_COUNT: usize = 6;

#[cfg(not(feature = "product"))]
pub const ALL_TASKS_MASK: u32 = TaskId::MainHeartbeat.mask()
    | TaskId::MdnsResponder.mask()
    | TaskId::NetStatus.mask()
    | TaskId::UsbConsole.mask();
#[cfg(feature = "product")]
pub const ALL_TASKS_MASK: u32 = TaskId::MainHeartbeat.mask()
    | TaskId::MdnsResponder.mask()
    | TaskId::NetStatus.mask()
    | TaskId::UsbConsole.mask()
    | TaskId::BuchiTlsClient.mask()
    | TaskId::OpcUaServer.mask();

/// Internal execution-unit identity. These slots project onto the stable
/// public [`TaskId`] surface but are classified independently for IWDG reset.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogSlot {
    MainHeartbeat = 0,
    MdnsResponder = 1,
    NetStatus = 2,
    UsbConsole = 3,
    #[cfg(feature = "product")]
    BuchiTlsClient = 4,
    #[cfg(feature = "product")]
    OpcUaListener0 = 5,
    #[cfg(feature = "product")]
    OpcUaListener1 = 6,
    #[cfg(feature = "product")]
    OpcUaListener2 = 7,
    #[cfg(feature = "product")]
    NetRunner = 8,
    #[cfg(feature = "product")]
    UsbDevice = 9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionClass {
    ResetCritical,
    HealthOnly,
}

impl WatchdogSlot {
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::MainHeartbeat),
            1 => Some(Self::MdnsResponder),
            2 => Some(Self::NetStatus),
            3 => Some(Self::UsbConsole),
            #[cfg(feature = "product")]
            4 => Some(Self::BuchiTlsClient),
            #[cfg(feature = "product")]
            5 => Some(Self::OpcUaListener0),
            #[cfg(feature = "product")]
            6 => Some(Self::OpcUaListener1),
            #[cfg(feature = "product")]
            7 => Some(Self::OpcUaListener2),
            #[cfg(feature = "product")]
            8 => Some(Self::NetRunner),
            #[cfg(feature = "product")]
            9 => Some(Self::UsbDevice),
            _ => None,
        }
    }

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn mask(self) -> u32 {
        1u32 << (self as u8)
    }

    pub const fn public_task(self) -> TaskId {
        match self {
            Self::MainHeartbeat => TaskId::MainHeartbeat,
            Self::MdnsResponder => TaskId::MdnsResponder,
            Self::NetStatus => TaskId::NetStatus,
            Self::UsbConsole => TaskId::UsbConsole,
            #[cfg(feature = "product")]
            Self::BuchiTlsClient => TaskId::BuchiTlsClient,
            #[cfg(feature = "product")]
            Self::OpcUaListener0 | Self::OpcUaListener1 | Self::OpcUaListener2 => {
                TaskId::OpcUaServer
            }
            #[cfg(feature = "product")]
            Self::NetRunner => TaskId::NetStatus,
            #[cfg(feature = "product")]
            Self::UsbDevice => TaskId::UsbConsole,
        }
    }

    pub const fn supervision_class(self) -> SupervisionClass {
        match self {
            Self::MainHeartbeat | Self::NetStatus | Self::UsbConsole => {
                SupervisionClass::HealthOnly
            }
            Self::MdnsResponder => SupervisionClass::ResetCritical,
            #[cfg(feature = "product")]
            Self::UsbDevice => SupervisionClass::HealthOnly,
            #[cfg(feature = "product")]
            Self::BuchiTlsClient
            | Self::OpcUaListener0
            | Self::OpcUaListener1
            | Self::OpcUaListener2
            | Self::NetRunner => SupervisionClass::ResetCritical,
        }
    }
}

#[cfg(not(feature = "product"))]
pub const WATCHDOG_SLOT_COUNT: usize = 4;
#[cfg(feature = "product")]
pub const WATCHDOG_SLOT_COUNT: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogSlotCheckin {
    pub slot: WatchdogSlot,
    pub last_checkin_ms: u32,
    pub deadline_ms: u32,
    pub exempt: bool,
}

impl WatchdogSlotCheckin {
    pub const fn new(slot: WatchdogSlot, last_checkin_ms: u32, deadline_ms: u32) -> Self {
        Self {
            slot,
            last_checkin_ms,
            deadline_ms,
            exempt: false,
        }
    }

    pub const fn exempt(mut self) -> Self {
        self.exempt = true;
        self
    }

    pub const fn age_ms(self, now_ms: u32) -> u32 {
        now_ms.wrapping_sub(self.last_checkin_ms)
    }

    pub const fn is_fresh(self, now_ms: u32) -> bool {
        self.exempt || self.age_ms(now_ms) <= self.deadline_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassifiedWatchdogSnapshot {
    pub now_ms: u32,
    pub observed_stale_slots_mask: u32,
    pub reset_critical_stale_slots_mask: u32,
    pub public_registered_mask: u32,
    pub public_fresh_mask: u32,
    pub public_reset_critical_stale_mask: u32,
    pub public_age_ms: [Option<u32>; TASK_COUNT],
    pub all_reset_critical_fresh: bool,
}

pub const fn classify_slots(
    now_ms: u32,
    checkins: &[WatchdogSlotCheckin],
) -> ClassifiedWatchdogSnapshot {
    let mut observed_stale_slots_mask = 0;
    let mut reset_critical_stale_slots_mask = 0;
    let mut public_registered_mask = 0;
    let mut public_observed_stale_mask = 0;
    let mut public_reset_critical_stale_mask = 0;
    let mut public_age_ms = [None; TASK_COUNT];
    let mut index = 0;

    while index < checkins.len() {
        let checkin = checkins[index];
        let public_task = checkin.slot.public_task();
        let public_index = public_task.index();
        public_registered_mask |= public_task.mask();

        if !checkin.exempt {
            let age_ms = checkin.age_ms(now_ms);
            public_age_ms[public_index] = match public_age_ms[public_index] {
                Some(current) if current >= age_ms => Some(current),
                _ => Some(age_ms),
            };
            if !checkin.is_fresh(now_ms) {
                observed_stale_slots_mask |= checkin.slot.mask();
                public_observed_stale_mask |= public_task.mask();
                if matches!(
                    checkin.slot.supervision_class(),
                    SupervisionClass::ResetCritical
                ) {
                    reset_critical_stale_slots_mask |= checkin.slot.mask();
                    public_reset_critical_stale_mask |= public_task.mask();
                }
            }
        }
        index += 1;
    }

    ClassifiedWatchdogSnapshot {
        now_ms,
        observed_stale_slots_mask,
        reset_critical_stale_slots_mask,
        public_registered_mask,
        public_fresh_mask: public_registered_mask & !public_observed_stale_mask,
        public_reset_critical_stale_mask,
        public_age_ms,
        all_reset_critical_fresh: reset_critical_stale_slots_mask == 0,
    }
}
