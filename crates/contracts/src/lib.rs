// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod reconnect;

/// STM32H747 CM4 boot-authorization decoding shared by firmware and host tests.
pub mod cm4;

/// Pure verifier-time arithmetic shared by firmware and host wrap tests.
pub mod trust_time {
    /// Advance an RTC-derived Unix-time origin by monotonic elapsed milliseconds.
    pub const fn verifier_now_seconds(
        base_unix_seconds: u64,
        base_monotonic_ms: u64,
        now_monotonic_ms: u64,
    ) -> u64 {
        base_unix_seconds + (now_monotonic_ms - base_monotonic_ms) / 1_000
    }
}

/// Long-horizon public uptime conversion shared by firmware and host tests.
pub mod uptime {
    /// Convert an untruncated monotonic millisecond sample to whole seconds.
    ///
    /// The cast is intentionally after division. This keeps the public value
    /// monotonic across every 32-bit millisecond wrap and gives the `UInt32`
    /// result its full seconds range.
    pub const fn seconds_from_monotonic_ms(monotonic_ms: u64) -> u32 {
        (monotonic_ms / 1_000) as u32
    }
}

/// Legacy arithmetic retained only for auditing pre-v3 millisecond evidence.
pub mod legacy_soak_monitor {
    /// Classify a legacy `Health.UptimeMs` decrease between old evidence samples.
    ///
    /// `Health.UptimeMs` is u32 milliseconds and wraps at ~49.7 days (BH-11). A
    /// wrap is modular arithmetic, not a reset: the modular advance still
    /// matches the wall-clock gap between samples. A genuine reboot instead
    /// restarts uptime near zero, so its modular advance is close to a full
    /// `2^32` epoch and vastly exceeds the sampling interval.
    ///
    /// Reset evidence (retained fault, watchdog bite) is authoritative and must
    /// be checked by the caller first; this only distinguishes a healthy wrap
    /// from an unexplained reset when no such evidence exists.
    pub const fn decrease_is_modular_ms_wrap(
        previous_uptime_ms: u32,
        current_uptime_ms: u32,
        observed_elapsed_ms: u64,
        slack_ms: u64,
    ) -> bool {
        if current_uptime_ms >= previous_uptime_ms {
            return false;
        }
        let modular_advance_ms = current_uptime_ms.wrapping_sub(previous_uptime_ms) as u64;
        modular_advance_ms <= observed_elapsed_ms.saturating_add(slack_ms)
    }
}

/// Product-scope constants carried from the current accepted default gateway.
pub mod product {
    /// `/process` cyclic poll target in milliseconds.
    pub const PROCESS_POLL_MS: u32 = 1_000;
    /// `/settings` cyclic poll target in milliseconds.
    pub const SETTINGS_POLL_MS: u32 = 5_000;
    /// `/info` cyclic poll target in milliseconds.
    pub const INFO_POLL_MS: u32 = 60_000;

    /// Freshness budget for Buchi status diagnostics.
    pub const BUCHI_STATUS_FRESHNESS_MS: u32 = 5_000;
    /// Freshness budget for `/process` values.
    pub const BUCHI_PROCESS_FRESHNESS_MS: u32 = 2_500;
    /// Freshness budget for `/settings` values.
    pub const BUCHI_SETTINGS_FRESHNESS_MS: u32 = 70_000;
    /// Freshness budget for `/info` values.
    pub const BUCHI_INFO_FRESHNESS_MS: u32 = 70_000;

    /// Current bounded all-variable DataChange contract.
    pub const MAX_ACTIVE_SUBSCRIPTIONS: usize = 1;
    /// Current supported monitored-item cap for default DataAccess variables.
    pub const MAX_MONITORED_ITEMS: usize = 135;
    /// Fixed publish/sampling interval for default DataChange variables.
    pub const DATA_CHANGE_INTERVAL_MS: u32 = 1_000;

    /// Compile-time queue capacity for write-through requests.
    pub const BUCHI_WRITE_QUEUE_CAPACITY: usize = 32;
    /// Maximum JSON bytes for one write-through request body.
    pub const BUCHI_WRITE_JSON_BYTES: usize = 128;
    /// Maximum bytes for one Buchi HTTP request line/header block plus optional body.
    pub const BUCHI_HTTP_REQUEST_BYTES: usize = 512;
    /// Maximum bytes for one Buchi HTTP response buffer.
    pub const BUCHI_HTTP_RESPONSE_BYTES: usize = 4_352;

    /// M7 foreground heartbeat publish target in milliseconds.
    pub const M7_HEARTBEAT_MS: u32 = 200;
    /// M7 status snapshot publish target in milliseconds.
    pub const M7_STATUS_SNAPSHOT_MS: u32 = 1_000;
    /// M4 timeout budget for missing M7 heartbeat progress.
    pub const M4_HEARTBEAT_TIMEOUT_MS: u32 = M7_HEARTBEAT_MS * 10;
    /// M4 one-shot software reset delay after a heartbeat fault is latched.
    pub const M4_SYSTEM_RESET_AFTER_FAULT_MS: u32 = 250;
}

/// RTC backup-domain ownership contract carried from the current gateway.
pub mod backup_domain;

/// Shared retained-record checksum primitive used by last-fault and breadcrumbs.
pub mod retained_record {
    pub const FNV1A32_OFFSET: u32 = 2_166_136_261;
    pub const FNV1A32_PRIME: u32 = 16_777_619;

    pub fn fnv1a32_words(words: &[u32]) -> u32 {
        let mut hash = FNV1A32_OFFSET;
        for mut word in words.iter().copied() {
            for _ in 0..core::mem::size_of::<u32>() {
                hash ^= word & 0xFF;
                hash = hash.wrapping_mul(FNV1A32_PRIME);
                word >>= 8;
            }
        }
        hash
    }
}

/// Last-fault retained-record contract.
pub mod last_fault;

/// M7 task-check watchdog contract for ADR 0010 hang recovery.
pub mod watchdog;

/// Persistent field-configuration contract for the M7 firmware.
pub mod config;

/// M7 boot breadcrumb retained-record contract.
pub mod boot;

/// Default-product OPC UA surface. This enum intentionally excludes retired or
/// secure-variant-only capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultOpcUaSurface {
    DataAccessRead,
    DataChangeSubscription,
    NumericBooleanWriteThrough,
    GatewayHealth,
}

/// Capabilities that must not enter the default image without a new ADR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutOfDefaultScope {
    Methods,
    Events,
    AlarmsAndConditions,
    History,
    PubSub,
    OpenInterfaceStrings,
    BrowserAdminUi,
    /// Compatibility fossil kept for historic scope diffing. Current Rust firmware
    /// uses HTTPS transport for Buchi communication, and this item is not active.
    DefaultBuchiTls,
    LocalOptaIo,
}

/// OPC UA status code values that are part of the current gateway contract.
pub mod opcua_status {
    pub const GOOD: u32 = 0x0000_0000;
    pub const GOOD_COMPLETES_ASYNCHRONOUSLY: u32 = 0x002E_0000;
    pub const BAD_UNEXPECTED_ERROR: u32 = 0x8001_0000;
    pub const BAD_INTERNAL_ERROR: u32 = 0x8002_0000;
    pub const BAD_RESOURCE_UNAVAILABLE: u32 = 0x8004_0000;
    pub const BAD_COMMUNICATION_ERROR: u32 = 0x8005_0000;
    /// open62541/OPC UA service boundary for requests exceeding a bounded
    /// operation budget.
    pub const BAD_TOO_MANY_OPERATIONS: u32 = 0x8010_0000;
    pub const BAD_TIMEOUT: u32 = 0x800A_0000;
    pub const BAD_USER_ACCESS_DENIED: u32 = 0x801F_0000;
    pub const BAD_INDEX_RANGE_INVALID: u32 = 0x8036_0000;
    pub const BAD_NOT_WRITABLE: u32 = 0x803B_0000;
    pub const BAD_OUT_OF_RANGE: u32 = 0x803C_0000;
    pub const BAD_WRITE_NOT_SUPPORTED: u32 = 0x8073_0000;
    pub const BAD_TYPE_MISMATCH: u32 = 0x8074_0000;
    /// Boundary status for configured DataAccess variables whose physical
    /// subsystem is intentionally absent/detached.
    pub const BAD_NOT_CONNECTED: u32 = 0x808A_0000;
    /// open62541/OPC UA operation result for monitored-item capacity rejection.
    pub const BAD_TOO_MANY_MONITORED_ITEMS: u32 = 0x80DB_0000;
    /// Boundary status for unpublished or stale cache values. This mirrors the
    /// current product's stale-not-fresh OPC UA boundary behavior.
    pub const BAD_WAITING_FOR_INITIAL_DATA: u32 = 0x8032_0000;
    /// Boundary status for absent retained last-fault numeric values.
    pub const BAD_NO_DATA: u32 = 0x809B_0000;
}

/// Cache/state freshness contracts.
pub mod freshness;

/// Default namespace and write-surface contract.
pub mod namespace;

#[cfg(test)]
mod tests;
