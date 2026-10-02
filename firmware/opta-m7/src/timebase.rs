//! Monotonic uptime helper shared by watchdog, fault, trust, and flash paths.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_time::Instant;

pub(crate) fn uptime_now_ms() -> u32 {
    Instant::now().as_millis() as u32
}

pub(crate) fn uptime_now_ms_u64() -> u64 {
    Instant::now().as_millis()
}

pub(crate) fn uptime_now_seconds() -> u32 {
    opta_gateway_contracts::uptime::seconds_from_monotonic_ms(uptime_now_ms_u64())
}
