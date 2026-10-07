// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Host repros for wave-2 long-horizon arithmetic findings.
//!
//! These deliberately exercise the production arithmetic at the cited
//! locations. Open findings remain ignored until the corresponding product
//! implementation is fixed.

use opta_gateway_contracts::trust_time::verifier_now_seconds;

const U32_WRAP_MS: u64 = u32::MAX as u64 + 1;
const TIMEBASE: &str = include_str!("../../../firmware/opta-m7/src/timebase.rs");
const MAIN: &str = include_str!("../../../firmware/opta-m7/src/main.rs");
const WATCHDOG: &str = include_str!("../../../firmware/opta-m7/src/watchdog.rs");
const CONTRACTS_WATCHDOG: &str = include_str!("../src/watchdog.rs");
const CONTRACTS_TESTS: &str = include_str!("../src/tests.rs");

#[test]
fn verifier_clock_remains_monotonic_across_full_u32_millisecond_epoch() {
    let base_unix_seconds = 1_750_000_000;
    let base_monotonic_ms = 123_456;
    let before_wrap = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + U32_WRAP_MS - 1,
    );
    let at_wrap = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + U32_WRAP_MS,
    );
    let after_wrap = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + U32_WRAP_MS + 1,
    );
    let one_second_after_wrap = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + U32_WRAP_MS + 1_000,
    );
    let after_two_wraps = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + 2 * U32_WRAP_MS,
    );

    assert_eq!(before_wrap, base_unix_seconds + 4_294_967);
    assert_eq!(at_wrap, base_unix_seconds + 4_294_967);
    assert_eq!(after_wrap, base_unix_seconds + 4_294_967);
    assert_eq!(one_second_after_wrap, base_unix_seconds + 4_294_968);
    assert_eq!(after_two_wraps, base_unix_seconds + 8_589_934);
    assert!(before_wrap <= at_wrap);
    assert!(at_wrap <= after_wrap);
    assert_eq!(one_second_after_wrap - at_wrap, 1);
    assert!(after_wrap <= one_second_after_wrap);
    assert!(one_second_after_wrap <= after_two_wraps);
}

#[test]
fn verifier_clock_sparse_reads_can_skip_whole_u32_millisecond_epochs() {
    let base_unix_seconds = 1_750_000_000;
    let base_monotonic_ms = 987_654;
    let first = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + 250,
    );
    let after_skipped_epochs = verifier_now_seconds(
        base_unix_seconds,
        base_monotonic_ms,
        base_monotonic_ms + 2 * U32_WRAP_MS + 250,
    );

    assert_eq!(first, base_unix_seconds);
    assert_eq!(after_skipped_epochs, base_unix_seconds + 8_589_934);
    assert!(after_skipped_epochs > first);
}

#[test]
fn public_seconds_use_wide_clock_while_watchdog_keeps_u32_milliseconds() {
    assert!(TIMEBASE.contains("pub(crate) fn uptime_now_ms() -> u32"));
    assert!(TIMEBASE.contains("pub(crate) fn uptime_now_ms_u64() -> u64"));
    assert!(TIMEBASE.contains("seconds_from_monotonic_ms(uptime_now_ms_u64())"));
    assert!(!TIMEBASE.contains("seconds_from_monotonic_ms(u64::from(uptime_now_ms()))"));
    assert!(MAIN.contains("pub(crate) use timebase::uptime_now_ms;"));
    assert!(WATCHDOG.contains("let now_ms_u64 = uptime_now_ms_u64();"));
    assert!(WATCHDOG.contains("let now_ms = now_ms_u64 as u32;"));
    assert!(CONTRACTS_WATCHDOG.contains("pub const fn age_ms(self, now_ms: u32) -> u32"));
    assert!(CONTRACTS_TESTS.contains("(4022, \"Health.UptimeSeconds\", ValueKind::UInt32)"));
    assert!(CONTRACTS_TESTS.contains("assert_eq!(node.value_kind, ValueKind::UInt32)"));
}

#[test]
fn legacy_soak_monitor_accepts_u32_millisecond_wrap_without_reset_evidence() {
    use opta_gateway_contracts::legacy_soak_monitor::decrease_is_modular_ms_wrap;

    const HOURLY_MS: u64 = 3_600_000;
    const SLACK_MS: u64 = 300_000;

    // A day-49.7 wrap sampled on the hourly soak cadence: the modular advance
    // still matches the sampling gap, so it is expected arithmetic, not a STOP.
    assert!(decrease_is_modular_ms_wrap(
        u32::MAX - 100,
        100,
        HOURLY_MS,
        SLACK_MS
    ));
    assert!(decrease_is_modular_ms_wrap(
        u32::MAX - 3_500_000,
        100_000,
        HOURLY_MS,
        SLACK_MS
    ));

    // A genuine reboot after ~100 h restarts uptime near zero. Its modular
    // advance is ~45.5 days, which cannot be mistaken for an hourly gap.
    assert!(!decrease_is_modular_ms_wrap(
        360_000_000,
        500,
        HOURLY_MS,
        SLACK_MS
    ));

    // Normal forward progress is not a decrease at all.
    assert!(!decrease_is_modular_ms_wrap(100, 200, HOURLY_MS, SLACK_MS));
}
