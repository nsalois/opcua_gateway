// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Host-test inputs and independent setup checks; never compiled into firmware.

pub const EPOCH_MS: u64 = 4_294_967_296;

pub fn admit_publication(
    expected_ms: u64,
    expected_freshness: u32,
    actual_ms: u64,
    actual_freshness: u32,
    published: bool,
) -> Result<(), &'static str> {
    if !published || actual_ms != expected_ms || actual_freshness != expected_freshness {
        return Err("INVALID_SETUP: publication metadata differs from scenario");
    }
    Ok(())
}

pub fn origins() -> Vec<u64> {
    let mut values = vec![1_000];
    for center in (1..=8)
        .map(|k| k * EPOCH_MS)
        .chain((0..8).map(|k| k * EPOCH_MS + EPOCH_MS / 2))
        .chain([60, 120, 270, 300, 365].map(|days| days * 86_400_000))
    {
        for offset in [-1_000i64, -1, 0, 1, 1_000] {
            values.push((center as i64 + offset) as u64);
        }
    }
    values.sort_unstable();
    values.dedup();
    values
}

pub fn admit_origin(
    expected_ms: u64,
    observed_ms: u64,
    initialized: bool,
) -> Result<(), &'static str> {
    if !initialized {
        return Err("INVALID_SETUP: incomplete initialization");
    }
    if expected_ms != observed_ms {
        return Err("INVALID_SETUP: origin/readback mismatch");
    }
    Ok(())
}

pub fn admit_deadline(
    origin_ms: u64,
    interval_ms: u32,
    observed_due_ms: u32,
) -> Result<(), &'static str> {
    if interval_ms == 0 || u64::from(interval_ms) >= EPOCH_MS / 2 {
        return Err("INVALID_SETUP: deadline outside modular half range");
    }
    let expected =
        ((u128::from(origin_ms) + u128::from(interval_ms)) % u128::from(EPOCH_MS)) as u32;
    if expected != observed_due_ms {
        return Err("INVALID_SETUP: inconsistent deadline");
    }
    Ok(())
}
