// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Lowest-impact diagnostic-only Time-driver counters.
//!
//! Each vendored driver event performs one relaxed atomic increment. There
//! are no timer-register reads, ring writes, executor callbacks, task wakeups,
//! or live output. A debugger may read the exported counters only after the
//! host access log observes a process-poll gap.
// Firmware policy marker: the crate root declares #![no_std]; this module must
// remain no-heap and no-alloc.

use core::sync::atomic::{AtomicU32, Ordering};

const EVENT_COUNT: usize = 8;

// SAFETY: these unique exported names are the debugger ABI for this opt-in
// diagnostic image and do not collide with product symbols.
#[unsafe(no_mangle)]
static BH20_TIME_EVENT_COUNTS: [AtomicU32; EVENT_COUNT] =
    [const { AtomicU32::new(0) }; EVENT_COUNT];
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
#[used]
static BH20_TIME_COUNTER_EVENT_COUNT: u32 = EVENT_COUNT as u32;
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
#[used]
static BH20_TIME_COUNTER_TICK_HZ: u32 = embassy_time::TICK_HZ as u32;

/// Increment one of the event counters defined beside the vendored driver
/// call sites. Unknown event numbers are ignored rather than indexing past
/// the fixed debugger ABI.
// SAFETY: this unique symbol is the fixed-signature hook declared by the
// feature-gated vendored time driver; both sides use the C ABI.
#[unsafe(no_mangle)]
pub extern "C" fn opta_bh20_time_counter(event: u32) {
    if let Some(counter) = BH20_TIME_EVENT_COUNTS.get(event as usize) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}
