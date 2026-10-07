// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Diagnostic-only Time-driver time-driver trace.
//!
//! The timer hook performs bounded atomic stores only. There is deliberately
//! no drain task and no live output: either would add periodic timer wakeups
//! and could repair the alarm/executor race under investigation. A debugger
//! may dump the exported ring only after the host access log observes a gap.
//! The optional `diagnostic-executor-wakeup` superset adds Embassy executor callbacks;
//! `diagnostic-time-driver` alone intentionally leaves them disabled.
// Firmware policy marker: the crate root declares #![no_std]; this module must
// remain no-heap and no-alloc.

use core::sync::atomic::{AtomicU32, Ordering};

const TIME_TRACE_CAPACITY: usize = 256;

#[repr(C)]
struct TimeTraceSlot {
    sequence: AtomicU32,
    event: AtomicU32,
    now_low: AtomicU32,
    alarm_at_low: AtomicU32,
    cnt: AtomicU32,
    sr: AtomicU32,
    dier: AtomicU32,
    ccr2: AtomicU32,
    current_task: AtomicU32,
    last_ready_task: AtomicU32,
    tls_stage: AtomicU32,
    poll_start_count: AtomicU32,
}

impl TimeTraceSlot {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            event: AtomicU32::new(0),
            now_low: AtomicU32::new(0),
            alarm_at_low: AtomicU32::new(0),
            cnt: AtomicU32::new(0),
            sr: AtomicU32::new(0),
            dier: AtomicU32::new(0),
            ccr2: AtomicU32::new(0),
            current_task: AtomicU32::new(0),
            last_ready_task: AtomicU32::new(0),
            tls_stage: AtomicU32::new(0),
            poll_start_count: AtomicU32::new(0),
        }
    }
}

// SAFETY: these unique exported names are the debugger ABI for this opt-in
// diagnostic image and do not collide with product symbols.
#[unsafe(no_mangle)]
static BH20_TIME_TRACE: [TimeTraceSlot; TIME_TRACE_CAPACITY] =
    [const { TimeTraceSlot::new() }; TIME_TRACE_CAPACITY];
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
static BH20_TIME_TRACE_WRITE_SEQUENCE: AtomicU32 = AtomicU32::new(0);
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
#[used]
static BH20_TIME_TRACE_CAPACITY: u32 = TIME_TRACE_CAPACITY as u32;
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
#[used]
static BH20_TIME_TRACE_TICK_HZ: u32 = embassy_time::TICK_HZ as u32;

// SAFETY: these unique exported names are the debugger ABI for this opt-in
// diagnostic image and do not collide with product symbols.
#[unsafe(no_mangle)]
static BH20_EXECUTOR_POLL_START_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
static BH20_EXECUTOR_IDLE_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
static BH20_EXECUTOR_READY_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: see the debugger ABI invariant above.
#[unsafe(no_mangle)]
static BH20_EXECUTOR_EXEC_COUNT: AtomicU32 = AtomicU32::new(0);
static EXECUTOR_CURRENT_TASK: AtomicU32 = AtomicU32::new(0);
static EXECUTOR_LAST_READY_TASK: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "diagnostic-executor-wakeup")]
static TLS_STAGE: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "diagnostic-executor-wakeup")]
pub(crate) fn set_tls_stage(stage: u32) {
    TLS_STAGE.store(stage, Ordering::Relaxed);
}

/// Called from the diagnostic time driver. Event numbers are defined beside
/// the driver call sites so raw records remain usable if RTT text is partial.
// SAFETY: this unique symbol is the fixed-signature hook declared by the
// feature-gated vendored time driver; both sides use the C ABI.
#[unsafe(no_mangle)]
pub extern "C" fn opta_bh20_time_trace(
    event: u32,
    now_low: u32,
    alarm_at_low: u32,
    cnt: u32,
    sr: u32,
    dier: u32,
    ccr2: u32,
) {
    let sequence = BH20_TIME_TRACE_WRITE_SEQUENCE
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let slot = &BH20_TIME_TRACE[(sequence.wrapping_sub(1) as usize) % TIME_TRACE_CAPACITY];

    // Mark incomplete first; the release sequence store publishes the entire
    // record to a debugger reader after the core has been halted.
    slot.sequence.store(0, Ordering::Relaxed);
    slot.event.store(event, Ordering::Relaxed);
    slot.now_low.store(now_low, Ordering::Relaxed);
    slot.alarm_at_low.store(alarm_at_low, Ordering::Relaxed);
    slot.cnt.store(cnt, Ordering::Relaxed);
    slot.sr.store(sr, Ordering::Relaxed);
    slot.dier.store(dier, Ordering::Relaxed);
    slot.ccr2.store(ccr2, Ordering::Relaxed);
    slot.current_task.store(
        EXECUTOR_CURRENT_TASK.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    slot.last_ready_task.store(
        EXECUTOR_LAST_READY_TASK.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    #[cfg(feature = "diagnostic-executor-wakeup")]
    slot.tls_stage
        .store(TLS_STAGE.load(Ordering::Relaxed), Ordering::Relaxed);
    // Without the wakeup-trace superset there is no TLS stage source; store a
    // constant 0 so reused ring slots never carry a stale stage forward.
    #[cfg(not(feature = "diagnostic-executor-wakeup"))]
    slot.tls_stage.store(0, Ordering::Relaxed);
    slot.poll_start_count.store(
        BH20_EXECUTOR_POLL_START_COUNT.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    slot.sequence.store(sequence, Ordering::Release);
}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_poll_start(_executor_id: u32) {
    BH20_EXECUTOR_POLL_START_COUNT.fetch_add(1, Ordering::Relaxed);
}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_task_new(_executor_id: u32, _task_id: u32) {}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_task_end(_executor_id: u32, _task_id: u32) {}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_task_exec_begin(_executor_id: u32, task_id: u32) {
    EXECUTOR_CURRENT_TASK.store(task_id, Ordering::Relaxed);
    BH20_EXECUTOR_EXEC_COUNT.fetch_add(1, Ordering::Relaxed);
}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_task_exec_end(_executor_id: u32, task_id: u32) {
    let _ =
        EXECUTOR_CURRENT_TASK.compare_exchange(task_id, 0, Ordering::Relaxed, Ordering::Relaxed);
}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_task_ready_begin(_executor_id: u32, task_id: u32) {
    EXECUTOR_LAST_READY_TASK.store(task_id, Ordering::Relaxed);
    BH20_EXECUTOR_READY_COUNT.fetch_add(1, Ordering::Relaxed);
}

// SAFETY: Embassy's trace feature declares this exact unique C-ABI symbol.
#[cfg(feature = "diagnostic-executor-wakeup")]
#[unsafe(no_mangle)]
fn _embassy_trace_executor_idle(_executor_id: u32) {
    BH20_EXECUTOR_IDLE_COUNT.fetch_add(1, Ordering::Relaxed);
}
