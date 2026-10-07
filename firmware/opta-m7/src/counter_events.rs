//! Bounded immutable records of real TLS-client operations after counter admission.
// Firmware policy marker: crate root declares #![no_std]; no alloc or std.

use core::sync::atomic::{AtomicU32, Ordering};
use opta_runtime::{DiagnosticCounterSnapshot, RuntimeDataAccess, RuntimeNode};

pub(crate) const EVENT_CAPACITY: usize = 64;
pub(crate) const EVENT_WORDS: usize = 24;
#[repr(C, align(32))]
pub struct EventWords(pub [AtomicU32; EVENT_WORDS]);
#[repr(C, align(32))]
pub struct EventRing(pub [EventWords; EVENT_CAPACITY]);
#[repr(C, align(32))]
pub struct EventSummary(pub [AtomicU32; 32]);

// SAFETY: fixed read-only debugger symbols. The sole TLS client writes each
// record once, data first and readiness last; no slot reuse or RAM input exists.
#[unsafe(no_mangle)]
pub static M7_COUNTER_EVENTS: EventRing =
    EventRing([const { EventWords([const { AtomicU32::new(0) }; EVENT_WORDS]) }; EVENT_CAPACITY]);
// SAFETY: bounded progress words, frozen after completion/abort. Firmware alone
// writes; admission/readback never unlocks writes to this object.
#[unsafe(no_mangle)]
pub static M7_COUNTER_EVENT_SUMMARY: EventSummary = EventSummary([const { AtomicU32::new(0) }; 32]);

pub(crate) fn collecting() -> bool {
    M7_COUNTER_EVENT_SUMMARY.0[1].load(Ordering::Acquire) == 1
}

pub(crate) fn begin(generation: u32) {
    assert_eq!(M7_COUNTER_EVENT_SUMMARY.0[1].load(Ordering::Relaxed), 0);
    M7_COUNTER_EVENT_SUMMARY.0[14].store(generation, Ordering::Relaxed);
    M7_COUNTER_EVENT_SUMMARY.0[1].store(1, Ordering::Release);
    clean_summary();
}

pub(crate) fn abort(reason: u32) {
    if collecting() {
        M7_COUNTER_EVENT_SUMMARY.0[5].store(reason, Ordering::Relaxed);
        M7_COUNTER_EVENT_SUMMARY.0[1].store(3, Ordering::Release);
        clean_summary();
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record<const N: usize>(
    kind: u32,
    target: u32,
    sequence: u32,
    http: i32,
    status: u32,
    now_ms: u64,
    before: DiagnosticCounterSnapshot,
    data: &RuntimeDataAccess<N>,
) {
    if !collecting() {
        return;
    }
    let count = M7_COUNTER_EVENT_SUMMARY.0[2].load(Ordering::Relaxed) as usize;
    if count >= EVENT_CAPACITY {
        abort(4);
        return;
    }
    let slot = &M7_COUNTER_EVENTS.0[count];
    let counter_index = if kind == 1 { 3 } else { 4 };
    let ordinal = M7_COUNTER_EVENT_SUMMARY.0[counter_index].load(Ordering::Relaxed) + 1;
    let after = data.diagnostic_counters();
    let mut words = [0u32; EVENT_WORDS];
    words[1..9].copy_from_slice(&[
        kind,
        ordinal,
        target,
        sequence,
        http as u32,
        status,
        now_ms as u32,
        (now_ms >> 32) as u32,
    ]);
    copy_counters(&mut words[9..14], before);
    copy_counters(&mut words[14..19], after);
    words[19] = data.write_queue_depth() as u32;
    words[20] = data.trust_state() as u32;
    let baseline = data.read_node(RuntimeNode::ProcessHeatingSet, now_ms);
    words[21] = baseline.opcua_status;
    if let Some(opta_gateway_contracts::freshness::ScalarValue::FloatMilli(value)) = baseline.value
    {
        words[22] = value as u32;
        words[23] = 1;
    }
    for (destination, value) in slot.0.iter().zip(words).skip(1) {
        destination.store(value, Ordering::Relaxed);
    }
    slot.0[0].store((count + 1) as u32, Ordering::Release);
    // SAFETY: the aligned immutable slot owns exactly three cache lines.
    // Only this TLS task publishes records; no cache invalidation or repaint.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB
        .clean_dcache_by_address(slot as *const _ as usize, core::mem::size_of_val(slot));
    cortex_m::asm::dsb();
    M7_COUNTER_EVENT_SUMMARY.0[counter_index].store(ordinal, Ordering::Relaxed);
    M7_COUNTER_EVENT_SUMMARY.0[2].store((count + 1) as u32, Ordering::Release);
    if kind == 2 && ordinal > 10 {
        abort(5);
    }
    clean_summary();
}

/// Finish only at another real GET while the caller holds trust then runtime.
pub(crate) fn finish<const N: usize>(
    data: &RuntimeDataAccess<N>,
    generation: u32,
    trust_state: u32,
    now_ms: u64,
) -> bool {
    let summary = &M7_COUNTER_EVENT_SUMMARY.0;
    if !collecting()
        || summary[3].load(Ordering::Relaxed) < 5
        || summary[4].load(Ordering::Relaxed) != 10
    {
        return false;
    }
    if summary[14].load(Ordering::Relaxed) != generation
        || trust_state != 2
        || data.trust_state() as u32 != 2
        || data.write_queue_depth() != 0
    {
        abort(6);
        return false;
    }
    let mut counters = [0u32; 5];
    copy_counters(&mut counters, data.diagnostic_counters());
    for (destination, value) in summary[9..14].iter().zip(counters) {
        destination.store(value, Ordering::Relaxed);
    }
    summary[7].store(now_ms as u32, Ordering::Relaxed);
    summary[8].store((now_ms >> 32) as u32, Ordering::Relaxed);
    summary[15].store(trust_state, Ordering::Relaxed);
    summary[16].store(data.write_queue_depth() as u32, Ordering::Relaxed);
    summary[1].store(2, Ordering::Relaxed);
    summary[0].store(1, Ordering::Release);
    clean_summary();
    true
}

fn copy_counters(words: &mut [u32], snapshot: DiagnosticCounterSnapshot) {
    words.copy_from_slice(&[
        snapshot.next_write_sequence,
        snapshot.accepted_writes,
        snapshot.completed_writes,
        snapshot.failed_writes,
        snapshot.successful_fetches,
    ]);
}

fn clean_summary() {
    // SAFETY: aligned bounded atomic object, owned by this TLS task. Cleaning
    // publishes to SRAM; the pinned cache primitive and explicit DSB complete.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB.clean_dcache_by_address(
        &M7_COUNTER_EVENT_SUMMARY as *const _ as usize,
        core::mem::size_of_val(&M7_COUNTER_EVENT_SUMMARY),
    );
    cortex_m::asm::dsb();
}

// SAFETY: stable breakpoint on completed immutable records, without busy-wait.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_COUNTER_EVENTS_GATE() {
    core::hint::black_box(M7_COUNTER_EVENT_SUMMARY.0[0].load(Ordering::Acquire));
}
