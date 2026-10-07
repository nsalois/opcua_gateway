//! Startup-only clock input and independent readback for accelerated diagnostics.

// Firmware policy marker: crate root declares #![no_std]; no alloc or std.
use core::sync::atomic::{AtomicU32, Ordering};

// SAFETY: exported diagnostic atomic words. The admitted runner may write ONLY
// the two input words while halted at the startup gate, before HAL initialization.
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_ORIGIN_LOW: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_ORIGIN_HIGH: AtomicU32 = AtomicU32::new(0);
// SAFETY: readback-only symbols. Firmware owns all writes; admitted manifest
// binds exact symbols and runner rejects changes outside the two input words.
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_SETUP_READY: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_TICK_HZ: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_PERIOD: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_COUNTER: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_DIER: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_ALARM_LOW: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable diagnostic atomic readback; startup firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_ALARM_HIGH: AtomicU32 = AtomicU32::new(0);

// SAFETY: fixed diagnostic readback array; firmware alone stores initial check-ins.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_CHECKINS: [AtomicU32; 10] = [const { AtomicU32::new(0) }; 10];
// SAFETY: stable readback of full-width initialized origin; firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_TRUST_LOW: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable readback of full-width initialized origin; firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_TRUST_HIGH: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable readback of initialized cache occupancy; firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_UNPUBLISHED_TAGS: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable readback of initialized write queue occupancy; firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_WRITE_QUEUE_DEPTH: AtomicU32 = AtomicU32::new(0);
// SAFETY: full-width startup observation; firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_DEPENDENT_NOW_LOW: AtomicU32 = AtomicU32::new(0);
// SAFETY: full-width startup observation; firmware owns writes.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_DEPENDENT_NOW_HIGH: AtomicU32 = AtomicU32::new(0);
// SAFETY: initialized dependent-state readiness; published last by firmware.
#[unsafe(no_mangle)]
pub static M7_ACCELERATED_DEPENDENTS_READY: AtomicU32 = AtomicU32::new(0);

pub(crate) fn capture_dependents(
    runtime: &crate::trust::SharedRuntime,
    trust: &crate::trust::SharedTrust,
) {
    use opta_gateway_contracts::freshness::CacheReadStatus;
    use opta_runtime::{NamespaceTarget, RuntimeNode, DEFAULT_NAMESPACE_NODES};
    let now = crate::timebase::uptime_now_ms_u64();
    let data = runtime
        .try_lock()
        .expect("startup runtime has no competing task");
    let trust = trust
        .try_lock()
        .expect("startup trust has no competing task");
    let unpublished = DEFAULT_NAMESPACE_NODES
        .iter()
        .filter(|node| {
            matches!(node.target, NamespaceTarget::Runtime(runtime_node)
            if runtime_node.index() < RuntimeNode::InfoBathAttached.index()
            && data.cache().read(runtime_node, now).status == CacheReadStatus::NeverPublished)
        })
        .count();
    M7_ACCELERATED_UNPUBLISHED_TAGS.store(unpublished as u32, Ordering::Relaxed);
    M7_ACCELERATED_WRITE_QUEUE_DEPTH.store(data.write_queue_depth() as u32, Ordering::Relaxed);
    let origin = trust.diagnostic_monotonic_origin();
    M7_ACCELERATED_TRUST_LOW.store(origin as u32, Ordering::Relaxed);
    M7_ACCELERATED_TRUST_HIGH.store((origin >> 32) as u32, Ordering::Relaxed);
    for (destination, value) in M7_ACCELERATED_CHECKINS
        .iter()
        .zip(crate::watchdog::diagnostic_initial_checkins())
    {
        destination.store(value, Ordering::Relaxed);
    }
    M7_ACCELERATED_DEPENDENT_NOW_LOW.store(now as u32, Ordering::Relaxed);
    M7_ACCELERATED_DEPENDENT_NOW_HIGH.store((now >> 32) as u32, Ordering::Relaxed);
    M7_ACCELERATED_DEPENDENTS_READY.store(1, Ordering::Release);
    // SAFETY: this pre-executor capture is the only writer of these diagnostic
    // objects. Publish their cache lines to SRAM before debugger readback. Clean
    // does not paint, reseed, or invalidate any live stack or runtime state.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    for word in [
        &M7_ACCELERATED_ORIGIN_LOW,
        &M7_ACCELERATED_ORIGIN_HIGH,
        &M7_ACCELERATED_SETUP_READY,
        &M7_ACCELERATED_TICK_HZ,
        &M7_ACCELERATED_PERIOD,
        &M7_ACCELERATED_COUNTER,
        &M7_ACCELERATED_DIER,
        &M7_ACCELERATED_ALARM_LOW,
        &M7_ACCELERATED_ALARM_HIGH,
        &M7_ACCELERATED_TRUST_LOW,
        &M7_ACCELERATED_TRUST_HIGH,
        &M7_ACCELERATED_UNPUBLISHED_TAGS,
        &M7_ACCELERATED_WRITE_QUEUE_DEPTH,
        &M7_ACCELERATED_DEPENDENT_NOW_LOW,
        &M7_ACCELERATED_DEPENDENT_NOW_HIGH,
        &M7_ACCELERATED_DEPENDENTS_READY,
    ] {
        cp.SCB
            .clean_dcache_by_address((word as *const _ as usize) & !31, 32);
    }
    let checkins = M7_ACCELERATED_CHECKINS.as_ptr() as usize;
    let bytes = (core::mem::size_of_val(&M7_ACCELERATED_CHECKINS) + (checkins & 31) + 31) & !31;
    cp.SCB.clean_dcache_by_address(checkins & !31, bytes);
    M7_ACCELERATED_DEPENDENTS_READY_GATE();
}

// SAFETY: readback breakpoint after initialized cache/trust/check-ins, before
// watchdog monitor and executor task execution. No initialized state is mutated.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_ACCELERATED_DEPENDENTS_READY_GATE() {
    core::hint::black_box(M7_ACCELERATED_DEPENDENTS_READY.load(Ordering::Acquire));
}

// SAFETY: stable breakpoint symbol. It performs no hardware action and occurs
// before HAL clock initialization, trust origins, runtime construction and tasks.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_ACCELERATED_CLOCK_GATE() {
    core::hint::black_box(M7_ACCELERATED_ORIGIN_LOW.load(Ordering::Relaxed));
}

pub(crate) fn prepare_origin() {
    // SAFETY: startup before HAL/IRQ/task initialization; no other SCB owner
    // exists here. Clean+invalidate BEFORE the debugger input breakpoint, so
    // AHB writes cannot be overwritten by dirty lines or read as stale zeros.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    let enabled = cortex_m::peripheral::SCB::dcache_enabled();
    cp.SCB.disable_dcache(&mut cp.CPUID);
    cortex_m::asm::dsb();
    M7_ACCELERATED_CLOCK_GATE();
    #[cfg(feature = "diagnostic-runtime-counters")]
    crate::counter_diagnostic::consume_startup_input();
    #[cfg(feature = "diagnostic-cache-ages")]
    crate::cache_age_diagnostic::consume_startup_input();
    #[cfg(feature = "diagnostic-trust-heartbeat-counters")]
    crate::trust_heartbeat_diagnostic::consume_startup_input();
    #[cfg(feature = "diagnostic-protocol-identifiers")]
    crate::protocol_id_diagnostic::consume_startup_input();
    if enabled {
        cp.SCB.enable_dcache(&mut cp.CPUID);
    }
}

// SAFETY: fixed-signature callback linked only by the explicit diagnostic
// driver feature. Startup inputs are read before any dependent timer exists.
#[unsafe(no_mangle)]
pub extern "C" fn opta_accelerated_origin_ticks(tick_hz: u32) -> u64 {
    assert_eq!(
        tick_hz, 1_000_000,
        "accelerated manifest requires default tick rate"
    );
    assert_eq!(M7_ACCELERATED_SETUP_READY.load(Ordering::Relaxed), 0);
    let origin_ms = (u64::from(M7_ACCELERATED_ORIGIN_HIGH.load(Ordering::Relaxed)) << 32)
        | u64::from(M7_ACCELERATED_ORIGIN_LOW.load(Ordering::Relaxed));
    assert!(
        origin_ms <= 400 * 86_400_000,
        "origin exceeds declared campaign horizon"
    );
    M7_ACCELERATED_TICK_HZ.store(tick_hz, Ordering::Relaxed);
    origin_ms * 1_000
}

// SAFETY: bounded startup readback callback, called with the configured timer
// stopped and interrupts excluded. No flash, options or storage are accessed.
#[unsafe(no_mangle)]
pub extern "C" fn opta_accelerated_clock_readback(
    period: u32,
    counter: u32,
    dier: u32,
    alarm: u64,
) {
    M7_ACCELERATED_PERIOD.store(period, Ordering::Relaxed);
    M7_ACCELERATED_COUNTER.store(counter, Ordering::Relaxed);
    M7_ACCELERATED_DIER.store(dier, Ordering::Relaxed);
    M7_ACCELERATED_ALARM_LOW.store(alarm as u32, Ordering::Relaxed);
    M7_ACCELERATED_ALARM_HIGH.store((alarm >> 32) as u32, Ordering::Relaxed);
    M7_ACCELERATED_SETUP_READY.store(1, Ordering::Release);
}
