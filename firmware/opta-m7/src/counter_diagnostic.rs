//! Finite, boot-only counter initialization at a real authenticated GET boundary.
// Firmware policy marker: crate root declares #![no_std]; no alloc or std.

use crate::probes::{
    M7_WATCHDOG_ARMED, M7_WATCHDOG_LAST_KICK_MS, M7_WATCHDOG_REFRESH_COUNT, M7_WATCHDOG_STALE_MASK,
};
use crate::trust::RuntimeTrust;
use core::sync::atomic::{AtomicU32, Ordering};
use opta_buchi::Endpoint;
use opta_gateway_contracts::{config::TrustState, freshness::ScalarValue, opcua_status};
use opta_runtime::{
    DiagnosticCounterSeed, DiagnosticCounterSnapshot, RuntimeDataAccess, RuntimeNode,
};

// SAFETY: this sole finite input is written only at the admitted pre-HAL clock
// gate with D-cache disabled. Zero disables; 1..3 select fixed enum recipes.
#[unsafe(no_mangle)]
pub static M7_COUNTER_RECIPE_INPUT: AtomicU32 = AtomicU32::new(0);
static STARTUP_RECIPE: AtomicU32 = AtomicU32::new(0);

pub(crate) const SNAPSHOT_WORDS: usize = 80;
#[repr(C, align(32))]
pub struct CounterWords(pub [AtomicU32; SNAPSHOT_WORDS]);

// SAFETY: immutable snapshot after publication. Firmware is the sole writer;
// debugger admission permits reads only. The aligned extent owns whole lines.
#[unsafe(no_mangle)]
pub static M7_COUNTER_ADMISSION: CounterWords =
    CounterWords([const { AtomicU32::new(0) }; SNAPSHOT_WORDS]);

pub(crate) fn consume_startup_input() {
    let index = M7_COUNTER_RECIPE_INPUT.load(Ordering::Relaxed);
    assert!(
        index <= 3,
        "counter recipe must be disabled or one of three fixed seeds"
    );
    STARTUP_RECIPE.store(index, Ordering::Relaxed);
}

pub(crate) struct CounterSession {
    recipe: Option<DiagnosticCounterSeed>,
    recipe_index: u32,
    successful_gets: u32,
    drain_calls: u32,
}

impl CounterSession {
    pub(crate) fn from_startup() -> Self {
        // This consumption is outside the cache/runtime owner and survives all
        // reconnects. Reconstructing an owner or this session cannot rearm it.
        let index = STARTUP_RECIPE.swap(0, Ordering::Relaxed);
        Self {
            recipe: match index {
                1 => Some(DiagnosticCounterSeed::MaxMinusTwo),
                2 => Some(DiagnosticCounterSeed::MaxMinusOne),
                3 => Some(DiagnosticCounterSeed::Max),
                _ => None,
            },
            recipe_index: index,
            successful_gets: 0,
            drain_calls: 0,
        }
    }

    pub(crate) fn before_drain(&mut self) {
        self.drain_calls = self.drain_calls.saturating_add(1);
    }

    /// Called synchronously in the actual parsed-GET success branch while the
    /// caller holds SharedTrust then SharedRuntime. No await/I/O occurs here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn after_get<const N: usize>(
        &mut self,
        trust: Option<&RuntimeTrust>,
        handshake_generation: Option<u32>,
        handshake_time_checked: bool,
        data: &mut RuntimeDataAccess<N>,
        endpoint: Endpoint,
        now_ms: u64,
        poll_deadlines_ms: [u32; 3],
    ) -> bool {
        self.successful_gets = self.successful_gets.saturating_add(1);
        let Some(recipe) = self.recipe.take() else {
            return false;
        };
        let before = data.diagnostic_counters();
        let baseline = data.read_node(RuntimeNode::ProcessHeatingSet, now_ms);
        let publication = data
            .cache()
            .diagnostic_publication(RuntimeNode::ProcessHeatingSet);
        let revoked = crate::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed);
        let verifier_now = trust.and_then(|owner| owner.verifier_now_seconds());
        let mut rejection = if self.successful_gets != 1 || self.drain_calls != 0 {
            1
        } else if trust.is_none() {
            2
        } else if trust.is_some_and(|owner| {
            owner.state != TrustState::Verified
                || Some(owner.generation) != handshake_generation
                || revoked != 0
        }) {
            3
        } else if trust.is_some_and(|owner| {
            owner.rtc_usable != handshake_time_checked
                || verifier_now.is_some() != handshake_time_checked
        }) {
            4
        } else if endpoint != Endpoint::Process
            || baseline.opcua_status != opcua_status::GOOD
            || baseline.value != Some(ScalarValue::FloatMilli(42_125))
            || !publication.published
            || publication.last_publish_monotonic_ms != now_ms
        {
            5
        } else {
            0
        };
        let after = if rejection == 0 {
            match data.diagnostic_seed_counters(recipe) {
                Some(snapshot) => snapshot,
                None => {
                    rejection = 6;
                    before
                }
            }
        } else {
            before
        };
        let mut words = [0u32; SNAPSHOT_WORDS];
        words[1] = 1; // layout version; word zero is published last
        words[2] = self.recipe_index;
        words[3] = rejection;
        words[4] = handshake_generation.unwrap_or(0);
        words[5] = trust.map_or(0, |owner| owner.generation);
        words[6] = trust.map_or(TrustState::Missing as u32, |owner| owner.state as u32);
        words[7] = u32::from(handshake_time_checked);
        words[8] = trust.map_or(0, |owner| u32::from(owner.rtc_usable));
        words[9] = revoked;
        words[10] = match endpoint {
            Endpoint::Process => 0,
            Endpoint::Settings => 1,
            Endpoint::Info => 2,
        };
        words[11] = data.write_queue_depth() as u32;
        words[12..14].copy_from_slice(&[now_ms as u32, (now_ms >> 32) as u32]);
        words[14] = baseline.opcua_status;
        if let Some(ScalarValue::FloatMilli(value)) = baseline.value {
            words[15] = value as u32;
            words[16] = 1;
        }
        words[17] = u32::from(publication.published);
        words[18..21].copy_from_slice(&[
            publication.last_publish_monotonic_ms as u32,
            (publication.last_publish_monotonic_ms >> 32) as u32,
            publication.freshness_ms,
        ]);
        words[21] = self.successful_gets;
        words[22] = self.drain_calls;
        copy_counters(&mut words[23..28], before);
        copy_counters(&mut words[28..33], after);
        words[33] = data.cache().failed_fetches();
        words[34] = u32::from(data.write_enabled());
        let seconds = verifier_now.unwrap_or(0);
        words[35..38].copy_from_slice(&[
            seconds as u32,
            (seconds >> 32) as u32,
            u32::from(verifier_now.is_some()),
        ]);
        words[38] = u32::from(handshake_generation.is_some());
        words[39] = data.trust_state() as u32;
        words[40..49].copy_from_slice(&embassy_stm32::accelerated_clock_snapshot());
        words[49..59].copy_from_slice(&crate::watchdog::diagnostic_initial_checkins());
        words[59] = M7_WATCHDOG_ARMED.load(Ordering::Relaxed);
        words[60] = M7_WATCHDOG_LAST_KICK_MS.load(Ordering::Relaxed);
        words[61] = M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Relaxed);
        words[62..65].copy_from_slice(&poll_deadlines_ms);
        words[65] = M7_WATCHDOG_STALE_MASK.load(Ordering::Relaxed);
        let captured_ms = crate::uptime_now_ms_u64();
        words[66..68].copy_from_slice(&[captured_ms as u32, (captured_ms >> 32) as u32]);
        words[68] = crate::M7_BUCHI_TRUST_VERIFIED_SESSIONS.load(Ordering::Relaxed);
        publish(&words, if rejection == 0 { 1 } else { 2 });
        true
    }
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

fn publish(words: &[u32; SNAPSHOT_WORDS], readiness: u32) {
    for (destination, value) in M7_COUNTER_ADMISSION.0.iter().zip(words).skip(1) {
        destination.store(*value, Ordering::Relaxed);
    }
    M7_COUNTER_ADMISSION.0[0].store(readiness, Ordering::Release);
    // Arm CMSIS D-Cache by-address requires 32-byte alignment. The pinned
    // cortex-m implementation brackets clean-by-address with DSB operations.
    // SAFETY: this wholly owned immutable aligned atomic extent is not a live
    // stack. Thread-mode clean and explicit DSB finish before the breakpoint.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB.clean_dcache_by_address(
        &M7_COUNTER_ADMISSION as *const _ as usize,
        core::mem::size_of_val(&M7_COUNTER_ADMISSION),
    );
    cortex_m::asm::dsb();
}

// SAFETY: stable one-shot breakpoint after read-only snapshot publication.
// It never busy-waits; absent an admitted debugger it returns immediately.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_COUNTER_ADMISSION_GATE() {
    core::hint::black_box(M7_COUNTER_ADMISSION.0[0].load(Ordering::Acquire));
}
