//! Boot-only finite publication ages on real authenticated cache owners.
// Firmware policy marker: crate root declares #![no_std]; no alloc or std.
use crate::{probes, trust::RuntimeTrust};
use core::sync::atomic::{AtomicU32, Ordering};
use opta_buchi::Endpoint;
use opta_gateway_contracts::{config::TrustState, freshness::ScalarValue, opcua_status};
use opta_runtime::{DiagnosticAge, NamespaceTarget, RuntimeDataAccess, DEFAULT_NAMESPACE_NODES};

// SAFETY: exact named atomic input; read only at the admitted cache-disabled
// startup gate. Zero disables and one enables the finite matrix for one boot.
#[unsafe(no_mangle)]
pub static M7_CACHE_AGE_ENABLE_INPUT: AtomicU32 = AtomicU32::new(0);
static STARTUP_ENABLE: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(32))]
pub struct Words<const N: usize>(pub [AtomicU32; N]);

// SAFETY: wholly owned aligned atomic storage. Sole firmware writer; debugger
// reads only after final release publication and complete cache clean + DSB.
#[unsafe(no_mangle)]
pub static M7_CACHE_AGE_HEADER: Words<272> = Words([const { AtomicU32::new(0) }; 272]);
// SAFETY: immutable aligned per-tag snapshot, sole firmware writer and read-only
// debugger lane. Final publication cleans the complete owned extent.
#[unsafe(no_mangle)]
pub static M7_CACHE_AGE_BASELINES: Words<1280> = Words([const { AtomicU32::new(0) }; 1280]);
// SAFETY: immutable aligned case snapshot, same sole-writer/cleaning invariant.
#[unsafe(no_mangle)]
pub static M7_CACHE_AGE_ROWS: Words<15360> = Words([const { AtomicU32::new(0) }; 15360]);

pub(crate) fn consume_startup_input() {
    let input = M7_CACHE_AGE_ENABLE_INPUT.load(Ordering::Relaxed);
    assert!(
        input <= 1,
        "cache age input must be disabled or the finite matrix"
    );
    STARTUP_ENABLE.store(input, Ordering::Relaxed);
}

pub(crate) struct CacheAgeSession {
    enabled: bool,
    seen: u32,
    generation: Option<u32>,
    rows: u32,
    tags: u32,
}

impl CacheAgeSession {
    pub(crate) fn from_startup() -> Self {
        Self {
            enabled: STARTUP_ENABLE.swap(0, Ordering::Relaxed) == 1,
            seen: 0,
            generation: None,
            rows: 0,
            tags: 0,
        }
    }

    /// Actual parsed GET success only, while real trust then runtime locks are
    /// held. Each endpoint is consumed once, including rejection. No await.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn after_get<const N: usize>(
        &mut self,
        trust: Option<&RuntimeTrust>,
        handshake_generation: Option<u32>,
        time_checked: bool,
        data: &mut RuntimeDataAccess<N>,
        endpoint: Endpoint,
        parsed_now: u64,
        deadlines: [u32; 3],
    ) -> bool {
        let ep = match endpoint {
            Endpoint::Process => 0,
            Endpoint::Settings => 1,
            Endpoint::Info => 2,
        };
        if !self.enabled || self.seen & (1 << ep) != 0 {
            return false;
        }
        self.seen |= 1 << ep;
        let start = crate::uptime_now_ms_u64();
        let revoked = crate::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed);
        let verifier = trust.and_then(|owner| owner.verifier_now_seconds());
        let reason = if trust.is_none() {
            1
        } else if trust.is_some_and(|owner| {
            owner.state != TrustState::Verified
                || Some(owner.generation) != handshake_generation
                || revoked != 0
                || self.generation.is_some_and(|gen| gen != owner.generation)
        }) {
            2
        } else if trust.is_some_and(|owner| {
            owner.rtc_usable != time_checked || verifier.is_some() != time_checked
        }) {
            3
        } else if !data.writes_allowed()
            || data.write_queue_depth() != 0
            || !data.cache().last_fetch_ok()
            || data.cache().last_endpoint() != Some(endpoint)
            || start < parsed_now
            || start > parsed_now + u64::from(endpoint.freshness_ms())
        {
            4
        } else {
            0
        };
        let header_offset = 32 + ep * 80;
        let header = endpoint_header(
            trust,
            handshake_generation,
            time_checked,
            data,
            ep as u32,
            parsed_now,
            start,
            deadlines,
        );
        write(&M7_CACHE_AGE_HEADER, header_offset, &header);
        if reason != 0 {
            return self.finish(reason, start);
        }
        self.generation = handshake_generation;
        let mut public_index = 0;
        let mut endpoint_tags = 0;
        for entry in DEFAULT_NAMESPACE_NODES {
            let NamespaceTarget::Runtime(node) = entry.target else {
                continue;
            };
            if (1032..=1036).contains(&entry.node_id) {
                continue;
            }
            let index = public_index;
            public_index += 1;
            if node.endpoint() != endpoint {
                continue;
            }
            if index >= 80 {
                return self.finish(5, crate::uptime_now_ms_u64());
            }
            let now = crate::uptime_now_ms_u64();
            let original = data.cache().diagnostic_publication(node);
            let baseline = data.read_node(node, now);
            let (kind, bits) = scalar(baseline.value);
            let mut words = [0u32; 16];
            words[..12].copy_from_slice(&[
                u32::from(entry.node_id),
                node.index() as u32,
                ep as u32,
                original.freshness_ms,
                original.last_publish_monotonic_ms as u32,
                (original.last_publish_monotonic_ms >> 32) as u32,
                kind,
                bits,
                baseline.opcua_status,
                original.published as u32,
                handshake_generation.unwrap_or(0),
                12,
            ]);
            write(&M7_CACHE_AGE_BASELINES, index * 16, &words);
            if !original.published
                || original.last_publish_monotonic_ms != parsed_now
                || original.freshness_ms != node.freshness_ms()
                || baseline.opcua_status != opcua_status::GOOD
                || kind == 0
            {
                return self.finish(6, crate::uptime_now_ms_u64());
            }
            for (case, age) in DiagnosticAge::ALL.into_iter().enumerate() {
                let consuming_now = crate::uptime_now_ms_u64();
                let Some(observed) = data.diagnostic_age_case(node, age, consuming_now) else {
                    return self.finish(7, crate::uptime_now_ms_u64());
                };
                let Some(sample) = observed.sampled else {
                    return self.finish(8, crate::uptime_now_ms_u64());
                };
                let (read_kind, read_bits) = scalar(observed.direct.value);
                let (sample_kind, sample_bits) = scalar(sample.value);
                let (restore_kind, restore_bits) = scalar(observed.restored_read.value);
                let row = [
                    u32::from(entry.node_id),
                    age as u32 | (u32::from(sample.node_id) << 8) | (sample.client_handle << 24),
                    consuming_now as u32,
                    (consuming_now >> 32) as u32,
                    observed.injected.last_publish_monotonic_ms as u32,
                    (observed.injected.last_publish_monotonic_ms >> 32) as u32,
                    observed.direct.opcua_status,
                    read_kind
                        | (sample_kind << 8)
                        | (restore_kind << 16)
                        | ((observed.injected.published as u32) << 24)
                        | ((observed.restored.published as u32) << 25)
                        | ((sample.changed as u32) << 26),
                    read_bits,
                    sample.opcua_status,
                    sample_bits,
                    observed.restored_read.opcua_status,
                    observed.restored.last_publish_monotonic_ms as u32,
                    (observed.restored.last_publish_monotonic_ms >> 32) as u32,
                    restore_bits,
                    observed.restored.freshness_ms,
                ];
                write(&M7_CACHE_AGE_ROWS, (index * 12 + case) * 16, &row);
                self.rows += 1;
                // Raw results are retained before failure. These guards protect
                // restoration; independent host validation decides age outcomes.
                if observed.original != observed.restored
                    || observed.baseline != observed.restored_read
                    || sample.node_id != entry.node_id
                    || sample.client_handle != 1
                {
                    return self.finish(9, crate::uptime_now_ms_u64());
                }
            }
            endpoint_tags += 1;
            self.tags += 1;
        }
        let end = crate::uptime_now_ms_u64();
        write(
            &M7_CACHE_AGE_HEADER,
            header_offset + 19,
            &[end as u32, (end >> 32) as u32, endpoint_tags],
        );
        if public_index != 80 || endpoint_tags != [28, 21, 31][ep] {
            return self.finish(10, end);
        }
        M7_CACHE_AGE_HEADER.0[header_offset].store(1, Ordering::Relaxed);
        if self.seen == 7 {
            self.finish(0, end)
        } else {
            false
        }
    }

    fn finish(&mut self, reason: u32, now: u64) -> bool {
        self.enabled = false;
        write(
            &M7_CACHE_AGE_HEADER,
            1,
            &[
                1,
                self.seen,
                self.rows,
                self.tags,
                reason,
                self.generation.unwrap_or(0),
                now as u32,
                (now >> 32) as u32,
            ],
        );
        M7_CACHE_AGE_HEADER.0[0].store(if reason == 0 { 1 } else { 2 }, Ordering::Release);
        clean(&M7_CACHE_AGE_BASELINES);
        clean(&M7_CACHE_AGE_ROWS);
        clean(&M7_CACHE_AGE_HEADER);
        true
    }
}

fn scalar(value: Option<ScalarValue>) -> (u32, u32) {
    match value {
        None => (0, 0),
        Some(ScalarValue::Boolean(v)) => (1, v as u32),
        Some(ScalarValue::Int32(v)) => (2, v as u32),
        Some(ScalarValue::UInt32(v)) => (3, v),
        Some(ScalarValue::FloatMilli(v)) => (4, v as u32),
    }
}

#[allow(clippy::too_many_arguments)]
fn endpoint_header<const N: usize>(
    trust: Option<&RuntimeTrust>,
    generation: Option<u32>,
    checked: bool,
    data: &RuntimeDataAccess<N>,
    ep: u32,
    parsed_now: u64,
    start: u64,
    deadlines: [u32; 3],
) -> [u32; 80] {
    let mut w = [0; 80];
    let verifier = trust.and_then(|owner| owner.verifier_now_seconds());
    w[..19].copy_from_slice(&[
        0,
        0,
        1,
        ep,
        generation.is_some() as u32,
        generation.unwrap_or(0),
        trust.is_some() as u32,
        trust.map_or(0, |owner| owner.generation),
        trust.map_or(0, |owner| owner.state as u32),
        checked as u32,
        trust.is_some_and(|owner| owner.rtc_usable) as u32,
        crate::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed),
        data.trust_state() as u32,
        data.write_queue_depth() as u32,
        data.write_enabled() as u32,
        parsed_now as u32,
        (parsed_now >> 32) as u32,
        start as u32,
        (start >> 32) as u32,
    ]);
    w[22..27].copy_from_slice(&[
        [28, 21, 31][ep as usize],
        data.cache().completed_fetches(),
        data.cache().failed_fetches(),
        data.cache().last_http_status().unwrap_or(0) as u32,
        data.cache().last_fetch_ok() as u32,
    ]);
    w[27..36].copy_from_slice(&embassy_stm32::accelerated_clock_snapshot());
    w[36..40].copy_from_slice(&[
        probes::M7_WATCHDOG_ARMED.load(Ordering::Relaxed),
        probes::M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Relaxed),
        probes::M7_WATCHDOG_STALE_MASK.load(Ordering::Relaxed),
        probes::M7_WATCHDOG_LAST_KICK_MS.load(Ordering::Relaxed),
    ]);
    w[40..50].copy_from_slice(&crate::watchdog::diagnostic_initial_checkins());
    w[50..53].copy_from_slice(&deadlines);
    let seconds = verifier.unwrap_or(0);
    w[53..56].copy_from_slice(&[
        seconds as u32,
        (seconds >> 32) as u32,
        verifier.is_some() as u32,
    ]);
    w
}

fn write<const N: usize>(buffer: &Words<N>, start: usize, words: &[u32]) {
    for (slot, word) in buffer.0[start..start + words.len()].iter().zip(words) {
        slot.store(*word, Ordering::Relaxed);
    }
}

fn clean<const N: usize>(buffer: &Words<N>) {
    // SAFETY: sole-writer immutable publication owns complete 32-byte cache
    // lines. No concurrent writer/stack alias; clean finishes before the gate.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB
        .clean_dcache_by_address(buffer as *const _ as usize, core::mem::size_of_val(buffer));
    cortex_m::asm::dsb();
}

// SAFETY: fixed-signature Flash gate after immutable publication and DSB.
// Returns immediately without a debugger; no busy wait or volatile write.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_CACHE_AGE_GATE() {
    core::hint::black_box(M7_CACHE_AGE_HEADER.0[0].load(Ordering::Acquire));
}
