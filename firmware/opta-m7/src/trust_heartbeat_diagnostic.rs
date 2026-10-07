// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Finite startup trust recipes and records of actual timer-driven counter updates.
// Firmware policy marker: crate root declares #![no_std]; no alloc or std.

use core::sync::atomic::{AtomicU32, Ordering};
use opta_gateway_contracts::config::TrustState;

use crate::{probes, trust, uptime_now_ms_u64};

// SAFETY: sole finite input, writable only at the cache-disabled pre-HAL gate.
// Zero disables; 1..3 select fixed MAX-2/MAX-1/MAX recipes. No running setter.
#[unsafe(no_mangle)]
pub static M7_OWNER_COUNTER_RECIPE_INPUT: AtomicU32 = AtomicU32::new(0);
static STARTUP_RECIPE: AtomicU32 = AtomicU32::new(0);
static RECIPE: AtomicU32 = AtomicU32::new(0);
static HEARTBEATS: AtomicU32 = AtomicU32::new(0);
static REFRESHES: AtomicU32 = AtomicU32::new(0);
static FINISHED: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(32))]
pub struct Header(pub [AtomicU32; 64]);
#[repr(C, align(32))]
pub struct TrustRows(pub [[AtomicU32; 32]; 5]);
#[repr(C, align(32))]
pub struct TickRows(pub [[AtomicU32; 16]; 5]);
#[repr(C, align(32))]
pub struct MaterialWords(pub [AtomicU32; 1024]);

// SAFETY: whole-line aligned atomic records. Firmware alone writes; debugger
// reads only. Each extent is immutable before final cache cleaning/publication.
#[unsafe(no_mangle)]
pub static M7_OWNER_COUNTER_HEADER: Header = Header([const { AtomicU32::new(0) }; 64]);
// SAFETY: boot thread is the only writer, before executor tasks can run.
#[unsafe(no_mangle)]
pub static M7_OWNER_TRUST_ROWS: TrustRows =
    TrustRows([const { [const { AtomicU32::new(0) }; 32] }; 5]);
// SAFETY: main heartbeat is the only writer and stops after five real updates.
#[unsafe(no_mangle)]
pub static M7_OWNER_HEARTBEAT_ROWS: TickRows =
    TickRows([const { [const { AtomicU32::new(0) }; 16] }; 5]);
// SAFETY: interrupt watchdog monitor is the only writer and stops after five
// real updates. Release count / Acquire observation precedes final cleaning.
#[unsafe(no_mangle)]
pub static M7_OWNER_WATCHDOG_ROWS: TickRows =
    TickRows([const { [const { AtomicU32::new(0) }; 16] }; 5]);
// SAFETY: boot-only original/restored public CA bytes, padded to fixed extents.
// No Buchi credentials or private keys are copied. Immutable before publication.
#[unsafe(no_mangle)]
pub static M7_OWNER_TRUST_MATERIAL: MaterialWords =
    MaterialWords([const { AtomicU32::new(0) }; 1024]);

pub(crate) fn consume_startup_input() {
    let recipe = M7_OWNER_COUNTER_RECIPE_INPUT.load(Ordering::Relaxed);
    assert!(recipe <= 3, "owner counter recipe must select a fixed seed");
    STARTUP_RECIPE.store(recipe, Ordering::Relaxed);
}

fn store(destination: &[AtomicU32], words: &[u32]) {
    assert_eq!(destination.len(), words.len());
    for (destination, value) in destination.iter().zip(words) {
        destination.store(*value, Ordering::Relaxed);
    }
}

fn split(value: u64) -> [u32; 2] {
    [value as u32, (value >> 32) as u32]
}

fn record_material(bytes: &[u8], offset: usize) {
    assert!(bytes.len() <= 2048);
    for index in 0..512 {
        let mut word = [0u8; 4];
        for (byte, destination) in word.iter_mut().enumerate() {
            *destination = bytes.get(index * 4 + byte).copied().unwrap_or(0);
        }
        M7_OWNER_TRUST_MATERIAL.0[offset + index]
            .store(u32::from_le_bytes(word), Ordering::Relaxed);
    }
}

/// Exclusive access to the actual boot owner, after CA/RTC validation and before
/// any executor task. Only this one-time path can initialize the finite counters.
pub(crate) fn initialize(owner: &mut trust::RuntimeTrust, rtc_seconds: Option<u64>) {
    let recipe = STARTUP_RECIPE.swap(0, Ordering::Relaxed);
    if recipe == 0 {
        return;
    }
    // A second owner construction never consumes or overwrites the first case.
    if RECIPE
        .compare_exchange(0, recipe, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let seed = u32::MAX - (3 - recipe);
    let before_refresh = probes::M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Relaxed);
    let before_heartbeat = probes::M7_SPIN_COUNT.load(Ordering::Relaxed);
    let mut header = [0u32; 64];
    header[1..14].copy_from_slice(&[
        1,
        recipe,
        0,
        seed,
        owner.generation,
        trust::M7_BUCHI_TRUST_REVOCATIONS.load(Ordering::Relaxed),
        owner.state as u32,
        u32::from(owner.rtc_usable),
        u32::from(rtc_seconds.is_some()),
        rtc_seconds.unwrap_or(0) as u32,
        (rtc_seconds.unwrap_or(0) >> 32) as u32,
        owner.material.ca_der_len() as u32,
        u32::from(owner.material.time_provisioned()),
    ]);
    header[14..16].copy_from_slice(&split(uptime_now_ms_u64()));
    header[48..50].copy_from_slice(&split(owner.diagnostic_monotonic_origin()));
    let original_verifier = owner.verifier_now_seconds();
    header[50..52].copy_from_slice(&split(original_verifier.unwrap_or(0)));
    header[52] = u32::from(original_verifier.is_some());
    header[29..31].copy_from_slice(&[before_heartbeat, before_refresh]);
    let rejected = owner.state != TrustState::Provisioned
        || !owner.material.is_complete()
        || owner.generation != 0
        || header[6] != 0
        || trust::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed) != 0
        || owner.rtc_usable != rtc_seconds.is_some()
        || before_heartbeat != 0
        || before_refresh != 0;
    if rejected {
        header[3] = 1;
        store(&M7_OWNER_COUNTER_HEADER.0, &header);
        return;
    }
    let material = owner.material.clone();
    record_material(material.ca_der(), 0);
    owner.generation = seed;
    trust::M7_BUCHI_TRUST_REVOCATIONS.store(seed, Ordering::Relaxed);
    for index in 0..5 {
        let mut row = [0u32; 32];
        let old_generation = owner.generation;
        row[..4].copy_from_slice(&[
            index as u32 + 1,
            old_generation,
            trust::M7_BUCHI_TRUST_REVOCATIONS.load(Ordering::Relaxed),
            owner.state as u32,
        ]);
        owner.revoke();
        row[4..10].copy_from_slice(&[
            owner.generation,
            owner.state as u32,
            trust::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed),
            trust::M7_BUCHI_TRUST_REVOCATIONS.load(Ordering::Relaxed),
            u32::from(owner.material.is_anchor_present()),
            u32::from(owner.rtc_usable),
        ]);
        row[10..12].copy_from_slice(&split(owner.diagnostic_monotonic_origin()));
        row[12] =
            u32::from(owner.transition_if_generation(owner.generation, TrustState::Verified, 0));
        row[13] = owner.state as u32;
        // Always restore through the actual install method, even if a defective
        // guard accepted the revoked callback. No diagnostic failure skips this.
        if let Some(seconds) = rtc_seconds {
            owner.install(material.clone(), seconds);
        } else {
            owner.install_without_time(material.clone());
        }
        row[14..20].copy_from_slice(&[
            owner.generation,
            owner.state as u32,
            trust::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed),
            trust::M7_BUCHI_TRUST_REVOCATIONS.load(Ordering::Relaxed),
            u32::from(owner.material == material),
            u32::from(owner.rtc_usable),
        ]);
        let verifier = owner.verifier_now_seconds();
        row[20] = u32::from(verifier.is_some());
        row[21..23].copy_from_slice(&split(verifier.unwrap_or(0)));
        row[23..25].copy_from_slice(&split(owner.diagnostic_monotonic_origin()));
        // The stale/current positive cases target Provisioned, so the diagnostic
        // never invents Verified trust. Only the real later TLS path may do that.
        row[25] =
            u32::from(owner.transition_if_generation(old_generation, TrustState::Provisioned, 0));
        row[26] =
            u32::from(owner.transition_if_generation(owner.generation, TrustState::Provisioned, 0));
        row[27..29].copy_from_slice(&[owner.generation, owner.state as u32]);
        store(&M7_OWNER_TRUST_ROWS.0[index], &row);
    }
    header[16..18].copy_from_slice(&split(uptime_now_ms_u64()));
    header[18..25].copy_from_slice(&[
        owner.generation,
        trust::M7_BUCHI_TRUST_REVOCATIONS.load(Ordering::Relaxed),
        owner.state as u32,
        trust::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed),
        u32::from(owner.material == material),
        u32::from(owner.rtc_usable),
        u32::from(owner.verifier_now_seconds().is_some()),
    ]);
    header[25..27].copy_from_slice(&split(owner.verifier_now_seconds().unwrap_or(0)));
    header[27..29].copy_from_slice(&split(owner.diagnostic_monotonic_origin()));
    header[46] = owner.material.ca_der_len() as u32;
    header[47] = u32::from(owner.material.time_provisioned());
    record_material(owner.material.ca_der(), 512);
    probes::M7_SPIN_COUNT.store(seed, Ordering::Relaxed);
    probes::M7_WATCHDOG_REFRESH_COUNT.store(seed, Ordering::Relaxed);
    header[31..33].copy_from_slice(&[
        probes::M7_SPIN_COUNT.load(Ordering::Relaxed),
        probes::M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Relaxed),
    ]);
    store(&M7_OWNER_COUNTER_HEADER.0, &header);
}

fn record_tick(rows: &TickRows, count: &AtomicU32, before: u32, after: u32, now: u64, branch: u32) {
    if RECIPE.load(Ordering::Acquire) == 0
        || M7_OWNER_COUNTER_HEADER.0[3].load(Ordering::Relaxed) != 0
    {
        return;
    }
    let index = count.load(Ordering::Relaxed) as usize;
    if index >= 5 {
        return;
    }
    let mut row = [0u32; 16];
    row[..10].copy_from_slice(&[
        index as u32 + 1,
        before,
        after,
        now as u32,
        (now >> 32) as u32,
        probes::M7_WATCHDOG_ARMED.load(Ordering::Relaxed),
        probes::M7_WATCHDOG_STALE_MASK.load(Ordering::Relaxed),
        branch,
        probes::M7_WATCHDOG_LAST_KICK_MS.load(Ordering::Relaxed),
        probes::M7_FAULT_REASON_PROBE.load(Ordering::Relaxed),
    ]);
    store(&rows.0[index], &row);
    count.store(index as u32 + 1, Ordering::Release);
}

pub(crate) fn heartbeat(before: u32, after: u32, now: u64) {
    record_tick(&M7_OWNER_HEARTBEAT_ROWS, &HEARTBEATS, before, after, now, 0);
}

pub(crate) fn refresh(before: u32, after: u32, now: u64, maintenance: bool) {
    record_tick(
        &M7_OWNER_WATCHDOG_ROWS,
        &REFRESHES,
        before,
        after,
        now,
        u32::from(maintenance),
    );
}

/// Thread-mode only. The watchdog writer has stopped before cache maintenance;
/// real TLS verification is a separate prerequisite, never synthesized here.
pub(crate) fn try_finish(shared: &trust::SharedTrust) {
    if RECIPE.load(Ordering::Acquire) == 0 || FINISHED.load(Ordering::Acquire) != 0 {
        return;
    }
    let rejected = M7_OWNER_COUNTER_HEADER.0[3].load(Ordering::Relaxed) != 0;
    if !rejected
        && (HEARTBEATS.load(Ordering::Acquire) != 5 || REFRESHES.load(Ordering::Acquire) != 5)
    {
        return;
    }
    let Ok(owner) = shared.try_lock() else {
        return;
    };
    if !rejected
        && (owner.state != TrustState::Verified
            || trust::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed) != 0
            || trust::M7_BUCHI_TRUST_VERIFIED_SESSIONS.load(Ordering::Relaxed) == 0)
    {
        return;
    }
    let now = uptime_now_ms_u64();
    let header = &M7_OWNER_COUNTER_HEADER.0;
    store(
        &header[33..44],
        &[
            HEARTBEATS.load(Ordering::Acquire),
            REFRESHES.load(Ordering::Acquire),
            probes::M7_SPIN_COUNT.load(Ordering::Relaxed),
            probes::M7_WATCHDOG_REFRESH_COUNT.load(Ordering::Relaxed),
            probes::M7_WATCHDOG_ARMED.load(Ordering::Relaxed),
            probes::M7_WATCHDOG_STALE_MASK.load(Ordering::Relaxed),
            0,
            owner.generation,
            owner.state as u32,
            trust::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed),
            trust::M7_BUCHI_TRUST_VERIFIED_SESSIONS.load(Ordering::Relaxed),
        ],
    );
    store(&header[44..46], &split(now));
    FINISHED.store(1, Ordering::Release);
    header[0].store(if rejected { 2 } else { 1 }, Ordering::Release);
    // SAFETY: no task writes these extents after the five-entry Release counts.
    // Atomic stores and Acquire counts synchronize the interrupt writer. The
    // aligned immutable extents own complete lines; never clean a live stack.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    for (address, bytes) in [
        (
            &M7_OWNER_COUNTER_HEADER as *const _ as usize,
            core::mem::size_of_val(&M7_OWNER_COUNTER_HEADER),
        ),
        (
            &M7_OWNER_TRUST_ROWS as *const _ as usize,
            core::mem::size_of_val(&M7_OWNER_TRUST_ROWS),
        ),
        (
            &M7_OWNER_HEARTBEAT_ROWS as *const _ as usize,
            core::mem::size_of_val(&M7_OWNER_HEARTBEAT_ROWS),
        ),
        (
            &M7_OWNER_WATCHDOG_ROWS as *const _ as usize,
            core::mem::size_of_val(&M7_OWNER_WATCHDOG_ROWS),
        ),
        (
            &M7_OWNER_TRUST_MATERIAL as *const _ as usize,
            core::mem::size_of_val(&M7_OWNER_TRUST_MATERIAL),
        ),
    ] {
        cp.SCB.clean_dcache_by_address(address, bytes);
    }
    cortex_m::asm::dsb();
    drop(owner);
    M7_OWNER_COUNTER_GATE();
}

// SAFETY: one-shot readback breakpoint. It does not wait or modify state.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn M7_OWNER_COUNTER_GATE() {
    core::hint::black_box(M7_OWNER_COUNTER_HEADER.0[0].load(Ordering::Acquire));
}
