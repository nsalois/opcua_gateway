// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Retained last-fault recording, exception vectors, and panic handling.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::hint::black_box;
use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use cortex_m_rt::{exception, ExceptionFrame};
use opta_gateway_contracts::last_fault::{self, LastFaultReason};

use crate::board;
use crate::probes::{M7_FAULT_REASON_PROBE, M7_LAST_FAULT_SEQUENCE_PROBE};
use crate::timebase::uptime_now_seconds;

fn read_last_fault_words_raw(
    _cs: critical_section::CriticalSection<'_>,
) -> last_fault::LastFaultWords {
    board::ensure_rtc_apb_clock_raw();
    // SAFETY: RTC_BKP0R starts at RTC base + 0x50 (RM0399 §49.6.20). Project
    // ownership assigns BKP2..BKP7 and BKP15 to the last-fault record; BKP0
    // and BKP8 are deliberately not read or written here.
    unsafe {
        const RTC_BKP0R: usize = 0x5800_4050;
        let read_bkp = |index: usize| ((RTC_BKP0R + index * 4) as *const u32).read_volatile();
        last_fault::LastFaultWords {
            magic: read_bkp(2),
            reason: read_bkp(3),
            sequence: read_bkp(4),
            uptime_word: read_bkp(5),
            detail: read_bkp(6),
            reset_flags: read_bkp(7),
            checksum: read_bkp(15),
        }
    }
}

fn write_last_fault_words_raw(
    _cs: critical_section::CriticalSection<'_>,
    words: last_fault::LastFaultWords,
) {
    board::enable_backup_domain_writes_raw();
    // SAFETY: RTC_BKP0R starts at RTC base + 0x50 (RM0399 §49.6.20). Writes
    // touch only BKP2..BKP7 and BKP15, matching the contract in
    // `opta_gateway_contracts::backup_domain`; BKP0 and BKP8 remain untouched.
    // Magic and checksum are invalidated before payload replacement, then the
    // final magic is committed last after a DSB. A maskable interruption cannot
    // observe a silently valid mixed record.
    // SAFETY: volatile accesses are limited to the assigned backup words above.
    unsafe {
        const RTC_BKP0R: usize = 0x5800_4050;
        let write_bkp =
            |index: usize, value: u32| ((RTC_BKP0R + index * 4) as *mut u32).write_volatile(value);
        write_bkp(2, 0);
        write_bkp(15, 0);
        cortex_m::asm::dsb();
        write_bkp(3, words.reason);
        write_bkp(4, words.sequence);
        write_bkp(5, words.uptime_word);
        write_bkp(6, words.detail);
        write_bkp(7, words.reset_flags);
        write_bkp(15, words.checksum);
        cortex_m::asm::dsb();
        write_bkp(2, words.magic);
        cortex_m::asm::dsb();
    }
    M7_LAST_FAULT_SEQUENCE_PROBE.store(words.sequence, Ordering::Relaxed);
}

pub(crate) fn update_last_fault_reset_flags(reset_flags: u32) -> last_fault::LastFaultRecord {
    critical_section::with(|cs| {
        let existing_words = read_last_fault_words_raw(cs);
        let existing = last_fault::decode_record(existing_words);
        let Some(updated_words) = last_fault::classify_reset_once(existing_words, reset_flags)
        else {
            return existing;
        };
        write_last_fault_words_raw(cs, updated_words);
        last_fault::decode_record(updated_words)
    })
}

pub(crate) fn persist_last_fault(reason: LastFaultReason, uptime_seconds: u32, detail: u32) {
    // The direct critical-section dependency covers the complete retained
    // read/decode/sequence/encode/probe/commit transaction against every
    // maskable runtime path, including the TIM7 watchdog executor. PRIMASK does
    // not mask HardFault or NMI; those handlers are nonreturning and either
    // replace the invalidated transaction completely or reset with it invalid.
    critical_section::with(|cs| {
        let existing = last_fault::decode_record(read_last_fault_words_raw(cs));
        let sequence = last_fault::next_sequence(existing.valid, existing.sequence);
        let words = last_fault::encode_pending_record(reason, sequence, uptime_seconds, detail);
        write_last_fault_words_raw(cs, words);
        M7_FAULT_REASON_PROBE.store(words.reason, Ordering::Relaxed);
    });
}

// SAFETY: this stable C ABI symbol is called by the vendored Embassy Ethernet
// driver timeout guard before it panics, so the firmware-specific last-fault
// probe records the precise reset reason without changing `Ethernet::new`'s API.
#[unsafe(no_mangle)]
pub extern "C" fn opta_record_eth_init_swr_timeout() {
    record_fault(LastFaultReason::EthInitSwrTimeout, 0, 0, 0);
}

#[inline(never)]
pub(crate) fn record_fault(reason: LastFaultReason, pc: u32, lr: u32, psr: u32) {
    let detail = last_fault::fault_detail_from_frame(pc, lr, psr);
    persist_last_fault(reason, uptime_now_seconds(), detail);
    black_box(detail);
}

#[inline(never)]
fn record_fault_if_none(reason: LastFaultReason, pc: u32, lr: u32, psr: u32) {
    if M7_FAULT_REASON_PROBE.load(Ordering::Relaxed) == LastFaultReason::None.as_word() {
        record_fault(reason, pc, lr, psr);
    }
}

#[exception]
// SAFETY: cortex-m-rt registers this as the non-returning HardFault vector.
// The handler writes the retained last-fault record and then requests a system reset.
unsafe fn HardFault(frame: &ExceptionFrame) -> ! {
    record_fault(
        LastFaultReason::HardFault,
        frame.pc(),
        frame.lr(),
        frame.xpsr(),
    );
    cortex_m::peripheral::SCB::sys_reset();
}

#[exception]
// SAFETY: cortex-m-rt registers this as the non-returning MemoryManagement
// vector. Product boot enables MEMFAULTENA after installing the MPU stack
// guard. The handler records the dedicated reason before requesting reset.
unsafe fn MemoryManagement() -> ! {
    record_fault(LastFaultReason::MemManageFault, 0, 0, 0);
    cortex_m::peripheral::SCB::sys_reset();
}

#[exception]
// SAFETY: cortex-m-rt registers this as the catch-all non-returning exception
// vector. The handler writes the retained last-fault record and then requests a
// system reset.
unsafe fn DefaultHandler(_irqn: i16) -> ! {
    record_fault_if_none(LastFaultReason::Assert, 0, 0, 0);
    cortex_m::peripheral::SCB::sys_reset();
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    record_fault_if_none(LastFaultReason::Assert, 0, 0, 0);
    cortex_m::peripheral::SCB::sys_reset();
}
