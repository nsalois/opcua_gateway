// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Diagnostic-only Ethernet digest rings.
//!
//! The feature-gated vendored driver supplies already-bounded scalar digests;
//! this module timestamps them and publishes fixed-size NOLOAD rings for the
//! no-halt probe tool. The single Embassy network runner is the sole writer.
//! There is no allocator, drain task, wake source, or product-facing surface.
// Firmware policy marker: the crate root declares #![no_std]; this module must
// remain no-heap and no-alloc.

use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

use embassy_time::Instant;

pub const RX_RING_CAPACITY: usize = 2_048;
pub const TX_RING_CAPACITY: usize = 4_096;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RxDigest {
    pub uptime_ms: u32,
    pub seq_raw: u32,
    pub payload_len: u16,
    pub tcp_flags: u8,
    pub checksum_verdict: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TxDigest {
    pub uptime_ms: u32,
    pub ack_raw: u32,
    pub payload_len: u16,
    pub tcp_flags: u8,
    pub reserved: u8,
}

const _: [(); 12] = [(); size_of::<RxDigest>()];
const _: [(); 12] = [(); size_of::<TxDigest>()];

// SAFETY: these unique exported names form the read-only debugger ABI for the
// opt-in ingress-trace image and cannot collide with default-product symbols. The
// feature-specific startup path initializes them because `.eth_dma` is NOLOAD.
#[unsafe(link_section = ".eth_dma.f8_indices")]
#[unsafe(no_mangle)]
pub static M7_F8_RX_RING_WRITE_INDEX: AtomicU32 = AtomicU32::new(0);
// SAFETY: see the debugger ABI invariant above.
#[unsafe(link_section = ".eth_dma.f8_indices")]
#[unsafe(no_mangle)]
pub static M7_F8_TX_RING_WRITE_INDEX: AtomicU32 = AtomicU32::new(0);

// SAFETY: memory.x collects `.eth_dma.*` into the Normal/shareable/non-cacheable
// NOLOAD D2 section. The ring is never read by firmware before the single
// writer fills a slot; the no-halt tool uses the index to select initialized
// slots.
#[unsafe(link_section = ".eth_dma.f8_rx_ring")]
// SAFETY: the exported ring name is part of the same unique debugger ABI.
#[unsafe(no_mangle)]
pub static mut M7_F8_RX_RING: MaybeUninit<[RxDigest; RX_RING_CAPACITY]> = MaybeUninit::uninit();
// SAFETY: the same NOLOAD and single-writer invariant applies to the TX ring.
#[unsafe(link_section = ".eth_dma.f8_tx_ring")]
// SAFETY: the exported ring name is part of the same unique debugger ABI.
#[unsafe(no_mangle)]
pub static mut M7_F8_TX_RING: MaybeUninit<[TxDigest; TX_RING_CAPACITY]> = MaybeUninit::uninit();

/// Initialize the NOLOAD publication words after the non-cacheable MPU region
/// is installed and before the network runner can invoke either callback.
pub(crate) fn initialize() {
    M7_F8_RX_RING_WRITE_INDEX.store(0, Ordering::Relaxed);
    M7_F8_TX_RING_WRITE_INDEX.store(0, Ordering::Relaxed);
}

// SAFETY: this fixed scalar-only C ABI satisfies the feature-gated vendored
// driver callback. The caller passes no pointers, and the Embassy network
// runner is the sole writer of the RX ring.
#[unsafe(no_mangle)]
pub extern "C" fn opta_f8_record_rx_digest(
    seq_raw: u32,
    payload_len: u16,
    tcp_flags: u8,
    checksum_verdict: u8,
) {
    let entry = RxDigest {
        uptime_ms: Instant::now().as_millis() as u32,
        seq_raw,
        payload_len,
        tcp_flags,
        checksum_verdict,
    };
    let write_index = M7_F8_RX_RING_WRITE_INDEX.load(Ordering::Relaxed);
    let slot = (write_index as usize) % RX_RING_CAPACITY;
    let ring = core::ptr::addr_of_mut!(M7_F8_RX_RING).cast::<RxDigest>();
    // SAFETY: `slot` is reduced modulo the fixed ring capacity, `ring` points
    // to storage sized and aligned for that exact array, and the network
    // runner is the sole writer. Volatile prevents elision of debugger data.
    unsafe { ring.add(slot).write_volatile(entry) };
    compiler_fence(Ordering::Release);
    M7_F8_RX_RING_WRITE_INDEX.store(write_index.wrapping_add(1), Ordering::Release);
}

// SAFETY: this fixed scalar-only C ABI satisfies the feature-gated vendored
// driver callback. The caller passes no pointers, and the Embassy network
// runner is the sole writer of the TX ring.
#[unsafe(no_mangle)]
pub extern "C" fn opta_f8_record_tx_digest(ack_raw: u32, payload_len: u16, tcp_flags: u8) {
    let entry = TxDigest {
        uptime_ms: Instant::now().as_millis() as u32,
        ack_raw,
        payload_len,
        tcp_flags,
        reserved: 0,
    };
    let write_index = M7_F8_TX_RING_WRITE_INDEX.load(Ordering::Relaxed);
    let slot = (write_index as usize) % TX_RING_CAPACITY;
    let ring = core::ptr::addr_of_mut!(M7_F8_TX_RING).cast::<TxDigest>();
    // SAFETY: `slot` is reduced modulo the fixed ring capacity, `ring` points
    // to storage sized and aligned for that exact array, and the network
    // runner is the sole writer. Volatile prevents elision of debugger data.
    unsafe { ring.add(slot).write_volatile(entry) };
    compiler_fence(Ordering::Release);
    M7_F8_TX_RING_WRITE_INDEX.store(write_index.wrapping_add(1), Ordering::Release);
}
