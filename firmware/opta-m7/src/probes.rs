//! Stable debugger/HIL probe symbols and boot-stage breadcrumbs.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::hint::black_box;
use core::sync::atomic::{AtomicU32, Ordering};

use opta_gateway_contracts::boot::{self, BootStage};
#[cfg(feature = "product")]
use opta_runtime::LoopTimingSnapshot;

pub(crate) const M7_BOOT_SENTINEL_RESET_ENTERED: u32 = 0x4D37_0001;
pub(crate) const M7_BOOT_SENTINEL_LOOP_ENTERED: u32 = 0x4D37_0002;

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_BOOT_SENTINEL: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_SPIN_COUNT: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_BOOT_STAGE_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_FAULT_REASON_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_UPTIME_MS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbols for lifetime main-loop timing;
// Rust owns all writes and publishes readiness after a complete measurement.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_LOOP_MAX_GAP_MS: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_HEARTBEAT_MAX_GAP_MS: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_LATE_HEARTBEAT_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readiness symbol; Rust publishes it last.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_LOOP_TIMING_READY: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbols for product TLS handshake
// duration. Rust owns all writes through the atomic objects.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_TLS_LAST_HANDSHAKE_MS: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_TLS_MAX_HANDSHAKE_MS: AtomicU32 = AtomicU32::new(0);

// SAFETY: these stable symbol names are exported for debugger/HIL readback of
// the product IWDG check-in monitor; Rust code owns all writes through atomics.
#[unsafe(no_mangle)]
pub static M7_RESET_FLAGS_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: this diagnostic-only stable symbol publishes the read-only reset
// classification handed off by the exact Opta bootloader in RTC_BKP8R. Rust
// owns the atomic write and never writes the bootloader-owned register.
#[cfg(feature = "diagnostic-pre-clock-stall")]
#[unsafe(no_mangle)]
pub static M7_BOOTLOADER_RESET_REASON_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable D1 debugger/HIL symbols for read-only CM4 boot-authorization
// observation. Rust owns every write through these atomic objects.
#[unsafe(no_mangle)]
pub static M7_CM4_RCC_APB4ENR_PRE: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_CM4_SYSCFG_UR1_RAW: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_CM4_RCC_CR_RAW: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_CM4_RCC_GCR_PRE_INIT: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_CM4_RCC_GCR_POST_INIT: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_CM4_RCC_GCR_POST_WW1RSC: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL state symbol. Values 0..3 are defined by the
// shared CM4 authorization contract and describe authorization, not execution.
#[unsafe(no_mangle)]
pub static M7_CM4_STATE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_ARMED: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for the exact early-watchdog
// failure bitmask; Rust owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_EARLY_IWDG_FAILURE_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_STALE_MASK: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_OBSERVED_STALE_SLOTS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_PUBLIC_FRESH_MASK: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_LAST_KICK_MS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_REFRESH_COUNT: AtomicU32 = AtomicU32::new(0);

// SAFETY: diagnostic-only stable symbols for the CPU-busy preemption proof;
// Rust owns all writes and target tooling reads them only after readiness.
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_CPU_BUSY_START_REFRESH_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol.
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_CPU_BUSY_END_REFRESH_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol.
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_CPU_BUSY_ELAPSED_MS: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol, published last.
#[cfg(feature = "diagnostic-watchdog-cpu-busy")]
#[unsafe(no_mangle)]
pub static M7_WATCHDOG_CPU_BUSY_PASSED: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_LAST_FAULT_SEQUENCE_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_INDUCED_HANG_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: diagnostic-only stable symbols for the two-boot stack-watermark
// harness. Rust owns all writes through atomics; the debugger only reads them.
#[cfg(feature = "diagnostic-stack-watermark")]
#[unsafe(no_mangle)]
pub static M7_STACK_WATERMARK_PHASE: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol.
#[cfg(feature = "diagnostic-stack-watermark")]
#[unsafe(no_mangle)]
pub static M7_STACK_WATERMARK_PAINT_START: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol.
#[cfg(feature = "diagnostic-stack-watermark")]
#[unsafe(no_mangle)]
pub static M7_STACK_WATERMARK_PAINT_END: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol.
#[cfg(feature = "diagnostic-stack-watermark")]
#[unsafe(no_mangle)]
pub static M7_STACK_GUARD_BASE: AtomicU32 = AtomicU32::new(0);
// SAFETY: diagnostic-only stable debugger readback symbol.
#[cfg(feature = "diagnostic-stack-watermark")]
#[unsafe(no_mangle)]
pub static M7_STACK_GUARD_BYTES: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL symbols for the diagnostic-only P05 LSE
// retention instrument. Rust owns all writes and publishes STATUS last.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_RTC_CAPTURE_STATUS: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_RTC_CAPTURE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RCC_BDCR: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RTC_ISR: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RTC_PRER: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RTC_SSR_BEFORE: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RTC_TR: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RTC_DR: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-lse-retention")]
#[unsafe(no_mangle)]
pub static M7_P05_BOOT_RTC_SSR_AFTER: AtomicU32 = AtomicU32::new(0);

/// Capture the first coherent raw RTC sample after `Rtc::new` and before the
/// immutable runtime trust snapshot is derived. The SSR/TR/DR/SSR retry shape
/// mirrors Embassy's retained-calendar read and RM0399 section 49.3.9.
#[cfg(feature = "diagnostic-lse-retention")]
pub(crate) fn capture_boot_rtc() {
    const COHERENT: u32 = 1;
    const INCOHERENT: u32 = 2;
    const MAX_ATTEMPTS: u32 = 5;

    let rtc = stm32_metapac::RTC;
    M7_P05_RTC_CAPTURE_STATUS.store(0, Ordering::Relaxed);
    M7_P05_BOOT_RCC_BDCR.store(stm32_metapac::RCC.bdcr().read().0, Ordering::Relaxed);
    M7_P05_BOOT_RTC_ISR.store(rtc.isr().read().0, Ordering::Relaxed);
    M7_P05_BOOT_RTC_PRER.store(rtc.prer().read().0, Ordering::Relaxed);

    let mut ss_before = rtc.ssr().read().0;
    for attempt in 1..=MAX_ATTEMPTS {
        let tr = rtc.tr().read().0;
        let dr = rtc.dr().read().0;
        let ss_after = rtc.ssr().read().0;

        M7_P05_RTC_CAPTURE_ATTEMPTS.store(attempt, Ordering::Relaxed);
        M7_P05_BOOT_RTC_SSR_BEFORE.store(ss_before, Ordering::Relaxed);
        M7_P05_BOOT_RTC_TR.store(tr, Ordering::Relaxed);
        M7_P05_BOOT_RTC_DR.store(dr, Ordering::Relaxed);
        M7_P05_BOOT_RTC_SSR_AFTER.store(ss_after, Ordering::Relaxed);

        if ss_before == ss_after {
            M7_P05_RTC_CAPTURE_STATUS.store(COHERENT, Ordering::Release);
            return;
        }
        ss_before = ss_after;
    }

    M7_P05_RTC_CAPTURE_STATUS.store(INCOHERENT, Ordering::Release);
}

// SAFETY: stable debugger/HIL readback symbol for USB-console task check-ins;
// Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_CHECKIN_COUNT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable target-observation symbols for USB Bus events and EP0 setup;
// Rust owns all writes through atomics. Event bits are Reset, Suspend, Resume,
// PowerDetected, and PowerRemoved in that order.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_BUS_EVENT_MASK: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_LAST_BUS_EVENT: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_BUS_EVENT_COUNT: AtomicU32 = AtomicU32::new(0);
// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_CONTROL_SETUP_COUNT: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_IPV4_ADDR: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback in the
// build-only M7 smoke path; Rust code owns all writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_LINK_STATE: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback of
// bounded Ethernet init recovery; Rust code owns all writes through the atomic
// object.
#[unsafe(no_mangle)]
pub static M7_ETH_INIT_RETRIES: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for the raw product ETH DMA
// channel status register; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_DMA_STATUS_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol that accumulates product RBU,
// DMA missed-frame, and MTL RX queue overflow/missed-packet indications;
// Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_RX_DROP_EVENTS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for the free-running MAC Rx CRC
// error packet counter; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_RX_CRC_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for the free-running MAC Rx
// alignment error packet counter; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_RX_ALIGNMENT_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for the free-running MAC Rx LPI
// transition counter; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_RX_LPI_TRANSITION_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbols for the RM0399-documented MMC
// control word and remaining supported counter set; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_MMC_CONTROL_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_TX_PACKET_COUNT_GOOD_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_TX_SINGLE_COLLISION_GOOD_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_TX_MULTIPLE_COLLISION_GOOD_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_RX_UNICAST_GOOD_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_TX_LPI_USEC_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_TX_LPI_TRANSITION_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_MAC_RX_LPI_USEC_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbols for the feature-gated vendored
// driver's invalid RX-descriptor path; Rust owns all writes through atomics.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_RX_INVALID_DESCRIPTOR_POP_COUNT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_RX_LAST_INVALID_RDES3: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub static M7_ETH_RX_LAST_INVALID_RDES1: AtomicU32 = AtomicU32::new(0);

// SAFETY: this fixed C ABI symbol satisfies the feature-gated vendored
// Embassy driver callback. The function only performs atomic writes to
// Rust-owned probe objects and has no pointer or lifetime preconditions.
#[cfg(feature = "diagnostic-ethernet-ingress")]
#[unsafe(no_mangle)]
pub extern "C" fn opta_f8_record_invalid_rx_descriptor(rdes3: u32, rdes1: u32) {
    M7_ETH_RX_LAST_INVALID_RDES3.store(rdes3, Ordering::Relaxed);
    M7_ETH_RX_LAST_INVALID_RDES1.store(rdes1, Ordering::Relaxed);
    M7_ETH_RX_INVALID_DESCRIPTOR_POP_COUNT.fetch_add(1, Ordering::Relaxed);
}

// SAFETY: stable debugger/HIL readback symbol for LAN8742A SECR raw reads;
// Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_PHY_SECR_RAW_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for LAN8742A ANLPAR link-up
// snapshots; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_PHY_ANLPAR_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol for LAN8742A PHYSCSR link-up
// snapshots; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_ETH_PHY_PHYSCSR_SNAPSHOT: AtomicU32 = AtomicU32::new(0);

// SAFETY: this stable symbol name is exported only for debugger readback of
// inherited Cortex-M7 cache state at application entry; Rust code owns all
// writes through the atomic object.
#[unsafe(no_mangle)]
pub static M7_ENTRY_CCR: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes for
// the product cache-on/D2 MPU policy.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_CACHE_CCR_PROBE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes for
// the product cache-on/D2 MPU policy.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_MPU_CTRL_PROBE: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "product")]
pub(crate) fn publish_loop_timing(snapshot: LoopTimingSnapshot) {
    M7_LOOP_MAX_GAP_MS.store(snapshot.loop_max_gap_ms, Ordering::Relaxed);
    M7_HEARTBEAT_MAX_GAP_MS.store(snapshot.heartbeat_max_gap_ms, Ordering::Relaxed);
    M7_LATE_HEARTBEAT_COUNT.store(snapshot.late_heartbeat_count, Ordering::Relaxed);
    M7_LOOP_TIMING_READY.store(1, Ordering::Release);
}

#[cfg(feature = "product")]
pub(crate) fn snapshot_loop_timing() -> Option<LoopTimingSnapshot> {
    if M7_LOOP_TIMING_READY.load(Ordering::Acquire) == 0 {
        return None;
    }
    Some(LoopTimingSnapshot {
        loop_max_gap_ms: M7_LOOP_MAX_GAP_MS.load(Ordering::Relaxed),
        heartbeat_max_gap_ms: M7_HEARTBEAT_MAX_GAP_MS.load(Ordering::Relaxed),
        late_heartbeat_count: M7_LATE_HEARTBEAT_COUNT.load(Ordering::Relaxed),
    })
}

#[cfg(feature = "product")]
pub(crate) fn record_tls_handshake_duration(elapsed_ms: u64) {
    let elapsed_ms = elapsed_ms.min(u64::from(u32::MAX)) as u32;
    M7_TLS_LAST_HANDSHAKE_MS.store(elapsed_ms, Ordering::Relaxed);
    M7_TLS_MAX_HANDSHAKE_MS.fetch_max(elapsed_ms, Ordering::Relaxed);
}

#[inline(never)]
pub(crate) fn record_boot_stage(stage: BootStage) {
    let breadcrumb = boot::encode_breadcrumb(stage, false, 0, 0, 0);
    M7_BOOT_STAGE_PROBE.store(breadcrumb.stage, Ordering::Relaxed);
    black_box(breadcrumb.checksum);
}
