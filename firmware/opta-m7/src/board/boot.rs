//! Warm-launch interrupt normalization and cache/MPU policy for Ethernet DMA.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
#[cfg(feature = "product")]
use core::sync::atomic::Ordering;

#[cfg(feature = "product")]
use cortex_m::peripheral::scb::Exception;

#[cfg(feature = "product")]
use crate::probes::{M7_CACHE_CCR_PROBE, M7_MPU_CTRL_PROBE};

#[cfg(feature = "product")]
const ETH_DMA_MPU_REGION: u32 = 7;
#[cfg(feature = "product")]
const STACK_GUARD_MPU_REGION: u32 = 15;
#[cfg(feature = "product")]
const CORTEX_M7_MPU_REGION_COUNT: u32 = 16;
#[cfg(feature = "product")]
const ETH_DMA_MPU_BASE: u32 = 0x3000_0000;
#[cfg(all(feature = "product", not(feature = "diagnostic-ethernet-ingress")))]
const ETH_DMA_MPU_SIZE_BYTES: u32 = 64 * 1024;
#[cfg(all(feature = "product", not(feature = "diagnostic-ethernet-ingress")))]
const ETH_DMA_MPU_SIZE_FIELD: u32 = 15; // log2(64 KiB) - 1, ARMv7-M MPU RASR.SIZE.
#[cfg(feature = "diagnostic-ethernet-ingress")]
const ETH_DMA_MPU_SIZE_BYTES: u32 = 128 * 1024;
#[cfg(feature = "diagnostic-ethernet-ingress")]
const ETH_DMA_MPU_SIZE_FIELD: u32 = 16; // log2(128 KiB) - 1, ARMv7-M MPU RASR.SIZE.
#[cfg(feature = "product")]
pub(crate) const STACK_GUARD_MPU_SIZE_BYTES: u32 = 16 * 1024;
#[cfg(feature = "product")]
const STACK_GUARD_MPU_SIZE_FIELD: u32 = 13; // log2(16 KiB) - 1, ARMv7-M MPU RASR.SIZE.

#[cfg(feature = "product")]
// SAFETY: memory.x defines this 16-KiB-aligned boundary inside M7 RAM_D1;
// startup reads only its address before enabling interrupts.
unsafe extern "C" {
    static __stack_limit: u8;
}

/// Restore the historical cache-off DMA scaffold before Ethernet state is
/// initialized by a deliberate `--no-default-features` build.
///
/// The SWD `reset run` path can enter Rust with Cortex-M7 I-cache and D-cache
/// still enabled by the pre-application environment (the stock bootloader
/// enables both) while the MPU is disabled. With D-cache enabled, the
/// CPU-visible RX descriptors can be dirty in cache while the Ethernet DMA
/// reads stale memory and reports RBU. Unpublished historical bench
/// observations established this failure mode; they do not verify every
/// boot path or current hardware state.
#[cfg(not(feature = "product"))]
pub(crate) fn normalize_cache_state_for_dma() {
    // Steal the Cortex-M core-peripheral proxies at the start of the application,
    // before this crate otherwise takes them. `cortex-m`'s SCB methods implement
    // the Arm-required sequences: disabling D-cache clears CCR.DC and then
    // cleans/invalidates all D-cache lines with DSB/ISB; disabling I-cache clears
    // CCR.IC and invalidates I-cache. No peripheral, flash, option-byte, QSPI,
    // backup-register, or MPU-region state is modified.
    // SAFETY: no other code owns the core-peripheral proxies at this point.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB.disable_icache();
    cp.SCB.disable_dcache(&mut cp.CPUID);
}

/// Configure the default product cache policy: the Ethernet packet queue is in
/// a RAM_D2 MPU region programmed as Normal, shareable, non-cacheable memory,
/// then I-cache and D-cache are enabled for the rest of the system. The
/// default region is 64 KiB; the ingress-trace diagnostic feature uses 128 KiB so its
/// NOLOAD rings remain coherent with no-halt debugger reads. The declared diagnostic
/// P4 perturbation leaves only D-cache disabled while retaining the product
/// composition, I-cache, and identical MPU policy.
#[cfg(feature = "product")]
pub(crate) fn configure_cache_policy_for_dma() {
    // This first cleans/disables inherited cache state, then installs the
    // `.eth_dma` and stack-guard MPU regions.
    // SAFETY: this runs before interrupts, Embassy, or Ethernet initialization,
    // so no other Rust code owns the core peripherals or D2 packet queue.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    cp.SCB.disable_icache();
    cp.SCB.disable_dcache(&mut cp.CPUID);
    configure_product_mpu_regions();
    cp.SCB.enable(Exception::MemoryManagement);
    cp.SCB.enable_icache();
    #[cfg(not(feature = "diagnostic-dcache-disabled"))]
    cp.SCB.enable_dcache(&mut cp.CPUID);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    // SAFETY: SCB->CCR and MPU->CTRL are architecturally defined SCS registers.
    // The atomics are debugger-visible readback only.
    unsafe {
        const SCB_CCR: *const u32 = 0xE000_ED14 as *const u32;
        const MPU_CTRL: *const u32 = 0xE000_ED94 as *const u32;
        M7_CACHE_CCR_PROBE.store(SCB_CCR.read_volatile(), Ordering::Relaxed);
        M7_MPU_CTRL_PROBE.store(MPU_CTRL.read_volatile(), Ordering::Relaxed);
    }
}

#[cfg(feature = "product")]
fn configure_product_mpu_regions() {
    let eth_dma_rasr = (1 << 28) // XN: execute-never
        | (0b011 << 24) // AP: full privileged/unprivileged access
        | (0b001 << 19) // TEX level 1: Normal memory, outer/inner non-cacheable with C/B clear
        | (1 << 18) // S: shareable
        | (ETH_DMA_MPU_SIZE_FIELD << 1)
        | 1; // ENABLE
    let stack_guard_rasr = (1 << 28) // XN: execute-never
        | (STACK_GUARD_MPU_SIZE_FIELD << 1)
        | 1; // ENABLE with AP=0b000: no privileged or unprivileged access.
    let stack_guard_base = core::ptr::addr_of!(__stack_limit) as u32;

    // The STM32H747 Cortex-M7 implements 16 regions (DS12930 §3.2). A
    // bootloader or prior image can
    // leave enabled RBAR/RASR entries behind when it jumps to this application;
    // merely disabling MPU_CTRL does not clear them. Clear every inherited
    // region before installing region 7, otherwise a stale read-only Flash
    // region can turn field-config programming into a MemManage DACCVIOL.
    // PRIVDEFENA then preserves the privileged default memory map for every
    // non-MPU address. Region 7 targets the Rust `.eth_dma` D2 section, while
    // highest-priority region 15 makes the first 16 KiB at `__stack_limit`
    // no-access. The release build gate requires this band to be at least as
    // large as every permitted generated frame so one stack adjustment cannot
    // skip it. A deliberate single-large-frame target overflow must still
    // prove the resulting fault.
    // SAFETY: these are the ARMv7-M SCS MPU registers, and this startup path
    // has exclusive ownership before interrupts or application tasks run.
    unsafe {
        const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
        const MPU_RNR: *mut u32 = 0xE000_ED98 as *mut u32;
        const MPU_RBAR: *mut u32 = 0xE000_ED9C as *mut u32;
        const MPU_RASR: *mut u32 = 0xE000_EDA0 as *mut u32;
        MPU_CTRL.write_volatile(0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        for region in 0..CORTEX_M7_MPU_REGION_COUNT {
            MPU_RNR.write_volatile(region);
            MPU_RASR.write_volatile(0);
        }
        MPU_RNR.write_volatile(ETH_DMA_MPU_REGION);
        MPU_RBAR.write_volatile(ETH_DMA_MPU_BASE);
        MPU_RASR.write_volatile(eth_dma_rasr);
        MPU_RNR.write_volatile(STACK_GUARD_MPU_REGION);
        MPU_RBAR.write_volatile(stack_guard_base);
        MPU_RASR.write_volatile(stack_guard_rasr);
        MPU_CTRL.write_volatile((1 << 2) | 1); // PRIVDEFENA | ENABLE
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }

    debug_assert!(ETH_DMA_MPU_SIZE_BYTES == 64 * 1024 || ETH_DMA_MPU_SIZE_BYTES == 128 * 1024);
    assert!(stack_guard_base % STACK_GUARD_MPU_SIZE_BYTES == 0);
}

/// Make a warm debugger launch equivalent to a cold boot for interrupt
/// state: the previously flashed image (or the probe's PRIMASK=1 launch
/// guard) may leave SysTick running, NVIC lines enabled/pending, and PRIMASK
/// set — a real reset clears all of these in hardware.
pub(crate) fn normalize_interrupt_state_for_warm_launch() {
    // SAFETY: writes target architecturally defined Cortex-M7 SCS registers
    // (SYST_CSR, NVIC ICER/ICPR banks) with their documented disable/clear
    // semantics, before any interrupt-driven code runs; enabling interrupts
    // afterwards restores the architectural cold-boot PRIMASK state.
    unsafe {
        const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
        SYST_CSR.write_volatile(0);
        for bank in 0..16usize {
            const NVIC_ICER0: usize = 0xE000_E180;
            const NVIC_ICPR0: usize = 0xE000_E280;
            ((NVIC_ICER0 + bank * 4) as *mut u32).write_volatile(0xFFFF_FFFF);
            ((NVIC_ICPR0 + bank * 4) as *mut u32).write_volatile(0xFFFF_FFFF);
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        cortex_m::interrupt::enable();
    }
}
