// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! PHY/SWR preparation and Ethernet DMA packet-queue storage.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::hint::spin_loop;
#[cfg(feature = "product")]
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use embassy_stm32::eth::PacketQueue;
use embassy_time::{Instant, Timer};
use opta_gateway_contracts::last_fault::LastFaultReason;
use rtt_target::rprintln;
#[cfg(not(feature = "product"))]
use static_cell::StaticCell;

use crate::board::PRODUCTION_MDIO;
use crate::fault::{opta_record_eth_init_swr_timeout, record_fault};
use crate::probes::M7_ETH_INIT_RETRIES;
#[cfg(feature = "diagnostic-ethernet-ingress")]
use crate::probes::M7_ETH_MAC_MMC_CONTROL_SNAPSHOT;

const ETH_INIT_MAX_ATTEMPTS: u32 = 3;
const ETH_SWR_TIMEOUT_MS: u64 = 500;
const PHY_MDIO_TIMEOUT_MS: u64 = 500;
/// LAN8742A Rev 1.1 Table 5.11 `trstia`: nRST assertion min 100 µs (§5.6.3).
const PHY_NRST_ASSERT_MS: u64 = 10;
/// LAN8742A Rev 1.1 Table 5.11 `tpurstd`: 25 ms min from supplies to nRST
/// deassert; §3.7.2 strap latch completes on nRST rising edge.
const PHY_SETTLE_MS: u64 = 500;
const LAN8742_PHY_ADDR: u8 = 0;
const PHY_REG_BMCR: u8 = 0;
const PHY_REG_ID1: u8 = 2;
const PHY_REG_ID2: u8 = 3;
const PHY_REG_SPECIAL_MODES: u8 = 18;
const PHY_BMCR_POWER_DOWN: u16 = 1 << 11;
const PHY_BMCR_ISOLATE: u16 = 1 << 10;
const LAN8742_ID1: u16 = 0x0007;
const LAN8742_ID2_MASK: u16 = 0xFFF0;
const LAN8742_ID2_MODEL: u16 = 0xC130;
const LAN8742_MODE_ALL_CAPABLE: u16 = 0b111;
const ETH_PACKET_QUEUE_TX_SLOTS: usize = 16;
#[cfg(feature = "diagnostic-ethernet-rx-ring-16")]
const ETH_PACKET_QUEUE_RX_SLOTS: usize = 16;
#[cfg(not(feature = "diagnostic-ethernet-rx-ring-16"))]
const ETH_PACKET_QUEUE_RX_SLOTS: usize = 8;
pub(crate) type EthPacketQueue = PacketQueue<ETH_PACKET_QUEUE_TX_SLOTS, ETH_PACKET_QUEUE_RX_SLOTS>;

#[cfg(feature = "diagnostic-ethernet-ingress")]
pub(crate) fn configure_ethernet_mmc_counters() {
    let control = stm32_metapac::ETH.ethernet_mac().mmc_control();
    control.modify(|w| {
        // RM0399 61.11.4: leave reset/preset deasserted, permit wrapping,
        // disable destructive reads, and keep the supported counters live.
        w.set_cntrst(false);
        w.set_cntstopro(false);
        w.set_rstonrd(false);
        w.set_cntfreez(false);
        w.set_cntprst(false);
    });
    M7_ETH_MAC_MMC_CONTROL_SNAPSHOT.store(control.read().0, Ordering::Relaxed);
}

// ETH DMA descriptor rings + packet buffers. The default product keeps the
// HIL-proven cache-on policy: the packet queue lives in RAM_D2 `.eth_dma`, and
// `configure_cache_policy_for_dma()` programs the matching non-cacheable MPU
// region before re-enabling I/D cache. The cache-off path remains available
// only to a deliberate `--no-default-features` scaffold build.
#[cfg(feature = "product")]
#[repr(align(32))]
struct EthPacketQueueStorage(MaybeUninit<EthPacketQueue>);

#[cfg(feature = "product")]
// SAFETY: the linker section is declared in memory.x at RAM_D2 origin and is
// initialized explicitly by `init_eth_packets()` before Embassy can use it.
#[unsafe(link_section = ".eth_dma")]
static mut ETH_PACKETS: EthPacketQueueStorage = EthPacketQueueStorage(MaybeUninit::uninit());

#[cfg(not(feature = "product"))]
pub(crate) static ETH_PACKETS: StaticCell<EthPacketQueue> = StaticCell::new();

#[cfg(feature = "product")]
#[inline(always)]
pub(crate) fn init_eth_packets() -> &'static mut EthPacketQueue {
    // SAFETY: `main()` calls this exactly once before interrupts or the
    // Ethernet runner can access the packet queue. The D2 `.eth_dma` section is
    // intentionally NOLOAD, so write a fresh PacketQueue before handing it to
    // Embassy instead of relying on reset-time zeroing of a custom section.
    unsafe {
        let queue = &mut *core::ptr::addr_of_mut!(ETH_PACKETS.0);
        EthPacketQueue::init(queue);
        &mut *queue.as_mut_ptr()
    }
}

#[derive(Clone, Copy, Debug)]
enum EthInitError {
    MdioBusy,
    PhyIdMismatch,
    StrapLatchFailed,
    SwrTimeout,
}

/// Enable the Ethernet MAC/TX/RX bus clocks before raw pre-gate register use.
fn enable_eth_ahb_clocks_raw() {
    // SAFETY: RCC_AHB1ENR (0x5802_44D8) is the STM32H747 AHB1 peripheral-clock
    // enable register. Bits 15/16/17 enable the ETH MAC, ETH TX, and ETH RX
    // clocks; read-back plus DSB orders the writes before MDIO/DMAMR access.
    unsafe {
        const RCC_AHB1ENR: *mut u32 = 0x5802_44D8 as *mut u32;
        RCC_AHB1ENR.write_volatile(RCC_AHB1ENR.read_volatile() | (1 << 15) | (1 << 16) | (1 << 17));
        let _ = RCC_AHB1ENR.read_volatile();
        cortex_m::asm::dsb();
    }
}

/// Configure RMII/SMI pins to AF11 before the app-level SWR pre-gate.
fn configure_rmii_pins_for_eth_pregate() {
    // SAFETY: RCC_AHB4ENR and GPIOx registers are STM32H747 memory-mapped
    // registers. The pins and AF11 mapping match the accepted Opta RMII pin map
    // used by `Ethernet::new`; this pre-configures the same pins before the raw
    // SWR pre-gate, and Embassy reclaims/configures the typed pin owners later.
    unsafe {
        const RCC_AHB4ENR: *mut u32 = 0x5802_44E0 as *mut u32;
        const GPIOA: usize = 0x5802_0000;
        const GPIOC: usize = 0x5802_0800;
        const GPIOG: usize = 0x5802_1800;
        RCC_AHB4ENR.write_volatile(RCC_AHB4ENR.read_volatile() | (1 << 0) | (1 << 2) | (1 << 6));
        let _ = RCC_AHB4ENR.read_volatile();

        configure_gpio_af(GPIOA, 1, 11); // RMII REF_CLK
        configure_gpio_af(GPIOA, 2, 11); // MDIO
        configure_gpio_af(GPIOA, 7, 11); // CRS_DV
        configure_gpio_af(GPIOC, 1, 11); // MDC
        configure_gpio_af(GPIOC, 4, 11); // RXD0
        configure_gpio_af(GPIOC, 5, 11); // RXD1
        configure_gpio_af(GPIOG, 11, 11); // TX_EN
        configure_gpio_af(GPIOG, 12, 11); // TXD1
        configure_gpio_af(GPIOG, 13, 11); // TXD0
        cortex_m::asm::dsb();
    }
}

fn configure_gpio_af(base: usize, pin: u8, af: u8) {
    let pin_shift = u32::from(pin) * 2;
    let afr_shift = u32::from(pin % 8) * 4;
    let moder = base as *mut u32;
    let otyper = (base + 0x04) as *mut u32;
    let ospeedr = (base + 0x08) as *mut u32;
    let pupdr = (base + 0x0C) as *mut u32;
    let afr = (base + if pin < 8 { 0x20 } else { 0x24 }) as *mut u32;

    // SAFETY: the caller supplies a valid GPIO peripheral base and pin number
    // from the fixed Opta RMII pin map; writes touch only the selected pin's
    // mode, output type, speed, pull, and alternate-function fields.
    unsafe {
        moder.write_volatile((moder.read_volatile() & !(0b11 << pin_shift)) | (0b10 << pin_shift));
        otyper.write_volatile(otyper.read_volatile() & !(1 << u32::from(pin)));
        ospeedr
            .write_volatile((ospeedr.read_volatile() & !(0b11 << pin_shift)) | (0b11 << pin_shift));
        pupdr.write_volatile(pupdr.read_volatile() & !(0b11 << pin_shift));
        afr.write_volatile(
            (afr.read_volatile() & !(0xF << afr_shift)) | (u32::from(af) << afr_shift),
        );
    }
}

fn elapsed_since_ms(start_ms: u64) -> u64 {
    Instant::now().as_millis().wrapping_sub(start_ms)
}

fn wait_mdio_ready(timeout_ms: u64) -> Result<(), EthInitError> {
    // SAFETY: ETH_MACMDIOAR (0x4002_8200) is the STM32H747 Ethernet MDIO
    // address register. Polling bit 0 observes MAC ownership of the SMI bus.
    unsafe {
        const ETH_MACMDIOAR: *mut u32 = 0x4002_8200 as *mut u32;
        let start = Instant::now().as_millis();
        while ETH_MACMDIOAR.read_volatile() & 1 != 0 {
            if elapsed_since_ms(start) >= timeout_ms {
                return Err(EthInitError::MdioBusy);
            }
            spin_loop();
        }
    }
    Ok(())
}

fn mdio_read(phy_addr: u8, reg: u8, timeout_ms: u64) -> Result<u16, EthInitError> {
    wait_mdio_ready(timeout_ms)?;
    // SAFETY: ETH_MACMDIOAR/ETH_MACMDIODR are the STM32H747 Ethernet MDIO
    // address/data registers. Clause-22 read uses GOC=0b11 and the same
    // HCLK/102 CR=4 selection as the H7 `eth/sma/v2.rs` driver at 200 MHz.
    unsafe {
        const ETH_MACMDIOAR: *mut u32 = 0x4002_8200 as *mut u32;
        const ETH_MACMDIODR: *const u32 = 0x4002_8204 as *const u32;
        let command = (u32::from(phy_addr) << 21)
            | (u32::from(reg) << 16)
            | (PRODUCTION_MDIO.clock_range << 8)
            | (0b11 << 2)
            | 1;
        ETH_MACMDIOAR.write_volatile(command);
        wait_mdio_ready(timeout_ms)?;
        Ok((ETH_MACMDIODR.read_volatile() & 0xFFFF) as u16)
    }
}

fn mdio_write(phy_addr: u8, reg: u8, val: u16, timeout_ms: u64) -> Result<(), EthInitError> {
    wait_mdio_ready(timeout_ms)?;
    // SAFETY: ETH_MACMDIOAR/ETH_MACMDIODR are the STM32H747 Ethernet MDIO
    // address/data registers. Clause-22 write uses GOC=0b01 and the same
    // HCLK/102 CR=4 selection as the H7 `eth/sma/v2.rs` driver at 200 MHz.
    unsafe {
        const ETH_MACMDIOAR: *mut u32 = 0x4002_8200 as *mut u32;
        const ETH_MACMDIODR: *mut u32 = 0x4002_8204 as *mut u32;
        ETH_MACMDIODR.write_volatile(u32::from(val));
        let command = (u32::from(phy_addr) << 21)
            | (u32::from(reg) << 16)
            | (PRODUCTION_MDIO.clock_range << 8)
            | (0b01 << 2)
            | 1;
        ETH_MACMDIOAR.write_volatile(command);
        wait_mdio_ready(timeout_ms)
    }
}

fn verify_lan8742_phy_id() -> Result<(), EthInitError> {
    let id1 = mdio_read(LAN8742_PHY_ADDR, PHY_REG_ID1, PHY_MDIO_TIMEOUT_MS)?;
    let id2 = mdio_read(LAN8742_PHY_ADDR, PHY_REG_ID2, PHY_MDIO_TIMEOUT_MS)?;
    if id1 == LAN8742_ID1 && (id2 & LAN8742_ID2_MASK) == LAN8742_ID2_MODEL {
        Ok(())
    } else {
        Err(EthInitError::PhyIdMismatch)
    }
}

/// Pulse PJ15 (`ETH.RST`, active-low) to hard-reset the LAN8742A PHY.
///
/// Provenance: Opta schematic AFX00001-3 U3B net `ETH.RST` on PJ15 (ball B10),
/// inferred from consecutive PJ-column BLE nets matching `CYBSP_BT_POWER` =
/// PJ_12 through `CYBSP_BT_DEVICE_WAKE` = PJ_14 in TARGET_OPTA/PinNames.h;
/// confirmed on bench in STEP 2b (`step2b-int3-pj15.log`). RXD0/RXD1/CRS_DV must
/// remain AF inputs during the pulse so the PHY's internal pulls own the strap
/// latch — `configure_rmii_pins_for_eth_pregate()` already guarantees that.
async fn pulse_phy_nrst_pj15_raw() {
    // SAFETY: RCC_AHB4ENR bit 9 enables GPIOJ; GPIOJ MODER/BSRR are documented
    // STM32H747 registers at 0x5802_2400/0x5802_2418. BSRR bit 31 drives PJ15
    // low before MODER15 is switched to output; MODER15=00 returns nRST to the
    // external pull-up.
    unsafe {
        const RCC_AHB4ENR: *mut u32 = 0x5802_44E0 as *mut u32;
        const GPIOJ_MODER: *mut u32 = 0x5802_2400 as *mut u32;
        const GPIOJ_BSRR: *mut u32 = 0x5802_2418 as *mut u32;
        RCC_AHB4ENR.write_volatile(RCC_AHB4ENR.read_volatile() | (1 << 9));
        let _ = RCC_AHB4ENR.read_volatile();
        GPIOJ_BSRR.write_volatile(1 << 31);
        GPIOJ_MODER.write_volatile((GPIOJ_MODER.read_volatile() & !0xC000_0000) | 0x4000_0000);
        cortex_m::asm::dsb();
    }
    Timer::after_millis(PHY_NRST_ASSERT_MS).await;
    // SAFETY: restore PJ15 to input so the external pull owns nRST deassert.
    unsafe {
        const GPIOJ_MODER: *mut u32 = 0x5802_2400 as *mut u32;
        GPIOJ_MODER.write_volatile(GPIOJ_MODER.read_volatile() & !0xC000_0000);
        cortex_m::asm::dsb();
    }
}

/// Pulse `RCC_AHB1RSTR.ETH1MACRST` (RM0399 bit 15 @ 0x5802_4480).
fn pulse_eth1macrst_raw() {
    // SAFETY: RM0399 documents ETH1MACRST as a software-set/reset MAC block reset.
    unsafe {
        const RCC_AHB1RSTR: *mut u32 = 0x5802_4480 as *mut u32;
        RCC_AHB1RSTR.write_volatile(1 << 15);
        let _ = RCC_AHB1RSTR.read_volatile();
        RCC_AHB1RSTR.write_volatile(0);
        let _ = RCC_AHB1RSTR.read_volatile();
        cortex_m::asm::dsb();
    }
}

fn clear_bmcr_power_down_isolate_if_needed() -> Result<(), EthInitError> {
    let bmcr = mdio_read(LAN8742_PHY_ADDR, PHY_REG_BMCR, PHY_MDIO_TIMEOUT_MS)?;
    if bmcr & (PHY_BMCR_POWER_DOWN | PHY_BMCR_ISOLATE) != 0 {
        mdio_write(
            LAN8742_PHY_ADDR,
            PHY_REG_BMCR,
            bmcr & !(PHY_BMCR_POWER_DOWN | PHY_BMCR_ISOLATE),
            PHY_MDIO_TIMEOUT_MS,
        )?;
    }
    Ok(())
}

fn verify_lan8742_mode_straps() -> Result<(), EthInitError> {
    let reg18 = mdio_read(LAN8742_PHY_ADDR, PHY_REG_SPECIAL_MODES, PHY_MDIO_TIMEOUT_MS)?;
    rprintln!("eth: phy reg18 after hard reset: {:#06x}", reg18);
    if ((reg18 >> 5) & 0x7) != LAN8742_MODE_ALL_CAPABLE {
        return Err(EthInitError::StrapLatchFailed);
    }
    Ok(())
}

async fn recover_ethernet_for_swr() -> Result<(), EthInitError> {
    pulse_phy_nrst_pj15_raw().await;
    Timer::after_millis(PHY_SETTLE_MS).await;
    verify_lan8742_phy_id()?;
    verify_lan8742_mode_straps()?;
    clear_bmcr_power_down_isolate_if_needed()?;
    pulse_eth1macrst_raw();
    eth_swr_reset_once(ETH_SWR_TIMEOUT_MS)
}

fn eth_swr_reset_once(timeout_ms: u64) -> Result<(), EthInitError> {
    // SAFETY: ETH_DMAMR (0x4002_9000) is the STM32H747 Ethernet DMA mode
    // register. Setting bit 0 requests the documented MAC/MTL/DMA software
    // reset; polling the same bit waits for hardware completion.
    unsafe {
        const ETH_DMAMR: *mut u32 = 0x4002_9000 as *mut u32;
        ETH_DMAMR.write_volatile(ETH_DMAMR.read_volatile() | 1);
        let start = Instant::now().as_millis();
        while ETH_DMAMR.read_volatile() & 1 != 0 {
            if elapsed_since_ms(start) >= timeout_ms {
                return Err(EthInitError::SwrTimeout);
            }
            spin_loop();
        }
    }
    Ok(())
}

pub(crate) async fn prepare_ethernet_reset_domain_or_panic() {
    enable_eth_ahb_clocks_raw();
    configure_rmii_pins_for_eth_pregate();
    for attempt in 0..ETH_INIT_MAX_ATTEMPTS {
        M7_ETH_INIT_RETRIES.store(attempt, Ordering::Relaxed);
        let result = recover_ethernet_for_swr().await;
        if result.is_ok() {
            return;
        }
        if attempt + 1 < ETH_INIT_MAX_ATTEMPTS {
            rprintln!("eth: SWR pre-gate retry {}", attempt + 1);
            continue;
        }
        if matches!(result, Err(EthInitError::SwrTimeout)) {
            opta_record_eth_init_swr_timeout();
            rprintln!("eth: pre-gate failed: {:?}", result);
            panic!("ETH DMAMR.SWR pre-gate timeout");
        }
        if matches!(result, Err(EthInitError::StrapLatchFailed)) {
            record_fault(LastFaultReason::EthInitStrapLatch, 0, 0, 0);
            rprintln!("eth: pre-gate failed: {:?}", result);
            panic!("ETH PHY strap latch failed");
        }
        rprintln!("eth: pre-gate failed: {:?}", result);
        panic!("ETH PHY/SWR pre-gate failed");
    }
}

/// Select RMII in SYSCFG before embassy's Ethernet init runs.
///
/// ST CubeH7 issue #121: the PMCR write crosses the slow APB4 bus; if the
/// ETH DMA software reset is issued before the write physically lands, the MAC
/// latches the reset with the mux still in MII and SWR never clears.
/// embassy-stm32 0.6.0 writes PMCR and sets SWR back-to-back, so we pre-set
/// EPIS (with the documented dummy read-back) long before.
pub(crate) fn select_rmii_before_eth_init() {
    // SAFETY: RCC_APB4ENR (0x580244F4) and SYSCFG_PMCR (0x58000404) are
    // architecturally documented STM32H747 registers (RM0399). Setting
    // SYSCFGEN then read-modify-writing EPIS[23:21]=0b100 selects RMII; the
    // trailing read-back forces APB4 write completion per ST's fix.
    unsafe {
        const RCC_APB4ENR: *mut u32 = 0x5802_44F4 as *mut u32;
        RCC_APB4ENR.write_volatile(RCC_APB4ENR.read_volatile() | (1 << 1));
        let _ = RCC_APB4ENR.read_volatile();
        const SYSCFG_PMCR: *mut u32 = 0x5800_0404 as *mut u32;
        let pmcr = (SYSCFG_PMCR.read_volatile() & !(0b111 << 21)) | (0b100 << 21);
        SYSCFG_PMCR.write_volatile(pmcr);
        let _ = SYSCFG_PMCR.read_volatile();
        cortex_m::asm::dsb();
    }
}
