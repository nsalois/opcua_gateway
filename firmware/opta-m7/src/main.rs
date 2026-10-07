// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

#![no_std]
#![no_main]

#[cfg(all(
    feature = "diagnostic-accelerated-clock",
    feature = "diagnostic-tick-hz-32768"
))]
compile_error!("accelerated clock admission requires the unchanged default tick rate");

#[cfg(all(
    feature = "diagnostic-ethernet-rx-ring-16",
    feature = "diagnostic-dcache-disabled"
))]
compile_error!("Ethernet diagnostic perturbations are mutually exclusive");

const WATCHDOG_FAULT_INJECTION_FEATURE_COUNT: u8 =
    (cfg!(feature = "diagnostic-suppress-net-runner-checkin") as u8)
        + (cfg!(feature = "diagnostic-suppress-main-heartbeat-checkin") as u8)
        + (cfg!(feature = "diagnostic-suppress-net-status-checkin") as u8)
        + (cfg!(feature = "diagnostic-stall-usb-console-write") as u8)
        + (cfg!(feature = "diagnostic-stall-usb-control") as u8)
        + (cfg!(feature = "diagnostic-suppress-opcua-listener0-checkin") as u8)
        + (cfg!(feature = "diagnostic-watchdog-cpu-busy") as u8);
const _: () = assert!(
    WATCHDOG_FAULT_INJECTION_FEATURE_COUNT <= 1,
    "select no more than one watchdog fault injection feature"
);

const _: () = assert!(
    (cfg!(feature = "diagnostic-runtime-counters") as u8)
        + (cfg!(feature = "diagnostic-cache-ages") as u8)
        + (cfg!(feature = "diagnostic-trust-heartbeat-counters") as u8)
        <= 1,
    "select one finite owner diagnostic per boot"
);

#[cfg(all(
    feature = "diagnostic-lse-retention",
    any(
        feature = "diagnostic-tls-mock",
        feature = "diagnostic-suppress-net-runner-checkin",
        feature = "diagnostic-suppress-main-heartbeat-checkin",
        feature = "diagnostic-suppress-net-status-checkin",
        feature = "diagnostic-stall-usb-console-write",
        feature = "diagnostic-stall-usb-control",
        feature = "diagnostic-suppress-opcua-listener0-checkin",
        feature = "diagnostic-watchdog-cpu-busy",
        feature = "diagnostic-pre-clock-stall",
        feature = "diagnostic-ethernet-ingress",
        feature = "diagnostic-time-counters",
        feature = "diagnostic-time-driver",
        feature = "diagnostic-executor-wakeup",
        feature = "diagnostic-tick-hz-32768",
        feature = "diagnostic-accelerated-clock"
    )
))]
compile_error!("the LSE retention instrument must be built without other diagnostic overlays");

use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use embassy_executor::Spawner;
use embassy_net::StackResources;
use embassy_stm32::eth::{Ethernet, Sma};
use embassy_stm32::flash::Flash;
use embassy_stm32::gpio::{Level, Output, Speed as GpioSpeed};
#[cfg(feature = "product")]
use embassy_stm32::peripherals::RNG;
use embassy_stm32::peripherals::USB_OTG_FS;
use embassy_stm32::rcc::Mco;
#[cfg(feature = "diagnostic-lse-retention")]
use embassy_stm32::rcc::{LsConfig, LseConfig, LseMode, RtcClockSource};
#[cfg(feature = "product")]
use embassy_stm32::rng;
#[cfg(feature = "product")]
use embassy_stm32::rtc::{Rtc, RtcConfig};
#[cfg(feature = "diagnostic-lse-retention")]
use embassy_stm32::time::Hertz;
use embassy_stm32::{bind_interrupts, eth, usb, SharedData};
use embassy_time::{Duration, Instant, Ticker, Timer};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcAcmState};
use embassy_usb::{Builder as UsbBuilder, Config as UsbDeviceConfig};
use opta_gateway_contracts::boot::BootStage;
#[cfg(not(feature = "product"))]
use opta_gateway_contracts::config::GatewayTrust;
use opta_gateway_contracts::last_fault::LastFaultReason;
use opta_gateway_contracts::watchdog::WatchdogSlot;
#[cfg(feature = "product")]
use opta_runtime::LoopTimingMonitor;
use rtt_target::{rprintln, rtt_init_print};

#[cfg(feature = "diagnostic-accelerated-clock")]
mod accelerated_clock;
mod board;
#[cfg(feature = "product")]
mod buchi_tls_transport;
mod build_info;
#[cfg(feature = "diagnostic-cache-ages")]
mod cache_age_diagnostic;
mod config_storage;
#[cfg(feature = "diagnostic-runtime-counters")]
mod counter_diagnostic;
#[cfg(feature = "diagnostic-runtime-counters")]
mod counter_events;
#[cfg(feature = "diagnostic-ethernet-ingress")]
mod ethernet_trace;
mod fault;
mod identity;
mod network;
mod probes;
#[cfg(feature = "product")]
mod product_opcua;
#[cfg(feature = "diagnostic-protocol-identifiers")]
mod protocol_id_diagnostic;
#[cfg(feature = "diagnostic-stack-guard-trip")]
mod stack_guard_trip;
#[cfg(feature = "diagnostic-stack-watermark")]
mod stack_watermark;
#[cfg(feature = "diagnostic-time-counters")]
mod time_counters;
#[cfg(feature = "diagnostic-time-driver")]
mod time_trace;
mod timebase;
#[cfg(feature = "diagnostic-tls-mock")]
mod tls_mock;
#[cfg(feature = "product")]
mod trust;
#[cfg(feature = "diagnostic-trust-heartbeat-counters")]
mod trust_heartbeat_diagnostic;
mod usb_console;
#[cfg(feature = "maintenance-usb-m4-boot-repair")]
mod usb_m4_boot_repair;
mod watchdog;
mod watchdog_executor;

// Crate-root re-exports preserve existing `crate::...` paths used by sibling modules.
pub(crate) use timebase::uptime_now_ms;
pub(crate) use timebase::uptime_now_ms_u64;
#[cfg(feature = "product")]
pub(crate) use trust::{
    snapshot_buchi_trust_health, RuntimeTrustSnapshot, SharedRuntime, SharedTrust,
    M7_BUCHI_RUNTIME_REVOKED, M7_BUCHI_TRUST_ANCHOR_PRESENT, M7_BUCHI_TRUST_LAST_VERIFY_ERROR,
    M7_BUCHI_TRUST_READY, M7_BUCHI_TRUST_RTC_USABLE, M7_BUCHI_TRUST_STATE,
    M7_BUCHI_TRUST_VERIFIED_SESSIONS, M7_BUCHI_TRUST_VERIFY_ATTEMPTS,
};
#[cfg(feature = "product")]
pub(crate) use watchdog::snapshot_single_core_health;
pub(crate) use watchdog::task_checkin;
#[cfg(feature = "product")]
pub(crate) use watchdog::WATCHDOG_TASK_DEADLINE;

// embassy-stm32 treats the H747 as dual-core and requires a SharedData slot
// to coordinate init between cores. The separate M4 quarantine companion does
// not participate in the M7 Embassy runtime or initialization, so only M7 uses
// this slot in ordinary M7 D1 RAM. It must move to a cross-core-visible region
// if a future design introduces coordinated initialization with M4.
static SHARED_DATA: MaybeUninit<SharedData> = MaybeUninit::uninit();

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    OTG_FS => usb::InterruptHandler<USB_OTG_FS>;
    #[cfg(feature = "product")]
    RNG => rng::InterruptHandler<RNG>;
});

/// Heartbeat cadence for the slice-3 proof: slow enough to make each tick a
/// real timer-driven wakeup (not a spin), fast enough that the probe's 1 s
/// run window observes the count advancing.
const HEARTBEAT_MS: u64 = 100;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // SAFETY: 0xE000_ED14 is SCB->CCR (RM). Store may land in inherited D-cache
    // and survives only because disable_dcache cleans before invalidating; 0
    // means store never ran (genuine CCR reads are nonzero; reset 0x00040200).
    let entry_ccr = unsafe { (0xE000_ED14 as *const u32).read_volatile() };
    probes::M7_ENTRY_CCR.store(entry_ccr, Ordering::Relaxed);

    #[cfg(feature = "product")]
    board::configure_cache_policy_for_dma();
    #[cfg(feature = "diagnostic-stack-watermark")]
    stack_watermark::M7_STACK_WATERMARK_GATE();
    #[cfg(feature = "diagnostic-ethernet-ingress")]
    ethernet_trace::initialize();
    #[cfg(not(feature = "product"))]
    board::normalize_cache_state_for_dma();
    board::normalize_interrupt_state_for_warm_launch();
    board::configure_product_interrupt_priorities();
    let cm4_boot_observation = board::capture_cm4_pre_init();
    let boot_reset_flags = board::read_reset_flags_raw();
    probes::M7_RESET_FLAGS_PROBE.store(boot_reset_flags, Ordering::Relaxed);
    #[cfg(feature = "diagnostic-pre-clock-stall")]
    let bootloader_reset_reason = board::read_bootloader_reset_reason_raw();
    #[cfg(feature = "diagnostic-pre-clock-stall")]
    probes::M7_BOOTLOADER_RESET_REASON_PROBE.store(bootloader_reset_reason, Ordering::Relaxed);
    probes::M7_SPIN_COUNT.store(0, Ordering::Relaxed);
    probes::M7_FAULT_REASON_PROBE.store(LastFaultReason::None.as_word(), Ordering::Relaxed);
    probes::M7_WATCHDOG_ARMED.store(0, Ordering::Relaxed);
    probes::M7_WATCHDOG_STALE_MASK.store(0, Ordering::Relaxed);
    probes::M7_WATCHDOG_OBSERVED_STALE_SLOTS.store(0, Ordering::Relaxed);
    probes::M7_WATCHDOG_PUBLIC_FRESH_MASK.store(0, Ordering::Relaxed);
    probes::M7_WATCHDOG_REFRESH_COUNT.store(0, Ordering::Relaxed);
    probes::M7_INDUCED_HANG_PROBE.store(0, Ordering::Relaxed);
    probes::M7_BOOT_SENTINEL.store(probes::M7_BOOT_SENTINEL_RESET_ENTERED, Ordering::Relaxed);
    probes::record_boot_stage(BootStage::SetupEntry);
    probes::record_boot_stage(BootStage::FaultHandlersInstalled);
    probes::record_boot_stage(BootStage::ResetFlagsCaptured);

    // Arm and fully validate IWDG1 while the inherited reset clock is still in
    // use. No field-config read or clock-startup wait is allowed above this
    // point. A failed validation is not published as armed and is never
    // refreshed; if IWDG1 did start, its independent LSI clock provides the
    // reset path instead of letting startup continue without supervision.
    let early_iwdg_valid = watchdog::iwdg1_arm_10s_early();
    board::capture_cm4_post_ww1rsc(&cm4_boot_observation);
    if !early_iwdg_valid {
        loop {
            core::hint::spin_loop();
        }
    }
    probes::record_boot_stage(BootStage::WatchdogArmed);

    #[cfg(feature = "diagnostic-pre-clock-stall")]
    watchdog::run_pre_clock_stall_probe(boot_reset_flags, bootloader_reset_reason);

    rtt_init_print!();
    rprintln!("opta-m7: embassy bring-up start");
    probes::record_boot_stage(BootStage::SerialReady);

    // Read the immutable factory identity once, after watchdog arming and
    // before configuration or any listener can start.
    let uid_words = identity::uid_words();
    #[cfg(feature = "product")]
    let server_identity = opta_opcua::ServerIdentity::from_uid_words(uid_words);
    let mac = identity::mac_from_uid(uid_words);
    #[cfg(feature = "product")]
    let mut runtime_trust = trust::PRODUCT_TRUST.take();
    #[cfg(feature = "product")]
    let (field_config_load, boot_config) =
        config_storage::load_field_config(uid_words, &mut runtime_trust.get_mut().material);
    #[cfg(not(feature = "product"))]
    let (field_config_load, boot_config) = {
        let mut ignored_trust = GatewayTrust::missing();
        config_storage::load_field_config(uid_words, &mut ignored_trust)
    };
    let boot_config_source = field_config_load.source;
    let boot_config_sequence = field_config_load.sequence;
    probes::record_boot_stage(BootStage::DeviceConfigReady);
    rprintln!(
        "opta-m7: config source={} sequence={} device-name={} net-mode={}",
        boot_config_source.as_str(),
        boot_config_sequence,
        boot_config.device_name.as_str(),
        boot_config.net_mode.as_str()
    );

    let config = board::PRODUCTION_CLOCK_PLAN.embassy_config();
    #[cfg(feature = "diagnostic-lse-retention")]
    let config = {
        let mut config = config;
        // Diagnostic-only LSE bypass selection. Arduino's Opta target
        // declares an external LSE clock in bypass mode, so default_lse()
        // (crystal oscillator mode) is deliberately not used here.
        let mut ls = LsConfig::off();
        ls.rtc = RtcClockSource::LSE;
        ls.lsi = false;
        ls.lse = Some(LseConfig {
            frequency: Hertz(32_768),
            mode: LseMode::Bypass,
        });
        config.rcc.ls = ls;
        config
    };
    board::quiesce_inherited_pll1();
    #[cfg(feature = "diagnostic-accelerated-clock")]
    accelerated_clock::prepare_origin();
    let p = embassy_stm32::init_primary(config, &SHARED_DATA);
    board::capture_cm4_post_init(&cm4_boot_observation);
    let boot_last_fault = fault::update_last_fault_reset_flags(boot_reset_flags);
    board::clear_reset_flags_raw();
    watchdog::iwdg1_start_uptime_telemetry();
    rprintln!(
        "opta-m7: rcc HSE-bypass={}Hz PLL1 M={} N={} P={} M7={}Hz AHB={}Hz APB1-4={}Hz TIM2={}Hz USB-HSI48={}Hz MDIO-CR={} div={} MDC={}Hz HSI=on VOS=Scale1 SMPS->LDO",
        board::PRODUCTION_CLOCK_FREQUENCIES.hse_hz,
        board::PRODUCTION_CLOCK_PLAN.pll1_predivisor(),
        board::PRODUCTION_CLOCK_PLAN.pll1_multiplier(),
        board::PRODUCTION_CLOCK_PLAN.pll1_p_divisor(),
        board::PRODUCTION_CLOCK_FREQUENCIES.m7_hz,
        board::PRODUCTION_CLOCK_FREQUENCIES.ahb_hz,
        board::PRODUCTION_CLOCK_FREQUENCIES.apb1_hz,
        board::PRODUCTION_CLOCK_FREQUENCIES.tim2_kernel_hz,
        board::PRODUCTION_CLOCK_FREQUENCIES.usb_hz,
        board::PRODUCTION_MDIO.clock_range,
        board::PRODUCTION_MDIO.divisor,
        board::PRODUCTION_CLOCK_FREQUENCIES.mdc_hz,
    );

    #[cfg(feature = "product")]
    let (rtc, rtc_time) = Rtc::new(p.RTC, RtcConfig::default());
    #[cfg(feature = "diagnostic-lse-retention")]
    probes::capture_boot_rtc();
    #[cfg(feature = "product")]
    let rtc_seconds = if runtime_trust.get_mut().material.time_provisioned() {
        trust::read_usable_rtc_seconds(&rtc_time)
    } else {
        None
    };
    #[cfg(feature = "product")]
    runtime_trust.get_mut().initialize_from_boot(rtc_seconds);
    #[cfg(feature = "diagnostic-trust-heartbeat-counters")]
    trust_heartbeat_diagnostic::initialize(runtime_trust.get_mut(), rtc_seconds);
    #[cfg(feature = "product")]
    let runtime_trust: &'static SharedTrust = runtime_trust;
    #[cfg(feature = "product")]
    let runtime = {
        let mut data_access = opta_runtime::RuntimeDataAccess::new();
        data_access.set_write_enabled(false);
        data_access.set_last_fault(boot_last_fault);
        data_access.set_reset_flags(boot_reset_flags);
        trust::PRODUCT_RUNTIME.init(SharedRuntime::new(data_access))
    };
    #[cfg(feature = "diagnostic-accelerated-clock")]
    {
        // Capture one coherent empty-runtime origin before USB spawning and
        // the first timer await. The normal pre-monitor initialization below
        // still runs after Ethernet startup, as in the product composition.
        watchdog::initialize_task_checkins(uptime_now_ms());
        accelerated_clock::capture_dependents(runtime, runtime_trust);
    }
    #[cfg(not(feature = "product"))]
    let _ = boot_last_fault;

    let flash = Flash::new_blocking(p.FLASH);
    let usb_driver = usb::Driver::new_fs(
        p.USB_OTG_FS,
        Irqs,
        p.PA12,
        p.PA11,
        usb_console::USB_EP_OUT_BUFFER.init([0; usb_console::USB_EP_OUT_BUFFER_BYTES]),
        usb::Config::default(),
    );
    #[cfg(feature = "product")]
    let usb_driver = {
        let mut usb_driver = usb_driver;
        usb_driver.set_watchdog_progress_hooks(
            watchdog::usb_device_progress_expected,
            watchdog::usb_device_progress_complete,
            watchdog::usb_device_bus_event,
            watchdog::usb_device_control_setup,
        );
        usb_driver
    };
    let mut usb_device_config = UsbDeviceConfig::new(
        usb_console::USB_VID_ARDUINO,
        usb_console::USB_PID_RUST_PROVISIONING,
    );
    usb_device_config.manufacturer = Some("Arduino");
    usb_device_config.product = Some("Opta Rust OPC UA Gateway");
    let usb_serial_number =
        usb_console::USB_SERIAL_NUMBER.init(identity::usb_serial_number_from_mac(mac));
    usb_device_config.serial_number = Some(usb_serial_number.as_str());
    usb_device_config.self_powered = true;
    let mut usb_builder = UsbBuilder::new(
        usb_driver,
        usb_device_config,
        usb_console::USB_CONFIG_DESCRIPTOR.init([0; usb_console::USB_CONFIG_DESCRIPTOR_BYTES]),
        usb_console::USB_BOS_DESCRIPTOR.init([0; usb_console::USB_BOS_DESCRIPTOR_BYTES]),
        usb_console::USB_MSOS_DESCRIPTOR.init([0; usb_console::USB_MSOS_DESCRIPTOR_BYTES]),
        usb_console::USB_CONTROL_BUFFER.init([0; usb_console::USB_CONTROL_BUFFER_BYTES]),
    );
    let usb_cdc = CdcAcmClass::new(
        &mut usb_builder,
        usb_console::USB_CDC_STATE.init(CdcAcmState::new()),
        usb_console::USB_CDC_MAX_PACKET_SIZE,
    );
    let usb_device = usb_builder.build();
    spawner.spawn(usb_console::usb_device_task(usb_device).expect("task arena: usb_device_task"));
    spawner.spawn(
        usb_console::usb_console_task(
            usb_cdc,
            flash,
            #[cfg(feature = "product")]
            rtc,
            #[cfg(feature = "product")]
            rtc_time,
            #[cfg(feature = "product")]
            runtime,
            #[cfg(feature = "product")]
            runtime_trust,
            boot_config,
            boot_config_source,
            boot_config_sequence,
            uid_words,
            #[cfg(feature = "product")]
            server_identity,
        )
        .expect("task arena: usb_console_task"),
    );
    probes::record_boot_stage(BootStage::ConsoleReady);

    // The Opta feeds the Ethernet PHY its 25 MHz clock from MCO1/PA8 — mbed's
    // OPTA SetSysClock ends with HAL_RCC_MCOConfig(MCO1, HSE, DIV1) (verified
    // by disassembling libmbed.a). Without this the PHY is clockless, emits
    // no 50 MHz RMII REF_CLK, and the ETH DMA software reset polls forever
    // (unpublished historical bench observation).
    let _mco = Mco::new(
        p.MCO1,
        p.PA8,
        board::PRODUCTION_CLOCK_PLAN.mco1_source(),
        board::PRODUCTION_CLOCK_PLAN.mco1_config(),
    );

    // These non-RMII board lines are empirical: differential GPIO capture
    // against a known-working firmware image showed them driven before
    // Ethernet was alive (unpublished historical observations). Datasheet
    // support for these lines was not established by that investigation. Keep
    // the Output owners live for the whole task; dropping them would return the pins to their floating reset state
    // and can remove PHY reset/power/clock enables.
    let _eth_ph15 = Output::new(p.PH15, Level::Low, GpioSpeed::Low);
    let _eth_pi0 = Output::new(p.PI0, Level::High, GpioSpeed::Low);
    let _eth_pi1 = Output::new(p.PI1, Level::High, GpioSpeed::Low);
    let _eth_pi3 = Output::new(p.PI3, Level::Low, GpioSpeed::Low);

    // 500 ms settle matches mbed's ETH_PHY_RESET_DELAY.
    Timer::after_millis(500).await;
    watchdog::iwdg1_refresh();
    network::select_rmii_before_eth_init();
    Timer::after_millis(1).await;
    network::prepare_ethernet_reset_domain_or_panic().await;
    watchdog::iwdg1_refresh();

    // OPTA RMII pin map and PHY facts come from the Arduino mbed target
    // (TARGET_OPTA/PinNames.h, mbed_config.h): LAN8742-class PHY at SMI
    // address 0, REF_CLK PA1, MDIO PA2, MDC PC1, CRS_DV PA7, RXD0 PC4,
    // RXD1 PC5, TXD0 PG13, TXD1 PG12, TX_EN PG11.
    rprintln!(
        "opta-m7: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    #[cfg(feature = "product")]
    let eth_packets = network::init_eth_packets();
    #[cfg(not(feature = "product"))]
    let eth_packets = network::ETH_PACKETS.init_with(network::EthPacketQueue::new);
    let sma = Sma::new(p.ETH_SMA, p.PA2, p.PC1);
    let eth_phy = network::Lan8742ProbePhy::new_auto(sma);
    let eth_device = Ethernet::new_with_phy(
        eth_packets,
        p.ETH,
        Irqs,
        p.PA1,  // REF_CLK
        p.PA7,  // CRS_DV
        p.PC4,  // RXD0
        p.PC5,  // RXD1
        p.PG13, // TXD0
        p.PG12, // TXD1
        p.PG11, // TX_EN
        mac,
        eth_phy,
    );
    #[cfg(feature = "product")]
    embassy_stm32::eth::set_watchdog_progress_hook(Some(watchdog::net_runner_driver_progress));
    #[cfg(feature = "diagnostic-ethernet-ingress")]
    network::configure_ethernet_mmc_counters();
    probes::record_boot_stage(BootStage::EthernetReady);
    watchdog::iwdg1_refresh();

    // The persistent field config feeds DHCP hostname, static/DHCP selection,
    // and mDNS name. A bench without DHCP provisions static addressing over USB
    // before rebooting.
    let hostname = network::configured_hostname(&boot_config);
    rprintln!(
        "opta-m7: network hostname {} mode {}",
        hostname.as_str(),
        boot_config.net_mode.as_str()
    );
    let mdns_hostname = hostname.clone();
    let net_config = network::configured_net_config(&boot_config, hostname);

    let seed = u64::from(mac[2]) << 40
        | u64::from(mac[3]) << 32
        | u64::from(mac[4]) << 24
        | u64::from(mac[5]) << 16;
    let reconnect_seed = (seed as u32) ^ ((seed >> 32) as u32);
    let (stack, runner) = embassy_net::new(
        eth_device,
        net_config,
        network::NET_RESOURCES.init(StackResources::new()),
        seed,
    );
    spawner.spawn(network::net_task(runner).expect("task arena: net_task"));
    spawner.spawn(
        network::mdns_task(stack, mdns_hostname, reconnect_seed).expect("task arena: mdns_task"),
    );
    spawner.spawn(network::net_status_task(stack).expect("task arena: net_status_task"));
    #[cfg(feature = "product")]
    spawner.spawn(network::eth_rx_drop_probe_task().expect("task arena: eth_rx_drop_probe_task"));
    #[cfg(feature = "product")]
    {
        let (opcua_buffers_0, opcua_buffers_1, opcua_buffers_2) =
            product_opcua::init_opcua_buffers();
        #[cfg(feature = "diagnostic-tls-mock")]
        {
            let tls_rng = rng::Rng::new(p.RNG, Irqs);
            spawner.spawn(
                tls_mock::buchi_tls_client_shared_task(
                    stack,
                    tls_rng,
                    reconnect_seed,
                    boot_config,
                    runtime,
                )
                .expect("task arena: buchi_tls_client_shared_task"),
            );
        }
        #[cfg(not(feature = "diagnostic-tls-mock"))]
        {
            let tls_rng = rng::Rng::new(p.RNG, Irqs);
            spawner.spawn(
                buchi_tls_transport::buchi_tls_client_product_task(
                    stack,
                    tls_rng,
                    reconnect_seed,
                    boot_config,
                    runtime,
                    runtime_trust,
                )
                .expect("task arena: buchi_tls_client_product_task"),
            );
        }
        spawner.spawn(
            product_opcua::opcua_server_task(stack, runtime, opcua_buffers_0, 0, server_identity)
                .expect("task arena: opcua_server_task0"),
        );
        spawner.spawn(
            product_opcua::opcua_server_task(stack, runtime, opcua_buffers_1, 1, server_identity)
                .expect("task arena: opcua_server_task1"),
        );
        spawner.spawn(
            product_opcua::opcua_server_task(stack, runtime, opcua_buffers_2, 2, server_identity)
                .expect("task arena: opcua_server_task2"),
        );
    }
    #[cfg(all(
        feature = "diagnostic-stack-watermark",
        feature = "diagnostic-accelerated-clock"
    ))]
    spawner.spawn(
        stack_watermark::completed_workload_capture_task(runtime)
            .expect("task arena: completed_workload_capture_task"),
    );
    watchdog::iwdg1_refresh();
    watchdog::initialize_task_checkins(uptime_now_ms());
    let watchdog_spawner = watchdog_executor::start();
    watchdog_spawner
        .spawn(watchdog::watchdog_monitor_task().expect("task arena: watchdog_monitor_task"));
    #[cfg(feature = "diagnostic-watchdog-cpu-busy")]
    watchdog::run_cpu_busy_preemption_probe();

    probes::M7_BOOT_SENTINEL.store(probes::M7_BOOT_SENTINEL_LOOP_ENTERED, Ordering::Relaxed);
    probes::record_boot_stage(BootStage::LoopEntered);

    #[cfg(feature = "diagnostic-stack-guard-trip")]
    stack_guard_trip::trigger();

    let mut ticker = Ticker::every(Duration::from_millis(HEARTBEAT_MS));
    #[cfg(feature = "product")]
    let mut loop_timing = LoopTimingMonitor::new(HEARTBEAT_MS, 10);
    loop {
        ticker.next().await;
        let uptime_ms = Instant::now().as_millis();
        probes::M7_UPTIME_MS.store(uptime_ms as u32, Ordering::Relaxed);
        task_checkin(WatchdogSlot::MainHeartbeat);
        #[cfg(feature = "product")]
        if let Some(snapshot) = loop_timing.observe(uptime_ms, Instant::now().as_millis()) {
            probes::publish_loop_timing(snapshot);
        }
        #[cfg(feature = "diagnostic-trust-heartbeat-counters")]
        let before_tick = probes::M7_SPIN_COUNT.load(Ordering::Relaxed);
        let ticks = probes::M7_SPIN_COUNT
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        #[cfg(feature = "diagnostic-trust-heartbeat-counters")]
        {
            trust_heartbeat_diagnostic::heartbeat(before_tick, ticks, uptime_ms);
            trust_heartbeat_diagnostic::try_finish(runtime_trust);
        }
        if ticks % 10 == 0 {
            let link_up = stack.is_link_up();
            probes::M7_LINK_STATE.store(u32::from(link_up), Ordering::Relaxed);
            rprintln!(
                "opta-m7 heartbeat: ticks={} uptime_ms={} link={}",
                ticks,
                uptime_ms,
                link_up
            );
        }
    }
}
