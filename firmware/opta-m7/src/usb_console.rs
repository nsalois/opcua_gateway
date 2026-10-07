//! USB-CDC provisioning console, command dispatch, and response writing.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::fmt::Write as FmtWrite;
#[cfg(feature = "diagnostic-stall-usb-console-write")]
use core::future::pending;
#[cfg(feature = "product")]
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_stm32::peripherals::USB_OTG_FS;
use embassy_stm32::usb;
use embassy_time::with_timeout;
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcAcmState};
#[cfg(feature = "product")]
use opta_gateway_contracts::config::TrustUpload;
use opta_gateway_contracts::config::{
    ConfigKey, ConfigSource, FactoryResetCommitEvidence, FactoryResetOutcome, GatewayConfig,
    GatewayTrust, Ipv4Display,
};
use opta_gateway_contracts::watchdog::WatchdogSlot;
use static_cell::StaticCell;

#[cfg(feature = "product")]
use embassy_stm32::rtc::{Rtc, RtcTimeProvider};
#[cfg(feature = "product")]
use opta_tls_verify::{verify_ca_certificate_with_optional_time, UnixTime};

use crate::board;
use crate::config_storage::{factory_reset_config, load_field_config, write_config_slot, M7Flash};
#[cfg(feature = "product")]
use crate::probes::{M7_IPV4_ADDR, M7_LINK_STATE};
#[cfg(feature = "product")]
use crate::trust::{
    apply_runtime_revocation, commit_trust_record, read_usable_rtc_seconds, rtc_datetime_from_unix,
    SharedRuntime, SharedTrust, TrustStatusSnapshot,
};
#[cfg(feature = "product")]
use crate::watchdog::task_watchdog_timeout;
use crate::watchdog::{task_checkin, WATCHDOG_TASK_DEADLINE};
#[cfg(feature = "diagnostic-stall-usb-console-write")]
use crate::{probes::M7_INDUCED_HANG_PROBE, timebase::uptime_now_ms};

pub(crate) const USB_CDC_MAX_PACKET_SIZE: u16 = 64;
pub(crate) const USB_EP_OUT_BUFFER_BYTES: usize = 256;
pub(crate) const USB_CONFIG_DESCRIPTOR_BYTES: usize = 256;
pub(crate) const USB_BOS_DESCRIPTOR_BYTES: usize = 64;
pub(crate) const USB_MSOS_DESCRIPTOR_BYTES: usize = 64;
pub(crate) const USB_CONTROL_BUFFER_BYTES: usize = 64;
const USB_LINE_BUFFER_BYTES: usize = 128;
const USB_RESPONSE_BUFFER_BYTES: usize = 192;
use crate::identity::USB_SERIAL_NUMBER_BYTES;
#[cfg(feature = "product")]
use opta_opcua::ServerIdentity;
pub(crate) const USB_VID_ARDUINO: u16 = 0x2341;
pub(crate) const USB_PID_RUST_PROVISIONING: u16 = 0x0064;
const DFU_BKP0R_MAGIC: u32 = 0x0000_DF59;

pub(crate) type UsbDriver = usb::Driver<'static, USB_OTG_FS>;
pub(crate) type UsbDevice = embassy_usb::UsbDevice<'static, UsbDriver>;
pub(crate) type UsbCdc = CdcAcmClass<'static, UsbDriver>;

pub(crate) static USB_EP_OUT_BUFFER: StaticCell<[u8; USB_EP_OUT_BUFFER_BYTES]> = StaticCell::new();
pub(crate) static USB_CONFIG_DESCRIPTOR: StaticCell<[u8; USB_CONFIG_DESCRIPTOR_BYTES]> =
    StaticCell::new();
pub(crate) static USB_BOS_DESCRIPTOR: StaticCell<[u8; USB_BOS_DESCRIPTOR_BYTES]> =
    StaticCell::new();
pub(crate) static USB_MSOS_DESCRIPTOR: StaticCell<[u8; USB_MSOS_DESCRIPTOR_BYTES]> =
    StaticCell::new();
pub(crate) static USB_CONTROL_BUFFER: StaticCell<[u8; USB_CONTROL_BUFFER_BYTES]> =
    StaticCell::new();
pub(crate) static USB_CDC_STATE: StaticCell<CdcAcmState<'static>> = StaticCell::new();
pub(crate) static USB_SERIAL_NUMBER: StaticCell<heapless::String<USB_SERIAL_NUMBER_BYTES>> =
    StaticCell::new();

// SAFETY: stable debugger/HIL readback symbols for the product USB-console
// watchdog path; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_STAGE: AtomicU32 = AtomicU32::new(UsbStage::Idle as u32);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_LAST_ERROR: AtomicU32 = AtomicU32::new(UsbProbeError::None as u32);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_PROGRESS_COUNT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[cfg(feature = "product")]
#[unsafe(no_mangle)]
pub static M7_USB_LAST_WRITE_LEN: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "product")]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsbStage {
    Idle = 0,
    WaitConnection = 1,
    GreetingWrite = 2,
    ReadPacket = 3,
    HandleCommand = 4,
    WritePacket = 5,
    WriteZeroLengthPacket = 6,
    Disconnected = 7,
}

#[cfg(feature = "product")]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsbProbeError {
    None = 0,
    WaitConnectionTimeout = 1,
    ReadTimeout = 2,
    ReadError = 3,
    WriteTimeout = 4,
    WriteError = 5,
}

#[cfg(feature = "product")]
fn usb_probe_stage(stage: UsbStage) {
    M7_USB_STAGE.store(stage as u32, Ordering::Relaxed);
    M7_USB_PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[cfg(feature = "product")]
fn usb_probe_error(error: UsbProbeError) {
    M7_USB_LAST_ERROR.store(error as u32, Ordering::Relaxed);
}

#[embassy_executor::task]
pub(crate) async fn usb_device_task(mut device: UsbDevice) -> ! {
    device.run().await
}

#[embassy_executor::task]
pub(crate) async fn usb_console_task(
    mut class: UsbCdc,
    mut flash: M7Flash,
    #[cfg(feature = "product")] mut rtc: Rtc,
    #[cfg(feature = "product")] rtc_time: RtcTimeProvider,
    #[cfg(feature = "product")] runtime: &'static SharedRuntime,
    #[cfg(feature = "product")] runtime_trust: &'static SharedTrust,
    active_config: GatewayConfig,
    active_source: ConfigSource,
    active_sequence: u64,
    uid_words: [u32; 3],
    #[cfg(feature = "product")] server_identity: ServerIdentity,
) -> ! {
    let mut pending = active_config;
    let mut committed = active_config;
    let mut committed_source = active_source;
    let mut committed_sequence = active_sequence;
    let mut reboot_required = false;
    #[cfg(feature = "product")]
    let mut trust_upload = TrustUpload::new();
    let mut packet = [0u8; USB_CDC_MAX_PACKET_SIZE as usize];
    let mut line = [0u8; USB_LINE_BUFFER_BYTES];
    // Assigned after each successful greeting so a real reconnect starts empty.
    let mut line_len;
    let mut discard_line;

    loop {
        task_checkin(WatchdogSlot::UsbConsole);
        #[cfg(feature = "product")]
        usb_probe_stage(UsbStage::WaitConnection);
        #[cfg(feature = "product")]
        let wait_connection = task_watchdog_timeout(
            WatchdogSlot::UsbConsole,
            WATCHDOG_TASK_DEADLINE,
            class.wait_connection(),
        )
        .await;
        #[cfg(not(feature = "product"))]
        let wait_connection = with_timeout(WATCHDOG_TASK_DEADLINE, class.wait_connection()).await;
        if wait_connection.is_err() {
            #[cfg(feature = "product")]
            {
                usb_probe_error(UsbProbeError::WaitConnectionTimeout);
                usb_probe_stage(UsbStage::Disconnected);
            }
            continue;
        }
        #[cfg(feature = "product")]
        {
            usb_probe_error(UsbProbeError::None);
            usb_probe_stage(UsbStage::GreetingWrite);
        }
        if !usb_write_str(&mut class, "opta-rust provisioning ready\r\n").await {
            #[cfg(feature = "product")]
            usb_probe_stage(UsbStage::Disconnected);
            continue;
        }
        // Real reconnect starts with an empty line buffer; partial lines from a
        // prior session must not bleed into the new connection.
        line_len = 0;
        discard_line = false;
        loop {
            task_checkin(WatchdogSlot::UsbConsole);
            #[cfg(feature = "product")]
            usb_probe_stage(UsbStage::ReadPacket);
            #[cfg(feature = "product")]
            let read = task_watchdog_timeout(
                WatchdogSlot::UsbConsole,
                WATCHDOG_TASK_DEADLINE,
                class.read_packet(&mut packet),
            )
            .await;
            #[cfg(not(feature = "product"))]
            let read = with_timeout(WATCHDOG_TASK_DEADLINE, class.read_packet(&mut packet)).await;
            let count = match read {
                Ok(Ok(count)) => {
                    #[cfg(feature = "product")]
                    usb_probe_error(UsbProbeError::None);
                    count
                }
                Ok(Err(_)) => {
                    #[cfg(feature = "product")]
                    {
                        usb_probe_error(UsbProbeError::ReadError);
                        usb_probe_stage(UsbStage::Disconnected);
                    }
                    break;
                }
                // Idle timeout is not disconnect: host remains attached. Continue
                // the inner read loop so we do not re-print the greeting every
                // WATCHDOG_TASK_DEADLINE (~1 s). task_checkin runs at the top of
                // this loop (and product builds also check in inside
                // task_watchdog_timeout), so legitimate connected-idle time
                // remains fresh without treating an outbound write as progress.
                // Do not stamp ReadTimeout into M7_USB_LAST_ERROR — that probe is
                // dump-only and would read as a permanent fault while the console
                // is simply idle-connected. Stay in ReadPacket; leave last error.
                Err(_) => continue,
            };
            for &byte in &packet[..count] {
                if byte == b'\r' || byte == b'\n' {
                    if discard_line {
                        discard_line = false;
                        continue;
                    }
                    if line_len != 0 {
                        let command = core::str::from_utf8(&line[..line_len]).unwrap_or("");
                        #[cfg(feature = "product")]
                        usb_probe_stage(UsbStage::HandleCommand);
                        let action = handle_console_command(
                            &mut class,
                            &mut flash,
                            &mut pending,
                            &mut committed,
                            &mut committed_source,
                            &mut committed_sequence,
                            &mut reboot_required,
                            #[cfg(feature = "product")]
                            &mut trust_upload,
                            #[cfg(feature = "product")]
                            &mut rtc,
                            #[cfg(feature = "product")]
                            &rtc_time,
                            #[cfg(feature = "product")]
                            runtime,
                            #[cfg(feature = "product")]
                            runtime_trust,
                            #[cfg(feature = "product")]
                            &active_config,
                            uid_words,
                            #[cfg(feature = "product")]
                            server_identity,
                            command,
                        )
                        .await;
                        line_len = 0;
                        match action {
                            ConsoleAction::Continue => {}
                            ConsoleAction::Reset => {
                                Timer::after_millis(100).await;
                                cortex_m::peripheral::SCB::sys_reset();
                            }
                            ConsoleAction::Dfu => {
                                Timer::after_millis(100).await;
                                enter_dfu_via_bkp0_and_reset();
                            }
                        }
                    }
                    continue;
                }
                if discard_line {
                    continue;
                }
                if line_len < line.len() {
                    line[line_len] = byte;
                    line_len += 1;
                } else {
                    line_len = 0;
                    // Reject through the delimiter: never interpret a rejected
                    // line's suffix as a separate provisioning/reset command.
                    discard_line = true;
                    let _ = usb_write_str(&mut class, "err line-too-long\r\n").await;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleAction {
    Continue,
    Reset,
    Dfu,
}

#[allow(clippy::too_many_arguments)]
async fn handle_console_command(
    class: &mut UsbCdc,
    flash: &mut M7Flash,
    pending: &mut GatewayConfig,
    committed: &mut GatewayConfig,
    committed_source: &mut ConfigSource,
    committed_sequence: &mut u64,
    reboot_required: &mut bool,
    #[cfg(feature = "product")] trust_upload: &mut TrustUpload,
    #[cfg(feature = "product")] rtc: &mut Rtc,
    #[cfg(feature = "product")] rtc_time: &RtcTimeProvider,
    #[cfg(feature = "product")] runtime: &'static SharedRuntime,
    #[cfg(feature = "product")] runtime_trust: &'static SharedTrust,
    #[cfg(feature = "product")] active_config: &GatewayConfig,
    uid_words: [u32; 3],
    #[cfg(feature = "product")] server_identity: ServerIdentity,
    line: &str,
) -> ConsoleAction {
    let line = line.trim();
    if line.is_empty() {
        return ConsoleAction::Continue;
    }
    let mut parts = line.splitn(3, char::is_whitespace);
    let command = parts.next().unwrap_or("");
    #[cfg(feature = "product")]
    let command = if command == "wipe" {
        if parts.next() != Some("confirm") || parts.next().is_some() {
            let _ = usb_write_str(class, "err usage: wipe confirm\r\n").await;
            return ConsoleAction::Continue;
        }
        // Normalize the guarded operator alias so it executes the exact
        // machine factory-reset arm and keeps every response byte identical.
        "factory-reset"
    } else {
        command
    };
    #[cfg(feature = "maintenance-usb-m4-boot-repair")]
    if command == "m4-boot-check" {
        if parts.next().is_some() {
            let _ = usb_write_str(class, "err usage: m4-boot-check\r\n").await;
        } else {
            let mut response: heapless::String<96> = heapless::String::new();
            match crate::usb_m4_boot_repair::status() {
                Ok(()) => {
                    let _ = writeln!(
                        response,
                        "ok m4-boot-repair-ready 004B00323033510D34323932\r"
                    );
                }
                Err(index) => {
                    let _ = writeln!(response, "err m4-boot-guard {index}\r");
                }
            }
            let _ = usb_write_str(class, response.as_str()).await;
        }
        return ConsoleAction::Continue;
    }
    #[cfg(feature = "maintenance-usb-m4-boot-repair")]
    if command == "m4-boot-correct" {
        if line != "m4-boot-correct 004B00323033510D34323932 10000810-to-08100810" {
            let _ = usb_write_str(class, "err repair-confirmation\r\n").await;
            return ConsoleAction::Continue;
        }
        let result = crate::usb_m4_boot_repair::correct();
        let mut response: heapless::String<96> = heapless::String::new();
        match result {
            Ok(()) => {
                let _ = writeln!(response, "ok m4-boot-corrected power-cycle-required\r");
            }
            Err(reason) => {
                let _ = writeln!(response, "err m4-boot-correction {reason}\r");
            }
        }
        let _ = usb_write_str(class, response.as_str()).await;
        return ConsoleAction::Continue;
    }
    match command {
        #[cfg(all(
            feature = "diagnostic-stack-watermark",
            feature = "diagnostic-accelerated-clock"
        ))]
        "stack-capture" if parts.next().is_none() => {
            let _ = usb_write_str(class, "ok stack-capture-requested\r\n").await;
            crate::stack_watermark::request_completed_workload_capture();
        }
        #[cfg(feature = "product")]
        "show" => {
            if parts.next().is_some() {
                let _ = usb_write_str(class, "err usage: show\r\n").await;
                return ConsoleAction::Continue;
            }
            let (settings, settings_label) =
                pending_or_committed_view(*pending, *committed, *reboot_required);
            write_operator_show(
                class,
                settings,
                settings_label,
                *pending != *committed,
                *reboot_required,
                runtime_trust,
                server_identity.application_uri(),
            )
            .await;
        }
        "status" => {
            #[cfg(feature = "product")]
            let trust_status = {
                let trust = runtime_trust.lock().await;
                TrustStatusSnapshot {
                    state: trust.state,
                    anchor_present: trust.material.is_anchor_present(),
                    rtc_usable: trust.rtc_usable,
                    upload_expected: trust_upload.expected_len(),
                    upload_received: trust_upload.received_len(),
                }
            };
            write_status(
                class,
                pending,
                *committed,
                *committed_source,
                *committed_sequence,
                *reboot_required,
                #[cfg(feature = "product")]
                trust_status,
                #[cfg(feature = "product")]
                active_config,
                #[cfg(feature = "product")]
                server_identity.application_uri(),
            )
            .await;
        }
        "get" => {
            let Some(key) = parts.next() else {
                let _ = usb_write_str(class, "err usage: get <key>\r\n").await;
                return ConsoleAction::Continue;
            };
            match ConfigKey::parse(key) {
                Ok(key) => write_config_value(class, pending, key).await,
                Err(error) => write_error(class, error.as_str()).await,
            }
        }
        "set" => {
            let Some(key) = parts.next() else {
                let _ = usb_write_str(class, "err usage: set <key> <value>\r\n").await;
                return ConsoleAction::Continue;
            };
            let Some(value) = parts.next() else {
                let _ = usb_write_str(class, "err usage: set <key> <value>\r\n").await;
                return ConsoleAction::Continue;
            };
            match ConfigKey::parse(key).and_then(|key| pending.set_key_value(key, value.trim())) {
                Ok(()) => {
                    let _ = usb_write_str(class, "ok\r\n").await;
                }
                Err(error) => write_error(class, error.as_str()).await,
            }
        }
        #[cfg(feature = "product")]
        "save" => {
            if parts.next().is_some() {
                let _ = usb_write_str(class, "err usage: save\r\n").await;
                return ConsoleAction::Continue;
            }
            if *pending == *committed {
                let _ = usb_write_str(class, "ok nothing-to-save\r\n").await;
            } else {
                write_commit_response(
                    class,
                    flash,
                    pending,
                    committed,
                    committed_source,
                    committed_sequence,
                    reboot_required,
                    uid_words,
                    ConfigSaveResponse::Operator,
                )
                .await;
            }
        }
        #[cfg(feature = "product")]
        "trust-ca-begin" => {
            let Some(length) = parts.next() else {
                let _ = usb_write_str(class, "err usage: trust-ca-begin <der-bytes>\r\n").await;
                return ConsoleAction::Continue;
            };
            match length.parse::<usize>() {
                Ok(length) => match trust_upload.begin(length) {
                    Ok(()) => {
                        let _ = usb_write_str(class, "ok trust-upload-started\r\n").await;
                    }
                    Err(error) => write_error(class, error.as_str()).await,
                },
                Err(_) => write_error(class, "trust-upload-invalid-length").await,
            }
        }
        #[cfg(feature = "product")]
        "trust-ca-chunk" => {
            let Some(hex) = parts.next() else {
                let _ = usb_write_str(class, "err usage: trust-ca-chunk <hex>\r\n").await;
                return ConsoleAction::Continue;
            };
            let hex = hex.trim();
            if hex.len() > 96 {
                write_error(class, "trust-upload-chunk-too-large").await;
                return ConsoleAction::Continue;
            }
            match trust_upload.append_hex(hex) {
                Ok(decoded) => {
                    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                    let _ = writeln!(
                        response,
                        "ok trust-chunk: {decoded} received: {}/{}\r",
                        trust_upload.received_len(),
                        trust_upload.expected_len()
                    );
                    let _ = usb_write_str(class, response.as_str()).await;
                }
                Err(error) => write_error(class, error.as_str()).await,
            }
        }
        #[cfg(feature = "product")]
        "trust-ca-commit" => {
            let ca_der = match trust_upload.ca_der() {
                Ok(ca_der) => ca_der,
                Err(error) => {
                    write_error(class, error.as_str()).await;
                    return ConsoleAction::Continue;
                }
            };
            let now_seconds = {
                let trust = runtime_trust.lock().await;
                trust.verifier_now_seconds()
            };
            if verify_ca_certificate_with_optional_time(
                ca_der,
                now_seconds.map(UnixTime::from_seconds),
            )
            .is_err()
            {
                write_error(class, "trust-ca-invalid").await;
                return ConsoleAction::Continue;
            }
            let mut provisioned = GatewayTrust::missing();
            let _ = load_field_config(uid_words, &mut provisioned);
            if let Err(error) = provisioned.replace_ca_der(ca_der) {
                write_error(class, error.as_str()).await;
                return ConsoleAction::Continue;
            }
            match commit_trust_record(flash, uid_words, &provisioned) {
                Ok((target, sequence, config)) => {
                    {
                        let mut trust = runtime_trust.lock().await;
                        match (provisioned.time_provisioned(), now_seconds) {
                            (true, Some(now_seconds)) => {
                                trust.install(provisioned, now_seconds);
                            }
                            _ => trust.install_without_time(provisioned),
                        }
                    }
                    {
                        let mut data_access = runtime.lock().await;
                        data_access.revoke_upstream_trust();
                    }
                    trust_upload.reset();
                    *committed = config;
                    *committed_source = target;
                    *committed_sequence = sequence;
                    let _ = usb_write_str(class, "ok trust-provisioned\r\n").await;
                }
                Err(stage) => {
                    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                    let _ = writeln!(response, "err trust-commit-failed: {stage}\r");
                    let _ = usb_write_str(class, response.as_str()).await;
                }
            }
        }
        #[cfg(feature = "product")]
        "trust-time" => {
            let Some(seconds) = parts.next() else {
                let _ = usb_write_str(class, "err usage: trust-time <unix-seconds>\r\n").await;
                return ConsoleAction::Continue;
            };
            let seconds = match seconds.parse::<u64>() {
                Ok(seconds) => seconds,
                Err(_) => {
                    write_error(class, "trust-time-invalid").await;
                    return ConsoleAction::Continue;
                }
            };
            let datetime = match rtc_datetime_from_unix(seconds) {
                Ok(datetime) => datetime,
                Err(error) => {
                    write_error(class, error).await;
                    return ConsoleAction::Continue;
                }
            };
            let mut current_trust = GatewayTrust::missing();
            let _ = load_field_config(uid_words, &mut current_trust);
            if current_trust.is_anchor_present()
                && verify_ca_certificate_with_optional_time(current_trust.ca_der(), None).is_err()
            {
                write_error(class, "trust-ca-invalid").await;
                return ConsoleAction::Continue;
            }
            if rtc.set_datetime(datetime).is_err() {
                write_error(class, "trust-time-rtc-write").await;
                return ConsoleAction::Continue;
            }
            let Some(readback_seconds) = read_usable_rtc_seconds(rtc_time) else {
                apply_runtime_revocation(runtime, runtime_trust).await;
                write_error(class, "trust-time-rtc-readback").await;
                return ConsoleAction::Continue;
            };
            if readback_seconds < seconds || readback_seconds > seconds.saturating_add(1) {
                apply_runtime_revocation(runtime, runtime_trust).await;
                write_error(class, "trust-time-rtc-mismatch").await;
                return ConsoleAction::Continue;
            }
            let mut updated = current_trust.clone();
            updated.set_time_provisioned(true);
            match commit_trust_record(flash, uid_words, &updated) {
                Ok((target, sequence, config)) => {
                    {
                        let mut trust = runtime_trust.lock().await;
                        trust.install(updated, readback_seconds);
                    }
                    {
                        let mut data_access = runtime.lock().await;
                        data_access.revoke_upstream_trust();
                    }
                    *committed = config;
                    *committed_source = target;
                    *committed_sequence = sequence;
                    let _ = usb_write_str(class, "ok trust-time-provisioned\r\n").await;
                }
                Err(stage) => {
                    apply_runtime_revocation(runtime, runtime_trust).await;
                    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                    let _ = writeln!(response, "err trust-time-commit-failed: {stage}\r");
                    let _ = usb_write_str(class, response.as_str()).await;
                }
            }
        }
        #[cfg(feature = "product")]
        "trust-clear" => {
            let cleared = GatewayTrust::missing();
            match commit_trust_record(flash, uid_words, &cleared) {
                Ok((target, sequence, config)) => {
                    apply_runtime_revocation(runtime, runtime_trust).await;
                    trust_upload.reset();
                    *committed = config;
                    *committed_source = target;
                    *committed_sequence = sequence;
                    let _ = usb_write_str(class, "ok trust-revoked\r\n").await;
                }
                Err(stage) => {
                    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                    let _ = writeln!(response, "err trust-clear-failed: {stage}\r");
                    let _ = usb_write_str(class, response.as_str()).await;
                }
            }
        }
        "commit" => {
            write_commit_response(
                class,
                flash,
                pending,
                committed,
                committed_source,
                committed_sequence,
                reboot_required,
                uid_words,
                ConfigSaveResponse::Machine,
            )
            .await;
        }
        "factory-reset" => {
            let mut reset = factory_reset_config(flash, uid_words);
            let outcome = reset.outcome();
            if outcome.requires_ram_revocation() {
                #[cfg(feature = "product")]
                {
                    apply_runtime_revocation(runtime, runtime_trust).await;
                    trust_upload.reset();
                }
            }

            match reset.error() {
                None => {
                    let completed = reset.complete_ram_revocation();
                    debug_assert!(completed);
                    *pending = GatewayConfig::defaults_from_uid(uid_words);
                    *committed = *pending;
                    *committed_source = reset.target_slot();
                    *committed_sequence = reset.tombstone_sequence();
                    *reboot_required = true;
                    let _ = usb_write_str(class, "ok factory-reset reboot-required: yes\r\n").await;
                }
                Some(stage) => match outcome {
                    FactoryResetOutcome::NotCommitted => {
                        let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                        let _ = writeln!(response, "err factory-reset-not-committed: {stage}\r");
                        let _ = usb_write_str(class, response.as_str()).await;
                    }
                    FactoryResetOutcome::CommittedCleanupIncomplete { commit } => {
                        *reboot_required = true;
                        if commit == FactoryResetCommitEvidence::Confirmed {
                            *pending = GatewayConfig::defaults_from_uid(uid_words);
                            *committed = *pending;
                            *committed_source = reset.target_slot();
                            *committed_sequence = reset.tombstone_sequence();
                        }
                        let commit = match commit {
                            FactoryResetCommitEvidence::Uncertain => "uncertain",
                            FactoryResetCommitEvidence::Confirmed => "confirmed",
                        };
                        let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                        let _ = writeln!(
                            response,
                            "err factory-reset-committed-cleanup-incomplete: {stage} commit: {commit} reboot-required: yes\r"
                        );
                        let _ = usb_write_str(class, response.as_str()).await;
                    }
                    FactoryResetOutcome::CommittedCleanupComplete => {
                        debug_assert!(false, "successful reset carried an error stage");
                    }
                },
            }
        }
        "reboot" => {
            return do_reboot(class).await;
        }
        #[cfg(feature = "product")]
        "restart" => {
            if parts.next().is_some() {
                let _ = usb_write_str(class, "err usage: restart\r\n").await;
                return ConsoleAction::Continue;
            }
            if *pending != *committed {
                let _ = usb_write_str(class, "err unsaved-changes\r\n").await;
            } else {
                return do_reboot(class).await;
            }
        }
        "dfu" => {
            let _ = usb_write_str(class, "ok entering-dfu\r\n").await;
            return ConsoleAction::Dfu;
        }
        #[cfg(feature = "product")]
        "help" => match parts.next() {
            None => {
                let _ = usb_write_str(
                    class,
                    "commands: show|set <key> <value>|save|restart|wipe confirm|help advanced\r\n",
                )
                .await;
            }
            Some("advanced") if parts.next().is_none() => {
                let _ = usb_write_str(
                        class,
                        "commands: status|get <key>|set <key> <value>|commit|trust-time <unix>|trust-ca-begin <len>|trust-ca-chunk <hex>|trust-ca-commit|trust-clear|factory-reset|reboot|dfu\r\n",
                    )
                    .await;
            }
            _ => {
                let _ = usb_write_str(class, "err usage: help\r\n").await;
            }
        },
        #[cfg(feature = "product")]
        "?" => {
            if parts.next().is_some() {
                let _ = usb_write_str(class, "err usage: help\r\n").await;
            } else {
                let _ = usb_write_str(
                    class,
                    "commands: show|set <key> <value>|save|restart|wipe confirm|help advanced\r\n",
                )
                .await;
            }
        }
        #[cfg(not(feature = "product"))]
        "help" | "?" => {
            let _ = usb_write_str(
                class,
                "commands: status|get <key>|set <key> <value>|commit|factory-reset|reboot|dfu\r\n",
            )
            .await;
        }
        _ => {
            let _ = usb_write_str(class, "err unknown-command\r\n").await;
        }
    }
    ConsoleAction::Continue
}

#[cfg(feature = "product")]
fn pending_or_committed_view(
    pending: GatewayConfig,
    committed: GatewayConfig,
    reboot_required: bool,
) -> (GatewayConfig, &'static str) {
    if pending != committed {
        (pending, "pending")
    } else if reboot_required {
        (committed, "saved-restart-needed")
    } else {
        (committed, "current")
    }
}

#[cfg(feature = "product")]
#[allow(clippy::too_many_arguments)]
async fn write_operator_show(
    class: &mut UsbCdc,
    settings: GatewayConfig,
    settings_label: &'static str,
    unsaved_changes: bool,
    reboot_required: bool,
    runtime_trust: &'static SharedTrust,
    application_uri: &str,
) {
    write_kv_str(class, "settings", settings_label).await;
    let mut software = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let revision = crate::build_info::REVISION;
    let short = revision
        .split_once(':')
        .map_or(revision, |(_, hash)| &hash[..12]);
    let _ = write!(software, "{} ({short})", crate::build_info::VERSION);
    write_kv_str(class, "Software", software.as_str()).await;
    write_kv_str(class, "name", settings.device_name.as_str()).await;
    write_kv_str(class, "net-mode", settings.net_mode.as_str()).await;
    if settings.net_mode.as_str() == "static" {
        write_kv_ipv4(class, "saved-ip", settings.static_ip).await;
    }
    write_kv_ipv4(class, "buchi-ip", settings.buchi_ip).await;
    write_kv_str(class, "buchi-user", settings.buchi_user.as_str()).await;
    write_kv_str(class, "buchi-password", settings.password_state().as_str()).await;
    write_kv_str(class, "opcua-application-uri", application_uri).await;
    write_kv_bool(class, "writes-configured", settings.write_enable).await;
    let trust_state = {
        let trust = runtime_trust.lock().await;
        trust.state.as_str()
    };
    write_kv_str(class, "buchi-trust", trust_state).await;
    write_kv_bool(class, "unsaved-changes", unsaved_changes).await;
    write_kv_bool(class, "restart-needed", reboot_required).await;
}

#[derive(Clone, Copy)]
enum ConfigSaveResponse {
    Machine,
    #[cfg(feature = "product")]
    Operator,
}

#[allow(clippy::too_many_arguments)]
async fn write_commit_response(
    class: &mut UsbCdc,
    flash: &mut M7Flash,
    pending: &mut GatewayConfig,
    committed: &mut GatewayConfig,
    committed_source: &mut ConfigSource,
    committed_sequence: &mut u64,
    reboot_required: &mut bool,
    uid_words: [u32; 3],
    response_kind: ConfigSaveResponse,
) {
    match pending.validate() {
        Ok(()) => {
            let mut current_trust = GatewayTrust::missing();
            let (current, _) = load_field_config(uid_words, &mut current_trust);
            let target = current.inactive_slot();
            let sequence = current.next_sequence();
            match write_config_slot(flash, target, sequence, pending, &current_trust) {
                Ok(()) => {
                    *committed = *pending;
                    *committed_source = target;
                    *committed_sequence = sequence;
                    *reboot_required = true;
                    match response_kind {
                        ConfigSaveResponse::Machine => {
                            let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                            let _ = writeln!(
                                response,
                                "ok committed: {} sequence: {} reboot-required: yes\r",
                                target.as_str(),
                                sequence
                            );
                            let _ = usb_write_str(class, response.as_str()).await;
                        }
                        #[cfg(feature = "product")]
                        ConfigSaveResponse::Operator => {
                            let _ = usb_write_str(class, "ok saved restart-needed: yes\r\n").await;
                        }
                    }
                }
                Err(stage) => {
                    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
                    match response_kind {
                        ConfigSaveResponse::Machine => {
                            let _ = writeln!(response, "err commit-failed: {stage}\r");
                        }
                        #[cfg(feature = "product")]
                        ConfigSaveResponse::Operator => {
                            let _ = writeln!(response, "err save-failed: {stage}\r");
                        }
                    }
                    let _ = usb_write_str(class, response.as_str()).await;
                }
            }
        }
        Err(error) => write_error(class, error.as_str()).await,
    }
}

async fn do_reboot(class: &mut UsbCdc) -> ConsoleAction {
    let _ = usb_write_str(class, "ok rebooting\r\n").await;
    ConsoleAction::Reset
}

async fn write_status(
    class: &mut UsbCdc,
    pending: &GatewayConfig,
    committed: GatewayConfig,
    committed_source: ConfigSource,
    committed_sequence: u64,
    reboot_required: bool,
    #[cfg(feature = "product")] trust: TrustStatusSnapshot,
    #[cfg(feature = "product")] active_config: &GatewayConfig,
    #[cfg(feature = "product")] application_uri: &str,
) {
    let dirty = *pending != committed;
    write_kv_str(class, "firmware-version", crate::build_info::VERSION).await;
    write_kv_str(class, "firmware-revision", crate::build_info::REVISION).await;
    write_kv_str(class, "firmware-flavor", crate::build_info::FLAVOR).await;
    write_kv_str(
        class,
        "firmware-source-state",
        crate::build_info::SOURCE_STATE,
    )
    .await;
    write_kv_str(class, "firmware-build-date", crate::build_info::BUILD_DATE).await;
    write_kv_str(class, "config-source", committed_source.as_str()).await;
    write_kv_u64(class, "config-sequence", committed_sequence).await;
    write_kv_str(class, "device-name", pending.device_name.as_str()).await;
    write_kv_str(class, "net-mode", pending.net_mode.as_str()).await;
    write_kv_ipv4(class, "static-ip", pending.static_ip).await;
    write_kv_ipv4(class, "static-netmask", pending.static_netmask).await;
    write_kv_ipv4(class, "static-gateway", pending.static_gateway).await;
    write_kv_ipv4(class, "static-dns", pending.static_dns).await;
    write_kv_ipv4(class, "buchi-ip", pending.buchi_ip).await;
    write_kv_str(class, "buchi-user", pending.buchi_user.as_str()).await;
    write_kv_str(class, "buchi-password", pending.password_state().as_str()).await;
    write_kv_bool(class, "write-enable", pending.write_enable).await;
    write_kv_bool(class, "pending-dirty", dirty).await;
    write_kv_bool(class, "reboot-required", reboot_required).await;
    #[cfg(feature = "product")]
    write_kv_str(class, "opcua-application-uri", application_uri).await;
    #[cfg(feature = "product")]
    {
        let ipv4_word = M7_IPV4_ADDR.load(Ordering::Relaxed);
        let network_active = M7_LINK_STATE.load(Ordering::Relaxed) != 0 && ipv4_word != 0;
        write_kv_bool(class, "network-active", network_active).await;
        write_kv_str(class, "active-net-mode", active_config.net_mode.as_str()).await;
        write_kv_ipv4(class, "active-buchi-ip", active_config.buchi_ip).await;
        write_kv_mdns_name(class, active_config.device_name.as_str()).await;
        let mdns_state = if network_active {
            crate::network::mdns_status()
        } else {
            "waiting"
        };
        write_kv_str(class, "mdns-state", mdns_state).await;
        if mdns_state == "active" {
            let mut name = heapless::String::<40>::new();
            let _ = write!(name, "{}.local", active_config.device_name.as_str());
            write_kv_str(class, "effective-mdns", name.as_str()).await;
        }
        if network_active {
            let active_ipv4 = ipv4_word.to_be_bytes();
            write_kv_ipv4(class, "live-ip", active_ipv4).await;
            write_kv_opcua_endpoint(class, active_ipv4).await;
        }
        write_kv_str(class, "trust-state", trust.state.as_str()).await;
        write_kv_bool(class, "trust-anchor-present", trust.anchor_present).await;
        write_kv_bool(class, "trust-rtc-usable", trust.rtc_usable).await;
        write_kv_u64(class, "trust-upload-expected", trust.upload_expected as u64).await;
        write_kv_u64(class, "trust-upload-received", trust.upload_received as u64).await;
    }
}

async fn write_config_value(class: &mut UsbCdc, config: &GatewayConfig, key: ConfigKey) {
    match key {
        ConfigKey::DeviceName => {
            write_kv_str(class, key.as_str(), config.device_name.as_str()).await
        }
        ConfigKey::NetMode => write_kv_str(class, key.as_str(), config.net_mode.as_str()).await,
        ConfigKey::StaticIp => write_kv_ipv4(class, key.as_str(), config.static_ip).await,
        ConfigKey::StaticNetmask => write_kv_ipv4(class, key.as_str(), config.static_netmask).await,
        ConfigKey::StaticGateway => write_kv_ipv4(class, key.as_str(), config.static_gateway).await,
        ConfigKey::StaticDns => write_kv_ipv4(class, key.as_str(), config.static_dns).await,
        ConfigKey::BuchiIp => write_kv_ipv4(class, key.as_str(), config.buchi_ip).await,
        ConfigKey::BuchiUser => write_kv_str(class, key.as_str(), config.buchi_user.as_str()).await,
        ConfigKey::BuchiPassword => {
            write_kv_str(class, key.as_str(), config.password_state().as_str()).await
        }
        ConfigKey::WriteEnable => write_kv_bool(class, key.as_str(), config.write_enable).await,
    }
}

async fn write_error(class: &mut UsbCdc, reason: &str) {
    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let _ = writeln!(response, "err {reason}\r");
    let _ = usb_write_str(class, response.as_str()).await;
}

async fn write_kv_str(class: &mut UsbCdc, key: &str, value: &str) {
    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let _ = writeln!(response, "{key}: {value}\r");
    let _ = usb_write_str(class, response.as_str()).await;
}

async fn write_kv_bool(class: &mut UsbCdc, key: &str, value: bool) {
    write_kv_str(class, key, if value { "yes" } else { "no" }).await;
}

async fn write_kv_u64(class: &mut UsbCdc, key: &str, value: u64) {
    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let _ = writeln!(response, "{key}: {value}\r");
    let _ = usb_write_str(class, response.as_str()).await;
}

async fn write_kv_ipv4(class: &mut UsbCdc, key: &str, value: [u8; 4]) {
    let mut response = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let _ = writeln!(response, "{key}: {}\r", Ipv4Display(value));
    let _ = usb_write_str(class, response.as_str()).await;
}

#[cfg(feature = "product")]
async fn write_kv_mdns_name(class: &mut UsbCdc, device_name: &str) {
    let mut name = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let _ = write!(name, "{device_name}.local");
    write_kv_str(class, "active-mdns", name.as_str()).await;
}

#[cfg(feature = "product")]
async fn write_kv_opcua_endpoint(class: &mut UsbCdc, ipv4: [u8; 4]) {
    let mut endpoint = heapless::String::<USB_RESPONSE_BUFFER_BYTES>::new();
    let _ = write!(
        endpoint,
        "opc.tcp://{}:{}",
        Ipv4Display(ipv4),
        crate::product_opcua::OPCUA_PORT
    );
    write_kv_str(class, "opcua-endpoint", endpoint.as_str()).await;
}

async fn usb_write_str(class: &mut UsbCdc, value: &str) -> bool {
    usb_write_bytes(class, value.as_bytes()).await
}

async fn usb_write_bytes(class: &mut UsbCdc, mut bytes: &[u8]) -> bool {
    let max_packet = USB_CDC_MAX_PACKET_SIZE as usize;
    let original_len = bytes.len();
    while !bytes.is_empty() {
        task_checkin(WatchdogSlot::UsbConsole);
        let take = if bytes.len() > max_packet {
            max_packet
        } else {
            bytes.len()
        };
        #[cfg(feature = "product")]
        let wrote = usb_write_packet(class, &bytes[..take], UsbStage::WritePacket).await;
        #[cfg(not(feature = "product"))]
        let wrote = usb_write_packet(class, &bytes[..take]).await;
        if !wrote {
            return false;
        }
        bytes = &bytes[take..];
    }
    if original_len != 0 && original_len % max_packet == 0 {
        #[cfg(feature = "product")]
        let wrote = usb_write_packet(class, &[], UsbStage::WriteZeroLengthPacket).await;
        #[cfg(not(feature = "product"))]
        let wrote = usb_write_packet(class, &[]).await;
        if !wrote {
            return false;
        }
    }
    true
}

#[cfg(feature = "product")]
async fn usb_write_packet(class: &mut UsbCdc, packet: &[u8], stage: UsbStage) -> bool {
    usb_probe_stage(stage);
    M7_USB_LAST_WRITE_LEN.store(packet.len() as u32, Ordering::Relaxed);
    #[cfg(feature = "diagnostic-stall-usb-console-write")]
    if stage == UsbStage::WritePacket && uptime_now_ms() >= 5_000 {
        M7_INDUCED_HANG_PROBE.store(WatchdogSlot::UsbConsole.mask(), Ordering::Relaxed);
        pending::<()>().await;
    }
    match with_timeout(WATCHDOG_TASK_DEADLINE, class.write_packet(packet)).await {
        Ok(Ok(())) => {
            task_checkin(WatchdogSlot::UsbConsole);
            usb_probe_error(UsbProbeError::None);
            true
        }
        Ok(Err(_)) => {
            usb_probe_error(UsbProbeError::WriteError);
            false
        }
        Err(_) => {
            usb_probe_error(UsbProbeError::WriteTimeout);
            false
        }
    }
}

#[cfg(not(feature = "product"))]
async fn usb_write_packet(class: &mut UsbCdc, packet: &[u8]) -> bool {
    class.write_packet(packet).await.is_ok()
}

fn enter_dfu_via_bkp0_and_reset() -> ! {
    board::enable_backup_domain_writes_raw();
    // SAFETY: RTC_BKP0R is the Arduino bootloader DFU handoff register for
    // this product family. The DFU command writes only BKP0R with 0xDF59, intentionally
    // leaves DBP set, and does not touch BKP8 or the last-fault registers.
    unsafe {
        const RTC_BKP0R: *mut u32 = 0x5800_4050 as *mut u32;
        RTC_BKP0R.write_volatile(DFU_BKP0R_MAGIC);
        cortex_m::asm::dsb();
    }
    cortex_m::peripheral::SCB::sys_reset();
}
