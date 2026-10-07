// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use super::*;
use opta_buchi::ProcessValues;

mod accelerated;
#[cfg(feature = "diagnostic-cache-ages")]
mod diagnostic_ages;
mod queued_write_cancellation;

fn verified_data_access<const WRITE_CAPACITY: usize>() -> RuntimeDataAccess<WRITE_CAPACITY> {
    let mut data_access = RuntimeDataAccess::new();
    data_access.set_trust_state(TrustState::Verified);
    data_access.set_write_enabled(true);
    data_access
}

fn verified_poll_runtime<const WRITE_CAPACITY: usize>(
    now_monotonic_ms: u32,
) -> BuchiPollRuntime<WRITE_CAPACITY> {
    let mut runtime = BuchiPollRuntime::new(now_monotonic_ms);
    runtime
        .data_access_mut()
        .set_trust_state(TrustState::Verified);
    runtime.data_access_mut().set_write_enabled(true);
    runtime
}

fn verified_client_task<
    const WRITE_CAPACITY: usize,
    const BODY_CAPACITY: usize,
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
>(
    now_monotonic_ms: u32,
) -> BuchiClientTask<WRITE_CAPACITY, BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY> {
    let mut task = BuchiClientTask::new(now_monotonic_ms);
    task.runtime_mut()
        .data_access_mut()
        .set_trust_state(TrustState::Verified);
    task.runtime_mut().data_access_mut().set_write_enabled(true);
    task
}
use opta_buchi::{
    BuchiGetTransactionError, BuchiGetTransportError, BuchiTransport, BuchiTransportIoError,
    BuchiTransportStep, EndpointResponseError, EndpointValues, HttpReadProgress, HttpResponseError,
    ParseError, ProcessRootPresence,
};
use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::{CacheRead, CacheReadStatus};
use opta_gateway_contracts::last_fault::{LastFaultFormat, LastFaultReason, LastFaultRecord};
use opta_gateway_contracts::opcua_status;

struct ScriptedTransport<'a> {
    write_steps: &'a [Result<usize, BuchiTransportIoError>],
    read_steps: &'a [Result<&'a [u8], BuchiTransportIoError>],
    write_index: usize,
    read_index: usize,
    written: [u8; 1024],
    written_len: usize,
}

impl<'a> ScriptedTransport<'a> {
    const fn new(
        write_steps: &'a [Result<usize, BuchiTransportIoError>],
        read_steps: &'a [Result<&'a [u8], BuchiTransportIoError>],
    ) -> Self {
        Self {
            write_steps,
            read_steps,
            write_index: 0,
            read_index: 0,
            written: [0; 1024],
            written_len: 0,
        }
    }

    fn written(&self) -> &[u8] {
        &self.written[..self.written_len]
    }
}

impl BuchiTransport for ScriptedTransport<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, BuchiTransportIoError> {
        let step = self
            .write_steps
            .get(self.write_index)
            .copied()
            .unwrap_or(Ok(bytes.len()));
        self.write_index += 1;
        let max_write = step?;
        let written_len = max_write.min(bytes.len());
        let end = self.written_len + written_len;
        self.written[self.written_len..end].copy_from_slice(&bytes[..written_len]);
        self.written_len = end;
        Ok(written_len)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, BuchiTransportIoError> {
        let step = self
            .read_steps
            .get(self.read_index)
            .copied()
            .unwrap_or(Ok(b"".as_slice()));
        self.read_index += 1;
        let chunk = step?;
        assert!(chunk.len() <= out.len());
        out[..chunk.len()].copy_from_slice(chunk);
        Ok(chunk.len())
    }
}

const PROCESS_JSON: &[u8] = include_bytes!("../testdata/process.json");

const SETTINGS_JSON: &[u8] = include_bytes!("../testdata/settings.json");

const INFO_JSON: &[u8] = include_bytes!("../testdata/info.json");

fn http_ok(body: &[u8]) -> std::vec::Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn http_status(status: i32, body: &[u8]) -> std::vec::Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        status,
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn assert_fresh_value(cache: &RuntimeCache, node: RuntimeNode, now: u64, value: ScalarValue) {
    let read = cache.read(node, now);
    assert_eq!(read.status, CacheReadStatus::Ok);
    assert_eq!(read.value, Some(value));
    assert_eq!(read.opcua_status(), opcua_status::GOOD);
    assert!(read.has_fresh_value());
}

fn assert_not_connected(cache: &RuntimeCache, node: RuntimeNode, now: u64) {
    let read = cache.read(node, now);
    assert_eq!(read.status, CacheReadStatus::NotConnected);
    assert_eq!(read.value, None);
    assert_eq!(read.opcua_status(), opcua_status::BAD_NOT_CONNECTED);
    assert!(!read.has_fresh_value());
}

#[test]
fn node_contract_table_covers_all_supported_endpoint_fields() {
    assert_eq!(NODE_COUNT, 86);
    assert_eq!(PROCESS_NODE_COUNT, 29);
    assert_eq!(SETTINGS_NODE_COUNT, 21);
    assert_eq!(INFO_NODE_COUNT, 36);
    assert_eq!(runtime_node_contracts().len(), NODE_COUNT);

    for (index, contract) in runtime_node_contracts().iter().enumerate() {
        assert_eq!(contract.node.index(), index);
        assert_eq!(contract.endpoint, contract.node.endpoint());
        assert_eq!(contract.node.contract(), contract);
    }

    assert_eq!(
        RuntimeNode::ProcessHeatingSet.contract().writable_node_id,
        Some(2001)
    );
    assert_eq!(
        RuntimeNode::ProcessGlobalStatusRunning
            .contract()
            .writable_node_id,
        Some(2030)
    );
    assert_eq!(
        RuntimeNode::SettingsVacuumMaxPermPressure
            .contract()
            .writable_node_id,
        Some(3001)
    );
    assert_eq!(
        RuntimeNode::InfoRotavaporLiftMoves
            .contract()
            .writable_node_id,
        None
    );
    assert_eq!(RuntimeNode::ProcessPressure.endpoint(), Endpoint::Process);
    assert_eq!(
        RuntimeNode::SettingsDisplayBrightness.endpoint(),
        Endpoint::Settings
    );
    assert_eq!(
        RuntimeNode::InfoVacuboxOperatingTimeHours.endpoint(),
        Endpoint::Info
    );
    assert_eq!(
        RuntimeNode::InfoChillerAttached.contract().browse_name,
        "Info.Chiller.Attached"
    );
    assert_eq!(
        RuntimeNode::InfoChillerAttached.contract().value_kind,
        ValueKind::Boolean
    );
}

#[test]
fn process_http_response_publishes_all_process_cache_slots_with_freshness() {
    let mut cache = RuntimeCache::new();
    let response = http_ok(PROCESS_JSON);
    let report = cache
        .apply_http_response(Endpoint::Process, &response, 4096, 1_000)
        .expect("process response should parse and publish");

    assert_eq!(report.summary.endpoint, Endpoint::Process);
    assert_eq!(report.summary.parsed_fields, 28);
    assert_eq!(report.summary.published_values, 29);
    assert_eq!(report.completed_fetches, 1);
    assert_eq!(report.failed_fetches, 0);
    assert_eq!(report.last_http_status, Some(200));
    assert_eq!(cache.last_endpoint(), Some(Endpoint::Process));

    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessHeatingSet,
        1_000,
        ScalarValue::FloatMilli(42_125),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessBathTemperature,
        1_000,
        ScalarValue::FloatMilli(41_875),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessCoolingRunning,
        1_000,
        ScalarValue::Boolean(false),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessVacuumSet,
        1_000,
        ScalarValue::FloatMilli(125_000),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessRotationSet,
        1_000,
        ScalarValue::FloatMilli(120_000),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusRunId,
        1_000,
        ScalarValue::UInt32(u32::MAX),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusRunning,
        1_000,
        ScalarValue::Boolean(true),
    );

    let stale = cache.read(
        RuntimeNode::ProcessHeatingSet,
        1_000 + u64::from(Endpoint::Process.freshness_ms()) + 1,
    );
    assert_eq!(stale.status, CacheReadStatus::Stale);
    assert_eq!(stale.value, None);
    assert_eq!(
        stale.opcua_status(),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
}

#[test]
fn settings_and_info_have_independent_freshness_windows() {
    let mut cache = RuntimeCache::new();
    let settings = http_ok(SETTINGS_JSON);
    let info = http_ok(INFO_JSON);

    let settings_report = cache
        .apply_http_response(Endpoint::Settings, &settings, 4096, 5_000)
        .expect("settings response publishes");
    assert_eq!(settings_report.summary.parsed_fields, 21);
    assert_eq!(settings_report.summary.published_values, 21);

    let info_report = cache
        .apply_http_response(Endpoint::Info, &info, 4096, 60_000)
        .expect("info response publishes");
    assert_eq!(info_report.summary.parsed_fields, 31);
    assert_eq!(info_report.summary.published_values, 31);
    assert_eq!(cache.completed_fetches(), 2);

    assert_fresh_value(
        &cache,
        RuntimeNode::SettingsDisplayBrightness,
        5_000,
        ScalarValue::Int32(75),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::SettingsVacuumMaxPermPressure,
        5_000,
        ScalarValue::FloatMilli(1_000_000),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::SettingsProgramEcoCoolantTemperature,
        5_000,
        ScalarValue::FloatMilli(12_500),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::InfoControllerRunTotalRuns,
        60_000,
        ScalarValue::Int32(10),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::InfoPumpModule1MaxTemperature,
        60_000,
        ScalarValue::FloatMilli(-3_750),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::InfoVacuboxOperatingTimeHours,
        60_000,
        ScalarValue::Int32(700),
    );

    assert_eq!(
        cache
            .read(
                RuntimeNode::SettingsDisplayBrightness,
                5_000 + u64::from(Endpoint::Settings.freshness_ms()) + 1,
            )
            .status,
        CacheReadStatus::Stale
    );
    assert_eq!(
        cache
            .read(RuntimeNode::InfoControllerRunTotalRuns, 60_000 + 1)
            .status,
        CacheReadStatus::Ok
    );
}

#[test]
fn failed_fetch_increments_failure_counter_without_overwriting_fresh_value() {
    let mut cache = RuntimeCache::new();
    let process = http_ok(PROCESS_JSON);
    cache
        .apply_http_response(Endpoint::Process, &process, 4096, 10)
        .expect("initial process publish");

    let response = http_status(503, br#"{"error":"down"}"#);
    let failure = cache
        .apply_http_response(Endpoint::Process, &response, 4096, 20)
        .expect_err("503 should fail closed");
    assert_eq!(failure.endpoint, Endpoint::Process);
    assert_eq!(
        failure.error,
        EndpointPollError::Response(EndpointResponseError::UnexpectedStatus(503))
    );
    assert_eq!(failure.completed_fetches, 1);
    assert_eq!(failure.failed_fetches, 1);
    assert_eq!(failure.last_http_status, Some(503));
    assert_eq!(cache.last_http_status(), Some(503));

    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessHeatingSet,
        20,
        ScalarValue::FloatMilli(42_125),
    );
    assert_eq!(
        cache
            .read(
                RuntimeNode::ProcessHeatingSet,
                10 + u64::from(Endpoint::Process.freshness_ms()) + 1,
            )
            .status,
        CacheReadStatus::Stale
    );
}

#[test]
fn malformed_success_body_counts_failure_and_does_not_publish_defaults() {
    let mut cache = RuntimeCache::new();
    let response = http_ok(br#"{"heating":{"set":42.0}"#);
    let failure = cache
        .apply_http_response(Endpoint::Process, &response, 4096, 100)
        .expect_err("malformed JSON body should fail");

    assert_eq!(
        failure.error,
        EndpointPollError::Response(EndpointResponseError::Body(ParseError::Malformed))
    );
    assert_eq!(failure.last_http_status, Some(200));
    assert_eq!(cache.completed_fetches(), 0);
    assert_eq!(cache.failed_fetches(), 1);
    assert_eq!(
        cache.read(RuntimeNode::ProcessHeatingSet, 100).status,
        CacheReadStatus::NeverPublished
    );
}

#[test]
fn partial_payload_publishes_only_present_fields() {
    let mut cache = RuntimeCache::new();
    let response =
        http_ok(br#"{"globalStatus":{"running":false,"processTime":0},"vacuum":{"act":0.125}}"#);
    let report = cache
        .apply_http_response(Endpoint::Process, &response, 4096, 100)
        .expect("partial but supported response should publish present fields");

    assert_eq!(report.summary.parsed_fields, 3);
    // 5 = the 4 present fields plus the substituted idle-run RunId.
    assert_eq!(report.summary.published_values, 5);
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusRunId,
        100,
        ScalarValue::UInt32(0),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessState,
        100,
        ScalarValue::Int32(0),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusRunning,
        100,
        ScalarValue::Boolean(false),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusProcessTime,
        100,
        ScalarValue::UInt32(0),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessPressure,
        100,
        ScalarValue::FloatMilli(125),
    );
    assert_eq!(
        cache.read(RuntimeNode::ProcessHeatingSet, 100).status,
        CacheReadStatus::NeverPublished
    );
}

#[test]
fn valid_root_with_stalled_field_never_realiases_good_across_wraps() {
    const EPOCH_MS: u64 = 1_u64 << 32;
    const PUBLISHED_AT_MS: u64 = 123_456;
    let mut data_access = verified_data_access::<4>();
    let initial =
        http_ok(br#"{"heating":{"set":42.125,"act":41.875},"globalStatus":{"running":true}}"#);
    data_access
        .apply_http_response(Endpoint::Process, &initial, 4096, PUBLISHED_AT_MS)
        .expect("initial valid field and sibling publish");
    assert_eq!(
        data_access
            .read_node(RuntimeNode::ProcessHeatingSet, PUBLISHED_AT_MS)
            .opcua_status,
        opcua_status::GOOD
    );

    let stalled =
        http_ok(br#"{"heating":{"set":"invalid","act":41.5},"globalStatus":{"running":true}}"#);
    for freshness_now_ms in [
        PUBLISHED_AT_MS + 1,
        PUBLISHED_AT_MS + EPOCH_MS,
        PUBLISHED_AT_MS + 2 * EPOCH_MS,
    ] {
        let report = data_access
            .apply_http_response(Endpoint::Process, &stalled, 4096, freshness_now_ms)
            .expect("valid root and sibling keep the response accepted");
        assert!(report.summary.published_values >= 2);
        let sibling = data_access.read_node(RuntimeNode::ProcessBathTemperature, freshness_now_ms);
        assert_eq!(sibling.opcua_status, opcua_status::GOOD);
        assert_eq!(sibling.value, Some(ScalarValue::FloatMilli(41_500)));
    }

    let stalled = data_access.read_node(
        RuntimeNode::ProcessHeatingSet,
        PUBLISHED_AT_MS + 2 * EPOCH_MS,
    );
    assert_eq!(stalled.cache_status, CacheReadStatus::Stale);
    assert_eq!(
        stalled.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(stalled.value, None);
}

#[test]
fn present_global_status_substitutes_good_zero_for_absent_run_members() {
    // DeltaV maps Bad tag quality onto LDT health, and the device omits
    // globalStatus.processTime/runId while no run is active. A present
    // globalStatus object must therefore serve Good 0 for both members,
    // while omitting the whole globalStatus object must still invalidate
    // them (BH-6).
    let mut cache = RuntimeCache::new();
    let idle = http_ok(br#"{"globalStatus":{"running":false,"onHold":0}}"#);
    cache
        .apply_http_response(Endpoint::Process, &idle, 4096, 100)
        .expect("idle-run payload should publish substituted members");
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusProcessTime,
        100,
        ScalarValue::UInt32(0),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusRunId,
        100,
        ScalarValue::UInt32(0),
    );

    let without_global_status = http_ok(br#"{"heating":{"set":42.0}}"#);
    cache
        .apply_http_response(Endpoint::Process, &without_global_status, 4096, 200)
        .expect("payload without globalStatus should still be accepted");
    for node in [
        RuntimeNode::ProcessGlobalStatusProcessTime,
        RuntimeNode::ProcessGlobalStatusRunId,
    ] {
        let read = cache.read(node, 200);
        assert_eq!(read.status, CacheReadStatus::NeverPublished);
        assert_eq!(read.value, None);
        assert_eq!(
            read.opcua_status(),
            opcua_status::BAD_WAITING_FOR_INITIAL_DATA
        );
    }
}

#[test]
fn subsystem_attachment_hysteresis_masks_detached_owned_nodes() {
    let mut cache = RuntimeCache::new();

    for now in [100, 200, 300] {
        cache.apply_endpoint_values(
            EndpointValues::Process(ProcessValues {
                roots: ProcessRootPresence {
                    cooling: true,
                    vacuum: true,
                    global_status: true,
                    ..ProcessRootPresence::default()
                },
                cooling_actual_milli_celsius: Some(4_250),
                pressure_milli_mbar: Some(125_000),
                process_state: Some(1),
                ..ProcessValues::default()
            }),
            now,
        );
    }
    assert_eq!(
        cache.attachment_state(Subsystem::Chiller),
        AttachmentState::Attached
    );
    assert_eq!(
        cache.read(RuntimeNode::InfoChillerAttached, 300).value,
        Some(ScalarValue::Boolean(true))
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessCoolingActual,
        300,
        ScalarValue::FloatMilli(4_250),
    );

    cache.record_endpoint_failure(
        Endpoint::Process,
        EndpointResponseError::UnexpectedStatus(503),
    );
    assert_eq!(
        cache.attachment_state(Subsystem::Chiller),
        AttachmentState::Attached
    );

    for now in [400, 500] {
        cache.apply_endpoint_values(
            EndpointValues::Process(ProcessValues {
                roots: ProcessRootPresence {
                    vacuum: true,
                    global_status: true,
                    ..ProcessRootPresence::default()
                },
                pressure_milli_mbar: Some(126_000),
                process_state: Some(1),
                ..ProcessValues::default()
            }),
            now,
        );
        // Attachment hysteresis still lags (Attached until 3 absences), but
        // BH-6 clears cooling value quality on the first omitted object.
        assert_eq!(
            cache.attachment_state(Subsystem::Chiller),
            AttachmentState::Attached
        );
        assert_ne!(
            cache.read(RuntimeNode::ProcessCoolingActual, now).status,
            CacheReadStatus::Ok,
            "first absent cooling object must not leave stale Good values"
        );
    }

    cache.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            roots: ProcessRootPresence {
                vacuum: true,
                global_status: true,
                ..ProcessRootPresence::default()
            },
            pressure_milli_mbar: Some(127_000),
            process_state: Some(1),
            ..ProcessValues::default()
        }),
        600,
    );
    assert_eq!(
        cache.attachment_state(Subsystem::Chiller),
        AttachmentState::Detached
    );
    assert_not_connected(&cache, RuntimeNode::ProcessCoolingActual, 600);
    assert_not_connected(&cache, RuntimeNode::SettingsCoolingStopOnFinish, 600);
    assert_not_connected(&cache, RuntimeNode::InfoChillerPumpHours, 600);
    assert_eq!(
        cache.read(RuntimeNode::InfoChillerAttached, 600),
        CacheRead {
            status: CacheReadStatus::Ok,
            value: Some(ScalarValue::Boolean(false)),
        }
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessPressure,
        600,
        ScalarValue::FloatMilli(127_000),
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessGlobalStatusRunning,
        600,
        ScalarValue::Boolean(true),
    );
}

#[test]
fn subsystem_reattach_requires_three_successful_present_polls() {
    let mut cache = RuntimeCache::new();

    for now in [100, 200, 300] {
        cache.apply_endpoint_values(
            EndpointValues::Process(ProcessValues {
                roots: ProcessRootPresence {
                    global_status: true,
                    ..ProcessRootPresence::default()
                },
                process_state: Some(1),
                ..ProcessValues::default()
            }),
            now,
        );
    }
    assert_eq!(
        cache.attachment_state(Subsystem::Chiller),
        AttachmentState::Detached
    );
    assert_not_connected(&cache, RuntimeNode::ProcessCoolingActual, 300);

    for (now, value) in [(400, 4_000), (500, 5_000)] {
        cache.apply_endpoint_values(
            EndpointValues::Process(ProcessValues {
                roots: ProcessRootPresence {
                    cooling: true,
                    global_status: true,
                    ..ProcessRootPresence::default()
                },
                cooling_actual_milli_celsius: Some(value),
                process_state: Some(1),
                ..ProcessValues::default()
            }),
            now,
        );
        assert_eq!(
            cache.attachment_state(Subsystem::Chiller),
            AttachmentState::Detached
        );
        assert_not_connected(&cache, RuntimeNode::ProcessCoolingActual, now);
    }

    cache.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            roots: ProcessRootPresence {
                cooling: true,
                global_status: true,
                ..ProcessRootPresence::default()
            },
            cooling_actual_milli_celsius: Some(6_000),
            process_state: Some(1),
            ..ProcessValues::default()
        }),
        600,
    );
    assert_eq!(
        cache.attachment_state(Subsystem::Chiller),
        AttachmentState::Attached
    );
    assert_fresh_value(
        &cache,
        RuntimeNode::ProcessCoolingActual,
        600,
        ScalarValue::FloatMilli(6_000),
    );
}

#[test]
fn stale_values_remain_distinct_from_not_connected_overlay() {
    let mut cache = RuntimeCache::new();
    cache.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            roots: ProcessRootPresence {
                heating: true,
                global_status: true,
                ..ProcessRootPresence::default()
            },
            heating_set_milli_celsius: Some(42_125),
            process_state: Some(1),
            ..ProcessValues::default()
        }),
        100,
    );

    let stale = cache.read(
        RuntimeNode::ProcessHeatingSet,
        100 + u64::from(Endpoint::Process.freshness_ms()) + 1,
    );
    assert_eq!(stale.status, CacheReadStatus::Stale);
    assert_eq!(
        stale.opcua_status(),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(stale.value, None);

    for now in [200, 300, 400] {
        cache.apply_endpoint_values(
            EndpointValues::Process(ProcessValues {
                roots: ProcessRootPresence {
                    global_status: true,
                    ..ProcessRootPresence::default()
                },
                process_state: Some(1),
                ..ProcessValues::default()
            }),
            now,
        );
    }
    assert_not_connected(&cache, RuntimeNode::ProcessHeatingSet, 400);
}

#[test]
fn endpoint_poll_scheduler_uses_product_behavior_cadence_and_priority() {
    let mut scheduler = EndpointPollScheduler::new(100);
    let due = scheduler.due_endpoints(100);
    assert_eq!(due.count(), 3);
    assert!(due.contains(Endpoint::Process));
    assert!(due.contains(Endpoint::Settings));
    assert!(due.contains(Endpoint::Info));
    assert_eq!(due.first_due(), Some(Endpoint::Process));
    assert_eq!(scheduler.next_due_endpoint(100), Some(Endpoint::Process));

    scheduler.mark_polled(Endpoint::Process, 100);
    assert_eq!(scheduler.last_poll_ms(Endpoint::Process), Some(100));
    assert_eq!(
        scheduler.next_due_ms(Endpoint::Process),
        100 + product::PROCESS_POLL_MS
    );
    assert!(!scheduler.due_endpoints(1_099).contains(Endpoint::Process));
    assert!(scheduler.due_endpoints(1_100).contains(Endpoint::Process));

    scheduler.mark_polled(Endpoint::Settings, 100);
    scheduler.mark_polled(Endpoint::Info, 100);
    assert_eq!(
        scheduler.next_due_ms(Endpoint::Settings),
        100 + product::SETTINGS_POLL_MS
    );
    assert_eq!(
        scheduler.next_due_ms(Endpoint::Info),
        100 + product::INFO_POLL_MS
    );
    assert!(scheduler.due_endpoints(1_100).contains(Endpoint::Process));
    assert!(!scheduler.due_endpoints(1_100).contains(Endpoint::Settings));
    assert!(!scheduler.due_endpoints(1_100).contains(Endpoint::Info));
    assert_eq!(scheduler.next_due_endpoint(5_100), Some(Endpoint::Process));
}

#[test]
fn endpoint_poll_scheduler_uses_wraparound_safe_due_checks() {
    let start = u32::MAX - 10;
    let mut scheduler = EndpointPollScheduler::new(start);
    assert_eq!(scheduler.next_due_endpoint(start), Some(Endpoint::Process));

    scheduler.mark_polled(Endpoint::Process, start);
    assert!(!scheduler
        .due_endpoints(start.wrapping_add(product::PROCESS_POLL_MS - 1))
        .contains(Endpoint::Process));
    assert!(scheduler
        .due_endpoints(start.wrapping_add(product::PROCESS_POLL_MS))
        .contains(Endpoint::Process));
    assert_eq!(
        scheduler.next_due_ms(Endpoint::Process),
        start.wrapping_add(product::PROCESS_POLL_MS)
    );
}

#[test]
fn buchi_poll_runtime_dispatches_due_polls_into_cache() {
    let mut runtime = verified_poll_runtime::<4>(0);
    assert_eq!(
        runtime.next_poll(0),
        Some(BuchiPollRequest {
            endpoint: Endpoint::Process,
            path: "/api/v1/process",
            poll_ms: product::PROCESS_POLL_MS,
        })
    );

    let process_response = http_ok(PROCESS_JSON);
    let process = runtime.apply_poll_http_response(Endpoint::Process, &process_response, 4096, 0);
    assert_eq!(process.endpoint, Endpoint::Process);
    assert_eq!(process.next_due_ms, product::PROCESS_POLL_MS);
    assert_eq!(
        process
            .result
            .expect("process poll should parse")
            .summary
            .endpoint,
        Endpoint::Process
    );
    assert_eq!(
        runtime
            .data_access()
            .read_node(RuntimeNode::ProcessHeatingSet, 0)
            .value,
        Some(ScalarValue::FloatMilli(42_125))
    );

    assert_eq!(
        runtime.next_poll(0),
        Some(BuchiPollRequest {
            endpoint: Endpoint::Settings,
            path: "/api/v1/settings",
            poll_ms: product::SETTINGS_POLL_MS,
        })
    );
    let settings_response = http_ok(SETTINGS_JSON);
    runtime.apply_poll_http_response(Endpoint::Settings, &settings_response, 4096, 10);
    assert_eq!(
        runtime
            .data_access()
            .read_node(RuntimeNode::SettingsDisplayBrightness, 10)
            .value,
        Some(ScalarValue::Int32(75))
    );

    assert_eq!(
        runtime.next_poll(10),
        Some(BuchiPollRequest {
            endpoint: Endpoint::Info,
            path: "/api/v1/info",
            poll_ms: product::INFO_POLL_MS,
        })
    );
    let info_response = http_ok(INFO_JSON);
    runtime.apply_poll_http_response(Endpoint::Info, &info_response, 4096, 20);
    assert_eq!(
        runtime
            .data_access()
            .read_node(RuntimeNode::InfoControllerRunTotalRuns, 20)
            .value,
        Some(ScalarValue::Int32(10))
    );

    assert_eq!(runtime.next_poll(999), None);
    assert_eq!(
        runtime.next_poll(product::PROCESS_POLL_MS),
        Some(BuchiPollRequest::new(Endpoint::Process))
    );
}

#[test]
fn buchi_poll_runtime_applies_completed_transaction_values() {
    let mut runtime = verified_poll_runtime::<4>(0);
    let values = EndpointValues::Process(ProcessValues {
        heating_set_milli_celsius: Some(42_125),
        global_status_process_time_seconds: Some(7),
        ..ProcessValues::default()
    });

    let completion = runtime.apply_poll_values(values, 1_000);
    assert_eq!(completion.endpoint, Endpoint::Process);
    assert_eq!(completion.next_due_ms, 2_000);
    let report = completion
        .result
        .expect("values publish as a successful poll");
    assert_eq!(report.completed_fetches, 1);
    assert_eq!(report.failed_fetches, 0);
    assert_eq!(report.last_http_status, Some(200));
    assert_eq!(report.summary.endpoint, Endpoint::Process);
    assert_eq!(report.summary.parsed_fields, 2);
    assert_eq!(report.summary.published_values, 2);
    assert_eq!(
        runtime
            .data_access()
            .read_node(RuntimeNode::ProcessHeatingSet, 1_000)
            .value,
        Some(ScalarValue::FloatMilli(42_125))
    );
    assert_eq!(
        runtime
            .data_access()
            .read_health_node(HealthNode::BuchiCompletedFetchCount)
            .value,
        Some(ScalarValue::UInt32(1))
    );
    assert_eq!(
        runtime.next_poll(1_999),
        Some(BuchiPollRequest::new(Endpoint::Settings))
    );
    assert_eq!(
        runtime.next_poll(2_000),
        Some(BuchiPollRequest::new(Endpoint::Process))
    );
}

#[test]
fn buchi_poll_runtime_builds_due_get_transaction_without_marking_polled() {
    let runtime = verified_poll_runtime::<4>(0);
    let poll = runtime
        .next_poll_transaction::<256, 160>(0, "r300.local", "cm86cm8=")
        .expect("due poll transaction builds")
        .expect("process poll is due");

    assert_eq!(poll.request, BuchiPollRequest::new(Endpoint::Process));
    assert_eq!(poll.transaction.endpoint(), Endpoint::Process);
    assert_eq!(
        poll.transaction.request(),
        b"GET /api/v1/process HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cm86cm8=\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(
        runtime.next_poll(0),
        Some(BuchiPollRequest::new(Endpoint::Process))
    );
    assert_eq!(
        runtime.next_poll_transaction::<16, 160>(0, "r300.local", "cm86cm8="),
        Err(BuchiGetTransactionError::Build(
            opta_buchi::BuildHttpRequestError::OutputTooSmall
        ))
    );
}

#[test]
fn buchi_poll_runtime_applies_completed_get_transaction() {
    let mut runtime = verified_poll_runtime::<4>(0);
    let mut poll = runtime
        .next_poll_transaction::<256, 160>(0, "r300.local", "cm86cm8=")
        .expect("due poll transaction builds")
        .expect("process poll is due");
    poll.transaction
        .record_write(poll.transaction.request_len())
        .expect("request send completes");
    poll.transaction
        .append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n",
        )
        .expect("headers accepted");
    poll.transaction
        .append_response(br#"{"heating":{"act":42.125}}"#)
        .expect("body reaches extra-byte probe");
    poll.transaction
        .finish_extra_body_probe()
        .expect("response completes");

    let completion = runtime
        .apply_completed_poll_transaction(&poll, 1_000)
        .expect("completed transaction can be applied");
    assert_eq!(completion.endpoint, Endpoint::Process);
    assert_eq!(completion.next_due_ms, 2_000);
    let report = completion.result.expect("completed GET publishes values");
    assert_eq!(report.completed_fetches, 1);
    assert_eq!(report.failed_fetches, 0);
    assert_eq!(
        runtime
            .data_access()
            .read_node(RuntimeNode::ProcessBathTemperature, 1_000)
            .value,
        Some(ScalarValue::FloatMilli(42_125))
    );
}

#[test]
fn buchi_poll_runtime_records_completed_get_transaction_endpoint_failure() {
    let mut runtime = verified_poll_runtime::<4>(0);
    let mut poll = runtime
        .next_poll_transaction::<256, 128>(0, "r300.local", "cm86cm8=")
        .expect("due poll transaction builds")
        .expect("process poll is due");
    poll.transaction
        .record_write(poll.transaction.request_len())
        .expect("request send completes");
    poll.transaction
        .append_response(
            b"HTTP/1.1 503 Busy\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("response reaches probe state");
    poll.transaction
        .finish_extra_body_probe()
        .expect("response completes");

    let completion = runtime
        .apply_completed_poll_transaction(&poll, 1_000)
        .expect("endpoint-status failure records as poll completion");
    let failure = completion.result.expect_err("503 fails closed");
    assert_eq!(failure.endpoint, Endpoint::Process);
    assert_eq!(
        failure.error,
        EndpointPollError::Response(EndpointResponseError::UnexpectedStatus(503))
    );
    assert_eq!(failure.failed_fetches, 1);
    assert_eq!(failure.last_http_status, Some(503));
    assert_eq!(completion.next_due_ms, 2_000);
    assert_eq!(
        runtime
            .data_access()
            .read_health_node(HealthNode::BuchiFailedFetchCount)
            .value,
        Some(ScalarValue::UInt32(1))
    );
}

#[test]
fn buchi_client_transaction_prioritizes_queued_writes_before_due_polls() {
    let mut runtime = verified_poll_runtime::<1>(0);
    assert!(
        runtime
            .data_access_mut()
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true)
            )
            .accepted
    );

    assert_eq!(
        runtime.next_client_transaction::<8, 384, 128>(0, "r300.local", "cm86cm8=", "cndyOnJ3"),
        Err(BuchiClientTransactionBuildError::Write(
            RuntimeWriteTransactionError::Build(BuchiPutTransactionError::BuildBody(
                BuildWriteJsonError::OutputTooSmall
            ))
        ))
    );
    assert_eq!(runtime.data_access().write_queue_depth(), 1);

    let write = runtime
        .next_client_transaction::<96, 384, 128>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("queued write builds")
        .expect("queued write becomes client transaction");
    match write {
        BuchiClientTransaction::Write(transaction) => {
            assert_eq!(transaction.endpoint(), Endpoint::Settings);
            assert_eq!(
                transaction.write_request().target,
                WriteTarget::SettingsProgramEcoEnabled
            );
        }
        BuchiClientTransaction::Poll(_) => panic!("write should be prioritized"),
    }
    assert_eq!(runtime.data_access().write_queue_depth(), 0);

    let poll = runtime
        .next_client_transaction::<96, 384, 128>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("due poll builds")
        .expect("process poll is due after write queue drains");
    match poll {
        BuchiClientTransaction::Poll(poll) => {
            assert_eq!(poll.request, BuchiPollRequest::new(Endpoint::Process));
        }
        BuchiClientTransaction::Write(_) => panic!("no write should remain"),
    }
}

#[test]
fn buchi_client_transaction_applies_write_and_poll_completions() {
    let mut runtime = verified_poll_runtime::<1>(0);
    assert!(
        runtime
            .data_access_mut()
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true)
            )
            .accepted
    );
    let mut write = runtime
        .next_client_transaction::<96, 384, 128>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("queued write builds")
        .expect("queued write becomes client transaction");
    let BuchiClientTransaction::Write(write_transaction) = &mut write else {
        panic!("write expected");
    };
    write_transaction
        .record_write(write_transaction.request_len())
        .expect("write request send completes");
    write_transaction
        .append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n",
        )
        .expect("write response headers accepted");
    write_transaction
        .append_response(br#"{"program":{"eco":{"isEnabled":true}}}"#)
        .expect("write response body reaches probe");
    write_transaction
        .finish_extra_body_probe()
        .expect("write response completes");
    let completion = runtime
        .apply_completed_client_transaction(&write, 0, 0)
        .expect("completed write records");
    match completion {
        BuchiClientTransactionCompletion::Write(completion) => {
            assert_eq!(completion.http_status, 200);
            assert_eq!(completion.opcua_status, opcua_status::GOOD);
        }
        BuchiClientTransactionCompletion::Poll(_) => panic!("write completion expected"),
    }
    assert_eq!(
        runtime.data_access().health().buchi_write_completed_count,
        1
    );

    let mut poll = runtime
        .next_client_transaction::<96, 384, 128>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("due poll builds")
        .expect("poll becomes client transaction");
    let BuchiClientTransaction::Poll(poll_transaction) = &mut poll else {
        panic!("poll expected");
    };
    poll_transaction
        .transaction
        .record_write(poll_transaction.transaction.request_len())
        .expect("poll request send completes");
    poll_transaction
        .transaction
        .append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n",
        )
        .expect("poll response headers accepted");
    poll_transaction
        .transaction
        .append_response(br#"{"heating":{"act":42.125}}"#)
        .expect("poll response body reaches probe");
    poll_transaction
        .transaction
        .finish_extra_body_probe()
        .expect("poll response completes");
    let completion = runtime
        .apply_completed_client_transaction(&poll, 1_000, 0)
        .expect("completed poll records");
    match completion {
        BuchiClientTransactionCompletion::Poll(completion) => {
            assert_eq!(completion.endpoint, Endpoint::Process);
            assert!(completion.result.is_ok());
        }
        BuchiClientTransactionCompletion::Write(_) => panic!("poll completion expected"),
    }
    assert_eq!(
        runtime
            .data_access()
            .read_node(RuntimeNode::ProcessBathTemperature, 1_000)
            .value,
        Some(ScalarValue::FloatMilli(42_125))
    );
}

#[test]
fn buchi_client_transaction_drives_write_transport_steps() {
    let mut runtime = verified_poll_runtime::<1>(0);
    assert!(
        runtime
            .data_access_mut()
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true)
            )
            .accepted
    );
    let mut transaction = runtime
        .next_client_transaction::<96, 384, 192>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("queued write builds")
        .expect("write transaction exists");
    let write_steps = [Ok(usize::MAX)];
    let read_steps = [
        Ok(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n"
                .as_slice(),
        ),
        Ok(br#"{"program":{"eco":{"isEnabled":true}}}"#.as_slice()),
        Ok(b"".as_slice()),
    ];
    let mut transport = ScriptedTransport::new(&write_steps, &read_steps);
    let mut scratch = [0u8; 96];

    assert!(matches!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(_))
    ));
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::Complete))
    );
    assert!(transport
        .written()
        .starts_with(b"PUT /api/v1/settings HTTP/1.1\r\n"));
    let completion = runtime
        .apply_completed_client_transaction(&transaction, 0, 0)
        .expect("completed write records");
    match completion {
        BuchiClientTransactionCompletion::Write(completion) => {
            assert_eq!(completion.http_status, 200);
        }
        BuchiClientTransactionCompletion::Poll(_) => panic!("write completion expected"),
    }
}

#[test]
fn buchi_client_transaction_drives_poll_transport_steps_and_errors_by_kind() {
    let mut runtime = verified_poll_runtime::<1>(0);
    let mut transaction = runtime
        .next_client_transaction::<96, 384, 192>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("due poll builds")
        .expect("poll transaction exists");
    let write_steps = [
        Ok(9),
        Err(BuchiTransportIoError::WouldBlock),
        Ok(usize::MAX),
    ];
    let read_steps = [
        Ok(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n"
                .as_slice(),
        ),
        Ok(br#"{"heating":{"act":42.125}}"#.as_slice()),
        Ok(b"".as_slice()),
    ];
    let mut transport = ScriptedTransport::new(&write_steps, &read_steps);
    let mut scratch = [0u8; 96];

    assert!(matches!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(_))
    ));
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::WouldBlock)
    );
    assert!(matches!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(_))
    ));
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::Complete))
    );
    assert!(transport
        .written()
        .starts_with(b"GET /api/v1/process HTTP/1.1\r\n"));
    let completion = runtime
        .apply_completed_client_transaction(&transaction, 1_000, 0)
        .expect("completed poll records");
    match completion {
        BuchiClientTransactionCompletion::Poll(completion) => {
            assert_eq!(completion.endpoint, Endpoint::Process);
            assert!(completion.result.is_ok());
        }
        BuchiClientTransactionCompletion::Write(_) => panic!("poll completion expected"),
    }

    let mut empty = [];
    assert_eq!(
        transaction.drive_transport_step(&mut transport, &mut empty),
        Ok(BuchiTransportStep::Complete)
    );

    let mut runtime = verified_poll_runtime::<1>(0);
    let mut error_transaction = runtime
        .next_client_transaction::<96, 384, 192>(0, "r300.local", "cm86cm8=", "cndyOnJ3")
        .expect("due poll builds")
        .expect("poll transaction exists");
    let BuchiClientTransaction::Poll(poll) = &mut error_transaction else {
        panic!("poll expected");
    };
    poll.transaction
        .record_write(poll.transaction.request_len())
        .expect("poll request send completes");
    let mut transport = ScriptedTransport::new(&[], &[]);
    assert_eq!(
        error_transaction.drive_transport_step(&mut transport, &mut empty),
        Err(BuchiClientTransportError::Poll(
            BuchiGetTransportError::EmptyReadBuffer
        ))
    );
}

#[test]
fn buchi_client_task_drives_selected_write_to_completion() {
    let mut task = verified_client_task::<1, 96, 384, 192>(0);
    assert!(
        task.runtime_mut()
            .data_access_mut()
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true)
            )
            .accepted
    );
    let write_steps = [Ok(usize::MAX)];
    let read_steps = [
        Ok(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n"
                .as_slice(),
        ),
        Ok(br#"{"program":{"eco":{"isEnabled":true}}}"#.as_slice()),
        Ok(b"".as_slice()),
    ];
    let mut transport = ScriptedTransport::new(&write_steps, &read_steps);
    let mut scratch = [0u8; 96];

    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::Started(
            BuchiClientTransactionKind::Write {
                node_id: 3014,
                target: WriteTarget::SettingsProgramEcoEnabled,
            }
        ))
    );
    assert_eq!(
        task.in_flight_kind(),
        Some(BuchiClientTransactionKind::Write {
            node_id: 3014,
            target: WriteTarget::SettingsProgramEcoEnabled,
        })
    );
    assert!(matches!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Sent(_)))
    ));
    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Received(
            HttpReadProgress::ReadMore
        )))
    );
    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Received(
            HttpReadProgress::ProbeForExtraBytes
        )))
    );
    let completion = task
        .poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        )
        .expect("write task completes");
    match completion {
        BuchiClientTaskStep::Completed(BuchiClientTransactionCompletion::Write(completion)) => {
            assert_eq!(completion.http_status, 200);
            assert_eq!(completion.opcua_status, opcua_status::GOOD);
        }
        other => panic!("write completion expected, got {other:?}"),
    }
    assert_eq!(task.in_flight_kind(), None);
    assert_eq!(task.runtime().data_access().write_queue_depth(), 0);
    assert_eq!(
        task.runtime()
            .data_access()
            .health()
            .buchi_write_completed_count,
        1
    );
}

#[test]
fn buchi_client_task_drives_due_poll_with_would_block_to_completion() {
    let mut task = verified_client_task::<1, 96, 384, 192>(0);
    let write_steps = [
        Ok(9),
        Err(BuchiTransportIoError::WouldBlock),
        Ok(usize::MAX),
    ];
    let read_steps = [
        Ok(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n"
                .as_slice(),
        ),
        Ok(br#"{"heating":{"act":42.125}}"#.as_slice()),
        Ok(b"".as_slice()),
    ];
    let mut transport = ScriptedTransport::new(&write_steps, &read_steps);
    let mut scratch = [0u8; 96];

    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::Started(
            BuchiClientTransactionKind::Poll {
                endpoint: Endpoint::Process,
            }
        ))
    );
    assert_eq!(
        task.in_flight_kind(),
        Some(BuchiClientTransactionKind::Poll {
            endpoint: Endpoint::Process,
        })
    );
    assert!(matches!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Sent(_)))
    ));
    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(
            BuchiTransportStep::WouldBlock
        ))
    );
    assert!(matches!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Sent(_)))
    ));
    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Received(
            HttpReadProgress::ReadMore
        )))
    );
    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::InFlight(BuchiTransportStep::Received(
            HttpReadProgress::ProbeForExtraBytes
        )))
    );
    let completion = task
        .poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        )
        .expect("poll task completes");
    match completion {
        BuchiClientTaskStep::Completed(BuchiClientTransactionCompletion::Poll(completion)) => {
            assert_eq!(completion.endpoint, Endpoint::Process);
            assert!(completion.result.is_ok());
            assert_eq!(completion.next_due_ms, product::PROCESS_POLL_MS);
        }
        other => panic!("poll completion expected, got {other:?}"),
    }
    assert_eq!(task.in_flight_kind(), None);
    assert_eq!(
        task.runtime()
            .data_access()
            .read_node(RuntimeNode::ProcessBathTemperature, 0)
            .value,
        Some(ScalarValue::FloatMilli(42_125))
    );
    assert_eq!(
        task.poll_transport_step(
            0,
            "r300.local",
            "cm86cm8=",
            "cndyOnJ3",
            0,
            &mut transport,
            &mut scratch,
        ),
        Ok(BuchiClientTaskStep::Started(
            BuchiClientTransactionKind::Poll {
                endpoint: Endpoint::Settings,
            }
        ))
    );
}

#[test]
fn buchi_poll_runtime_records_failed_attempts_without_immediate_retry() {
    let mut runtime = verified_poll_runtime::<4>(100);
    let failure_response = http_status(503, br#"{"error":"busy"}"#);
    let completion =
        runtime.apply_poll_http_response(Endpoint::Process, &failure_response, 4096, 100);
    let failure = completion.result.expect_err("503 should fail closed");
    assert_eq!(failure.endpoint, Endpoint::Process);
    assert_eq!(failure.failed_fetches, 1);
    assert_eq!(completion.next_due_ms, 100 + product::PROCESS_POLL_MS);
    assert!(!runtime
        .scheduler()
        .due_endpoints(100 + product::PROCESS_POLL_MS - 1)
        .contains(Endpoint::Process));
    assert!(runtime
        .scheduler()
        .due_endpoints(100 + product::PROCESS_POLL_MS)
        .contains(Endpoint::Process));
    assert_eq!(
        runtime
            .data_access()
            .read_health_node(HealthNode::BuchiFailedFetchCount)
            .value,
        Some(ScalarValue::UInt32(1))
    );
}

#[test]
fn default_namespace_map_covers_source_backed_runtime_and_health_nodes() {
    assert_eq!(
        DEFAULT_NAMESPACE_NODE_COUNT,
        NODE_COUNT - 1 + RUNTIME_HEALTH_NODE_COUNT
    );
    assert_eq!(
        default_namespace_nodes().len(),
        DEFAULT_NAMESPACE_NODE_COUNT
    );
    assert_eq!(lookup_default_namespace_node(4037), None);
    assert_eq!(HealthNode::from_node_id(4037), None);
    for (index, node) in default_namespace_nodes().iter().enumerate() {
        assert_eq!(lookup_default_namespace_node(node.node_id), Some(node));
        for other in default_namespace_nodes().iter().skip(index + 1) {
            assert_ne!(node.node_id, other.node_id);
        }
        match node.target {
            NamespaceTarget::Runtime(runtime_node) => {
                assert_ne!(runtime_node, RuntimeNode::ProcessState);
                assert_eq!(node.value_kind, runtime_node.contract().value_kind);
                assert_eq!(node.access, runtime_node.contract().access());
            }
            NamespaceTarget::Health(health_node) => {
                assert_eq!(node.node_id, health_node.node_id());
                assert_eq!(node.access, Access::ReadOnly);
            }
        }
    }

    for runtime_node in runtime_node_contracts()
        .iter()
        .map(|contract| contract.node)
    {
        if runtime_node == RuntimeNode::ProcessState {
            continue;
        }
        assert!(default_namespace_nodes()
            .iter()
            .any(|node| { node.target == NamespaceTarget::Runtime(runtime_node) }));
    }
    for health in RUNTIME_HEALTH_NODES {
        assert!(default_namespace_nodes()
            .iter()
            .any(|node| { node.target == NamespaceTarget::Health(health) }));
    }

    let heating = lookup_default_namespace_node(2001).expect("source node 2001 exists");
    assert_eq!(heating.browse_name, "Process.Heating.Set");
    assert_eq!(
        heating.target,
        NamespaceTarget::Runtime(RuntimeNode::ProcessHeatingSet)
    );
    assert_eq!(heating.access, Access::WritableNumericBoolean);
    let actual = lookup_default_namespace_node(2002).expect("source node 2002 exists");
    assert_eq!(actual.browse_name, "Process.Heating.ActualTemperatureC");
    assert_eq!(
        actual.target,
        NamespaceTarget::Runtime(RuntimeNode::ProcessBathTemperature)
    );
    assert_eq!(actual.access, Access::ReadOnly);
    let health = lookup_default_namespace_node(4028).expect("source node 4028 exists");
    assert_eq!(health.browse_name, "Health.LastFaultPresent");
    assert_eq!(
        health.target,
        NamespaceTarget::Health(HealthNode::LastFaultPresent)
    );
    let verifier_time =
        lookup_default_namespace_node(4050).expect("verifier time node 4050 exists");
    assert_eq!(verifier_time.browse_name, "Health.BuchiVerifierTimeTrusted");
    assert_eq!(verifier_time.value_kind, ValueKind::Boolean);
    assert_eq!(verifier_time.access, Access::ReadOnly);
    assert_eq!(
        verifier_time.target,
        NamespaceTarget::Health(HealthNode::BuchiVerifierTimeTrusted)
    );
    let attached = lookup_default_namespace_node(1033).expect("attached node 1033 exists");
    assert_eq!(attached.browse_name, "Info.Chiller.Attached");
    assert_eq!(
        attached.target,
        NamespaceTarget::Runtime(RuntimeNode::InfoChillerAttached)
    );
    assert_eq!(attached.access, Access::ReadOnly);
}

#[test]
fn namespace_read_dispatches_runtime_and_health_nodes_by_source_node_id() {
    let mut data_access = verified_data_access::<4>();
    let invalid = data_access.read_namespace_node_id(9999, 0);
    assert_eq!(invalid.target, None);
    assert_eq!(invalid.opcua_status, opcua_status::BAD_INDEX_RANGE_INVALID);
    assert_eq!(invalid.value, None);

    let never = data_access.read_namespace_node_id(2001, 0);
    assert_eq!(never.browse_name, Some("Process.Heating.Set"));
    assert_eq!(never.value_kind, Some(ValueKind::Float));
    assert_eq!(never.access, Some(Access::WritableNumericBoolean));
    assert_eq!(
        never.target,
        Some(NamespaceTarget::Runtime(RuntimeNode::ProcessHeatingSet))
    );
    assert_eq!(never.cache_status, Some(CacheReadStatus::NeverPublished));
    assert_eq!(
        never.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(never.value, None);

    data_access.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            heating_set_milli_celsius: Some(42_125),
            bath_temperature_milli_celsius: Some(41_875),
            process_state: Some(1),
            ..ProcessValues::default()
        }),
        100,
    );
    let heating = data_access.read_namespace_node_id(2001, 100);
    assert_eq!(heating.cache_status, Some(CacheReadStatus::Ok));
    assert_eq!(heating.opcua_status, opcua_status::GOOD);
    assert_eq!(heating.value, Some(ScalarValue::FloatMilli(42_125)));
    let actual = data_access.read_namespace_node_id(2002, 100);
    assert_eq!(
        actual.browse_name,
        Some("Process.Heating.ActualTemperatureC")
    );
    assert_eq!(actual.access, Some(Access::ReadOnly));
    assert_eq!(actual.value, Some(ScalarValue::FloatMilli(41_875)));
    let running = data_access.read_namespace_node_id(2030, 100);
    assert_eq!(running.value_kind, Some(ValueKind::Boolean));
    assert_eq!(running.value, Some(ScalarValue::Boolean(true)));

    assert!(
        data_access
            .enqueue_write_node(
                RuntimeNode::ProcessHeatingSet,
                ScalarValue::FloatMilli(42_125)
            )
            .accepted
    );
    let queue_depth = data_access.read_namespace_node_id(4014, 100);
    assert_eq!(
        queue_depth.target,
        Some(NamespaceTarget::Health(HealthNode::BuchiWriteQueueDepth))
    );
    assert_eq!(queue_depth.cache_status, None);
    assert_eq!(queue_depth.opcua_status, opcua_status::GOOD);
    assert_eq!(queue_depth.value, Some(ScalarValue::UInt32(1)));
}

fn assert_health_value<const WRITE_CAPACITY: usize>(
    data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
    node: HealthNode,
    status: u32,
    value: Option<ScalarValue>,
) {
    let read = data_access.read_health_node(node);
    assert_eq!(read.node, Some(node));
    assert_eq!(read.node_id, node.node_id());
    assert!(read.browse_name.is_some());
    assert!(read.value_kind.is_some());
    assert_eq!(read.opcua_status, status);
    assert_eq!(read.value, value);
}

#[test]
fn health_read_facade_reports_buchi_counters_queue_depth_and_flags() {
    let mut data_access = verified_data_access::<4>();
    assert_health_value(
        &data_access,
        HealthNode::BuchiCompletedFetchCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiFailedFetchCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteQueueDepth,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );

    data_access.set_buchi_status_inputs(true, true, false);
    assert_health_value(
        &data_access,
        HealthNode::BuchiStatusFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(
            buchi_status_flags::CONFIGURED | buchi_status_flags::NETWORK_READY,
        )),
    );

    let process = http_ok(PROCESS_JSON);
    data_access
        .apply_http_response(Endpoint::Process, &process, 4096, 100)
        .expect("successful process fetch updates health counters");
    assert_health_value(
        &data_access,
        HealthNode::BuchiCompletedFetchCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiStatusFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(
            buchi_status_flags::CONFIGURED
                | buchi_status_flags::NETWORK_READY
                | buchi_status_flags::LAST_FETCH_OK,
        )),
    );

    let queued = data_access.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_125),
    );
    assert!(queued.accepted);
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteQueueDepth,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteAcceptedCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastTargetNodeId,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(2001)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastHttpStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastOpcUaStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(
            opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY,
        )),
    );

    data_access.record_buchi_write_result(2001, 200, opcua_status::GOOD);
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteCompletedCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastHttpStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(200)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastOpcUaStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(opcua_status::GOOD)),
    );

    data_access.record_buchi_write_result(3018, 503, opcua_status::BAD_RESOURCE_UNAVAILABLE);
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteFailedCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastTargetNodeId,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(3018)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastHttpStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(503)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastOpcUaStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(opcua_status::BAD_RESOURCE_UNAVAILABLE)),
    );

    let failed = http_status(503, br#"{"error":"down"}"#);
    data_access
        .apply_http_response(Endpoint::Process, &failed, 4096, 200)
        .expect_err("failed fetch updates health counters");
    assert_health_value(
        &data_access,
        HealthNode::BuchiFailedFetchCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    data_access.set_buchi_status_inputs(true, true, true);
    assert_health_value(
        &data_access,
        HealthNode::BuchiStatusFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(
            buchi_status_flags::CONFIGURED
                | buchi_status_flags::NETWORK_READY
                | buchi_status_flags::BODY_TRUNCATED,
        )),
    );

    let invalid = data_access.read_health_node_id(4999);
    assert_eq!(invalid.node, None);
    assert_eq!(invalid.node_id, 4999);
    assert_eq!(invalid.browse_name, None);
    assert_eq!(invalid.value_kind, None);
    assert_eq!(invalid.opcua_status, opcua_status::BAD_INDEX_RANGE_INVALID);
    assert_eq!(invalid.value, None);
}

#[test]
fn health_read_facade_reports_runtime_diagnostics_for_full_health_set() {
    let mut data_access = verified_data_access::<4>();

    data_access.set_memory_diagnostics(11, 22, 33, 44);
    data_access.set_opcua_transport_diagnostics(55, 66);
    data_access.set_loop_timing_diagnostics(77, 88, 99);
    data_access.set_buchi_rejected_request_count(111);

    for (node, value) in [
        (HealthNode::MbedtlsCurrentBytes, 11),
        (HealthNode::MbedtlsPeakBytes, 22),
        (HealthNode::HeapAllocFailCount, 33),
        (HealthNode::MbedtlsFailedAllocCount, 44),
        (HealthNode::OpcUaTransportDrops, 55),
        (HealthNode::OpcUaCloseQueueFullCount, 66),
        (HealthNode::LoopMaxGapMs, 77),
        (HealthNode::HeartbeatMaxGapMs, 88),
        (HealthNode::LateHeartbeatCount, 99),
        (HealthNode::BuchiRejectedRequestCount, 111),
    ] {
        assert_health_value(
            &data_access,
            node,
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(value)),
        );
    }
}

#[test]
fn loop_timing_health_is_bad_no_data_until_first_complete_measurement() {
    let mut data_access = verified_data_access::<4>();

    for node in [
        HealthNode::LoopMaxGapMs,
        HealthNode::HeartbeatMaxGapMs,
        HealthNode::LateHeartbeatCount,
    ] {
        assert_health_value(&data_access, node, opcua_status::BAD_NO_DATA, None);
    }

    data_access.set_loop_timing_diagnostics(100, 100, 0);
    for (node, value) in [
        (HealthNode::LoopMaxGapMs, 100),
        (HealthNode::HeartbeatMaxGapMs, 100),
        (HealthNode::LateHeartbeatCount, 0),
    ] {
        assert_health_value(
            &data_access,
            node,
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(value)),
        );
    }
}

#[test]
fn health_compatibility_memory_nodes_default_to_zero_in_allocator_free_runtime() {
    let data_access = RuntimeDataAccess::<4>::new();
    for (node, value) in [
        (HealthNode::MbedtlsCurrentBytes, 0),
        (HealthNode::MbedtlsPeakBytes, 0),
        (HealthNode::HeapAllocFailCount, 0),
        (HealthNode::MbedtlsFailedAllocCount, 0),
    ] {
        assert_health_value(
            &data_access,
            node,
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(value)),
        );
    }
}

#[test]
fn loop_timing_monitor_first_sample_only_establishes_baselines() {
    let mut monitor = LoopTimingMonitor::new(100, 10);
    assert_eq!(monitor.observe(1_000, 1_001), None);
}

#[test]
fn loop_timing_monitor_records_normal_intervals() {
    let mut monitor = LoopTimingMonitor::new(100, 10);
    assert_eq!(monitor.observe(1_000, 1_001), None);
    assert_eq!(
        monitor.observe(1_100, 1_101),
        Some(LoopTimingSnapshot {
            loop_max_gap_ms: 100,
            heartbeat_max_gap_ms: 100,
            late_heartbeat_count: 0,
        })
    );
}

#[test]
fn loop_timing_monitor_counts_intervals_above_110_ms() {
    let mut monitor = LoopTimingMonitor::new(100, 10);
    assert_eq!(monitor.observe(1_000, 1_001), None);
    assert_eq!(
        monitor.observe(1_111, 1_112),
        Some(LoopTimingSnapshot {
            loop_max_gap_ms: 111,
            heartbeat_max_gap_ms: 111,
            late_heartbeat_count: 1,
        })
    );
}

#[test]
fn loop_timing_monitor_retains_lifetime_maxima() {
    let mut monitor = LoopTimingMonitor::new(100, 10);
    assert_eq!(monitor.observe(1_000, 1_001), None);
    assert!(monitor.observe(1_150, 1_161).is_some());
    assert_eq!(
        monitor.observe(1_200, 1_201),
        Some(LoopTimingSnapshot {
            loop_max_gap_ms: 150,
            heartbeat_max_gap_ms: 160,
            late_heartbeat_count: 1,
        })
    );
}

#[test]
fn loop_timing_monitor_saturates_published_durations() {
    let mut monitor = LoopTimingMonitor::new(100, 10);
    assert_eq!(monitor.observe(0, 0), None);
    assert_eq!(
        monitor.observe(u64::from(u32::MAX) + 1, u64::from(u32::MAX) + 2),
        Some(LoopTimingSnapshot {
            loop_max_gap_ms: u32::MAX,
            heartbeat_max_gap_ms: u32::MAX,
            late_heartbeat_count: 1,
        })
    );
}

#[test]
fn loop_timing_monitor_uses_multi_epoch_u64_time() {
    let epoch = u64::from(u32::MAX) + 10_000;
    let mut monitor = LoopTimingMonitor::new(100, 10);
    assert_eq!(monitor.observe(epoch, epoch + 1), None);
    assert_eq!(
        monitor.observe(epoch + 100, epoch + 101),
        Some(LoopTimingSnapshot {
            loop_max_gap_ms: 100,
            heartbeat_max_gap_ms: 100,
            late_heartbeat_count: 0,
        })
    );
}

#[test]
fn buchi_trust_health_reports_all_states_flags_errors_and_counters() {
    let mut data_access = RuntimeDataAccess::<4>::new();
    for (index, state) in [
        TrustState::Missing,
        TrustState::Provisioned,
        TrustState::Verified,
        TrustState::VerifyRejected,
        TrustState::Revoked,
    ]
    .into_iter()
    .enumerate()
    {
        data_access.set_buchi_trust_health(BuchiTrustHealthSnapshot {
            state,
            anchor_present: index >= 1,
            rtc_usable: index >= 2,
            last_verify_error: index as u32 + 10,
            verify_attempt_count: index as u32 + 20,
            verified_session_count: index as u32 + 30,
            revocation_count: index as u32 + 40,
        });
        assert_health_value(
            &data_access,
            HealthNode::BuchiTrustState,
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(state as u32)),
        );
        assert_health_value(
            &data_access,
            HealthNode::BuchiTrustAnchorPresent,
            opcua_status::GOOD,
            Some(ScalarValue::Boolean(index >= 1)),
        );
        assert_health_value(
            &data_access,
            HealthNode::BuchiTrustRtcUsable,
            opcua_status::GOOD,
            Some(ScalarValue::Boolean(index >= 2)),
        );
        for (node, value) in [
            (HealthNode::BuchiTrustLastVerifyError, index as u32 + 10),
            (HealthNode::BuchiTrustVerifyAttemptCount, index as u32 + 20),
            (
                HealthNode::BuchiTrustVerifiedSessionCount,
                index as u32 + 30,
            ),
            (HealthNode::BuchiTrustRevocationCount, index as u32 + 40),
        ] {
            assert_health_value(
                &data_access,
                node,
                opcua_status::GOOD,
                Some(ScalarValue::UInt32(value)),
            );
        }
    }
}

#[test]
fn buchi_verifier_time_health_tracks_only_the_current_verified_session() {
    let mut data_access = RuntimeDataAccess::<4>::new();
    let verifier_time_value = |data_access: &RuntimeDataAccess<4>| {
        data_access
            .read_health_node(HealthNode::BuchiVerifierTimeTrusted)
            .value
    };
    let trust_snapshot = |state| BuchiTrustHealthSnapshot {
        state,
        anchor_present: true,
        rtc_usable: true,
        last_verify_error: 0,
        verify_attempt_count: 1,
        verified_session_count: 1,
        revocation_count: 0,
    };

    let initial = data_access.read_health_node(HealthNode::BuchiVerifierTimeTrusted);
    assert_eq!(initial.opcua_status, opcua_status::GOOD);
    assert_eq!(initial.value_kind, Some(ValueKind::Boolean));
    assert_eq!(initial.value, Some(ScalarValue::Boolean(false)));
    data_access.set_verified_trust_session(false);
    assert_eq!(
        verifier_time_value(&data_access),
        Some(ScalarValue::Boolean(false))
    );
    data_access.set_verified_trust_session(true);
    assert_eq!(
        verifier_time_value(&data_access),
        Some(ScalarValue::Boolean(true))
    );

    // A periodic probe refresh may retain, but must never synthesize, the
    // exact property recorded when the current session was established.
    data_access.set_buchi_trust_health(trust_snapshot(TrustState::Verified));
    assert_eq!(
        verifier_time_value(&data_access),
        Some(ScalarValue::Boolean(true))
    );
    data_access.set_trust_state(TrustState::Verified);
    assert_eq!(
        verifier_time_value(&data_access),
        Some(ScalarValue::Boolean(false))
    );

    for state in [
        TrustState::Missing,
        TrustState::Provisioned,
        TrustState::VerifyRejected,
        TrustState::Revoked,
    ] {
        data_access.set_verified_trust_session(true);
        data_access.set_trust_state(state);
        assert_eq!(
            verifier_time_value(&data_access),
            Some(ScalarValue::Boolean(false))
        );
    }

    data_access.set_verified_trust_session(true);
    data_access.set_buchi_trust_health(trust_snapshot(TrustState::Provisioned));
    assert_eq!(
        verifier_time_value(&data_access),
        Some(ScalarValue::Boolean(false))
    );

    data_access.set_verified_trust_session(true);
    data_access.revoke_upstream_trust();
    assert_eq!(
        verifier_time_value(&data_access),
        Some(ScalarValue::Boolean(false))
    );
}

#[test]
fn default_single_core_health_fields_report_bad_no_data() {
    let mut data_access = verified_data_access::<4>();

    for node in [
        HealthNode::UptimeSeconds,
        HealthNode::IwdgLastKickAgeMs,
        HealthNode::WatchdogStaleMask,
        HealthNode::TaskCheckinRegisteredMask,
        HealthNode::TaskCheckinFreshMask,
        HealthNode::TaskCheckinDeadlineMs,
        HealthNode::TaskCheckinMainHeartbeatAgeMs,
        HealthNode::TaskCheckinMdnsResponderAgeMs,
        HealthNode::TaskCheckinNetStatusAgeMs,
        HealthNode::TaskCheckinUsbConsoleAgeMs,
        HealthNode::TaskCheckinBuchiTlsClientAgeMs,
        HealthNode::TaskCheckinOpcUaServerAgeMs,
    ] {
        assert_health_value(&data_access, node, opcua_status::BAD_NO_DATA, None);
    }

    data_access.set_reset_diagnostics(0xA5A5_0001, 7);
    assert_health_value(
        &data_access,
        HealthNode::ResetFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0xA5A5_0001)),
    );
    assert_health_value(
        &data_access,
        HealthNode::WatchdogBiteCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(7)),
    );
}

#[test]
fn boot_reset_flags_do_not_synthesize_a_watchdog_bite_and_stay_distinct_from_retained_flags() {
    let mut data_access = verified_data_access::<4>();
    data_access.set_last_fault(LastFaultRecord {
        valid: true,
        reason_word: LastFaultReason::IwdgReset.as_word(),
        known_reason: Some(LastFaultReason::IwdgReset),
        sequence: 9,
        format: Some(LastFaultFormat::SecondsV2),
        uptime_word: 1_234,
        detail: 0x55AA,
        reset_flags: 0x2000_0000,
    });
    data_access.set_reset_flags(0x0400_0000);

    assert_health_value(
        &data_access,
        HealthNode::LastFaultResetFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0x2000_0000)),
    );
    assert_health_value(
        &data_access,
        HealthNode::ResetFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0x0400_0000)),
    );
    assert_health_value(
        &data_access,
        HealthNode::WatchdogBiteCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );
}

#[test]
fn populated_single_core_health_snapshot_reports_masks_deadline_and_task_ages() {
    let mut data_access = verified_data_access::<4>();
    let mut ages = [None; SINGLE_CORE_TASK_HEALTH_SLOT_COUNT];
    ages[0] = Some(10);
    ages[1] = Some(2_001);
    ages[2] = Some(40);
    ages[3] = Some(50);
    ages[4] = Some(60);
    ages[5] = Some(70);
    data_access.set_single_core_health(SingleCoreHealthSnapshot::new(
        12_345,
        Some(15),
        1 << 2,
        0b10_1111,
        0b01_1011,
        2_000,
        ages,
    ));

    for (node, value) in [
        (HealthNode::UptimeSeconds, 12_345),
        (HealthNode::IwdgLastKickAgeMs, 15),
        (HealthNode::WatchdogStaleMask, 1 << 2),
        (HealthNode::TaskCheckinRegisteredMask, 0b10_1111),
        (HealthNode::TaskCheckinFreshMask, 0b01_1011),
        (HealthNode::TaskCheckinDeadlineMs, 2_000),
        (HealthNode::TaskCheckinMainHeartbeatAgeMs, 10),
        (HealthNode::TaskCheckinMdnsResponderAgeMs, 2_001),
        (HealthNode::TaskCheckinNetStatusAgeMs, 40),
        (HealthNode::TaskCheckinUsbConsoleAgeMs, 50),
        (HealthNode::TaskCheckinOpcUaServerAgeMs, 70),
    ] {
        assert_health_value(
            &data_access,
            node,
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(value)),
        );
    }
    assert_health_value(
        &data_access,
        HealthNode::TaskCheckinBuchiTlsClientAgeMs,
        opcua_status::BAD_NO_DATA,
        None,
    );
}

#[test]
fn iwdg_kick_age_and_unregistered_task_age_report_bad_no_data() {
    let mut data_access = verified_data_access::<4>();
    let mut ages = [None; SINGLE_CORE_TASK_HEALTH_SLOT_COUNT];
    ages[0] = Some(10);
    ages[4] = Some(60);
    data_access.set_single_core_health(SingleCoreHealthSnapshot::new(
        1_000, None, 0, 0b1, 0b1, 2_000, ages,
    ));

    assert_health_value(
        &data_access,
        HealthNode::IwdgLastKickAgeMs,
        opcua_status::BAD_NO_DATA,
        None,
    );
    assert_health_value(
        &data_access,
        HealthNode::TaskCheckinMainHeartbeatAgeMs,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(10)),
    );
    assert_health_value(
        &data_access,
        HealthNode::TaskCheckinBuchiTlsClientAgeMs,
        opcua_status::BAD_NO_DATA,
        None,
    );
}

#[test]
fn health_read_facade_keeps_last_fault_semantics() {
    let mut data_access = verified_data_access::<4>();
    assert_health_value(
        &data_access,
        HealthNode::LastFaultPresent,
        opcua_status::GOOD,
        Some(ScalarValue::Boolean(false)),
    );
    // No recorded fault serves the Good zero shape (DeltaV LDT health);
    // LastFaultPresent=false is the fault-recorded discriminator.
    assert_health_value(
        &data_access,
        HealthNode::LastFaultReason,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );

    data_access.set_last_fault(LastFaultRecord {
        valid: true,
        reason_word: LastFaultReason::HardFault.as_word(),
        known_reason: Some(LastFaultReason::HardFault),
        sequence: 42,
        format: Some(LastFaultFormat::SecondsV2),
        uptime_word: 12_345,
        detail: 0x0804_1234,
        reset_flags: 0xDEAD_BEEF,
    });
    assert_health_value(
        &data_access,
        HealthNode::LastFaultPresent,
        opcua_status::GOOD,
        Some(ScalarValue::Boolean(true)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultReason,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(LastFaultReason::HardFault.as_word())),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultSequence,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(42)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultUptimeSeconds,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(12_345)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultDetail,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0x0804_1234)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultResetFlags,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0xDEAD_BEEF)),
    );

    data_access.clear_last_fault();
    assert_health_value(
        &data_access,
        HealthNode::LastFaultPresent,
        opcua_status::GOOD,
        Some(ScalarValue::Boolean(false)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultReason,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );
    data_access.set_last_fault(LastFaultRecord::invalid());
    assert_health_value(
        &data_access,
        HealthNode::LastFaultPresent,
        opcua_status::GOOD,
        Some(ScalarValue::Boolean(false)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultSequence,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0)),
    );
}

#[test]
fn legacy_last_fault_hides_only_unprovable_seconds() {
    let mut data_access = verified_data_access::<4>();
    data_access.set_last_fault(LastFaultRecord {
        valid: true,
        reason_word: LastFaultReason::Assert.as_word(),
        known_reason: Some(LastFaultReason::Assert),
        sequence: 43,
        format: Some(LastFaultFormat::LegacyMillisecondsV1),
        uptime_word: 4_294_000,
        detail: 0x1234,
        reset_flags: 0x1000_0000,
    });

    assert_health_value(
        &data_access,
        HealthNode::LastFaultUptimeSeconds,
        opcua_status::BAD_NO_DATA,
        None,
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultReason,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(LastFaultReason::Assert.as_word())),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultSequence,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(43)),
    );
    assert_health_value(
        &data_access,
        HealthNode::LastFaultDetail,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(0x1234)),
    );
}

#[test]
fn data_access_read_facade_exposes_cache_status_and_node_metadata() {
    let mut data_access = verified_data_access::<2>();

    let never = data_access.read_node(RuntimeNode::ProcessHeatingSet, 0);
    assert_eq!(never.node, Some(RuntimeNode::ProcessHeatingSet));
    assert_eq!(never.browse_name, Some("Process.Heating.Set"));
    assert_eq!(never.value_kind, Some(ValueKind::Float));
    assert_eq!(never.access, Some(Access::WritableNumericBoolean));
    assert_eq!(never.cache_status, CacheReadStatus::NeverPublished);
    assert_eq!(
        never.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(never.value, None);

    let summary = data_access.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            heating_set_milli_celsius: Some(42_125),
            ..ProcessValues::default()
        }),
        100,
    );
    assert_eq!(summary.published_values, 1);

    let fresh = data_access.read_node(RuntimeNode::ProcessHeatingSet, 100);
    assert_eq!(fresh.cache_status, CacheReadStatus::Ok);
    assert_eq!(fresh.opcua_status, opcua_status::GOOD);
    assert_eq!(fresh.value, Some(ScalarValue::FloatMilli(42_125)));

    let stale = data_access.read_node(
        RuntimeNode::ProcessHeatingSet,
        100 + u64::from(Endpoint::Process.freshness_ms()) + 1,
    );
    assert_eq!(stale.cache_status, CacheReadStatus::Stale);
    assert_eq!(
        stale.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(stale.value, None);

    let invalid = data_access.read_index(NODE_COUNT, 100);
    assert_eq!(invalid.node, None);
    assert_eq!(invalid.browse_name, None);
    assert_eq!(invalid.value_kind, None);
    assert_eq!(invalid.access, None);
    assert_eq!(invalid.cache_status, CacheReadStatus::InvalidIndex);
    assert_eq!(invalid.opcua_status, opcua_status::BAD_INDEX_RANGE_INVALID);
    assert_eq!(invalid.value, None);
}

#[test]
fn trust_revocation_invalidates_good_cache_and_pending_writes_immediately() {
    let mut data_access = verified_data_access::<2>();
    data_access.set_write_enabled(true);
    data_access.set_buchi_status_inputs(true, true, false);
    data_access.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            heating_set_milli_celsius: Some(42_125),
            ..ProcessValues::default()
        }),
        100,
    );
    assert_eq!(
        data_access
            .read_node(RuntimeNode::ProcessHeatingSet, 100)
            .opcua_status,
        opcua_status::GOOD
    );
    assert!(
        data_access
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true),
            )
            .accepted
    );

    data_access.revoke_upstream_trust();

    let read = data_access.read_node(RuntimeNode::ProcessHeatingSet, 100);
    assert_eq!(read.cache_status, CacheReadStatus::NeverPublished);
    assert_eq!(
        read.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(read.value, None);
    assert_eq!(data_access.write_queue_depth(), 0);
    assert!(!data_access.write_enabled());
    assert!(!data_access.health().buchi_configured);
    assert!(!data_access.health().buchi_network_ready);
    assert_eq!(data_access.trust_state(), TrustState::Revoked);
    assert!(!data_access.trust_verified());
    assert!(!data_access.writes_allowed());
}

#[test]
fn dequeued_write_is_not_send_authorized_after_trust_revoke() {
    // BH-8 host model: transport pops a write under Verified trust, then
    // USB revoke races before the first TLS byte. Send authorization must
    // fail so the caller records Bad and does not transmit the PUT.
    let mut data_access = verified_data_access::<2>();
    data_access.set_write_enabled(true);
    assert!(
        data_access
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true),
            )
            .accepted
    );

    let mut body = [0u8; product::BUCHI_WRITE_JSON_BYTES];
    let dispatch = data_access
        .pop_next_write_json(&mut body)
        .expect("dequeue under verified trust");
    assert_eq!(data_access.write_queue_depth(), 0);
    assert!(data_access.write_send_authorized());

    data_access.revoke_upstream_trust();

    assert!(!data_access.write_send_authorized());
    assert!(!data_access.trust_verified());
    assert!(!data_access.writes_allowed());
    assert_eq!(data_access.write_queue_depth(), 0);

    // Completing without send records a failed write (no Good publish).
    // Firmware/host use BadUserAccessDenied for deliberate trust-revoked
    // refusals so telemetry is not confused with TLS I/O failure.
    data_access.record_buchi_write_result(
        dispatch.request.node_id,
        0,
        opcua_status::BAD_USER_ACCESS_DENIED,
    );
    assert_eq!(data_access.health().buchi_write_failed_count, 1);
    assert_eq!(data_access.health().buchi_write_completed_count, 0);
    assert_eq!(
        data_access.health().buchi_write_last_opcua_status,
        opcua_status::BAD_USER_ACCESS_DENIED
    );
}

#[test]
fn explicit_trust_state_gates_good_progress_and_async_write_acceptance() {
    let mut data_access = RuntimeDataAccess::<2>::new();
    data_access.set_write_enabled(true);
    assert_eq!(data_access.trust_state(), TrustState::Missing);
    assert!(!data_access.writes_allowed());

    let response = http_ok(PROCESS_JSON);
    let failure = data_access
        .apply_http_response(Endpoint::Process, &response, 4096, 100)
        .expect_err("unverified HTTP data must not be applied");
    assert_eq!(failure.error, EndpointPollError::TrustNotVerified);
    assert_eq!(failure.completed_fetches, 0);
    assert_eq!(failure.failed_fetches, 0);

    let report = data_access.apply_endpoint_values_report(
        EndpointValues::Process(ProcessValues {
            heating_set_milli_celsius: Some(42_125),
            ..ProcessValues::default()
        }),
        100,
    );
    assert_eq!(report.completed_fetches, 0);
    assert_eq!(report.summary.published_values, 0);
    let read = data_access.read_node(RuntimeNode::ProcessHeatingSet, 100);
    assert_ne!(read.opcua_status, opcua_status::GOOD);
    assert_eq!(read.value, None);

    let rejected = data_access.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_125),
    );
    assert_eq!(rejected.opcua_status, opcua_status::BAD_NOT_WRITABLE);
    assert!(!rejected.accepted);
    assert_eq!(data_access.write_queue_depth(), 0);
    assert_eq!(data_access.health().buchi_write_accepted_count, 0);

    data_access.set_trust_state(TrustState::Verified);
    assert!(data_access.writes_allowed());
    let report = data_access.apply_endpoint_values_report(
        EndpointValues::Process(ProcessValues {
            heating_set_milli_celsius: Some(42_125),
            ..ProcessValues::default()
        }),
        200,
    );
    assert_eq!(report.completed_fetches, 1);
    assert_eq!(
        data_access
            .read_node(RuntimeNode::ProcessHeatingSet, 200)
            .opcua_status,
        opcua_status::GOOD
    );
    assert!(
        data_access
            .enqueue_write_node(
                RuntimeNode::ProcessHeatingSet,
                ScalarValue::FloatMilli(42_125),
            )
            .accepted
    );

    data_access.set_trust_state(TrustState::Provisioned);
    assert_eq!(data_access.write_queue_depth(), 0);
    let read = data_access.read_node(RuntimeNode::ProcessHeatingSet, 200);
    assert_ne!(read.opcua_status, opcua_status::GOOD);
    assert_eq!(read.value, None);
    let rejected = data_access.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_125),
    );
    assert_eq!(rejected.opcua_status, opcua_status::BAD_NOT_WRITABLE);
    assert!(!rejected.accepted);
    assert_eq!(data_access.health().buchi_write_accepted_count, 1);
}

#[test]
fn data_access_write_facade_queues_valid_numeric_boolean_requests() {
    let mut data_access = verified_data_access::<2>();

    let heating = data_access.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_125),
    );
    assert_eq!(heating.node_id, Some(2001));
    assert_eq!(heating.target, WriteTarget::ProcessHeatingSet);
    assert_eq!(heating.validation, WriteValidationStatus::Ok);
    assert_eq!(
        heating.opcua_status,
        opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY
    );
    assert!(heating.accepted);
    assert!(!heating.coalesced);
    assert_eq!(heating.depth, 1);
    assert_eq!(heating.sequence, Some(1));

    let running = data_access.enqueue_write_node_id(2003, ScalarValue::Boolean(true));
    assert_eq!(running.target, WriteTarget::ProcessHeatingRunning);
    assert_eq!(running.validation, WriteValidationStatus::Ok);
    assert!(running.accepted);
    assert_eq!(running.depth, 2);
    assert_eq!(running.sequence, Some(2));
    assert_eq!(data_access.write_queue_depth(), 2);
    assert_eq!(data_access.write_queue_capacity(), 2);

    let first = data_access.pop_write_request().expect("first queued write");
    assert_eq!(first.target, WriteTarget::ProcessHeatingSet);
    assert_eq!(first.raw_value, 42_125);
    assert_eq!(first.node_id, 2001);
    assert_eq!(first.sequence, 1);
    let second = data_access
        .pop_write_request()
        .expect("second queued write");
    assert_eq!(second.target, WriteTarget::ProcessHeatingRunning);
    assert_eq!(second.raw_value, 1);
    assert_eq!(second.node_id, 2003);
    assert_eq!(second.sequence, 2);
    assert_eq!(data_access.pop_write_request(), None);
}

#[test]
fn data_access_write_facade_rejects_not_writable_type_and_range_failures() {
    let mut data_access = verified_data_access::<2>();

    let not_writable = data_access.enqueue_write_node(
        RuntimeNode::ProcessPressure,
        ScalarValue::FloatMilli(125_000),
    );
    assert_eq!(not_writable.node_id, None);
    assert_eq!(not_writable.target, WriteTarget::None);
    assert_eq!(
        not_writable.validation,
        WriteValidationStatus::UnknownTarget
    );
    assert_eq!(not_writable.opcua_status, opcua_status::BAD_NOT_WRITABLE);
    assert!(!not_writable.accepted);

    let type_mismatch = data_access.enqueue_write_node(
        RuntimeNode::SettingsDisplayBrightness,
        ScalarValue::Boolean(true),
    );
    assert_eq!(type_mismatch.node_id, Some(3018));
    assert_eq!(type_mismatch.target, WriteTarget::SettingsDisplayBrightness);
    assert_eq!(
        type_mismatch.validation,
        WriteValidationStatus::TypeMismatch
    );
    assert_eq!(type_mismatch.opcua_status, opcua_status::BAD_TYPE_MISMATCH);
    assert!(!type_mismatch.accepted);

    let out_of_range = data_access.enqueue_write_node(
        RuntimeNode::SettingsDisplayUtcOffset,
        ScalarValue::Int32(-315),
    );
    assert_eq!(out_of_range.node_id, Some(3019));
    assert_eq!(out_of_range.target, WriteTarget::SettingsDisplayUtcOffset);
    assert_eq!(out_of_range.validation, WriteValidationStatus::OutOfRange);
    assert_eq!(out_of_range.opcua_status, opcua_status::BAD_OUT_OF_RANGE);
    assert!(!out_of_range.accepted);

    let unsupported_float_resolution = data_access.enqueue_write_node(
        RuntimeNode::ProcessVacuumSet,
        ScalarValue::FloatMilli(125_500),
    );
    assert_eq!(unsupported_float_resolution.node_id, Some(2007));
    assert_eq!(
        unsupported_float_resolution.target,
        WriteTarget::ProcessVacuumSet
    );
    assert_eq!(
        unsupported_float_resolution.validation,
        WriteValidationStatus::OutOfRange
    );
    assert_eq!(
        unsupported_float_resolution.opcua_status,
        opcua_status::BAD_OUT_OF_RANGE
    );
    assert!(!unsupported_float_resolution.accepted);
    assert_eq!(data_access.write_queue_depth(), 0);
}

#[test]
fn data_access_write_facade_preserves_bounded_queue_and_coalesce_policy() {
    let mut data_access = verified_data_access::<1>();

    let first = data_access.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(1_000),
    );
    assert!(first.accepted);
    assert!(!first.coalesced);
    assert_eq!(first.sequence, Some(1));
    assert_eq!(first.depth, 1);

    let replacement = data_access.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(2_000),
    );
    assert!(replacement.accepted);
    assert!(replacement.coalesced);
    assert_eq!(replacement.sequence, Some(2));
    assert_eq!(replacement.depth, 1);

    let full = data_access.enqueue_write_node(
        RuntimeNode::ProcessRotationRunning,
        ScalarValue::Boolean(true),
    );
    assert_eq!(full.target, WriteTarget::ProcessRotationRunning);
    assert_eq!(full.validation, WriteValidationStatus::Ok);
    assert_eq!(full.opcua_status, opcua_status::BAD_RESOURCE_UNAVAILABLE);
    assert!(!full.accepted);
    assert_eq!(full.depth, 1);
    assert_eq!(full.sequence, None);
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteAcceptedCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(2)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteQueueFullCount,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(1)),
    );
    assert_health_value(
        &data_access,
        HealthNode::BuchiWriteLastOpcUaStatus,
        opcua_status::GOOD,
        Some(ScalarValue::UInt32(opcua_status::BAD_RESOURCE_UNAVAILABLE)),
    );

    let queued = data_access
        .pop_write_request()
        .expect("coalesced write remains");
    assert_eq!(queued.target, WriteTarget::ProcessHeatingSet);
    assert_eq!(queued.raw_value, 2_000);
    assert_eq!(queued.sequence, 2);
    assert_eq!(data_access.pop_write_request(), None);
}

#[test]
fn datachange_subscription_accepts_product_cap_and_rejects_over_cap() {
    let mut subscription = DefaultDataChangeSubscription::new();
    assert_eq!(subscription.capacity(), product::MAX_MONITORED_ITEMS);
    assert_eq!(
        subscription.sampling_interval_ms(),
        product::DATA_CHANGE_INTERVAL_MS
    );

    for offset in 0..product::MAX_MONITORED_ITEMS {
        let result =
            subscription.add_runtime_node(RuntimeNode::ProcessHeatingSet, offset as u32 + 1);
        assert_eq!(result.status, MonitoredItemAddStatus::Ok);
        assert_eq!(result.opcua_status, opcua_status::GOOD);
        assert_eq!(result.depth, offset + 1);
        assert_eq!(result.slot, Some(offset));
    }
    assert_eq!(subscription.len(), product::MAX_MONITORED_ITEMS);

    let over_cap = subscription.add_runtime_node(RuntimeNode::ProcessHeatingSet, 9_999);
    assert_eq!(over_cap.status, MonitoredItemAddStatus::CapacityReached);
    assert_eq!(
        over_cap.opcua_status,
        opcua_status::BAD_TOO_MANY_MONITORED_ITEMS
    );
    assert_eq!(over_cap.slot, None);
    assert_eq!(over_cap.depth, product::MAX_MONITORED_ITEMS);
}

#[test]
fn datachange_subscription_rejects_invalid_node_and_samples_cache_changes() {
    let mut data_access = verified_data_access::<1>();
    let mut subscription = DataChangeSubscription::<2>::new();

    let invalid = subscription.add_node_index(NODE_COUNT, 1);
    assert_eq!(invalid.status, MonitoredItemAddStatus::InvalidNodeIndex);
    assert_eq!(invalid.opcua_status, opcua_status::BAD_INDEX_RANGE_INVALID);
    assert_eq!(invalid.depth, 0);
    assert_eq!(subscription.len(), 0);

    let add = subscription.add_runtime_node(RuntimeNode::ProcessHeatingSet, 42);
    assert_eq!(add.status, MonitoredItemAddStatus::Ok);
    assert_eq!(add.slot, Some(0));
    assert_eq!(subscription.len(), 1);

    let first = subscription
        .sample_slot(0, &data_access, 100)
        .expect("first monitored sample");
    assert_eq!(first.client_handle, 42);
    assert_eq!(first.node_id, 2001);
    assert_eq!(
        first.target,
        Some(NamespaceTarget::Runtime(RuntimeNode::ProcessHeatingSet))
    );
    assert_eq!(first.node, Some(RuntimeNode::ProcessHeatingSet));
    assert_eq!(first.cache_status, Some(CacheReadStatus::NeverPublished));
    assert_eq!(
        first.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(first.value, None);
    assert!(first.changed);

    data_access.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            heating_set_milli_celsius: Some(42_125),
            ..ProcessValues::default()
        }),
        200,
    );
    assert_eq!(
        subscription.sample_slot(0, &data_access, 200),
        None,
        "sampling interval gates back-to-back Publish requests"
    );
    let fresh = subscription
        .sample_slot(0, &data_access, 1_100)
        .expect("fresh monitored sample");
    assert_eq!(fresh.cache_status, Some(CacheReadStatus::Ok));
    assert_eq!(fresh.opcua_status, opcua_status::GOOD);
    assert_eq!(fresh.value, Some(ScalarValue::FloatMilli(42_125)));
    assert!(fresh.changed);

    assert_eq!(
        subscription.sample_slot(0, &data_access, 1_101),
        None,
        "sampling interval suppresses unchanged sub-interval polls"
    );
    let unchanged = subscription
        .sample_slot(0, &data_access, 2_100)
        .expect("unchanged monitored sample");
    assert_eq!(unchanged.cache_status, Some(CacheReadStatus::Ok));
    assert_eq!(unchanged.value, Some(ScalarValue::FloatMilli(42_125)));
    assert!(!unchanged.changed);

    let stale = subscription
        .sample_slot(
            0,
            &data_access,
            200 + u64::from(Endpoint::Process.freshness_ms())
                + u64::from(product::DATA_CHANGE_INTERVAL_MS)
                + 1,
        )
        .expect("stale monitored sample");
    assert_eq!(stale.cache_status, Some(CacheReadStatus::Stale));
    assert_eq!(
        stale.opcua_status,
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(stale.value, None);
    assert!(stale.changed);
}

#[test]
fn datachange_subscription_samples_health_namespace_nodes() {
    let mut data_access = verified_data_access::<1>();
    let mut subscription = DataChangeSubscription::<2>::new();

    let invalid = subscription.add_namespace_node_id(9999, 1);
    assert_eq!(
        invalid.status,
        MonitoredItemAddStatus::InvalidNamespaceNodeId
    );
    assert_eq!(invalid.opcua_status, opcua_status::BAD_INDEX_RANGE_INVALID);
    assert_eq!(subscription.len(), 0);

    let add = subscription.add_namespace_node_id(4006, 77);
    assert_eq!(add.status, MonitoredItemAddStatus::Ok);
    assert_eq!(add.slot, Some(0));
    assert_eq!(subscription.len(), 1);

    let first = subscription
        .sample_slot(0, &data_access, 100)
        .expect("first health sample");
    assert_eq!(first.client_handle, 77);
    assert_eq!(first.node_id, 4006);
    assert_eq!(
        first.target,
        Some(NamespaceTarget::Health(
            HealthNode::BuchiRejectedRequestCount
        ))
    );
    assert_eq!(first.node, None);
    assert_eq!(first.cache_status, None);
    assert_eq!(first.opcua_status, opcua_status::GOOD);
    assert_eq!(first.value, Some(ScalarValue::UInt32(0)));
    assert!(first.changed);

    assert_eq!(
        subscription.sample_slot(0, &data_access, 101),
        None,
        "health nodes are also paced by the sampling interval"
    );
    let unchanged = subscription
        .sample_slot(0, &data_access, 1_100)
        .expect("unchanged health sample");
    assert_eq!(unchanged.value, Some(ScalarValue::UInt32(0)));
    assert!(!unchanged.changed);

    data_access.health_mut().buchi_rejected_request_count = 1;
    assert_eq!(
        subscription.sample_slot(0, &data_access, 1_101),
        None,
        "changed health values wait for the next sampling tick"
    );
    let changed = subscription
        .sample_slot(0, &data_access, 2_100)
        .expect("changed health sample");
    assert_eq!(changed.value, Some(ScalarValue::UInt32(1)));
    assert!(changed.changed);
}

#[test]
fn uptime_datachange_advances_only_when_whole_seconds_change() {
    let mut data_access = verified_data_access::<1>();
    let mut subscription = DataChangeSubscription::<1>::new();
    assert_eq!(
        subscription.add_namespace_node_id(4022, 88).status,
        MonitoredItemAddStatus::Ok
    );
    let ages = [None; SINGLE_CORE_TASK_HEALTH_SLOT_COUNT];
    data_access.set_single_core_health(SingleCoreHealthSnapshot::new(
        10, None, 0, 0, 0, 2_000, ages,
    ));
    let first = subscription
        .sample_slot(0, &data_access, 0)
        .expect("initial whole-second uptime sample");
    assert_eq!(first.value, Some(ScalarValue::UInt32(10)));
    assert!(first.changed);

    data_access.set_single_core_health(SingleCoreHealthSnapshot::new(
        10, None, 0, 0, 0, 2_000, ages,
    ));
    let same_second = subscription
        .sample_slot(0, &data_access, 1_000)
        .expect("paced sample in the same whole second");
    assert!(!same_second.changed);

    data_access.set_single_core_health(SingleCoreHealthSnapshot::new(
        11, None, 0, 0, 0, 2_000, ages,
    ));
    let next_second = subscription
        .sample_slot(0, &data_access, 2_000)
        .expect("next whole-second uptime sample");
    assert_eq!(next_second.value, Some(ScalarValue::UInt32(11)));
    assert!(next_second.changed);
}

#[test]
fn datachange_subscription_removes_by_client_handle_and_reuses_slot() {
    let data_access = verified_data_access::<1>();
    let mut subscription = DataChangeSubscription::<2>::new();
    assert!(subscription.is_empty());
    assert_eq!(
        subscription
            .add_runtime_node(RuntimeNode::ProcessHeatingSet, 7)
            .slot,
        Some(0)
    );
    assert_eq!(
        subscription
            .add_runtime_node(RuntimeNode::ProcessPressure, 8)
            .slot,
        Some(1)
    );
    assert_eq!(subscription.len(), 2);
    assert!(subscription.remove_client_handle(7));
    assert_eq!(subscription.len(), 1);
    assert!(!subscription.remove_client_handle(7));
    assert_eq!(
        subscription
            .add_runtime_node(RuntimeNode::SettingsDisplayBrightness, 9)
            .slot,
        Some(0)
    );
    assert_eq!(subscription.len(), 2);
    let reused = subscription
        .sample_slot(0, &data_access, 0)
        .expect("reused slot samples");
    assert_eq!(reused.client_handle, 9);
    assert_eq!(reused.node, Some(RuntimeNode::SettingsDisplayBrightness));
}

#[test]
fn data_access_write_dispatch_builds_json_without_losing_request_on_small_buffer() {
    let mut data_access = verified_data_access::<1>();
    let queued = data_access.enqueue_write_node(
        RuntimeNode::SettingsProgramEcoEnabled,
        ScalarValue::Boolean(true),
    );
    assert!(queued.accepted);
    assert_eq!(data_access.write_queue_depth(), 1);

    let mut tiny = [0u8; 8];
    assert_eq!(
        data_access.pop_next_write_json(&mut tiny),
        Err(RuntimeWriteDispatchError::Build(
            BuildWriteJsonError::OutputTooSmall
        ))
    );
    assert_eq!(data_access.write_queue_depth(), 1);

    let mut body = [0u8; product::BUCHI_WRITE_JSON_BYTES];
    let dispatch = data_access
        .pop_next_write_json(&mut body)
        .expect("large enough body buffer dispatches queued write");
    assert_eq!(dispatch.endpoint, Endpoint::Settings);
    assert_eq!(dispatch.path(), "/api/v1/settings");
    assert_eq!(
        dispatch.request.target,
        WriteTarget::SettingsProgramEcoEnabled
    );
    assert_eq!(dispatch.request.raw_value, 1);
    assert_eq!(dispatch.request.node_id, 3014);
    assert_eq!(dispatch.request.sequence, 1);
    assert_eq!(
        &body[..dispatch.body_len],
        br#"{"program":{"eco":{"isEnabled":true}}}"#
    );
    assert_eq!(data_access.write_queue_depth(), 0);
    assert_eq!(
        data_access.pop_next_write_json(&mut body),
        Err(RuntimeWriteDispatchError::EmptyQueue)
    );
}

#[test]
fn data_access_write_transaction_builds_put_without_losing_request_on_failure() {
    let mut data_access = verified_data_access::<1>();
    let queued = data_access.enqueue_write_node(
        RuntimeNode::SettingsProgramEcoEnabled,
        ScalarValue::Boolean(true),
    );
    assert!(queued.accepted);
    assert_eq!(data_access.write_queue_depth(), 1);

    assert_eq!(
        data_access.pop_next_write_transaction::<8, 384, 128>("r300.local", "cndyOnJ3"),
        Err(RuntimeWriteTransactionError::Build(
            BuchiPutTransactionError::BuildBody(BuildWriteJsonError::OutputTooSmall)
        ))
    );
    assert_eq!(data_access.write_queue_depth(), 1);

    let transaction = data_access
        .pop_next_write_transaction::<96, 384, 128>("r300.local", "cndyOnJ3")
        .expect("large enough transaction buffers build queued write");
    assert_eq!(
        transaction.write_request().target,
        WriteTarget::SettingsProgramEcoEnabled
    );
    assert_eq!(transaction.write_request().raw_value, 1);
    assert_eq!(transaction.write_request().node_id, 3014);
    assert_eq!(transaction.endpoint(), Endpoint::Settings);
    assert_eq!(transaction.body_len(), 38);
    assert_eq!(
        transaction.request(),
        b"PUT /api/v1/settings HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cndyOnJ3\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"program\":{\"eco\":{\"isEnabled\":true}}}"
    );
    assert_eq!(data_access.write_queue_depth(), 0);
    assert_eq!(
        data_access.pop_next_write_transaction::<96, 384, 128>("r300.local", "cndyOnJ3"),
        Err(RuntimeWriteTransactionError::EmptyQueue)
    );
}

#[test]
fn data_access_records_completed_write_transaction_status() {
    let mut data_access = verified_data_access::<1>();
    assert!(
        data_access
            .enqueue_write_node(
                RuntimeNode::SettingsProgramEcoEnabled,
                ScalarValue::Boolean(true)
            )
            .accepted
    );
    let mut transaction = data_access
        .pop_next_write_transaction::<96, 384, 128>("r300.local", "cndyOnJ3")
        .expect("queued write builds transaction");
    transaction
        .record_write(transaction.request_len())
        .expect("request send completes");
    transaction
        .append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n",
        )
        .expect("headers accepted");
    transaction
        .append_response(br#"{"program":{"eco":{"isEnabled":true}}}"#)
        .expect("body reaches extra-byte probe");
    transaction
        .finish_extra_body_probe()
        .expect("response completes");

    let completion = data_access
        .record_write_transaction_completion(&transaction, 0)
        .expect("completed transaction records write status");
    assert_eq!(completion.request.node_id, 3014);
    assert_eq!(completion.http_status, 200);
    assert_eq!(completion.opcua_status, opcua_status::GOOD);
    assert_eq!(data_access.health().buchi_write_accepted_count, 1);
    assert_eq!(data_access.health().buchi_write_completed_count, 1);
    assert_eq!(data_access.health().buchi_write_failed_count, 0);
    assert_eq!(data_access.health().buchi_write_last_target_node_id, 3014);
    assert_eq!(data_access.health().buchi_write_last_http_status, 200);
    assert_eq!(
        data_access.health().buchi_write_last_opcua_status,
        opcua_status::GOOD
    );
}

#[test]
fn invalid_http_response_fails_before_status_is_known() {
    let mut cache = RuntimeCache::new();
    let failure = cache
        .apply_http_response(Endpoint::Info, b"HTTP/1.1 200 OK\r\n", 128, 1)
        .expect_err("truncated HTTP should fail");
    assert_eq!(
        failure.error,
        EndpointPollError::Response(EndpointResponseError::Http(
            HttpResponseError::HeaderTerminatorMissing
        ))
    );
    assert_eq!(failure.last_http_status, None);
    assert_eq!(cache.failed_fetches(), 1);
}

#[cfg(feature = "diagnostic-runtime-counters")]
mod diagnostic_counters;
