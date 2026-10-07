use super::*;

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
        assert!(
            chunk.len() <= out.len(),
            "scripted read chunk exceeds scratch buffer"
        );
        out[..chunk.len()].copy_from_slice(chunk);
        Ok(chunk.len())
    }
}

#[test]
fn endpoint_contract_matches_default_paths_and_cadence() {
    assert_eq!(Endpoint::Process.path(), "/api/v1/process");
    assert_eq!(Endpoint::Settings.path(), "/api/v1/settings");
    assert_eq!(Endpoint::Info.path(), "/api/v1/info");
    assert_eq!(Endpoint::Process.poll_ms(), 1_000);
    assert_eq!(Endpoint::Settings.poll_ms(), 5_000);
    assert_eq!(Endpoint::Info.poll_ms(), 60_000);
    assert!(PollPlan::DEFAULT.is_default_contract());
    assert!(!PollPlan {
        process_ms: 2_000,
        ..PollPlan::DEFAULT
    }
    .is_default_contract());
}

#[test]
fn http_header_lookup_is_case_insensitive_trimmed_and_duplicate_safe() {
    let headers =
        b"HTTP/1.1 200 OK\r\nContent-Type:\t application/json ; charset=utf-8 \r\nContent-Length: 7\r\n\r\n";
    assert_eq!(
        find_unique_http_header_value(headers, b"content-type"),
        HttpHeaderLookup::Found(b"application/json ; charset=utf-8".as_slice())
    );
    assert_eq!(
        find_unique_http_header_value(headers, b"CONTENT-LENGTH"),
        HttpHeaderLookup::Found(b"7".as_slice())
    );
    assert_eq!(
        find_unique_http_header_value(headers, b"Connection"),
        HttpHeaderLookup::Missing
    );
    assert_eq!(
        find_unique_http_header_value(
            b"Content-Length: 7\r\ncontent-length: 8\r\n\r\n",
            b"Content-Length"
        ),
        HttpHeaderLookup::Duplicate
    );
    assert_eq!(
        find_unique_http_header_value(headers, b""),
        HttpHeaderLookup::Missing
    );
}

#[test]
fn content_length_and_content_type_helpers_fail_closed() {
    assert_eq!(parse_content_length_value(b" 123 \t"), Some(123));
    assert_eq!(parse_content_length_value(b"001"), Some(1));
    assert_eq!(parse_content_length_value(b""), None);
    assert_eq!(parse_content_length_value(b"1 2"), None);
    assert_eq!(parse_content_length_value(b"-1"), None);

    assert!(http_header_value_is_json_content_type(b"application/json"));
    assert!(http_header_value_is_json_content_type(
        b"Application/JSON ; charset=utf-8"
    ));
    assert!(!http_header_value_is_json_content_type(b"text/json"));
    assert!(!http_header_value_is_json_content_type(
        b"application/jsonish"
    ));
}

#[test]
fn http_status_line_and_body_size_helpers_match_current_contract() {
    assert_eq!(parse_http_status_line(b"HTTP/1.1 200 OK"), Some(200));
    assert_eq!(parse_http_status_line(b"HTTP/2 503"), None);
    assert_eq!(parse_http_status_line(b"HTTP/1.1 99"), None);
    assert_eq!(parse_http_status_line(b"HTTP/1.1 600"), None);
    assert_eq!(parse_http_status_line(b"HTTP/1.1 200OK"), None);

    assert_eq!(compute_http_expected_total_bytes(10, 5, 20), Some(15));
    assert_eq!(compute_http_expected_total_bytes(10, 11, 20), None);
    assert_eq!(check_http_body_size(15, 10, 5), HttpBodySizeResult::Exact);
    assert_eq!(
        check_http_body_size(14, 10, 5),
        HttpBodySizeResult::Truncated
    );
    assert_eq!(check_http_body_size(16, 10, 5), HttpBodySizeResult::Extra);
    assert_eq!(
        check_http_body_size(usize::MAX, usize::MAX, 1),
        HttpBodySizeResult::Invalid
    );
}

#[test]
fn http_read_progress_probes_once_for_extra_body_bytes() {
    assert_eq!(
        classify_http_read_progress(false, 0, 10, false),
        HttpReadProgress::ReadMore
    );
    assert_eq!(
        classify_http_read_progress(true, 9, 10, false),
        HttpReadProgress::ReadMore
    );
    assert_eq!(
        classify_http_read_progress(true, 10, 10, false),
        HttpReadProgress::ProbeForExtraBytes
    );
    assert_eq!(
        classify_http_read_progress(true, 10, 10, true),
        HttpReadProgress::Complete
    );
    assert_eq!(
        classify_http_read_progress(true, 11, 10, false),
        HttpReadProgress::Complete
    );
}

#[test]
fn http_response_parser_accepts_exact_bounded_json_response() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 7\r\n\r\n{\"x\":1}";
    let parsed = parse_http_response(response, 256).expect("response parses");
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.body, b"{\"x\":1}");
}

#[test]
fn http_response_parser_allows_non_json_diagnostic_body_for_non_200_status() {
    let response =
        b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nERR";
    let parsed = parse_http_response(response, 256).expect("response parses");
    assert_eq!(parsed.status, 401);
    assert_eq!(parsed.body, b"ERR");
}

#[test]
fn http_response_parser_rejects_ambiguous_or_invalid_headers() {
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::MissingContentLength)
    );
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ncontent-length: 3\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::DuplicateContentLength)
    );
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::UnexpectedContentType)
    );
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2x\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::InvalidContentLength)
    );
}

#[test]
fn http_response_parser_rejects_bad_status_size_and_limit_cases() {
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 99 Nope\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::InvalidStatusLine)
    );
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::BodySize(HttpBodySizeResult::Truncated))
    );
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{}",
            128
        ),
        Err(HttpResponseError::BodySize(HttpBodySizeResult::Extra))
    );
    assert_eq!(
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            8
        ),
        Err(HttpResponseError::ResponseTooLarge)
    );
    assert_eq!(
        parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{}", 128),
        Err(HttpResponseError::HeaderTerminatorMissing)
    );
}

#[test]
fn endpoint_response_dispatch_parses_each_supported_body() {
    let process = parse_endpoint_http_response(
        Endpoint::Process,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"heating\":{\"act\":42.125}}",
        128,
    )
    .unwrap();
    match process {
        EndpointValues::Process(values) => {
            assert_eq!(values.bath_temperature_milli_celsius, Some(42_125));
        }
        _ => panic!("wrong endpoint variant"),
    }

    let settings = parse_endpoint_http_response(
        Endpoint::Settings,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"display\":{\"brightness\":75}}",
        128,
    )
    .unwrap();
    match settings {
        EndpointValues::Settings(values) => {
            assert_eq!(values.display_brightness_percent, Some(75));
        }
        _ => panic!("wrong endpoint variant"),
    }

    let info = parse_endpoint_http_response(
        Endpoint::Info,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"vacubox\":{\"operatingTimeCounter\":700}}",
        128,
    )
    .unwrap();
    match info {
        EndpointValues::Info(values) => {
            assert_eq!(values.vacubox_operating_time_hours, Some(700));
        }
        _ => panic!("wrong endpoint variant"),
    }
}

#[test]
fn endpoint_response_dispatch_separates_http_status_and_body_failures() {
    assert_eq!(
        parse_endpoint_http_response(
            Endpoint::Process,
            b"HTTP/1.1 503 Busy\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            128,
        ),
        Err(EndpointResponseError::UnexpectedStatus(503))
    );
    assert_eq!(
        parse_endpoint_http_response(
            Endpoint::Process,
            b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nERR",
            128,
        ),
        Err(EndpointResponseError::UnexpectedStatus(401))
    );
    assert_eq!(
        parse_endpoint_http_response(
            Endpoint::Process,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            128,
        ),
        Err(EndpointResponseError::Body(ParseError::NoSupportedFields))
    );
    assert_eq!(
        parse_endpoint_http_response(
            Endpoint::Process,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}",
            128,
        ),
        Err(EndpointResponseError::Http(
            HttpResponseError::UnexpectedContentType
        ))
    );
}

#[test]
fn streaming_receive_model_requires_one_extra_body_probe_before_completion() {
    let mut receive = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        receive.append(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
        Ok(HttpReadProgress::ReadMore)
    );
    assert!(!receive.headers_parsed());
    assert_eq!(
        receive.append(b"Content-Length: 26\r\n\r\n{\"heating\":{\"act\":42.125}}"),
        Ok(HttpReadProgress::ProbeForExtraBytes)
    );
    assert!(receive.headers_parsed());
    assert_eq!(receive.status(), Some(200));
    assert_eq!(
        receive.response(),
        Err(HttpResponseError::ExtraBodyProbeRequired)
    );
    assert_eq!(
        receive.finish_extra_body_probe(),
        Ok(HttpReadProgress::Complete)
    );
    let parsed = receive.response().unwrap();
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.body, br#"{"heating":{"act":42.125}}"#);
}

#[test]
fn streaming_receive_model_distinguishes_truncated_extra_and_too_large() {
    let mut truncated = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        truncated.append(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}"
        ),
        Ok(HttpReadProgress::ReadMore)
    );
    assert_eq!(
        truncated.response(),
        Err(HttpResponseError::BodySize(HttpBodySizeResult::Truncated))
    );

    let mut extra = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        extra.append(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{}"
        ),
        Err(HttpResponseError::BodySize(HttpBodySizeResult::Extra))
    );

    let mut too_large = HttpReceiveBuffer::<8>::new();
    assert_eq!(
        too_large.append(b"HTTP/1.1 200 OK"),
        Err(HttpResponseError::ResponseTooLarge)
    );
}

#[test]
fn streaming_receive_model_rejects_unsupported_or_ambiguous_encoding() {
    let mut transfer = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        transfer.append(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        ),
        Err(HttpResponseError::UnsupportedTransferEncoding)
    );

    let mut duplicate_transfer = HttpReceiveBuffer::<160>::new();
    assert_eq!(
        duplicate_transfer.append(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\ntransfer-encoding: chunked\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        ),
        Err(HttpResponseError::DuplicateTransferEncoding)
    );

    let mut content_encoding = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        content_encoding.append(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        ),
        Err(HttpResponseError::UnsupportedContentEncoding)
    );
}

#[test]
fn streaming_receive_model_allows_non_json_diagnostic_body_for_non_200_status() {
    let mut receive = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        receive.append(b"HTTP/1.1 503 Busy\r\nContent-Length: 3\r\n\r\nERR"),
        Ok(HttpReadProgress::ProbeForExtraBytes)
    );
    assert_eq!(
        receive.finish_extra_body_probe(),
        Ok(HttpReadProgress::Complete)
    );
    let parsed = receive.response().unwrap();
    assert_eq!(parsed.status, 503);
    assert_eq!(parsed.body, b"ERR");
}

#[test]
fn persistent_receive_model_completes_at_content_length_without_close_probe() {
    let mut receive = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        receive.append(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
        Ok(HttpReadProgress::ReadMore)
    );
    assert_eq!(
        receive.finish_persistent_response(),
        Ok(HttpReadProgress::ReadMore)
    );
    assert_eq!(
        receive.append(b"Content-Length: 26\r\n\r\n{\"heating\":{\"act\":42.125}}"),
        Ok(HttpReadProgress::ProbeForExtraBytes)
    );
    assert_eq!(
        receive.finish_persistent_response(),
        Ok(HttpReadProgress::Complete)
    );
    let parsed = receive.response().unwrap();
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.body, br#"{"heating":{"act":42.125}}"#);

    let mut extra = HttpReceiveBuffer::<128>::new();
    assert_eq!(
        extra.append(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{}"
        ),
        Err(HttpResponseError::BodySize(HttpBodySizeResult::Extra))
    );
    assert_eq!(
        extra.finish_persistent_response(),
        Err(HttpResponseError::BodySize(HttpBodySizeResult::Extra))
    );
}

#[test]
fn parses_representative_process_payload() {
    let json = br#"{"heating":{"act":42.125},"vacuum":{"act":125},"rotation":{"act":120},"globalStatus":{"running":true}}"#;
    let values = parse_process_json(json).expect("representative payload parses");
    assert_eq!(values.bath_temperature_milli_celsius, Some(42_125));
    assert_eq!(values.pressure_milli_mbar, Some(125_000));
    assert_eq!(values.rotation_speed_milli_rpm, Some(120_000));
    assert_eq!(values.process_state, Some(1));
    assert!(values.roots.heating);
    assert!(values.roots.vacuum);
    assert!(values.roots.rotation);
    assert!(values.roots.global_status);
    assert!(!values.roots.cooling);
}

#[test]
fn preserves_fractional_vacuum_pressure() {
    let values = parse_process_json(br#"{"vacuum":{"act":125.625}}"#).unwrap();
    assert_eq!(values.pressure_milli_mbar, Some(125_625));
}

#[test]
fn missing_optional_fields_remain_absent() {
    let values = parse_process_json(br#"{"heating":{"act":20.5}}"#).unwrap();
    assert_eq!(values.bath_temperature_milli_celsius, Some(20_500));
    assert_eq!(values.pressure_milli_mbar, None);
    assert_eq!(values.rotation_speed_milli_rpm, None);
    assert_eq!(values.process_state, None);
}

#[test]
fn omitted_root_object_keeps_other_data() {
    let json = br#"{"globalStatus":{"running":true},"vacuum":{"act":500},"rotation":{"act":120}}"#;
    let values = parse_process_json(json).unwrap();
    assert_eq!(values.bath_temperature_milli_celsius, None);
    assert_eq!(values.pressure_milli_mbar, Some(500_000));
    assert_eq!(values.rotation_speed_milli_rpm, Some(120_000));
    assert_eq!(values.process_state, Some(1));
    assert!(!values.roots.heating);
    assert!(values.roots.vacuum);
    assert!(values.roots.rotation);
}

#[test]
fn process_root_presence_tracks_object_existence_not_field_validity() {
    let values = parse_process_json(
        br#"{"cooling":{"set":-99.0},"vacuum":{"powerPercentAct":101},"globalStatus":{"running":false}}"#,
    )
    .unwrap();
    assert!(values.roots.cooling);
    assert!(values.roots.vacuum);
    assert!(values.roots.global_status);
    assert_eq!(values.cooling_set_milli_celsius, None);
    assert_eq!(values.vacuum_power_percent_milli_percent, None);
    assert_eq!(values.process_state, Some(0));
}

#[test]
fn nested_irrelevant_members_do_not_parse_as_root_objects() {
    let json = br#"{"program":{"name":"act is not a key here","nested":{"act":999}},"heating":{"running":false,"act":-5.25},"globalStatus":{"running":false}}"#;
    let values = parse_process_json(json).unwrap();
    assert_eq!(values.bath_temperature_milli_celsius, Some(-5_250));
    assert_eq!(values.heating_running, Some(false));
    assert_eq!(values.process_state, Some(0));
    assert_eq!(values.rotation_speed_milli_rpm, None);
}

#[test]
fn rejects_malformed_or_unsupported_payloads_without_publishing_defaults() {
    assert_eq!(parse_process_json(b""), Err(ParseError::Empty));
    assert_eq!(
        parse_process_json(br#"{"heating":{"act":1}"#),
        Err(ParseError::Malformed)
    );
    assert_eq!(
        parse_process_json(br#"{"program":{"type":"Manual"}}"#),
        Err(ParseError::NoSupportedFields)
    );
}

#[test]
fn enforces_current_rotation_actual_lower_bound() {
    let low = parse_process_json(br#"{"rotation":{"act":9.999}}"#);
    assert_eq!(low, Err(ParseError::NoSupportedFields));
    let ok = parse_process_json(br#"{"rotation":{"act":10.0}}"#).unwrap();
    assert_eq!(ok.rotation_speed_milli_rpm, Some(10_000));
}

#[test]
fn parses_boolean_zero_one_but_rejects_other_numbers() {
    let values =
        parse_process_json(br#"{"heating":{"running":1},"rotation":{"running":0}}"#).unwrap();
    assert_eq!(values.heating_running, Some(true));
    assert_eq!(values.rotation_running, Some(false));
    assert_eq!(
        parse_process_json(br#"{"heating":{"running":2}}"#),
        Err(ParseError::NoSupportedFields)
    );
}

#[test]
fn parses_full_process_payload_contract() {
    let json = br#"{
        "heating":{"set":42.125,"act":41.875,"running":true},
        "cooling":{"set":-5.5,"act":4.25,"running":0},
        "vacuum":{
            "set":125,
            "act":124.875,
            "aerateValveOpen":1,
            "aerateValvePulse":false,
            "vacuumValveOpen":true,
            "vaporTemp":65.5,
            "autoDestIn":52.25,
            "autoDestOut":48.75,
            "powerPercentAct":75,
            "running":1
        },
        "rotation":{"set":120,"act":120.5,"running":true},
        "lift":{"set":220,"act":110.25,"limit":200.5},
        "globalStatus":{
            "running":true,
            "processTime":1234,
            "runId":4294967295,
            "onHold":0,
            "foamActive":1,
            "currentError":-12
        }
    }"#;

    let values = parse_process_json(json).expect("full process payload parses");
    assert_eq!(values.parsed_field_count(), 28);
    assert_eq!(values.process_state, Some(1));
    assert_eq!(values.heating_set_milli_celsius, Some(42_125));
    assert_eq!(values.bath_temperature_milli_celsius, Some(41_875));
    assert_eq!(values.heating_running, Some(true));
    assert_eq!(values.cooling_set_milli_celsius, Some(-5_500));
    assert_eq!(values.cooling_actual_milli_celsius, Some(4_250));
    assert_eq!(values.cooling_running, Some(false));
    assert_eq!(values.vacuum_set_mbar, Some(125));
    assert_eq!(values.pressure_milli_mbar, Some(124_875));
    assert_eq!(values.vacuum_aerate_valve_open, Some(true));
    assert_eq!(values.vacuum_aerate_valve_pulse, Some(false));
    assert_eq!(values.vacuum_valve_open, Some(true));
    assert_eq!(values.vacuum_vapor_temperature_milli_celsius, Some(65_500));
    assert_eq!(
        values.vacuum_auto_destination_in_milli_celsius,
        Some(52_250)
    );
    assert_eq!(
        values.vacuum_auto_destination_out_milli_celsius,
        Some(48_750)
    );
    assert_eq!(values.vacuum_power_percent_milli_percent, Some(75_000));
    assert_eq!(values.vacuum_running, Some(true));
    assert_eq!(values.rotation_set_rpm, Some(120));
    assert_eq!(values.rotation_speed_milli_rpm, Some(120_500));
    assert_eq!(values.rotation_running, Some(true));
    assert_eq!(values.lift_set_milli_millimeters, Some(220_000));
    assert_eq!(values.lift_actual_milli_millimeters, Some(110_250));
    assert_eq!(values.lift_limit_milli_millimeters, Some(200_500));
    assert_eq!(values.global_status_process_time_seconds, Some(1_234));
    assert_eq!(values.global_status_run_id, Some(u32::MAX));
    assert_eq!(values.global_status_on_hold, Some(false));
    assert_eq!(values.global_status_foam_active, Some(true));
    assert_eq!(values.global_status_current_error, Some(-12));
}

#[test]
fn process_parser_enforces_source_backed_ranges() {
    let values = parse_process_json(
        br#"{
            "cooling":{"set":-10.001,"act":-10.001},
            "vacuum":{"powerPercentAct":101,"act":0.125},
            "rotation":{"set":281,"act":9.999},
            "lift":{"set":110,"limit":19.999,"act":19.999},
            "globalStatus":{"running":false}
        }"#,
    )
    .unwrap();

    assert_eq!(values.cooling_set_milli_celsius, None);
    assert_eq!(values.cooling_actual_milli_celsius, Some(-10_001));
    assert_eq!(values.vacuum_power_percent_milli_percent, None);
    assert_eq!(values.pressure_milli_mbar, Some(125));
    assert_eq!(values.rotation_set_rpm, None);
    assert_eq!(values.rotation_speed_milli_rpm, None);
    assert_eq!(values.lift_set_milli_millimeters, None);
    assert_eq!(values.lift_limit_milli_millimeters, None);
    assert_eq!(values.lift_actual_milli_millimeters, Some(19_999));
    assert_eq!(values.process_state, Some(0));
}

#[test]
fn global_status_running_requires_boolean_but_other_flags_accept_zero_one() {
    let values = parse_process_json(
        br#"{"globalStatus":{"running":1,"onHold":1,"foamActive":0,"currentError":7}}"#,
    )
    .unwrap();

    assert_eq!(values.process_state, None);
    assert_eq!(values.global_status_on_hold, Some(true));
    assert_eq!(values.global_status_foam_active, Some(false));
    assert_eq!(values.global_status_current_error, Some(7));
}

#[test]
fn process_integer_fields_reject_fractional_signed_and_overflow_values() {
    let unsupported = parse_process_json(
        br#"{"globalStatus":{"processTime":-1,"runId":4294967296,"currentError":1.0},"vacuum":{"powerPercentAct":75.0}}"#,
    );
    assert_eq!(unsupported, Err(ParseError::NoSupportedFields));

    let values = parse_process_json(
        br#"{"globalStatus":{"processTime":0,"runId":4294967295,"currentError":-2147483648},"vacuum":{"powerPercentAct":100}}"#,
    )
    .unwrap();
    assert_eq!(values.global_status_process_time_seconds, Some(0));
    assert_eq!(values.global_status_run_id, Some(u32::MAX));
    assert_eq!(values.global_status_current_error, Some(i32::MIN));
    assert_eq!(values.vacuum_power_percent_milli_percent, Some(100_000));
}

#[test]
fn parses_full_settings_payload_contract() {
    let json = br#"{
        "display":{"brightness":75,"utcOffset":-330},
        "sounds":{"buttonTone":true,"playSoundOnFinish":0},
        "vacuum":{
            "pressureHysteresis":125,
            "altitude":1234,
            "maxPermPressure":1000,
            "maxPumpOutput":80,
            "ventOnFinish":1
        },
        "rotation":{"startRotationOnStart":true,"stopRotationOnFinish":false},
        "heating":{"maxTemperature":180,"stopHeatingOnFinish":1},
        "cooling":{"stopCoolingOnFinish":0},
        "lift":{"depthStop":120.5,"immerseOnStart":true,"liftOutFlaskOnFinish":false},
        "program":{"eco":{
            "isEnabled":true,
            "activationAfterMins":15,
            "heatingBathTemperature":42.125,
            "coolantTemperature":12.5
        }}
    }"#;

    let values = parse_settings_json(json).expect("full settings payload parses");
    assert_eq!(values.parsed_field_count(), 21);
    assert_eq!(
        values.roots,
        SettingsRootPresence {
            display: true,
            sounds: true,
            vacuum: true,
            rotation: true,
            heating: true,
            cooling: true,
            lift: true,
            program: true,
        }
    );
    assert_eq!(values.display_brightness_percent, Some(75));
    assert_eq!(values.display_utc_offset_minutes, Some(-330));
    assert_eq!(values.sounds_button_tone, Some(true));
    assert_eq!(values.sounds_play_sound_on_finish, Some(false));
    assert_eq!(values.vacuum_pressure_hysteresis_mbar, Some(125));
    assert_eq!(values.vacuum_altitude_meters, Some(1_234));
    assert_eq!(values.vacuum_max_perm_pressure_mbar, Some(1_000));
    assert_eq!(values.vacuum_max_pump_output_percent, Some(80));
    assert_eq!(values.vacuum_vent_on_finish, Some(true));
    assert_eq!(values.rotation_start_on_start, Some(true));
    assert_eq!(values.rotation_stop_on_finish, Some(false));
    assert_eq!(values.heating_max_temperature_milli_celsius, Some(180_000));
    assert_eq!(values.heating_stop_on_finish, Some(true));
    assert_eq!(values.cooling_stop_on_finish, Some(false));
    assert_eq!(values.lift_depth_stop_milli_millimeters, Some(120_500));
    assert_eq!(values.lift_immerse_on_start, Some(true));
    assert_eq!(values.lift_out_flask_on_finish, Some(false));
    assert_eq!(values.program_eco_enabled, Some(true));
    assert_eq!(values.program_eco_activation_after_mins, Some(15));
    assert_eq!(
        values.program_eco_heating_bath_temperature_milli_celsius,
        Some(42_125)
    );
    assert_eq!(
        values.program_eco_coolant_temperature_milli_celsius,
        Some(12_500)
    );
}

#[test]
fn settings_parser_enforces_source_backed_ranges_and_sets() {
    let values = parse_settings_json(
        br#"{
            "display":{"brightness":101,"utcOffset":-315},
            "vacuum":{"pressureHysteresis":201,"altitude":4001,"maxPermPressure":1301,"maxPumpOutput":-1},
            "heating":{"maxTemperature":181,"stopHeatingOnFinish":true},
            "lift":{"depthStop":19.999,"immerseOnStart":2},
            "program":{"eco":{
                "activationAfterMins":4,
                "heatingBathTemperature":2.999,
                "coolantTemperature":50.001,
                "isEnabled":1
            }}
        }"#,
    )
    .unwrap();

    assert_eq!(values.display_brightness_percent, None);
    assert_eq!(values.display_utc_offset_minutes, None);
    assert_eq!(values.vacuum_pressure_hysteresis_mbar, None);
    assert_eq!(values.vacuum_altitude_meters, None);
    assert_eq!(values.vacuum_max_perm_pressure_mbar, None);
    assert_eq!(values.vacuum_max_pump_output_percent, None);
    assert_eq!(values.heating_max_temperature_milli_celsius, None);
    assert_eq!(values.heating_stop_on_finish, Some(true));
    assert_eq!(values.lift_depth_stop_milli_millimeters, None);
    assert_eq!(values.lift_immerse_on_start, None);
    assert_eq!(values.program_eco_activation_after_mins, None);
    assert_eq!(
        values.program_eco_heating_bath_temperature_milli_celsius,
        None
    );
    assert_eq!(values.program_eco_coolant_temperature_milli_celsius, None);
    assert_eq!(values.program_eco_enabled, Some(true));
    assert!(values.roots.display);
    assert!(values.roots.vacuum);
    assert!(values.roots.heating);
    assert!(values.roots.lift);
    assert!(values.roots.program);
}

#[test]
fn settings_parser_rejects_malformed_or_unsupported_without_defaults() {
    assert_eq!(parse_settings_json(b""), Err(ParseError::Empty));
    assert_eq!(
        parse_settings_json(br#"{"display":{"brightness":75}"#),
        Err(ParseError::Malformed)
    );
    assert_eq!(
        parse_settings_json(br#"{"program":{"type":"Manual"}}"#),
        Err(ParseError::NoSupportedFields)
    );
    assert_eq!(
        parse_settings_json(br#"{"display":{"brightness":75.0}}"#),
        Err(ParseError::NoSupportedFields)
    );
}

#[test]
fn parses_full_info_payload_contract() {
    let json = br#"{
        "controller":{
            "operatingTimeCounter":100,
            "runCounters":{
                "totalRuns":10,
                "manual":1,
                "timer":2,
                "continuous":3,
                "solvent":4,
                "method":5,
                "autoDest":6,
                "cloudDest":7,
                "drying":8,
                "leakTest":9,
                "calibration":11
            }
        },
        "bath":{"operatingTimeCounter":200,"hoursOver190C":12},
        "chiller":{"operatingTimeCounter":300,"pumpHours":301,"compressorHours":302,"valveCounter":303},
        "rotavapor":{"operatingTimeCounter":400,"rotationHours":401,"liftMoves":402},
        "pump":{
            "operatingTimeCounter":500,
            "module1":{"switchOn":501,"overCurrent":1.25,"maxCurrent":2.5,"maxTemperature":-3.75},
            "module2":{"switchOn":601,"overCurrent":4.125,"maxCurrent":5.875,"maxTemperature":6.5}
        },
        "vacubox":{"operatingTimeCounter":700}
    }"#;

    let values = parse_info_json(json).expect("full info payload parses");
    assert_eq!(values.parsed_field_count(), 31);
    assert_eq!(
        values.roots,
        InfoRootPresence {
            controller: true,
            bath: true,
            chiller: true,
            rotavapor: true,
            pump: true,
            vacubox: true,
        }
    );
    assert_eq!(values.controller_operating_time_hours, Some(100));
    assert_eq!(values.controller_run_total_runs, Some(10));
    assert_eq!(values.controller_run_manual, Some(1));
    assert_eq!(values.controller_run_timer, Some(2));
    assert_eq!(values.controller_run_continuous, Some(3));
    assert_eq!(values.controller_run_solvent, Some(4));
    assert_eq!(values.controller_run_method, Some(5));
    assert_eq!(values.controller_run_auto_dest, Some(6));
    assert_eq!(values.controller_run_cloud_dest, Some(7));
    assert_eq!(values.controller_run_drying, Some(8));
    assert_eq!(values.controller_run_leak_test, Some(9));
    assert_eq!(values.controller_run_calibration, Some(11));
    assert_eq!(values.bath_operating_time_hours, Some(200));
    assert_eq!(values.bath_hours_over_190c, Some(12));
    assert_eq!(values.chiller_operating_time_hours, Some(300));
    assert_eq!(values.chiller_pump_hours, Some(301));
    assert_eq!(values.chiller_compressor_hours, Some(302));
    assert_eq!(values.chiller_valve_counter, Some(303));
    assert_eq!(values.rotavapor_operating_time_hours, Some(400));
    assert_eq!(values.rotavapor_rotation_hours, Some(401));
    assert_eq!(values.rotavapor_lift_moves, Some(402));
    assert_eq!(values.pump_operating_time_hours, Some(500));
    assert_eq!(values.pump_module1_switch_on, Some(501));
    assert_eq!(values.pump_module1_over_current_milli_count, Some(1_250));
    assert_eq!(values.pump_module1_max_current_milli_amps, Some(2_500));
    assert_eq!(
        values.pump_module1_max_temperature_milli_celsius,
        Some(-3_750)
    );
    assert_eq!(values.pump_module2_switch_on, Some(601));
    assert_eq!(values.pump_module2_over_current_milli_count, Some(4_125));
    assert_eq!(values.pump_module2_max_current_milli_amps, Some(5_875));
    assert_eq!(
        values.pump_module2_max_temperature_milli_celsius,
        Some(6_500)
    );
    assert_eq!(values.vacubox_operating_time_hours, Some(700));
}

#[test]
fn info_parser_enforces_counter_and_nonnegative_number_rules() {
    let values = parse_info_json(
        br#"{
            "controller":{"operatingTimeCounter":-1,"runCounters":{"totalRuns":1.0,"manual":0}},
            "pump":{"module1":{"switchOn":-1,"overCurrent":-0.001,"maxCurrent":1.5,"maxTemperature":-40.125}},
            "vacubox":{"operatingTimeCounter":2147483648}
        }"#,
    )
    .unwrap();

    assert_eq!(values.controller_operating_time_hours, None);
    assert_eq!(values.controller_run_total_runs, None);
    assert_eq!(values.controller_run_manual, Some(0));
    assert_eq!(values.pump_module1_switch_on, None);
    assert_eq!(values.pump_module1_over_current_milli_count, None);
    assert_eq!(values.pump_module1_max_current_milli_amps, Some(1_500));
    assert_eq!(
        values.pump_module1_max_temperature_milli_celsius,
        Some(-40_125)
    );
    assert_eq!(values.vacubox_operating_time_hours, None);
    assert!(values.roots.controller);
    assert!(values.roots.pump);
    assert!(values.roots.vacubox);
}

#[test]
fn info_parser_rejects_malformed_or_unsupported_without_defaults() {
    assert_eq!(parse_info_json(b""), Err(ParseError::Empty));
    assert_eq!(
        parse_info_json(br#"{"controller":{"operatingTimeCounter":1}"#),
        Err(ParseError::Malformed)
    );
    assert_eq!(
        parse_info_json(br#"{"controller":{"serialNumber":"abc"}}"#),
        Err(ParseError::NoSupportedFields)
    );
    assert_eq!(
        parse_info_json(br#"{"pump":{"module1":{"overCurrent":0.0001}}}"#),
        Err(ParseError::NoSupportedFields)
    );
}

#[test]
fn write_specs_match_default_writable_contract() {
    use opta_gateway_contracts::namespace::{self, ValueKind};

    assert_eq!(WRITE_SPECS.len(), namespace::WRITABLE_NODES.len());
    for spec in WRITE_SPECS {
        let contract = namespace::lookup_writable_node(spec.node_id)
            .expect("write spec has a namespace contract");
        assert_eq!(contract.browse_name, spec.browse_name);
        assert_eq!(
            contract.value_kind,
            match spec.value_type {
                WriteValueType::Boolean => ValueKind::Boolean,
                WriteValueType::Int32 => ValueKind::Int32,
                WriteValueType::Float => ValueKind::Float,
            }
        );
    }

    assert!(lookup_write_spec(WriteTarget::ProcessHeatingSet).is_some());
    assert!(lookup_write_spec_by_node_id(3001).is_some());
    assert_eq!(lookup_write_spec_by_node_id(4028), None);
    assert_eq!(write_target_name(WriteTarget::None), "-");
}

#[test]
fn write_raw_validation_enforces_type_range_and_multiples() {
    let heating_running = lookup_write_spec(WriteTarget::ProcessHeatingRunning).unwrap();
    assert_eq!(
        validate_write_raw_value(heating_running, 0),
        WriteValidationStatus::Ok
    );
    assert_eq!(
        validate_write_raw_value(heating_running, 1),
        WriteValidationStatus::Ok
    );
    assert_eq!(
        validate_write_raw_value(heating_running, 2),
        WriteValidationStatus::TypeMismatch
    );

    let heating_set = lookup_write_spec(WriteTarget::ProcessHeatingSet).unwrap();
    assert_eq!(
        validate_write_raw_value(heating_set, -1),
        WriteValidationStatus::OutOfRange
    );
    assert_eq!(
        validate_write_raw_value(heating_set, 220_000),
        WriteValidationStatus::Ok
    );
    assert_eq!(
        validate_write_raw_value(heating_set, 220_001),
        WriteValidationStatus::OutOfRange
    );

    let utc_offset = lookup_write_spec(WriteTarget::SettingsDisplayUtcOffset).unwrap();
    assert_eq!(
        validate_write_raw_value(utc_offset, -330),
        WriteValidationStatus::Ok
    );
    assert_eq!(
        validate_write_raw_value(utc_offset, -315),
        WriteValidationStatus::OutOfRange
    );

    let lift = lookup_write_spec(WriteTarget::ProcessLiftSet).unwrap();
    assert_eq!(validate_write_raw_value(lift, 0), WriteValidationStatus::Ok);
    assert_eq!(
        validate_write_raw_value(lift, 220_000),
        WriteValidationStatus::Ok
    );
    assert_eq!(
        validate_write_raw_value(lift, 1_000),
        WriteValidationStatus::OutOfRange
    );

    assert_eq!(
        validate_write_request(WriteTarget::None, 0),
        WriteValidationStatus::UnknownTarget
    );
}

#[test]
fn float_conversion_requires_exact_raw_value() {
    let heating_set = lookup_write_spec(WriteTarget::ProcessHeatingSet).unwrap();
    assert_eq!(
        convert_write_float_to_raw_value(heating_set, 42.125),
        Some(42_125)
    );
    assert_eq!(
        convert_write_float_to_raw_value(heating_set, 220.0),
        Some(220_000)
    );
    assert_eq!(convert_write_float_to_raw_value(heating_set, -0.001), None);
    assert_eq!(convert_write_float_to_raw_value(heating_set, 220.001), None);
    assert_eq!(convert_write_float_to_raw_value(heating_set, 42.1234), None);

    let brightness = lookup_write_spec(WriteTarget::SettingsDisplayBrightness).unwrap();
    assert_eq!(convert_write_float_to_raw_value(brightness, 10.0), None);
}

#[test]
fn write_queue_is_bounded_fifo_and_coalesces() {
    let first = WriteRequest {
        target: WriteTarget::ProcessHeatingSet,
        raw_value: 1_000,
        node_id: 2001,
        sequence: 1,
    };
    let second = WriteRequest {
        target: WriteTarget::ProcessRotationRunning,
        raw_value: 1,
        node_id: 2019,
        sequence: 2,
    };
    let replacement = WriteRequest {
        raw_value: 2_000,
        sequence: 3,
        ..first
    };
    let rejected = WriteRequest {
        target: WriteTarget::SettingsDisplayBrightness,
        raw_value: 50,
        node_id: 3018,
        sequence: 4,
    };

    let mut queue = WriteQueue::<2>::new();
    assert_eq!(queue.capacity(), 2);
    assert_eq!(
        queue.push(first),
        WriteQueuePushResult {
            accepted: true,
            coalesced: false,
            depth: 1,
        }
    );
    assert_eq!(
        queue.push(second),
        WriteQueuePushResult {
            accepted: true,
            coalesced: false,
            depth: 2,
        }
    );
    assert_eq!(
        queue.push(replacement),
        WriteQueuePushResult {
            accepted: true,
            coalesced: true,
            depth: 2,
        }
    );
    assert_eq!(
        queue.push(rejected),
        WriteQueuePushResult {
            accepted: false,
            coalesced: false,
            depth: 2,
        }
    );

    assert_eq!(queue.peek(), Some(replacement));
    assert_eq!(queue.pop(), Some(replacement));
    assert_eq!(queue.peek(), Some(second));
    assert_eq!(queue.pop(), Some(second));
    assert_eq!(queue.peek(), None);
    assert_eq!(queue.pop(), None);
}

#[test]
fn write_json_builder_formats_bounded_payloads() {
    let mut buf = [0u8; product::BUCHI_WRITE_JSON_BYTES];
    let used = build_write_json(
        WriteRequest {
            target: WriteTarget::ProcessHeatingSet,
            raw_value: 42_125,
            node_id: 2001,
            sequence: 1,
        },
        &mut buf,
    )
    .unwrap();
    assert_eq!(&buf[..used], br#"{"heating":{"set":42.125}}"#);

    let used = build_write_json(
        WriteRequest {
            target: WriteTarget::SettingsProgramEcoEnabled,
            raw_value: 1,
            node_id: 3014,
            sequence: 2,
        },
        &mut buf,
    )
    .unwrap();
    assert_eq!(&buf[..used], br#"{"program":{"eco":{"isEnabled":true}}}"#);

    let used = build_write_json(
        WriteRequest {
            target: WriteTarget::SettingsDisplayUtcOffset,
            raw_value: -330,
            node_id: 3019,
            sequence: 3,
        },
        &mut buf,
    )
    .unwrap();
    assert_eq!(&buf[..used], br#"{"display":{"utcOffset":-330}}"#);

    assert_eq!(
        build_write_json(
            WriteRequest {
                target: WriteTarget::SettingsDisplayUtcOffset,
                raw_value: -315,
                node_id: 3019,
                sequence: 4,
            },
            &mut buf,
        ),
        Err(BuildWriteJsonError::InvalidValue(
            WriteValidationStatus::OutOfRange
        ))
    );

    let mut tiny = [0u8; 8];
    assert_eq!(
        build_write_json(
            WriteRequest {
                target: WriteTarget::SettingsProgramEcoEnabled,
                raw_value: 1,
                node_id: 3014,
                sequence: 5,
            },
            &mut tiny,
        ),
        Err(BuildWriteJsonError::OutputTooSmall)
    );

    for spec in WRITE_SPECS {
        let raw_value = if spec.value_type == WriteValueType::Boolean {
            1
        } else {
            spec.min_raw
        };
        let used = build_write_json(
            WriteRequest {
                target: spec.target,
                raw_value,
                node_id: spec.node_id,
                sequence: 0,
            },
            &mut buf,
        )
        .expect("all write specs fit the fixed JSON buffer");
        assert!(used < product::BUCHI_WRITE_JSON_BYTES);
    }
}

#[test]
fn http_request_builders_match_product_behavior_request_shape() {
    let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
    let used = build_get_request(Endpoint::Process, "r300.local", "cm86cm8=", &mut request)
        .expect("GET request fits fixed buffer");
    assert_eq!(
        &request[..used],
        b"GET /api/v1/process HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cm86cm8=\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );

    let mut body = [0u8; product::BUCHI_WRITE_JSON_BYTES];
    let body_len = build_write_json(
        WriteRequest {
            target: WriteTarget::SettingsDisplayBrightness,
            raw_value: 75,
            node_id: 3018,
            sequence: 1,
        },
        &mut body,
    )
    .expect("write body fits");
    let used = build_put_request(
        Endpoint::Settings,
        "192.0.2.50",
        "cndyOnJ3",
        &body[..body_len],
        &mut request,
    )
    .expect("PUT request fits fixed buffer");
    assert_eq!(
        &request[..used],
        b"PUT /api/v1/settings HTTP/1.1\r\nHost: 192.0.2.50\r\nAuthorization: Basic cndyOnJ3\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: 29\r\nConnection: close\r\n\r\n{\"display\":{\"brightness\":75}}"
    );
    assert!(used < product::BUCHI_HTTP_REQUEST_BYTES);
}

#[test]
fn http_request_builders_can_select_keep_alive_connection() {
    let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
    let used = build_get_request_with_connection(
        Endpoint::Settings,
        "r300.local",
        "cm86cm8=",
        HttpConnectionMode::KeepAlive,
        &mut request,
    )
    .expect("keep-alive GET request fits fixed buffer");
    assert_eq!(
        &request[..used],
        b"GET /api/v1/settings HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cm86cm8=\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n"
    );

    let body = br#"{"display":{"brightness":75}}"#;
    let used = build_put_request_with_connection(
        Endpoint::Settings,
        "192.0.2.50",
        "cndyOnJ3",
        body,
        HttpConnectionMode::KeepAlive,
        &mut request,
    )
    .expect("keep-alive PUT request fits fixed buffer");
    assert_eq!(
        &request[..used],
        b"PUT /api/v1/settings HTTP/1.1\r\nHost: 192.0.2.50\r\nAuthorization: Basic cndyOnJ3\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: 29\r\nConnection: keep-alive\r\n\r\n{\"display\":{\"brightness\":75}}"
    );
}

#[test]
fn basic_auth_builder_encodes_credentials_without_allocation() {
    let mut token = [0u8; 16];
    let used =
        build_basic_auth_token("rw", "rw", &mut token).expect("rw/rw token fits fixed buffer");
    assert_eq!(&token[..used], b"cnc6cnc=");
    assert_eq!(used, basic_auth_token_capacity(2, 2).unwrap());

    let used =
        build_basic_auth_token("ro", "ro", &mut token).expect("ro/ro token fits fixed buffer");
    assert_eq!(&token[..used], b"cm86cm8=");

    let used =
        build_basic_auth_token("abc", "de", &mut token).expect("abc/de token fits fixed buffer");
    assert_eq!(&token[..used], b"YWJjOmRl");
}

#[test]
fn basic_auth_builder_rejects_invalid_credentials_and_capacity() {
    let mut token = [0u8; 8];
    assert_eq!(
        build_basic_auth_token("", "rw", &mut token),
        Err(BasicAuthError::EmptyCredential)
    );
    assert_eq!(
        build_basic_auth_token("rw", "", &mut token),
        Err(BasicAuthError::EmptyCredential)
    );
    assert_eq!(
        build_basic_auth_token("rø", "rw", &mut token),
        Err(BasicAuthError::NonAscii)
    );
    let mut tiny = [0u8; 7];
    assert_eq!(
        build_basic_auth_token("rw", "rw", &mut tiny),
        Err(BasicAuthError::OutputTooSmall)
    );
}

#[test]
fn http_request_builders_fail_closed_for_invalid_inputs_and_capacity() {
    let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
    assert_eq!(
        build_get_request(Endpoint::Process, "", "cm86cm8=", &mut request),
        Err(BuildHttpRequestError::EmptyHost)
    );
    assert_eq!(
        build_get_request(Endpoint::Process, "r300.local", "", &mut request),
        Err(BuildHttpRequestError::EmptyAuth)
    );
    assert_eq!(
        build_get_request(
            Endpoint::Process,
            "r300.local\r\nx",
            "cm86cm8=",
            &mut request
        ),
        Err(BuildHttpRequestError::InvalidHeaderValue)
    );
    assert_eq!(
        build_put_request(
            Endpoint::Info,
            "r300.local",
            "cndyOnJ3",
            b"{}",
            &mut request
        ),
        Err(BuildHttpRequestError::UnsupportedMethod)
    );
    assert_eq!(
        build_put_request(
            Endpoint::Process,
            "r300.local",
            "cndyOnJ3",
            b"",
            &mut request
        ),
        Err(BuildHttpRequestError::EmptyBody)
    );

    let mut tiny = [0u8; 32];
    assert_eq!(
        build_get_request(Endpoint::Process, "r300.local", "cm86cm8=", &mut tiny),
        Err(BuildHttpRequestError::OutputTooSmall)
    );
    assert_eq!(
        build_get_request_with_connection(
            Endpoint::Process,
            "r300.local",
            "cm86cm8=",
            HttpConnectionMode::KeepAlive,
            &mut tiny
        ),
        Err(BuildHttpRequestError::OutputTooSmall)
    );
    assert_eq!(
        build_put_request(
            Endpoint::Process,
            "r300.local",
            "cndyOnJ3",
            br#"{"heating":{"set":42.125}}"#,
            &mut tiny,
        ),
        Err(BuildHttpRequestError::OutputTooSmall)
    );
    assert_eq!(
        build_put_request_with_connection(
            Endpoint::Process,
            "r300.local\nx",
            "cndyOnJ3",
            br#"{"heating":{"set":42.125}}"#,
            HttpConnectionMode::KeepAlive,
            &mut request,
        ),
        Err(BuildHttpRequestError::InvalidHeaderValue)
    );
}

#[test]
fn http_request_send_cursor_tracks_partial_transport_writes() {
    let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
    let request_len = build_get_request(Endpoint::Process, "r300.local", "cm86cm8=", &mut request)
        .expect("GET request fits");
    let mut cursor =
        HttpRequestSendCursor::new(request_len).expect("non-empty request can be sent");
    assert_eq!(cursor.request_len(), request_len);
    assert_eq!(cursor.sent_len(), 0);
    assert_eq!(cursor.remaining_len(), request_len);
    assert_eq!(
        cursor.remaining_bytes(&request),
        Some(&request[..request_len])
    );

    assert_eq!(
        cursor.advance(5),
        Ok(HttpRequestSendStatus::Pending {
            sent_len: 5,
            remaining_len: request_len - 5,
        })
    );
    assert_eq!(
        cursor.remaining_bytes(&request),
        Some(&request[5..request_len])
    );

    assert_eq!(
        cursor.advance(request_len - 5),
        Ok(HttpRequestSendStatus::Complete {
            sent_len: request_len,
        })
    );
    assert!(cursor.is_complete());
    assert_eq!(
        cursor.remaining_bytes(&request),
        Some(&request[request_len..request_len])
    );
}

#[test]
fn http_request_send_cursor_rejects_invalid_progress() {
    assert_eq!(
        HttpRequestSendCursor::new(0),
        Err(HttpRequestSendError::EmptyRequest)
    );

    let mut cursor = HttpRequestSendCursor::new(10).expect("non-empty request");
    assert_eq!(
        cursor.advance(0),
        Err(HttpRequestSendError::ZeroLengthWrite)
    );
    assert_eq!(
        cursor.advance(11),
        Err(HttpRequestSendError::WriteBeyondRequest)
    );
    assert_eq!(
        cursor.advance(10),
        Ok(HttpRequestSendStatus::Complete { sent_len: 10 })
    );
    assert_eq!(
        cursor.advance(1),
        Err(HttpRequestSendError::WriteBeyondRequest)
    );

    let short_request = [0u8; 5];
    assert_eq!(cursor.remaining_bytes(&short_request), None);
}

#[test]
fn http_exchange_ties_request_send_to_response_receive() {
    let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
    let request_len = build_get_request(Endpoint::Process, "r300.local", "cm86cm8=", &mut request)
        .expect("GET request fits");
    let mut exchange =
        HttpExchange::<128>::new(request_len).expect("non-empty request starts exchange");
    assert_eq!(exchange.phase(), HttpExchangePhase::Sending);
    assert_eq!(exchange.next_write(&request), Ok(&request[..request_len]));

    assert_eq!(
        exchange.record_write(7),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Pending {
                sent_len: 7,
                remaining_len: request_len - 7,
            }
        ))
    );
    assert_eq!(exchange.next_write(&request), Ok(&request[7..request_len]));

    assert_eq!(
        exchange.record_write(request_len - 7),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Complete {
                sent_len: request_len,
            }
        ))
    );
    assert_eq!(exchange.phase(), HttpExchangePhase::Receiving);
    assert_eq!(
        exchange.next_write(&request),
        Err(HttpExchangeError::NotSending)
    );

    assert_eq!(
        exchange.append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n"
        ),
        Ok(HttpExchangeProgress::Receiving(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        exchange.append_response(br#"{"heating":{"act":42.125}}"#),
        Ok(HttpExchangeProgress::Receiving(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        exchange.finish_extra_body_probe(),
        Ok(HttpExchangeProgress::Receiving(HttpReadProgress::Complete))
    );
    assert_eq!(exchange.phase(), HttpExchangePhase::Complete);
    let response = exchange.response().expect("completed response available");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, br#"{"heating":{"act":42.125}}"#);
}

#[test]
fn http_exchange_rejects_wrong_phase_and_short_request_slice() {
    let mut exchange = HttpExchange::<64>::new(10).expect("non-empty request");
    assert_eq!(
        exchange.append_response(b"HTTP/1.1 200 OK\r\n"),
        Err(HttpExchangeError::NotReceiving)
    );
    let short = [0u8; 4];
    assert_eq!(
        exchange.next_write(&short),
        Err(HttpExchangeError::RequestSliceTooShort)
    );
    assert_eq!(
        exchange.record_write(0),
        Err(HttpExchangeError::Send(
            HttpRequestSendError::ZeroLengthWrite
        ))
    );
    assert_eq!(
        exchange.record_write(10),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Complete { sent_len: 10 }
        ))
    );
    assert_eq!(exchange.record_write(1), Err(HttpExchangeError::NotSending));
}

#[test]
fn buchi_get_transaction_builds_sends_receives_and_parses_endpoint_values() {
    let mut transaction =
        BuchiGetTransaction::<256, 160>::new(Endpoint::Process, "r300.local", "cm86cm8=")
            .expect("GET transaction builds");
    assert_eq!(transaction.endpoint(), Endpoint::Process);
    assert_eq!(transaction.phase(), HttpExchangePhase::Sending);
    assert_eq!(
        transaction.request(),
        b"GET /api/v1/process HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cm86cm8=\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(transaction.next_write(), Ok(transaction.request()));

    let first_write = 11;
    assert_eq!(
        transaction.record_write(first_write),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Pending {
                sent_len: first_write,
                remaining_len: transaction.request_len() - first_write,
            }
        ))
    );
    assert_eq!(
        transaction.next_write(),
        Ok(&transaction.request()[first_write..])
    );
    assert_eq!(
        transaction.record_write(transaction.request_len() - first_write),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Complete {
                sent_len: transaction.request_len(),
            }
        ))
    );
    assert_eq!(transaction.phase(), HttpExchangePhase::Receiving);
    assert_eq!(
        transaction.values(),
        Err(BuchiGetTransactionError::Incomplete)
    );

    assert_eq!(
        transaction.append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n"
        ),
        Ok(HttpExchangeProgress::Receiving(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        transaction.append_response(br#"{"heating":{"act":42.125}}"#),
        Ok(HttpExchangeProgress::Receiving(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        transaction.finish_extra_body_probe(),
        Ok(HttpExchangeProgress::Receiving(HttpReadProgress::Complete))
    );
    match transaction.values().expect("completed transaction parses") {
        EndpointValues::Process(values) => {
            assert_eq!(values.bath_temperature_milli_celsius, Some(42_125));
        }
        _ => panic!("wrong endpoint values"),
    }
}

#[test]
fn buchi_get_transaction_reports_build_and_endpoint_failures() {
    assert_eq!(
        BuchiGetTransaction::<16, 128>::new(Endpoint::Process, "r300.local", "cm86cm8=")
            .expect_err("tiny request buffer should fail"),
        BuchiGetTransactionError::Build(BuildHttpRequestError::OutputTooSmall)
    );

    let mut transaction =
        BuchiGetTransaction::<256, 128>::new(Endpoint::Info, "r300.local", "cm86cm8=")
            .expect("GET transaction builds");
    let request_len = transaction.request_len();
    transaction
        .record_write(request_len)
        .expect("request send completes");
    transaction
        .append_response(
            b"HTTP/1.1 503 Busy\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("response reaches probe state");
    transaction
        .finish_extra_body_probe()
        .expect("response completes");
    assert_eq!(
        transaction.values(),
        Err(BuchiGetTransactionError::Endpoint(
            EndpointResponseError::UnexpectedStatus(503)
        ))
    );
}

#[test]
fn buchi_put_transaction_builds_sends_receives_and_parses_endpoint_values() {
    let write_request = WriteRequest {
        target: WriteTarget::SettingsProgramEcoEnabled,
        raw_value: 1,
        node_id: 3014,
        sequence: 7,
    };
    let mut transaction =
        BuchiPutTransaction::<96, 384, 192>::new(write_request, "r300.local", "cndyOnJ3")
            .expect("PUT transaction builds");
    assert_eq!(transaction.write_request(), write_request);
    assert_eq!(transaction.endpoint(), Endpoint::Settings);
    assert_eq!(transaction.body_len(), 38);
    assert_eq!(transaction.phase(), HttpExchangePhase::Sending);
    assert_eq!(
        transaction.request(),
        b"PUT /api/v1/settings HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cndyOnJ3\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"program\":{\"eco\":{\"isEnabled\":true}}}"
    );
    assert_eq!(transaction.next_write(), Ok(transaction.request()));

    let first_write = 23;
    assert_eq!(
        transaction.record_write(first_write),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Pending {
                sent_len: first_write,
                remaining_len: transaction.request_len() - first_write,
            }
        ))
    );
    assert_eq!(
        transaction.next_write(),
        Ok(&transaction.request()[first_write..])
    );
    assert_eq!(
        transaction.record_write(transaction.request_len() - first_write),
        Ok(HttpExchangeProgress::Sending(
            HttpRequestSendStatus::Complete {
                sent_len: transaction.request_len(),
            }
        ))
    );
    assert_eq!(transaction.phase(), HttpExchangePhase::Receiving);
    assert_eq!(
        transaction.values(),
        Err(BuchiPutTransactionError::Incomplete)
    );

    assert_eq!(
        transaction.append_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n"
        ),
        Ok(HttpExchangeProgress::Receiving(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        transaction.append_response(br#"{"program":{"eco":{"isEnabled":true}}}"#),
        Ok(HttpExchangeProgress::Receiving(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        transaction.finish_extra_body_probe(),
        Ok(HttpExchangeProgress::Receiving(HttpReadProgress::Complete))
    );
    assert_eq!(transaction.http_status(), Ok(200));
    assert_eq!(
        transaction.completion_opcua_status(0),
        Ok(opcua_status::GOOD)
    );
    match transaction.values().expect("completed PUT response parses") {
        EndpointValues::Settings(values) => {
            assert_eq!(values.program_eco_enabled, Some(true));
        }
        _ => panic!("wrong endpoint values"),
    }
}

#[test]
fn buchi_put_transaction_reports_body_request_and_endpoint_failures() {
    let write_request = WriteRequest {
        target: WriteTarget::ProcessHeatingSet,
        raw_value: 42_125,
        node_id: 2001,
        sequence: 9,
    };
    assert_eq!(
        BuchiPutTransaction::<8, 384, 128>::new(write_request, "r300.local", "cndyOnJ3")
            .expect_err("tiny body buffer should fail"),
        BuchiPutTransactionError::BuildBody(BuildWriteJsonError::OutputTooSmall)
    );
    assert_eq!(
        BuchiPutTransaction::<96, 64, 128>::new(write_request, "r300.local", "cndyOnJ3")
            .expect_err("tiny request buffer should fail"),
        BuchiPutTransactionError::BuildRequest(BuildHttpRequestError::OutputTooSmall)
    );
    assert_eq!(
        BuchiPutTransaction::<96, 384, 128>::new(
            WriteRequest {
                target: WriteTarget::SettingsProgramEcoEnabled,
                raw_value: 2,
                node_id: 3014,
                sequence: 10,
            },
            "r300.local",
            "cndyOnJ3",
        )
        .expect_err("boolean write values must be zero or one"),
        BuchiPutTransactionError::BuildBody(BuildWriteJsonError::InvalidValue(
            WriteValidationStatus::TypeMismatch
        ))
    );

    let mut transaction =
        BuchiPutTransaction::<96, 384, 128>::new(write_request, "r300.local", "cndyOnJ3")
            .expect("PUT transaction builds");
    transaction
        .record_write(transaction.request_len())
        .expect("request send completes");
    transaction
        .append_response(
            b"HTTP/1.1 503 Busy\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("response reaches probe state");
    transaction
        .finish_extra_body_probe()
        .expect("response completes");
    assert_eq!(transaction.http_status(), Ok(503));
    assert_eq!(
        transaction.completion_opcua_status(0),
        Ok(opcua_status::BAD_RESOURCE_UNAVAILABLE)
    );
    assert_eq!(
        transaction.values(),
        Err(BuchiPutTransactionError::Endpoint(
            EndpointResponseError::UnexpectedStatus(503)
        ))
    );
}

#[test]
fn transport_step_drives_get_transaction_over_scripted_io() {
    let mut transaction =
        BuchiGetTransaction::<256, 160>::new(Endpoint::Process, "r300.local", "cm86cm8=")
            .expect("GET transaction builds");
    let expected_request = *b"GET /api/v1/process HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cm86cm8=\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
    let write_steps = [
        Ok(7),
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
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(HttpRequestSendStatus::Pending {
            sent_len: 7,
            remaining_len: expected_request.len() - 7,
        }))
    );
    assert_eq!(
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::WouldBlock)
    );
    assert_eq!(
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(HttpRequestSendStatus::Complete {
            sent_len: expected_request.len(),
        }))
    );
    assert_eq!(transaction.phase(), HttpExchangePhase::Receiving);
    assert_eq!(
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::Complete))
    );
    assert_eq!(transaction.phase(), HttpExchangePhase::Complete);
    assert_eq!(
        drive_get_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Complete)
    );
    assert_eq!(transport.written(), expected_request);
    match transaction.values().expect("completed GET parses") {
        EndpointValues::Process(values) => {
            assert_eq!(values.bath_temperature_milli_celsius, Some(42_125));
        }
        _ => panic!("wrong endpoint values"),
    }
}

#[test]
fn transport_step_drives_put_transaction_over_scripted_io() {
    let write_request = WriteRequest {
        target: WriteTarget::SettingsProgramEcoEnabled,
        raw_value: 1,
        node_id: 3014,
        sequence: 11,
    };
    let mut transaction =
        BuchiPutTransaction::<96, 384, 192>::new(write_request, "r300.local", "cndyOnJ3")
            .expect("PUT transaction builds");
    let expected_request = b"PUT /api/v1/settings HTTP/1.1\r\nHost: r300.local\r\nAuthorization: Basic cndyOnJ3\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"program\":{\"eco\":{\"isEnabled\":true}}}";
    let write_steps = [Ok(13), Ok(usize::MAX)];
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
        drive_put_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(HttpRequestSendStatus::Pending {
            sent_len: 13,
            remaining_len: expected_request.len() - 13,
        }))
    );
    assert_eq!(
        drive_put_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Sent(HttpRequestSendStatus::Complete {
            sent_len: expected_request.len(),
        }))
    );
    assert_eq!(
        drive_put_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        drive_put_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(
            HttpReadProgress::ProbeForExtraBytes
        ))
    );
    assert_eq!(
        drive_put_transaction_transport_step(&mut transaction, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::Complete))
    );
    assert_eq!(transport.written(), expected_request);
    assert_eq!(transaction.http_status(), Ok(200));
    assert_eq!(
        transaction.completion_opcua_status(0),
        Ok(opcua_status::GOOD)
    );
    match transaction.values().expect("completed PUT parses") {
        EndpointValues::Settings(values) => {
            assert_eq!(values.program_eco_enabled, Some(true));
        }
        _ => panic!("wrong endpoint values"),
    }
}

#[test]
fn transport_step_fails_closed_for_empty_scratch_eof_and_transport_errors() {
    let mut get = BuchiGetTransaction::<256, 160>::new(Endpoint::Process, "r300.local", "cm86cm8=")
        .expect("GET transaction builds");
    let request_len = get.request_len();
    get.record_write(request_len)
        .expect("move to receiving phase");
    let mut transport = ScriptedTransport::new(&[], &[]);
    let mut empty = [];
    assert_eq!(
        drive_get_transaction_transport_step(&mut get, &mut transport, &mut empty),
        Err(BuchiGetTransportError::EmptyReadBuffer)
    );

    let mut truncated =
        BuchiGetTransaction::<256, 160>::new(Endpoint::Process, "r300.local", "cm86cm8=")
            .expect("GET transaction builds");
    let request_len = truncated.request_len();
    truncated
        .record_write(request_len)
        .expect("move to receiving phase");
    let read_steps = [
        Ok(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}"
                .as_slice(),
        ),
        Ok(b"".as_slice()),
    ];
    let mut transport = ScriptedTransport::new(&[], &read_steps);
    let mut scratch = [0u8; 96];
    assert_eq!(
        drive_get_transaction_transport_step(&mut truncated, &mut transport, &mut scratch),
        Ok(BuchiTransportStep::Received(HttpReadProgress::ReadMore))
    );
    assert_eq!(
        drive_get_transaction_transport_step(&mut truncated, &mut transport, &mut scratch),
        Err(BuchiGetTransportError::UnexpectedEof)
    );

    let write_request = WriteRequest {
        target: WriteTarget::ProcessHeatingSet,
        raw_value: 42_125,
        node_id: 2001,
        sequence: 12,
    };
    let mut put = BuchiPutTransaction::<96, 384, 192>::new(write_request, "r300.local", "cndyOnJ3")
        .expect("PUT transaction builds");
    let mut transport = ScriptedTransport::new(&[Err(BuchiTransportIoError::WriteFailed)], &[]);
    assert_eq!(
        drive_put_transaction_transport_step(&mut put, &mut transport, &mut scratch),
        Err(BuchiPutTransportError::Transport(
            BuchiTransportIoError::WriteFailed
        ))
    );
}

#[test]
fn write_status_mappers_match_current_contract() {
    assert_eq!(
        write_validation_status_to_opcua_status(WriteValidationStatus::Ok),
        opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY
    );
    assert_eq!(
        write_validation_status_to_opcua_status(WriteValidationStatus::UnknownTarget),
        opcua_status::BAD_NOT_WRITABLE
    );
    assert_eq!(
        write_validation_status_to_opcua_status(WriteValidationStatus::TypeMismatch),
        opcua_status::BAD_TYPE_MISMATCH
    );
    assert_eq!(
        write_validation_status_to_opcua_status(WriteValidationStatus::OutOfRange),
        opcua_status::BAD_OUT_OF_RANGE
    );

    assert_eq!(
        write_http_status_to_opcua_status(200, 0),
        opcua_status::GOOD
    );
    assert_eq!(
        write_http_status_to_opcua_status(200, -1008),
        opcua_status::BAD_TIMEOUT
    );
    assert_eq!(
        write_http_status_to_opcua_status(400, 0),
        opcua_status::BAD_OUT_OF_RANGE
    );
    assert_eq!(
        write_http_status_to_opcua_status(401, 0),
        opcua_status::BAD_USER_ACCESS_DENIED
    );
    assert_eq!(
        write_http_status_to_opcua_status(503, 0),
        opcua_status::BAD_RESOURCE_UNAVAILABLE
    );
    assert_eq!(
        write_http_status_to_opcua_status(500, -1),
        opcua_status::BAD_COMMUNICATION_ERROR
    );
    assert_eq!(
        write_http_status_to_opcua_status(500, 0),
        opcua_status::BAD_UNEXPECTED_ERROR
    );
}
