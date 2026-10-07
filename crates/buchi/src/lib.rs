// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Fixed-capacity HTTP/JSON and write-request primitives for the R-300
//! OpenInterface `/process`, `/settings`, and `/info` resources.
//!
//! The published OpenInterface schema supplies field names, types, and write
//! ranges. Freshness windows, OPC UA quality mapping, and queue limits are
//! gateway policy owned by `opta-gateway-contracts` and `opta-runtime`. Parsers
//! reject malformed or oversized input rather than truncating it into a sample.

use core::fmt::{self, Write as _};
use core::ops::Range;

use opta_gateway_contracts::{opcua_status, product};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    Process,
    Settings,
    Info,
}

impl Endpoint {
    pub const fn path(self) -> &'static str {
        match self {
            Endpoint::Process => "/api/v1/process",
            Endpoint::Settings => "/api/v1/settings",
            Endpoint::Info => "/api/v1/info",
        }
    }

    pub const fn poll_ms(self) -> u32 {
        match self {
            Endpoint::Process => product::PROCESS_POLL_MS,
            Endpoint::Settings => product::SETTINGS_POLL_MS,
            Endpoint::Info => product::INFO_POLL_MS,
        }
    }

    pub const fn freshness_ms(self) -> u32 {
        match self {
            Endpoint::Process => product::BUCHI_PROCESS_FRESHNESS_MS,
            Endpoint::Settings => product::BUCHI_SETTINGS_FRESHNESS_MS,
            Endpoint::Info => product::BUCHI_INFO_FRESHNESS_MS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpConnectionMode {
    Close,
    KeepAlive,
}

impl HttpConnectionMode {
    const fn header_value(self) -> &'static str {
        match self {
            Self::Close => "close",
            Self::KeepAlive => "keep-alive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollPlan {
    pub process_ms: u32,
    pub settings_ms: u32,
    pub info_ms: u32,
}

impl PollPlan {
    pub const DEFAULT: Self = Self {
        process_ms: product::PROCESS_POLL_MS,
        settings_ms: product::SETTINGS_POLL_MS,
        info_ms: product::INFO_POLL_MS,
    };

    pub const fn is_default_contract(self) -> bool {
        self.process_ms == product::PROCESS_POLL_MS
            && self.settings_ms == product::SETTINGS_POLL_MS
            && self.info_ms == product::INFO_POLL_MS
    }
}

mod http_response;
pub use http_response::{
    check_http_body_size, classify_http_read_progress, compute_http_expected_total_bytes,
    find_unique_http_header_value, http_header_value_is_json_content_type,
    parse_content_length_value, parse_endpoint_http_response, parse_http_response,
    parse_http_status_line, EndpointResponseError, EndpointValues, HttpBodySizeResult,
    HttpHeaderLookup, HttpReadProgress, HttpReceiveBuffer, HttpResponse, HttpResponseError,
    ParseError,
};

mod endpoint_values;
pub use endpoint_values::{
    InfoRootPresence, InfoValues, ProcessRootPresence, ProcessValues, SettingsRootPresence,
    SettingsValues,
};

mod write_specs;
pub use write_specs::{WriteEndpoint, WriteSpec, WriteTarget, WriteValueType, WRITE_SPECS};

mod write_queue;
pub use write_queue::{
    DefaultWriteQueue, WriteQueue, WriteQueuePushResult, WriteRequest, WriteValidationStatus,
};

mod transactions;
pub use transactions::{
    BasicAuthError, BuchiGetTransaction, BuchiGetTransactionError, BuchiPutTransaction,
    BuchiPutTransactionError, BuildHttpRequestError, BuildWriteJsonError,
    DefaultBuchiGetTransaction, DefaultBuchiPutTransaction, HttpExchange, HttpExchangeError,
    HttpExchangePhase, HttpExchangeProgress, HttpRequestSendCursor, HttpRequestSendError,
    HttpRequestSendStatus,
};

mod transport;
pub use transport::{
    drive_get_transaction_transport_step, drive_put_transaction_transport_step,
    BuchiGetTransportError, BuchiPutTransportError, BuchiTransport, BuchiTransportIoError,
    BuchiTransportStep,
};

pub fn lookup_write_spec(target: WriteTarget) -> Option<&'static WriteSpec> {
    if target == WriteTarget::None {
        return None;
    }
    WRITE_SPECS.iter().find(|spec| spec.target == target)
}

pub fn lookup_write_spec_by_node_id(node_id: u16) -> Option<&'static WriteSpec> {
    WRITE_SPECS.iter().find(|spec| spec.node_id == node_id)
}

pub fn validate_write_raw_value(spec: &WriteSpec, raw_value: i32) -> WriteValidationStatus {
    if spec.target == WriteTarget::None {
        return WriteValidationStatus::UnknownTarget;
    }
    if spec.value_type == WriteValueType::Boolean && raw_value != 0 && raw_value != 1 {
        return WriteValidationStatus::TypeMismatch;
    }
    if raw_value < spec.min_raw || raw_value > spec.max_raw {
        return WriteValidationStatus::OutOfRange;
    }
    if spec.multiple_raw > 0 && (raw_value % spec.multiple_raw) != 0 {
        return WriteValidationStatus::OutOfRange;
    }
    WriteValidationStatus::Ok
}

pub fn validate_write_request(target: WriteTarget, raw_value: i32) -> WriteValidationStatus {
    let Some(spec) = lookup_write_spec(target) else {
        return WriteValidationStatus::UnknownTarget;
    };
    validate_write_raw_value(spec, raw_value)
}

pub fn convert_write_float_to_raw_value(spec: &WriteSpec, value: f32) -> Option<i32> {
    if spec.value_type != WriteValueType::Float || spec.scale <= 0 || !value.is_finite() {
        return None;
    }

    let scale = spec.scale as f32;
    let min_value = spec.min_raw as f32 / scale;
    let max_value = spec.max_raw as f32 / scale;
    if value < min_value || value > max_value {
        return None;
    }

    let scaled = value * scale;
    if !scaled.is_finite() || scaled < i32::MIN as f32 || scaled > i32::MAX as f32 {
        return None;
    }

    let raw = if scaled >= 0.0 {
        (scaled + 0.5) as i32
    } else {
        (scaled - 0.5) as i32
    };
    let raw_float = raw as f32;
    let abs_raw = raw_float.abs();
    let tolerance = if abs_raw > 1.0 { abs_raw } else { 1.0 } * (4.0 * f32::EPSILON);
    if (scaled - raw_float).abs() > tolerance {
        return None;
    }

    if validate_write_raw_value(spec, raw) != WriteValidationStatus::Ok {
        return None;
    }

    Some(raw)
}

pub const fn write_validation_status_to_opcua_status(status: WriteValidationStatus) -> u32 {
    match status {
        WriteValidationStatus::Ok => opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY,
        WriteValidationStatus::UnknownTarget => opcua_status::BAD_NOT_WRITABLE,
        WriteValidationStatus::TypeMismatch => opcua_status::BAD_TYPE_MISMATCH,
        WriteValidationStatus::OutOfRange => opcua_status::BAD_OUT_OF_RANGE,
    }
}

pub const fn write_http_status_to_opcua_status(http_status: i32, transport_result: i32) -> u32 {
    if http_status == 200 {
        if transport_result == 0 {
            return opcua_status::GOOD;
        }
        if transport_result == -1008 || transport_result == -1013 {
            return opcua_status::BAD_TIMEOUT;
        }
        if transport_result < 0 {
            return opcua_status::BAD_COMMUNICATION_ERROR;
        }
        return opcua_status::BAD_UNEXPECTED_ERROR;
    }
    if http_status == 400 || http_status == 413 || http_status == 415 {
        return opcua_status::BAD_OUT_OF_RANGE;
    }
    if http_status == 401 || http_status == 403 {
        return opcua_status::BAD_USER_ACCESS_DENIED;
    }
    if http_status == 503 {
        return opcua_status::BAD_RESOURCE_UNAVAILABLE;
    }
    if transport_result == -1008 || transport_result == -1013 {
        return opcua_status::BAD_TIMEOUT;
    }
    if transport_result < 0 {
        return opcua_status::BAD_COMMUNICATION_ERROR;
    }
    opcua_status::BAD_UNEXPECTED_ERROR
}

pub fn build_write_json(
    request: WriteRequest,
    out: &mut [u8],
) -> Result<usize, BuildWriteJsonError> {
    let spec = lookup_write_spec(request.target).ok_or(BuildWriteJsonError::UnknownTarget)?;
    let validation = validate_write_raw_value(spec, request.raw_value);
    if validation != WriteValidationStatus::Ok {
        return Err(BuildWriteJsonError::InvalidValue(validation));
    }

    let mut writer = SliceWriter::new(out);
    write!(writer, "{{\"{}\":", spec.object_key)
        .map_err(|_| BuildWriteJsonError::OutputTooSmall)?;
    if let Some(child_key) = spec.child_key {
        write!(writer, "{{\"{}\":", child_key).map_err(|_| BuildWriteJsonError::OutputTooSmall)?;
    }
    write!(writer, "{{\"{}\":", spec.value_key).map_err(|_| BuildWriteJsonError::OutputTooSmall)?;
    match spec.value_type {
        WriteValueType::Boolean => writer
            .write_str(if request.raw_value == 0 {
                "false"
            } else {
                "true"
            })
            .map_err(|_| BuildWriteJsonError::OutputTooSmall)?,
        WriteValueType::Int32 | WriteValueType::Float => {
            write_raw_json_number(&mut writer, request.raw_value, spec.scale)?;
        }
    }
    writer
        .write_str("}")
        .map_err(|_| BuildWriteJsonError::OutputTooSmall)?;
    if spec.child_key.is_some() {
        writer
            .write_str("}")
            .map_err(|_| BuildWriteJsonError::OutputTooSmall)?;
    }
    writer
        .write_str("}")
        .map_err(|_| BuildWriteJsonError::OutputTooSmall)?;
    Ok(writer.len())
}

pub fn build_get_request(
    endpoint: Endpoint,
    host: &str,
    basic_auth_token: &str,
    out: &mut [u8],
) -> Result<usize, BuildHttpRequestError> {
    build_get_request_with_connection(
        endpoint,
        host,
        basic_auth_token,
        HttpConnectionMode::Close,
        out,
    )
}

pub fn build_get_request_with_connection(
    endpoint: Endpoint,
    host: &str,
    basic_auth_token: &str,
    connection_mode: HttpConnectionMode,
    out: &mut [u8],
) -> Result<usize, BuildHttpRequestError> {
    validate_http_request_parts(host, basic_auth_token)?;
    let mut writer = SliceWriter::new(out);
    write!(
        writer,
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nAccept: application/json\r\nConnection: {}\r\n\r\n",
        endpoint.path(),
        host,
        basic_auth_token,
        connection_mode.header_value()
    )
    .map_err(|_| BuildHttpRequestError::OutputTooSmall)?;
    Ok(writer.len())
}

pub fn build_put_request(
    endpoint: Endpoint,
    host: &str,
    basic_auth_token: &str,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, BuildHttpRequestError> {
    build_put_request_with_connection(
        endpoint,
        host,
        basic_auth_token,
        body,
        HttpConnectionMode::Close,
        out,
    )
}

pub fn build_put_request_with_connection(
    endpoint: Endpoint,
    host: &str,
    basic_auth_token: &str,
    body: &[u8],
    connection_mode: HttpConnectionMode,
    out: &mut [u8],
) -> Result<usize, BuildHttpRequestError> {
    if endpoint == Endpoint::Info {
        return Err(BuildHttpRequestError::UnsupportedMethod);
    }
    validate_http_request_parts(host, basic_auth_token)?;
    if body.is_empty() {
        return Err(BuildHttpRequestError::EmptyBody);
    }

    let mut writer = SliceWriter::new(out);
    write!(
        writer,
        "PUT {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        endpoint.path(),
        host,
        basic_auth_token,
        body.len(),
        connection_mode.header_value()
    )
    .map_err(|_| BuildHttpRequestError::OutputTooSmall)?;
    writer
        .write_bytes(body)
        .map_err(|_| BuildHttpRequestError::OutputTooSmall)?;
    Ok(writer.len())
}

pub const fn basic_auth_token_capacity(username_len: usize, password_len: usize) -> Option<usize> {
    let Some(with_colon) = username_len.checked_add(1) else {
        return None;
    };
    let Some(input_len) = with_colon.checked_add(password_len) else {
        return None;
    };
    let Some(padded) = input_len.checked_add(2) else {
        return None;
    };
    Some((padded / 3) * 4)
}

pub fn build_basic_auth_token(
    username: &str,
    password: &str,
    out: &mut [u8],
) -> Result<usize, BasicAuthError> {
    if username.is_empty() || password.is_empty() {
        return Err(BasicAuthError::EmptyCredential);
    }
    if !username.is_ascii() || !password.is_ascii() {
        return Err(BasicAuthError::NonAscii);
    }
    let encoded_len = basic_auth_token_capacity(username.len(), password.len())
        .ok_or(BasicAuthError::OutputTooSmall)?;
    if out.len() < encoded_len {
        return Err(BasicAuthError::OutputTooSmall);
    }

    let input_len = username.len() + 1 + password.len();
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    while input_index < input_len {
        let b0 = basic_auth_input_byte(username.as_bytes(), password.as_bytes(), input_index)
            .ok_or(BasicAuthError::OutputTooSmall)?;
        let b1 = basic_auth_input_byte(username.as_bytes(), password.as_bytes(), input_index + 1);
        let b2 = basic_auth_input_byte(username.as_bytes(), password.as_bytes(), input_index + 2);
        let v1 = b1.unwrap_or(0);
        let v2 = b2.unwrap_or(0);
        out[output_index] = BASIC_AUTH_BASE64[(b0 >> 2) as usize];
        out[output_index + 1] = BASIC_AUTH_BASE64[(((b0 & 0b0000_0011) << 4) | (v1 >> 4)) as usize];
        out[output_index + 2] = if b1.is_some() {
            BASIC_AUTH_BASE64[(((v1 & 0b0000_1111) << 2) | (v2 >> 6)) as usize]
        } else {
            b'='
        };
        out[output_index + 3] = if b2.is_some() {
            BASIC_AUTH_BASE64[(v2 & 0b0011_1111) as usize]
        } else {
            b'='
        };
        input_index += 3;
        output_index += 4;
    }

    Ok(encoded_len)
}

const BASIC_AUTH_BASE64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn basic_auth_input_byte(username: &[u8], password: &[u8], index: usize) -> Option<u8> {
    if index < username.len() {
        Some(username[index])
    } else if index == username.len() {
        Some(b':')
    } else {
        password.get(index - username.len() - 1).copied()
    }
}

pub fn write_target_name(target: WriteTarget) -> &'static str {
    lookup_write_spec(target)
        .map(|spec| spec.browse_name)
        .unwrap_or("-")
}

fn validate_http_request_parts(
    host: &str,
    basic_auth_token: &str,
) -> Result<(), BuildHttpRequestError> {
    if host.is_empty() {
        return Err(BuildHttpRequestError::EmptyHost);
    }
    if basic_auth_token.is_empty() {
        return Err(BuildHttpRequestError::EmptyAuth);
    }
    if contains_header_line_break(host) || contains_header_line_break(basic_auth_token) {
        return Err(BuildHttpRequestError::InvalidHeaderValue);
    }
    Ok(())
}

fn contains_header_line_break(value: &str) -> bool {
    value.as_bytes().contains(&b'\r') || value.as_bytes().contains(&b'\n')
}

fn write_raw_json_number(
    writer: &mut SliceWriter<'_>,
    raw_value: i32,
    scale: i32,
) -> Result<(), BuildWriteJsonError> {
    if scale == 1 {
        write!(writer, "{}", raw_value).map_err(|_| BuildWriteJsonError::OutputTooSmall)
    } else if scale == 1_000 {
        let negative = raw_value < 0;
        let magnitude = if negative {
            -(raw_value as i64)
        } else {
            raw_value as i64
        };
        let whole = magnitude / scale as i64;
        let fraction = magnitude % scale as i64;
        write!(
            writer,
            "{}{}.{:03}",
            if negative { "-" } else { "" },
            whole,
            fraction
        )
        .map_err(|_| BuildWriteJsonError::OutputTooSmall)
    } else {
        Err(BuildWriteJsonError::UnsupportedScale)
    }
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        let end = self.len.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let Some(target) = self.out.get_mut(self.len..end) else {
            return Err(fmt::Error);
        };
        target.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let bytes = value.as_bytes();
        let end = self.len.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let Some(target) = self.out.get_mut(self.len..end) else {
            return Err(fmt::Error);
        };
        target.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

pub fn parse_process_json(json: &[u8]) -> Result<ProcessValues, ParseError> {
    if json.is_empty() {
        return Err(ParseError::Empty);
    }
    if !looks_like_json_object(json) {
        return Err(ParseError::Malformed);
    }

    let mut out = ProcessValues::default();

    if let Some(heating) = find_root_object(json, b"heating") {
        out.roots.heating = true;
        out.heating_set_milli_celsius =
            parse_number_member(json, heating.clone(), b"set", 1000, 0, 220_000);
        out.bath_temperature_milli_celsius =
            parse_number_member(json, heating.clone(), b"act", 1000, i32::MIN, i32::MAX);
        out.heating_running = parse_bool_or_zero_one_member(json, heating, b"running");
    }
    if let Some(cooling) = find_root_object(json, b"cooling") {
        out.roots.cooling = true;
        out.cooling_set_milli_celsius =
            parse_number_member(json, cooling.clone(), b"set", 1000, -10_000, 25_000);
        out.cooling_actual_milli_celsius =
            parse_number_member(json, cooling.clone(), b"act", 1000, i32::MIN, i32::MAX);
        out.cooling_running = parse_bool_or_zero_one_member(json, cooling, b"running");
    }
    if let Some(vacuum) = find_root_object(json, b"vacuum") {
        out.roots.vacuum = true;
        out.vacuum_set_mbar = parse_number_member(json, vacuum.clone(), b"set", 1, 0, 1_300);
        out.pressure_milli_mbar =
            parse_number_member(json, vacuum.clone(), b"act", 1000, i32::MIN, i32::MAX);
        out.vacuum_aerate_valve_open =
            parse_bool_or_zero_one_member(json, vacuum.clone(), b"aerateValveOpen");
        out.vacuum_aerate_valve_pulse =
            parse_bool_or_zero_one_member(json, vacuum.clone(), b"aerateValvePulse");
        out.vacuum_valve_open =
            parse_bool_or_zero_one_member(json, vacuum.clone(), b"vacuumValveOpen");
        out.vacuum_vapor_temperature_milli_celsius =
            parse_number_member(json, vacuum.clone(), b"vaporTemp", 1000, i32::MIN, i32::MAX);
        out.vacuum_auto_destination_in_milli_celsius = parse_number_member(
            json,
            vacuum.clone(),
            b"autoDestIn",
            1000,
            i32::MIN,
            i32::MAX,
        );
        out.vacuum_auto_destination_out_milli_celsius = parse_number_member(
            json,
            vacuum.clone(),
            b"autoDestOut",
            1000,
            i32::MIN,
            i32::MAX,
        );
        out.vacuum_power_percent_milli_percent =
            parse_integer_member(json, vacuum.clone(), b"powerPercentAct", 1000, 0, 100_000);
        out.vacuum_running = parse_bool_or_zero_one_member(json, vacuum, b"running");
    }
    if let Some(rotation) = find_root_object(json, b"rotation") {
        out.roots.rotation = true;
        out.rotation_set_rpm = parse_number_member(json, rotation.clone(), b"set", 1, 0, 280);
        out.rotation_speed_milli_rpm =
            parse_number_member(json, rotation.clone(), b"act", 1000, 10_000, 280_000);
        out.rotation_running = parse_bool_or_zero_one_member(json, rotation, b"running");
    }
    if let Some(lift) = find_root_object(json, b"lift") {
        out.roots.lift = true;
        out.lift_set_milli_millimeters = parse_number_member_with_multiple(
            json,
            lift.clone(),
            b"set",
            1000,
            0,
            220_000,
            220_000,
        );
        out.lift_actual_milli_millimeters =
            parse_number_member(json, lift.clone(), b"act", 1000, i32::MIN, i32::MAX);
        out.lift_limit_milli_millimeters =
            parse_number_member(json, lift, b"limit", 1000, 20_000, 220_000);
    }
    if let Some(global_status) = find_root_object(json, b"globalStatus") {
        out.roots.global_status = true;
        out.global_status_process_time_seconds =
            parse_unsigned_member(json, global_status.clone(), b"processTime");
        out.global_status_run_id = parse_unsigned_member(json, global_status.clone(), b"runId");
        out.global_status_on_hold =
            parse_bool_or_zero_one_member(json, global_status.clone(), b"onHold");
        out.global_status_foam_active =
            parse_bool_or_zero_one_member(json, global_status.clone(), b"foamActive");
        out.global_status_current_error = parse_integer_member(
            json,
            global_status.clone(),
            b"currentError",
            1,
            i32::MIN,
            i32::MAX,
        );
        out.process_state =
            parse_bool_member(json, global_status, b"running")
                .map(|running| if running { 1 } else { 0 });
    }

    if out.parsed_field_count() == 0 {
        Err(ParseError::NoSupportedFields)
    } else {
        Ok(out)
    }
}

pub fn parse_settings_json(json: &[u8]) -> Result<SettingsValues, ParseError> {
    if json.is_empty() {
        return Err(ParseError::Empty);
    }
    if !looks_like_json_object(json) {
        return Err(ParseError::Malformed);
    }

    let mut out = SettingsValues::default();

    if let Some(display) = find_root_object(json, b"display") {
        out.roots.display = true;
        out.display_brightness_percent =
            parse_integer_member(json, display.clone(), b"brightness", 1, 0, 100);
        out.display_utc_offset_minutes =
            parse_integer_member_with_multiple(json, display, b"utcOffset", 1, -720, 840, 30);
    }
    if let Some(sounds) = find_root_object(json, b"sounds") {
        out.roots.sounds = true;
        out.sounds_button_tone = parse_bool_or_zero_one_member(json, sounds.clone(), b"buttonTone");
        out.sounds_play_sound_on_finish =
            parse_bool_or_zero_one_member(json, sounds, b"playSoundOnFinish");
    }
    if let Some(vacuum) = find_root_object(json, b"vacuum") {
        out.roots.vacuum = true;
        out.vacuum_pressure_hysteresis_mbar =
            parse_number_member(json, vacuum.clone(), b"pressureHysteresis", 1, 0, 200);
        out.vacuum_altitude_meters =
            parse_number_member(json, vacuum.clone(), b"altitude", 1, 0, 4_000);
        out.vacuum_max_perm_pressure_mbar =
            parse_number_member(json, vacuum.clone(), b"maxPermPressure", 1, 0, 1_300);
        out.vacuum_max_pump_output_percent =
            parse_integer_member(json, vacuum.clone(), b"maxPumpOutput", 1, 0, 100);
        out.vacuum_vent_on_finish = parse_bool_or_zero_one_member(json, vacuum, b"ventOnFinish");
    }
    if let Some(rotation) = find_root_object(json, b"rotation") {
        out.roots.rotation = true;
        out.rotation_start_on_start =
            parse_bool_or_zero_one_member(json, rotation.clone(), b"startRotationOnStart");
        out.rotation_stop_on_finish =
            parse_bool_or_zero_one_member(json, rotation, b"stopRotationOnFinish");
    }
    if let Some(heating) = find_root_object(json, b"heating") {
        out.roots.heating = true;
        out.heating_max_temperature_milli_celsius = parse_number_member_in_set(
            json,
            heating.clone(),
            b"maxTemperature",
            1000,
            &[95_000, 180_000, 220_000],
        );
        out.heating_stop_on_finish =
            parse_bool_or_zero_one_member(json, heating, b"stopHeatingOnFinish");
    }
    if let Some(cooling) = find_root_object(json, b"cooling") {
        out.roots.cooling = true;
        out.cooling_stop_on_finish =
            parse_bool_or_zero_one_member(json, cooling, b"stopCoolingOnFinish");
    }
    if let Some(lift) = find_root_object(json, b"lift") {
        out.roots.lift = true;
        out.lift_depth_stop_milli_millimeters =
            parse_number_member(json, lift.clone(), b"depthStop", 1000, 20_000, 220_000);
        out.lift_immerse_on_start =
            parse_bool_or_zero_one_member(json, lift.clone(), b"immerseOnStart");
        out.lift_out_flask_on_finish =
            parse_bool_or_zero_one_member(json, lift, b"liftOutFlaskOnFinish");
    }
    if let Some(program) = find_root_object(json, b"program") {
        out.roots.program = true;
        if let Some(eco) = find_child_object(json, program, b"eco") {
            out.program_eco_enabled =
                parse_bool_or_zero_one_member(json, eco.clone(), b"isEnabled");
            out.program_eco_activation_after_mins =
                parse_integer_member(json, eco.clone(), b"activationAfterMins", 1, 5, 100);
            out.program_eco_heating_bath_temperature_milli_celsius = parse_number_member(
                json,
                eco.clone(),
                b"heatingBathTemperature",
                1000,
                3_000,
                200_000,
            );
            out.program_eco_coolant_temperature_milli_celsius =
                parse_number_member(json, eco, b"coolantTemperature", 1000, 3_000, 50_000);
        }
    }

    if out.parsed_field_count() == 0 {
        Err(ParseError::NoSupportedFields)
    } else {
        Ok(out)
    }
}

pub fn parse_info_json(json: &[u8]) -> Result<InfoValues, ParseError> {
    if json.is_empty() {
        return Err(ParseError::Empty);
    }
    if !looks_like_json_object(json) {
        return Err(ParseError::Malformed);
    }

    let mut out = InfoValues::default();

    if let Some(controller) = find_root_object(json, b"controller") {
        out.roots.controller = true;
        out.controller_operating_time_hours = parse_integer_member(
            json,
            controller.clone(),
            b"operatingTimeCounter",
            1,
            0,
            i32::MAX,
        );
        if let Some(run_counters) = find_child_object(json, controller, b"runCounters") {
            out.controller_run_total_runs =
                parse_integer_member(json, run_counters.clone(), b"totalRuns", 1, 0, i32::MAX);
            out.controller_run_manual =
                parse_integer_member(json, run_counters.clone(), b"manual", 1, 0, i32::MAX);
            out.controller_run_timer =
                parse_integer_member(json, run_counters.clone(), b"timer", 1, 0, i32::MAX);
            out.controller_run_continuous =
                parse_integer_member(json, run_counters.clone(), b"continuous", 1, 0, i32::MAX);
            out.controller_run_solvent =
                parse_integer_member(json, run_counters.clone(), b"solvent", 1, 0, i32::MAX);
            out.controller_run_method =
                parse_integer_member(json, run_counters.clone(), b"method", 1, 0, i32::MAX);
            out.controller_run_auto_dest =
                parse_integer_member(json, run_counters.clone(), b"autoDest", 1, 0, i32::MAX);
            out.controller_run_cloud_dest =
                parse_integer_member(json, run_counters.clone(), b"cloudDest", 1, 0, i32::MAX);
            out.controller_run_drying =
                parse_integer_member(json, run_counters.clone(), b"drying", 1, 0, i32::MAX);
            out.controller_run_leak_test =
                parse_integer_member(json, run_counters.clone(), b"leakTest", 1, 0, i32::MAX);
            out.controller_run_calibration =
                parse_integer_member(json, run_counters, b"calibration", 1, 0, i32::MAX);
        }
    }
    if let Some(bath) = find_root_object(json, b"bath") {
        out.roots.bath = true;
        out.bath_operating_time_hours =
            parse_integer_member(json, bath.clone(), b"operatingTimeCounter", 1, 0, i32::MAX);
        out.bath_hours_over_190c =
            parse_integer_member(json, bath, b"hoursOver190C", 1, 0, i32::MAX);
    }
    if let Some(chiller) = find_root_object(json, b"chiller") {
        out.roots.chiller = true;
        out.chiller_operating_time_hours = parse_integer_member(
            json,
            chiller.clone(),
            b"operatingTimeCounter",
            1,
            0,
            i32::MAX,
        );
        out.chiller_pump_hours =
            parse_integer_member(json, chiller.clone(), b"pumpHours", 1, 0, i32::MAX);
        out.chiller_compressor_hours =
            parse_integer_member(json, chiller.clone(), b"compressorHours", 1, 0, i32::MAX);
        out.chiller_valve_counter =
            parse_integer_member(json, chiller, b"valveCounter", 1, 0, i32::MAX);
    }
    if let Some(rotavapor) = find_root_object(json, b"rotavapor") {
        out.roots.rotavapor = true;
        out.rotavapor_operating_time_hours = parse_integer_member(
            json,
            rotavapor.clone(),
            b"operatingTimeCounter",
            1,
            0,
            i32::MAX,
        );
        out.rotavapor_rotation_hours =
            parse_integer_member(json, rotavapor.clone(), b"rotationHours", 1, 0, i32::MAX);
        out.rotavapor_lift_moves =
            parse_integer_member(json, rotavapor, b"liftMoves", 1, 0, i32::MAX);
    }
    if let Some(pump) = find_root_object(json, b"pump") {
        out.roots.pump = true;
        out.pump_operating_time_hours =
            parse_integer_member(json, pump.clone(), b"operatingTimeCounter", 1, 0, i32::MAX);
        if let Some(module1) = find_child_object(json, pump.clone(), b"module1") {
            out.pump_module1_switch_on =
                parse_integer_member(json, module1.clone(), b"switchOn", 1, 0, i32::MAX);
            out.pump_module1_over_current_milli_count =
                parse_number_member(json, module1.clone(), b"overCurrent", 1000, 0, i32::MAX);
            out.pump_module1_max_current_milli_amps =
                parse_number_member(json, module1.clone(), b"maxCurrent", 1000, 0, i32::MAX);
            out.pump_module1_max_temperature_milli_celsius =
                parse_number_member(json, module1, b"maxTemperature", 1000, i32::MIN, i32::MAX);
        }
        if let Some(module2) = find_child_object(json, pump, b"module2") {
            out.pump_module2_switch_on =
                parse_integer_member(json, module2.clone(), b"switchOn", 1, 0, i32::MAX);
            out.pump_module2_over_current_milli_count =
                parse_number_member(json, module2.clone(), b"overCurrent", 1000, 0, i32::MAX);
            out.pump_module2_max_current_milli_amps =
                parse_number_member(json, module2.clone(), b"maxCurrent", 1000, 0, i32::MAX);
            out.pump_module2_max_temperature_milli_celsius =
                parse_number_member(json, module2, b"maxTemperature", 1000, i32::MIN, i32::MAX);
        }
    }
    if let Some(vacubox) = find_root_object(json, b"vacubox") {
        out.roots.vacubox = true;
        out.vacubox_operating_time_hours =
            parse_integer_member(json, vacubox, b"operatingTimeCounter", 1, 0, i32::MAX);
    }

    if out.parsed_field_count() == 0 {
        Err(ParseError::NoSupportedFields)
    } else {
        Ok(out)
    }
}

fn looks_like_json_object(input: &[u8]) -> bool {
    let Some(first) = input.iter().position(|byte| !byte.is_ascii_whitespace()) else {
        return false;
    };
    let Some(last) = input.iter().rposition(|byte| !byte.is_ascii_whitespace()) else {
        return false;
    };
    input[first] == b'{' && input[last] == b'}' && balanced_braces_and_strings(&input[first..=last])
}

fn balanced_braces_and_strings(input: &[u8]) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    for byte in input {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            _ => {}
        }
    }
    !in_string && depth == 0
}

fn find_root_object(input: &[u8], key: &[u8]) -> Option<Range<usize>> {
    find_child_object(input, root_range(input)?, key)
}

fn find_child_object(input: &[u8], object: Range<usize>, key: &[u8]) -> Option<Range<usize>> {
    find_member_value(input, object, key).and_then(|range| object_value_range(input, range.start))
}

fn root_range(input: &[u8]) -> Option<Range<usize>> {
    let start = input.iter().position(|byte| !byte.is_ascii_whitespace())?;
    if input.get(start) != Some(&b'{') {
        return None;
    }
    object_value_range(input, start)
}

fn find_member_value(input: &[u8], object: Range<usize>, key: &[u8]) -> Option<Range<usize>> {
    let mut index = object.start + 1;
    while index < object.end.saturating_sub(1) {
        skip_ws(input, &mut index);
        if input.get(index) == Some(&b'}') {
            return None;
        }
        let key_range = string_range(input, index)?;
        index = key_range.end + 1;
        skip_ws(input, &mut index);
        if input.get(index) != Some(&b':') {
            return None;
        }
        index += 1;
        skip_ws(input, &mut index);
        let value = value_range(input, index)?;
        if bytes_eq(&input[key_range.clone()], key) {
            return Some(value);
        }
        index = value.end;
        skip_ws(input, &mut index);
        if input.get(index) == Some(&b',') {
            index += 1;
        }
    }
    None
}

fn parse_number_member(
    input: &[u8],
    object: Range<usize>,
    key: &[u8],
    scale: i32,
    min_raw: i32,
    max_raw: i32,
) -> Option<i32> {
    parse_number_member_with_multiple(input, object, key, scale, min_raw, max_raw, 0)
}

fn parse_number_member_with_multiple(
    input: &[u8],
    object: Range<usize>,
    key: &[u8],
    scale: i32,
    min_raw: i32,
    max_raw: i32,
    multiple_raw: i32,
) -> Option<i32> {
    let range = find_member_value(input, object, key)?;
    let value = parse_scaled_number(&input[range], scale)?;
    is_within_raw_range(value, min_raw, max_raw, multiple_raw).then_some(value)
}

fn parse_number_member_in_set(
    input: &[u8],
    object: Range<usize>,
    key: &[u8],
    scale: i32,
    allowed_raw_values: &[i32],
) -> Option<i32> {
    let range = find_member_value(input, object, key)?;
    let value = parse_scaled_number(&input[range], scale)?;
    allowed_raw_values.contains(&value).then_some(value)
}

fn parse_integer_member(
    input: &[u8],
    object: Range<usize>,
    key: &[u8],
    scale: i32,
    min_raw: i32,
    max_raw: i32,
) -> Option<i32> {
    parse_integer_member_with_multiple(input, object, key, scale, min_raw, max_raw, 0)
}

fn parse_integer_member_with_multiple(
    input: &[u8],
    object: Range<usize>,
    key: &[u8],
    scale: i32,
    min_raw: i32,
    max_raw: i32,
    multiple_raw: i32,
) -> Option<i32> {
    let range = find_member_value(input, object, key)?;
    let value = parse_scaled_integer(&input[range], scale)?;
    is_within_raw_range(value, min_raw, max_raw, multiple_raw).then_some(value)
}

fn parse_unsigned_member(input: &[u8], object: Range<usize>, key: &[u8]) -> Option<u32> {
    let range = find_member_value(input, object, key)?;
    parse_unsigned_integer(&input[range])
}

fn parse_bool_member(input: &[u8], object: Range<usize>, key: &[u8]) -> Option<bool> {
    let range = find_member_value(input, object, key)?;
    parse_bool_token(&input[range])
}

fn parse_bool_or_zero_one_member(input: &[u8], object: Range<usize>, key: &[u8]) -> Option<bool> {
    let range = find_member_value(input, object, key)?;
    let raw = trim_ascii(&input[range]);
    parse_bool_token(raw).or_else(|| {
        if raw == b"1" {
            Some(true)
        } else if raw == b"0" {
            Some(false)
        } else {
            None
        }
    })
}

fn parse_bool_token(input: &[u8]) -> Option<bool> {
    let raw = trim_ascii(input);
    if raw == b"true" {
        Some(true)
    } else if raw == b"false" {
        Some(false)
    } else {
        None
    }
}

fn is_within_raw_range(value: i32, min_raw: i32, max_raw: i32, multiple_raw: i32) -> bool {
    value >= min_raw && value <= max_raw && (multiple_raw <= 0 || value % multiple_raw == 0)
}

fn parse_scaled_integer(input: &[u8], scale: i32) -> Option<i32> {
    if scale <= 0 {
        return None;
    }
    let value = parse_signed_integer(input)? as i64;
    let scaled = value.checked_mul(scale as i64)?;
    i32::try_from(scaled).ok()
}

fn parse_signed_integer(input: &[u8]) -> Option<i32> {
    let bytes = trim_ascii(input);
    if bytes.is_empty() {
        return None;
    }
    let mut index = 0usize;
    let negative = bytes.get(index) == Some(&b'-');
    if negative {
        index += 1;
    }
    let mut value: i64 = 0;
    let mut saw_digit = false;
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_digit() {
            return None;
        }
        saw_digit = true;
        value = value.checked_mul(10)?.checked_add((byte - b'0') as i64)?;
        index += 1;
    }
    if !saw_digit {
        return None;
    }
    let signed = if negative { -value } else { value };
    i32::try_from(signed).ok()
}

fn parse_unsigned_integer(input: &[u8]) -> Option<u32> {
    let bytes = trim_ascii(input);
    if bytes.is_empty() || bytes.first() == Some(&b'-') {
        return None;
    }
    let mut value: u64 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
        if value > u32::MAX as u64 {
            return None;
        }
    }
    u32::try_from(value).ok()
}

fn parse_scaled_number(input: &[u8], scale: i32) -> Option<i32> {
    if scale <= 0 {
        return None;
    }
    let bytes = trim_ascii(input);
    if bytes.is_empty() {
        return None;
    }

    let mut index = 0usize;
    let negative = bytes.get(index) == Some(&b'-');
    if negative {
        index += 1;
    }

    let mut whole: i64 = 0;
    let mut saw_digit = false;
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_digit() {
            break;
        }
        saw_digit = true;
        whole = whole.checked_mul(10)?.checked_add((byte - b'0') as i64)?;
        index += 1;
    }
    if !saw_digit {
        return None;
    }

    let mut frac = 0i64;
    let mut frac_scale = 1i64;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let mut saw_frac = false;
        while let Some(byte) = bytes.get(index) {
            if !byte.is_ascii_digit() {
                break;
            }
            saw_frac = true;
            if frac_scale < scale as i64 {
                frac = frac.checked_mul(10)?.checked_add((byte - b'0') as i64)?;
                frac_scale *= 10;
            } else if *byte != b'0' {
                return None;
            }
            index += 1;
        }
        if !saw_frac {
            return None;
        }
    }
    if index != bytes.len() {
        return None;
    }

    while frac_scale < scale as i64 {
        frac = frac.checked_mul(10)?;
        frac_scale *= 10;
    }
    if scale == 1 && frac != 0 {
        return None;
    }

    let raw = whole.checked_mul(scale as i64)?.checked_add(frac)?;
    let signed = if negative { -raw } else { raw };
    i32::try_from(signed).ok()
}

fn object_value_range(input: &[u8], start: usize) -> Option<Range<usize>> {
    if input.get(start) != Some(&b'{') {
        return None;
    }
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut index = start;
    while index < input.len() {
        let byte = input[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth = depth.checked_add(1)?,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start..index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn value_range(input: &[u8], start: usize) -> Option<Range<usize>> {
    match input.get(start)? {
        b'{' => object_value_range(input, start),
        b'"' => {
            let content = string_range(input, start)?;
            Some(start..content.end + 1)
        }
        _ => {
            let mut end = start;
            while end < input.len() && input[end] != b',' && input[end] != b'}' {
                end += 1;
            }
            Some(start..end)
        }
    }
}

fn string_range(input: &[u8], start: usize) -> Option<Range<usize>> {
    if input.get(start) != Some(&b'"') {
        return None;
    }
    let mut index = start + 1;
    let mut escaped = false;
    while index < input.len() {
        let byte = input[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(start + 1..index);
        }
        index += 1;
    }
    None
}

fn skip_ws(input: &[u8], index: &mut usize) {
    while input.get(*index).is_some_and(u8::is_ascii_whitespace) {
        *index += 1;
    }
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

fn bytes_eq(left: &[u8], right: &[u8]) -> bool {
    left == right
}

struct HeaderLines<'a> {
    remaining: &'a [u8],
    finished: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedHttpHeaders {
    status: i32,
    expected_total_bytes: usize,
}

fn parse_received_http_headers(
    header_block: &[u8],
    body_offset: usize,
    response_limit: usize,
) -> Result<ParsedHttpHeaders, HttpResponseError> {
    if header_block.is_empty() {
        return Err(HttpResponseError::StatusLineMissing);
    }
    let (status_line, headers) = if let Some(status_line_end) = find_crlf(header_block) {
        (
            &header_block[..status_line_end],
            &header_block[status_line_end + 2..],
        )
    } else {
        (header_block, &[][..])
    };
    if status_line.is_empty() {
        return Err(HttpResponseError::StatusLineMissing);
    }
    let status = parse_http_status_line(status_line).ok_or(HttpResponseError::InvalidStatusLine)?;

    match find_unique_http_header_value(headers, b"Transfer-Encoding") {
        HttpHeaderLookup::Missing => {}
        HttpHeaderLookup::Found(_) => return Err(HttpResponseError::UnsupportedTransferEncoding),
        HttpHeaderLookup::Duplicate => return Err(HttpResponseError::DuplicateTransferEncoding),
    }
    match find_unique_http_header_value(headers, b"Content-Encoding") {
        HttpHeaderLookup::Missing => {}
        HttpHeaderLookup::Found(_) => return Err(HttpResponseError::UnsupportedContentEncoding),
        HttpHeaderLookup::Duplicate => return Err(HttpResponseError::DuplicateContentEncoding),
    }

    if status == 200 {
        match find_unique_http_header_value(headers, b"Content-Type") {
            HttpHeaderLookup::Found(value) => {
                if !http_header_value_is_json_content_type(value) {
                    return Err(HttpResponseError::UnexpectedContentType);
                }
            }
            HttpHeaderLookup::Missing => return Err(HttpResponseError::MissingContentType),
            HttpHeaderLookup::Duplicate => return Err(HttpResponseError::DuplicateContentType),
        }
    }

    let content_length = match find_unique_http_header_value(headers, b"Content-Length") {
        HttpHeaderLookup::Found(value) => {
            parse_content_length_value(value).ok_or(HttpResponseError::InvalidContentLength)?
        }
        HttpHeaderLookup::Missing => return Err(HttpResponseError::MissingContentLength),
        HttpHeaderLookup::Duplicate => return Err(HttpResponseError::DuplicateContentLength),
    };
    let expected_total_bytes =
        compute_http_expected_total_bytes(body_offset, content_length, response_limit)
            .ok_or(HttpResponseError::ResponseTooLarge)?;

    Ok(ParsedHttpHeaders {
        status,
        expected_total_bytes,
    })
}

impl<'a> HeaderLines<'a> {
    fn new(headers: &'a [u8]) -> Self {
        Self {
            remaining: headers,
            finished: false,
        }
    }
}

impl<'a> Iterator for HeaderLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(index) = find_crlf(self.remaining) {
            let line = &self.remaining[..index];
            self.remaining = &self.remaining[index + 2..];
            Some(line)
        } else {
            self.finished = true;
            Some(self.remaining)
        }
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(2)
        .position(|window| window[0] == b'\r' && window[1] == b'\n')
}

fn find_header_body_split(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| {
            let body_offset = index + 4;
            (index, body_offset)
        })
}

fn trim_http_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| is_http_whitespace(*byte)) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| is_http_whitespace(*byte)) {
        value = &value[..value.len() - 1];
    }
    value
}

fn eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

const fn is_http_whitespace(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn consume_one_or_more_digits(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    if !bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    Some(cursor)
}

#[cfg(test)]
mod tests;
