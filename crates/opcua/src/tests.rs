use super::*;

mod accelerated;
#[cfg(feature = "diagnostic-protocol-identifiers")]
mod protocol_diagnostic;

fn test_identity() -> ServerIdentity {
    ServerIdentity::from_uid_words([0x01020304, 0x05060708, 0x090A0B0C])
}
use opta_buchi::{EndpointValues, ProcessRootPresence, ProcessValues};
use opta_gateway_contracts::{
    config::{ConfigKey, GatewayConfig, TrustState},
    namespace, opcua_status, product,
};
use opta_runtime::{
    DefaultRuntimeDataAccess, RuntimeNode, SingleCoreHealthSnapshot, DEFAULT_NAMESPACE_NODES,
    SINGLE_CORE_TASK_HEALTH_SLOT_COUNT,
};

const TEST_BUILD_INFO: BuildInfo = BuildInfo::new(
    "Host test fixture",
    "1.0.0",
    "sha1:0123456789012345678901234567890123456789;product;clean",
    116444736000000000,
);

const TEST_REQUEST_TIMESTAMP: i64 = 134_269_920_000_000_000; // 2026-06-27T00:00:00Z

fn verified_data_access() -> DefaultRuntimeDataAccess {
    let mut data_access = DefaultRuntimeDataAccess::new();
    data_access.set_trust_state(TrustState::Verified);
    data_access
}

fn install_test_session_token(server: &mut OpcUaServer) {
    server.session_token = NodeId::numeric(APPLICATION_NAMESPACE_INDEX, DEFAULT_SESSION_TOKEN_SEED);
    server.session_token_minted = true;
}

fn activate_test_session(server: &mut OpcUaServer) {
    install_test_session_token(server);
    server.session_active = true;
    server.session_timeout_ms = DEFAULT_SESSION_TIMEOUT_MS;
    server.last_session_activity_ms = 0;
}

fn contains_bytes(haystack: &[u8], needle: [u8; 4]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hello_frame(endpoint_url: &str) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let mut e = Encoder::new(&mut buf);
    e.write_bytes(b"HELF").unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(65_535).unwrap();
    e.write_u32(65_535).unwrap();
    e.write_u32(65_535).unwrap();
    e.write_u32(1).unwrap();
    e.write_string(endpoint_url).unwrap();
    let len = e.len();
    e.patch_u32(4, len as u32).unwrap();
    buf[..len].to_vec()
}

fn client_uasc_request(
    body_type: u32,
    request_handle: u32,
    body: impl FnOnce(&mut Encoder<'_>) -> Result<()>,
) -> std::vec::Vec<u8> {
    client_uasc_request_with_auth(
        body_type,
        request_handle,
        NodeId::numeric(APPLICATION_NAMESPACE_INDEX, 7001),
        body,
    )
}

fn client_uasc_request_with_auth(
    body_type: u32,
    request_handle: u32,
    authentication_token: NodeId,
    body: impl FnOnce(&mut Encoder<'_>) -> Result<()>,
) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 65_535];
    let mut e = Encoder::new(&mut buf);
    e.write_bytes(b"MSGF").unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(1).unwrap();
    e.write_u32(1).unwrap();
    e.write_u32(1).unwrap();
    e.write_u32(request_handle).unwrap();
    e.write_node_id(NodeId::numeric(0, body_type)).unwrap();
    write_request_header_for_test_with_token(&mut e, request_handle, authentication_token).unwrap();
    body(&mut e).unwrap();
    let len = e.len();
    e.patch_u32(4, len as u32).unwrap();
    buf[..len].to_vec()
}

fn client_open_secure_channel_request(request_id: u32, request_handle: u32) -> std::vec::Vec<u8> {
    client_open_secure_channel_request_with_timestamp(
        request_id,
        request_handle,
        TEST_REQUEST_TIMESTAMP,
    )
}

fn client_open_secure_channel_request_with_timestamp(
    request_id: u32,
    request_handle: u32,
    request_timestamp: i64,
) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let mut e = Encoder::new(&mut buf);
    e.write_bytes(b"OPNF").unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(0).unwrap();
    e.write_string(SECURITY_POLICY_NONE).unwrap();
    e.write_null_byte_string().unwrap();
    e.write_null_byte_string().unwrap();
    e.write_u32(1).unwrap();
    e.write_u32(request_id).unwrap();
    e.write_node_id(NodeId::numeric(0, service_id::OPEN_SECURE_CHANNEL_REQUEST))
        .unwrap();
    write_request_header_for_test_with_timestamp(&mut e, request_handle, request_timestamp)
        .unwrap();
    e.write_u32(0).unwrap();
    e.write_i32(0).unwrap();
    e.write_i32(1).unwrap();
    e.write_null_byte_string().unwrap();
    e.write_u32(60_000).unwrap();
    let len = e.len();
    e.patch_u32(4, len as u32).unwrap();
    buf[..len].to_vec()
}

fn client_close_secure_channel_request(
    token_id: u32,
    request_id: u32,
    request_handle: u32,
) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let mut e = Encoder::new(&mut buf);
    e.write_bytes(b"CLOF").unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(1).unwrap();
    e.write_u32(token_id).unwrap();
    e.write_u32(1).unwrap();
    e.write_u32(request_id).unwrap();
    e.write_node_id(NodeId::numeric(0, service_id::CLOSE_SECURE_CHANNEL_REQUEST))
        .unwrap();
    write_request_header_for_test_with_token(
        &mut e,
        request_handle,
        NodeId::numeric(APPLICATION_NAMESPACE_INDEX, 7001),
    )
    .unwrap();
    let len = e.len();
    e.patch_u32(4, len as u32).unwrap();
    buf[..len].to_vec()
}

fn write_request_header_for_test_with_timestamp(
    e: &mut Encoder<'_>,
    request_handle: u32,
    request_timestamp: i64,
) -> Result<()> {
    write_request_header_for_test_with_token_timestamp(
        e,
        request_handle,
        NodeId::numeric(APPLICATION_NAMESPACE_INDEX, 7001),
        request_timestamp,
    )
}

fn write_request_header_for_test_with_token(
    e: &mut Encoder<'_>,
    request_handle: u32,
    authentication_token: NodeId,
) -> Result<()> {
    write_request_header_for_test_with_token_timestamp(
        e,
        request_handle,
        authentication_token,
        TEST_REQUEST_TIMESTAMP,
    )
}

fn write_request_header_for_test_with_token_timestamp(
    e: &mut Encoder<'_>,
    request_handle: u32,
    authentication_token: NodeId,
    request_timestamp: i64,
) -> Result<()> {
    e.write_node_id(authentication_token)?;
    e.write_i64(request_timestamp)?;
    e.write_u32(request_handle)?;
    e.write_u32(0)?;
    e.write_null_string()?;
    e.write_u32(0)?;
    e.write_extension_object_none()
}

fn seed(data_access: &mut DefaultRuntimeDataAccess) {
    for now in [1_000, 2_000, 3_000] {
        let values = ProcessValues {
            roots: ProcessRootPresence {
                heating: true,
                cooling: true,
                vacuum: true,
                rotation: true,
                lift: true,
                global_status: true,
            },
            heating_set_milli_celsius: Some(42_500),
            cooling_actual_milli_celsius: Some(10_250),
            pressure_milli_mbar: Some(950_000),
            ..Default::default()
        };
        data_access.apply_endpoint_values(EndpointValues::Process(values), now);
    }
}

fn seed_frozen_heating_set(data_access: &mut DefaultRuntimeDataAccess, published_at_ms: u64) {
    data_access.apply_endpoint_values(
        EndpointValues::Process(ProcessValues {
            roots: ProcessRootPresence {
                heating: true,
                global_status: true,
                ..ProcessRootPresence::default()
            },
            heating_set_milli_celsius: Some(42_500),
            bath_temperature_milli_celsius: Some(41_875),
            process_state: Some(1),
            ..ProcessValues::default()
        }),
        published_at_ms,
    );
}

fn handle_frame_len(
    server: &mut OpcUaServer,
    request: &[u8],
    out: &mut [u8],
    data_access: &mut DefaultRuntimeDataAccess,
    freshness_now_ms: u64,
) -> usize {
    server
        .handle_frame(request, out, data_access, freshness_now_ms)
        .unwrap()
        .response_len()
        .expect("frame action sends a response")
}

fn decode_response_header_for_test(d: &mut Decoder<'_>) -> (i64, u32, u32) {
    let timestamp = d.read_i64().unwrap();
    let request_handle = d.read_u32().unwrap();
    let service_result = d.read_u32().unwrap();
    assert_eq!(d.read_u8().unwrap(), 0); // DiagnosticInfo encoding mask: none.
    assert_eq!(d.read_i32().unwrap(), -1); // stringTable: null array.
    assert_eq!(d.read_node_id().unwrap(), NodeId::numeric(0, 0));
    assert_eq!(d.read_u8().unwrap(), 0); // additionalHeader: no body.
    (timestamp, request_handle, service_result)
}

fn decode_application_uri_for_test(d: &mut Decoder<'_>) -> std::vec::Vec<u8> {
    let uri = d.read_byte_string().unwrap().unwrap().to_vec();
    d.skip_string().unwrap();
    d.skip_localized_text().unwrap();
    d.read_i32().unwrap();
    d.skip_string().unwrap();
    d.skip_string().unwrap();
    d.skip_string_array(MAX_REQUESTED_NODES).unwrap();
    uri
}

fn assert_service_fault_for_test(response: &[u8], expected_status: u32) {
    let (info, mut d, _) = decode_uasc_prefix(response).unwrap();
    assert_eq!(info.service_type_id, service_id::SERVICE_FAULT_RESPONSE);
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, expected_status);
}

fn decode_write_statuses_for_test(response: &[u8]) -> std::vec::Vec<u32> {
    let (info, mut d, _) = decode_uasc_prefix(response).unwrap();
    assert_eq!(info.service_type_id, service_id::WRITE_RESPONSE);
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, opcua_status::GOOD);
    let count = d.read_array_len(MAX_REQUESTED_NODES).unwrap();
    let mut statuses = std::vec::Vec::with_capacity(count);
    for _ in 0..count {
        statuses.push(d.read_u32().unwrap());
    }
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0);
    statuses
}

fn create_session_token_for_test(response: &[u8]) -> NodeId {
    let (info, mut d, _) = decode_uasc_prefix(response).unwrap();
    assert_eq!(info.service_type_id, service_id::CREATE_SESSION_RESPONSE);
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, opcua_status::GOOD);
    let _session_id = d.read_node_id().unwrap();
    d.read_node_id().unwrap()
}

#[derive(Debug, Eq, PartialEq)]
struct PublishSummary {
    request_handle: u32,
    service_result: u32,
    subscription_id: u32,
    sequence_number: u32,
    publish_time: i64,
    notification_data_len: usize,
    monitored_item_count: usize,
    ack_result_count: usize,
}

fn decode_publish_summary_for_test(response: &[u8]) -> PublishSummary {
    let (info, mut d, _) = decode_uasc_prefix(response).unwrap();
    assert_eq!(info.service_type_id, service_id::PUBLISH_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    let subscription_id = d.read_u32().unwrap();
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0); // no retransmission queue
    assert!(!d.read_bool().unwrap()); // moreNotifications
    let sequence_number = d.read_u32().unwrap();
    let publish_time = d.read_i64().unwrap();
    let notification_data_len = d.read_array_len(MAX_REQUESTED_NODES).unwrap();
    let mut monitored_item_count = 0usize;
    for _ in 0..notification_data_len {
        let type_id = d.read_node_id().unwrap();
        assert_eq!(
            type_id,
            NodeId::numeric(0, service_id::DATA_CHANGE_NOTIFICATION)
        );
        assert_eq!(d.read_u8().unwrap(), 1);
        let body_len = d.read_i32().unwrap();
        assert!(body_len >= 0);
        let body_end = d.position() + body_len as usize;
        let item_count = d.read_array_len(MAX_REQUESTED_NODES).unwrap();
        monitored_item_count += item_count;
        for _ in 0..item_count {
            let _client_handle = d.read_u32().unwrap();
            skip_data_value_for_test(&mut d);
        }
        assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0); // diagnosticInfos
        assert_eq!(d.position(), body_end);
    }
    let ack_result_count = d.read_array_len(MAX_REQUESTED_NODES).unwrap();
    for _ in 0..ack_result_count {
        assert_eq!(
            d.read_u32().unwrap(),
            status::GOOD_RETRANSMISSION_QUEUE_NOT_SUPPORTED
        );
    }
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0); // diagnosticInfos
    PublishSummary {
        request_handle,
        service_result,
        subscription_id,
        sequence_number,
        publish_time,
        notification_data_len,
        monitored_item_count,
        ack_result_count,
    }
}

fn decode_data_value_status_and_presence_for_test(d: &mut Decoder<'_>) -> (u32, bool) {
    let mask = d.read_u8().unwrap();
    let has_value = mask & DATA_VALUE_HAS_VALUE != 0;
    if has_value {
        skip_variant_for_test(d);
    }
    let status = if mask & DATA_VALUE_HAS_STATUS != 0 {
        d.read_u32().unwrap()
    } else {
        opcua_status::GOOD
    };
    if mask & DATA_VALUE_HAS_SOURCE_TIMESTAMP != 0 {
        let _ = d.read_i64().unwrap();
    }
    if mask & DATA_VALUE_HAS_SOURCE_PICOSECONDS != 0 {
        let _ = d.read_u16().unwrap();
    }
    if mask & DATA_VALUE_HAS_SERVER_TIMESTAMP != 0 {
        let _ = d.read_i64().unwrap();
    }
    if mask & DATA_VALUE_HAS_SERVER_PICOSECONDS != 0 {
        let _ = d.read_u16().unwrap();
    }
    (status, has_value)
}

fn skip_data_value_for_test(d: &mut Decoder<'_>) {
    let _ = decode_data_value_status_and_presence_for_test(d);
}

fn skip_variant_for_test(d: &mut Decoder<'_>) {
    let encoding = d.read_u8().unwrap();
    assert_eq!(encoding & VARIANT_ARRAY_BIT, 0);
    match encoding {
        VARIANT_BOOLEAN => {
            let _ = d.read_bool().unwrap();
        }
        VARIANT_BYTE => {
            let _ = d.read_u8().unwrap();
        }
        VARIANT_INT32 => {
            let _ = d.read_i32().unwrap();
        }
        VARIANT_UINT32 => {
            let _ = d.read_u32().unwrap();
        }
        VARIANT_FLOAT => {
            let _ = d.read_f32().unwrap();
        }
        VARIANT_STRING => {
            let _ = d.read_byte_string().unwrap();
        }
        VARIANT_DATETIME => {
            let _ = d.read_i64().unwrap();
        }
        VARIANT_NODEID => {
            let _ = d.read_node_id().unwrap();
        }
        VARIANT_QUALIFIED_NAME => {
            let _ = d.read_qualified_name().unwrap();
        }
        VARIANT_LOCALIZED_TEXT => {
            let mask = d.read_u8().unwrap();
            if mask & 0x01 != 0 {
                let _ = d.read_byte_string().unwrap();
            }
            if mask & 0x02 != 0 {
                let _ = d.read_byte_string().unwrap();
            }
        }
        other => panic!("unsupported test variant encoding {other}"),
    }
}

fn create_subscription_frame(
    request_handle: u32,
    interval_ms: f64,
    lifetime: u32,
    keepalive: u32,
    publishing_enabled: bool,
) -> std::vec::Vec<u8> {
    client_uasc_request(
        service_id::CREATE_SUBSCRIPTION_REQUEST,
        request_handle,
        |e| {
            e.write_f64(interval_ms)?;
            e.write_u32(lifetime)?;
            e.write_u32(keepalive)?;
            e.write_u32(0)?;
            e.write_bool(publishing_enabled)?;
            e.write_u8(0)
        },
    )
}

fn modify_subscription_frame(
    request_handle: u32,
    interval_ms: f64,
    lifetime: u32,
    keepalive: u32,
) -> std::vec::Vec<u8> {
    client_uasc_request(
        service_id::MODIFY_SUBSCRIPTION_REQUEST,
        request_handle,
        |e| {
            e.write_u32(1)?;
            e.write_f64(interval_ms)?;
            e.write_u32(lifetime)?;
            e.write_u32(keepalive)?;
            e.write_u32(0)?;
            e.write_u8(0)
        },
    )
}

fn publish_frame(request_handle: u32) -> std::vec::Vec<u8> {
    client_uasc_request(service_id::PUBLISH_REQUEST, request_handle, |e| {
        e.write_array_len(0)
    })
}

#[test]
fn hello_ack_golden_frame() {
    let mut hel = [0u8; 128];
    let mut e = Encoder::new(&mut hel);
    e.write_bytes(b"HELF").unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(0).unwrap();
    e.write_u32(65_535).unwrap();
    e.write_u32(65_535).unwrap();
    e.write_u32(65_535).unwrap();
    e.write_u32(1).unwrap();
    e.write_string("opc.tcp://127.0.0.1:4840").unwrap();
    let len = e.len();
    e.patch_u32(4, len as u32).unwrap();
    let hello = decode_hello(&hel[..len]).unwrap();
    assert_eq!(hello.receive_buffer_size, 65_535);
    let mut ack = [0u8; 64];
    let ack_len = encode_ack(&mut ack, AcknowledgeMessage::default()).unwrap();
    assert_eq!(&ack[..8], b"ACKF\x1c\x00\x00\x00");
    assert_eq!(ack_len, 28);
}

#[test]
fn target_transport_limits_are_advertised_and_enforced() {
    let mut server = OpcUaServer::new_with_limits(
        test_identity(),
        &TEST_BUILD_INFO,
        TransportLimits::product_target(),
    );
    let mut data_access = DefaultRuntimeDataAccess::new();
    let hello = hello_frame("opc.tcp://192.0.2.230:4840");
    let mut out = [0u8; 256];
    let len = handle_frame_len(&mut server, &hello, &mut out, &mut data_access, 0);
    assert_eq!(&out[..8], b"ACKF\x1c\x00\x00\x00");
    let mut d = Decoder::new(&out[8..len]);
    assert_eq!(d.read_u32().unwrap(), 0);
    assert_eq!(d.read_u32().unwrap(), PRODUCT_TARGET_BUFFER_SIZE);
    assert_eq!(d.read_u32().unwrap(), PRODUCT_TARGET_BUFFER_SIZE);
    assert_eq!(d.read_u32().unwrap(), PRODUCT_TARGET_BUFFER_SIZE);
    assert_eq!(d.read_u32().unwrap(), DEFAULT_MAX_CHUNK_COUNT);

    let mut oversized = *b"MSGF\x01@\x00\x00";
    oversized[4..8].copy_from_slice(&(PRODUCT_TARGET_BUFFER_SIZE + 1).to_le_bytes());
    let action = server
        .handle_frame(&oversized, &mut out, &mut data_access, 0)
        .unwrap();
    let len = match action {
        FrameAction::SendResponseThenClose(len) => len,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(&out[..4], b"ERRF");
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TCP_MESSAGE_TOO_LARGE.to_le_bytes()
    ));
}

#[test]
fn oversized_or_chunked_frames_fail_closed() {
    let mut frame = *b"MSGF\x08\x00\x00\x00";
    frame[3] = b'C';
    assert_eq!(parse_frame_header(&frame), Err(OpcUaError::Unsupported));
    let frame = *b"MSGF\xff\xff\x01\x00";
    assert_eq!(parse_frame_header(&frame), Err(OpcUaError::Truncated));
}

#[test]
fn transport_faults_return_errf_then_close() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 1024];
    let frame = *b"BADF\x08\x00\x00\x00";
    let action = server
        .handle_frame(&frame, &mut out, &mut data_access, 0)
        .unwrap();
    let len = match action {
        FrameAction::SendResponseThenClose(len) => len,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(&out[..4], b"ERRF");
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TCP_MESSAGE_TYPE_INVALID.to_le_bytes()
    ));

    let mut oversize = *b"MSGF\x00\x00\x01\x00";
    let action = server
        .handle_frame(&oversize, &mut out, &mut data_access, 0)
        .unwrap();
    let len = match action {
        FrameAction::SendResponseThenClose(len) => len,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(&out[..4], b"ERRF");
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TCP_MESSAGE_TOO_LARGE.to_le_bytes()
    ));

    oversize[3] = b'C';
    let action = server
        .handle_frame(&oversize[..8], &mut out, &mut data_access, 0)
        .unwrap();
    assert!(action.closes_connection());
}

#[test]
fn hello_endpoint_overflow_returns_tcp_error() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let endpoint = "opc.tcp://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz:4840";
    assert!(endpoint.len() > MAX_ENDPOINT_URL_LEN);
    let hello = hello_frame(endpoint);
    let mut out = [0u8; 1024];
    let action = server
        .handle_frame(&hello, &mut out, &mut data_access, 0)
        .unwrap();
    let len = match action {
        FrameAction::SendResponseThenClose(len) => len,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(&out[..4], b"ERRF");
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TCP_ENDPOINT_URL_INVALID.to_le_bytes()
    ));
}

#[test]
fn open_secure_channel_accepts_unwrapped_uasc_service_body() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_open_secure_channel_request(1_001, 17);
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(&out[..4], b"OPNF");
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::OPEN_SECURE_CHANNEL_RESPONSE
    );
    let (response_timestamp, request_handle, service_result) =
        decode_response_header_for_test(&mut d);
    assert_eq!(response_timestamp, TEST_REQUEST_TIMESTAMP);
    assert_eq!(request_handle, 17);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_u32().unwrap(), 0); // ServerProtocolVersion.
    assert_eq!(d.read_u32().unwrap(), 1); // SecureChannelId.
    assert_eq!(d.read_u32().unwrap(), 2); // TokenId after first Issue.
    assert_eq!(d.read_i64().unwrap(), TEST_REQUEST_TIMESTAMP);
    assert_eq!(d.read_u32().unwrap(), 60_000);
    assert!(d.read_byte_string().unwrap().is_none());
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_SERVICE_UNSUPPORTED.to_le_bytes()
    ));
}

#[test]
fn open_secure_channel_extends_lifetime_for_null_request_timestamp() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_open_secure_channel_request_with_timestamp(1_002, 18, 0);
    let mut out = [0u8; 8192];
    let now_monotonic_ms = 123_456_u32;
    let expected_created_at = NULL_TIMESTAMP_CHANNEL_EPOCH_UTC
        + i64::from(now_monotonic_ms) * OPCUA_DATETIME_TICKS_PER_MILLISECOND;
    let len = handle_frame_len(
        &mut server,
        &request,
        &mut out,
        &mut data_access,
        u64::from(now_monotonic_ms),
    );
    assert_eq!(&out[..4], b"OPNF");
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::OPEN_SECURE_CHANNEL_RESPONSE
    );
    let (response_timestamp, request_handle, service_result) =
        decode_response_header_for_test(&mut d);
    assert_eq!(response_timestamp, expected_created_at);
    assert_eq!(request_handle, 18);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_u32().unwrap(), 0); // ServerProtocolVersion.
    assert_eq!(d.read_u32().unwrap(), 1); // SecureChannelId.
    assert_eq!(d.read_u32().unwrap(), 2); // TokenId after first Issue.
    assert_eq!(d.read_i64().unwrap(), expected_created_at);
    assert_eq!(d.read_u32().unwrap(), NULL_TIMESTAMP_TOKEN_LIFETIME_MS);
    assert!(d.read_byte_string().unwrap().is_none());
}

#[test]
fn close_secure_channel_closes_without_response() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];

    let open = client_open_secure_channel_request(1_003, 19);
    let open_len = handle_frame_len(&mut server, &open, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..open_len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::OPEN_SECURE_CHANNEL_RESPONSE
    );
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_u32().unwrap(), 0); // ServerProtocolVersion.
    assert_eq!(d.read_u32().unwrap(), 1); // SecureChannelId.
    assert_eq!(d.read_u32().unwrap(), 2); // TokenId after first Issue.

    let close = client_close_secure_channel_request(2, 1_004, 20);
    let action = server
        .handle_frame(&close, &mut out, &mut data_access, 0)
        .unwrap();
    assert_eq!(action, FrameAction::Close);
    assert_eq!(action.response_len(), None);
    assert!(action.closes_connection());
}

#[test]
fn discovery_services_return_server_descriptions_without_session() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let endpoint_url = "opc.tcp://localhost:4840";

    let hello = hello_frame(endpoint_url);
    let len = handle_frame_len(&mut server, &hello, &mut out, &mut data_access, 0);
    assert_eq!(
        &out[..len],
        b"ACKF\x1c\x00\x00\x00\0\0\0\0\xff\xff\0\0\xff\xff\0\0\xff\xff\0\0\x01\0\0\0"
    );

    let find_servers = client_uasc_request(service_id::FIND_SERVERS_REQUEST, 13, |e| {
        e.write_string(endpoint_url)?;
        e.write_array_len(0)?;
        e.write_array_len(0)
    });
    let len = handle_frame_len(&mut server, &find_servers, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::FIND_SERVERS_RESPONSE);
    assert!(contains_slice(&out[..len], APPLICATION_NAME.as_bytes()));
    assert!(contains_slice(&out[..len], endpoint_url.as_bytes()));
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_SERVICE_UNSUPPORTED.to_le_bytes()
    ));

    let get_endpoints = client_uasc_request(service_id::GET_ENDPOINTS_REQUEST, 14, |e| {
        e.write_string(endpoint_url)?;
        e.write_array_len(0)?;
        e.write_array_len(0)
    });
    let len = handle_frame_len(&mut server, &get_endpoints, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::GET_ENDPOINTS_RESPONSE);
    assert!(contains_slice(&out[..len], endpoint_url.as_bytes()));
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 14);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_array_len(4).unwrap(), 1);
    assert_eq!(d.read_byte_string().unwrap(), Some(endpoint_url.as_bytes()));
    assert_eq!(
        decode_application_uri_for_test(&mut d),
        test_identity().application_uri().as_bytes()
    );
    assert!(d.read_byte_string().unwrap().is_none()); // serverCertificate
    assert_eq!(d.read_i32().unwrap(), 1); // MessageSecurityMode::None
    assert_eq!(
        d.read_byte_string().unwrap(),
        Some(SECURITY_POLICY_NONE.as_bytes())
    );
    assert_eq!(d.read_array_len(4).unwrap(), 1);
    assert_eq!(d.read_byte_string().unwrap(), Some(b"anonymous".as_slice()));
    assert_eq!(d.read_i32().unwrap(), 0); // UserTokenType::Anonymous
    assert!(d.read_byte_string().unwrap().is_none()); // issuedTokenType
    assert!(d.read_byte_string().unwrap().is_none()); // issuerEndpointUrl
    assert!(d.read_byte_string().unwrap().is_none()); // securityPolicyUri
    assert_eq!(
        d.read_byte_string().unwrap(),
        Some(TRANSPORT_PROFILE_URI.as_bytes())
    );
    assert_eq!(d.read_u8().unwrap(), 0);

    let find_on_network =
        client_uasc_request(service_id::FIND_SERVERS_ON_NETWORK_REQUEST, 15, |e| {
            e.write_u32(0)?;
            e.write_u32(0)?;
            e.write_array_len(0)
        });
    let len = handle_frame_len(&mut server, &find_on_network, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::FIND_SERVERS_ON_NETWORK_RESPONSE
    );
    assert!(contains_slice(&out[..len], endpoint_url.as_bytes()));
}

#[test]
fn find_servers_filters_exact_identity_and_consumes_full_filter() {
    let identity = test_identity();
    let uri = identity.application_uri();
    let lowercase_uri = uri.to_ascii_lowercase();
    for (filters, expected) in [
        (vec![Some(uri)], 1),
        (vec![Some("urn:foreign")], 0),
        (vec![Some(uri), Some("urn:foreign")], 1),
        (vec![Some("urn:foreign"), Some(uri)], 1),
        (vec![Some(lowercase_uri.as_str())], 0),
        (vec![], 1),
        (vec![Some(uri), Some(uri)], 1),
        (vec![None], 0),
    ] {
        let mut server = OpcUaServer::new(identity, &TEST_BUILD_INFO);
        let mut data_access = DefaultRuntimeDataAccess::new();
        let mut out = [0u8; 8192];
        let hello = hello_frame("opc.tcp://localhost:4840");
        handle_frame_len(&mut server, &hello, &mut out, &mut data_access, 0);
        let request = client_uasc_request(service_id::FIND_SERVERS_REQUEST, 13, |e| {
            e.write_string("opc.tcp://localhost:4840")?;
            e.write_array_len(0)?;
            e.write_array_len(filters.len())?;
            for filter in filters.iter().copied() {
                match filter {
                    Some(value) => e.write_string(value)?,
                    None => e.write_null_string()?,
                }
            }
            Ok(())
        });
        let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
        let (_, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
        let (_, _, status) = decode_response_header_for_test(&mut d);
        assert_eq!(status, opcua_status::GOOD);
        assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), expected);
        if expected == 1 {
            assert_eq!(decode_application_uri_for_test(&mut d), uri.as_bytes());
        }
    }

    let mut server = OpcUaServer::new(identity, &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    handle_frame_len(
        &mut server,
        &hello_frame("opc.tcp://localhost:4840"),
        &mut out,
        &mut data_access,
        0,
    );
    let null_filter = client_uasc_request(service_id::FIND_SERVERS_REQUEST, 13, |e| {
        e.write_string("opc.tcp://localhost:4840")?;
        e.write_array_len(0)?;
        e.write_i32(-1)
    });
    let len = handle_frame_len(&mut server, &null_filter, &mut out, &mut data_access, 0);
    let (_, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    let (_, _, status) = decode_response_header_for_test(&mut d);
    assert_eq!(status, opcua_status::GOOD);
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 1);

    let malformed = client_uasc_request(service_id::FIND_SERVERS_REQUEST, 13, |e| {
        e.write_string("opc.tcp://localhost:4840")?;
        e.write_array_len(0)?;
        e.write_array_len(2)?;
        e.write_string(uri)?;
        e.write_i32(4)?;
        e.write_u8(b'x')
    });
    assert!(matches!(
        server.handle_frame(&malformed, &mut out, &mut data_access, 0),
        Err(OpcUaError::Truncated)
    ));

    let oversized = client_uasc_request(service_id::FIND_SERVERS_REQUEST, 13, |e| {
        e.write_string("opc.tcp://localhost:4840")?;
        e.write_array_len(0)?;
        e.write_i32((MAX_REQUESTED_NODES + 1) as i32)
    });
    assert!(matches!(
        server.handle_frame(&oversized, &mut out, &mut data_access, 0),
        Err(OpcUaError::Unsupported)
    ));
}

#[test]
fn standard_type_cache_nodes_have_basic_attributes() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::READ_REQUEST, 16, |e| {
        e.write_f64(0.0)?;
        e.write_i32(3)?;
        e.write_array_len(12)?;
        for node_id in [
            NODEID_ORGANIZES,
            NODEID_HAS_COMPONENT,
            NODEID_BASE_OBJECT_TYPE,
            NODEID_FOLDER_TYPE,
            NODEID_BASE_DATA_VARIABLE_TYPE,
            DATATYPE_BOOLEAN,
        ] {
            for attr in [ATTR_NODECLASS, ATTR_BROWSENAME] {
                e.write_node_id(NodeId::numeric(0, node_id))?;
                e.write_u32(attr)?;
                e.write_null_string()?;
                e.write_qualified_name(0, "")?;
            }
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_NODE_ID_UNKNOWN.to_le_bytes()
    ));
    assert!(contains_slice(&out[..len], b"Organizes"));
    assert!(contains_slice(&out[..len], b"HasComponent"));
    assert!(contains_slice(&out[..len], b"BaseObjectType"));
    assert!(contains_slice(&out[..len], b"FolderType"));
    assert!(contains_slice(&out[..len], b"BaseDataVariableType"));
    assert!(contains_slice(&out[..len], b"Boolean"));
}

#[test]
fn read_accepts_uatexpert_sized_type_cache_batches() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let requested_values = 960;
    assert!(requested_values <= MAX_REQUESTED_NODES);
    let type_nodes = [
        NODEID_ORGANIZES,
        NODEID_HAS_COMPONENT,
        NODEID_BASE_OBJECT_TYPE,
        NODEID_FOLDER_TYPE,
        NODEID_BASE_DATA_VARIABLE_TYPE,
        DATATYPE_BOOLEAN,
        DATATYPE_INT32,
        DATATYPE_UINT32,
        DATATYPE_FLOAT,
        DATATYPE_STRING,
        DATATYPE_DATETIME,
        DATATYPE_SERVER_STATUS,
    ];
    let attrs = [ATTR_NODECLASS, ATTR_BROWSENAME, ATTR_DISPLAYNAME];
    let request = client_uasc_request(service_id::READ_REQUEST, 17, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(requested_values)?;
        for i in 0..requested_values {
            let node = type_nodes[(i / attrs.len()) % type_nodes.len()];
            let attr = attrs[i % attrs.len()];
            e.write_node_id(NodeId::numeric(0, node))?;
            e.write_u32(attr)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let mut out = [0u8; 65_535];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_NODE_ID_UNKNOWN.to_le_bytes()
    ));
}

#[test]
fn target_sized_bulk_read_response_returns_service_fault_without_closing() {
    let mut server = OpcUaServer::new_with_limits(
        test_identity(),
        &TEST_BUILD_INFO,
        TransportLimits::product_target(),
    );
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let requested_values = 512;
    assert!(requested_values <= MAX_BULK_SERVICE_OPERATIONS);
    let request = client_uasc_request(service_id::READ_REQUEST, 117, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(requested_values)?;
        for i in 0..requested_values {
            let node = if i % 2 == 0 {
                NODEID_BASE_DATA_VARIABLE_TYPE
            } else {
                NODEID_SERVER_STATUS_CURRENT_TIME
            };
            e.write_node_id(NodeId::numeric(0, node))?;
            e.write_u32(ATTR_DISPLAYNAME)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    assert!(request.len() < PRODUCT_TARGET_BUFFER_SIZE as usize);
    let mut out = [0u8; PRODUCT_TARGET_BUFFER_SIZE as usize];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::SERVICE_FAULT_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 117);
    assert_eq!(service_result, status::BAD_RESPONSE_TOO_LARGE);

    let small_read = client_uasc_request(service_id::READ_REQUEST, 118, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(0, NODEID_SERVER_STATUS_CURRENT_TIME))?;
        e.write_u32(ATTR_DISPLAYNAME)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")
    });
    let len = handle_frame_len(&mut server, &small_read, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    assert!(contains_slice(&out[..len], b"CurrentTime"));
}

#[test]
fn over_budget_bulk_read_returns_too_many_operations_fault() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let requested_values = MAX_BULK_SERVICE_OPERATIONS + 1;
    assert!(requested_values <= MAX_REQUESTED_NODES);
    let request = client_uasc_request(service_id::READ_REQUEST, 119, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(requested_values)?;
        for _ in 0..requested_values {
            e.write_node_id(NodeId::numeric(0, NODEID_SERVER_STATUS_CURRENT_TIME))?;
            e.write_u32(ATTR_DISPLAYNAME)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::SERVICE_FAULT_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 119);
    assert_eq!(service_result, status::BAD_TOO_MANY_OPERATIONS);
}

#[test]
fn direct_read_encodes_bad_without_value_after_freshness_wrap_alias() {
    const EPOCH_MS: u64 = 1_u64 << 32;
    const PUBLISHED_AT_MS: u64 = 123_456;
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    seed_frozen_heating_set(&mut data_access, PUBLISHED_AT_MS);
    let request = client_uasc_request(service_id::READ_REQUEST, 118, |e| {
        e.write_f64(0.0)?;
        e.write_i32(3)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(
        &mut server,
        &request,
        &mut out,
        &mut data_access,
        PUBLISHED_AT_MS + EPOCH_MS,
    );

    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 118);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 1);
    let (status, has_value) = decode_data_value_status_and_presence_for_test(&mut d);
    assert_eq!(status, opcua_status::BAD_WAITING_FOR_INITIAL_DATA);
    assert!(
        !has_value,
        "stale direct Read must not encode a scalar value"
    );
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0);
}

#[test]
fn browse_accepts_inverse_has_subtype_parent_queries() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::BROWSE_REQUEST, 18, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(3)?;
        for node in [
            NODEID_FOLDER_TYPE,
            NODEID_BASE_DATA_VARIABLE_TYPE,
            NODEID_HAS_COMPONENT,
        ] {
            e.write_node_id(NodeId::numeric(0, node))?;
            e.write_i32(1)?;
            e.write_node_id(NodeId::numeric(0, NODEID_HAS_SUBTYPE))?;
            e.write_bool(true)?;
            e.write_u32(0)?;
            e.write_u32(63)?;
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_REFERENCE_TYPE_ID_INVALID.to_le_bytes()
    ));
    assert!(contains_slice(&out[..len], b"BaseObjectType"));
    assert!(contains_slice(&out[..len], b"BaseVariableType"));
    assert!(contains_slice(&out[..len], b"Aggregates"));
}

#[test]
fn extension_object_skip_accepts_expanded_type_ids_and_xml_bodies() {
    let mut buf = [0u8; 64];
    let mut e = Encoder::new(&mut buf);
    e.write_u8(0x80).unwrap(); // TwoByte NodeId with NamespaceUri flag.
    e.write_u8(0).unwrap();
    e.write_string("urn:opta:test").unwrap();
    e.write_u8(2).unwrap(); // XmlElement body encoding, which is length-delimited.
    e.write_byte_string(b"<Filter/>").unwrap();
    let len = e.len();

    let mut d = Decoder::new(&buf[..len]);
    d.skip_extension_object().unwrap();
    assert_eq!(d.position(), len);
}

#[test]
fn read_seeded_runtime_node_returns_good_value() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    seed(&mut data_access);
    let request = client_uasc_request(service_id::READ_REQUEST, 7, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 3_000);
    assert_eq!(&out[..4], b"MSGF");
    assert!(len > 32);
    assert!(contains_bytes(&out[..len], 42.5f32.to_le_bytes()));
}

#[test]
fn read_exposes_single_core_health_nodes() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::READ_REQUEST, 71, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(3)?;
        for node_id in [4022, 4042, 4037] {
            e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, node_id))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(&out[..4], b"MSGF");
    assert!(contains_bytes(
        &out[..len],
        opcua_status::BAD_NO_DATA.to_le_bytes()
    ));
    assert!(contains_bytes(
        &out[..len],
        status::BAD_NODE_ID_UNKNOWN.to_le_bytes()
    ));

    let mut ages = [None; SINGLE_CORE_TASK_HEALTH_SLOT_COUNT];
    ages[5] = Some(70);
    data_access.set_single_core_health(SingleCoreHealthSnapshot::new(
        12_345,
        Some(15),
        0,
        0b10_0000,
        0b10_0000,
        2_000,
        ages,
    ));
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 12_345);
    assert!(contains_bytes(&out[..len], 12_345u32.to_le_bytes()));
    assert!(contains_bytes(&out[..len], 70u32.to_le_bytes()));
}

#[test]
fn browse_exposes_single_core_health_names_without_m4_placeholders() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::BROWSE_REQUEST, 72, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(
            PRODUCT_NAMESPACE_INDEX,
            PRODUCT_OBJECT_HEALTH as u32,
        ))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, NODEID_HAS_COMPONENT))?;
        e.write_bool(true)?;
        e.write_u32(NODECLASS_VARIABLE as u32)?;
        e.write_u32(RESULT_MASK_BROWSE_NAME | RESULT_MASK_DISPLAY_NAME)
    });
    let mut out = [0u8; 16_384];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(contains_slice(&out[..len], b"Health.UptimeSeconds"));
    assert!(contains_slice(
        &out[..len],
        b"Health.TaskCheckin.OpcUaServerAgeMs"
    ));
    assert!(!contains_slice(&out[..len], b"Health.M4StatusValid"));
}

#[test]
fn target_limits_handle_recursive_buchi_browse_read_and_monitor_setup() {
    let mut server = OpcUaServer::new_with_limits(
        test_identity(),
        &TEST_BUILD_INFO,
        TransportLimits::product_target(),
    );
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; PRODUCT_TARGET_BUFFER_SIZE as usize];

    for (request_handle, node) in [
        NodeId::numeric(0, NODEID_OBJECTS_FOLDER),
        NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_BUCHI as u32),
        NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_INFO as u32),
        NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_PROCESS as u32),
        NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_SETTINGS as u32),
        NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_HEALTH as u32),
    ]
    .into_iter()
    .enumerate()
    {
        let request = client_uasc_request(
            service_id::BROWSE_REQUEST,
            130 + request_handle as u32,
            |e| {
                e.write_node_id(NodeId::numeric(0, 0))?;
                e.write_i64(0)?;
                e.write_u32(0)?;
                e.write_u32(0)?;
                e.write_array_len(1)?;
                e.write_node_id(node)?;
                e.write_i32(0)?;
                e.write_node_id(NodeId::numeric(0, 0))?;
                e.write_bool(true)?;
                e.write_u32(0)?;
                e.write_u32(63)
            },
        );
        let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
        let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
        assert_eq!(info.service_type_id, service_id::BROWSE_RESPONSE);
        assert!(!contains_bytes(
            &out[..len],
            status::BAD_RESPONSE_TOO_LARGE.to_le_bytes()
        ));
    }

    let read_all = client_uasc_request(service_id::READ_REQUEST, 140, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(DEFAULT_NAMESPACE_NODES.len())?;
        for node in DEFAULT_NAMESPACE_NODES.iter() {
            e.write_node_id(NodeId::numeric(
                PRODUCT_NAMESPACE_INDEX,
                u32::from(node.node_id),
            ))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let len = handle_frame_len(&mut server, &read_all, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_RESPONSE_TOO_LARGE.to_le_bytes()
    ));

    server.subscription_active = true;
    let monitor_all = client_uasc_request(service_id::CREATE_MONITORED_ITEMS_REQUEST, 141, |e| {
        e.write_u32(1)?;
        e.write_i32(3)?;
        e.write_array_len(DEFAULT_NAMESPACE_NODES.len())?;
        for (i, node) in DEFAULT_NAMESPACE_NODES.iter().enumerate() {
            e.write_node_id(NodeId::numeric(
                PRODUCT_NAMESPACE_INDEX,
                u32::from(node.node_id),
            ))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
            e.write_i32(1)?;
            e.write_u32(i as u32 + 1)?;
            e.write_f64(1000.0)?;
            e.write_extension_object_none()?;
            e.write_u32(1)?;
            e.write_bool(true)?;
        }
        Ok(())
    });
    let len = handle_frame_len(&mut server, &monitor_all, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::CREATE_MONITORED_ITEMS_RESPONSE
    );
    assert_eq!(server.subscription.len(), DEFAULT_NAMESPACE_NODES.len());
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_RESPONSE_TOO_LARGE.to_le_bytes()
    ));
}

#[test]
fn read_probe_decoder_reports_first_read_node() {
    let request = client_uasc_request(service_id::READ_REQUEST, 171, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")
    });
    assert_eq!(
        decode_first_read_value_node(&request).unwrap(),
        Some(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))
    );

    let browse = client_uasc_request(service_id::BROWSE_REQUEST, 172, |e| e.write_null_array());
    assert_eq!(decode_first_read_value_node(&browse).unwrap(), None);
}

#[test]
fn session_bound_services_return_fault_until_activated_and_validate_token() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    install_test_session_token(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let read = client_uasc_request(service_id::READ_REQUEST, 31, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(0)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &read, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::SERVICE_FAULT_RESPONSE);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_SESSION_NOT_ACTIVATED.to_le_bytes()
    ));

    activate_test_session(&mut server);
    let wrong_token_read = client_uasc_request_with_auth(
        service_id::READ_REQUEST,
        32,
        NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 7999),
        |e| {
            e.write_f64(0.0)?;
            e.write_i32(2)?;
            e.write_array_len(0)
        },
    );
    let len = handle_frame_len(
        &mut server,
        &wrong_token_read,
        &mut out,
        &mut data_access,
        0,
    );
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::SERVICE_FAULT_RESPONSE);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_SESSION_ID_INVALID.to_le_bytes()
    ));
}

#[test]
fn activate_session_before_create_rejects_sentinel_token() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let activate = client_uasc_request_with_auth(
        service_id::ACTIVATE_SESSION_REQUEST,
        34,
        NodeId::numeric(APPLICATION_NAMESPACE_INDEX, SESSION_TOKEN_SENTINEL_ID),
        |_| Ok(()),
    );
    let mut out = [0u8; 1024];
    let len = handle_frame_len(&mut server, &activate, &mut out, &mut data_access, 0);
    assert_service_fault_for_test(&out[..len], status::BAD_SESSION_ID_INVALID);
}

#[test]
fn close_session_invalidates_authentication_token() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 2048];

    let create = client_uasc_request(service_id::CREATE_SESSION_REQUEST, 35, |_| Ok(()));
    let len = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    let token = create_session_token_for_test(&out[..len]);

    let activate =
        client_uasc_request_with_auth(service_id::ACTIVATE_SESSION_REQUEST, 36, token, |_| Ok(()));
    let len = handle_frame_len(&mut server, &activate, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::ACTIVATE_SESSION_RESPONSE);

    let close =
        client_uasc_request_with_auth(service_id::CLOSE_SESSION_REQUEST, 37, token, |_| Ok(()));
    let len = handle_frame_len(&mut server, &close, &mut out, &mut data_access, 0);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::CLOSE_SESSION_RESPONSE);

    let stale_activate =
        client_uasc_request_with_auth(service_id::ACTIVATE_SESSION_REQUEST, 38, token, |_| Ok(()));
    let len = handle_frame_len(&mut server, &stale_activate, &mut out, &mut data_access, 0);
    assert_service_fault_for_test(&out[..len], status::BAD_SESSION_ID_INVALID);
}

#[test]
fn create_session_ignores_every_server_uri_and_returns_exact_identity() {
    let identity = test_identity();
    let endpoint_url = "opc.tcp://localhost:4840";
    for requested_uri in [
        None,
        Some(""),
        Some(identity.application_uri()),
        Some("urn:foreign"),
    ] {
        let mut server = OpcUaServer::new(identity, &TEST_BUILD_INFO);
        let mut data_access = DefaultRuntimeDataAccess::new();
        handle_frame_len(
            &mut server,
            &hello_frame(endpoint_url),
            &mut [0u8; 1024],
            &mut data_access,
            0,
        );
        let request = client_uasc_request(service_id::CREATE_SESSION_REQUEST, 35, |e| {
            e.write_string("urn:client")?;
            e.write_string("urn:product")?;
            e.write_localized_text("client")?;
            e.write_i32(1)?;
            e.write_string("")?;
            e.write_string("")?;
            e.write_array_len(0)?;
            match requested_uri {
                Some(uri) => e.write_string(uri)?,
                None => e.write_null_string()?,
            }
            e.write_string(endpoint_url)?;
            e.write_string("session")?;
            e.write_null_byte_string()?;
            e.write_null_byte_string()?;
            e.write_f64(10_000.0)?;
            e.write_u32(0)
        });
        let mut out = [0u8; 4096];
        let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
        let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
        assert_eq!(info.service_type_id, service_id::CREATE_SESSION_RESPONSE);
        let (_, _, status) = decode_response_header_for_test(&mut d);
        assert_eq!(status, opcua_status::GOOD);
        d.read_node_id().unwrap();
        d.read_node_id().unwrap();
        d.read_f64().unwrap();
        d.read_byte_string().unwrap();
        d.read_byte_string().unwrap();
        assert_eq!(d.read_array_len(4).unwrap(), 1);
        assert_eq!(d.read_byte_string().unwrap(), Some(endpoint_url.as_bytes()));
        assert_eq!(
            decode_application_uri_for_test(&mut d),
            identity.application_uri().as_bytes()
        );
    }
}

#[test]
fn unknown_channel_or_token_returns_errf_then_close() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut request = client_uasc_request(service_id::READ_REQUEST, 33, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(0)
    });
    request[8..12].copy_from_slice(&99u32.to_le_bytes());
    let mut out = [0u8; 1024];
    let action = server
        .handle_frame(&request, &mut out, &mut data_access, 0)
        .unwrap();
    let len = match action {
        FrameAction::SendResponseThenClose(len) => len,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(&out[..4], b"ERRF");
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TCP_SECURE_CHANNEL_UNKNOWN.to_le_bytes()
    ));

    let mut request = client_uasc_request(service_id::READ_REQUEST, 34, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(0)
    });
    request[12..16].copy_from_slice(&99u32.to_le_bytes());
    let action = server
        .handle_frame(&request, &mut out, &mut data_access, 0)
        .unwrap();
    let len = match action {
        FrameAction::SendResponseThenClose(len) => len,
        other => panic!("unexpected action: {other:?}"),
    };
    assert_eq!(&out[..4], b"ERRF");
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TCP_SECURE_CHANNEL_UNKNOWN.to_le_bytes()
    ));
}

#[test]
fn write_enable_config_controls_all_mapped_writes() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    let mut config = GatewayConfig::defaults_from_mac([0xA8, 0x61, 0x0A, 0x50, 0x44, 0x0D]);
    data_access.set_write_enabled(config.write_enable);
    assert!(!data_access.write_enabled());

    let request = client_uasc_request(service_id::WRITE_REQUEST, 8, |e| {
        e.write_array_len(namespace::WRITABLE_NODES.len())?;
        for node in namespace::WRITABLE_NODES {
            e.write_node_id(NodeId::numeric(
                PRODUCT_NAMESPACE_INDEX,
                u32::from(node.node_id),
            ))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_u8(DATA_VALUE_HAS_VALUE)?;
            e.write_u8(VARIANT_BOOLEAN)?;
            e.write_bool(true)?;
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let statuses = decode_write_statuses_for_test(&out[..len]);
    assert_eq!(statuses.len(), namespace::WRITABLE_NODES.len());
    assert!(statuses
        .iter()
        .all(|status| *status == opcua_status::BAD_NOT_WRITABLE));
    assert_eq!(data_access.write_queue_depth(), 0);

    config
        .set_key_value(ConfigKey::WriteEnable, "true")
        .unwrap();
    data_access.set_write_enabled(config.write_enable);
    assert!(data_access.write_enabled());
    let request = client_uasc_request(service_id::WRITE_REQUEST, 9, |e| {
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(DATA_VALUE_HAS_VALUE)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)
    });
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(
        decode_write_statuses_for_test(&out[..len]),
        [opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY]
    );
    assert_eq!(data_access.write_queue_depth(), 1);
}

#[test]
fn trust_not_verified_closes_async_write_queue_before_acceptance() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    data_access.set_write_enabled(true);

    let request = client_uasc_request(service_id::WRITE_REQUEST, 61, |e| {
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(DATA_VALUE_HAS_VALUE)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(
        decode_write_statuses_for_test(&out[..len]),
        [opcua_status::BAD_NOT_WRITABLE]
    );
    assert_eq!(data_access.write_queue_depth(), 0);
    assert_eq!(data_access.health().buchi_write_accepted_count, 0);

    data_access.set_trust_state(TrustState::Verified);
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(
        decode_write_statuses_for_test(&out[..len]),
        [opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY]
    );
    assert_eq!(data_access.write_queue_depth(), 1);
    assert_eq!(data_access.health().buchi_write_accepted_count, 1);
}

#[test]
fn write_valid_node_queues_and_read_only_rejects() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    data_access.set_write_enabled(true);
    let request = client_uasc_request(service_id::WRITE_REQUEST, 8, |e| {
        e.write_array_len(2)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(0x01)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2002))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(0x01)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(41.0)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(data_access.write_queue_depth(), 1);
    assert!(contains_bytes(
        &out[..len],
        opcua_status::GOOD.to_le_bytes()
    ));
    assert!(contains_bytes(
        &out[..len],
        opcua_status::BAD_NOT_WRITABLE.to_le_bytes()
    ));
}

#[test]
fn write_value_plus_good_status_queues_for_uatexpert_datavalue() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    data_access.set_write_enabled(true);
    let request = client_uasc_request(service_id::WRITE_REQUEST, 55, |e| {
        e.write_array_len(2)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(DATA_VALUE_HAS_VALUE | DATA_VALUE_HAS_STATUS)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)?;
        e.write_u32(opcua_status::GOOD)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2002))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(DATA_VALUE_HAS_VALUE | DATA_VALUE_HAS_STATUS)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(41.0)?;
        e.write_u32(opcua_status::GOOD)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(data_access.write_queue_depth(), 1);
    assert!(contains_bytes(
        &out[..len],
        opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY.to_le_bytes()
    ));
    assert!(contains_bytes(
        &out[..len],
        opcua_status::BAD_NOT_WRITABLE.to_le_bytes()
    ));
    assert!(!contains_bytes(
        &out[..len],
        opcua_status::BAD_WRITE_NOT_SUPPORTED.to_le_bytes()
    ));
}

#[test]
fn write_timestamps_are_rejected_without_desynchronizing_decoder() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    data_access.set_write_enabled(true);
    let request = client_uasc_request(service_id::WRITE_REQUEST, 56, |e| {
        e.write_array_len(2)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(
            DATA_VALUE_HAS_VALUE
                | DATA_VALUE_HAS_SOURCE_TIMESTAMP
                | DATA_VALUE_HAS_SERVER_TIMESTAMP
                | DATA_VALUE_HAS_SOURCE_PICOSECONDS
                | DATA_VALUE_HAS_SERVER_PICOSECONDS,
        )?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)?;
        e.write_i64(TEST_REQUEST_TIMESTAMP)?;
        e.write_u16(10)?;
        e.write_i64(TEST_REQUEST_TIMESTAMP + 1_000)?;
        e.write_u16(20)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(DATA_VALUE_HAS_VALUE)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(41.0)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(data_access.write_queue_depth(), 1);
    assert!(contains_bytes(
        &out[..len],
        opcua_status::BAD_WRITE_NOT_SUPPORTED.to_le_bytes()
    ));
    assert!(contains_bytes(
        &out[..len],
        opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY.to_le_bytes()
    ));
}

#[test]
fn read_rejects_invalid_service_and_operation_parameters() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];

    let invalid_max_age = client_uasc_request(service_id::READ_REQUEST, 51, |e| {
        e.write_f64(-1.0)?;
        e.write_i32(2)?;
        e.write_array_len(0)
    });
    let len = handle_frame_len(&mut server, &invalid_max_age, &mut out, &mut data_access, 0);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_MAX_AGE_INVALID.to_le_bytes()
    ));

    let invalid_timestamps = client_uasc_request(service_id::READ_REQUEST, 52, |e| {
        e.write_f64(0.0)?;
        e.write_i32(4)?;
        e.write_array_len(0)
    });
    let len = handle_frame_len(
        &mut server,
        &invalid_timestamps,
        &mut out,
        &mut data_access,
        0,
    );
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TIMESTAMPS_TO_RETURN_INVALID.to_le_bytes()
    ));

    let invalid_node_params = client_uasc_request(service_id::READ_REQUEST, 53, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(2)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_string("0")?;
        e.write_qualified_name(0, "")?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "Default Binary")
    });
    let len = handle_frame_len(
        &mut server,
        &invalid_node_params,
        &mut out,
        &mut data_access,
        0,
    );
    assert!(contains_bytes(
        &out[..len],
        opcua_status::BAD_INDEX_RANGE_INVALID.to_le_bytes()
    ));
    assert!(contains_bytes(
        &out[..len],
        status::BAD_DATA_ENCODING_UNSUPPORTED.to_le_bytes()
    ));
}

#[test]
fn write_rejects_non_value_only_or_unsupported_values_without_queueing() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    data_access.set_write_enabled(true);
    let request = client_uasc_request(service_id::WRITE_REQUEST, 54, |e| {
        e.write_array_len(5)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(0x03)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)?;
        e.write_u32(opcua_status::BAD_OUT_OF_RANGE)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_string("0")?;
        e.write_u8(0x01)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(0x01)?;
        e.write_u8(VARIANT_STRING)?;
        e.write_string("not numeric")?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_u8(0x01)?;
        e.write_u8(VARIANT_ARRAY_BIT | VARIANT_FLOAT)?;
        e.write_array_len(1)?;
        e.write_f32(40.0)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_DATATYPE)?;
        e.write_null_string()?;
        e.write_u8(0x01)?;
        e.write_u8(VARIANT_FLOAT)?;
        e.write_f32(40.0)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(data_access.write_queue_depth(), 0);
    let write_not_supported_count = out[..len]
        .windows(4)
        .filter(|window| *window == opcua_status::BAD_WRITE_NOT_SUPPORTED.to_le_bytes())
        .count();
    assert_eq!(write_not_supported_count, 2);
    let type_mismatch_count = out[..len]
        .windows(4)
        .filter(|window| *window == opcua_status::BAD_TYPE_MISMATCH.to_le_bytes())
        .count();
    assert_eq!(type_mismatch_count, 2);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_ATTRIBUTE_ID_INVALID.to_le_bytes()
    ));
}

#[test]
fn create_monitored_items_enforces_product_cap() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let mut data_access = DefaultRuntimeDataAccess::new();
    let requested_items = product::MAX_MONITORED_ITEMS + 19;
    assert!(requested_items <= MAX_REQUESTED_NODES);
    let request = client_uasc_request(service_id::CREATE_MONITORED_ITEMS_REQUEST, 9, |e| {
        e.write_u32(1)?;
        e.write_i32(3)?;
        e.write_array_len(requested_items)?;
        for i in 0..requested_items {
            e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
            e.write_i32(1)?;
            e.write_u32(i as u32 + 1)?;
            e.write_f64(1000.0)?;
            e.write_extension_object_none()?;
            e.write_u32(1)?;
            e.write_bool(true)?;
        }
        Ok(())
    });
    let mut out = [0u8; 32768];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(server.subscription.len(), product::MAX_MONITORED_ITEMS);
    assert!(out[..len]
        .windows(4)
        .any(|window| window == opcua_status::BAD_TOO_MANY_MONITORED_ITEMS.to_le_bytes()));
    let over_cap_count = out[..len]
        .windows(4)
        .filter(|window| *window == opcua_status::BAD_TOO_MANY_MONITORED_ITEMS.to_le_bytes())
        .count();
    assert_eq!(
        over_cap_count,
        requested_items - product::MAX_MONITORED_ITEMS
    );
}

#[test]
fn create_subscription_rejects_second_subscription() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::CREATE_SUBSCRIPTION_REQUEST, 61, |e| {
        e.write_f64(1000.0)?;
        e.write_u32(10)?;
        e.write_u32(3)?;
        e.write_u32(0)?;
        e.write_bool(true)?;
        e.write_u8(0)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_TOO_MANY_SUBSCRIPTIONS.to_le_bytes()
    ));
    let second = client_uasc_request(service_id::CREATE_SUBSCRIPTION_REQUEST, 62, |e| {
        e.write_f64(1000.0)?;
        e.write_u32(10)?;
        e.write_u32(3)?;
        e.write_u32(0)?;
        e.write_bool(true)?;
        e.write_u8(0)
    });
    let len = handle_frame_len(&mut server, &second, &mut out, &mut data_access, 0);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_TOO_MANY_SUBSCRIPTIONS.to_le_bytes()
    ));
}

#[test]
fn monitored_items_reject_filters_and_revise_queue_to_one() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::CREATE_MONITORED_ITEMS_REQUEST, 63, |e| {
        e.write_u32(1)?;
        e.write_i32(2)?;
        e.write_array_len(3)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")?;
        e.write_i32(1)?;
        e.write_u32(1)?;
        e.write_f64(1000.0)?;
        e.write_extension_object_none()?;
        e.write_u32(99)?;
        e.write_bool(true)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")?;
        e.write_i32(1)?;
        e.write_u32(2)?;
        e.write_f64(1000.0)?;
        e.write_node_id(NodeId::numeric(0, 1))?;
        e.write_u8(1)?;
        e.write_i32(0)?;
        e.write_u32(1)?;
        e.write_bool(true)?;

        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_BROWSENAME)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")?;
        e.write_i32(1)?;
        e.write_u32(3)?;
        e.write_f64(1000.0)?;
        e.write_extension_object_none()?;
        e.write_u32(1)?;
        e.write_bool(true)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(server.subscription.len(), 1);
    assert!(!contains_bytes(&out[..len], 99u32.to_le_bytes()));
    // Filter EO → BadMonitoredItemFilterUnsupported; BrowseName attr → BadNotSupported.
    let filter_unsupported = out[..len]
        .windows(4)
        .filter(|window| *window == status::BAD_MONITORED_ITEM_FILTER_UNSUPPORTED.to_le_bytes())
        .count();
    let not_supported = out[..len]
        .windows(4)
        .filter(|window| *window == status::BAD_NOT_SUPPORTED.to_le_bytes())
        .count();
    assert_eq!(filter_unsupported, 1, "filter EO must use correct status");
    assert_eq!(
        not_supported, 1,
        "non-Value attribute remains BadNotSupported"
    );
}

#[test]
fn create_monitored_items_accepts_single_core_health_nodes() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::CREATE_MONITORED_ITEMS_REQUEST, 73, |e| {
        e.write_u32(1)?;
        e.write_i32(3)?;
        e.write_array_len(2)?;
        for (i, node_id) in [4022, 4042].into_iter().enumerate() {
            e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, node_id))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
            e.write_i32(1)?;
            e.write_u32(i as u32 + 1)?;
            e.write_f64(1000.0)?;
            e.write_extension_object_none()?;
            e.write_u32(1)?;
            e.write_bool(true)?;
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(server.subscription.len(), 2);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_NODE_ID_UNKNOWN.to_le_bytes()
    ));
    assert!(!contains_bytes(
        &out[..len],
        opcua_status::BAD_TOO_MANY_MONITORED_ITEMS.to_le_bytes()
    ));
}

#[test]
fn create_monitored_items_accepts_all_default_namespace_nodes() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let mut data_access = DefaultRuntimeDataAccess::new();
    assert!(DEFAULT_NAMESPACE_NODES.len() <= product::MAX_MONITORED_ITEMS);
    assert!(DEFAULT_NAMESPACE_NODES.len() <= MAX_REQUESTED_NODES);

    let request = client_uasc_request(service_id::CREATE_MONITORED_ITEMS_REQUEST, 9, |e| {
        e.write_u32(1)?;
        e.write_i32(3)?;
        e.write_array_len(DEFAULT_NAMESPACE_NODES.len())?;
        for (i, node) in DEFAULT_NAMESPACE_NODES.iter().enumerate() {
            e.write_node_id(NodeId::numeric(
                PRODUCT_NAMESPACE_INDEX,
                u32::from(node.node_id),
            ))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
            e.write_i32(1)?;
            e.write_u32(i as u32 + 1)?;
            e.write_f64(1000.0)?;
            e.write_extension_object_none()?;
            e.write_u32(1)?;
            e.write_bool(true)?;
        }
        Ok(())
    });
    let mut out = [0u8; PRODUCT_TARGET_BUFFER_SIZE as usize];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(server.subscription.len(), DEFAULT_NAMESPACE_NODES.len());
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::CREATE_MONITORED_ITEMS_RESPONSE
    );
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(
        d.read_array_len(MAX_REQUESTED_NODES).unwrap(),
        DEFAULT_NAMESPACE_NODES.len()
    );
    for expected_id in 1..=DEFAULT_NAMESPACE_NODES.len() {
        assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
        assert_eq!(d.read_u32().unwrap(), expected_id as u32);
        assert_eq!(
            d.read_f64().unwrap(),
            product::DATA_CHANGE_INTERVAL_MS as f64
        );
        assert_eq!(d.read_u32().unwrap(), 1);
        assert!(!d.read_extension_object_present().unwrap());
    }
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0);
}

#[test]
fn over_budget_create_monitored_items_faults_without_mutating_subscription() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let mut data_access = DefaultRuntimeDataAccess::new();
    let requested_items = MAX_MONITORED_ITEM_OPERATIONS + 1;
    assert!(requested_items <= MAX_REQUESTED_NODES);

    let request = client_uasc_request(service_id::CREATE_MONITORED_ITEMS_REQUEST, 120, |e| {
        e.write_u32(1)?;
        e.write_i32(3)?;
        e.write_array_len(requested_items)?;
        for i in 0..requested_items {
            e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
            e.write_i32(1)?;
            e.write_u32(i as u32 + 1)?;
            e.write_f64(1000.0)?;
            e.write_extension_object_none()?;
            e.write_u32(1)?;
            e.write_bool(true)?;
        }
        Ok(())
    });
    let mut out = [0u8; PRODUCT_TARGET_BUFFER_SIZE as usize];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert_eq!(server.subscription.len(), 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::SERVICE_FAULT_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 120);
    assert_eq!(service_result, status::BAD_TOO_MANY_OPERATIONS);
}

#[test]
fn publish_reports_datachange_samples() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let add = server
        .subscription
        .add_node_index(RuntimeNode::ProcessHeatingSet.index(), 77);
    assert_eq!(add.opcua_status, opcua_status::GOOD);
    let mut data_access = verified_data_access();
    seed(&mut data_access);
    let request = client_uasc_request(service_id::PUBLISH_REQUEST, 10, |e| {
        e.write_array_len(1)?;
        e.write_u32(1)?;
        e.write_u32(123)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 3_000);
    assert!(contains_bytes(&out[..len], 77u32.to_le_bytes()));
    assert!(contains_bytes(&out[..len], 42.5f32.to_le_bytes()));
    assert!(contains_bytes(
        &out[..len],
        status::GOOD_RETRANSMISSION_QUEUE_NOT_SUPPORTED.to_le_bytes()
    ));
}

#[test]
fn subscription_encodes_bad_without_value_after_freshness_wrap_alias() {
    const EPOCH_MS: u64 = 1_u64 << 32;
    const PUBLISHED_AT_MS: u64 = 123_456;
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    server.next_publish_due_ms = PUBLISHED_AT_MS as u32;
    assert_eq!(
        server
            .subscription
            .add_node_index(RuntimeNode::ProcessHeatingSet.index(), 177)
            .opcua_status,
        opcua_status::GOOD
    );
    let mut data_access = verified_data_access();
    seed_frozen_heating_set(&mut data_access, PUBLISHED_AT_MS);
    assert_eq!(server.enqueue_publish_request(119, 178, 0), None);
    let mut out = [0u8; 8192];
    let len = server
        .drain_due_publish_response(&mut out, &data_access, PUBLISHED_AT_MS + EPOCH_MS)
        .unwrap()
        .expect_response("wrap-injected stale DataChange response");

    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::PUBLISH_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 178);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_u32().unwrap(), 1);
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0);
    assert!(!d.read_bool().unwrap());
    assert_eq!(d.read_u32().unwrap(), 1);
    let _publish_time = d.read_i64().unwrap();
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 1);
    assert_eq!(
        d.read_node_id().unwrap(),
        NodeId::numeric(0, service_id::DATA_CHANGE_NOTIFICATION)
    );
    assert_eq!(d.read_u8().unwrap(), 1);
    let body_len = d.read_i32().unwrap();
    assert!(body_len >= 0);
    let body_end = d.position() + body_len as usize;
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 1);
    assert_eq!(d.read_u32().unwrap(), 177);
    let (status, has_value) = decode_data_value_status_and_presence_for_test(&mut d);
    assert_eq!(status, opcua_status::BAD_WAITING_FOR_INITIAL_DATA);
    assert!(
        !has_value,
        "stale DataChange must not encode a scalar value"
    );
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0);
    assert_eq!(d.position(), body_end);
}

#[test]
fn publish_enqueues_and_returns_no_response_before_first_due_cycle() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(70, 1000.0, 10, 3, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    let add = server
        .subscription
        .add_node_index(RuntimeNode::ProcessHeatingSet.index(), 91);
    assert_eq!(add.opcua_status, opcua_status::GOOD);
    seed(&mut data_access);

    let request = publish_frame(74);
    let action = server
        .handle_frame(&request, &mut out, &mut data_access, 999)
        .unwrap();
    assert_eq!(action, FrameAction::NoResponse);
    assert_eq!(server.queued_publish_count, 1);
    assert_eq!(server.next_publish_delay_ms(999), Some(1));
}

#[test]
fn first_due_publish_batches_multiple_changed_monitored_items() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(71, 1000.0, 10, 3, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    assert_eq!(
        server
            .subscription
            .add_node_index(RuntimeNode::ProcessHeatingSet.index(), 77)
            .opcua_status,
        opcua_status::GOOD
    );
    assert_eq!(
        server
            .subscription
            .add_node_index(RuntimeNode::ProcessPressure.index(), 78)
            .opcua_status,
        opcua_status::GOOD
    );
    seed(&mut data_access);

    let request = publish_frame(75);
    assert_eq!(
        server
            .handle_frame(&request, &mut out, &mut data_access, 900)
            .unwrap(),
        FrameAction::NoResponse
    );
    let len = server
        .drain_due_publish_response(&mut out, &data_access, 1000)
        .unwrap()
        .expect_response("due Publish response");
    let summary = decode_publish_summary_for_test(&out[..len]);
    assert_eq!(summary.request_handle, 75);
    assert_eq!(summary.service_result, opcua_status::GOOD);
    assert_eq!(summary.sequence_number, 1);
    assert_eq!(summary.notification_data_len, 1);
    assert_eq!(summary.monitored_item_count, 2);
    assert!(summary.publish_time > 0);
}

#[test]
fn keepalive_does_not_consume_publish_sequence_number() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(72, 1000.0, 10, 1, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    assert_eq!(
        server
            .subscription
            .add_node_index(RuntimeNode::ProcessHeatingSet.index(), 79)
            .opcua_status,
        opcua_status::GOOD
    );
    seed(&mut data_access);

    let first = publish_frame(76);
    assert_eq!(
        server
            .handle_frame(&first, &mut out, &mut data_access, 900)
            .unwrap(),
        FrameAction::NoResponse
    );
    let first_len = server
        .drain_due_publish_response(&mut out, &data_access, 1000)
        .unwrap();
    let first_summary =
        decode_publish_summary_for_test(&out[..first_len.expect_response("first publish")]);
    assert_eq!(first_summary.sequence_number, 1);
    assert_eq!(first_summary.notification_data_len, 1);
    assert_eq!(server.publish_sequence_number, 2);

    let keepalive = publish_frame(77);
    assert_eq!(
        server
            .handle_frame(&keepalive, &mut out, &mut data_access, 1500)
            .unwrap(),
        FrameAction::NoResponse
    );
    let keepalive_len = server
        .drain_due_publish_response(&mut out, &data_access, 2000)
        .unwrap()
        .expect_response("keepalive response");
    let keepalive_summary = decode_publish_summary_for_test(&out[..keepalive_len]);
    assert_eq!(keepalive_summary.sequence_number, 2);
    assert_eq!(keepalive_summary.notification_data_len, 0);
    assert_eq!(server.publish_sequence_number, 2);

    let values = ProcessValues {
        roots: ProcessRootPresence {
            heating: true,
            cooling: true,
            vacuum: true,
            rotation: true,
            lift: true,
            global_status: true,
        },
        heating_set_milli_celsius: Some(43_000),
        ..Default::default()
    };
    data_access.apply_endpoint_values(EndpointValues::Process(values), 2_500);
    let second_data = publish_frame(78);
    assert_eq!(
        server
            .handle_frame(&second_data, &mut out, &mut data_access, 2500)
            .unwrap(),
        FrameAction::NoResponse
    );
    let second_len = server
        .drain_due_publish_response(&mut out, &data_access, 3000)
        .unwrap()
        .expect_response("second data response");
    let second_summary = decode_publish_summary_for_test(&out[..second_len]);
    assert_eq!(second_summary.sequence_number, 2);
    assert_eq!(second_summary.notification_data_len, 1);
    assert_eq!(server.publish_sequence_number, 3);
}

#[test]
fn sixth_queued_publish_evicts_oldest_with_too_many_publish_requests() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(73, 1000.0, 10, 3, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);

    for handle in 200..205 {
        let request = publish_frame(handle);
        assert_eq!(
            server
                .handle_frame(&request, &mut out, &mut data_access, 100)
                .unwrap(),
            FrameAction::NoResponse
        );
    }
    assert_eq!(server.queued_publish_count, 5);
    let overflow = publish_frame(205);
    let len = handle_frame_len(&mut server, &overflow, &mut out, &mut data_access, 100);
    let summary = decode_publish_summary_for_test(&out[..len]);
    assert_eq!(summary.request_handle, 200);
    assert_eq!(
        summary.service_result,
        status::BAD_TOO_MANY_PUBLISH_REQUESTS
    );
    assert_eq!(summary.notification_data_len, 0);
    assert_eq!(server.publish_sequence_number, 1);
    assert_eq!(server.queued_publish_count, 5);
}

#[test]
fn publish_without_subscription_returns_bad_no_subscription_immediately() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let request = publish_frame(206);
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 100);
    let summary = decode_publish_summary_for_test(&out[..len]);
    assert_eq!(summary.request_handle, 206);
    assert_eq!(summary.service_result, status::BAD_NO_SUBSCRIPTION);
    assert_eq!(summary.subscription_id, 0);
    assert_eq!(summary.notification_data_len, 0);
    assert_eq!(server.queued_publish_count, 0);
    assert_eq!(server.publish_sequence_number, 1);
}

#[test]
fn republish_returns_response_with_bad_message_not_available() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.subscription_active = true;
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::REPUBLISH_REQUEST, 207, |e| {
        e.write_u32(1)?;
        e.write_u32(1)
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::REPUBLISH_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 207);
    assert_eq!(service_result, status::BAD_MESSAGE_NOT_AVAILABLE);
    assert_eq!(d.read_u32().unwrap(), 0);
    assert_eq!(d.read_i64().unwrap(), 0);
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 0);
}

#[test]
fn set_publishing_mode_disables_data_notifications_but_keeps_keepalives() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = verified_data_access();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(208, 1000.0, 10, 1, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    assert_eq!(
        server
            .subscription
            .add_node_index(RuntimeNode::ProcessHeatingSet.index(), 88)
            .opcua_status,
        opcua_status::GOOD
    );
    seed(&mut data_access);
    let disable = client_uasc_request(service_id::SET_PUBLISHING_MODE_REQUEST, 209, |e| {
        e.write_bool(false)?;
        e.write_array_len(1)?;
        e.write_u32(1)
    });
    let disable_len = handle_frame_len(&mut server, &disable, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..disable_len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::SET_PUBLISHING_MODE_RESPONSE
    );
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_array_len(MAX_REQUESTED_NODES).unwrap(), 1);
    assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
    assert!(!server.publishing_enabled);

    let disabled_publish = publish_frame(210);
    assert_eq!(
        server
            .handle_frame(&disabled_publish, &mut out, &mut data_access, 900)
            .unwrap(),
        FrameAction::NoResponse
    );
    let keepalive_len = server
        .drain_due_publish_response(&mut out, &data_access, 1000)
        .unwrap()
        .expect_response("disabled subscription keepalive");
    let keepalive_summary = decode_publish_summary_for_test(&out[..keepalive_len]);
    assert_eq!(keepalive_summary.sequence_number, 1);
    assert_eq!(keepalive_summary.notification_data_len, 0);
    assert_eq!(server.publish_sequence_number, 1);

    let enable = client_uasc_request(service_id::SET_PUBLISHING_MODE_REQUEST, 211, |e| {
        e.write_bool(true)?;
        e.write_array_len(1)?;
        e.write_u32(1)
    });
    let _ = handle_frame_len(&mut server, &enable, &mut out, &mut data_access, 1_100);
    let values = ProcessValues {
        roots: ProcessRootPresence {
            heating: true,
            cooling: true,
            vacuum: true,
            rotation: true,
            lift: true,
            global_status: true,
        },
        heating_set_milli_celsius: Some(44_000),
        ..Default::default()
    };
    data_access.apply_endpoint_values(EndpointValues::Process(values), 1_500);
    let enabled_publish = publish_frame(212);
    assert_eq!(
        server
            .handle_frame(&enabled_publish, &mut out, &mut data_access, 1_500)
            .unwrap(),
        FrameAction::NoResponse
    );
    let data_len = server
        .drain_due_publish_response(&mut out, &data_access, 2_000)
        .unwrap()
        .expect_response("enabled data response");
    let data_summary = decode_publish_summary_for_test(&out[..data_len]);
    assert_eq!(data_summary.sequence_number, 1);
    assert_eq!(data_summary.notification_data_len, 1);
    assert_eq!(data_summary.monitored_item_count, 1);
    assert_eq!(server.publish_sequence_number, 2);
}

#[test]
fn disabled_subscription_sends_initial_keepalive_on_first_interval() {
    // DeltaV stages its monitored items by creating the Subscription with
    // publishing disabled and a max keep-alive count of 10. OPC UA Part 4
    // 5.14.1.2, Table 79 transition 7 requires the initial keep-alive on
    // the first publishing-timer expiry while MessageSent is still false;
    // the max keep-alive count applies to subsequent empty cycles.
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(215, 1000.0, 2400, 10, false);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    assert!(!server.publishing_enabled);
    assert_eq!(server.keepalive_count, 10);

    let publish = publish_frame(216);
    assert_eq!(
        server
            .handle_frame(&publish, &mut out, &mut data_access, 100)
            .unwrap(),
        FrameAction::NoResponse
    );
    assert_eq!(
        server
            .drain_due_publish_response(&mut out, &data_access, 999)
            .unwrap(),
        TimerDrainResult::None
    );

    let keepalive_len = server
        .drain_due_publish_response(&mut out, &data_access, 1000)
        .unwrap()
        .expect_response("initial disabled-subscription keepalive");
    let keepalive_summary = decode_publish_summary_for_test(&out[..keepalive_len]);
    assert_eq!(keepalive_summary.request_handle, 216);
    assert_eq!(keepalive_summary.service_result, opcua_status::GOOD);
    assert_eq!(keepalive_summary.sequence_number, 1);
    assert_eq!(keepalive_summary.notification_data_len, 0);
    assert_eq!(server.publish_sequence_number, 1);
    assert_eq!(server.queued_publish_count, 0);

    let subsequent = publish_frame(217);
    assert_eq!(
        server
            .handle_frame(&subsequent, &mut out, &mut data_access, 1_100)
            .unwrap(),
        FrameAction::NoResponse
    );
    for now_ms in (2_000..=10_000).step_by(1_000) {
        assert_eq!(
            server
                .drain_due_publish_response(&mut out, &data_access, now_ms)
                .unwrap(),
            TimerDrainResult::None,
            "subsequent keepalive fired before max keep-alive count at {now_ms} ms"
        );
    }
    let subsequent_len = server
        .drain_due_publish_response(&mut out, &data_access, 11_000)
        .unwrap()
        .expect_response("subsequent disabled-subscription keepalive");
    let subsequent_summary = decode_publish_summary_for_test(&out[..subsequent_len]);
    assert_eq!(subsequent_summary.request_handle, 217);
    assert_eq!(subsequent_summary.service_result, opcua_status::GOOD);
    assert_eq!(subsequent_summary.sequence_number, 1);
    assert_eq!(subsequent_summary.notification_data_len, 0);
    assert_eq!(server.publish_sequence_number, 1);
    assert_eq!(server.queued_publish_count, 0);
}

#[test]
fn modify_subscription_updates_publish_timer_and_keepalive_revision() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    let create = create_subscription_frame(213, 1000.0, 10, 3, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 100);
    let modify = modify_subscription_frame(214, 2500.0, 4, 4);
    let len = handle_frame_len(&mut server, &modify, &mut out, &mut data_access, 200);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        info.service_type_id,
        service_id::MODIFY_SUBSCRIPTION_RESPONSE
    );
    let (_, _, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_f64().unwrap(), 2500.0);
    assert_eq!(d.read_u32().unwrap(), 12);
    assert_eq!(d.read_u32().unwrap(), 4);
    assert_eq!(server.publishing_interval_ms, 2500);
    assert_eq!(server.keepalive_count, 4);
    assert_eq!(server.next_publish_due_ms, 2700);
}

#[test]
fn publishing_interval_never_exceeds_modular_timer_half_range() {
    accelerated::check_subscription_interval_requests(false);
}

#[test]
fn browse_exposes_objects_and_product_namespace() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::BROWSE_REQUEST, 11, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(2)?;
        e.write_node_id(NodeId::numeric(0, NODEID_OBJECTS_FOLDER))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(63)?;
        e.write_node_id(NodeId::numeric(
            PRODUCT_NAMESPACE_INDEX,
            PRODUCT_OBJECT_PROCESS as u32,
        ))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(63)
    });
    let mut out = [0u8; 32768];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(out[..len].windows(b"Buchi".len()).any(|w| w == b"Buchi"));
    assert!(out[..len]
        .windows(b"Process.Heating.Set".len())
        .any(|w| w == b"Process.Heating.Set"));
}

#[test]
fn namespace_two_is_the_only_product_identity() {
    assert_eq!(APPLICATION_NAMESPACE_INDEX, 1);
    assert_eq!(PRODUCT_NAMESPACE_INDEX, 2);
    assert_eq!(
        namespace_node_id_for_product_node(NodeId::numeric(2, 4022)),
        Some(4022)
    );
    assert_eq!(
        namespace_node_id_for_product_node(NodeId::numeric(1, 4022)),
        None
    );

    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::READ_REQUEST, 40, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(2)?;
        for node in [NODEID_NAMESPACE_ARRAY, NODEID_SERVER_ARRAY] {
            e.write_node_id(NodeId::numeric(0, node))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 40);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_array_len(2).unwrap(), 2);
    let identity = test_identity();
    let namespaces = [
        "http://opcfoundation.org/UA/",
        identity.application_uri(),
        PRODUCT_NAMESPACE_URI,
    ];
    let servers = [identity.application_uri()];
    for expected in [namespaces.as_slice(), servers.as_slice()] {
        assert_eq!(
            d.read_u8().unwrap(),
            DATA_VALUE_HAS_VALUE | DATA_VALUE_HAS_STATUS
        );
        assert_eq!(d.read_u8().unwrap(), VARIANT_ARRAY_BIT | VARIANT_STRING);
        assert_eq!(d.read_array_len(expected.len()).unwrap(), expected.len());
        for value in expected {
            assert_eq!(d.read_byte_string().unwrap(), Some(value.as_bytes()));
        }
        assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
    }
    assert_eq!(d.read_array_len(0).unwrap(), 0);
    assert_eq!(d.position() + 8, len); // Decoder excludes the eight-byte frame header.
}

#[test]
fn standard_folders_and_fixed_attributes_are_present() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let browse_root = client_uasc_request(service_id::BROWSE_REQUEST, 41, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(0, NODEID_ROOT_FOLDER))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(63)
    });
    let mut out = [0u8; 32768];
    let len = handle_frame_len(&mut server, &browse_root, &mut out, &mut data_access, 0);
    assert!(contains_slice(&out[..len], b"Objects"));
    assert!(contains_slice(&out[..len], b"Types"));
    assert!(contains_slice(&out[..len], b"Views"));

    let read_attrs = client_uasc_request(service_id::READ_REQUEST, 42, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(4)?;
        for (node, attr) in [
            (NodeId::numeric(0, NODEID_ROOT_FOLDER), ATTR_EVENTNOTIFIER),
            (
                NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_BUCHI as u32),
                ATTR_EVENTNOTIFIER,
            ),
            (
                NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001),
                ATTR_HISTORIZING,
            ),
            (NodeId::numeric(0, NODEID_SERVER_ARRAY), ATTR_HISTORIZING),
        ] {
            e.write_node_id(node)?;
            e.write_u32(attr)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let len = handle_frame_len(&mut server, &read_attrs, &mut out, &mut data_access, 0);
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_ATTRIBUTE_ID_INVALID.to_le_bytes()
    ));
}

#[test]
fn deltav_service_level_read_returns_healthy_byte() {
    // DeltaV polls mandatory Server.ServiceLevel (ns=0;i=2267) once per
    // second as a server-usability signal. The project deliberately maps
    // OPC UA server availability to 255 and reports Büchi reachability via
    // per-tag quality; see the mapping decision in the retained DeltaV
    // capture findings. This pins that interoperability policy rather than
    // inferring ServiceLevel dynamically from the cache.
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::READ_REQUEST, 421, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(0, 2267))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")
    });
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    let (_, request_handle, service_result) = decode_response_header_for_test(&mut d);
    assert_eq!(request_handle, 421);
    assert_eq!(service_result, opcua_status::GOOD);
    assert_eq!(d.read_array_len(1).unwrap(), 1);
    assert_eq!(
        d.read_u8().unwrap(),
        DATA_VALUE_HAS_VALUE | DATA_VALUE_HAS_STATUS
    );
    assert_eq!(d.read_u8().unwrap(), VARIANT_BYTE);
    assert_eq!(d.read_u8().unwrap(), 255);
    assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
    assert_eq!(d.read_array_len(1).unwrap(), 0);

    let browse = client_uasc_request(service_id::BROWSE_REQUEST, 422, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(0, NODEID_SERVER))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, NODEID_HAS_PROPERTY))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(63)
    });
    let len = handle_frame_len(&mut server, &browse, &mut out, &mut data_access, 0);
    assert!(contains_slice(&out[..len], b"ServiceLevel"));
    assert!(!contains_bytes(
        &out[..len],
        status::BAD_NODE_ID_UNKNOWN.to_le_bytes()
    ));
}

#[test]
fn product_nodes_expose_forward_type_definition_references() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(service_id::BROWSE_REQUEST, 43, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(2)?;
        for node in [
            NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_BUCHI as u32),
            NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001),
        ] {
            e.write_node_id(node)?;
            e.write_i32(0)?;
            e.write_node_id(NodeId::numeric(0, NODEID_HAS_TYPE_DEFINITION))?;
            e.write_bool(true)?;
            e.write_u32(0)?;
            e.write_u32(63)?;
        }
        Ok(())
    });
    let mut out = [0u8; 32768];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(contains_slice(&out[..len], b"FolderType"));
    assert!(contains_slice(&out[..len], b"BaseDataVariableType"));
}

#[test]
fn browse_honors_filters_and_reports_no_continuation_points() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let filtered = client_uasc_request(service_id::BROWSE_REQUEST, 44, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(2)?;

        e.write_node_id(NodeId::numeric(0, NODEID_OBJECTS_FOLDER))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, NODEID_HIERARCHICAL_REFERENCES))?;
        e.write_bool(true)?;
        e.write_u32(NODECLASS_VARIABLE as u32)?;
        e.write_u32(63)?;

        e.write_node_id(NodeId::numeric(0, NODEID_OBJECTS_FOLDER))?;
        e.write_i32(1)?;
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(63)
    });
    let mut out = [0u8; 32768];
    let len = handle_frame_len(&mut server, &filtered, &mut out, &mut data_access, 0);
    assert!(!contains_slice(&out[..len], b"Buchi"));
    assert!(!contains_slice(&out[..len], b"Server"));

    let too_small = client_uasc_request(service_id::BROWSE_REQUEST, 45, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(1)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(0, NODEID_ROOT_FOLDER))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(63)
    });
    let len = handle_frame_len(&mut server, &too_small, &mut out, &mut data_access, 0);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_NO_CONTINUATION_POINTS.to_le_bytes()
    ));

    let names_masked = client_uasc_request(service_id::BROWSE_REQUEST, 46, |e| {
        e.write_node_id(NodeId::numeric(0, 0))?;
        e.write_i64(0)?;
        e.write_u32(0)?;
        e.write_u32(0)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(
            PRODUCT_NAMESPACE_INDEX,
            PRODUCT_OBJECT_PROCESS as u32,
        ))?;
        e.write_i32(0)?;
        e.write_node_id(NodeId::numeric(0, NODEID_HAS_COMPONENT))?;
        e.write_bool(true)?;
        e.write_u32(0)?;
        e.write_u32(0)
    });
    let len = handle_frame_len(&mut server, &names_masked, &mut out, &mut data_access, 0);
    assert!(!contains_slice(&out[..len], b"Process.Heating.Set"));
}

#[test]
fn unsupported_services_return_service_fault() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let request = client_uasc_request(664, 12, |_e| Ok(()));
    let mut out = [0u8; 8192];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data_access, 0);
    assert!(contains_bytes(
        &out[..len],
        status::BAD_SERVICE_UNSUPPORTED.to_le_bytes()
    ));
}

#[test]
fn idle_session_is_reclaimed_after_revised_timeout() {
    // B.5a: activated session with no activity past revisedSessionTimeout
    // must reject subsequent session-bound services with BadSessionIdInvalid
    // and request transport close so the listener slot is freed.
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.session_timeout_ms = 1_000;
    server.last_session_activity_ms = 0;
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 2048];

    // Still inside window: Read succeeds and touches activity.
    seed(&mut data_access);
    let read = client_uasc_request(service_id::READ_REQUEST, 301, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(1)?;
        e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
        e.write_u32(ATTR_VALUE)?;
        e.write_null_string()?;
        e.write_qualified_name(0, "")?;
        Ok(())
    });
    let len = handle_frame_len(&mut server, &read, &mut out, &mut data_access, 500);
    let (info, _, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(info.service_type_id, service_id::READ_RESPONSE);
    assert!(server.session_active);
    assert_eq!(server.last_session_activity_ms, 500);

    // Idle past timeout from last activity: reclaimed + transport close.
    let action = server
        .handle_frame(&read, &mut out, &mut data_access, 1_600)
        .unwrap();
    assert!(
        action.closes_connection(),
        "idle reclaim on inbound must free TCP (SendResponseThenClose); got {action:?}"
    );
    let len = action.response_len().expect("fault response body");
    assert_service_fault_for_test(&out[..len], status::BAD_SESSION_ID_INVALID);
    assert!(!server.session_active);
    assert!(!server.session_token_minted);
}

#[test]
fn idle_session_timer_reclaim_closes_transport_without_response() {
    // Silent hung client: no inbound frames; timer path must CloseConnection.
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    server.session_timeout_ms = 1_000;
    server.last_session_activity_ms = 0;
    let data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 256];
    let drain = server
        .drain_due_publish_response(&mut out, &data_access, 1_000)
        .unwrap();
    assert_eq!(drain, TimerDrainResult::CloseConnection);
    assert!(!server.session_active);
}

#[test]
fn publish_starved_subscription_expires_after_lifetime_count() {
    // B.5b: publishing timer fires lifetime_count times with no Publish
    // token available → subscription deleted; next Publish is BadNoSubscription.
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data_access = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    // interval 1000, lifetime 3, keepalive 1
    let create = create_subscription_frame(320, 1000.0, 3, 1, true);
    let _ = handle_frame_len(&mut server, &create, &mut out, &mut data_access, 0);
    assert!(server.subscription_active);
    assert_eq!(server.subscription_lifetime_count, 3);

    // Three publishing intervals with empty Publish queue.
    for (i, now) in [1000u32, 2000, 3000].into_iter().enumerate() {
        let drain = server
            .drain_due_publish_response(&mut out, &data_access, u64::from(now))
            .unwrap();
        assert!(
            matches!(drain, TimerDrainResult::None),
            "no token → no Publish response at step {i}, got {drain:?}"
        );
    }
    assert!(
        !server.subscription_active,
        "subscription must expire after lifetime intervals without Publish tokens"
    );

    let publish = publish_frame(321);
    let len = handle_frame_len(&mut server, &publish, &mut out, &mut data_access, 3500);
    let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    // Immediate BadNoSubscription path or service fault.
    if info.service_type_id == service_id::PUBLISH_RESPONSE {
        let (_, _, service_result) = decode_response_header_for_test(&mut d);
        assert_eq!(service_result, status::BAD_NO_SUBSCRIPTION);
    } else {
        assert_service_fault_for_test(&out[..len], status::BAD_NO_SUBSCRIPTION);
    }
}

#[test]
fn build_info_structure_and_components_have_identical_wire_values() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data = DefaultRuntimeDataAccess::new();
    let ids = [2260, 2262, 2263, 2261, 2264, 2265, 2266];
    let request = client_uasc_request(service_id::READ_REQUEST, 17, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(ids.len())?;
        for id in ids {
            e.write_node_id(NodeId::numeric(0, id))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    });
    let mut out = [0; 2048];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data, 0);
    let (_, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        decode_response_header_for_test(&mut d).2,
        opcua_status::GOOD
    );
    assert_eq!(d.read_array_len(7).unwrap(), 7);
    assert_eq!(d.read_u8().unwrap(), 3); // Value and StatusCode only.
    assert_eq!(d.read_u8().unwrap(), 22);
    assert_eq!(d.read_node_id().unwrap(), NodeId::numeric(0, 340));
    assert_eq!(d.read_u8().unwrap(), 1);
    let body_len = d.read_i32().unwrap() as usize;
    let end = d.position() + body_len;
    let expected = [
        PRODUCT_URI,
        "Host test fixture",
        "Opta Buchi OPC UA Gateway",
        "1.0.0",
        "sha1:0123456789012345678901234567890123456789;product;clean",
    ];
    for value in expected {
        assert_eq!(d.read_byte_string().unwrap().unwrap(), value.as_bytes());
    }
    assert_eq!(d.read_i64().unwrap(), 116444736000000000);
    assert_eq!(d.position(), end);
    assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
    for value in expected {
        assert_eq!(d.read_u8().unwrap(), 3);
        assert_eq!(d.read_u8().unwrap(), 12);
        assert_eq!(d.read_byte_string().unwrap().unwrap(), value.as_bytes());
        assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
    }
    assert_eq!(d.read_u8().unwrap(), 3);
    assert_eq!(d.read_u8().unwrap(), 13);
    assert_eq!(d.read_i64().unwrap(), 116444736000000000);
    assert_eq!(d.read_u32().unwrap(), opcua_status::GOOD);
    assert_eq!(d.read_array_len(0).unwrap(), 0);
    assert_eq!(d.position(), len - 8); // Decoder excludes the UA-TCP header.
}

#[test]
fn build_info_writes_are_rejected_without_queuing() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data = verified_data_access();
    data.set_write_enabled(true);
    let request = client_uasc_request(service_id::WRITE_REQUEST, 18, |e| {
        e.write_array_len(7)?;
        for id in 2260..=2266 {
            e.write_node_id(NodeId::numeric(0, id))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_u8(1)?;
            e.write_u8(VARIANT_FLOAT)?;
            e.write_f32(42.0)?;
        }
        Ok(())
    });
    let mut out = [0; 1024];
    let len = handle_frame_len(&mut server, &request, &mut out, &mut data, 0);
    let (_, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        decode_response_header_for_test(&mut d).2,
        opcua_status::GOOD
    );
    assert_eq!(d.read_array_len(7).unwrap(), 7);
    for _ in 0..7 {
        assert_eq!(d.read_u32().unwrap(), opcua_status::BAD_NOT_WRITABLE);
    }
    assert_eq!(data.write_queue_depth(), 0);
}
