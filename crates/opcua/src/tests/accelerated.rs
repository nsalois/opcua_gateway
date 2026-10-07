// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use super::{
    activate_test_session, client_open_secure_channel_request, client_uasc_request,
    client_uasc_request_with_auth, create_session_token_for_test, create_subscription_frame,
    decode_data_value_status_and_presence_for_test, decode_publish_summary_for_test,
    decode_response_header_for_test, handle_frame_len, modify_subscription_frame, test_identity,
    TEST_BUILD_INFO,
};
use crate::server::monotonic_due;
use crate::{
    decode_uasc_prefix, service_id, status, FrameAction, NodeId, OpcUaServer, TimerDrainResult,
    APPLICATION_NAMESPACE_INDEX, ATTR_VALUE, DEFAULT_SESSION_TIMEOUT_MS,
    DEFAULT_SESSION_TOKEN_SEED, MAX_QUEUED_PUBLISH_REQUESTS, PRODUCT_NAMESPACE_INDEX,
};
use opta_buchi::{Endpoint, EndpointValues, ProcessRootPresence, ProcessValues};
use opta_gateway_contracts::{config::TrustState, opcua_status, product};
use opta_runtime::{
    DefaultRuntimeDataAccess, NamespaceTarget, RuntimeNode, DEFAULT_NAMESPACE_NODES,
};

#[path = "../../../../tools/accelerated_time_test_support.rs"]
mod support;
#[path = "../../../../tools/accelerated_tag_test_support.rs"]
mod tag_support;

pub(super) fn check_subscription_interval_requests(modify: bool) {
    // Independent integer expectations: modular deadlines must be less than
    // half a u32 epoch ahead. The wire value must describe the stored timer.
    let inputs = [
        (4_294_967_295.0, 2_147_483_647),
        (f64::NEG_INFINITY, 1000u32),
        (-1.0, 1000),
        (0.0, 1000),
        (999.0, 1000),
        (1000.0, 1000),
        (1000.75, 1000),
        (2500.0, 2500),
        (2_147_483_646.0, 2_147_483_646),
        (2_147_483_647.0, 2_147_483_647),
        (2_147_483_648.0, 2_147_483_647),
        (4_294_967_296.0, 2_147_483_647),
        (f64::MAX, 2_147_483_647),
        (f64::INFINITY, 1000),
        (f64::NAN, 1000),
    ];
    for origin in [0u32, 123, 2_147_483_647, 4_294_966_295] {
        for (requested, expected) in inputs {
            let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
            activate_test_session(&mut server);
            server.last_session_activity_ms = origin;
            let mut data_access = DefaultRuntimeDataAccess::new();
            let mut out = [0u8; 8192];
            // Admission checks initialization independently of the operation.
            assert!(server.session_active && !server.subscription_active);
            assert_eq!(server.last_session_activity_ms, origin);
            assert_eq!(server.subscription.len(), 0);
            assert_eq!(server.queued_publish_count, 0);
            if modify {
                let create = create_subscription_frame(400, 1000.0, 10, 3, true);
                handle_frame_len(
                    &mut server,
                    &create,
                    &mut out,
                    &mut data_access,
                    u64::from(origin),
                );
            }
            let request = if modify {
                modify_subscription_frame(401, requested, 10, 3)
            } else {
                create_subscription_frame(401, requested, 10, 3, true)
            };
            let len = handle_frame_len(
                &mut server,
                &request,
                &mut out,
                &mut data_access,
                u64::from(origin),
            );
            let (info, mut d, _) = decode_uasc_prefix(&out[..len]).unwrap();
            assert_eq!(
                info.service_type_id,
                if modify {
                    service_id::MODIFY_SUBSCRIPTION_RESPONSE
                } else {
                    service_id::CREATE_SUBSCRIPTION_RESPONSE
                }
            );
            let (_, handle, result) = decode_response_header_for_test(&mut d);
            assert_eq!((handle, result), (401, opcua_status::GOOD));
            if !modify {
                assert_eq!(d.read_u32().unwrap(), 1);
            }
            let wire_interval = d.read_f64().unwrap();
            assert!(
                !monotonic_due(origin, server.next_publish_due_ms),
                "actual newly scheduled timer is due: requested={requested}, modify={modify}"
            );
            assert_eq!(
                wire_interval,
                f64::from(expected),
                "requested={requested}, modify={modify}"
            );
            assert_eq!(server.publishing_interval_ms, expected);
            let reference_due = ((u64::from(origin) + u64::from(expected)) % 4_294_967_296) as u32;
            assert_eq!(server.next_publish_due_ms, reference_due);
            assert!(
                !monotonic_due(origin, reference_due),
                "new timer is due: requested={requested}"
            );
            assert!(!monotonic_due(reference_due.wrapping_sub(1), reference_due));
            assert!(monotonic_due(reference_due, reference_due));
            assert!(monotonic_due(reference_due.wrapping_add(1), reference_due));
        }
    }
}

#[test]
fn accelerated_create_subscription_interval_matrix() {
    check_subscription_interval_requests(false);
}

#[test]
fn accelerated_modify_subscription_interval_matrix() {
    check_subscription_interval_requests(true);
}

fn session_request() -> std::vec::Vec<u8> {
    client_uasc_request(service_id::CREATE_SESSION_REQUEST, 501, |e| {
        e.write_string("urn:accelerated-test-client")?;
        e.write_string("urn:client-product")?;
        e.write_localized_text("accelerated test")?;
        e.write_i32(1)?;
        e.write_string("")?;
        e.write_string("")?;
        e.write_array_len(0)?;
        e.write_null_string()?;
        e.write_string("opc.tcp://localhost:4840")?;
        e.write_string("accelerated")?;
        e.write_null_byte_string()?;
        e.write_null_byte_string()?;
        e.write_f64(f64::from(DEFAULT_SESSION_TIMEOUT_MS))?;
        e.write_u32(0)
    })
}

fn subscription_request(token: NodeId) -> std::vec::Vec<u8> {
    client_uasc_request_with_auth(service_id::CREATE_SUBSCRIPTION_REQUEST, 503, token, |e| {
        e.write_f64(1_000.0)?;
        e.write_u32(9)?;
        e.write_u32(1)?;
        e.write_u32(0)?;
        e.write_bool(true)?;
        e.write_u8(0)
    })
}

fn read_request(token: NodeId, nodes: &[u16]) -> std::vec::Vec<u8> {
    client_uasc_request_with_auth(service_id::READ_REQUEST, 505, token, |e| {
        e.write_f64(0.0)?;
        e.write_i32(2)?;
        e.write_array_len(nodes.len())?;
        for node in nodes {
            e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, u32::from(*node)))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
        }
        Ok(())
    })
}

fn monitor_request(token: NodeId, nodes: &[u16]) -> std::vec::Vec<u8> {
    client_uasc_request_with_auth(
        service_id::CREATE_MONITORED_ITEMS_REQUEST,
        504,
        token,
        |e| {
            e.write_u32(1)?;
            e.write_i32(2)?;
            e.write_array_len(nodes.len())?;
            for (index, node) in nodes.iter().enumerate() {
                e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, u32::from(*node)))?;
                e.write_u32(ATTR_VALUE)?;
                e.write_null_string()?;
                e.write_qualified_name(0, "")?;
                e.write_i32(2)?;
                e.write_u32(index as u32 + 1)?;
                e.write_f64(1_000.0)?;
                e.write_extension_object_none()?;
                e.write_u32(1)?;
                e.write_bool(true)?;
            }
            Ok(())
        },
    )
}

fn open_session(
    server: &mut OpcUaServer,
    data: &mut DefaultRuntimeDataAccess,
    out: &mut [u8],
    now: u64,
) -> NodeId {
    let length = handle_frame_len(server, &session_request(), out, data, now);
    let token = create_session_token_for_test(&out[..length]);
    let activate =
        client_uasc_request_with_auth(service_id::ACTIVATE_SESSION_REQUEST, 502, token, |_| Ok(()));
    handle_frame_len(server, &activate, out, data, now);
    assert!(server.session_active);
    token
}

fn service_result(bytes: &[u8]) -> u32 {
    let (_, mut decoder, _) = decode_uasc_prefix(bytes).unwrap();
    decode_response_header_for_test(&mut decoder).2
}

#[test]
fn accelerated_repeated_sessions_subscriptions_publish_and_cleanup() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    let mut data = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 32_768];
    let mut now = 0u64;
    let mut modes = [0usize; 3];
    let mut operations = 0;
    for cycle in 0..10_000 {
        assert!(!server.session_active && !server.subscription_active);
        assert_eq!(server.subscription.len(), 0);
        assert_eq!(server.queued_publish_count, 0);
        let token = open_session(&mut server, &mut data, &mut out, now);
        let create = subscription_request(token);
        let len = handle_frame_len(&mut server, &create, &mut out, &mut data, now);
        assert_eq!(service_result(&out[..len]), opcua_status::GOOD);
        let len = handle_frame_len(&mut server, &create, &mut out, &mut data, now);
        assert_eq!(
            service_result(&out[..len]),
            status::BAD_TOO_MANY_SUBSCRIPTIONS
        );
        let nodes: std::vec::Vec<_> = DEFAULT_NAMESPACE_NODES
            .iter()
            .map(|node| node.node_id)
            .collect();
        handle_frame_len(
            &mut server,
            &monitor_request(token, &nodes),
            &mut out,
            &mut data,
            now,
        );
        assert_eq!(server.subscription.len(), nodes.len());
        while server.subscription.len() < product::MAX_MONITORED_ITEMS {
            handle_frame_len(
                &mut server,
                &monitor_request(token, &[2001]),
                &mut out,
                &mut data,
                now,
            );
        }
        let len = handle_frame_len(
            &mut server,
            &monitor_request(token, &[2001]),
            &mut out,
            &mut data,
            now,
        );
        let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
        decode_response_header_for_test(&mut decoder);
        assert_eq!(decoder.read_array_len(1).unwrap(), 1);
        assert_eq!(
            decoder.read_u32().unwrap(),
            opcua_status::BAD_TOO_MANY_MONITORED_ITEMS
        );
        let read = read_request(token, &[4022]);
        let len = handle_frame_len(&mut server, &read, &mut out, &mut data, now);
        assert_eq!(service_result(&out[..len]), opcua_status::GOOD);
        let publish = client_uasc_request_with_auth(service_id::PUBLISH_REQUEST, 506, token, |e| {
            e.write_array_len(0)
        });
        assert_eq!(
            server
                .handle_frame(&publish, &mut out, &mut data, now)
                .unwrap(),
            FrameAction::NoResponse
        );
        let len = server
            .drain_due_publish_response(&mut out, &data, now + 1_000)
            .unwrap()
            .expect_response("notification");
        assert_eq!(
            decode_publish_summary_for_test(&out[..len]).monitored_item_count,
            product::MAX_MONITORED_ITEMS
        );
        // Fill/refuse/release the actual queued-Publish pool on one retained owner.
        for _ in 0..MAX_QUEUED_PUBLISH_REQUESTS {
            assert_eq!(
                server
                    .handle_frame(&publish, &mut out, &mut data, now + 1_001)
                    .unwrap(),
                FrameAction::NoResponse
            );
        }
        let len = handle_frame_len(&mut server, &publish, &mut out, &mut data, now + 1_001);
        assert_eq!(
            service_result(&out[..len]),
            status::BAD_TOO_MANY_PUBLISH_REQUESTS
        );
        let mode = cycle % 3;
        match mode {
            0 => {
                let close = client_uasc_request_with_auth(
                    service_id::CLOSE_SESSION_REQUEST,
                    507,
                    token,
                    |e| e.write_bool(true),
                );
                handle_frame_len(&mut server, &close, &mut out, &mut data, now + 1_002);
            }
            1 => {
                let close = client_uasc_request_with_auth(
                    service_id::CLOSE_SECURE_CHANNEL_REQUEST,
                    508,
                    token,
                    |_| Ok(()),
                );
                assert_eq!(
                    server
                        .handle_frame(&close, &mut out, &mut data, now + 1_002)
                        .unwrap(),
                    FrameAction::Close
                );
            }
            _ => {
                let deadline = now + 1_001 + u64::from(server.session_timeout_ms);
                assert_eq!(
                    server
                        .drain_due_publish_response(&mut out, &data, deadline)
                        .unwrap(),
                    TimerDrainResult::CloseConnection
                );
                now = deadline;
            }
        }
        assert!(!server.session_active && !server.subscription_active);
        assert_eq!(server.subscription.len(), 0);
        assert_eq!(server.queued_publish_count, 0);
        assert!(server.queued_publish_requests.iter().all(Option::is_none));
        modes[mode] += 1;
        // Actual handler/drain calls: two session calls, two subscriptions,
        // initial monitors, individual pool fills, refusal, Read, Publish,
        // notification drain, queued requests, refusal, and one cleanup.
        operations += 11 + product::MAX_MONITORED_ITEMS - nodes.len() + MAX_QUEUED_PUBLISH_REQUESTS;
        if (cycle + 1) % 100 == 0 {
            println!(
                "checkpoint session_cycles={} monitored=0 publish_queue=0 cleanup_modes={modes:?}",
                cycle + 1
            );
        }
        now += 2_000;
    }
    assert_eq!(modes.iter().sum::<usize>(), 10_000);
    // Subsequent successful admission is measured, not inferred from a counter.
    open_session(&mut server, &mut data, &mut out, now);
    println!(
        "PASS session/subscription cycles=10000 operations={operations} cleanup_modes={modes:?}"
    );
}

#[test]
fn accelerated_modify_lifetime_applies_the_encoded_revision() {
    let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
    activate_test_session(&mut server);
    let mut data = DefaultRuntimeDataAccess::new();
    let mut out = [0u8; 8192];
    handle_frame_len(
        &mut server,
        &create_subscription_frame(601, 1_000.0, 30, 1, true),
        &mut out,
        &mut data,
        0,
    );
    let modify = modify_subscription_frame(602, 1_000.0, 3, 1);
    let len = handle_frame_len(&mut server, &modify, &mut out, &mut data, 0);
    let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        decode_response_header_for_test(&mut decoder).2,
        opcua_status::GOOD
    );
    assert_eq!(decoder.read_f64().unwrap(), 1_000.0);
    let revised_lifetime = decoder.read_u32().unwrap();
    assert_eq!(revised_lifetime, 3);
    assert_eq!(
        server.subscription_lifetime_count, revised_lifetime,
        "ModifySubscription reports a lifetime it never applies"
    );
    for now in [1_000, 2_000] {
        assert_eq!(
            server
                .drain_due_publish_response(&mut out, &data, now)
                .unwrap(),
            TimerDrainResult::None
        );
        assert!(server.subscription_active);
    }
    server
        .drain_due_publish_response(&mut out, &data, 3_000)
        .unwrap();
    assert!(!server.subscription_active);
}

fn load_all_data(data: &mut DefaultRuntimeDataAccess, stamp: u64) {
    data.set_trust_state(TrustState::Verified);
    for (endpoint, body) in [
        (
            Endpoint::Process,
            include_bytes!("../../../runtime/testdata/process.json").as_slice(),
        ),
        (
            Endpoint::Settings,
            include_bytes!("../../../runtime/testdata/settings.json").as_slice(),
        ),
        (
            Endpoint::Info,
            include_bytes!("../../../runtime/testdata/info.json").as_slice(),
        ),
    ] {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        data.apply_http_response(endpoint, &response, response.len(), stamp)
            .unwrap();
    }
    assert!(data.trust_verified());
    assert_eq!(data.write_queue_depth(), 0);
    for node in DEFAULT_NAMESPACE_NODES {
        if let NamespaceTarget::Runtime(runtime) = node.target {
            if runtime.index() >= RuntimeNode::InfoBathAttached.index() {
                continue;
            }
            let metadata = data.cache().validation_metadata(runtime);
            support::admit_publication(
                stamp,
                runtime.freshness_ms(),
                metadata.last_publish_monotonic_ms,
                metadata.freshness_ms,
                metadata.published,
            )
            .unwrap();
        }
    }
}

fn assert_read_and_notification_quality(
    server: &mut OpcUaServer,
    data: &mut DefaultRuntimeDataAccess,
    out: &mut [u8],
    token: NodeId,
    node: u16,
    now: u64,
    good: bool,
) {
    let publish = client_uasc_request_with_auth(service_id::PUBLISH_REQUEST, 506, token, |e| {
        e.write_array_len(0)
    });
    assert_eq!(
        server.handle_frame(&publish, out, data, now - 1).unwrap(),
        FrameAction::NoResponse
    );
    let len = handle_frame_len(server, &read_request(token, &[node]), out, data, now);
    let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        decode_response_header_for_test(&mut decoder).2,
        opcua_status::GOOD
    );
    assert_eq!(decoder.read_array_len(1).unwrap(), 1);
    let expected = (
        if good {
            opcua_status::GOOD
        } else {
            opcua_status::BAD_WAITING_FOR_INITIAL_DATA
        },
        good,
    );
    assert_eq!(
        decode_data_value_status_and_presence_for_test(&mut decoder),
        expected
    );
    let len = server
        .drain_due_publish_response(out, data, now)
        .unwrap()
        .expect_response("field quality notification");
    let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(
        decode_response_header_for_test(&mut decoder).2,
        opcua_status::GOOD
    );
    assert_eq!(decoder.read_u32().unwrap(), 1);
    assert_eq!(decoder.read_array_len(0).unwrap(), 0);
    assert!(!decoder.read_bool().unwrap());
    decoder.read_u32().unwrap();
    decoder.read_i64().unwrap();
    assert_eq!(decoder.read_array_len(1).unwrap(), 1);
    assert_eq!(
        decoder.read_node_id().unwrap(),
        NodeId::numeric(0, service_id::DATA_CHANGE_NOTIFICATION)
    );
    assert_eq!(decoder.read_u8().unwrap(), 1);
    decoder.read_i32().unwrap();
    assert_eq!(decoder.read_array_len(1).unwrap(), 1);
    assert_eq!(decoder.read_u32().unwrap(), 1);
    assert_eq!(
        decode_data_value_status_and_presence_for_test(&mut decoder),
        expected
    );
}

#[test]
fn accelerated_stalled_fields_encoded_recovery_with_live_siblings() {
    let mut cases = 0;
    for origin in support::origins() {
        let mut baseline = DefaultRuntimeDataAccess::new();
        load_all_data(&mut baseline, origin);
        for entry in DEFAULT_NAMESPACE_NODES {
            let NamespaceTarget::Runtime(node) = entry.target else {
                continue;
            };
            if node.index() >= RuntimeNode::InfoBathAttached.index() {
                continue;
            }
            let body = match node.endpoint() {
                Endpoint::Process => {
                    include_bytes!("../../../runtime/testdata/process.json").as_slice()
                }
                Endpoint::Settings => {
                    include_bytes!("../../../runtime/testdata/settings.json").as_slice()
                }
                Endpoint::Info => include_bytes!("../../../runtime/testdata/info.json").as_slice(),
            };
            let values = match node.endpoint() {
                Endpoint::Process => {
                    EndpointValues::Process(opta_buchi::parse_process_json(body).unwrap())
                }
                Endpoint::Settings => {
                    EndpointValues::Settings(opta_buchi::parse_settings_json(body).unwrap())
                }
                Endpoint::Info => EndpointValues::Info(opta_buchi::parse_info_json(body).unwrap()),
            };
            let absent = tag_support::without_field(&format!("{node:?}"), values);
            let absent_is_zero = matches!(
                node,
                RuntimeNode::ProcessGlobalStatusProcessTime | RuntimeNode::ProcessGlobalStatusRunId
            );
            for age in [u64::from(node.freshness_ms()) + 1]
                .into_iter()
                .chain((1..=8).map(|k| k * support::EPOCH_MS))
            {
                let now = origin + age;
                let mut data = baseline.clone();
                data.apply_endpoint_values(absent, now - 1000);
                let metadata = data.cache().validation_metadata(node);
                support::admit_publication(
                    if absent_is_zero { now - 1000 } else { origin },
                    node.freshness_ms(),
                    metadata.last_publish_monotonic_ms,
                    metadata.freshness_ms,
                    metadata.published,
                )
                .unwrap();
                // A new client encounters a retained old cache, then observes
                // recovery on this same server/subscription. Runtime tests also
                // retain the sampler across the entire sparse access interval.
                let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
                let mut out = [0u8; 8192];
                let token = open_session(&mut server, &mut data, &mut out, now - 1000);
                support::admit_origin(
                    (now - 1000) % support::EPOCH_MS,
                    u64::from(server.last_session_activity_ms),
                    server.session_active,
                )
                .unwrap();
                handle_frame_len(
                    &mut server,
                    &subscription_request(token),
                    &mut out,
                    &mut data,
                    now - 1000,
                );
                support::admit_deadline(now - 1000, 1000, server.next_publish_due_ms).unwrap();
                handle_frame_len(
                    &mut server,
                    &monitor_request(token, &[entry.node_id]),
                    &mut out,
                    &mut data,
                    now - 1000,
                );
                assert_read_and_notification_quality(
                    &mut server,
                    &mut data,
                    &mut out,
                    token,
                    entry.node_id,
                    now,
                    absent_is_zero,
                );
                data.apply_endpoint_values(values, now + 1000);
                assert_read_and_notification_quality(
                    &mut server,
                    &mut data,
                    &mut out,
                    token,
                    entry.node_id,
                    now + 1000,
                    true,
                );
                println!("encoded_field origin={origin} node={node:?} id={} freshness={} age={age} missing_zero={absent_is_zero} good={absent_is_zero} recovered=true", entry.node_id, node.freshness_ms());
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 80 * 106 * 9);
    println!("PASS encoded per-field recovery cases={cases}; retained cache and Bad-to-Good subscription");
}

#[test]
fn accelerated_all_data_tags_encoded_reads_and_notifications() {
    let nodes: std::vec::Vec<_> = DEFAULT_NAMESPACE_NODES
        .iter()
        .filter_map(|node| {
            if let NamespaceTarget::Runtime(runtime) = node.target {
                if runtime.index() < RuntimeNode::InfoBathAttached.index() {
                    return Some((node.node_id, runtime));
                }
            }
            None
        })
        .collect();
    assert_eq!(nodes.len(), 80);
    let mut cases = 0;
    for origin in support::origins() {
        for (node_id, runtime) in &nodes {
            for age in [
                u64::from(runtime.freshness_ms()) - 1,
                u64::from(runtime.freshness_ms()),
                u64::from(runtime.freshness_ms()) + 1,
                support::EPOCH_MS,
                2 * support::EPOCH_MS,
                8 * support::EPOCH_MS,
                u64::MAX, // Declared fault: cache publication one millisecond in the future.
            ] {
                let future = age == u64::MAX;
                let now = if future { origin + 1000 } else { origin + age };
                let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
                let mut data = DefaultRuntimeDataAccess::new();
                load_all_data(&mut data, if future { now + 1 } else { origin });
                let mut out = [0u8; 8_192];
                let token = open_session(&mut server, &mut data, &mut out, now - 1_000);
                support::admit_origin(
                    (now - 1_000) % support::EPOCH_MS,
                    u64::from(server.last_session_activity_ms),
                    server.session_active,
                )
                .unwrap();
                handle_frame_len(
                    &mut server,
                    &subscription_request(token),
                    &mut out,
                    &mut data,
                    now - 1_000,
                );
                support::admit_deadline(now - 1_000, 1_000, server.next_publish_due_ms).unwrap();
                handle_frame_len(
                    &mut server,
                    &monitor_request(token, &[*node_id]),
                    &mut out,
                    &mut data,
                    now - 1_000,
                );
                let publish =
                    client_uasc_request_with_auth(service_id::PUBLISH_REQUEST, 506, token, |e| {
                        e.write_array_len(0)
                    });
                assert_eq!(
                    server
                        .handle_frame(&publish, &mut out, &mut data, now - 1)
                        .unwrap(),
                    FrameAction::NoResponse
                );
                let len = handle_frame_len(
                    &mut server,
                    &read_request(token, &[*node_id]),
                    &mut out,
                    &mut data,
                    now,
                );
                let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
                assert_eq!(
                    decode_response_header_for_test(&mut decoder).2,
                    opcua_status::GOOD
                );
                assert_eq!(decoder.read_array_len(1).unwrap(), 1);
                let direct = decode_data_value_status_and_presence_for_test(&mut decoder);
                let good = age <= u64::from(runtime.freshness_ms());
                assert_eq!(
                    direct,
                    (
                        if good {
                            opcua_status::GOOD
                        } else {
                            opcua_status::BAD_WAITING_FOR_INITIAL_DATA
                        },
                        good
                    )
                );
                let len = server
                    .drain_due_publish_response(&mut out, &data, now)
                    .unwrap()
                    .expect_response("encoded notification");
                let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
                decode_response_header_for_test(&mut decoder);
                decoder.read_u32().unwrap(); // subscription id
                assert_eq!(decoder.read_array_len(0).unwrap(), 0);
                assert!(!decoder.read_bool().unwrap());
                decoder.read_u32().unwrap(); // notification sequence
                decoder.read_i64().unwrap(); // publish time
                assert_eq!(decoder.read_array_len(1).unwrap(), 1);
                assert_eq!(
                    decoder.read_node_id().unwrap(),
                    NodeId::numeric(0, service_id::DATA_CHANGE_NOTIFICATION)
                );
                assert_eq!(decoder.read_u8().unwrap(), 1);
                decoder.read_i32().unwrap();
                assert_eq!(decoder.read_array_len(1).unwrap(), 1);
                assert_eq!(decoder.read_u32().unwrap(), 1);
                assert_eq!(
                    decode_data_value_status_and_presence_for_test(&mut decoder),
                    direct
                );
                cases += 1;
            }
        }
    }
    println!("PASS encoded direct/notification data_tags=80 cases={cases}");
}

#[test]
fn accelerated_subscription_lifetime_count_revision_avoids_overflow() {
    for modify in [false, true] {
        let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
        activate_test_session(&mut server);
        let mut data = DefaultRuntimeDataAccess::new();
        let mut out = [0u8; 8192];
        if modify {
            handle_frame_len(
                &mut server,
                &create_subscription_frame(701, 1_000.0, 3, 1, true),
                &mut out,
                &mut data,
                0,
            );
        }
        let request = if modify {
            modify_subscription_frame(702, 1_000.0, u32::MAX, u32::MAX)
        } else {
            create_subscription_frame(702, 1_000.0, u32::MAX, u32::MAX, true)
        };
        let len = handle_frame_len(&mut server, &request, &mut out, &mut data, 0);
        let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
        assert_eq!(
            decode_response_header_for_test(&mut decoder).2,
            opcua_status::GOOD
        );
        if !modify {
            decoder.read_u32().unwrap();
        }
        decoder.read_f64().unwrap();
        let lifetime = decoder.read_u32().unwrap();
        let keepalive = decoder.read_u32().unwrap();
        assert!(
            u64::from(lifetime) >= 3 * u64::from(keepalive),
            "revised counts violate minimum lifetime"
        );
        assert_eq!(server.subscription_lifetime_count, lifetime);
        assert_eq!(server.keepalive_count, keepalive);
    }
}

#[test]
fn accelerated_session_channel_and_wire_sequence_boundaries() {
    for seed in [u32::MAX - 2, u32::MAX - 1, u32::MAX] {
        let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
        let mut data = DefaultRuntimeDataAccess::new();
        let mut out = [0u8; 8192];
        server.next_session_token_id = seed;
        server.sequence_number = seed;
        let mut expected_token = seed;
        let mut expected_wire = seed;
        for _ in 0..5 {
            let len = handle_frame_len(&mut server, &session_request(), &mut out, &mut data, 0);
            let token = create_session_token_for_test(&out[..len]);
            assert_eq!(
                token,
                NodeId::numeric(APPLICATION_NAMESPACE_INDEX, expected_token)
            );
            assert_eq!(
                u32::from_le_bytes(out[16..20].try_into().unwrap()),
                expected_wire
            );
            let next_token = (u64::from(expected_token) + 1) % support::EPOCH_MS;
            expected_token = if next_token == 0 {
                DEFAULT_SESSION_TOKEN_SEED
            } else {
                next_token as u32
            };
            expected_wire = if expected_wire == u32::MAX {
                1
            } else {
                expected_wire + 1
            };
        }
        let mut channel_server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
        channel_server.token_id = seed;
        let mut expected = seed;
        for _ in 0..5 {
            let request = client_open_secure_channel_request(801, 802);
            handle_frame_len(&mut channel_server, &request, &mut out, &mut data, 0);
            expected = if expected == u32::MAX {
                1
            } else {
                expected + 1
            };
            assert_eq!(channel_server.token_id, expected);
        }
    }
}

#[test]
fn accelerated_emit_actual_wire_rollover_responses() {
    // These are actual production encoders/handlers, with only the initial
    // volatile sequence seeded by this host test. No target/NVM seam is added.
    for seed in [123, u32::MAX - 2, u32::MAX - 1, u32::MAX] {
        let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
        activate_test_session(&mut server);
        let mut data = DefaultRuntimeDataAccess::new();
        data.set_trust_state(TrustState::Verified);
        server.sequence_number = seed;
        server.token_id = seed;
        let mut out = [0u8; 8192];
        for step in 0..5 {
            let request = if step == 0 {
                client_open_secure_channel_request(901, 902)
            } else {
                let mut frame = read_request(
                    NodeId::numeric(APPLICATION_NAMESPACE_INDEX, DEFAULT_SESSION_TOKEN_SEED),
                    &[4007, 2001],
                );
                frame[12..16].copy_from_slice(&server.token_id.to_le_bytes());
                frame
            };
            let len = handle_frame_len(&mut server, &request, &mut out, &mut data, 0);
            let (info, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
            let (_, handle, service_status) = decode_response_header_for_test(&mut decoder);
            assert_eq!(service_status, opcua_status::GOOD);
            assert_eq!(info.secure_channel_id, 1);
            assert_eq!(info.request_id, if step == 0 { 901 } else { 505 });
            assert_eq!(handle, if step == 0 { 902 } else { 505 });
            let expected = (u64::from(seed) - 1 + step) % u64::from(u32::MAX) + 1;
            assert_eq!(u64::from(info.sequence_number), expected);
            let hex: std::string::String = out[..len]
                .iter()
                .map(|byte| std::format!("{byte:02x}"))
                .collect();
            std::println!(
                "ACTUAL_WIRE_FRAME {{\"seed\":{seed},\"step\":{step},\"request_id\":{},\"request_handle\":{handle},\"hex\":\"{hex}\"}}",
                info.request_id
            );
        }
    }
}

#[test]
fn accelerated_notification_sequence_wrap_keepalives_do_not_consume_it() {
    for seed in [u32::MAX - 2, u32::MAX - 1, u32::MAX] {
        let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
        let mut data = DefaultRuntimeDataAccess::new();
        let mut out = [0u8; 8192];
        let token = open_session(&mut server, &mut data, &mut out, 0);
        handle_frame_len(
            &mut server,
            &subscription_request(token),
            &mut out,
            &mut data,
            0,
        );
        handle_frame_len(
            &mut server,
            &monitor_request(token, &[2001]),
            &mut out,
            &mut data,
            0,
        );
        server.publish_sequence_number = seed;
        let mut expected = seed;
        for operation in 0..5u64 {
            let now = operation * 2_000 + 1_000;
            data.set_trust_state(TrustState::Verified);
            data.apply_endpoint_values(
                EndpointValues::Process(ProcessValues {
                    roots: ProcessRootPresence {
                        heating: true,
                        global_status: true,
                        ..Default::default()
                    },
                    heating_set_milli_celsius: Some(42_000 + operation as i32),
                    ..Default::default()
                }),
                now - 1,
            );
            let publish =
                client_uasc_request_with_auth(service_id::PUBLISH_REQUEST, 803, token, |e| {
                    e.write_array_len(0)
                });
            assert_eq!(
                server
                    .handle_frame(&publish, &mut out, &mut data, now - 1)
                    .unwrap(),
                FrameAction::NoResponse
            );
            let len = server
                .drain_due_publish_response(&mut out, &data, now)
                .unwrap()
                .expect_response("data");
            let summary = decode_publish_summary_for_test(&out[..len]);
            assert_eq!(summary.sequence_number, expected);
            assert_eq!(summary.notification_data_len, 1);
            expected = if expected == u32::MAX {
                1
            } else {
                expected + 1
            };
            assert_eq!(server.publish_sequence_number, expected);
            assert_eq!(
                server
                    .handle_frame(&publish, &mut out, &mut data, now + 999)
                    .unwrap(),
                FrameAction::NoResponse
            );
            let len = server
                .drain_due_publish_response(&mut out, &data, now + 1_000)
                .unwrap()
                .expect_response("keepalive");
            let summary = decode_publish_summary_for_test(&out[..len]);
            assert_eq!(summary.notification_data_len, 0);
            assert_eq!(summary.sequence_number, expected);
            assert_eq!(server.publish_sequence_number, expected);
        }
    }
}

#[test]
fn accelerated_session_and_subscription_lifetimes_at_all_origins() {
    let mut cases = 0;
    for origin in support::origins() {
        for enabled in [false, true] {
            let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
            let mut data = DefaultRuntimeDataAccess::new();
            let mut out = [0u8; 8192];
            let token = open_session(&mut server, &mut data, &mut out, origin);
            let create = client_uasc_request_with_auth(
                service_id::CREATE_SUBSCRIPTION_REQUEST,
                801,
                token,
                |e| {
                    e.write_f64(1000.0)?;
                    e.write_u32(3)?;
                    e.write_u32(1)?;
                    e.write_u32(0)?;
                    e.write_bool(enabled)?;
                    e.write_u8(0)
                },
            );
            handle_frame_len(&mut server, &create, &mut out, &mut data, origin);
            support::admit_deadline(origin, 1000, server.next_publish_due_ms).unwrap();
            assert_eq!(server.last_session_activity_ms, origin as u32);
            assert_eq!(server.publish_intervals_without_token, 0);
            assert_eq!(server.queued_publish_count, 0);
            // Ordinary Reads renew the session, but cannot replace Publish tokens.
            for interval in 1..=3u64 {
                let due = origin + interval * 1000;
                assert_eq!(
                    server
                        .drain_due_publish_response(&mut out, &data, due - 1)
                        .unwrap(),
                    TimerDrainResult::None
                );
                assert!(server.subscription_active);
                handle_frame_len(
                    &mut server,
                    &read_request(token, &[4022]),
                    &mut out,
                    &mut data,
                    due,
                );
                assert_eq!(
                    server
                        .drain_due_publish_response(&mut out, &data, due)
                        .unwrap(),
                    TimerDrainResult::None
                );
                assert!(server.session_active);
                assert_eq!(server.subscription_active, interval < 3);
                assert_eq!(
                    server
                        .drain_due_publish_response(&mut out, &data, due + 1)
                        .unwrap(),
                    TimerDrainResult::None
                );
            }
            assert_eq!(server.subscription.len(), 0);
            let last_activity = origin + 3000;
            let deadline = last_activity + u64::from(server.session_timeout_ms);
            assert_eq!(
                server
                    .drain_due_publish_response(&mut out, &data, deadline - 1)
                    .unwrap(),
                TimerDrainResult::None
            );
            assert!(server.session_active);
            assert_eq!(
                server
                    .drain_due_publish_response(&mut out, &data, deadline)
                    .unwrap(),
                TimerDrainResult::CloseConnection
            );
            assert!(!server.session_active);
            assert_eq!(server.queued_publish_count, 0);
            assert_eq!(
                server
                    .drain_due_publish_response(&mut out, &data, deadline + 1)
                    .unwrap(),
                TimerDrainResult::None
            );
            cases += 1;
        }
    }
    println!("PASS distinct session/subscription lifetimes cases={cases}; disabled and enabled publishing; deadline -1/at/+1");
}

#[test]
fn accelerated_mixed_protocol_traces_reconnect_and_expiration() {
    let origins = support::origins();
    for trace in 0..100u64 {
        let started = std::time::Instant::now();
        let seed = 0xacce_2000_0000_0000 + trace;
        let mut random = seed;
        let mut now = origins[trace as usize % origins.len()];
        let mut stamp = now;
        let mut trusted = true;
        let mut data = DefaultRuntimeDataAccess::new();
        load_all_data(&mut data, now);
        let mut server = OpcUaServer::new(test_identity(), &TEST_BUILD_INFO);
        let mut out = [0u8; 8192];
        let mut token = open_session(&mut server, &mut data, &mut out, now);
        let mut counts = [0usize; 7];
        for event in 0..1000u64 {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // Each trace guarantees every promised class before randomized ordering.
            let action = if event < 7 {
                event as usize
            } else {
                ((random >> 32) % 7) as usize
            };
            now += 1000 + random % 2001;
            assert!(server.session_active);
            assert_eq!(server.session_timeout_ms, DEFAULT_SESSION_TIMEOUT_MS);
            match action {
                0 => {} // Read below without an update: exercise genuine aging.
                1 => {
                    if trusted {
                        load_all_data(&mut data, now);
                        stamp = now;
                    }
                }
                2 => {
                    data.revoke_upstream_trust();
                    trusted = false;
                }
                3 => {
                    load_all_data(&mut data, now);
                    stamp = now;
                    trusted = true;
                }
                4 => {
                    let close = client_uasc_request_with_auth(
                        service_id::CLOSE_SECURE_CHANNEL_REQUEST,
                        508,
                        token,
                        |_| Ok(()),
                    );
                    assert_eq!(
                        server
                            .handle_frame(&close, &mut out, &mut data, now)
                            .unwrap(),
                        FrameAction::Close
                    );
                    assert!(!server.session_active);
                    token = open_session(&mut server, &mut data, &mut out, now);
                }
                5 => {
                    assert!(!server.subscription_active);
                    let len = handle_frame_len(
                        &mut server,
                        &subscription_request(token),
                        &mut out,
                        &mut data,
                        now,
                    );
                    assert_eq!(service_result(&out[..len]), opcua_status::GOOD);
                    assert!(server.subscription_active);
                    support::admit_deadline(now, 1000, server.next_publish_due_ms).unwrap();
                    // Reads keep the session alive while missing Publish expires
                    // its subscription. Every timer callback is an actual call.
                    for tick in 1..=9 {
                        now += 1000;
                        handle_frame_len(
                            &mut server,
                            &read_request(token, &[2001]),
                            &mut out,
                            &mut data,
                            now,
                        );
                        assert_eq!(
                            server
                                .drain_due_publish_response(&mut out, &data, now)
                                .unwrap(),
                            TimerDrainResult::None
                        );
                        assert_eq!(server.subscription_active, tick < 9);
                        assert!(server.session_active);
                    }
                }
                6 => {
                    handle_frame_len(
                        &mut server,
                        &read_request(token, &[2001]),
                        &mut out,
                        &mut data,
                        now,
                    );
                    now += u64::from(DEFAULT_SESSION_TIMEOUT_MS);
                    assert_eq!(
                        server
                            .drain_due_publish_response(&mut out, &data, now)
                            .unwrap(),
                        TimerDrainResult::CloseConnection
                    );
                    assert!(!server.session_active && !server.subscription_active);
                    assert_eq!(server.queued_publish_count, 0);
                    token = open_session(&mut server, &mut data, &mut out, now);
                }
                _ => unreachable!(),
            }
            counts[action] += 1;
            let len = handle_frame_len(
                &mut server,
                &read_request(token, &[2001]),
                &mut out,
                &mut data,
                now,
            );
            let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
            assert_eq!(
                decode_response_header_for_test(&mut decoder).2,
                opcua_status::GOOD
            );
            assert_eq!(decoder.read_array_len(1).unwrap(), 1);
            let observed = decode_data_value_status_and_presence_for_test(&mut decoder);
            let expected = trusted && now - stamp <= 2500;
            assert_eq!(
                (observed.0 == opcua_status::GOOD, observed.1),
                (expected, expected)
            );
            println!("protocol_trace={trace} seed={seed} event={event} action={action} now_ms={now} stamp_ms={stamp} trusted={trusted} expected_good={expected} status={} present={}",observed.0,observed.1);
        }
        assert!(counts.iter().all(|&n| n > 0));
        assert_eq!(counts.iter().sum::<usize>(), 1000);
        assert!(
            started.elapsed().as_secs() < 60,
            "protocol trace wall-time guard"
        );
        println!("PASS protocol_trace={trace} event_counts={counts:?}");
    }
}
