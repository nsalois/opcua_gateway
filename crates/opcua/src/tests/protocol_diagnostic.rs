// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use crate::tests::{
    client_open_secure_channel_request, client_uasc_request_with_auth,
    create_session_token_for_test, decode_publish_summary_for_test,
    decode_response_header_for_test, handle_frame_len, test_identity, TEST_BUILD_INFO,
};
use crate::{
    decode_uasc_prefix, service_id, DiagnosticIdentifierRecipe, FrameAction, NodeId, OpcUaServer,
    TransportLimits, APPLICATION_NAMESPACE_INDEX, ATTR_VALUE, DEFAULT_SESSION_TOKEN_SEED,
    PRODUCT_NAMESPACE_INDEX,
};
use opta_buchi::{EndpointValues, ProcessRootPresence, ProcessValues};
use opta_gateway_contracts::config::TrustState;
use opta_runtime::DefaultRuntimeDataAccess;

fn session_request(handle: u32) -> std::vec::Vec<u8> {
    client_uasc_request_with_auth(
        service_id::CREATE_SESSION_REQUEST,
        handle,
        NodeId::numeric(0, 0),
        |e| {
            e.write_string("urn:protocol-diagnostic")?;
            e.write_string("urn:client-product")?;
            e.write_localized_text("protocol diagnostic")?;
            e.write_i32(1)?;
            e.write_string("")?;
            e.write_string("")?;
            e.write_array_len(0)?;
            e.write_null_string()?;
            e.write_string("opc.tcp://localhost:4840")?;
            e.write_string("diagnostic")?;
            e.write_null_byte_string()?;
            e.write_null_byte_string()?;
            e.write_f64(60_000.0)?;
            e.write_u32(0)
        },
    )
}

fn good_frame(
    server: &mut OpcUaServer,
    frame: std::vec::Vec<u8>,
    out: &mut [u8],
    data: &mut DefaultRuntimeDataAccess,
) -> usize {
    good_at(server, frame, out, data, 0)
}

fn good_at(
    server: &mut OpcUaServer,
    mut frame: std::vec::Vec<u8>,
    out: &mut [u8],
    data: &mut DefaultRuntimeDataAccess,
    now: u64,
) -> usize {
    frame[12..16].copy_from_slice(&server.token_id.to_le_bytes());
    let len = handle_frame_len(server, &frame, out, data, now);
    let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
    assert_eq!(decode_response_header_for_test(&mut decoder).2, 0);
    len
}

#[test]
fn diagnostic_identifier_input_is_finite() {
    for value in [0, 4, u32::MAX] {
        assert_eq!(DiagnosticIdentifierRecipe::from_recipe(value), None);
    }
    for value in 1..=3 {
        assert_eq!(
            DiagnosticIdentifierRecipe::from_recipe(value)
                .unwrap()
                .seed(),
            u32::MAX - 3 + value
        );
    }
}

#[test]
fn diagnostic_publish_initialization_is_consumed_once_by_actual_creation() {
    for value in 1..=3 {
        let recipe = DiagnosticIdentifierRecipe::from_recipe(value).unwrap();
        let mut server = OpcUaServer::new_with_diagnostic_identifiers(
            test_identity(),
            &TEST_BUILD_INFO,
            TransportLimits::product_target(),
            recipe,
        );
        assert_eq!(server.token_id, recipe.seed());
        assert_eq!(server.sequence_number, recipe.seed());
        assert_eq!(server.next_session_token_id, recipe.seed());
        assert_eq!(server.publish_sequence_number, 1);
        let mut data = DefaultRuntimeDataAccess::new();
        let mut out = [0u8; 8192];
        let len = good_frame(&mut server, session_request(701), &mut out, &mut data);
        let token = create_session_token_for_test(&out[..len]);
        assert_eq!(
            token,
            NodeId::numeric(APPLICATION_NAMESPACE_INDEX, recipe.seed())
        );
        good_frame(
            &mut server,
            client_uasc_request_with_auth(service_id::ACTIVATE_SESSION_REQUEST, 702, token, |_| {
                Ok(())
            }),
            &mut out,
            &mut data,
        );
        let create = || {
            client_uasc_request_with_auth(
                service_id::CREATE_SUBSCRIPTION_REQUEST,
                703,
                token,
                |e| {
                    e.write_f64(1000.0)?;
                    e.write_u32(10)?;
                    e.write_u32(1)?;
                    e.write_u32(0)?;
                    e.write_bool(true)?;
                    e.write_u8(0)
                },
            )
        };
        good_frame(&mut server, create(), &mut out, &mut data);
        assert_eq!(server.publish_sequence_number, recipe.seed());
        assert_eq!(server.initial_publish_sequence, None);
        let len = good_frame(
            &mut server,
            client_uasc_request_with_auth(
                service_id::DELETE_SUBSCRIPTIONS_REQUEST,
                704,
                token,
                |e| {
                    e.write_array_len(1)?;
                    e.write_u32(1)
                },
            ),
            &mut out,
            &mut data,
        );
        let (_, mut decoder, _) = decode_uasc_prefix(&out[..len]).unwrap();
        decode_response_header_for_test(&mut decoder);
        assert_eq!(decoder.read_array_len(1).unwrap(), 1);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert!(!server.subscription_active);
        good_frame(&mut server, create(), &mut out, &mut data);
        assert_eq!(server.publish_sequence_number, 1);
    }
}

fn monitor_request(handle: u32, token: NodeId) -> std::vec::Vec<u8> {
    client_uasc_request_with_auth(
        service_id::CREATE_MONITORED_ITEMS_REQUEST,
        handle,
        token,
        |e| {
            e.write_u32(1)?;
            e.write_i32(2)?;
            e.write_array_len(1)?;
            e.write_node_id(NodeId::numeric(PRODUCT_NAMESPACE_INDEX, 2001))?;
            e.write_u32(ATTR_VALUE)?;
            e.write_null_string()?;
            e.write_qualified_name(0, "")?;
            e.write_i32(2)?;
            e.write_u32(77)?;
            e.write_f64(1000.0)?;
            e.write_extension_object_none()?;
            e.write_u32(1)?;
            e.write_bool(true)
        },
    )
}

fn emit(seed: u32, step: &mut u64, bytes: &[u8]) {
    let (info, mut decoder, _) = decode_uasc_prefix(bytes).unwrap();
    let (_, handle, status) = decode_response_header_for_test(&mut decoder);
    assert_eq!(status, 0);
    assert_eq!(
        u64::from(info.sequence_number),
        (u64::from(seed) - 1 + *step) % u64::from(u32::MAX) + 1
    );
    let hex: std::string::String = bytes.iter().map(|b| std::format!("{b:02x}")).collect();
    std::println!("ACTUAL_IDENTIFIER_FRAME {{\"seed\":{seed},\"step\":{step},\"request_id\":{},\"request_handle\":{handle},\"hex\":\"{hex}\"}}",info.request_id);
    *step += 1;
}

#[test]
fn diagnostic_constructor_emits_actual_identifier_rollover_responses() {
    // No private owner is changed after the constructor. Sessions, renewal,
    // subscriptions, monitoring and Publish all use actual service handlers.
    for recipe in 1..=3 {
        let recipe = DiagnosticIdentifierRecipe::from_recipe(recipe).unwrap();
        let seed = recipe.seed();
        let mut server = OpcUaServer::new_with_diagnostic_identifiers(
            test_identity(),
            &TEST_BUILD_INFO,
            TransportLimits::product_target(),
            recipe,
        );
        let mut data = DefaultRuntimeDataAccess::new();
        let mut out = [0u8; 8192];
        let mut step = 0;
        let len = handle_frame_len(
            &mut server,
            &client_open_secure_channel_request(800, 800),
            &mut out,
            &mut data,
            0,
        );
        emit(seed, &mut step, &out[..len]);
        let mut token = NodeId::numeric(0, 0);
        let mut expected_session = seed;
        for handle in 801..=805 {
            let len = good_frame(&mut server, session_request(handle), &mut out, &mut data);
            token = create_session_token_for_test(&out[..len]);
            assert_eq!(
                token,
                NodeId::numeric(APPLICATION_NAMESPACE_INDEX, expected_session)
            );
            expected_session = if expected_session == u32::MAX {
                DEFAULT_SESSION_TOKEN_SEED
            } else {
                expected_session + 1
            };
            emit(seed, &mut step, &out[..len]);
        }
        let len = good_frame(
            &mut server,
            client_uasc_request_with_auth(service_id::ACTIVATE_SESSION_REQUEST, 806, token, |_| {
                Ok(())
            }),
            &mut out,
            &mut data,
        );
        emit(seed, &mut step, &out[..len]);
        for handle in [807, 822] {
            let request = client_uasc_request_with_auth(
                service_id::CREATE_SUBSCRIPTION_REQUEST,
                handle,
                token,
                |e| {
                    e.write_f64(1000.0)?;
                    e.write_u32(30)?;
                    e.write_u32(1)?;
                    e.write_u32(0)?;
                    e.write_bool(true)?;
                    e.write_u8(0)
                },
            );
            let now = if handle == 807 { 0 } else { 6000 };
            let len = good_at(&mut server, request, &mut out, &mut data, now);
            emit(seed, &mut step, &out[..len]);
            let len = good_at(
                &mut server,
                monitor_request(handle + 1, token),
                &mut out,
                &mut data,
                now,
            );
            emit(seed, &mut step, &out[..len]);
            let publications = if handle == 807 { 5 } else { 1 };
            for operation in 0..publications {
                let now = if handle == 807 {
                    1000 + operation * 1000
                } else {
                    7000
                };
                data.set_trust_state(TrustState::Verified);
                data.apply_endpoint_values(
                    EndpointValues::Process(ProcessValues {
                        roots: ProcessRootPresence {
                            heating: true,
                            global_status: true,
                            ..Default::default()
                        },
                        heating_set_milli_celsius: Some(42000 + operation as i32),
                        ..Default::default()
                    }),
                    now - 1,
                );
                let mut request = client_uasc_request_with_auth(
                    service_id::PUBLISH_REQUEST,
                    if handle == 807 {
                        809 + operation as u32
                    } else {
                        824
                    },
                    token,
                    |e| e.write_array_len(0),
                );
                request[12..16].copy_from_slice(&server.token_id.to_le_bytes());
                assert_eq!(
                    server
                        .handle_frame(&request, &mut out, &mut data, now - 1)
                        .unwrap(),
                    FrameAction::NoResponse
                );
                let len = server
                    .drain_due_publish_response(&mut out, &data, now)
                    .unwrap()
                    .expect_response("actual DataChange");
                let summary = decode_publish_summary_for_test(&out[..len]);
                assert_eq!(summary.notification_data_len, 1);
                assert_eq!(
                    u64::from(summary.sequence_number),
                    if handle == 807 {
                        (u64::from(seed) - 1 + operation) % u64::from(u32::MAX) + 1
                    } else {
                        1
                    }
                );
                emit(seed, &mut step, &out[..len]);
            }
            if handle == 822 {
                break;
            }
            // No change: the next keepalive uses, and does not consume, the next
            // DataChange sequence. Renewal preserves the channel wire sequence.
            let mut request =
                client_uasc_request_with_auth(service_id::PUBLISH_REQUEST, 814, token, |e| {
                    e.write_array_len(0)
                });
            request[12..16].copy_from_slice(&server.token_id.to_le_bytes());
            assert_eq!(
                server
                    .handle_frame(&request, &mut out, &mut data, 5999)
                    .unwrap(),
                FrameAction::NoResponse
            );
            let len = server
                .drain_due_publish_response(&mut out, &data, 6000)
                .unwrap()
                .expect_response("actual keepalive");
            assert_eq!(
                decode_publish_summary_for_test(&out[..len]).notification_data_len,
                0
            );
            emit(seed, &mut step, &out[..len]);
            for handle in 815..=818 {
                let mut request = client_open_secure_channel_request(handle, handle);
                request[8..12].copy_from_slice(&1u32.to_le_bytes());
                let request_type = request.len() - 16;
                request[request_type..request_type + 4].copy_from_slice(&1u32.to_le_bytes());
                let len = handle_frame_len(&mut server, &request, &mut out, &mut data, 6000);
                emit(seed, &mut step, &out[..len]);
            }
            let len = good_at(
                &mut server,
                client_uasc_request_with_auth(
                    service_id::DELETE_SUBSCRIPTIONS_REQUEST,
                    821,
                    token,
                    |e| {
                        e.write_array_len(1)?;
                        e.write_u32(1)
                    },
                ),
                &mut out,
                &mut data,
                6000,
            );
            assert!(!server.subscription_active);
            emit(seed, &mut step, &out[..len]);
        }
        assert_eq!(step, 23);
    }
}
