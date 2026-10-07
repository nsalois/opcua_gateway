// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use opta_buchi::Endpoint;
use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::opcua_status;
use opta_opcua::Encoder;
use opta_runtime::{DefaultRuntimeDataAccess, RuntimeNode};
use proptest::prelude::*;

fn http_ok(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn apply_process(body: &[u8], limit: usize) -> DefaultRuntimeDataAccess {
    let mut runtime = DefaultRuntimeDataAccess::new();
    runtime.set_trust_state(TrustState::Verified);
    runtime
        .apply_http_response(Endpoint::Process, &http_ok(body), limit, 100)
        .unwrap();
    runtime
}

fn assert_good_finite_variant(runtime: &DefaultRuntimeDataAccess, node: RuntimeNode) {
    let read = runtime.read_node(node, 100);
    assert_eq!(read.opcua_status, opcua_status::GOOD);
    let value = read.value.expect("Good read carries a scalar");
    let ScalarValue::FloatMilli(_) = value else {
        panic!("expected Float scalar, got {value:?}");
    };
    let mut encoded = [0u8; 8];
    let mut encoder = Encoder::new(&mut encoded);
    encoder.write_scalar_variant(value).unwrap();
    assert_eq!(encoder.finish(), 5);
    let float = f32::from_le_bytes(encoded[1..5].try_into().unwrap());
    assert!(
        float.is_finite(),
        "Good OPC UA Float is non-finite: {float}"
    );
}

proptest! {
    #[test]
    fn hostile_numeric_tokens_never_become_good_float_variants(
        token in prop_oneof![
            Just("null".to_owned()),
            Just("NaN".to_owned()),
            Just("Infinity".to_owned()),
            Just("-Infinity".to_owned()),
            Just("\"42.5\"".to_owned()),
            "[0-9]{11,80}",
            "-[0-9]{11,80}",
        ]
    ) {
        let body = format!(r#"{{"heating":{{"act":{token}}},"vacuum":{{"act":125}}}}"#);
        let runtime = apply_process(body.as_bytes(), 4096);
        let hostile = runtime.read_node(RuntimeNode::ProcessBathTemperature, 100);
        prop_assert_ne!(hostile.opcua_status, opcua_status::GOOD);
        prop_assert_eq!(hostile.value, None);
        assert_good_finite_variant(&runtime, RuntimeNode::ProcessPressure);
    }
}

#[test]
fn exact_temperature_plausibility_bounds_encode_as_finite_good_variants() {
    for value in ["-40", "250"] {
        let body = format!(r#"{{"heating":{{"act":{value}}}}}"#);
        let runtime = apply_process(body.as_bytes(), 4096);
        assert_good_finite_variant(&runtime, RuntimeNode::ProcessBathTemperature);
    }
}

#[test]
#[ignore = "pins open finding BH-19"]
fn temperature_epsilon_outside_plausibility_bounds_is_not_good() {
    for value in ["-40.001", "250.001"] {
        let body = format!(r#"{{"heating":{{"act":{value}}}}}"#);
        let runtime = apply_process(body.as_bytes(), 4096);
        let read = runtime.read_node(RuntimeNode::ProcessBathTemperature, 100);
        assert_ne!(read.opcua_status, opcua_status::GOOD, "value={value}");
        assert_eq!(read.value, None, "value={value}");
    }
}

#[test]
#[ignore = "pins open finding BH-18"]
fn unknown_nonempty_array_does_not_hide_later_supported_sibling() {
    let runtime = apply_process(
        br#"{"unknown":[1,2,{"nested":[3,4]}],"heating":{"act":42.5}}"#,
        4096,
    );
    assert_good_finite_variant(&runtime, RuntimeNode::ProcessBathTemperature);
}

#[test]
fn oversized_utf8_string_is_rejected_as_a_bounded_response_not_truncated() {
    let note = "🧪".repeat(300);
    let body = format!(r#"{{"note":"{note}","heating":{{"act":42.5}}}}"#);
    let mut runtime = DefaultRuntimeDataAccess::new();
    runtime.set_trust_state(TrustState::Verified);
    assert!(runtime
        .apply_http_response(Endpoint::Process, &http_ok(body.as_bytes()), 512, 100)
        .is_err());
    let read = runtime.read_node(RuntimeNode::ProcessBathTemperature, 100);
    assert_ne!(read.opcua_status, opcua_status::GOOD);
    assert_eq!(read.value, None);
}
