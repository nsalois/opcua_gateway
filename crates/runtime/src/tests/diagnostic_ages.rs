use crate::{DiagnosticAge, RuntimeDataAccess, RuntimeNode};
use opta_buchi::{Endpoint, EndpointValues, ProcessValues};
use opta_gateway_contracts::{config::TrustState, freshness::ScalarValue, opcua_status};

fn baseline(now: u64) -> RuntimeDataAccess<1> {
    let mut data = RuntimeDataAccess::new();
    data.set_verified_trust_session(true);
    data.set_write_enabled(true);
    let response = super::http_ok(super::PROCESS_JSON);
    data.apply_http_response(Endpoint::Process, &response, response.len(), now)
        .unwrap();
    data
}

#[test]
fn finite_age_cases_preserve_value_and_restore_the_real_owner() {
    let now = (8u64 << 32) + 100_000;
    let mut data = baseline(now);
    let unchanged = data.clone();
    for (index, age) in DiagnosticAge::ALL.into_iter().enumerate() {
        let row = data
            .diagnostic_age_case(RuntimeNode::ProcessHeatingSet, age, now)
            .unwrap();
        let expected_publication = match index {
            0 => now - 2499,
            1 => now - 2500,
            2 => now - 2501,
            3 => now + 1,
            _ => now - ((index as u64 - 3) * 4_294_967_296),
        };
        let status = if index < 2 { 0 } else { 0x8032_0000 };
        let value = if index < 2 {
            Some(ScalarValue::FloatMilli(42_125))
        } else {
            None
        };
        assert_eq!(row.original.last_publish_monotonic_ms, now);
        assert_eq!(row.original.freshness_ms, 2500);
        assert_eq!(row.injected.last_publish_monotonic_ms, expected_publication);
        assert_eq!(row.injected.freshness_ms, 2500);
        assert!(row.injected.published);
        assert_eq!((row.direct.opcua_status, row.direct.value), (status, value));
        let sampled = row.sampled.unwrap();
        assert_eq!((sampled.opcua_status, sampled.value), (status, value));
        assert_eq!((sampled.node_id, sampled.client_handle), (2001, 1));
        assert!(sampled.changed);
        assert_eq!(row.restored, row.original);
        assert_eq!(row.restored_read, row.baseline);
        assert_eq!(data, unchanged);
    }
}

#[test]
fn invalid_owners_and_unrepresentable_ages_do_not_mutate() {
    let now = 100_000;
    let data = baseline(now);
    for variant in 0..6 {
        let mut rejected = data.clone();
        match variant {
            0 => rejected.set_trust_state(TrustState::Revoked),
            1 => rejected.set_write_enabled(false),
            2 => {
                rejected.enqueue_write_node(
                    RuntimeNode::ProcessHeatingSet,
                    ScalarValue::FloatMilli(43_000),
                );
            }
            3 => {
                rejected
                    .apply_endpoint_values(EndpointValues::Process(ProcessValues::default()), now);
            }
            4 => {
                rejected.record_endpoint_failure(
                    Endpoint::Process,
                    opta_buchi::EndpointResponseError::Body(opta_buchi::ParseError::Malformed),
                );
            }
            _ => {}
        }
        let before = rejected.clone();
        let age = if variant == 5 {
            DiagnosticAge::Epoch1
        } else {
            DiagnosticAge::AtFreshness
        };
        assert!(rejected
            .diagnostic_age_case(RuntimeNode::ProcessHeatingSet, age, now)
            .is_none());
        assert_eq!(rejected, before);
    }
    let mut data = baseline(now);
    assert!(data
        .diagnostic_age_case(
            RuntimeNode::ProcessHeatingSet,
            DiagnosticAge::AtFreshness,
            now + 2501
        )
        .is_none());
    assert_eq!(
        data.read_node(RuntimeNode::ProcessHeatingSet, now)
            .opcua_status,
        opcua_status::GOOD
    );
}
