use super::{assert_health_value, verified_data_access};
use crate::{HealthNode, RuntimeDataAccess, RuntimeNode};
use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::opcua_status;

fn lose_trust<const N: usize>(data: &mut RuntimeDataAccess<N>, state: Option<TrustState>) {
    match state {
        Some(state) => data.set_trust_state(state),
        None => data.revoke_upstream_trust(),
    }
}

#[test]
fn queued_write_cancellation_on_revoke_records_live_entries_and_allows_reuse() {
    assert_live_entries_and_reuse(None);
}

#[test]
fn queued_write_cancellation_on_state_change_records_live_entries_and_allows_reuse() {
    for state in [
        TrustState::Missing,
        TrustState::Provisioned,
        TrustState::VerifyRejected,
        TrustState::Revoked,
    ] {
        assert_live_entries_and_reuse(Some(state));
    }
}

fn assert_live_entries_and_reuse(state: Option<TrustState>) {
    let mut data = verified_data_access::<2>();
    assert!(
        data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(42_000))
            .accepted
    );
    assert!(
        data.enqueue_write_node_id(2003, ScalarValue::Boolean(true))
            .accepted
    );
    let replacement = data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(43_000));
    assert!(replacement.accepted && replacement.coalesced);
    assert_eq!(data.write_queue_depth(), 2);

    lose_trust(&mut data, state);

    assert_eq!(data.trust_state(), state.unwrap_or(TrustState::Revoked));
    assert!(!data.writes_allowed());
    assert_eq!(data.write_queue_depth(), 0);
    assert_eq!(data.pop_write_request(), None);
    assert_eq!(data.health().buchi_write_accepted_count, 3);
    assert_eq!(data.health().buchi_write_completed_count, 0);
    assert_eq!(data.health().buchi_write_failed_count, 2);
    for (node, value) in [
        (HealthNode::BuchiWriteLastTargetNodeId, 2003),
        (HealthNode::BuchiWriteLastHttpStatus, 0),
        (
            HealthNode::BuchiWriteLastOpcUaStatus,
            opcua_status::BAD_USER_ACCESS_DENIED,
        ),
    ] {
        assert_health_value(
            &data,
            node,
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(value)),
        );
    }
    // Repeated revocation and empty transitions must not fabricate outcomes.
    let terminal_health = *data.health();
    lose_trust(&mut data, state);
    assert_eq!(*data.health(), terminal_health);
    let rejected = data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(44_000));
    assert!(!rejected.accepted);
    assert_eq!(rejected.opcua_status, opcua_status::BAD_NOT_WRITABLE);
    assert_eq!(*data.health(), terminal_health);

    data.set_verified_trust_session(false);
    data.set_write_enabled(true);
    assert!(
        data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(45_000))
            .accepted
    );
    let mut body = [0u8; 256];
    let dispatch = data.pop_next_write_json(&mut body).unwrap();
    assert_eq!(dispatch.request.node_id, 2001);
    assert_eq!(dispatch.request.raw_value, 45_000);
    assert_eq!(&body[..dispatch.body_len], br#"{"heating":{"set":45.000}}"#);
    data.record_buchi_write_result(dispatch.request.node_id, 200, opcua_status::GOOD);
    assert_eq!(data.health().buchi_write_accepted_count, 4);
    assert_eq!(data.health().buchi_write_completed_count, 1);
    assert_eq!(data.health().buchi_write_failed_count, 2);
    assert_eq!(
        data.health().buchi_write_last_opcua_status,
        opcua_status::GOOD
    );
    assert_eq!(data.write_queue_depth(), 0);
}

#[test]
fn queued_write_cancellation_does_not_complete_an_already_dequeued_write() {
    for state in [None, Some(TrustState::Provisioned)] {
        let mut data = verified_data_access::<2>();
        assert!(
            data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(42_000))
                .accepted
        );
        let inflight = data.pop_write_request().unwrap();
        assert!(
            data.enqueue_write_node_id(2003, ScalarValue::Boolean(true))
                .accepted
        );
        lose_trust(&mut data, state);
        assert_eq!(data.health().buchi_write_failed_count, 1);
        assert_eq!(data.health().buchi_write_last_target_node_id, 2003);
        assert_eq!(data.health().buchi_write_completed_count, 0);
        assert_eq!(data.write_queue_depth(), 0);

        // The transport still owns the dequeued item and records its own outcome.
        data.record_buchi_write_result(inflight.node_id, 0, opcua_status::BAD_USER_ACCESS_DENIED);
        assert_eq!(data.health().buchi_write_failed_count, 2);
        assert_eq!(data.health().buchi_write_last_target_node_id, 2001);
        lose_trust(&mut data, state);
        assert_eq!(data.health().buchi_write_failed_count, 2);
    }
}

#[test]
fn queued_write_cancellation_saturates_failed_count() {
    for state in [None, Some(TrustState::Provisioned)] {
        let mut data = verified_data_access::<2>();
        data.health_mut().buchi_write_failed_count = u32::MAX - 1;
        data.health_mut().buchi_write_completed_count = 7;
        assert!(
            data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(42_000))
                .accepted
        );
        assert!(
            data.enqueue_write_node_id(2003, ScalarValue::Boolean(true))
                .accepted
        );
        lose_trust(&mut data, state);
        assert_eq!(data.health().buchi_write_failed_count, u32::MAX);
        assert_eq!(data.health().buchi_write_completed_count, 7);
        assert_eq!(data.health().buchi_write_last_target_node_id, 2003);
        assert_eq!(data.health().buchi_write_last_http_status, 0);
        assert_eq!(
            data.health().buchi_write_last_opcua_status,
            opcua_status::BAD_USER_ACCESS_DENIED
        );
        assert_eq!(data.write_queue_depth(), 0);
    }
}

#[test]
fn queued_write_cancellation_preserves_verified_noop_and_empty_queue_telemetry() {
    let mut data = verified_data_access::<1>();
    let accepted = data.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_000),
    );
    assert!(accepted.accepted);
    let accepted_health = *data.health();
    data.set_trust_state(TrustState::Verified);
    assert_eq!(*data.health(), accepted_health);
    assert_eq!(data.write_queue_depth(), 1);
    let request = data.pop_write_request().unwrap();
    assert_eq!(Some(request.sequence), accepted.sequence);
    data.record_buchi_write_result(request.node_id, 200, opcua_status::GOOD);
    data.set_trust_state(TrustState::Provisioned);
    let finished_health = *data.health();
    data.set_trust_state(TrustState::Provisioned);
    assert_eq!(*data.health(), finished_health);
    data.revoke_upstream_trust();
    assert_eq!(data.health().buchi_write_completed_count, 1);
    assert_eq!(data.health().buchi_write_failed_count, 0);
    assert_eq!(data.health().buchi_write_last_target_node_id, 2001);
    assert_eq!(data.health().buchi_write_last_http_status, 200);
    assert_eq!(
        data.health().buchi_write_last_opcua_status,
        opcua_status::GOOD
    );
}
