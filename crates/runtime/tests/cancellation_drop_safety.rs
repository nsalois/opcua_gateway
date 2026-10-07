use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::product;
use opta_runtime::{DefaultRuntimeDataAccess, RuntimeNode};

#[test]
#[ignore = "pins open finding BH-16"]
fn response_loss_retry_does_not_create_a_second_upstream_write() {
    let mut runtime = DefaultRuntimeDataAccess::new();
    runtime.set_trust_state(TrustState::Verified);
    runtime.set_write_enabled(true);

    let first = runtime.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_125),
    );
    assert!(first.accepted);

    // Transport can dequeue the PUT after OpcUaServer has mutated runtime state
    // but before the WriteResponse reaches the client.
    let mut body = [0u8; product::BUCHI_WRITE_JSON_BYTES];
    let dispatched = runtime.pop_next_write_json(&mut body).unwrap();
    assert_eq!(runtime.write_queue_depth(), 0);

    // A client that observed the dropped response retries the same setpoint.
    let retry = runtime.enqueue_write_node(
        RuntimeNode::ProcessHeatingSet,
        ScalarValue::FloatMilli(42_125),
    );
    assert_eq!(retry.sequence, Some(dispatched.request.sequence));
    assert_eq!(runtime.write_queue_depth(), 0);
}
