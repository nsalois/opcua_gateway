//! Static pin for target-only async lock scope in the OPC UA listener.

const PRODUCT_OPCUA: &str = include_str!("../../../firmware/opta-m7/src/product_opcua.rs");

#[test]
fn shared_opcua_buffers_are_not_locked_across_socket_awaits() {
    assert!(
        !PRODUCT_OPCUA.contains("Mutex<NoopRawMutex, OpcUaBuffers>"),
        "fleet-wide OPC UA buffer mutex was reintroduced"
    );
    assert!(
        !PRODUCT_OPCUA.contains("buffers.lock().await"),
        "listener still leases shared OPC UA buffers"
    );
}

#[test]
fn runtime_lock_does_not_span_socket_awaits() {
    assert_eq!(
        PRODUCT_OPCUA.matches("runtime.lock().await").count(),
        2,
        "review every runtime lock region before changing this source pin"
    );

    let publish_drain_region = source_region(
        "let response_len = {",
        "let drain = match response_len {",
        "Publish drain runtime lock",
    );
    let frame_handler_region = source_region(
        "let action = {",
        "let action = match action {",
        "frame-handler runtime lock",
    );

    for (label, region) in [
        ("Publish drain", publish_drain_region),
        ("frame handler", frame_handler_region),
    ] {
        assert!(
            region.contains("runtime.lock().await"),
            "{label} source pin no longer covers the runtime lock"
        );
        assert!(
            !region.contains("socket."),
            "{label} holds the shared runtime lock across a socket operation"
        );
    }
}

fn source_region(start: &str, end: &str, label: &str) -> &'static str {
    let start_offset = PRODUCT_OPCUA
        .find(start)
        .unwrap_or_else(|| panic!("{label} start marker changed"));
    let remainder = &PRODUCT_OPCUA[start_offset..];
    let end_offset = remainder
        .find(end)
        .unwrap_or_else(|| panic!("{label} end marker changed"));
    &remainder[..end_offset]
}
