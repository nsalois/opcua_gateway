#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Native, bounded OPC UA subset for the Rust Opta gateway.
//!
//! This crate intentionally implements only the product surface defined by ADR 0010:
//! UA-TCP HEL/ACK, UASC chunks with SecurityPolicy `None`, anonymous session
//! establishment, Browse/Read/Write, and bounded Value-only DataChange
//! subscriptions over the compile-time Buchi namespace. It is not an OPC
//! Foundation conformance claim.

use opta_runtime::DefaultDataChangeSubscription;

mod build_info;
pub use build_info::BuildInfo;

mod public_constants;
mod server_identity;
pub use public_constants::{
    APPLICATION_NAME, APPLICATION_NAMESPACE_INDEX, DEFAULT_ENDPOINT_URL, DEFAULT_MAX_CHUNK_COUNT,
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_RECEIVE_BUFFER_SIZE, DEFAULT_SEND_BUFFER_SIZE,
    MAX_BROWSE_REFERENCES_PER_RESULT, MAX_BULK_SERVICE_OPERATIONS, MAX_ENDPOINT_URL_LEN,
    MAX_MONITORED_ITEM_OPERATIONS, MAX_REQUESTED_NODES, PRODUCT_NAMESPACE_INDEX,
    PRODUCT_NAMESPACE_URI, PRODUCT_TARGET_BUFFER_SIZE, PRODUCT_URI, SECURITY_POLICY_NONE,
    TRANSPORT_PROFILE_URI,
};
pub use server_identity::{ServerIdentity, APPLICATION_URI_PREFIX};
const OPCUA_DATETIME_TICKS_PER_MILLISECOND: i64 = 10_000;
const MAX_QUEUED_PUBLISH_REQUESTS: usize = 5;
// Fallback for clients which send a null RequestHeader timestamp. The target has
// no wall-clock input to this channel path; a non-null client RequestHeader
// timestamp is mirrored into the SecureChannel token.
const NULL_TIMESTAMP_CHANNEL_EPOCH_UTC: i64 = 134_269_056_000_000_000; // 2026-06-26T00:00:00Z
const NULL_TIMESTAMP_TOKEN_LIFETIME_MS: u32 = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TOKEN_SEED: u32 = 7_001;
const SESSION_TOKEN_SENTINEL_ID: u32 = 0;
const SECURITY_TOKEN_REQUEST_TYPE_RENEW: i32 = 1;
/// Product default revisedSessionTimeout (ms) when client omits/oversize request.
const DEFAULT_SESSION_TIMEOUT_MS: u32 = 600_000;
/// Floor so short host/unit tests can request a few seconds without being clamped
/// to the product default; still long enough to avoid accidental reclaim.
const MIN_SESSION_TIMEOUT_MS: u32 = 1_000;
const MAX_SESSION_TIMEOUT_MS: u32 = 600_000;

pub const PRODUCT_OBJECT_BUCHI: u16 = 900;
pub const PRODUCT_OBJECT_INFO: u16 = 1000;
pub const PRODUCT_OBJECT_PROCESS: u16 = 2000;
pub const PRODUCT_OBJECT_SETTINGS: u16 = 3000;
pub const PRODUCT_OBJECT_HEALTH: u16 = 4000;

const NODEID_ROOT_FOLDER: u32 = 84;
const NODEID_OBJECTS_FOLDER: u32 = 85;
const NODEID_TYPES_FOLDER: u32 = 86;
const NODEID_VIEWS_FOLDER: u32 = 87;
const NODEID_REFERENCES: u32 = 31;
const NODEID_NON_HIERARCHICAL_REFERENCES: u32 = 32;
const NODEID_HIERARCHICAL_REFERENCES: u32 = 33;
const NODEID_HAS_CHILD: u32 = 34;
const NODEID_ORGANIZES: u32 = 35;
const NODEID_HAS_TYPE_DEFINITION: u32 = 40;
const NODEID_AGGREGATES: u32 = 44;
const NODEID_HAS_SUBTYPE: u32 = 45;
const NODEID_HAS_PROPERTY: u32 = 46;
const NODEID_HAS_COMPONENT: u32 = 47;
const NODEID_BASE_OBJECT_TYPE: u32 = 58;
const NODEID_BASE_VARIABLE_TYPE: u32 = 62;
const NODEID_BASE_DATA_VARIABLE_TYPE: u32 = 63;
const NODEID_FOLDER_TYPE: u32 = 61;
const NODEID_SERVER: u32 = 2253;
const NODEID_SERVER_ARRAY: u32 = 2254;
const NODEID_NAMESPACE_ARRAY: u32 = 2255;
const NODEID_SERVER_STATUS: u32 = 2256;
const NODEID_SERVER_STATUS_CURRENT_TIME: u32 = 2258;
const NODEID_SERVER_STATUS_STATE: u32 = 2259;
const NODEID_SERVER_SERVICE_LEVEL: u32 = 2267;

const DATATYPE_BOOLEAN: u32 = 1;
const DATATYPE_BYTE: u32 = 3;
const DATATYPE_BASE_DATA_TYPE: u32 = 24;
const DATATYPE_INT32: u32 = 6;
const DATATYPE_UINT32: u32 = 7;
const DATATYPE_FLOAT: u32 = 10;
const DATATYPE_STRING: u32 = 12;
const DATATYPE_DATETIME: u32 = 13;
const DATATYPE_SERVER_STATUS: u32 = 862;

const ATTR_NODEID: u32 = 1;
const ATTR_NODECLASS: u32 = 2;
const ATTR_BROWSENAME: u32 = 3;
const ATTR_DISPLAYNAME: u32 = 4;
const ATTR_VALUE: u32 = 13;
const ATTR_DATATYPE: u32 = 14;
const ATTR_VALUERANK: u32 = 15;
const ATTR_ACCESSLEVEL: u32 = 17;
const ATTR_USERACCESSLEVEL: u32 = 18;
const ATTR_EVENTNOTIFIER: u32 = 12;
const ATTR_HISTORIZING: u32 = 20;

const NODECLASS_OBJECT: i32 = 1;
const NODECLASS_VARIABLE: i32 = 2;
const NODECLASS_OBJECT_TYPE: i32 = 8;
const NODECLASS_VARIABLE_TYPE: i32 = 16;
const NODECLASS_REFERENCE_TYPE: i32 = 32;
const NODECLASS_DATA_TYPE: i32 = 64;

const VARIANT_ARRAY_BIT: u8 = 0x80;
const VARIANT_BOOLEAN: u8 = 1;
const VARIANT_BYTE: u8 = 3;
const VARIANT_INT32: u8 = 6;
const VARIANT_UINT32: u8 = 7;
const VARIANT_FLOAT: u8 = 10;
const VARIANT_STRING: u8 = 12;
const VARIANT_DATETIME: u8 = 13;
const VARIANT_NODEID: u8 = 17;
const VARIANT_QUALIFIED_NAME: u8 = 20;
const VARIANT_LOCALIZED_TEXT: u8 = 21;

const DATA_VALUE_HAS_VALUE: u8 = 0x01;
const DATA_VALUE_HAS_STATUS: u8 = 0x02;
const DATA_VALUE_HAS_SOURCE_TIMESTAMP: u8 = 0x04;
const DATA_VALUE_HAS_SERVER_TIMESTAMP: u8 = 0x08;
const DATA_VALUE_HAS_SOURCE_PICOSECONDS: u8 = 0x10;
const DATA_VALUE_HAS_SERVER_PICOSECONDS: u8 = 0x20;
const DATA_VALUE_KNOWN_MASK: u8 = DATA_VALUE_HAS_VALUE
    | DATA_VALUE_HAS_STATUS
    | DATA_VALUE_HAS_SOURCE_TIMESTAMP
    | DATA_VALUE_HAS_SERVER_TIMESTAMP
    | DATA_VALUE_HAS_SOURCE_PICOSECONDS
    | DATA_VALUE_HAS_SERVER_PICOSECONDS;

mod service_constants;
pub use service_constants::{service_id, status};

mod wire;
pub use wire::{
    decode_first_read_value_node, decode_hello, decode_uasc_request_info, encode_ack,
    encode_tcp_error, parse_frame_header, AcknowledgeMessage, BrowseDescription, DecodedScalar,
    DecodedWriteValue, Decoder, Encoder, FrameAction, FrameHeader, FrameKind, HelloMessage, NodeId,
    OpcUaError, QueuedPublishRequest, ReadValueId, RequestHeader, Result, TimerDrainResult,
    TransportLimits, UascRequestInfo,
};
pub(crate) use wire::{decode_uasc_prefix, normalize_session_token_seed, BrowseReference};

pub struct OpcUaServer {
    build_info: &'static BuildInfo,
    pub(crate) identity: ServerIdentity,
    limits: TransportLimits,
    secure_channel_id: u32,
    token_id: u32,
    previous_token_id: Option<u32>,
    sequence_number: u32,
    session_token: NodeId,
    session_token_minted: bool,
    next_session_token_id: u32,
    endpoint_url: [u8; MAX_ENDPOINT_URL_LEN],
    endpoint_url_len: usize,
    session_active: bool,
    /// Revised session timeout (ms) from CreateSession; enforced for B.5a idle reclaim.
    session_timeout_ms: u32,
    /// Monotonic ms of last session activity (Create/Activate or session-guarded service).
    last_session_activity_ms: u32,
    subscription_active: bool,
    subscription_id: u32,
    /// Revised lifetime count (publishing intervals without a Publish token).
    subscription_lifetime_count: u32,
    /// Consecutive publishing-timer firings with no Publish request available (B.5b).
    publish_intervals_without_token: u32,
    publish_sequence_number: u32,
    #[cfg(feature = "diagnostic-protocol-identifiers")]
    initial_publish_sequence: Option<u32>,
    queued_publish_requests: [Option<QueuedPublishRequest>; MAX_QUEUED_PUBLISH_REQUESTS],
    queued_publish_count: usize,
    publishing_interval_ms: u32,
    keepalive_count: u32,
    empty_cycle_count: u32,
    /// Whether this Subscription has sent its first data or keep-alive response.
    publish_message_sent: bool,
    next_publish_due_ms: u32,
    publishing_enabled: bool,
    subscription: DefaultDataChangeSubscription,
    /// Set when idle reclaim runs; next session-invalid fault should close TCP.
    close_transport_after_session_fault: bool,
}

#[cfg(feature = "diagnostic-protocol-identifiers")]
mod protocol_diagnostic;
mod server;
#[cfg(feature = "diagnostic-protocol-identifiers")]
pub use protocol_diagnostic::DiagnosticIdentifierRecipe;

mod node_access;
pub(crate) use node_access::{
    namespace_node_id_for_product_node, product_object, write_node_value, write_read_data_value,
};

mod browse;
pub(crate) use browse::write_browse_result;
#[cfg(test)]
pub(crate) use browse::{RESULT_MASK_BROWSE_NAME, RESULT_MASK_DISPLAY_NAME};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
