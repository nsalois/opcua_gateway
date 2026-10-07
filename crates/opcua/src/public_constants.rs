// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

pub const APPLICATION_NAMESPACE_INDEX: u16 = 1;
pub const PRODUCT_NAMESPACE_INDEX: u16 = 2;
pub const PRODUCT_NAMESPACE_URI: &str = "urn:opta:gateway:buchi-r300";
pub const PRODUCT_URI: &str = "urn:opta:gateway";
pub const APPLICATION_NAME: &str = "Opta Buchi OPC UA Gateway";
pub const DEFAULT_ENDPOINT_URL: &str = "opc.tcp://127.0.0.1:4840";
pub const TRANSPORT_PROFILE_URI: &str =
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
pub const SECURITY_POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";

pub const DEFAULT_RECEIVE_BUFFER_SIZE: u32 = 65_535;
pub const DEFAULT_SEND_BUFFER_SIZE: u32 = 65_535;
pub const DEFAULT_MAX_MESSAGE_SIZE: u32 = 65_535;
pub const DEFAULT_MAX_CHUNK_COUNT: u32 = 1;
/// Product UA-TCP/UASC frame cap. Target listener RX/TX buffers are sized to
/// this bound so a full all-node Publish response stays allocation-free.
pub const PRODUCT_TARGET_BUFFER_SIZE: u32 = 16_384;
pub const MAX_REQUESTED_NODES: usize = 2048;
pub const MAX_BULK_SERVICE_OPERATIONS: usize = 1024;
pub const MAX_MONITORED_ITEM_OPERATIONS: usize = 512;
pub const MAX_BROWSE_REFERENCES_PER_RESULT: usize = 128;
pub const MAX_ENDPOINT_URL_LEN: usize = 128;
