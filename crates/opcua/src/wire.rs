// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use core::convert::TryFrom;

use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::opcua_status;

use crate::{
    service_id, DATA_VALUE_HAS_SERVER_PICOSECONDS, DATA_VALUE_HAS_SERVER_TIMESTAMP,
    DATA_VALUE_HAS_SOURCE_PICOSECONDS, DATA_VALUE_HAS_SOURCE_TIMESTAMP, DATA_VALUE_HAS_STATUS,
    DATA_VALUE_HAS_VALUE, DATA_VALUE_KNOWN_MASK, DEFAULT_MAX_CHUNK_COUNT, DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_RECEIVE_BUFFER_SIZE, DEFAULT_SEND_BUFFER_SIZE, DEFAULT_SESSION_TOKEN_SEED,
    MAX_REQUESTED_NODES, PRODUCT_TARGET_BUFFER_SIZE, SESSION_TOKEN_SENTINEL_ID, VARIANT_ARRAY_BIT,
    VARIANT_BOOLEAN, VARIANT_BYTE, VARIANT_DATETIME, VARIANT_FLOAT, VARIANT_INT32,
    VARIANT_LOCALIZED_TEXT, VARIANT_NODEID, VARIANT_QUALIFIED_NAME, VARIANT_STRING, VARIANT_UINT32,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpcUaError {
    BufferTooSmall,
    Truncated,
    InvalidFrame,
    Unsupported,
    Malformed,
}

pub type Result<T> = core::result::Result<T, OpcUaError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameAction {
    SendResponse(usize),
    SendResponseThenClose(usize),
    NoResponse,
    Close,
}

impl FrameAction {
    pub const fn response_len(self) -> Option<usize> {
        match self {
            Self::SendResponse(len) | Self::SendResponseThenClose(len) => Some(len),
            Self::NoResponse | Self::Close => None,
        }
    }

    pub const fn closes_connection(self) -> bool {
        matches!(self, Self::SendResponseThenClose(_) | Self::Close)
    }
}

/// Result of timer-driven maintenance (session idle + publish drain).
///
/// Idle session reclaim must free the **TCP listener**, not only session state —
/// otherwise hung clients that hold the socket open still brick a 3-listener target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerDrainResult {
    None,
    Response(usize),
    /// Session reclaimed (or equivalent); caller must close the transport.
    CloseConnection,
}

impl TimerDrainResult {
    pub const fn response_len(self) -> Option<usize> {
        match self {
            Self::Response(len) => Some(len),
            Self::None | Self::CloseConnection => None,
        }
    }

    pub const fn closes_connection(self) -> bool {
        matches!(self, Self::CloseConnection)
    }

    pub fn expect_response(self, msg: &str) -> usize {
        match self {
            Self::Response(len) => len,
            other => panic!("{msg}: got {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeId {
    pub namespace: u16,
    pub identifier: u32,
}

impl NodeId {
    pub const fn numeric(namespace: u16, identifier: u32) -> Self {
        Self {
            namespace,
            identifier,
        }
    }
}

pub(crate) const fn normalize_session_token_seed(seed: u32) -> u32 {
    if seed == SESSION_TOKEN_SENTINEL_ID {
        DEFAULT_SESSION_TOKEN_SEED
    } else {
        seed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloMessage<'a> {
    pub protocol_version: u32,
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
    pub endpoint_url: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgeMessage {
    pub protocol_version: u32,
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
}

impl Default for AcknowledgeMessage {
    fn default() -> Self {
        Self::from_limits(TransportLimits::default())
    }
}

impl AcknowledgeMessage {
    pub const fn from_limits(limits: TransportLimits) -> Self {
        Self {
            protocol_version: 0,
            receive_buffer_size: limits.receive_buffer_size,
            send_buffer_size: limits.send_buffer_size,
            max_message_size: limits.max_message_size,
            max_chunk_count: limits.max_chunk_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
}

impl TransportLimits {
    pub const fn new(
        receive_buffer_size: u32,
        send_buffer_size: u32,
        max_message_size: u32,
        max_chunk_count: u32,
    ) -> Self {
        Self {
            receive_buffer_size,
            send_buffer_size,
            max_message_size,
            max_chunk_count,
        }
    }

    pub const fn product_target() -> Self {
        Self {
            receive_buffer_size: PRODUCT_TARGET_BUFFER_SIZE,
            send_buffer_size: PRODUCT_TARGET_BUFFER_SIZE,
            max_message_size: PRODUCT_TARGET_BUFFER_SIZE,
            max_chunk_count: DEFAULT_MAX_CHUNK_COUNT,
        }
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            receive_buffer_size: DEFAULT_RECEIVE_BUFFER_SIZE,
            send_buffer_size: DEFAULT_SEND_BUFFER_SIZE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_chunk_count: DEFAULT_MAX_CHUNK_COUNT,
        }
    }
}

pub struct Encoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub const fn len(&self) -> usize {
        self.pos
    }

    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn finish(self) -> usize {
        self.pos
    }

    pub(crate) fn reserve(&mut self, len: usize) -> Result<usize> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(OpcUaError::BufferTooSmall)?;
        if end > self.buf.len() {
            return Err(OpcUaError::BufferTooSmall);
        }
        let start = self.pos;
        self.pos = end;
        Ok(start)
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let start = self.reserve(bytes.len())?;
        self.buf[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_bytes(&[value])
    }

    pub fn write_bool(&mut self, value: bool) -> Result<()> {
        self.write_u8(if value { 1 } else { 0 })
    }

    pub fn write_i32(&mut self, value: i32) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_i64(&mut self, value: i64) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_f64(&mut self, value: f64) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_f32(&mut self, value: f32) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_byte_string(value.as_bytes())
    }

    pub fn write_null_string(&mut self) -> Result<()> {
        self.write_i32(-1)
    }

    pub fn write_byte_string(&mut self, value: &[u8]) -> Result<()> {
        let len = i32::try_from(value.len()).map_err(|_| OpcUaError::BufferTooSmall)?;
        self.write_i32(len)?;
        self.write_bytes(value)
    }

    pub fn write_null_byte_string(&mut self) -> Result<()> {
        self.write_i32(-1)
    }

    pub fn write_array_len(&mut self, len: usize) -> Result<()> {
        let len = i32::try_from(len).map_err(|_| OpcUaError::BufferTooSmall)?;
        self.write_i32(len)
    }

    pub fn write_null_array(&mut self) -> Result<()> {
        self.write_i32(-1)
    }

    pub fn write_node_id(&mut self, node: NodeId) -> Result<()> {
        if node.namespace == 0 && node.identifier <= 255 {
            self.write_u8(0x00)?;
            self.write_u8(node.identifier as u8)
        } else if node.namespace <= 255 && node.identifier <= 65_535 {
            self.write_u8(0x01)?;
            self.write_u8(node.namespace as u8)?;
            self.write_u16(node.identifier as u16)
        } else {
            self.write_u8(0x02)?;
            self.write_u16(node.namespace)?;
            self.write_u32(node.identifier)
        }
    }

    pub fn write_expanded_node_id(&mut self, node: NodeId) -> Result<()> {
        self.write_node_id(node)
    }

    pub fn write_qualified_name(&mut self, namespace: u16, name: &str) -> Result<()> {
        self.write_u16(namespace)?;
        self.write_string(name)
    }

    pub fn write_localized_text(&mut self, text: &str) -> Result<()> {
        self.write_u8(0x03)?; // locale + text
        self.write_string("en-US")?;
        self.write_string(text)
    }

    pub fn write_diagnostic_info_none(&mut self) -> Result<()> {
        self.write_u8(0)
    }

    pub fn write_extension_object_none(&mut self) -> Result<()> {
        self.write_node_id(NodeId::numeric(0, 0))?;
        self.write_u8(0)
    }

    pub fn begin_extension_object(&mut self, type_id: u32) -> Result<usize> {
        self.write_node_id(NodeId::numeric(0, type_id))?;
        self.write_u8(1)?;
        let len_pos = self.reserve(4)?;
        Ok(len_pos)
    }

    pub fn end_extension_object(&mut self, len_pos: usize) -> Result<()> {
        if len_pos + 4 > self.pos {
            return Err(OpcUaError::InvalidFrame);
        }
        let body_start = len_pos + 4;
        let len = self.pos - body_start;
        let len = i32::try_from(len).map_err(|_| OpcUaError::BufferTooSmall)?;
        self.buf[len_pos..len_pos + 4].copy_from_slice(&len.to_le_bytes());
        Ok(())
    }

    pub fn patch_u32(&mut self, pos: usize, value: u32) -> Result<()> {
        if pos + 4 > self.buf.len() {
            return Err(OpcUaError::BufferTooSmall);
        }
        self.buf[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn write_data_value_status(&mut self, status: u32) -> Result<()> {
        // ADR 0013: status only — no source/server timestamps (mask 0x02).
        self.write_u8(0x02)?;
        self.write_u32(status)
    }

    pub fn write_data_value_scalar(&mut self, status: u32, value: ScalarValue) -> Result<()> {
        // ADR 0013: value + status only (mask 0x03). Do not set timestamp bits
        // (0x04/0x08); StatusCode is the sole freshness signal for DataValues.
        self.write_u8(0x03)?;
        self.write_scalar_variant(value)?;
        self.write_u32(status)
    }

    pub fn write_scalar_variant(&mut self, value: ScalarValue) -> Result<()> {
        match value {
            ScalarValue::Boolean(value) => {
                self.write_u8(VARIANT_BOOLEAN)?;
                self.write_bool(value)
            }
            ScalarValue::Int32(value) => {
                self.write_u8(VARIANT_INT32)?;
                self.write_i32(value)
            }
            ScalarValue::UInt32(value) => {
                self.write_u8(VARIANT_UINT32)?;
                self.write_u32(value)
            }
            ScalarValue::FloatMilli(value) => {
                self.write_u8(VARIANT_FLOAT)?;
                self.write_f32(value as f32 / 1000.0)
            }
        }
    }

    pub(crate) fn write_variant_i32(&mut self, value: i32) -> Result<()> {
        self.write_u8(VARIANT_INT32)?;
        self.write_i32(value)
    }

    pub(crate) fn write_variant_byte(&mut self, value: u8) -> Result<()> {
        self.write_u8(VARIANT_BYTE)?;
        self.write_u8(value)
    }

    pub(crate) fn write_variant_node_id(&mut self, node: NodeId) -> Result<()> {
        self.write_u8(VARIANT_NODEID)?;
        self.write_node_id(node)
    }

    pub(crate) fn write_variant_qualified_name(
        &mut self,
        namespace: u16,
        name: &str,
    ) -> Result<()> {
        self.write_u8(VARIANT_QUALIFIED_NAME)?;
        self.write_qualified_name(namespace, name)
    }

    pub(crate) fn write_variant_localized_text(&mut self, text: &str) -> Result<()> {
        self.write_u8(VARIANT_LOCALIZED_TEXT)?;
        self.write_localized_text(text)
    }

    pub(crate) fn write_variant_datetime(&mut self, value: i64) -> Result<()> {
        self.write_u8(VARIANT_DATETIME)?;
        self.write_i64(value)
    }

    pub(crate) fn write_variant_string_array(&mut self, values: &[&str]) -> Result<()> {
        self.write_u8(VARIANT_ARRAY_BIT | VARIANT_STRING)?;
        self.write_array_len(values.len())?;
        for value in values {
            self.write_string(value)?;
        }
        Ok(())
    }
}

pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            limit: buf.len(),
        }
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(OpcUaError::Truncated)?;
        if end > self.limit {
            return Err(OpcUaError::Truncated);
        }
        let start = self.pos;
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(i32::from_le_bytes(bytes))
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.read_exact(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(i64::from_le_bytes(bytes))
    }

    pub fn read_f32(&mut self) -> Result<f32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(f32::from_le_bytes(bytes))
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(f64::from_le_bytes(bytes))
    }

    pub fn read_byte_string(&mut self) -> Result<Option<&'a [u8]>> {
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(None);
        }
        let len = usize::try_from(len).map_err(|_| OpcUaError::Malformed)?;
        Ok(Some(self.read_exact(len)?))
    }

    pub fn skip_string(&mut self) -> Result<()> {
        let _ = self.read_byte_string()?;
        Ok(())
    }

    pub fn read_array_len(&mut self, max: usize) -> Result<usize> {
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(0);
        }
        let len = usize::try_from(len).map_err(|_| OpcUaError::Malformed)?;
        if len > max {
            return Err(OpcUaError::Unsupported);
        }
        Ok(len)
    }

    pub fn read_node_id(&mut self) -> Result<NodeId> {
        let encoding = self.read_u8()?;
        self.read_node_id_with_encoding(encoding)
    }

    fn read_node_id_with_encoding(&mut self, encoding: u8) -> Result<NodeId> {
        match encoding & 0x3f {
            0x00 => Ok(NodeId::numeric(0, u32::from(self.read_u8()?))),
            0x01 => {
                let ns = u16::from(self.read_u8()?);
                let id = u32::from(self.read_u16()?);
                Ok(NodeId::numeric(ns, id))
            }
            0x02 => {
                let ns = self.read_u16()?;
                let id = self.read_u32()?;
                Ok(NodeId::numeric(ns, id))
            }
            _ => Err(OpcUaError::Unsupported),
        }
    }

    pub fn read_expanded_node_id(&mut self) -> Result<NodeId> {
        let encoding = self.read_u8()?;
        let node_id = self.read_node_id_with_encoding(encoding)?;
        if encoding & 0x80 != 0 {
            self.skip_string()?;
        }
        if encoding & 0x40 != 0 {
            let _server_index = self.read_u32()?;
        }
        Ok(node_id)
    }

    pub fn read_qualified_name(&mut self) -> Result<(u16, Option<&'a [u8]>)> {
        let ns = self.read_u16()?;
        let name = self.read_byte_string()?;
        Ok((ns, name))
    }

    pub fn skip_extension_object(&mut self) -> Result<()> {
        let _ = self.read_extension_object_present()?;
        Ok(())
    }

    pub fn read_extension_object_present(&mut self) -> Result<bool> {
        let type_id = self.read_expanded_node_id()?;
        let encoding = self.read_u8()?;
        if encoding == 0 {
            return Ok(type_id != NodeId::numeric(0, 0));
        }
        if encoding != 1 && encoding != 2 {
            return Err(OpcUaError::Unsupported);
        }
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(true);
        }
        let len = usize::try_from(len).map_err(|_| OpcUaError::Malformed)?;
        let _ = self.read_exact(len)?;
        Ok(true)
    }

    pub fn begin_extension_object(&mut self) -> Result<(u32, usize)> {
        let type_id = self.read_expanded_node_id()?;
        let encoding = self.read_u8()?;
        if encoding != 1 {
            return Err(OpcUaError::Unsupported);
        }
        let len = self.read_i32()?;
        if len < 0 {
            return Err(OpcUaError::Malformed);
        }
        let len = usize::try_from(len).map_err(|_| OpcUaError::Malformed)?;
        let end = self.pos.checked_add(len).ok_or(OpcUaError::Malformed)?;
        if end > self.limit {
            return Err(OpcUaError::Truncated);
        }
        self.limit = end;
        Ok((type_id.identifier, end))
    }

    pub fn end_limited(&mut self, previous_limit: usize) -> Result<()> {
        if self.pos > self.limit {
            return Err(OpcUaError::Truncated);
        }
        self.pos = self.limit;
        self.limit = previous_limit;
        Ok(())
    }

    pub fn read_request_header(&mut self) -> Result<RequestHeader> {
        let authentication_token = self.read_node_id()?;
        let timestamp = self.read_i64()?;
        let request_handle = self.read_u32()?;
        let _return_diagnostics = self.read_u32()?;
        self.skip_string()?;
        let _timeout_hint = self.read_u32()?;
        self.skip_extension_object()?;
        Ok(RequestHeader {
            authentication_token,
            timestamp,
            request_handle,
        })
    }

    pub fn skip_application_description(&mut self) -> Result<()> {
        self.skip_string()?;
        self.skip_string()?;
        self.skip_localized_text()?;
        let _application_type = self.read_i32()?;
        self.skip_string()?;
        self.skip_string()?;
        self.skip_string_array(MAX_REQUESTED_NODES)
    }

    pub fn skip_localized_text(&mut self) -> Result<()> {
        let mask = self.read_u8()?;
        if mask & 0x01 != 0 {
            self.skip_string()?;
        }
        if mask & 0x02 != 0 {
            self.skip_string()?;
        }
        Ok(())
    }

    pub fn skip_string_array(&mut self, max: usize) -> Result<()> {
        let len = self.read_array_len(max)?;
        for _ in 0..len {
            self.skip_string()?;
        }
        Ok(())
    }

    pub fn read_read_value_id(&mut self) -> Result<ReadValueId> {
        let node_id = self.read_node_id()?;
        let attribute_id = self.read_u32()?;
        let index_range_present = self
            .read_byte_string()?
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        let (data_encoding_ns, data_encoding_name) = self.read_qualified_name()?;
        let data_encoding_present = data_encoding_ns != 0
            || data_encoding_name
                .map(|value| !value.is_empty())
                .unwrap_or(false);
        Ok(ReadValueId {
            node_id,
            attribute_id,
            index_range_present,
            data_encoding_present,
        })
    }

    pub fn read_data_value_for_write(&mut self) -> Result<DecodedWriteValue> {
        let mask = self.read_u8()?;
        let mut value_supported = true;
        let value_present = mask & DATA_VALUE_HAS_VALUE != 0;
        let value = if value_present {
            match self.read_variant_for_write()? {
                Some(value) => Some(value),
                None => {
                    value_supported = false;
                    None
                }
            }
        } else {
            None
        };
        let status_code = if mask & DATA_VALUE_HAS_STATUS != 0 {
            Some(self.read_u32()?)
        } else {
            None
        };
        let source_timestamp_present = mask & DATA_VALUE_HAS_SOURCE_TIMESTAMP != 0;
        let server_timestamp_present = mask & DATA_VALUE_HAS_SERVER_TIMESTAMP != 0;
        let source_picoseconds_present = mask & DATA_VALUE_HAS_SOURCE_PICOSECONDS != 0;
        let server_picoseconds_present = mask & DATA_VALUE_HAS_SERVER_PICOSECONDS != 0;
        if source_timestamp_present {
            let _ = self.read_i64()?;
        }
        if source_picoseconds_present {
            let _ = self.read_u16()?;
        }
        if server_timestamp_present {
            let _ = self.read_i64()?;
        }
        if server_picoseconds_present {
            let _ = self.read_u16()?;
        }
        Ok(DecodedWriteValue {
            value,
            value_present,
            value_supported,
            status_code,
            source_timestamp_present,
            server_timestamp_present,
            source_picoseconds_present,
            server_picoseconds_present,
            unsupported_encoding_bits: mask & !DATA_VALUE_KNOWN_MASK != 0,
        })
    }

    fn read_variant_for_write(&mut self) -> Result<Option<DecodedScalar>> {
        let tag = self.read_u8()?;
        let scalar_tag = tag & !VARIANT_ARRAY_BIT;
        if tag & VARIANT_ARRAY_BIT != 0 {
            self.skip_variant_array(scalar_tag)?;
            return Ok(None);
        }
        match scalar_tag {
            VARIANT_BOOLEAN => Ok(Some(DecodedScalar::Boolean(self.read_bool()?))),
            VARIANT_INT32 => Ok(Some(DecodedScalar::Int32(self.read_i32()?))),
            VARIANT_UINT32 => Ok(Some(DecodedScalar::UInt32(self.read_u32()?))),
            VARIANT_FLOAT => Ok(Some(DecodedScalar::Float(self.read_f32()? as f64))),
            // Double (type id 11): decode-and-reject for product writes — strict
            // policy (depth plan call 3a). Do not coerce to Float.
            11 => {
                let _ = self.read_f64()?;
                Ok(None)
            }
            VARIANT_STRING => {
                self.skip_string()?;
                Ok(None)
            }
            VARIANT_BYTE => {
                let _ = self.read_u8()?;
                Ok(None)
            }
            VARIANT_DATETIME => {
                let _ = self.read_i64()?;
                Ok(None)
            }
            22 => {
                self.skip_extension_object()?;
                Ok(None)
            }
            _ => Err(OpcUaError::Unsupported),
        }
    }

    fn skip_variant_array(&mut self, scalar_tag: u8) -> Result<()> {
        let len = self.read_array_len(MAX_REQUESTED_NODES)?;
        for _ in 0..len {
            match scalar_tag {
                VARIANT_BOOLEAN | VARIANT_BYTE => {
                    let _ = self.read_u8()?;
                }
                VARIANT_INT32 | VARIANT_UINT32 | VARIANT_FLOAT => {
                    let _ = self.read_u32()?;
                }
                11 | VARIANT_DATETIME => {
                    let _ = self.read_i64()?;
                }
                VARIANT_STRING => {
                    self.skip_string()?;
                }
                22 => {
                    self.skip_extension_object()?;
                }
                _ => return Err(OpcUaError::Unsupported),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    pub authentication_token: NodeId,
    pub timestamp: i64,
    pub request_handle: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadValueId {
    pub node_id: NodeId,
    pub attribute_id: u32,
    pub index_range_present: bool,
    pub data_encoding_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowseDescription {
    pub node_id: NodeId,
    pub browse_direction: i32,
    pub reference_type_id: NodeId,
    pub include_subtypes: bool,
    pub node_class_mask: u32,
    pub result_mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BrowseReference {
    pub(crate) reference_type_id: u32,
    pub(crate) is_forward: bool,
    pub(crate) target_node_id: NodeId,
    pub(crate) browse_name: &'static str,
    pub(crate) browse_namespace: u16,
    pub(crate) node_class: i32,
    pub(crate) type_definition: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DecodedScalar {
    Boolean(bool),
    Int32(i32),
    UInt32(u32),
    Float(f64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DecodedWriteValue {
    pub value: Option<DecodedScalar>,
    pub value_present: bool,
    pub value_supported: bool,
    pub status_code: Option<u32>,
    pub source_timestamp_present: bool,
    pub server_timestamp_present: bool,
    pub source_picoseconds_present: bool,
    pub server_picoseconds_present: bool,
    pub unsupported_encoding_bits: bool,
}

impl DecodedWriteValue {
    pub(crate) fn is_supported_product_value_write(&self) -> bool {
        self.value_present
            && !self.unsupported_encoding_bits
            && self.status_code.unwrap_or(opcua_status::GOOD) == opcua_status::GOOD
            && !self.source_timestamp_present
            && !self.server_timestamp_present
            && !self.source_picoseconds_present
            && !self.server_picoseconds_present
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Hello,
    OpenSecureChannel,
    Message,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub final_chunk: u8,
    pub message_size: usize,
}

pub fn parse_frame_header(frame: &[u8]) -> Result<FrameHeader> {
    if frame.len() < 8 {
        return Err(OpcUaError::Truncated);
    }
    let kind = match &frame[..3] {
        b"HEL" => FrameKind::Hello,
        b"OPN" => FrameKind::OpenSecureChannel,
        b"MSG" => FrameKind::Message,
        b"CLO" => FrameKind::Close,
        _ => return Err(OpcUaError::InvalidFrame),
    };
    let final_chunk = frame[3];
    let mut size = [0u8; 4];
    size.copy_from_slice(&frame[4..8]);
    let message_size = u32::from_le_bytes(size) as usize;
    if message_size < 8 || message_size > frame.len() {
        return Err(OpcUaError::Truncated);
    }
    if final_chunk != b'F' {
        return Err(OpcUaError::Unsupported);
    }
    Ok(FrameHeader {
        kind,
        final_chunk,
        message_size,
    })
}

pub fn decode_hello(frame: &[u8]) -> Result<HelloMessage<'_>> {
    let header = parse_frame_header(frame)?;
    if header.kind != FrameKind::Hello {
        return Err(OpcUaError::InvalidFrame);
    }
    let mut d = Decoder::new(&frame[8..header.message_size]);
    Ok(HelloMessage {
        protocol_version: d.read_u32()?,
        receive_buffer_size: d.read_u32()?,
        send_buffer_size: d.read_u32()?,
        max_message_size: d.read_u32()?,
        max_chunk_count: d.read_u32()?,
        endpoint_url: d.read_byte_string()?.unwrap_or(&[]),
    })
}

pub fn encode_ack(out: &mut [u8], ack: AcknowledgeMessage) -> Result<usize> {
    let mut e = Encoder::new(out);
    e.write_bytes(b"ACKF")?;
    e.write_u32(28)?;
    e.write_u32(ack.protocol_version)?;
    e.write_u32(ack.receive_buffer_size)?;
    e.write_u32(ack.send_buffer_size)?;
    e.write_u32(ack.max_message_size)?;
    e.write_u32(ack.max_chunk_count)?;
    Ok(e.finish())
}

pub fn decode_uasc_request_info(frame: &[u8]) -> Result<UascRequestInfo> {
    let (info, _, _) = decode_uasc_prefix(frame)?;
    Ok(info)
}

pub fn decode_first_read_value_node(frame: &[u8]) -> Result<Option<NodeId>> {
    let (info, mut d, _previous_limit) = decode_uasc_prefix(frame)?;
    if info.service_type_id != service_id::READ_REQUEST {
        return Ok(None);
    }
    let _request = d.read_request_header()?;
    let _max_age = d.read_f64()?;
    let _timestamps_to_return = d.read_u32()?;
    let count = d.read_array_len(1)?;
    if count == 0 {
        return Ok(None);
    }
    Ok(Some(d.read_node_id()?))
}

pub fn encode_tcp_error(out: &mut [u8], status_code: u32, reason: &str) -> Result<usize> {
    let mut e = Encoder::new(out);
    e.write_bytes(b"ERRF")?;
    let size_pos = e.reserve(4)?;
    e.write_u32(status_code)?;
    e.write_string(reason)?;
    let len = e.len();
    e.patch_u32(size_pos, len as u32)?;
    Ok(e.finish())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UascRequestInfo {
    pub kind: FrameKind,
    pub secure_channel_id: u32,
    pub token_id: u32,
    pub sequence_number: u32,
    pub request_id: u32,
    pub service_type_id: u32,
    pub body_limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedPublishRequest {
    pub(crate) request_id: u32,
    pub(crate) request_handle: u32,
    pub(crate) ack_count: usize,
}

pub(crate) fn decode_uasc_prefix<'a>(
    frame: &'a [u8],
) -> Result<(UascRequestInfo, Decoder<'a>, usize)> {
    let header = parse_frame_header(frame)?;
    let mut d = Decoder::new(&frame[8..header.message_size]);
    let secure_channel_id = d.read_u32()?;
    let token_id = if header.kind == FrameKind::Message || header.kind == FrameKind::Close {
        d.read_u32()?
    } else {
        d.skip_string()?; // securityPolicyUri
        let _ = d.read_byte_string()?; // senderCertificate
        let _ = d.read_byte_string()?; // receiverCertificateThumbprint
        0
    };
    let sequence_number = d.read_u32()?;
    let request_id = d.read_u32()?;
    let previous_limit = d.limit;
    let service_type_id = d.read_node_id()?.identifier;
    Ok((
        UascRequestInfo {
            kind: header.kind,
            secure_channel_id,
            token_id,
            sequence_number,
            request_id,
            service_type_id,
            body_limit: previous_limit,
        },
        d,
        previous_limit,
    ))
}
