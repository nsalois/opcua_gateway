// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use opta_gateway_contracts::{opcua_status, product};
use opta_runtime::{DefaultDataChangeSubscription, RuntimeDataAccess};

use crate::{
    decode_hello, decode_uasc_prefix, encode_ack, encode_tcp_error,
    namespace_node_id_for_product_node, normalize_session_token_seed, parse_frame_header,
    service_id, status, write_browse_result, write_node_value, write_read_data_value,
    AcknowledgeMessage, BrowseDescription, BuildInfo, Decoder, Encoder, FrameAction, FrameKind,
    NodeId, OpcUaError, OpcUaServer, QueuedPublishRequest, Result, ServerIdentity,
    TimerDrainResult, TransportLimits, UascRequestInfo, APPLICATION_NAME,
    APPLICATION_NAMESPACE_INDEX, ATTR_VALUE, DEFAULT_ENDPOINT_URL, DEFAULT_MAX_CHUNK_COUNT,
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_RECEIVE_BUFFER_SIZE, DEFAULT_SEND_BUFFER_SIZE,
    DEFAULT_SESSION_TIMEOUT_MS, DEFAULT_SESSION_TOKEN_SEED, MAX_BULK_SERVICE_OPERATIONS,
    MAX_ENDPOINT_URL_LEN, MAX_MONITORED_ITEM_OPERATIONS, MAX_QUEUED_PUBLISH_REQUESTS,
    MAX_REQUESTED_NODES, MAX_SESSION_TIMEOUT_MS, MIN_SESSION_TIMEOUT_MS,
    NULL_TIMESTAMP_CHANNEL_EPOCH_UTC, NULL_TIMESTAMP_TOKEN_LIFETIME_MS,
    OPCUA_DATETIME_TICKS_PER_MILLISECOND, PRODUCT_URI, SECURITY_POLICY_NONE,
    SECURITY_TOKEN_REQUEST_TYPE_RENEW, SESSION_TOKEN_SENTINEL_ID, TRANSPORT_PROFILE_URI,
};

impl OpcUaServer {
    pub const fn new(identity: ServerIdentity, build_info: &'static BuildInfo) -> Self {
        Self::new_with_limits(
            identity,
            build_info,
            TransportLimits {
                receive_buffer_size: DEFAULT_RECEIVE_BUFFER_SIZE,
                send_buffer_size: DEFAULT_SEND_BUFFER_SIZE,
                max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
                max_chunk_count: DEFAULT_MAX_CHUNK_COUNT,
            },
        )
    }

    pub const fn new_with_limits(
        identity: ServerIdentity,
        build_info: &'static BuildInfo,
        limits: TransportLimits,
    ) -> Self {
        Self::new_with_limits_and_session_nonce(
            identity,
            build_info,
            limits,
            DEFAULT_SESSION_TOKEN_SEED,
        )
    }

    pub const fn new_with_limits_and_session_nonce(
        identity: ServerIdentity,
        build_info: &'static BuildInfo,
        limits: TransportLimits,
        session_token_seed: u32,
    ) -> Self {
        Self {
            identity,
            build_info,
            limits,
            secure_channel_id: 1,
            token_id: 1,
            previous_token_id: None,
            sequence_number: 1,
            session_token: NodeId::numeric(APPLICATION_NAMESPACE_INDEX, SESSION_TOKEN_SENTINEL_ID),
            session_token_minted: false,
            next_session_token_id: normalize_session_token_seed(session_token_seed),
            endpoint_url: [0; MAX_ENDPOINT_URL_LEN],
            endpoint_url_len: 0,
            session_active: false,
            session_timeout_ms: DEFAULT_SESSION_TIMEOUT_MS,
            last_session_activity_ms: 0,
            subscription_active: false,
            subscription_id: 1,
            subscription_lifetime_count: 10,
            publish_intervals_without_token: 0,
            publish_sequence_number: 1,
            #[cfg(feature = "diagnostic-protocol-identifiers")]
            initial_publish_sequence: None,
            queued_publish_requests: [None; MAX_QUEUED_PUBLISH_REQUESTS],
            queued_publish_count: 0,
            publishing_interval_ms: product::DATA_CHANGE_INTERVAL_MS,
            keepalive_count: 1,
            empty_cycle_count: 0,
            publish_message_sent: false,
            next_publish_due_ms: product::DATA_CHANGE_INTERVAL_MS,
            publishing_enabled: true,
            subscription: DefaultDataChangeSubscription::new(),
            close_transport_after_session_fault: false,
        }
    }

    pub const fn new_with_session_nonce(
        identity: ServerIdentity,
        build_info: &'static BuildInfo,
        session_token_seed: u32,
    ) -> Self {
        Self::new_with_limits_and_session_nonce(
            identity,
            build_info,
            TransportLimits {
                receive_buffer_size: DEFAULT_RECEIVE_BUFFER_SIZE,
                send_buffer_size: DEFAULT_SEND_BUFFER_SIZE,
                max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
                max_chunk_count: DEFAULT_MAX_CHUNK_COUNT,
            },
            session_token_seed,
        )
    }

    pub fn handle_frame<const WRITE_CAPACITY: usize>(
        &mut self,
        frame: &[u8],
        out: &mut [u8],
        data_access: &mut RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Result<FrameAction> {
        let scheduler_now_ms = freshness_now_ms as u32;
        if frame.len() < 8 {
            return Ok(FrameAction::Close);
        }

        let mut size = [0u8; 4];
        size.copy_from_slice(&frame[4..8]);
        let message_size = u32::from_le_bytes(size) as usize;
        if !matches!(&frame[..3], b"HEL" | b"OPN" | b"MSG" | b"CLO") {
            let len = encode_tcp_error(
                out,
                status::BAD_TCP_MESSAGE_TYPE_INVALID,
                "unsupported OPC UA TCP message type",
            )?;
            return Ok(FrameAction::SendResponseThenClose(len));
        }
        if message_size < 8
            || message_size > self.limits.receive_buffer_size as usize
            || message_size > self.limits.max_message_size as usize
        {
            let len = encode_tcp_error(
                out,
                status::BAD_TCP_MESSAGE_TOO_LARGE,
                "OPC UA TCP message size exceeds receive buffer",
            )?;
            return Ok(FrameAction::SendResponseThenClose(len));
        }
        if message_size > frame.len() {
            return Ok(FrameAction::Close);
        }

        let header = match parse_frame_header(&frame[..message_size]) {
            Ok(header) => header,
            Err(OpcUaError::Unsupported | OpcUaError::InvalidFrame) => {
                let len = encode_tcp_error(
                    out,
                    status::BAD_TCP_MESSAGE_TYPE_INVALID,
                    "unsupported OPC UA TCP chunk header",
                )?;
                return Ok(FrameAction::SendResponseThenClose(len));
            }
            Err(_) => return Ok(FrameAction::Close),
        };
        match header.kind {
            FrameKind::Hello => {
                let hello = match decode_hello(&frame[..message_size]) {
                    Ok(hello) => hello,
                    Err(_) => {
                        let len = encode_tcp_error(
                            out,
                            status::BAD_TCP_ENDPOINT_URL_INVALID,
                            "invalid OPC UA TCP Hello endpoint",
                        )?;
                        return Ok(FrameAction::SendResponseThenClose(len));
                    }
                };
                if hello.endpoint_url.len() > self.endpoint_url.len() {
                    let len = encode_tcp_error(
                        out,
                        status::BAD_TCP_ENDPOINT_URL_INVALID,
                        "OPC UA TCP endpoint URL exceeds fixed server buffer",
                    )?;
                    return Ok(FrameAction::SendResponseThenClose(len));
                }
                self.remember_endpoint_url(hello.endpoint_url);
                encode_ack(out, AcknowledgeMessage::from_limits(self.limits))
                    .map(FrameAction::SendResponse)
            }
            FrameKind::OpenSecureChannel => {
                let (info, mut d, previous_limit) = match decode_uasc_prefix(&frame[..message_size])
                {
                    Ok(decoded) => decoded,
                    Err(_) => return Ok(FrameAction::Close),
                };
                if info.service_type_id != service_id::OPEN_SECURE_CHANNEL_REQUEST {
                    return self
                        .encode_service_fault(
                            out,
                            FrameKind::OpenSecureChannel,
                            info.request_id,
                            0,
                            status::BAD_SERVICE_UNSUPPORTED,
                        )
                        .map(FrameAction::SendResponse);
                }
                let request = d.read_request_header()?;
                let _client_protocol_version = d.read_u32()?;
                let request_type = d.read_i32()?;
                let security_mode = d.read_i32()?;
                let _client_nonce = d.read_byte_string()?;
                let requested_lifetime = d.read_u32().unwrap_or(60_000);
                d.end_limited(previous_limit)?;
                if security_mode != 1 {
                    return self
                        .encode_service_fault(
                            out,
                            FrameKind::OpenSecureChannel,
                            info.request_id,
                            request.request_handle,
                            status::BAD_SERVICE_UNSUPPORTED,
                        )
                        .map(FrameAction::SendResponse);
                }
                let created_at = secure_channel_timestamp(request.timestamp, scheduler_now_ms);
                let revised_lifetime =
                    secure_channel_revised_lifetime(request.timestamp, requested_lifetime);
                self.previous_token_id =
                    (request_type == SECURITY_TOKEN_REQUEST_TYPE_RENEW).then_some(self.token_id);
                self.token_id = self.token_id.wrapping_add(1).max(1);
                self.encode_open_secure_channel_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    created_at,
                    revised_lifetime,
                )
                .map(FrameAction::SendResponse)
            }
            FrameKind::Message | FrameKind::Close => {
                let (info, mut d, previous_limit) = match decode_uasc_prefix(&frame[..message_size])
                {
                    Ok(decoded) => decoded,
                    Err(_) => return Ok(FrameAction::Close),
                };
                if info.secure_channel_id != self.secure_channel_id {
                    let len = encode_tcp_error(
                        out,
                        status::BAD_TCP_SECURE_CHANNEL_UNKNOWN,
                        "unknown OPC UA SecureChannel id",
                    )?;
                    return Ok(FrameAction::SendResponseThenClose(len));
                }
                if !self.accepts_secure_channel_token(info.token_id) {
                    let len = encode_tcp_error(
                        out,
                        status::BAD_TCP_SECURE_CHANNEL_UNKNOWN,
                        "unknown OPC UA SecureChannel token",
                    )?;
                    return Ok(FrameAction::SendResponseThenClose(len));
                }
                if info.token_id == self.token_id {
                    self.previous_token_id = None;
                }
                self.dispatch_msg(
                    info,
                    &mut d,
                    previous_limit,
                    out,
                    data_access,
                    freshness_now_ms,
                )
            }
        }
    }

    fn remember_endpoint_url(&mut self, endpoint_url: &[u8]) {
        if endpoint_url.is_empty() || endpoint_url.len() > self.endpoint_url.len() {
            return;
        }
        self.endpoint_url[..endpoint_url.len()].copy_from_slice(endpoint_url);
        self.endpoint_url_len = endpoint_url.len();
    }

    fn mint_session_token(&mut self) {
        let token_id = normalize_session_token_seed(self.next_session_token_id);
        self.session_token = NodeId::numeric(APPLICATION_NAMESPACE_INDEX, token_id);
        self.session_token_minted = true;
        self.next_session_token_id = normalize_session_token_seed(token_id.wrapping_add(1));
    }

    fn invalidate_session_token(&mut self) {
        self.session_token =
            NodeId::numeric(APPLICATION_NAMESPACE_INDEX, SESSION_TOKEN_SENTINEL_ID);
        self.session_token_minted = false;
        self.session_active = false;
        self.session_timeout_ms = DEFAULT_SESSION_TIMEOUT_MS;
        self.last_session_activity_ms = 0;
    }

    fn touch_session_activity(&mut self, now_ms: u32) {
        self.last_session_activity_ms = now_ms;
    }

    fn revise_session_timeout_ms(requested_ms: f64) -> u32 {
        if !requested_ms.is_finite() || requested_ms <= 0.0 {
            return DEFAULT_SESSION_TIMEOUT_MS;
        }
        let requested = if requested_ms > f64::from(u32::MAX) {
            u32::MAX
        } else {
            requested_ms as u32
        };
        requested.clamp(MIN_SESSION_TIMEOUT_MS, MAX_SESSION_TIMEOUT_MS)
    }

    fn revise_publishing_interval_ms(requested_ms: f64) -> u32 {
        // Part 4 5.14.2/5.14.3 permit revision to a supported interval.
        // Signed modular deadline ordering requires a distance below 2^31.
        // Encode this integer again so the client sees the actual timer value.
        if !requested_ms.is_finite() {
            return product::DATA_CHANGE_INTERVAL_MS;
        }
        (requested_ms as u32).clamp(product::DATA_CHANGE_INTERVAL_MS, u32::MAX / 2)
    }

    /// B.5a: reclaim activated session after revisedSessionTimeout with no activity.
    /// Sets [`Self::close_transport_after_session_fault`] so the TCP slot is freed
    /// (listener re-arm), not only session state.
    fn reclaim_idle_session_if_due(&mut self, now_ms: u32) -> bool {
        if !self.session_active {
            return false;
        }
        let idle = now_ms.wrapping_sub(self.last_session_activity_ms);
        if idle < self.session_timeout_ms {
            return false;
        }
        self.subscription.clear();
        self.subscription_active = false;
        self.clear_publish_state();
        self.invalidate_session_token();
        self.close_transport_after_session_fault = true;
        true
    }

    fn take_session_fault_frame_action(&mut self, response_len: usize) -> FrameAction {
        if self.close_transport_after_session_fault {
            self.close_transport_after_session_fault = false;
            FrameAction::SendResponseThenClose(response_len)
        } else {
            FrameAction::SendResponse(response_len)
        }
    }

    fn encode_session_service_fault(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        status: u32,
    ) -> Result<FrameAction> {
        let len =
            self.encode_service_fault(out, FrameKind::Message, request_id, request_handle, status)?;
        Ok(self.take_session_fault_frame_action(len))
    }

    /// B.5b: delete subscription after revisedLifetimeCount publishing intervals
    /// with no Publish request available to service the timer.
    fn expire_publish_starved_subscription_if_due(&mut self, now_ms: u32) {
        if !self.subscription_active {
            return;
        }
        if !monotonic_due(now_ms, self.next_publish_due_ms) {
            return;
        }
        if self.queued_publish_count > 0 {
            // Client has Publish tokens; leave timer due for drain_due_publish.
            self.publish_intervals_without_token = 0;
            return;
        }
        // No token available: this publishing interval counts toward lifetime.
        self.next_publish_due_ms = now_ms.wrapping_add(self.publishing_interval_ms.max(1));
        self.publish_intervals_without_token =
            self.publish_intervals_without_token.saturating_add(1);
        let lifetime = self.subscription_lifetime_count.max(1);
        if self.publish_intervals_without_token >= lifetime {
            self.subscription.clear();
            self.subscription_active = false;
            self.clear_publish_state();
            self.publish_intervals_without_token = 0;
        }
    }

    fn accepts_secure_channel_token(&self, token_id: u32) -> bool {
        token_id == self.token_id || self.previous_token_id == Some(token_id)
    }

    pub fn enqueue_publish_request(
        &mut self,
        request_id: u32,
        request_handle: u32,
        ack_count: usize,
    ) -> Option<QueuedPublishRequest> {
        let queued = QueuedPublishRequest {
            request_id,
            request_handle,
            ack_count,
        };
        if self.queued_publish_count < MAX_QUEUED_PUBLISH_REQUESTS {
            self.queued_publish_requests[self.queued_publish_count] = Some(queued);
            self.queued_publish_count += 1;
            return None;
        }

        let evicted = self.queued_publish_requests[0].replace(queued);
        let mut index = 1;
        while index < MAX_QUEUED_PUBLISH_REQUESTS {
            self.queued_publish_requests[index - 1] = self.queued_publish_requests[index];
            index += 1;
        }
        self.queued_publish_requests[MAX_QUEUED_PUBLISH_REQUESTS - 1] = Some(queued);
        evicted
    }

    pub fn pop_publish_request(&mut self) -> Option<QueuedPublishRequest> {
        if self.queued_publish_count == 0 {
            return None;
        }
        let request = self.queued_publish_requests[0].take();
        let mut index = 1;
        while index < MAX_QUEUED_PUBLISH_REQUESTS {
            self.queued_publish_requests[index - 1] = self.queued_publish_requests[index];
            index += 1;
        }
        self.queued_publish_requests[MAX_QUEUED_PUBLISH_REQUESTS - 1] = None;
        self.queued_publish_count -= 1;
        request
    }

    pub fn clear_publish_queue(&mut self) {
        self.queued_publish_requests = [None; MAX_QUEUED_PUBLISH_REQUESTS];
        self.queued_publish_count = 0;
    }

    /// Delay until the next session-idle or subscription publishing-timer event.
    /// Host/firmware event loops race this against the next inbound frame read.
    pub fn next_publish_delay_ms(&self, now_ms: u32) -> Option<u32> {
        self.next_server_timer_delay_ms(now_ms)
    }

    pub fn next_server_timer_delay_ms(&self, now_ms: u32) -> Option<u32> {
        let mut best: Option<u32> = None;
        let consider = |best: &mut Option<u32>, delay: u32| {
            *best = Some(match *best {
                Some(current) => current.min(delay),
                None => delay,
            });
        };
        if self.session_active {
            let due = self
                .last_session_activity_ms
                .wrapping_add(self.session_timeout_ms.max(1));
            if monotonic_due(now_ms, due) {
                consider(&mut best, 0);
            } else {
                consider(&mut best, due.wrapping_sub(now_ms));
            }
        }
        if self.subscription_active {
            // Fire even with an empty Publish queue so B.5b starvation advances.
            if monotonic_due(now_ms, self.next_publish_due_ms) {
                consider(&mut best, 0);
            } else {
                consider(&mut best, self.next_publish_due_ms.wrapping_sub(now_ms));
            }
        }
        best
    }

    /// Session idle reclaim + publish-starvation tick + due Publish drain.
    ///
    /// On idle session reclaim returns [`TimerDrainResult::CloseConnection`] so
    /// the transport layer frees the listener (B.5 residual / hung-client brick).
    pub fn drain_due_publish_response<const WRITE_CAPACITY: usize>(
        &mut self,
        out: &mut [u8],
        data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Result<TimerDrainResult> {
        let scheduler_now_ms = freshness_now_ms as u32;
        if self.reclaim_idle_session_if_due(scheduler_now_ms) {
            return Ok(TimerDrainResult::CloseConnection);
        }
        self.expire_publish_starved_subscription_if_due(scheduler_now_ms);

        if !self.subscription_active || self.queued_publish_count == 0 {
            return Ok(TimerDrainResult::None);
        }
        if !monotonic_due(scheduler_now_ms, self.next_publish_due_ms) {
            // expire_publish_starved already advanced next_publish_due when due
            // without tokens; when tokens exist but timer not due, wait.
            return Ok(TimerDrainResult::None);
        }

        // Token present and timer due: service data/keepalive (starvation reset
        // already applied in expire_publish_starved when tokens were present).
        self.next_publish_due_ms =
            scheduler_now_ms.wrapping_add(self.publishing_interval_ms.max(1));
        self.publish_intervals_without_token = 0;
        let changed_count = if self.publishing_enabled {
            self.subscription
                .due_changed_count(data_access, freshness_now_ms)
        } else {
            0
        };
        if changed_count > 0 {
            let Some(request) = self.pop_publish_request() else {
                return Ok(TimerDrainResult::None);
            };
            self.empty_cycle_count = 0;
            let len = self.encode_publish_data_response(
                out,
                request,
                changed_count,
                data_access,
                freshness_now_ms,
            )?;
            self.publish_message_sent = true;
            return Ok(TimerDrainResult::Response(len));
        }

        self.advance_due_subscription_samples(data_access, freshness_now_ms);
        if !self.publish_message_sent {
            let Some(request) = self.pop_publish_request() else {
                return Ok(TimerDrainResult::None);
            };
            self.empty_cycle_count = 0;
            let len = self.encode_publish_keepalive_response(out, request, scheduler_now_ms)?;
            self.publish_message_sent = true;
            return Ok(TimerDrainResult::Response(len));
        }
        self.empty_cycle_count = self.empty_cycle_count.saturating_add(1);
        let keepalive_due = self.empty_cycle_count >= self.keepalive_count.max(1);
        if !keepalive_due {
            return Ok(TimerDrainResult::None);
        }
        let Some(request) = self.pop_publish_request() else {
            return Ok(TimerDrainResult::None);
        };
        self.empty_cycle_count = 0;
        let len = self.encode_publish_keepalive_response(out, request, scheduler_now_ms)?;
        self.publish_message_sent = true;
        Ok(TimerDrainResult::Response(len))
    }

    fn clear_publish_state(&mut self) {
        self.clear_publish_queue();
        self.publish_sequence_number = 1;
        self.empty_cycle_count = 0;
        self.publish_message_sent = false;
        self.publish_intervals_without_token = 0;
        self.next_publish_due_ms = self.publishing_interval_ms.max(1);
        self.publishing_enabled = true;
    }

    fn dispatch_msg<const WRITE_CAPACITY: usize>(
        &mut self,
        info: UascRequestInfo,
        d: &mut Decoder<'_>,
        previous_limit: usize,
        out: &mut [u8],
        data_access: &mut RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Result<FrameAction> {
        let scheduler_now_ms = freshness_now_ms as u32;
        match info.service_type_id {
            service_id::FIND_SERVERS_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(endpoint_url) = d.read_byte_string()? {
                    self.remember_endpoint_url(endpoint_url);
                }
                d.skip_string_array(MAX_REQUESTED_NODES)?; // localeIds
                let server_uri_count = d.read_array_len(MAX_REQUESTED_NODES)?;
                let mut server_uri_match = server_uri_count == 0;
                for _ in 0..server_uri_count {
                    if let Some(uri) = d.read_byte_string()? {
                        server_uri_match |= uri == self.identity.application_uri().as_bytes();
                    }
                }
                d.end_limited(previous_limit)?;
                self.encode_find_servers_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    server_uri_match,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::FIND_SERVERS_ON_NETWORK_REQUEST => {
                let request = d.read_request_header()?;
                let _starting_record_id = d.read_u32()?;
                let _max_records = d.read_u32()?;
                d.skip_string_array(MAX_REQUESTED_NODES)?;
                d.end_limited(previous_limit)?;
                self.encode_find_servers_on_network_response(
                    out,
                    info.request_id,
                    request.request_handle,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::GET_ENDPOINTS_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(endpoint_url) = d.read_byte_string()? {
                    self.remember_endpoint_url(endpoint_url);
                }
                d.skip_string_array(MAX_REQUESTED_NODES)?; // localeIds
                d.skip_string_array(MAX_REQUESTED_NODES)?; // profileUris
                d.end_limited(previous_limit)?;
                self.encode_get_endpoints_response(out, info.request_id, request.request_handle)
                    .map(FrameAction::SendResponse)
            }
            service_id::CREATE_SESSION_REQUEST => {
                let request = d.read_request_header()?;
                // Parse body far enough for requestedSessionTimeout (B.5a).
                // Empty/partial bodies fall back to the product default timeout.
                let requested_timeout = match Self::decode_create_session_timeout(d, previous_limit)
                {
                    Ok(timeout) => timeout,
                    Err(_) => {
                        let _ = d.end_limited(previous_limit);
                        f64::from(DEFAULT_SESSION_TIMEOUT_MS)
                    }
                };
                self.session_active = false;
                self.subscription.clear();
                self.subscription_active = false;
                self.clear_publish_state();
                self.session_timeout_ms = Self::revise_session_timeout_ms(requested_timeout);
                self.touch_session_activity(scheduler_now_ms);
                self.mint_session_token();
                self.encode_create_session_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    self.session_timeout_ms,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::ACTIVATE_SESSION_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, false, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                d.end_limited(previous_limit)?;
                self.session_active = true;
                self.touch_session_activity(scheduler_now_ms);
                self.encode_activate_session_response(out, info.request_id, request.request_handle)
                    .map(FrameAction::SendResponse)
            }
            service_id::CLOSE_SESSION_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                d.end_limited(previous_limit)?;
                self.invalidate_session_token();
                self.subscription.clear();
                self.subscription_active = false;
                self.clear_publish_state();
                self.encode_empty_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    service_id::CLOSE_SESSION_RESPONSE,
                    opcua_status::GOOD,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::CLOSE_SECURE_CHANNEL_REQUEST => {
                let _request = d.read_request_header()?;
                d.end_limited(previous_limit)?;
                self.session_active = false;
                self.subscription.clear();
                self.subscription_active = false;
                self.clear_publish_state();
                Ok(FrameAction::Close)
            }
            service_id::BROWSE_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result =
                    self.encode_browse_response(out, info.request_id, request.request_handle, d);
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::READ_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result = self.encode_read_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                    data_access,
                    freshness_now_ms,
                );
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::WRITE_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result = self.encode_write_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                    data_access,
                );
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::CREATE_SUBSCRIPTION_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                self.encode_create_subscription_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                    scheduler_now_ms,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::MODIFY_SUBSCRIPTION_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                self.encode_modify_subscription_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                    scheduler_now_ms,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::DELETE_SUBSCRIPTIONS_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                self.encode_delete_subscriptions_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                )
                .map(FrameAction::SendResponse)
            }
            service_id::CREATE_MONITORED_ITEMS_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result = self.encode_create_monitored_items_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                );
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::MODIFY_MONITORED_ITEMS_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result = self.encode_modify_monitored_items_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                );
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::DELETE_MONITORED_ITEMS_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result = self.encode_delete_monitored_items_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                );
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::PUBLISH_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let ack_count = d.read_array_len(MAX_REQUESTED_NODES)?;
                if ack_count > MAX_BULK_SERVICE_OPERATIONS {
                    return self
                        .encode_service_fault(
                            out,
                            FrameKind::Message,
                            info.request_id,
                            request.request_handle,
                            status::BAD_TOO_MANY_OPERATIONS,
                        )
                        .map(FrameAction::SendResponse);
                }
                for _ in 0..ack_count {
                    let _subscription_id = d.read_u32()?;
                    let _sequence_number = d.read_u32()?;
                }
                if !self.subscription_active {
                    return self
                        .encode_publish_service_result_response(
                            out,
                            QueuedPublishRequest {
                                request_id: info.request_id,
                                request_handle: request.request_handle,
                                ack_count,
                            },
                            status::BAD_NO_SUBSCRIPTION,
                            scheduler_now_ms,
                        )
                        .map(FrameAction::SendResponse);
                }
                if let Some(evicted) =
                    self.enqueue_publish_request(info.request_id, request.request_handle, ack_count)
                {
                    return self
                        .encode_publish_service_result_response(
                            out,
                            evicted,
                            status::BAD_TOO_MANY_PUBLISH_REQUESTS,
                            scheduler_now_ms,
                        )
                        .map(FrameAction::SendResponse);
                }
                match self.drain_due_publish_response(out, data_access, freshness_now_ms) {
                    Ok(TimerDrainResult::Response(len)) => Ok(FrameAction::SendResponse(len)),
                    Ok(TimerDrainResult::None) => Ok(FrameAction::NoResponse),
                    Ok(TimerDrainResult::CloseConnection) => Ok(FrameAction::Close),
                    Err(error) => {
                        let status = service_fault_status_for_error(error);
                        self.encode_service_fault(
                            out,
                            FrameKind::Message,
                            info.request_id,
                            request.request_handle,
                            status,
                        )
                        .map(FrameAction::SendResponse)
                    }
                }
            }
            service_id::REPUBLISH_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result =
                    self.encode_republish_response(out, info.request_id, request.request_handle, d);
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            service_id::SET_PUBLISHING_MODE_REQUEST => {
                let request = d.read_request_header()?;
                if let Some(status) =
                    self.session_guard_touch(request.authentication_token, true, scheduler_now_ms)
                {
                    return self.encode_session_service_fault(
                        out,
                        info.request_id,
                        request.request_handle,
                        status,
                    );
                }
                let result = self.encode_set_publishing_mode_response(
                    out,
                    info.request_id,
                    request.request_handle,
                    d,
                );
                self.service_response_or_fault(
                    result,
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                )
            }
            _ => {
                let request = match d.read_request_header() {
                    Ok(request) => request,
                    Err(_) => return Ok(FrameAction::Close),
                };
                self.encode_service_fault(
                    out,
                    FrameKind::Message,
                    info.request_id,
                    request.request_handle,
                    status::BAD_SERVICE_UNSUPPORTED,
                )
                .map(FrameAction::SendResponse)
            }
        }
    }

    fn session_guard(&self, authentication_token: NodeId, require_active: bool) -> Option<u32> {
        if !self.session_token_minted || authentication_token != self.session_token {
            Some(status::BAD_SESSION_ID_INVALID)
        } else if require_active && !self.session_active {
            Some(status::BAD_SESSION_NOT_ACTIVATED)
        } else {
            None
        }
    }

    /// Reclaim idle session first, then validate token; on success touch activity.
    fn session_guard_touch(
        &mut self,
        authentication_token: NodeId,
        require_active: bool,
        now_ms: u32,
    ) -> Option<u32> {
        let _ = self.reclaim_idle_session_if_due(now_ms);
        if let Some(status) = self.session_guard(authentication_token, require_active) {
            return Some(status);
        }
        self.touch_session_activity(now_ms);
        None
    }

    fn begin_uasc_response<'a>(
        &mut self,
        out: &'a mut [u8],
        kind: FrameKind,
        request_id: u32,
        response_type_id: u32,
    ) -> Result<(Encoder<'a>, usize)> {
        let mut e = Encoder::new(out);
        match kind {
            FrameKind::OpenSecureChannel => e.write_bytes(b"OPNF")?,
            FrameKind::Message | FrameKind::Close => e.write_bytes(b"MSGF")?,
            FrameKind::Hello => return Err(OpcUaError::InvalidFrame),
        }
        let size_pos = e.reserve(4)?;
        e.write_u32(self.secure_channel_id)?;
        if kind == FrameKind::OpenSecureChannel {
            e.write_string(SECURITY_POLICY_NONE)?;
            e.write_null_byte_string()?;
            e.write_null_byte_string()?;
        } else {
            e.write_u32(self.token_id)?;
        }
        e.write_u32(self.sequence_number)?;
        self.sequence_number = self.sequence_number.wrapping_add(1).max(1);
        e.write_u32(request_id)?;
        e.write_node_id(NodeId::numeric(0, response_type_id))?;
        Ok((e, size_pos))
    }

    fn finish_uasc_response(mut e: Encoder<'_>, size_pos: usize) -> Result<usize> {
        let len = e.len();
        e.patch_u32(size_pos, len as u32)?;
        Ok(e.finish())
    }

    fn write_response_header(
        e: &mut Encoder<'_>,
        request_handle: u32,
        service_result: u32,
    ) -> Result<()> {
        Self::write_response_header_at(e, request_handle, service_result, 0)
    }

    fn write_response_header_at(
        e: &mut Encoder<'_>,
        request_handle: u32,
        service_result: u32,
        timestamp: i64,
    ) -> Result<()> {
        e.write_i64(timestamp)?;
        e.write_u32(request_handle)?;
        e.write_u32(service_result)?;
        e.write_diagnostic_info_none()?;
        e.write_null_array()?;
        e.write_extension_object_none()
    }

    fn encode_open_secure_channel_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        created_at: i64,
        revised_lifetime: u32,
    ) -> Result<usize> {
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::OpenSecureChannel,
            request_id,
            service_id::OPEN_SECURE_CHANNEL_RESPONSE,
        )?;
        Self::write_response_header_at(&mut e, request_handle, opcua_status::GOOD, created_at)?;
        e.write_u32(0)?;
        e.write_u32(self.secure_channel_id)?;
        e.write_u32(self.token_id)?;
        e.write_i64(created_at)?;
        e.write_u32(revised_lifetime)?;
        e.write_null_byte_string()?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_empty_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        response_type_id: u32,
        service_result: u32,
    ) -> Result<usize> {
        let (mut e, len_pos) =
            self.begin_uasc_response(out, FrameKind::Message, request_id, response_type_id)?;
        Self::write_response_header(&mut e, request_handle, service_result)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_service_fault(
        &mut self,
        out: &mut [u8],
        kind: FrameKind,
        request_id: u32,
        request_handle: u32,
        service_result: u32,
    ) -> Result<usize> {
        let kind = if kind == FrameKind::OpenSecureChannel {
            FrameKind::OpenSecureChannel
        } else {
            FrameKind::Message
        };
        let (mut e, len_pos) =
            self.begin_uasc_response(out, kind, request_id, service_id::SERVICE_FAULT_RESPONSE)?;
        Self::write_response_header(&mut e, request_handle, service_result)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn service_response_or_fault(
        &mut self,
        result: Result<usize>,
        out: &mut [u8],
        kind: FrameKind,
        request_id: u32,
        request_handle: u32,
    ) -> Result<FrameAction> {
        match result {
            Ok(len) => Ok(FrameAction::SendResponse(len)),
            Err(error) => {
                let status = service_fault_status_for_error(error);
                self.encode_service_fault(out, kind, request_id, request_handle, status)
                    .map(FrameAction::SendResponse)
            }
        }
    }

    fn encode_find_servers_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        include_local: bool,
    ) -> Result<usize> {
        let endpoint_buf = self.endpoint_url;
        let endpoint_len = self.endpoint_url_len;
        let endpoint_url = endpoint_url_from_buffer(&endpoint_buf, endpoint_len);
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::FIND_SERVERS_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(usize::from(include_local))?;
        if include_local {
            write_application_description(&mut e, endpoint_url, self.identity.application_uri())?;
        }
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_find_servers_on_network_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
    ) -> Result<usize> {
        let endpoint_buf = self.endpoint_url;
        let endpoint_len = self.endpoint_url_len;
        let endpoint_url = endpoint_url_from_buffer(&endpoint_buf, endpoint_len);
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::FIND_SERVERS_ON_NETWORK_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_i64(0)?; // lastCounterResetTime
        e.write_array_len(1)?;
        e.write_u32(1)?; // recordId
        e.write_string(APPLICATION_NAME)?;
        e.write_string(endpoint_url)?;
        e.write_array_len(1)?;
        e.write_string("DA")?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_get_endpoints_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
    ) -> Result<usize> {
        let endpoint_buf = self.endpoint_url;
        let endpoint_len = self.endpoint_url_len;
        let endpoint_url = endpoint_url_from_buffer(&endpoint_buf, endpoint_len);
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::GET_ENDPOINTS_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(1)?;
        write_endpoint_description(&mut e, endpoint_url, self.identity.application_uri())?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn decode_create_session_timeout(d: &mut Decoder<'_>, previous_limit: usize) -> Result<f64> {
        d.skip_application_description()?;
        d.skip_string()?; // serverUri
        d.skip_string()?; // endpointUrl
        d.skip_string()?; // sessionName
        let _client_nonce = d.read_byte_string()?;
        let _client_certificate = d.read_byte_string()?;
        let requested_timeout = d
            .read_f64()
            .unwrap_or(f64::from(DEFAULT_SESSION_TIMEOUT_MS));
        let _max_response_message_size = d.read_u32().unwrap_or(0);
        d.end_limited(previous_limit)?;
        Ok(requested_timeout)
    }

    fn encode_create_session_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        revised_session_timeout_ms: u32,
    ) -> Result<usize> {
        let endpoint_buf = self.endpoint_url;
        let endpoint_len = self.endpoint_url_len;
        let endpoint_url = endpoint_url_from_buffer(&endpoint_buf, endpoint_len);
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::CREATE_SESSION_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_node_id(NodeId::numeric(APPLICATION_NAMESPACE_INDEX, 7000))?;
        e.write_node_id(self.session_token)?;
        e.write_f64(f64::from(revised_session_timeout_ms))?;
        e.write_null_byte_string()?;
        e.write_null_byte_string()?;
        e.write_array_len(1)?;
        write_endpoint_description(&mut e, endpoint_url, self.identity.application_uri())?;
        e.write_array_len(0)?;
        e.write_string("")?;
        e.write_null_byte_string()?;
        e.write_u32(DEFAULT_MAX_MESSAGE_SIZE)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_activate_session_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
    ) -> Result<usize> {
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::ACTIVATE_SESSION_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_null_byte_string()?;
        e.write_array_len(0)?;
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_browse_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        d.read_node_id()?; // viewId
        d.read_i64()?; // timestamp
        d.read_u32()?; // viewVersion
        let requested_max = d.read_u32()?;
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_BULK_SERVICE_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::BROWSE_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let browse = BrowseDescription {
                node_id: d.read_node_id()?,
                browse_direction: d.read_i32()?,
                reference_type_id: d.read_node_id()?,
                include_subtypes: d.read_bool()?,
                node_class_mask: d.read_u32()?,
                result_mask: d.read_u32()?,
            };
            write_browse_result(&mut e, browse, requested_max)?;
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_read_response<const WRITE_CAPACITY: usize>(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
        data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Result<usize> {
        let max_age = d.read_f64()?;
        let timestamps = d.read_i32()?;
        if max_age < 0.0 {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_MAX_AGE_INVALID,
            );
        }
        if !(0..=3).contains(&timestamps) {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TIMESTAMPS_TO_RETURN_INVALID,
            );
        }
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_BULK_SERVICE_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::READ_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        let namespace_array = [
            "http://opcfoundation.org/UA/",
            self.identity.application_uri(),
            crate::PRODUCT_NAMESPACE_URI,
        ];
        let server_array = [self.identity.application_uri()];
        for _ in 0..count {
            let rv = d.read_read_value_id()?;
            write_read_data_value(
                &mut e,
                rv,
                data_access,
                freshness_now_ms,
                self.build_info,
                &namespace_array,
                &server_array,
            )?;
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_write_response<const WRITE_CAPACITY: usize>(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
        data_access: &mut RuntimeDataAccess<WRITE_CAPACITY>,
    ) -> Result<usize> {
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_BULK_SERVICE_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::WRITE_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let node = d.read_node_id()?;
            let attr = d.read_u32()?;
            let index_range_present = d
                .read_byte_string()?
                .map(|value| !value.is_empty())
                .unwrap_or(false);
            let value = d.read_data_value_for_write()?;
            let status = write_node_value(node, attr, index_range_present, value, data_access);
            e.write_u32(status)?;
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_create_subscription_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
        now_monotonic_ms: u32,
    ) -> Result<usize> {
        let requested_interval = d
            .read_f64()
            .unwrap_or(product::DATA_CHANGE_INTERVAL_MS as f64);
        let requested_lifetime = d.read_u32().unwrap_or(10);
        let requested_keepalive = d.read_u32().unwrap_or(3);
        let _max_notifs = d.read_u32().unwrap_or(0);
        let publishing_enabled = d.read_bool().unwrap_or(true);
        let _priority = d.read_u8().unwrap_or(0);
        let revised_interval_ms = Self::revise_publishing_interval_ms(requested_interval);
        let revised_keepalive = requested_keepalive.clamp(1, u32::MAX / 3);
        let revised_lifetime = requested_lifetime.max(revised_keepalive.saturating_mul(3));
        let service_result = if self.subscription_active {
            status::BAD_TOO_MANY_SUBSCRIPTIONS
        } else {
            self.subscription_active = true;
            self.publish_sequence_number = 1;
            #[cfg(feature = "diagnostic-protocol-identifiers")]
            if let Some(seed) = self.initial_publish_sequence.take() {
                self.publish_sequence_number = seed;
            }
            self.clear_publish_queue();
            self.publishing_interval_ms = revised_interval_ms.max(1);
            self.keepalive_count = revised_keepalive;
            self.subscription_lifetime_count = revised_lifetime.max(1);
            self.publish_intervals_without_token = 0;
            self.empty_cycle_count = 0;
            self.publish_message_sent = false;
            self.next_publish_due_ms = now_monotonic_ms.wrapping_add(self.publishing_interval_ms);
            self.publishing_enabled = publishing_enabled;
            opcua_status::GOOD
        };
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::CREATE_SUBSCRIPTION_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, service_result)?;
        e.write_u32(self.subscription_id)?;
        e.write_f64(f64::from(revised_interval_ms))?;
        e.write_u32(revised_lifetime)?;
        e.write_u32(revised_keepalive)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_modify_subscription_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
        now_monotonic_ms: u32,
    ) -> Result<usize> {
        let sub_id = d.read_u32().unwrap_or(0);
        let requested_interval = d
            .read_f64()
            .unwrap_or(product::DATA_CHANGE_INTERVAL_MS as f64);
        let requested_lifetime = d.read_u32().unwrap_or(10);
        let requested_keepalive = d.read_u32().unwrap_or(3);
        let _max_notifs = d.read_u32().unwrap_or(0);
        let _priority = d.read_u8().unwrap_or(0);
        let revised_interval_ms = Self::revise_publishing_interval_ms(requested_interval);
        let revised_keepalive = requested_keepalive.clamp(1, u32::MAX / 3);
        let revised_lifetime = requested_lifetime.max(revised_keepalive.saturating_mul(3));
        let service_result = if self.subscription_active && sub_id == self.subscription_id {
            self.publishing_interval_ms = revised_interval_ms;
            self.keepalive_count = revised_keepalive;
            self.subscription_lifetime_count = revised_lifetime;
            self.empty_cycle_count = 0;
            self.next_publish_due_ms = now_monotonic_ms.wrapping_add(revised_interval_ms);
            opcua_status::GOOD
        } else {
            status::BAD_SUBSCRIPTION_ID_INVALID
        };
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::MODIFY_SUBSCRIPTION_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, service_result)?;
        e.write_f64(f64::from(revised_interval_ms))?;
        e.write_u32(revised_lifetime)?;
        e.write_u32(revised_keepalive)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_delete_subscriptions_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::DELETE_SUBSCRIPTIONS_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let id = d.read_u32()?;
            if self.subscription_active && id == self.subscription_id {
                self.subscription.clear();
                self.subscription_active = false;
                self.clear_publish_state();
                e.write_u32(opcua_status::GOOD)?;
            } else {
                e.write_u32(status::BAD_SUBSCRIPTION_ID_INVALID)?;
            }
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_create_monitored_items_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        let sub_id = d.read_u32()?;
        let _timestamps = d.read_i32()?;
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_MONITORED_ITEM_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::CREATE_MONITORED_ITEMS_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let rv = d.read_read_value_id()?;
            let _monitoring_mode = d.read_i32()?;
            let client_handle = d.read_u32()?;
            let sampling_interval = d
                .read_f64()
                .unwrap_or(product::DATA_CHANGE_INTERVAL_MS as f64);
            let filter_present = d.read_extension_object_present()?;
            let _queue_size = d.read_u32().unwrap_or(1);
            let _discard_oldest = d.read_bool().unwrap_or(true);
            let (status_code, monitored_item_id) =
                if !self.subscription_active || sub_id != self.subscription_id {
                    (status::BAD_SUBSCRIPTION_ID_INVALID, 0)
                } else if filter_present {
                    // ADR depth policy call 4(a): reject filters with correct code.
                    (status::BAD_MONITORED_ITEM_FILTER_UNSUPPORTED, 0)
                } else if rv.attribute_id != ATTR_VALUE {
                    (status::BAD_NOT_SUPPORTED, 0)
                } else if let Some(node_id) = namespace_node_id_for_product_node(rv.node_id) {
                    let result = self
                        .subscription
                        .add_namespace_node_id(node_id, client_handle);
                    (
                        result.opcua_status,
                        result.slot.map(|slot| slot as u32 + 1).unwrap_or(0),
                    )
                } else {
                    (status::BAD_NODE_ID_UNKNOWN, 0)
                };
            e.write_u32(status_code)?;
            e.write_u32(monitored_item_id)?;
            e.write_f64(sampling_interval.max(product::DATA_CHANGE_INTERVAL_MS as f64))?;
            e.write_u32(1)?;
            e.write_extension_object_none()?;
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_modify_monitored_items_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        let sub_id = d.read_u32()?;
        let _timestamps = d.read_i32()?;
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_MONITORED_ITEM_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::MODIFY_MONITORED_ITEMS_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let monitored_item_id = d.read_u32()?;
            let _client_handle = d.read_u32()?;
            let sampling_interval = d
                .read_f64()
                .unwrap_or(product::DATA_CHANGE_INTERVAL_MS as f64);
            let filter_present = d.read_extension_object_present()?;
            let _queue_size = d.read_u32().unwrap_or(1);
            let _discard_oldest = d.read_bool().unwrap_or(true);
            let status_code = if self.subscription_active
                && sub_id == self.subscription_id
                && monitored_item_id > 0
                && monitored_item_id as usize <= self.subscription.capacity()
            {
                if filter_present {
                    status::BAD_MONITORED_ITEM_FILTER_UNSUPPORTED
                } else {
                    opcua_status::GOOD
                }
            } else if !self.subscription_active || sub_id != self.subscription_id {
                status::BAD_SUBSCRIPTION_ID_INVALID
            } else {
                status::BAD_MONITORED_ITEM_ID_INVALID
            };
            e.write_u32(status_code)?;
            e.write_f64(sampling_interval.max(product::DATA_CHANGE_INTERVAL_MS as f64))?;
            e.write_u32(1)?;
            e.write_extension_object_none()?;
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_delete_monitored_items_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        let sub_id = d.read_u32()?;
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_MONITORED_ITEM_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::DELETE_MONITORED_ITEMS_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let monitored_item_id = d.read_u32()?;
            let status_code = if !self.subscription_active || sub_id != self.subscription_id {
                status::BAD_SUBSCRIPTION_ID_INVALID
            } else if monitored_item_id == 0 {
                status::BAD_MONITORED_ITEM_ID_INVALID
            } else {
                let slot = monitored_item_id as usize - 1;
                if self.subscription.remove_slot(slot) {
                    opcua_status::GOOD
                } else {
                    status::BAD_MONITORED_ITEM_ID_INVALID
                }
            };
            e.write_u32(status_code)?;
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn advance_due_subscription_samples<const WRITE_CAPACITY: usize>(
        &mut self,
        data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) {
        for slot in 0..self.subscription.capacity() {
            let _ = self
                .subscription
                .sample_slot(slot, data_access, freshness_now_ms);
        }
    }

    fn encode_publish_data_response<const WRITE_CAPACITY: usize>(
        &mut self,
        out: &mut [u8],
        request: QueuedPublishRequest,
        changed_count: usize,
        data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Result<usize> {
        let scheduler_now_ms = freshness_now_ms as u32;
        let sequence_number = self.publish_sequence_number;
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request.request_id,
            service_id::PUBLISH_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request.request_handle, opcua_status::GOOD)?;
        e.write_u32(self.subscription_id)?;
        e.write_array_len(0)?;
        e.write_bool(false)?;
        e.write_u32(sequence_number)?;
        e.write_i64(opcua_datetime_from_monotonic(scheduler_now_ms))?;
        e.write_array_len(1)?;
        let dc_len = e.begin_extension_object(service_id::DATA_CHANGE_NOTIFICATION)?;
        e.write_array_len(changed_count)?;
        let mut emitted = 0usize;
        for slot in 0..self.subscription.capacity() {
            if let Some(sample) = self
                .subscription
                .sample_slot(slot, data_access, freshness_now_ms)
            {
                if sample.changed {
                    e.write_u32(sample.client_handle)?;
                    match sample.value {
                        Some(value) if sample.opcua_status == opcua_status::GOOD => {
                            e.write_data_value_scalar(sample.opcua_status, value)?;
                        }
                        _ => e.write_data_value_status(sample.opcua_status)?,
                    }
                    emitted += 1;
                }
            }
        }
        if emitted != changed_count {
            return Err(OpcUaError::InvalidFrame);
        }
        e.write_array_len(0)?;
        e.end_extension_object(dc_len)?;
        Self::write_publish_ack_results(&mut e, request.ack_count)?;
        let len = Self::finish_uasc_response(e, len_pos)?;
        self.publish_sequence_number = next_publish_sequence_number(sequence_number);
        Ok(len)
    }

    fn encode_publish_keepalive_response(
        &mut self,
        out: &mut [u8],
        request: QueuedPublishRequest,
        now_monotonic_ms: u32,
    ) -> Result<usize> {
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request.request_id,
            service_id::PUBLISH_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request.request_handle, opcua_status::GOOD)?;
        e.write_u32(self.subscription_id)?;
        e.write_array_len(0)?;
        e.write_bool(false)?;
        e.write_u32(self.publish_sequence_number)?;
        e.write_i64(opcua_datetime_from_monotonic(now_monotonic_ms))?;
        e.write_array_len(0)?;
        Self::write_publish_ack_results(&mut e, request.ack_count)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_publish_service_result_response(
        &mut self,
        out: &mut [u8],
        request: QueuedPublishRequest,
        service_result: u32,
        now_monotonic_ms: u32,
    ) -> Result<usize> {
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request.request_id,
            service_id::PUBLISH_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request.request_handle, service_result)?;
        e.write_u32(if self.subscription_active {
            self.subscription_id
        } else {
            0
        })?;
        e.write_array_len(0)?;
        e.write_bool(false)?;
        e.write_u32(self.publish_sequence_number)?;
        e.write_i64(opcua_datetime_from_monotonic(now_monotonic_ms))?;
        e.write_array_len(0)?;
        Self::write_publish_ack_results(&mut e, request.ack_count)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn write_publish_ack_results(e: &mut Encoder<'_>, ack_count: usize) -> Result<()> {
        e.write_array_len(ack_count)?;
        for _ in 0..ack_count {
            e.write_u32(status::GOOD_RETRANSMISSION_QUEUE_NOT_SUPPORTED)?;
        }
        e.write_array_len(0)
    }

    fn encode_republish_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        let subscription_id = d.read_u32()?;
        let _retransmit_sequence_number = d.read_u32()?;
        let service_result = if self.subscription_active && subscription_id == self.subscription_id
        {
            status::BAD_MESSAGE_NOT_AVAILABLE
        } else {
            status::BAD_SUBSCRIPTION_ID_INVALID
        };
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::REPUBLISH_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, service_result)?;
        e.write_u32(0)?;
        e.write_i64(0)?;
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }

    fn encode_set_publishing_mode_response(
        &mut self,
        out: &mut [u8],
        request_id: u32,
        request_handle: u32,
        d: &mut Decoder<'_>,
    ) -> Result<usize> {
        let publishing_enabled = d.read_bool()?;
        let count = d.read_array_len(MAX_REQUESTED_NODES)?;
        if count > MAX_BULK_SERVICE_OPERATIONS {
            return self.encode_service_fault(
                out,
                FrameKind::Message,
                request_id,
                request_handle,
                status::BAD_TOO_MANY_OPERATIONS,
            );
        }
        let (mut e, len_pos) = self.begin_uasc_response(
            out,
            FrameKind::Message,
            request_id,
            service_id::SET_PUBLISHING_MODE_RESPONSE,
        )?;
        Self::write_response_header(&mut e, request_handle, opcua_status::GOOD)?;
        e.write_array_len(count)?;
        for _ in 0..count {
            let subscription_id = d.read_u32()?;
            if self.subscription_active && subscription_id == self.subscription_id {
                self.publishing_enabled = publishing_enabled;
                e.write_u32(opcua_status::GOOD)?;
            } else {
                e.write_u32(status::BAD_SUBSCRIPTION_ID_INVALID)?;
            }
        }
        e.write_array_len(0)?;
        Self::finish_uasc_response(e, len_pos)
    }
}

fn endpoint_url_from_buffer(buf: &[u8; MAX_ENDPOINT_URL_LEN], len: usize) -> &str {
    core::str::from_utf8(&buf[..len])
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_ENDPOINT_URL)
}

fn secure_channel_timestamp(request_timestamp: i64, now_monotonic_ms: u32) -> i64 {
    if request_timestamp > 0 {
        request_timestamp
    } else {
        opcua_datetime_from_monotonic(now_monotonic_ms)
    }
}

fn opcua_datetime_from_monotonic(now_monotonic_ms: u32) -> i64 {
    NULL_TIMESTAMP_CHANNEL_EPOCH_UTC
        + i64::from(now_monotonic_ms) * OPCUA_DATETIME_TICKS_PER_MILLISECOND
}

fn secure_channel_revised_lifetime(request_timestamp: i64, requested_lifetime: u32) -> u32 {
    let minimum_lifetime = if request_timestamp > 0 {
        60_000
    } else {
        NULL_TIMESTAMP_TOKEN_LIFETIME_MS
    };
    requested_lifetime.max(minimum_lifetime)
}

pub(crate) fn monotonic_due(now_ms: u32, due_ms: u32) -> bool {
    now_ms.wrapping_sub(due_ms) < 0x8000_0000
}

fn next_publish_sequence_number(sequence_number: u32) -> u32 {
    sequence_number.wrapping_add(1).max(1)
}

fn service_fault_status_for_error(error: OpcUaError) -> u32 {
    match error {
        OpcUaError::BufferTooSmall => status::BAD_RESPONSE_TOO_LARGE,
        OpcUaError::Malformed => status::BAD_ENCODING_LIMITS_EXCEEDED,
        OpcUaError::Truncated | OpcUaError::InvalidFrame => status::BAD_DECODING_ERROR,
        OpcUaError::Unsupported => status::BAD_SERVICE_UNSUPPORTED,
    }
}

fn write_endpoint_description(
    e: &mut Encoder<'_>,
    endpoint_url: &str,
    application_uri: &str,
) -> Result<()> {
    e.write_string(endpoint_url)?;
    write_application_description(e, endpoint_url, application_uri)?;
    e.write_null_byte_string()?;
    e.write_i32(1)?; // MessageSecurityMode::None
    e.write_string(SECURITY_POLICY_NONE)?;
    e.write_array_len(1)?;
    e.write_string("anonymous")?;
    e.write_i32(0)?; // UserTokenType::Anonymous
    e.write_null_string()?;
    e.write_null_string()?;
    e.write_null_string()?;
    e.write_string(TRANSPORT_PROFILE_URI)?;
    e.write_u8(0)
}

fn write_application_description(
    e: &mut Encoder<'_>,
    endpoint_url: &str,
    application_uri: &str,
) -> Result<()> {
    e.write_string(application_uri)?;
    e.write_string(PRODUCT_URI)?;
    e.write_localized_text(APPLICATION_NAME)?;
    e.write_i32(0)?; // Server
    e.write_string("")?;
    e.write_string("")?;
    e.write_array_len(1)?;
    e.write_string(endpoint_url)
}
