use opta_buchi::{
    build_write_json, lookup_write_spec, lookup_write_spec_by_node_id, validate_write_raw_value,
    BuchiPutTransaction, BuildWriteJsonError, Endpoint, EndpointResponseError, EndpointValues,
    WriteQueue, WriteRequest, WriteTarget, WriteValidationStatus,
};
use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::last_fault::LastFaultRecord;
use opta_gateway_contracts::opcua_status;

#[cfg(feature = "diagnostic-cache-ages")]
pub(super) mod diagnostic_ages;

use crate::{
    endpoint_from_values, health_u32, lookup_default_namespace_node,
    runtime_node_contract_by_index, scalar_write_value_to_raw, BuchiTrustHealthSnapshot,
    DataAccessRead, DataAccessWriteResult, EndpointPollError, EndpointPollFailure,
    EndpointPollReport, HealthNode, HealthRead, NamespaceRead, NamespaceTarget, PublishSummary,
    RuntimeCache, RuntimeHealthState, RuntimeNode, RuntimeWriteCompletion,
    RuntimeWriteCompletionError, RuntimeWriteDispatch, RuntimeWriteDispatchError,
    RuntimeWriteTransactionError, SingleCoreHealthSnapshot, SINGLE_CORE_TASK_HEALTH_SLOT_COUNT,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDataAccess<const WRITE_CAPACITY: usize> {
    cache: RuntimeCache,
    write_queue: WriteQueue<WRITE_CAPACITY>,
    health: RuntimeHealthState,
    trust_state: TrustState,
    write_enabled: bool,
    next_write_sequence: u32,
}

impl<const WRITE_CAPACITY: usize> RuntimeDataAccess<WRITE_CAPACITY> {
    pub const fn new() -> Self {
        Self {
            cache: RuntimeCache::new(),
            write_queue: WriteQueue::new(),
            health: RuntimeHealthState::new(),
            trust_state: TrustState::Missing,
            write_enabled: false,
            next_write_sequence: 1,
        }
    }

    pub const fn cache(&self) -> &RuntimeCache {
        &self.cache
    }

    /// Seed a Verified owner after a successful response, with no write history.
    ///
    /// `last_fetch_ok` records successful response processing, not a Good
    /// baseline for any particular tag. A response containing only a sibling
    /// field can satisfy it while the intended baseline tag is unavailable.
    /// Firmware must separately prove a real current handshake/generation and
    /// the required Good baseline, then hold trust/runtime owners through raw
    /// readback. A host trust setter is not authentication. This method has no
    /// await or intervening update.
    /// Pristine accepted/completion counts reject even already-dequeued writes.
    /// The seeded accepted count stays nonzero (saturating, not cache-owned),
    /// so cache reset/reverification cannot rearm this owner.
    #[cfg(feature = "diagnostic-runtime-counters")]
    pub fn diagnostic_seed_counters(
        &mut self,
        seed: crate::DiagnosticCounterSeed,
    ) -> Option<crate::DiagnosticCounterSnapshot> {
        if !self.writes_allowed()
            || !self.cache.last_fetch_ok()
            || !self.write_queue.is_empty()
            || self.next_write_sequence != 1
            || self.health.buchi_write_accepted_count != 0
            || self.health.buchi_write_completed_count != 0
            || self.health.buchi_write_failed_count != 0
        {
            return None;
        }
        let value = seed.value();
        self.next_write_sequence = value;
        self.health.buchi_write_accepted_count = value;
        self.health.buchi_write_completed_count = value;
        self.health.buchi_write_failed_count = value;
        self.cache.diagnostic_seed_successful_fetches(seed);
        Some(self.diagnostic_counters())
    }

    #[cfg(feature = "diagnostic-runtime-counters")]
    pub fn diagnostic_counters(&self) -> crate::DiagnosticCounterSnapshot {
        crate::DiagnosticCounterSnapshot {
            next_write_sequence: self.next_write_sequence,
            accepted_writes: self.health.buchi_write_accepted_count,
            completed_writes: self.health.buchi_write_completed_count,
            failed_writes: self.health.buchi_write_failed_count,
            successful_fetches: self.cache.completed_fetches(),
        }
    }

    pub const fn health(&self) -> &RuntimeHealthState {
        &self.health
    }

    pub fn health_mut(&mut self) -> &mut RuntimeHealthState {
        &mut self.health
    }

    pub const fn write_enabled(&self) -> bool {
        self.write_enabled
    }

    pub const fn trust_state(&self) -> TrustState {
        self.trust_state
    }

    pub const fn trust_verified(&self) -> bool {
        matches!(self.trust_state, TrustState::Verified)
    }

    pub const fn writes_allowed(&self) -> bool {
        self.write_enabled && self.trust_verified()
    }

    /// Whether a dequeued write may still enter the transport send path.
    ///
    /// Call after `pop_next_write_json` (or equivalent) and again immediately
    /// before the first request byte is written. Trust revoke clears the queue
    /// and flips this to false; the caller must record a failed completion and
    /// must not send. Residual boundary (BH-8): once any PUT byte has entered
    /// the TLS/TCP stack, revoke cannot retract the upstream setpoint.
    pub const fn write_send_authorized(&self) -> bool {
        self.trust_verified()
    }

    /// Set the authorization state for upstream-derived data and writes.
    ///
    /// Any non-Verified state invalidates cached values and queued writes.
    /// Entering Verified also starts from an empty cache so material observed
    /// before the current verified session can never become Good later.
    pub fn set_trust_state(&mut self, state: TrustState) {
        if state != self.trust_state {
            self.cache = RuntimeCache::new();
            self.cancel_queued_writes_for_trust_loss();
        }
        self.health.buchi_verifier_time_trusted = false;
        self.trust_state = state;
        self.health.buchi_trust_state = state;
    }

    /// Establish a Verified session and record whether its verifier used trusted time.
    pub fn set_verified_trust_session(&mut self, verifier_time_trusted: bool) {
        self.set_trust_state(TrustState::Verified);
        self.health.buchi_verifier_time_trusted = verifier_time_trusted;
    }

    pub fn set_write_enabled(&mut self, enabled: bool) {
        self.write_enabled = enabled;
    }

    pub fn set_buchi_status_inputs(
        &mut self,
        configured: bool,
        network_ready: bool,
        body_truncated: bool,
    ) {
        self.health.buchi_configured = configured;
        self.health.buchi_network_ready = network_ready;
        self.health.buchi_body_truncated = body_truncated;
    }

    pub fn set_memory_diagnostics(
        &mut self,
        mbedtls_current_bytes: u32,
        mbedtls_peak_bytes: u32,
        heap_alloc_fail_count: u32,
        mbedtls_failed_alloc_count: u32,
    ) {
        self.health.mbedtls_current_bytes = mbedtls_current_bytes;
        self.health.mbedtls_peak_bytes = mbedtls_peak_bytes;
        self.health.heap_alloc_fail_count = heap_alloc_fail_count;
        self.health.mbedtls_failed_alloc_count = mbedtls_failed_alloc_count;
    }

    pub fn set_opcua_transport_diagnostics(
        &mut self,
        opcua_transport_drops: u32,
        opcua_close_queue_full_count: u32,
    ) {
        self.health.opcua_transport_drops = opcua_transport_drops;
        self.health.opcua_close_queue_full_count = opcua_close_queue_full_count;
    }

    pub fn set_loop_timing_diagnostics(
        &mut self,
        loop_max_gap_ms: u32,
        heartbeat_max_gap_ms: u32,
        late_heartbeat_count: u32,
    ) {
        self.health.loop_max_gap_ms = loop_max_gap_ms;
        self.health.heartbeat_max_gap_ms = heartbeat_max_gap_ms;
        self.health.late_heartbeat_count = late_heartbeat_count;
        self.health.loop_timing_measured = true;
    }

    pub fn set_buchi_rejected_request_count(&mut self, rejected_request_count: u32) {
        self.health.buchi_rejected_request_count = rejected_request_count;
    }

    pub fn set_single_core_health(&mut self, snapshot: SingleCoreHealthSnapshot) {
        self.health.single_core = Some(snapshot);
    }

    pub fn set_buchi_trust_health(&mut self, snapshot: BuchiTrustHealthSnapshot) {
        if snapshot.state != TrustState::Verified {
            self.health.buchi_verifier_time_trusted = false;
        }
        self.health.buchi_trust_state = snapshot.state;
        self.health.buchi_trust_anchor_present = snapshot.anchor_present;
        self.health.buchi_trust_rtc_usable = snapshot.rtc_usable;
        self.health.buchi_trust_last_verify_error = snapshot.last_verify_error;
        self.health.buchi_trust_verify_attempt_count = snapshot.verify_attempt_count;
        self.health.buchi_trust_verified_session_count = snapshot.verified_session_count;
        self.health.buchi_trust_revocation_count = snapshot.revocation_count;
    }

    pub fn set_last_fault(&mut self, record: LastFaultRecord) {
        self.health.last_fault = if record.valid { Some(record) } else { None };
    }

    pub fn clear_last_fault(&mut self) {
        self.health.last_fault = None;
    }

    pub fn set_reset_flags(&mut self, reset_flags: u32) {
        self.health.reset_flags = reset_flags;
    }

    /// Compatibility setter retained for callers and tests that carry both
    /// values. Product boot currently leaves `watchdog_bite_count` at zero;
    /// no cumulative retained bite counter has been implemented.
    pub fn set_reset_diagnostics(&mut self, reset_flags: u32, watchdog_bite_count: u32) {
        self.set_reset_flags(reset_flags);
        self.health.watchdog_bite_count = watchdog_bite_count;
    }

    pub fn record_buchi_write_result(
        &mut self,
        target_node_id: u16,
        http_status: i32,
        completion_opcua_status: u32,
    ) {
        self.record_buchi_write_target(target_node_id, http_status, completion_opcua_status);
        if completion_opcua_status == opcua_status::GOOD {
            self.health.buchi_write_completed_count =
                self.health.buchi_write_completed_count.saturating_add(1);
        } else {
            self.health.buchi_write_failed_count =
                self.health.buchi_write_failed_count.saturating_add(1);
        }
    }

    fn record_buchi_write_target(
        &mut self,
        target_node_id: u16,
        http_status: i32,
        completion_opcua_status: u32,
    ) {
        self.health.buchi_write_last_target_node_id = u32::from(target_node_id);
        self.health.buchi_write_last_http_status = http_status as u32;
        self.health.buchi_write_last_opcua_status = completion_opcua_status;
    }

    pub const fn write_queue_depth(&self) -> usize {
        self.write_queue.len()
    }

    pub const fn write_queue_capacity(&self) -> usize {
        self.write_queue.capacity()
    }

    pub fn pop_write_request(&mut self) -> Option<WriteRequest> {
        self.write_queue.pop()
    }

    pub fn pop_next_write_json(
        &mut self,
        out: &mut [u8],
    ) -> Result<RuntimeWriteDispatch, RuntimeWriteDispatchError> {
        let request = self
            .write_queue
            .peek()
            .ok_or(RuntimeWriteDispatchError::EmptyQueue)?;
        let spec = lookup_write_spec(request.target).ok_or(RuntimeWriteDispatchError::Build(
            BuildWriteJsonError::UnknownTarget,
        ))?;
        let body_len = build_write_json(request, out).map_err(RuntimeWriteDispatchError::Build)?;
        let _ = self.write_queue.pop();
        Ok(RuntimeWriteDispatch {
            request,
            endpoint: spec.endpoint.endpoint(),
            body_len,
        })
    }

    pub fn pop_next_write_transaction<
        const BODY_CAPACITY: usize,
        const REQUEST_CAPACITY: usize,
        const RESPONSE_CAPACITY: usize,
    >(
        &mut self,
        host: &str,
        basic_auth_token: &str,
    ) -> Result<
        BuchiPutTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>,
        RuntimeWriteTransactionError,
    > {
        let request = self
            .write_queue
            .peek()
            .ok_or(RuntimeWriteTransactionError::EmptyQueue)?;
        let transaction = BuchiPutTransaction::new(request, host, basic_auth_token)
            .map_err(RuntimeWriteTransactionError::Build)?;
        let _ = self.write_queue.pop();
        Ok(transaction)
    }

    pub fn record_write_transaction_completion<
        const BODY_CAPACITY: usize,
        const REQUEST_CAPACITY: usize,
        const RESPONSE_CAPACITY: usize,
    >(
        &mut self,
        transaction: &BuchiPutTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>,
        transport_result: i32,
    ) -> Result<RuntimeWriteCompletion, RuntimeWriteCompletionError> {
        let request = transaction.write_request();
        let http_status = transaction
            .http_status()
            .map_err(RuntimeWriteCompletionError::Transaction)?;
        let opcua_status = transaction
            .completion_opcua_status(transport_result)
            .map_err(RuntimeWriteCompletionError::Transaction)?;
        self.record_buchi_write_result(request.node_id, http_status, opcua_status);
        Ok(RuntimeWriteCompletion {
            request,
            http_status,
            opcua_status,
        })
    }

    /// Immediately remove all upstream-derived state after trust revocation.
    ///
    /// This deliberately resets successful-fetch history as well as values so
    /// no previously Good cache entry can survive a USB trust-clear or factory
    /// reset. The configured write-enable preference may be restored only when
    /// usable trust is provisioned again.
    pub fn revoke_upstream_trust(&mut self) {
        self.cache = RuntimeCache::new();
        self.cancel_queued_writes_for_trust_loss();
        self.health.buchi_configured = false;
        self.health.buchi_network_ready = false;
        self.health.buchi_body_truncated = false;
        self.write_enabled = false;
        self.trust_state = TrustState::Revoked;
        self.health.buchi_verifier_time_trusted = false;
    }

    fn cancel_queued_writes_for_trust_loss(&mut self) {
        // Match the transport's pre-send trust-loss outcome. Coalesced requests
        // occupy one entry; already-dequeued writes stay owned by the transport.
        while let Some(request) = self.write_queue.pop() {
            self.record_buchi_write_result(
                request.node_id,
                0,
                opcua_status::BAD_USER_ACCESS_DENIED,
            );
        }
        self.write_queue.clear();
    }

    pub fn apply_http_response(
        &mut self,
        endpoint: Endpoint,
        response: &[u8],
        response_limit: usize,
        freshness_now_ms: u64,
    ) -> Result<EndpointPollReport, EndpointPollFailure> {
        if !self.trust_verified() {
            return Err(EndpointPollFailure {
                endpoint,
                error: EndpointPollError::TrustNotVerified,
                completed_fetches: self.cache.completed_fetches(),
                failed_fetches: self.cache.failed_fetches(),
                last_http_status: self.cache.last_http_status(),
            });
        }
        self.cache
            .apply_http_response(endpoint, response, response_limit, freshness_now_ms)
    }

    pub fn apply_endpoint_values(
        &mut self,
        values: EndpointValues,
        freshness_now_ms: u64,
    ) -> PublishSummary {
        if !self.trust_verified() {
            return PublishSummary {
                endpoint: endpoint_from_values(&values),
                parsed_fields: 0,
                published_values: 0,
            };
        }
        self.cache.apply_endpoint_values(values, freshness_now_ms)
    }

    pub fn apply_endpoint_values_report(
        &mut self,
        values: EndpointValues,
        freshness_now_ms: u64,
    ) -> EndpointPollReport {
        if !self.trust_verified() {
            return EndpointPollReport {
                summary: PublishSummary {
                    endpoint: endpoint_from_values(&values),
                    parsed_fields: 0,
                    published_values: 0,
                },
                completed_fetches: self.cache.completed_fetches(),
                failed_fetches: self.cache.failed_fetches(),
                last_http_status: self.cache.last_http_status(),
            };
        }
        self.cache
            .apply_endpoint_values_report(values, freshness_now_ms)
    }

    pub fn record_endpoint_failure(
        &mut self,
        endpoint: Endpoint,
        error: EndpointResponseError,
    ) -> EndpointPollFailure {
        self.cache.record_endpoint_failure(endpoint, error)
    }

    pub fn read_namespace_node_id(&self, node_id: u16, freshness_now_ms: u64) -> NamespaceRead {
        let Some(namespace_node) = lookup_default_namespace_node(node_id) else {
            return NamespaceRead {
                node_id,
                browse_name: None,
                value_kind: None,
                access: None,
                target: None,
                cache_status: None,
                opcua_status: opcua_status::BAD_INDEX_RANGE_INVALID,
                value: None,
            };
        };

        match namespace_node.target {
            NamespaceTarget::Runtime(node) => {
                let read = self.read_node(node, freshness_now_ms);
                NamespaceRead {
                    node_id,
                    browse_name: Some(namespace_node.browse_name),
                    value_kind: Some(namespace_node.value_kind),
                    access: Some(namespace_node.access),
                    target: Some(namespace_node.target),
                    cache_status: Some(read.cache_status),
                    opcua_status: read.opcua_status,
                    value: read.value,
                }
            }
            NamespaceTarget::Health(node) => {
                let read = self.read_health_node(node);
                NamespaceRead {
                    node_id,
                    browse_name: Some(namespace_node.browse_name),
                    value_kind: Some(namespace_node.value_kind),
                    access: Some(namespace_node.access),
                    target: Some(namespace_node.target),
                    cache_status: None,
                    opcua_status: read.opcua_status,
                    value: read.value,
                }
            }
        }
    }

    pub fn read_health_node(&self, node: HealthNode) -> HealthRead {
        self.read_health_node_id(node.node_id())
    }

    pub fn read_health_node_id(&self, node_id: u16) -> HealthRead {
        let Some(node) = HealthNode::from_node_id(node_id) else {
            return HealthRead {
                node: None,
                node_id,
                browse_name: None,
                value_kind: None,
                opcua_status: opcua_status::BAD_INDEX_RANGE_INVALID,
                value: None,
            };
        };
        let contract = node.contract();
        let (opcua_status, value) = self.health_value(node);
        HealthRead {
            node: Some(node),
            node_id,
            browse_name: contract.map(|contract| contract.browse_name),
            value_kind: contract.map(|contract| contract.value_kind),
            opcua_status,
            value,
        }
    }

    fn health_value(&self, node: HealthNode) -> (u32, Option<ScalarValue>) {
        match node {
            HealthNode::BuchiCompletedFetchCount => (
                opcua_status::GOOD,
                Some(ScalarValue::UInt32(self.cache.completed_fetches())),
            ),
            HealthNode::BuchiFailedFetchCount => (
                opcua_status::GOOD,
                Some(ScalarValue::UInt32(self.cache.failed_fetches())),
            ),
            HealthNode::MbedtlsCurrentBytes => health_u32(self.health.mbedtls_current_bytes),
            HealthNode::MbedtlsPeakBytes => health_u32(self.health.mbedtls_peak_bytes),
            HealthNode::OpcUaTransportDrops => health_u32(self.health.opcua_transport_drops),
            HealthNode::BuchiRejectedRequestCount => {
                health_u32(self.health.buchi_rejected_request_count)
            }
            HealthNode::HeapAllocFailCount => health_u32(self.health.heap_alloc_fail_count),
            HealthNode::MbedtlsFailedAllocCount => {
                health_u32(self.health.mbedtls_failed_alloc_count)
            }
            HealthNode::OpcUaCloseQueueFullCount => {
                health_u32(self.health.opcua_close_queue_full_count)
            }
            HealthNode::LoopMaxGapMs => self.loop_timing_health_u32(self.health.loop_max_gap_ms),
            HealthNode::HeartbeatMaxGapMs => {
                self.loop_timing_health_u32(self.health.heartbeat_max_gap_ms)
            }
            HealthNode::LateHeartbeatCount => {
                self.loop_timing_health_u32(self.health.late_heartbeat_count)
            }
            HealthNode::BuchiStatusFlags => (
                opcua_status::GOOD,
                Some(ScalarValue::UInt32(
                    self.health.buchi_status_flags(self.cache.last_fetch_ok()),
                )),
            ),
            HealthNode::BuchiWriteQueueDepth => health_u32(self.write_queue_depth() as u32),
            HealthNode::BuchiWriteAcceptedCount => {
                health_u32(self.health.buchi_write_accepted_count)
            }
            HealthNode::BuchiWriteCompletedCount => {
                health_u32(self.health.buchi_write_completed_count)
            }
            HealthNode::BuchiWriteFailedCount => health_u32(self.health.buchi_write_failed_count),
            HealthNode::BuchiWriteQueueFullCount => {
                health_u32(self.health.buchi_write_queue_full_count)
            }
            HealthNode::BuchiWriteLastTargetNodeId => {
                health_u32(self.health.buchi_write_last_target_node_id)
            }
            HealthNode::BuchiWriteLastHttpStatus => {
                health_u32(self.health.buchi_write_last_http_status)
            }
            HealthNode::BuchiWriteLastOpcUaStatus => {
                health_u32(self.health.buchi_write_last_opcua_status)
            }
            HealthNode::UptimeSeconds => {
                self.single_core_health_u32(|snapshot| Some(snapshot.uptime_seconds))
            }
            HealthNode::IwdgLastKickAgeMs => {
                self.single_core_health_u32(|snapshot| snapshot.iwdg_last_kick_age_ms)
            }
            HealthNode::WatchdogStaleMask => {
                self.single_core_health_u32(|snapshot| Some(snapshot.watchdog_stale_mask))
            }
            HealthNode::TaskCheckinRegisteredMask => {
                self.single_core_health_u32(|snapshot| Some(snapshot.task_checkin_registered_mask))
            }
            HealthNode::TaskCheckinFreshMask => {
                self.single_core_health_u32(|snapshot| Some(snapshot.task_checkin_fresh_mask))
            }
            HealthNode::TaskCheckinDeadlineMs => {
                self.single_core_health_u32(|snapshot| Some(snapshot.task_checkin_deadline_ms))
            }
            HealthNode::LastFaultPresent => (
                opcua_status::GOOD,
                Some(ScalarValue::Boolean(self.health.last_fault.is_some())),
            ),
            HealthNode::LastFaultReason => self.last_fault_u32(|record| record.reason_word),
            HealthNode::LastFaultSequence => self.last_fault_u32(|record| record.sequence),
            HealthNode::LastFaultUptimeSeconds => match self.health.last_fault {
                Some(record) => match record.uptime_seconds() {
                    Some(seconds) => health_u32(seconds),
                    None => (opcua_status::BAD_NO_DATA, None),
                },
                None => health_u32(0),
            },
            HealthNode::LastFaultDetail => self.last_fault_u32(|record| record.detail),
            HealthNode::LastFaultResetFlags => self.last_fault_u32(|record| record.reset_flags),
            HealthNode::ResetFlags => health_u32(self.health.reset_flags),
            HealthNode::WatchdogBiteCount => health_u32(self.health.watchdog_bite_count),
            HealthNode::TaskCheckinMainHeartbeatAgeMs => self.single_core_task_age_u32(0),
            HealthNode::TaskCheckinMdnsResponderAgeMs => self.single_core_task_age_u32(1),
            HealthNode::TaskCheckinNetStatusAgeMs => self.single_core_task_age_u32(2),
            HealthNode::TaskCheckinUsbConsoleAgeMs => self.single_core_task_age_u32(3),
            HealthNode::TaskCheckinBuchiTlsClientAgeMs => self.single_core_task_age_u32(4),
            HealthNode::TaskCheckinOpcUaServerAgeMs => self.single_core_task_age_u32(5),
            HealthNode::BuchiTrustState => health_u32(self.health.buchi_trust_state as u32),
            HealthNode::BuchiTrustAnchorPresent => (
                opcua_status::GOOD,
                Some(ScalarValue::Boolean(self.health.buchi_trust_anchor_present)),
            ),
            HealthNode::BuchiTrustRtcUsable => (
                opcua_status::GOOD,
                Some(ScalarValue::Boolean(self.health.buchi_trust_rtc_usable)),
            ),
            HealthNode::BuchiTrustLastVerifyError => {
                health_u32(self.health.buchi_trust_last_verify_error)
            }
            HealthNode::BuchiTrustVerifyAttemptCount => {
                health_u32(self.health.buchi_trust_verify_attempt_count)
            }
            HealthNode::BuchiTrustVerifiedSessionCount => {
                health_u32(self.health.buchi_trust_verified_session_count)
            }
            HealthNode::BuchiTrustRevocationCount => {
                health_u32(self.health.buchi_trust_revocation_count)
            }
            HealthNode::BuchiVerifierTimeTrusted => (
                opcua_status::GOOD,
                Some(ScalarValue::Boolean(
                    self.health.buchi_verifier_time_trusted,
                )),
            ),
        }
    }

    fn single_core_health_u32(
        &self,
        select: fn(SingleCoreHealthSnapshot) -> Option<u32>,
    ) -> (u32, Option<ScalarValue>) {
        match self.health.single_core.and_then(select) {
            Some(value) => health_u32(value),
            None => (opcua_status::BAD_NO_DATA, None),
        }
    }

    fn loop_timing_health_u32(&self, value: u32) -> (u32, Option<ScalarValue>) {
        if self.health.loop_timing_measured {
            health_u32(value)
        } else {
            (opcua_status::BAD_NO_DATA, None)
        }
    }

    fn single_core_task_age_u32(&self, task_index: usize) -> (u32, Option<ScalarValue>) {
        let Some(snapshot) = self.health.single_core else {
            return (opcua_status::BAD_NO_DATA, None);
        };
        if task_index >= SINGLE_CORE_TASK_HEALTH_SLOT_COUNT {
            return (opcua_status::BAD_NO_DATA, None);
        }
        if snapshot.task_checkin_registered_mask & (1u32 << task_index) == 0 {
            return (opcua_status::BAD_NO_DATA, None);
        }
        match snapshot.task_checkin_age_ms[task_index] {
            Some(value) => health_u32(value),
            None => (opcua_status::BAD_NO_DATA, None),
        }
    }

    fn last_fault_u32(&self, select: fn(LastFaultRecord) -> u32) -> (u32, Option<ScalarValue>) {
        // No recorded fault is the healthy state. Serve the
        // LastFaultRecord::invalid() zero shape with Good; sequence 0 is
        // unambiguous because real faults number from 1 (next_sequence), and
        // LastFaultPresent stays the explicit fault-recorded discriminator.
        let record = self.health.last_fault.unwrap_or(LastFaultRecord::invalid());
        (
            opcua_status::GOOD,
            Some(ScalarValue::UInt32(select(record))),
        )
    }

    pub fn read_node(&self, node: RuntimeNode, freshness_now_ms: u64) -> DataAccessRead {
        self.read_index(node.index(), freshness_now_ms)
    }

    pub fn read_index(&self, index: usize, freshness_now_ms: u64) -> DataAccessRead {
        let read = self.cache.read_index(index, freshness_now_ms);
        let contract = runtime_node_contract_by_index(index);
        DataAccessRead {
            node: contract.map(|contract| contract.node),
            browse_name: contract.map(|contract| contract.browse_name),
            value_kind: contract.map(|contract| contract.value_kind),
            access: contract.map(|contract| contract.access()),
            cache_status: read.status,
            opcua_status: read.opcua_status(),
            value: read.value,
        }
    }

    pub fn enqueue_write_node(
        &mut self,
        node: RuntimeNode,
        value: ScalarValue,
    ) -> DataAccessWriteResult {
        let Some(node_id) = node.contract().writable_node_id else {
            return DataAccessWriteResult::rejected(
                None,
                WriteTarget::None,
                WriteValidationStatus::UnknownTarget,
                opta_buchi::write_validation_status_to_opcua_status(
                    WriteValidationStatus::UnknownTarget,
                ),
                self.write_queue.len(),
            );
        };
        self.enqueue_write_node_id(node_id, value)
    }

    pub fn enqueue_write_node_id(
        &mut self,
        node_id: u16,
        value: ScalarValue,
    ) -> DataAccessWriteResult {
        let Some(spec) = lookup_write_spec_by_node_id(node_id) else {
            return DataAccessWriteResult::rejected(
                Some(node_id),
                WriteTarget::None,
                WriteValidationStatus::UnknownTarget,
                opta_buchi::write_validation_status_to_opcua_status(
                    WriteValidationStatus::UnknownTarget,
                ),
                self.write_queue.len(),
            );
        };

        if !self.writes_allowed() {
            return DataAccessWriteResult::rejected(
                Some(node_id),
                spec.target,
                WriteValidationStatus::Ok,
                opcua_status::BAD_NOT_WRITABLE,
                self.write_queue.len(),
            );
        }

        let raw_value = match scalar_write_value_to_raw(spec, value) {
            Ok(raw_value) => raw_value,
            Err(validation) => {
                return DataAccessWriteResult::rejected(
                    Some(node_id),
                    spec.target,
                    validation,
                    opta_buchi::write_validation_status_to_opcua_status(validation),
                    self.write_queue.len(),
                );
            }
        };
        let validation = validate_write_raw_value(spec, raw_value);
        if validation != WriteValidationStatus::Ok {
            return DataAccessWriteResult::rejected(
                Some(node_id),
                spec.target,
                validation,
                opta_buchi::write_validation_status_to_opcua_status(validation),
                self.write_queue.len(),
            );
        }

        let sequence = self.next_write_sequence;
        let push = self.write_queue.push(WriteRequest {
            target: spec.target,
            raw_value,
            node_id,
            sequence,
        });
        if !push.accepted {
            self.record_buchi_write_target(node_id, 0, opcua_status::BAD_RESOURCE_UNAVAILABLE);
            self.health.buchi_write_queue_full_count =
                self.health.buchi_write_queue_full_count.saturating_add(1);
            return DataAccessWriteResult::rejected(
                Some(node_id),
                spec.target,
                WriteValidationStatus::Ok,
                opcua_status::BAD_RESOURCE_UNAVAILABLE,
                push.depth,
            );
        }
        self.next_write_sequence = self.next_write_sequence.wrapping_add(1);
        self.record_buchi_write_target(node_id, 0, opcua_status::GOOD_COMPLETES_ASYNCHRONOUSLY);
        self.health.buchi_write_accepted_count =
            self.health.buchi_write_accepted_count.saturating_add(1);
        DataAccessWriteResult {
            node_id: Some(node_id),
            target: spec.target,
            validation: WriteValidationStatus::Ok,
            opcua_status: opta_buchi::write_validation_status_to_opcua_status(
                WriteValidationStatus::Ok,
            ),
            accepted: true,
            coalesced: push.coalesced,
            depth: push.depth,
            sequence: Some(sequence),
        }
    }
}

impl<const WRITE_CAPACITY: usize> Default for RuntimeDataAccess<WRITE_CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod counter_tests {
    use super::RuntimeDataAccess;
    use crate::RuntimeNode;
    use opta_gateway_contracts::{config::TrustState, freshness::ScalarValue, opcua_status};

    #[test]
    fn accelerated_write_sequences_wrap_and_health_counts_saturate() {
        for seed in [u32::MAX - 2, u32::MAX - 1, u32::MAX] {
            let mut data = RuntimeDataAccess::<1>::new();
            data.set_trust_state(TrustState::Verified);
            data.set_write_enabled(true);
            data.next_write_sequence = seed;
            data.health.buchi_write_accepted_count = seed;
            data.health.buchi_write_completed_count = seed;
            data.health.buchi_write_failed_count = seed;
            for operation in 0..5u64 {
                let accepted = data.enqueue_write_node(
                    RuntimeNode::ProcessHeatingSet,
                    ScalarValue::FloatMilli(42_000),
                );
                assert!(accepted.accepted);
                assert_eq!(
                    accepted.sequence,
                    Some(((u64::from(seed) + operation) % 4_294_967_296) as u32)
                );
                let request = data.pop_write_request().unwrap();
                assert_eq!(Some(request.sequence), accepted.sequence);
                data.record_buchi_write_result(request.node_id, 200, opcua_status::GOOD);
                data.record_buchi_write_result(
                    request.node_id,
                    503,
                    opcua_status::BAD_NOT_CONNECTED,
                );
                let expected = (u64::from(seed) + operation + 1).min(u64::from(u32::MAX)) as u32;
                assert_eq!(data.health.buchi_write_accepted_count, expected);
                assert_eq!(data.health.buchi_write_completed_count, expected);
                assert_eq!(data.health.buchi_write_failed_count, expected);
                assert_eq!(data.write_queue_depth(), 0);
            }
        }
    }
}
