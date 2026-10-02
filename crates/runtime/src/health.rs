use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::last_fault::LastFaultRecord;
use opta_gateway_contracts::namespace::{self, ValueKind};

pub mod buchi_status_flags {
    /// Matches current-product `BuchiStatusFlags::kBuchiStatusConfigured`.
    pub const CONFIGURED: u32 = 1 << 0;
    /// Matches current-product `BuchiStatusFlags::kBuchiStatusNetworkReady`.
    pub const NETWORK_READY: u32 = 1 << 1;
    /// Matches current-product `BuchiStatusFlags::kBuchiStatusLastFetchOk`.
    pub const LAST_FETCH_OK: u32 = 1 << 2;
    /// Matches current-product `BuchiStatusFlags::kBuchiStatusBodyTruncated`.
    pub const BODY_TRUNCATED: u32 = 1 << 3;
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthNode {
    BuchiCompletedFetchCount = 4001,
    BuchiFailedFetchCount = 4002,
    MbedtlsCurrentBytes = 4003,
    MbedtlsPeakBytes = 4004,
    OpcUaTransportDrops = 4005,
    BuchiRejectedRequestCount = 4006,
    HeapAllocFailCount = 4007,
    MbedtlsFailedAllocCount = 4008,
    OpcUaCloseQueueFullCount = 4009,
    LoopMaxGapMs = 4010,
    HeartbeatMaxGapMs = 4011,
    LateHeartbeatCount = 4012,
    BuchiStatusFlags = 4013,
    BuchiWriteQueueDepth = 4014,
    BuchiWriteAcceptedCount = 4015,
    BuchiWriteCompletedCount = 4016,
    BuchiWriteFailedCount = 4017,
    BuchiWriteQueueFullCount = 4018,
    BuchiWriteLastTargetNodeId = 4019,
    BuchiWriteLastHttpStatus = 4020,
    BuchiWriteLastOpcUaStatus = 4021,
    UptimeSeconds = 4022,
    IwdgLastKickAgeMs = 4023,
    WatchdogStaleMask = 4024,
    TaskCheckinRegisteredMask = 4025,
    TaskCheckinFreshMask = 4026,
    TaskCheckinDeadlineMs = 4027,
    LastFaultPresent = 4028,
    LastFaultReason = 4029,
    LastFaultSequence = 4030,
    LastFaultUptimeSeconds = 4031,
    LastFaultDetail = 4032,
    LastFaultResetFlags = 4033,
    ResetFlags = 4034,
    WatchdogBiteCount = 4035,
    TaskCheckinMainHeartbeatAgeMs = 4036,
    TaskCheckinMdnsResponderAgeMs = 4038,
    TaskCheckinNetStatusAgeMs = 4039,
    TaskCheckinUsbConsoleAgeMs = 4040,
    TaskCheckinBuchiTlsClientAgeMs = 4041,
    TaskCheckinOpcUaServerAgeMs = 4042,
    BuchiTrustState = 4043,
    BuchiTrustAnchorPresent = 4044,
    BuchiTrustRtcUsable = 4045,
    BuchiTrustLastVerifyError = 4046,
    BuchiTrustVerifyAttemptCount = 4047,
    BuchiTrustVerifiedSessionCount = 4048,
    BuchiTrustRevocationCount = 4049,
    BuchiVerifierTimeTrusted = 4050,
}
impl HealthNode {
    pub const fn node_id(self) -> u16 {
        self as u16
    }

    pub const fn from_node_id(node_id: u16) -> Option<Self> {
        match node_id {
            4001 => Some(Self::BuchiCompletedFetchCount),
            4002 => Some(Self::BuchiFailedFetchCount),
            4003 => Some(Self::MbedtlsCurrentBytes),
            4004 => Some(Self::MbedtlsPeakBytes),
            4005 => Some(Self::OpcUaTransportDrops),
            4006 => Some(Self::BuchiRejectedRequestCount),
            4007 => Some(Self::HeapAllocFailCount),
            4008 => Some(Self::MbedtlsFailedAllocCount),
            4009 => Some(Self::OpcUaCloseQueueFullCount),
            4010 => Some(Self::LoopMaxGapMs),
            4011 => Some(Self::HeartbeatMaxGapMs),
            4012 => Some(Self::LateHeartbeatCount),
            4013 => Some(Self::BuchiStatusFlags),
            4014 => Some(Self::BuchiWriteQueueDepth),
            4015 => Some(Self::BuchiWriteAcceptedCount),
            4016 => Some(Self::BuchiWriteCompletedCount),
            4017 => Some(Self::BuchiWriteFailedCount),
            4018 => Some(Self::BuchiWriteQueueFullCount),
            4019 => Some(Self::BuchiWriteLastTargetNodeId),
            4020 => Some(Self::BuchiWriteLastHttpStatus),
            4021 => Some(Self::BuchiWriteLastOpcUaStatus),
            4022 => Some(Self::UptimeSeconds),
            4023 => Some(Self::IwdgLastKickAgeMs),
            4024 => Some(Self::WatchdogStaleMask),
            4025 => Some(Self::TaskCheckinRegisteredMask),
            4026 => Some(Self::TaskCheckinFreshMask),
            4027 => Some(Self::TaskCheckinDeadlineMs),
            4028 => Some(Self::LastFaultPresent),
            4029 => Some(Self::LastFaultReason),
            4030 => Some(Self::LastFaultSequence),
            4031 => Some(Self::LastFaultUptimeSeconds),
            4032 => Some(Self::LastFaultDetail),
            4033 => Some(Self::LastFaultResetFlags),
            4034 => Some(Self::ResetFlags),
            4035 => Some(Self::WatchdogBiteCount),
            4036 => Some(Self::TaskCheckinMainHeartbeatAgeMs),
            4038 => Some(Self::TaskCheckinMdnsResponderAgeMs),
            4039 => Some(Self::TaskCheckinNetStatusAgeMs),
            4040 => Some(Self::TaskCheckinUsbConsoleAgeMs),
            4041 => Some(Self::TaskCheckinBuchiTlsClientAgeMs),
            4042 => Some(Self::TaskCheckinOpcUaServerAgeMs),
            4043 => Some(Self::BuchiTrustState),
            4044 => Some(Self::BuchiTrustAnchorPresent),
            4045 => Some(Self::BuchiTrustRtcUsable),
            4046 => Some(Self::BuchiTrustLastVerifyError),
            4047 => Some(Self::BuchiTrustVerifyAttemptCount),
            4048 => Some(Self::BuchiTrustVerifiedSessionCount),
            4049 => Some(Self::BuchiTrustRevocationCount),
            4050 => Some(Self::BuchiVerifierTimeTrusted),
            _ => None,
        }
    }
    pub fn contract(self) -> Option<&'static namespace::NodeContract> {
        namespace::lookup_health_node(self.node_id())
    }
}

pub const SINGLE_CORE_TASK_HEALTH_SLOT_COUNT: usize = 6;

pub const RUNTIME_HEALTH_NODE_COUNT: usize = 49;
pub const RUNTIME_HEALTH_NODES: [HealthNode; RUNTIME_HEALTH_NODE_COUNT] = [
    HealthNode::BuchiCompletedFetchCount,
    HealthNode::BuchiFailedFetchCount,
    HealthNode::MbedtlsCurrentBytes,
    HealthNode::MbedtlsPeakBytes,
    HealthNode::OpcUaTransportDrops,
    HealthNode::BuchiRejectedRequestCount,
    HealthNode::HeapAllocFailCount,
    HealthNode::MbedtlsFailedAllocCount,
    HealthNode::OpcUaCloseQueueFullCount,
    HealthNode::LoopMaxGapMs,
    HealthNode::HeartbeatMaxGapMs,
    HealthNode::LateHeartbeatCount,
    HealthNode::BuchiStatusFlags,
    HealthNode::BuchiWriteQueueDepth,
    HealthNode::BuchiWriteAcceptedCount,
    HealthNode::BuchiWriteCompletedCount,
    HealthNode::BuchiWriteFailedCount,
    HealthNode::BuchiWriteQueueFullCount,
    HealthNode::BuchiWriteLastTargetNodeId,
    HealthNode::BuchiWriteLastHttpStatus,
    HealthNode::BuchiWriteLastOpcUaStatus,
    HealthNode::UptimeSeconds,
    HealthNode::IwdgLastKickAgeMs,
    HealthNode::WatchdogStaleMask,
    HealthNode::TaskCheckinRegisteredMask,
    HealthNode::TaskCheckinFreshMask,
    HealthNode::TaskCheckinDeadlineMs,
    HealthNode::LastFaultPresent,
    HealthNode::LastFaultReason,
    HealthNode::LastFaultSequence,
    HealthNode::LastFaultUptimeSeconds,
    HealthNode::LastFaultDetail,
    HealthNode::LastFaultResetFlags,
    HealthNode::ResetFlags,
    HealthNode::WatchdogBiteCount,
    HealthNode::TaskCheckinMainHeartbeatAgeMs,
    HealthNode::TaskCheckinMdnsResponderAgeMs,
    HealthNode::TaskCheckinNetStatusAgeMs,
    HealthNode::TaskCheckinUsbConsoleAgeMs,
    HealthNode::TaskCheckinBuchiTlsClientAgeMs,
    HealthNode::TaskCheckinOpcUaServerAgeMs,
    HealthNode::BuchiTrustState,
    HealthNode::BuchiTrustAnchorPresent,
    HealthNode::BuchiTrustRtcUsable,
    HealthNode::BuchiTrustLastVerifyError,
    HealthNode::BuchiTrustVerifyAttemptCount,
    HealthNode::BuchiTrustVerifiedSessionCount,
    HealthNode::BuchiTrustRevocationCount,
    HealthNode::BuchiVerifierTimeTrusted,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SingleCoreHealthSnapshot {
    pub uptime_seconds: u32,
    pub iwdg_last_kick_age_ms: Option<u32>,
    pub watchdog_stale_mask: u32,
    pub task_checkin_registered_mask: u32,
    pub task_checkin_fresh_mask: u32,
    pub task_checkin_deadline_ms: u32,
    pub task_checkin_age_ms: [Option<u32>; SINGLE_CORE_TASK_HEALTH_SLOT_COUNT],
}

impl SingleCoreHealthSnapshot {
    pub const fn new(
        uptime_seconds: u32,
        iwdg_last_kick_age_ms: Option<u32>,
        watchdog_stale_mask: u32,
        task_checkin_registered_mask: u32,
        task_checkin_fresh_mask: u32,
        task_checkin_deadline_ms: u32,
        task_checkin_age_ms: [Option<u32>; SINGLE_CORE_TASK_HEALTH_SLOT_COUNT],
    ) -> Self {
        Self {
            uptime_seconds,
            iwdg_last_kick_age_ms,
            watchdog_stale_mask,
            task_checkin_registered_mask,
            task_checkin_fresh_mask,
            task_checkin_deadline_ms,
            task_checkin_age_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHealthState {
    pub buchi_configured: bool,
    pub buchi_network_ready: bool,
    pub buchi_body_truncated: bool,
    /// Compatibility placeholder: always zero in the allocator-free Rust
    /// product. The stable node ID/name is retained for existing clients.
    pub mbedtls_current_bytes: u32,
    /// Compatibility placeholder: always zero in the allocator-free Rust
    /// product. The stable node ID/name is retained for existing clients.
    pub mbedtls_peak_bytes: u32,
    pub opcua_transport_drops: u32,
    pub buchi_rejected_request_count: u32,
    /// Compatibility placeholder: always zero in the allocator-free Rust
    /// product. The stable node ID/name is retained for existing clients.
    pub heap_alloc_fail_count: u32,
    /// Compatibility placeholder: always zero in the allocator-free Rust
    /// product. The stable node ID/name is retained for existing clients.
    pub mbedtls_failed_alloc_count: u32,
    pub opcua_close_queue_full_count: u32,
    pub loop_max_gap_ms: u32,
    pub heartbeat_max_gap_ms: u32,
    pub late_heartbeat_count: u32,
    pub loop_timing_measured: bool,
    pub buchi_write_accepted_count: u32,
    pub buchi_write_completed_count: u32,
    pub buchi_write_failed_count: u32,
    pub buchi_write_queue_full_count: u32,
    pub buchi_write_last_target_node_id: u32,
    pub buchi_write_last_http_status: u32,
    pub buchi_write_last_opcua_status: u32,
    pub single_core: Option<SingleCoreHealthSnapshot>,
    pub last_fault: Option<LastFaultRecord>,
    pub reset_flags: u32,
    /// Compatibility node initialized to zero. The product does not yet
    /// implement a cumulative retained watchdog-bite counter.
    pub watchdog_bite_count: u32,
    pub buchi_trust_state: TrustState,
    pub buchi_trust_anchor_present: bool,
    pub buchi_trust_rtc_usable: bool,
    pub buchi_trust_last_verify_error: u32,
    pub buchi_trust_verify_attempt_count: u32,
    pub buchi_trust_verified_session_count: u32,
    pub buchi_trust_revocation_count: u32,
    pub buchi_verifier_time_trusted: bool,
}
impl RuntimeHealthState {
    pub const fn new() -> Self {
        Self {
            buchi_configured: false,
            buchi_network_ready: false,
            buchi_body_truncated: false,
            mbedtls_current_bytes: 0,
            mbedtls_peak_bytes: 0,
            opcua_transport_drops: 0,
            buchi_rejected_request_count: 0,
            heap_alloc_fail_count: 0,
            mbedtls_failed_alloc_count: 0,
            opcua_close_queue_full_count: 0,
            loop_max_gap_ms: 0,
            heartbeat_max_gap_ms: 0,
            late_heartbeat_count: 0,
            loop_timing_measured: false,
            buchi_write_accepted_count: 0,
            buchi_write_completed_count: 0,
            buchi_write_failed_count: 0,
            buchi_write_queue_full_count: 0,
            buchi_write_last_target_node_id: 0,
            buchi_write_last_http_status: 0,
            buchi_write_last_opcua_status: 0,
            single_core: None,
            last_fault: None,
            reset_flags: 0,
            watchdog_bite_count: 0,
            buchi_trust_state: TrustState::Missing,
            buchi_trust_anchor_present: false,
            buchi_trust_rtc_usable: false,
            buchi_trust_last_verify_error: 0,
            buchi_trust_verify_attempt_count: 0,
            buchi_trust_verified_session_count: 0,
            buchi_trust_revocation_count: 0,
            buchi_verifier_time_trusted: false,
        }
    }
    pub const fn buchi_status_flags(self, last_fetch_ok: bool) -> u32 {
        let mut flags = 0;
        if self.buchi_configured {
            flags |= buchi_status_flags::CONFIGURED;
        }
        if self.buchi_network_ready {
            flags |= buchi_status_flags::NETWORK_READY;
        }
        if last_fetch_ok {
            flags |= buchi_status_flags::LAST_FETCH_OK;
        }
        if self.buchi_body_truncated {
            flags |= buchi_status_flags::BODY_TRUNCATED;
        }
        flags
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuchiTrustHealthSnapshot {
    pub state: TrustState,
    pub anchor_present: bool,
    pub rtc_usable: bool,
    pub last_verify_error: u32,
    pub verify_attempt_count: u32,
    pub verified_session_count: u32,
    pub revocation_count: u32,
}

impl Default for RuntimeHealthState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthRead {
    pub node: Option<HealthNode>,
    pub node_id: u16,
    pub browse_name: Option<&'static str>,
    pub value_kind: Option<ValueKind>,
    pub opcua_status: u32,
    pub value: Option<ScalarValue>,
}
