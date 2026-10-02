use super::product;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointClass {
    Process,
    Settings,
    Info,
    Health,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueKind {
    Boolean,
    Int32,
    Float,
    UInt32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    ReadOnly,
    WritableNumericBoolean,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeContract {
    pub node_id: u16,
    pub browse_name: &'static str,
    pub endpoint: EndpointClass,
    pub value_kind: ValueKind,
    pub access: Access,
}

pub const HEALTH_LAST_FAULT_PRESENT_NODE_ID: u16 = 4028;
pub const HEALTH_LAST_FAULT_REASON_NODE_ID: u16 = 4029;
pub const HEALTH_LAST_FAULT_SEQUENCE_NODE_ID: u16 = 4030;
pub const HEALTH_LAST_FAULT_UPTIME_SECONDS_NODE_ID: u16 = 4031;
pub const HEALTH_LAST_FAULT_DETAIL_NODE_ID: u16 = 4032;
pub const HEALTH_LAST_FAULT_RESET_FLAGS_NODE_ID: u16 = 4033;

pub const WRITABLE_NODES: &[NodeContract] = &[
    NodeContract::writable(
        2001,
        "Process.Heating.Set",
        EndpointClass::Process,
        ValueKind::Float,
    ),
    NodeContract::writable(
        2003,
        "Process.Heating.Running",
        EndpointClass::Process,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        2004,
        "Process.Cooling.Set",
        EndpointClass::Process,
        ValueKind::Float,
    ),
    NodeContract::writable(
        2006,
        "Process.Cooling.Running",
        EndpointClass::Process,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        2007,
        "Process.Vacuum.Set",
        EndpointClass::Process,
        ValueKind::Float,
    ),
    NodeContract::writable(
        2009,
        "Process.Vacuum.AerateValveOpen",
        EndpointClass::Process,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        2010,
        "Process.Vacuum.AerateValvePulse",
        EndpointClass::Process,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        2017,
        "Process.Rotation.Set",
        EndpointClass::Process,
        ValueKind::Float,
    ),
    NodeContract::writable(
        2019,
        "Process.Rotation.Running",
        EndpointClass::Process,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        2020,
        "Process.Lift.Set",
        EndpointClass::Process,
        ValueKind::Float,
    ),
    NodeContract::writable(
        2030,
        "Process.GlobalStatus.Running",
        EndpointClass::Process,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3001,
        "Settings.Vacuum.MaxPermPressureMbar",
        EndpointClass::Settings,
        ValueKind::Float,
    ),
    NodeContract::writable(
        3004,
        "Settings.Rotation.StartRotationOnStart",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3005,
        "Settings.Vacuum.PressureHysteresisMbar",
        EndpointClass::Settings,
        ValueKind::Float,
    ),
    NodeContract::writable(
        3006,
        "Settings.Vacuum.AltitudeMeters",
        EndpointClass::Settings,
        ValueKind::Float,
    ),
    NodeContract::writable(
        3007,
        "Settings.Vacuum.MaxPumpOutputPercent",
        EndpointClass::Settings,
        ValueKind::Int32,
    ),
    NodeContract::writable(
        3008,
        "Settings.Vacuum.VentOnFinish",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3009,
        "Settings.Rotation.StopRotationOnFinish",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3010,
        "Settings.Heating.StopHeatingOnFinish",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3011,
        "Settings.Cooling.StopCoolingOnFinish",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3012,
        "Settings.Lift.ImmerseOnStart",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3013,
        "Settings.Lift.LiftOutFlaskOnFinish",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3014,
        "Settings.Program.Eco.Enabled",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3015,
        "Settings.Program.Eco.ActivationAfterMins",
        EndpointClass::Settings,
        ValueKind::Int32,
    ),
    NodeContract::writable(
        3016,
        "Settings.Program.Eco.HeatingBathTemperatureC",
        EndpointClass::Settings,
        ValueKind::Float,
    ),
    NodeContract::writable(
        3017,
        "Settings.Program.Eco.CoolantTemperatureC",
        EndpointClass::Settings,
        ValueKind::Float,
    ),
    NodeContract::writable(
        3018,
        "Settings.Display.BrightnessPercent",
        EndpointClass::Settings,
        ValueKind::Int32,
    ),
    NodeContract::writable(
        3019,
        "Settings.Display.UtcOffsetMinutes",
        EndpointClass::Settings,
        ValueKind::Int32,
    ),
    NodeContract::writable(
        3020,
        "Settings.Sounds.ButtonTone",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
    NodeContract::writable(
        3021,
        "Settings.Sounds.PlaySoundOnFinish",
        EndpointClass::Settings,
        ValueKind::Boolean,
    ),
];

pub const HEALTH_NODES: &[NodeContract] = &[
    NodeContract::readonly(
        4001,
        "Health.BuchiCompletedFetchCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4002,
        "Health.BuchiFailedFetchCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4003,
        "Health.MbedtlsCurrentBytes",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4004,
        "Health.MbedtlsPeakBytes",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4005,
        "Health.OpcUaTransportDrops",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4006,
        "Health.BuchiRejectedRequestCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4007,
        "Health.HeapAllocFailCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4008,
        "Health.MbedtlsFailedAllocCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4009,
        "Health.OpcUaCloseQueueFullCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4010,
        "Health.LoopMaxGapMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4011,
        "Health.HeartbeatMaxGapMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4012,
        "Health.LateHeartbeatCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4013,
        "Health.BuchiStatusFlags",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4014,
        "Health.BuchiWriteQueueDepth",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4015,
        "Health.BuchiWriteAcceptedCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4016,
        "Health.BuchiWriteCompletedCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4017,
        "Health.BuchiWriteFailedCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4018,
        "Health.BuchiWriteQueueFullCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4019,
        "Health.BuchiWriteLastTargetNodeId",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4020,
        "Health.BuchiWriteLastHttpStatus",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4021,
        "Health.BuchiWriteLastOpcUaStatus",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4022,
        "Health.UptimeSeconds",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4023,
        "Health.IwdgLastKickAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4024,
        "Health.WatchdogStaleMask",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4025,
        "Health.TaskCheckinRegisteredMask",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4026,
        "Health.TaskCheckinFreshMask",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4027,
        "Health.TaskCheckinDeadlineMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        HEALTH_LAST_FAULT_PRESENT_NODE_ID,
        "Health.LastFaultPresent",
        EndpointClass::Health,
        ValueKind::Boolean,
    ),
    NodeContract::readonly(
        HEALTH_LAST_FAULT_REASON_NODE_ID,
        "Health.LastFaultReason",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        HEALTH_LAST_FAULT_SEQUENCE_NODE_ID,
        "Health.LastFaultSequence",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        HEALTH_LAST_FAULT_UPTIME_SECONDS_NODE_ID,
        "Health.LastFaultUptimeSeconds",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        HEALTH_LAST_FAULT_DETAIL_NODE_ID,
        "Health.LastFaultDetail",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        HEALTH_LAST_FAULT_RESET_FLAGS_NODE_ID,
        "Health.LastFaultResetFlags",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4034,
        "Health.ResetFlags",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4035,
        "Health.WatchdogBiteCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4036,
        "Health.TaskCheckin.MainHeartbeatAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4038,
        "Health.TaskCheckin.MdnsResponderAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4039,
        "Health.TaskCheckin.NetStatusAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4040,
        "Health.TaskCheckin.UsbConsoleAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4041,
        "Health.TaskCheckin.BuchiTlsClientAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4042,
        "Health.TaskCheckin.OpcUaServerAgeMs",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4043,
        "Health.BuchiTrustState",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4044,
        "Health.BuchiTrustAnchorPresent",
        EndpointClass::Health,
        ValueKind::Boolean,
    ),
    NodeContract::readonly(
        4045,
        "Health.BuchiTrustRtcUsable",
        EndpointClass::Health,
        ValueKind::Boolean,
    ),
    NodeContract::readonly(
        4046,
        "Health.BuchiTrustLastVerifyError",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4047,
        "Health.BuchiTrustVerifyAttemptCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4048,
        "Health.BuchiTrustVerifiedSessionCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4049,
        "Health.BuchiTrustRevocationCount",
        EndpointClass::Health,
        ValueKind::UInt32,
    ),
    NodeContract::readonly(
        4050,
        "Health.BuchiVerifierTimeTrusted",
        EndpointClass::Health,
        ValueKind::Boolean,
    ),
];

impl NodeContract {
    pub const fn readonly(
        node_id: u16,
        browse_name: &'static str,
        endpoint: EndpointClass,
        value_kind: ValueKind,
    ) -> Self {
        Self {
            node_id,
            browse_name,
            endpoint,
            value_kind,
            access: Access::ReadOnly,
        }
    }

    pub const fn writable(
        node_id: u16,
        browse_name: &'static str,
        endpoint: EndpointClass,
        value_kind: ValueKind,
    ) -> Self {
        Self {
            node_id,
            browse_name,
            endpoint,
            value_kind,
            access: Access::WritableNumericBoolean,
        }
    }
}

pub fn lookup_writable_node(node_id: u16) -> Option<&'static NodeContract> {
    WRITABLE_NODES.iter().find(|node| node.node_id == node_id)
}

pub fn lookup_health_node(node_id: u16) -> Option<&'static NodeContract> {
    HEALTH_NODES.iter().find(|node| node.node_id == node_id)
}

pub fn is_default_writable_node(node_id: u16) -> bool {
    lookup_writable_node(node_id).is_some()
}

pub fn is_default_health_node(node_id: u16) -> bool {
    lookup_health_node(node_id).is_some()
}

pub const fn max_write_queue_capacity() -> usize {
    product::BUCHI_WRITE_QUEUE_CAPACITY
}
