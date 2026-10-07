#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Allocation-free runtime state plane between Büchi transactions and OPC UA.
//!
//! Parsed endpoint samples enter fixed caches with per-endpoint freshness;
//! omitted owned fields are invalidated instead of remaining stale-Good. The
//! same state plane enforces bounded write dispatch, trust/write gates, Health
//! telemetry, and the compile-time namespace mapping.

use opta_buchi::{
    BuchiPutTransactionError, BuildWriteJsonError, Endpoint, WriteRequest, WriteTarget,
    WriteValidationStatus,
};
use opta_gateway_contracts::freshness::{CacheReadStatus, ScalarValue};
use opta_gateway_contracts::namespace::{Access, ValueKind};
use opta_gateway_contracts::product;

mod node_contracts;
pub use node_contracts::{
    runtime_node_contract_by_index, runtime_node_contracts, RuntimeNode, RuntimeNodeContract,
    INFO_NODE_COUNT, INFO_NODE_OFFSET, NODE_COUNT, PROCESS_NODE_COUNT, RUNTIME_NODE_CONTRACTS,
    SETTINGS_NODE_COUNT, SETTINGS_NODE_OFFSET,
};

mod poll_schedule;
pub use poll_schedule::{
    EndpointDueSet, EndpointPollScheduler, POLL_ENDPOINTS, POLL_ENDPOINT_COUNT,
};

mod attachments;
pub(crate) use attachments::SubsystemAttachments;
pub use attachments::{AttachmentState, Subsystem, ATTACHMENT_HYSTERESIS_POLLS, SUBSYSTEM_COUNT};
mod health;
pub use health::{
    buchi_status_flags, BuchiTrustHealthSnapshot, HealthNode, HealthRead, RuntimeHealthState,
    SingleCoreHealthSnapshot, RUNTIME_HEALTH_NODES, RUNTIME_HEALTH_NODE_COUNT,
    SINGLE_CORE_TASK_HEALTH_SLOT_COUNT,
};
mod loop_timing;
pub use loop_timing::{LoopTimingMonitor, LoopTimingSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataAccessRead {
    pub node: Option<RuntimeNode>,
    pub browse_name: Option<&'static str>,
    pub value_kind: Option<ValueKind>,
    pub access: Option<Access>,
    pub cache_status: CacheReadStatus,
    pub opcua_status: u32,
    pub value: Option<ScalarValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceTarget {
    Runtime(RuntimeNode),
    Health(HealthNode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceNode {
    pub node_id: u16,
    pub browse_name: &'static str,
    pub value_kind: ValueKind,
    pub access: Access,
    pub target: NamespaceTarget,
}

const fn runtime_namespace_node(
    node_id: u16,
    browse_name: &'static str,
    node: RuntimeNode,
) -> NamespaceNode {
    let contract = RUNTIME_NODE_CONTRACTS[node.index()];
    NamespaceNode {
        node_id,
        browse_name,
        value_kind: contract.value_kind,
        access: contract.access(),
        target: NamespaceTarget::Runtime(node),
    }
}

const fn health_namespace_node(
    node_id: u16,
    browse_name: &'static str,
    value_kind: ValueKind,
    node: HealthNode,
) -> NamespaceNode {
    NamespaceNode {
        node_id,
        browse_name,
        value_kind,
        access: Access::ReadOnly,
        target: NamespaceTarget::Health(node),
    }
}

pub const DEFAULT_NAMESPACE_NODE_COUNT: usize = 134;

pub const DEFAULT_NAMESPACE_NODES: [NamespaceNode; DEFAULT_NAMESPACE_NODE_COUNT] = [
    runtime_namespace_node(
        1001,
        "Info.Controller.OperatingTimeHours",
        RuntimeNode::InfoControllerOperatingTimeHours,
    ),
    runtime_namespace_node(
        1002,
        "Info.Rotavapor.OperatingTimeHours",
        RuntimeNode::InfoRotavaporOperatingTimeHours,
    ),
    runtime_namespace_node(
        1003,
        "Info.Rotavapor.RotationHours",
        RuntimeNode::InfoRotavaporRotationHours,
    ),
    runtime_namespace_node(
        1004,
        "Info.Controller.RunCounters.TotalRuns",
        RuntimeNode::InfoControllerRunTotalRuns,
    ),
    runtime_namespace_node(
        1005,
        "Info.Controller.RunCounters.Manual",
        RuntimeNode::InfoControllerRunManual,
    ),
    runtime_namespace_node(
        1006,
        "Info.Controller.RunCounters.Timer",
        RuntimeNode::InfoControllerRunTimer,
    ),
    runtime_namespace_node(
        1007,
        "Info.Controller.RunCounters.Continuous",
        RuntimeNode::InfoControllerRunContinuous,
    ),
    runtime_namespace_node(
        1008,
        "Info.Controller.RunCounters.Solvent",
        RuntimeNode::InfoControllerRunSolvent,
    ),
    runtime_namespace_node(
        1009,
        "Info.Controller.RunCounters.Method",
        RuntimeNode::InfoControllerRunMethod,
    ),
    runtime_namespace_node(
        1010,
        "Info.Controller.RunCounters.AutoDest",
        RuntimeNode::InfoControllerRunAutoDest,
    ),
    runtime_namespace_node(
        1011,
        "Info.Controller.RunCounters.CloudDest",
        RuntimeNode::InfoControllerRunCloudDest,
    ),
    runtime_namespace_node(
        1012,
        "Info.Controller.RunCounters.Drying",
        RuntimeNode::InfoControllerRunDrying,
    ),
    runtime_namespace_node(
        1013,
        "Info.Controller.RunCounters.LeakTest",
        RuntimeNode::InfoControllerRunLeakTest,
    ),
    runtime_namespace_node(
        1014,
        "Info.Controller.RunCounters.Calibration",
        RuntimeNode::InfoControllerRunCalibration,
    ),
    runtime_namespace_node(
        1015,
        "Info.Bath.OperatingTimeHours",
        RuntimeNode::InfoBathOperatingTimeHours,
    ),
    runtime_namespace_node(
        1016,
        "Info.Bath.HoursOver190C",
        RuntimeNode::InfoBathHoursOver190c,
    ),
    runtime_namespace_node(
        1017,
        "Info.Chiller.OperatingTimeHours",
        RuntimeNode::InfoChillerOperatingTimeHours,
    ),
    runtime_namespace_node(
        1018,
        "Info.Chiller.PumpHours",
        RuntimeNode::InfoChillerPumpHours,
    ),
    runtime_namespace_node(
        1019,
        "Info.Chiller.CompressorHours",
        RuntimeNode::InfoChillerCompressorHours,
    ),
    runtime_namespace_node(
        1020,
        "Info.Chiller.ValveCounter",
        RuntimeNode::InfoChillerValveCounter,
    ),
    runtime_namespace_node(
        1021,
        "Info.Rotavapor.LiftMoves",
        RuntimeNode::InfoRotavaporLiftMoves,
    ),
    runtime_namespace_node(
        1022,
        "Info.Pump.OperatingTimeHours",
        RuntimeNode::InfoPumpOperatingTimeHours,
    ),
    runtime_namespace_node(
        1023,
        "Info.Pump.Module1.SwitchOn",
        RuntimeNode::InfoPumpModule1SwitchOn,
    ),
    runtime_namespace_node(
        1024,
        "Info.Pump.Module1.OverCurrentCount",
        RuntimeNode::InfoPumpModule1OverCurrent,
    ),
    runtime_namespace_node(
        1025,
        "Info.Pump.Module1.MaxCurrentAmps",
        RuntimeNode::InfoPumpModule1MaxCurrent,
    ),
    runtime_namespace_node(
        1026,
        "Info.Pump.Module1.MaxTemperatureC",
        RuntimeNode::InfoPumpModule1MaxTemperature,
    ),
    runtime_namespace_node(
        1027,
        "Info.Pump.Module2.SwitchOn",
        RuntimeNode::InfoPumpModule2SwitchOn,
    ),
    runtime_namespace_node(
        1028,
        "Info.Pump.Module2.OverCurrentCount",
        RuntimeNode::InfoPumpModule2OverCurrent,
    ),
    runtime_namespace_node(
        1029,
        "Info.Pump.Module2.MaxCurrentAmps",
        RuntimeNode::InfoPumpModule2MaxCurrent,
    ),
    runtime_namespace_node(
        1030,
        "Info.Pump.Module2.MaxTemperatureC",
        RuntimeNode::InfoPumpModule2MaxTemperature,
    ),
    runtime_namespace_node(
        1031,
        "Info.Vacubox.OperatingTimeHours",
        RuntimeNode::InfoVacuboxOperatingTimeHours,
    ),
    runtime_namespace_node(1032, "Info.Bath.Attached", RuntimeNode::InfoBathAttached),
    runtime_namespace_node(
        1033,
        "Info.Chiller.Attached",
        RuntimeNode::InfoChillerAttached,
    ),
    runtime_namespace_node(
        1034,
        "Info.Rotavapor.Attached",
        RuntimeNode::InfoRotavaporAttached,
    ),
    runtime_namespace_node(1035, "Info.Pump.Attached", RuntimeNode::InfoPumpAttached),
    runtime_namespace_node(
        1036,
        "Info.Vacubox.Attached",
        RuntimeNode::InfoVacuboxAttached,
    ),
    runtime_namespace_node(2001, "Process.Heating.Set", RuntimeNode::ProcessHeatingSet),
    runtime_namespace_node(
        2002,
        "Process.Heating.ActualTemperatureC",
        RuntimeNode::ProcessBathTemperature,
    ),
    runtime_namespace_node(
        2003,
        "Process.Heating.Running",
        RuntimeNode::ProcessHeatingRunning,
    ),
    runtime_namespace_node(2004, "Process.Cooling.Set", RuntimeNode::ProcessCoolingSet),
    runtime_namespace_node(
        2005,
        "Process.Cooling.ActualTemperatureC",
        RuntimeNode::ProcessCoolingActual,
    ),
    runtime_namespace_node(
        2006,
        "Process.Cooling.Running",
        RuntimeNode::ProcessCoolingRunning,
    ),
    runtime_namespace_node(2007, "Process.Vacuum.Set", RuntimeNode::ProcessVacuumSet),
    runtime_namespace_node(
        2008,
        "Process.Vacuum.ActualPressureMbar",
        RuntimeNode::ProcessPressure,
    ),
    runtime_namespace_node(
        2009,
        "Process.Vacuum.AerateValveOpen",
        RuntimeNode::ProcessVacuumAerateValveOpen,
    ),
    runtime_namespace_node(
        2010,
        "Process.Vacuum.AerateValvePulse",
        RuntimeNode::ProcessVacuumAerateValvePulse,
    ),
    runtime_namespace_node(
        2011,
        "Process.Vacuum.VacuumValveOpen",
        RuntimeNode::ProcessVacuumValveOpen,
    ),
    runtime_namespace_node(
        2012,
        "Process.Vacuum.VaporTemperatureC",
        RuntimeNode::ProcessVacuumVaporTemperature,
    ),
    runtime_namespace_node(
        2013,
        "Process.Vacuum.AutoDestinationInC",
        RuntimeNode::ProcessVacuumAutoDestinationIn,
    ),
    runtime_namespace_node(
        2014,
        "Process.Vacuum.AutoDestinationOutC",
        RuntimeNode::ProcessVacuumAutoDestinationOut,
    ),
    runtime_namespace_node(
        2015,
        "Process.Vacuum.PowerPercentActual",
        RuntimeNode::ProcessVacuumPowerPercent,
    ),
    runtime_namespace_node(
        2016,
        "Process.Vacuum.Running",
        RuntimeNode::ProcessVacuumRunning,
    ),
    runtime_namespace_node(
        2017,
        "Process.Rotation.Set",
        RuntimeNode::ProcessRotationSet,
    ),
    runtime_namespace_node(
        2018,
        "Process.Rotation.ActualSpeedRpm",
        RuntimeNode::ProcessRotationSpeed,
    ),
    runtime_namespace_node(
        2019,
        "Process.Rotation.Running",
        RuntimeNode::ProcessRotationRunning,
    ),
    runtime_namespace_node(2020, "Process.Lift.Set", RuntimeNode::ProcessLiftSet),
    runtime_namespace_node(2021, "Process.Lift.Actual", RuntimeNode::ProcessLiftActual),
    runtime_namespace_node(2022, "Process.Lift.Limit", RuntimeNode::ProcessLiftLimit),
    runtime_namespace_node(
        2025,
        "Process.GlobalStatus.ProcessTimeSeconds",
        RuntimeNode::ProcessGlobalStatusProcessTime,
    ),
    runtime_namespace_node(
        2026,
        "Process.GlobalStatus.RunId",
        RuntimeNode::ProcessGlobalStatusRunId,
    ),
    runtime_namespace_node(
        2027,
        "Process.GlobalStatus.OnHold",
        RuntimeNode::ProcessGlobalStatusOnHold,
    ),
    runtime_namespace_node(
        2028,
        "Process.GlobalStatus.FoamActive",
        RuntimeNode::ProcessGlobalStatusFoamActive,
    ),
    runtime_namespace_node(
        2029,
        "Process.GlobalStatus.CurrentError",
        RuntimeNode::ProcessGlobalStatusCurrentError,
    ),
    runtime_namespace_node(
        2030,
        "Process.GlobalStatus.Running",
        RuntimeNode::ProcessGlobalStatusRunning,
    ),
    runtime_namespace_node(
        3001,
        "Settings.Vacuum.MaxPermPressureMbar",
        RuntimeNode::SettingsVacuumMaxPermPressure,
    ),
    runtime_namespace_node(
        3002,
        "Settings.Heating.MaxTemperatureC",
        RuntimeNode::SettingsHeatingMaxTemperature,
    ),
    runtime_namespace_node(
        3003,
        "Settings.Lift.DepthStopMm",
        RuntimeNode::SettingsLiftDepthStop,
    ),
    runtime_namespace_node(
        3004,
        "Settings.Rotation.StartRotationOnStart",
        RuntimeNode::SettingsRotationStartOnStart,
    ),
    runtime_namespace_node(
        3005,
        "Settings.Vacuum.PressureHysteresisMbar",
        RuntimeNode::SettingsVacuumPressureHysteresis,
    ),
    runtime_namespace_node(
        3006,
        "Settings.Vacuum.AltitudeMeters",
        RuntimeNode::SettingsVacuumAltitude,
    ),
    runtime_namespace_node(
        3007,
        "Settings.Vacuum.MaxPumpOutputPercent",
        RuntimeNode::SettingsVacuumMaxPumpOutput,
    ),
    runtime_namespace_node(
        3008,
        "Settings.Vacuum.VentOnFinish",
        RuntimeNode::SettingsVacuumVentOnFinish,
    ),
    runtime_namespace_node(
        3009,
        "Settings.Rotation.StopRotationOnFinish",
        RuntimeNode::SettingsRotationStopOnFinish,
    ),
    runtime_namespace_node(
        3010,
        "Settings.Heating.StopHeatingOnFinish",
        RuntimeNode::SettingsHeatingStopOnFinish,
    ),
    runtime_namespace_node(
        3011,
        "Settings.Cooling.StopCoolingOnFinish",
        RuntimeNode::SettingsCoolingStopOnFinish,
    ),
    runtime_namespace_node(
        3012,
        "Settings.Lift.ImmerseOnStart",
        RuntimeNode::SettingsLiftImmerseOnStart,
    ),
    runtime_namespace_node(
        3013,
        "Settings.Lift.LiftOutFlaskOnFinish",
        RuntimeNode::SettingsLiftOutFlaskOnFinish,
    ),
    runtime_namespace_node(
        3014,
        "Settings.Program.Eco.Enabled",
        RuntimeNode::SettingsProgramEcoEnabled,
    ),
    runtime_namespace_node(
        3015,
        "Settings.Program.Eco.ActivationAfterMins",
        RuntimeNode::SettingsProgramEcoActivationAfterMins,
    ),
    runtime_namespace_node(
        3016,
        "Settings.Program.Eco.HeatingBathTemperatureC",
        RuntimeNode::SettingsProgramEcoHeatingBathTemperature,
    ),
    runtime_namespace_node(
        3017,
        "Settings.Program.Eco.CoolantTemperatureC",
        RuntimeNode::SettingsProgramEcoCoolantTemperature,
    ),
    runtime_namespace_node(
        3018,
        "Settings.Display.BrightnessPercent",
        RuntimeNode::SettingsDisplayBrightness,
    ),
    runtime_namespace_node(
        3019,
        "Settings.Display.UtcOffsetMinutes",
        RuntimeNode::SettingsDisplayUtcOffset,
    ),
    runtime_namespace_node(
        3020,
        "Settings.Sounds.ButtonTone",
        RuntimeNode::SettingsSoundsButtonTone,
    ),
    runtime_namespace_node(
        3021,
        "Settings.Sounds.PlaySoundOnFinish",
        RuntimeNode::SettingsSoundsPlaySoundOnFinish,
    ),
    health_namespace_node(
        4001,
        "Health.BuchiCompletedFetchCount",
        ValueKind::UInt32,
        HealthNode::BuchiCompletedFetchCount,
    ),
    health_namespace_node(
        4002,
        "Health.BuchiFailedFetchCount",
        ValueKind::UInt32,
        HealthNode::BuchiFailedFetchCount,
    ),
    health_namespace_node(
        4003,
        "Health.MbedtlsCurrentBytes",
        ValueKind::UInt32,
        HealthNode::MbedtlsCurrentBytes,
    ),
    health_namespace_node(
        4004,
        "Health.MbedtlsPeakBytes",
        ValueKind::UInt32,
        HealthNode::MbedtlsPeakBytes,
    ),
    health_namespace_node(
        4005,
        "Health.OpcUaTransportDrops",
        ValueKind::UInt32,
        HealthNode::OpcUaTransportDrops,
    ),
    health_namespace_node(
        4006,
        "Health.BuchiRejectedRequestCount",
        ValueKind::UInt32,
        HealthNode::BuchiRejectedRequestCount,
    ),
    health_namespace_node(
        4007,
        "Health.HeapAllocFailCount",
        ValueKind::UInt32,
        HealthNode::HeapAllocFailCount,
    ),
    health_namespace_node(
        4008,
        "Health.MbedtlsFailedAllocCount",
        ValueKind::UInt32,
        HealthNode::MbedtlsFailedAllocCount,
    ),
    health_namespace_node(
        4009,
        "Health.OpcUaCloseQueueFullCount",
        ValueKind::UInt32,
        HealthNode::OpcUaCloseQueueFullCount,
    ),
    health_namespace_node(
        4010,
        "Health.LoopMaxGapMs",
        ValueKind::UInt32,
        HealthNode::LoopMaxGapMs,
    ),
    health_namespace_node(
        4011,
        "Health.HeartbeatMaxGapMs",
        ValueKind::UInt32,
        HealthNode::HeartbeatMaxGapMs,
    ),
    health_namespace_node(
        4012,
        "Health.LateHeartbeatCount",
        ValueKind::UInt32,
        HealthNode::LateHeartbeatCount,
    ),
    health_namespace_node(
        4013,
        "Health.BuchiStatusFlags",
        ValueKind::UInt32,
        HealthNode::BuchiStatusFlags,
    ),
    health_namespace_node(
        4014,
        "Health.BuchiWriteQueueDepth",
        ValueKind::UInt32,
        HealthNode::BuchiWriteQueueDepth,
    ),
    health_namespace_node(
        4015,
        "Health.BuchiWriteAcceptedCount",
        ValueKind::UInt32,
        HealthNode::BuchiWriteAcceptedCount,
    ),
    health_namespace_node(
        4016,
        "Health.BuchiWriteCompletedCount",
        ValueKind::UInt32,
        HealthNode::BuchiWriteCompletedCount,
    ),
    health_namespace_node(
        4017,
        "Health.BuchiWriteFailedCount",
        ValueKind::UInt32,
        HealthNode::BuchiWriteFailedCount,
    ),
    health_namespace_node(
        4018,
        "Health.BuchiWriteQueueFullCount",
        ValueKind::UInt32,
        HealthNode::BuchiWriteQueueFullCount,
    ),
    health_namespace_node(
        4019,
        "Health.BuchiWriteLastTargetNodeId",
        ValueKind::UInt32,
        HealthNode::BuchiWriteLastTargetNodeId,
    ),
    health_namespace_node(
        4020,
        "Health.BuchiWriteLastHttpStatus",
        ValueKind::UInt32,
        HealthNode::BuchiWriteLastHttpStatus,
    ),
    health_namespace_node(
        4021,
        "Health.BuchiWriteLastOpcUaStatus",
        ValueKind::UInt32,
        HealthNode::BuchiWriteLastOpcUaStatus,
    ),
    health_namespace_node(
        4022,
        "Health.UptimeSeconds",
        ValueKind::UInt32,
        HealthNode::UptimeSeconds,
    ),
    health_namespace_node(
        4023,
        "Health.IwdgLastKickAgeMs",
        ValueKind::UInt32,
        HealthNode::IwdgLastKickAgeMs,
    ),
    health_namespace_node(
        4024,
        "Health.WatchdogStaleMask",
        ValueKind::UInt32,
        HealthNode::WatchdogStaleMask,
    ),
    health_namespace_node(
        4025,
        "Health.TaskCheckinRegisteredMask",
        ValueKind::UInt32,
        HealthNode::TaskCheckinRegisteredMask,
    ),
    health_namespace_node(
        4026,
        "Health.TaskCheckinFreshMask",
        ValueKind::UInt32,
        HealthNode::TaskCheckinFreshMask,
    ),
    health_namespace_node(
        4027,
        "Health.TaskCheckinDeadlineMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinDeadlineMs,
    ),
    health_namespace_node(
        4028,
        "Health.LastFaultPresent",
        ValueKind::Boolean,
        HealthNode::LastFaultPresent,
    ),
    health_namespace_node(
        4029,
        "Health.LastFaultReason",
        ValueKind::UInt32,
        HealthNode::LastFaultReason,
    ),
    health_namespace_node(
        4030,
        "Health.LastFaultSequence",
        ValueKind::UInt32,
        HealthNode::LastFaultSequence,
    ),
    health_namespace_node(
        4031,
        "Health.LastFaultUptimeSeconds",
        ValueKind::UInt32,
        HealthNode::LastFaultUptimeSeconds,
    ),
    health_namespace_node(
        4032,
        "Health.LastFaultDetail",
        ValueKind::UInt32,
        HealthNode::LastFaultDetail,
    ),
    health_namespace_node(
        4033,
        "Health.LastFaultResetFlags",
        ValueKind::UInt32,
        HealthNode::LastFaultResetFlags,
    ),
    health_namespace_node(
        4034,
        "Health.ResetFlags",
        ValueKind::UInt32,
        HealthNode::ResetFlags,
    ),
    health_namespace_node(
        4035,
        "Health.WatchdogBiteCount",
        ValueKind::UInt32,
        HealthNode::WatchdogBiteCount,
    ),
    health_namespace_node(
        4036,
        "Health.TaskCheckin.MainHeartbeatAgeMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinMainHeartbeatAgeMs,
    ),
    health_namespace_node(
        4038,
        "Health.TaskCheckin.MdnsResponderAgeMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinMdnsResponderAgeMs,
    ),
    health_namespace_node(
        4039,
        "Health.TaskCheckin.NetStatusAgeMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinNetStatusAgeMs,
    ),
    health_namespace_node(
        4040,
        "Health.TaskCheckin.UsbConsoleAgeMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinUsbConsoleAgeMs,
    ),
    health_namespace_node(
        4041,
        "Health.TaskCheckin.BuchiTlsClientAgeMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinBuchiTlsClientAgeMs,
    ),
    health_namespace_node(
        4042,
        "Health.TaskCheckin.OpcUaServerAgeMs",
        ValueKind::UInt32,
        HealthNode::TaskCheckinOpcUaServerAgeMs,
    ),
    health_namespace_node(
        4043,
        "Health.BuchiTrustState",
        ValueKind::UInt32,
        HealthNode::BuchiTrustState,
    ),
    health_namespace_node(
        4044,
        "Health.BuchiTrustAnchorPresent",
        ValueKind::Boolean,
        HealthNode::BuchiTrustAnchorPresent,
    ),
    health_namespace_node(
        4045,
        "Health.BuchiTrustRtcUsable",
        ValueKind::Boolean,
        HealthNode::BuchiTrustRtcUsable,
    ),
    health_namespace_node(
        4046,
        "Health.BuchiTrustLastVerifyError",
        ValueKind::UInt32,
        HealthNode::BuchiTrustLastVerifyError,
    ),
    health_namespace_node(
        4047,
        "Health.BuchiTrustVerifyAttemptCount",
        ValueKind::UInt32,
        HealthNode::BuchiTrustVerifyAttemptCount,
    ),
    health_namespace_node(
        4048,
        "Health.BuchiTrustVerifiedSessionCount",
        ValueKind::UInt32,
        HealthNode::BuchiTrustVerifiedSessionCount,
    ),
    health_namespace_node(
        4049,
        "Health.BuchiTrustRevocationCount",
        ValueKind::UInt32,
        HealthNode::BuchiTrustRevocationCount,
    ),
    health_namespace_node(
        4050,
        "Health.BuchiVerifierTimeTrusted",
        ValueKind::Boolean,
        HealthNode::BuchiVerifierTimeTrusted,
    ),
];

pub fn default_namespace_nodes() -> &'static [NamespaceNode; DEFAULT_NAMESPACE_NODE_COUNT] {
    &DEFAULT_NAMESPACE_NODES
}

pub fn lookup_default_namespace_node(node_id: u16) -> Option<&'static NamespaceNode> {
    DEFAULT_NAMESPACE_NODES
        .iter()
        .find(|node| node.node_id == node_id)
}

pub fn lookup_default_namespace_runtime_node(
    runtime_node: RuntimeNode,
) -> Option<&'static NamespaceNode> {
    DEFAULT_NAMESPACE_NODES
        .iter()
        .find(|node| node.target == NamespaceTarget::Runtime(runtime_node))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceRead {
    pub node_id: u16,
    pub browse_name: Option<&'static str>,
    pub value_kind: Option<ValueKind>,
    pub access: Option<Access>,
    pub target: Option<NamespaceTarget>,
    pub cache_status: Option<CacheReadStatus>,
    pub opcua_status: u32,
    pub value: Option<ScalarValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeWriteDispatch {
    pub request: WriteRequest,
    pub endpoint: Endpoint,
    pub body_len: usize,
}

impl RuntimeWriteDispatch {
    pub const fn path(self) -> &'static str {
        self.endpoint.path()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeWriteDispatchError {
    EmptyQueue,
    Build(BuildWriteJsonError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeWriteTransactionError {
    EmptyQueue,
    Build(BuchiPutTransactionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeWriteCompletion {
    pub request: WriteRequest,
    pub http_status: i32,
    pub opcua_status: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeWriteCompletionError {
    Transaction(BuchiPutTransactionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataAccessWriteResult {
    pub node_id: Option<u16>,
    pub target: WriteTarget,
    pub validation: WriteValidationStatus,
    pub opcua_status: u32,
    pub accepted: bool,
    pub coalesced: bool,
    pub depth: usize,
    pub sequence: Option<u32>,
}

impl DataAccessWriteResult {
    const fn rejected(
        node_id: Option<u16>,
        target: WriteTarget,
        validation: WriteValidationStatus,
        opcua_status: u32,
        depth: usize,
    ) -> Self {
        Self {
            node_id,
            target,
            validation,
            opcua_status,
            accepted: false,
            coalesced: false,
            depth,
            sequence: None,
        }
    }
}

mod subscriptions;
pub use subscriptions::{
    opcua_status_for_monitored_item_add, DataChangeSample, DataChangeSubscription,
    DefaultDataChangeSubscription, MonitoredItem, MonitoredItemAddResult, MonitoredItemAddStatus,
};

pub type DefaultRuntimeDataAccess = RuntimeDataAccess<{ product::BUCHI_WRITE_QUEUE_CAPACITY }>;

mod buchi_client;
pub use buchi_client::{
    BuchiClientTask, BuchiClientTaskError, BuchiClientTaskStep, BuchiClientTransaction,
    BuchiClientTransactionBuildError, BuchiClientTransactionCompletion,
    BuchiClientTransactionCompletionError, BuchiClientTransactionKind, BuchiClientTransportError,
    BuchiPollCompletion, BuchiPollRequest, BuchiPollRuntime, BuchiPollTransaction,
    DefaultBuchiClientTransaction, DefaultBuchiPollRuntime, DefaultBuchiPollTransaction,
};

mod data_access;
#[cfg(feature = "diagnostic-cache-ages")]
pub use data_access::diagnostic_ages::DiagnosticAgeObservation;
pub use data_access::RuntimeDataAccess;
#[cfg(feature = "diagnostic-cache-ages")]
pub use opta_gateway_contracts::freshness::DiagnosticAge;

#[cfg(feature = "diagnostic-runtime-counters")]
mod diagnostic_counters;
#[cfg(feature = "diagnostic-runtime-counters")]
pub use diagnostic_counters::{DiagnosticCounterSeed, DiagnosticCounterSnapshot};

mod cache;
pub use cache::{
    EndpointPollError, EndpointPollFailure, EndpointPollReport, PublishSummary, RuntimeCache,
};

mod runtime_values;
pub(crate) use runtime_values::{
    attached_indicator_subsystem, attachment_indicator_read, bool_value, endpoint_from_values,
    health_u32, i32_value, integer_unit_as_milli_float, milli_float_value, nonnegative_i32_value,
    process_state_as_running, scalar_write_value_to_raw, status_from_error, subsystem_owner,
    u32_value, NodeOwner,
};

#[cfg(test)]
mod tests;
