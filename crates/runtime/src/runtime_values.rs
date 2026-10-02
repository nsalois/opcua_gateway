use opta_buchi::{
    Endpoint, EndpointResponseError, EndpointValues, WriteSpec, WriteValidationStatus,
    WriteValueType,
};
use opta_gateway_contracts::freshness::{CacheRead, CacheReadStatus, ScalarValue};
use opta_gateway_contracts::opcua_status;

use crate::{AttachmentState, RuntimeNode, Subsystem};

pub(crate) fn scalar_write_value_to_raw(
    spec: &WriteSpec,
    value: ScalarValue,
) -> Result<i32, WriteValidationStatus> {
    match (spec.value_type, value) {
        (WriteValueType::Boolean, ScalarValue::Boolean(value)) => Ok(if value { 1 } else { 0 }),
        (WriteValueType::Int32, ScalarValue::Int32(value)) => Ok(value),
        (WriteValueType::Float, ScalarValue::FloatMilli(value)) => {
            raw_from_milli_for_write_spec(spec, value).ok_or(WriteValidationStatus::OutOfRange)
        }
        _ => Err(WriteValidationStatus::TypeMismatch),
    }
}

fn raw_from_milli_for_write_spec(spec: &WriteSpec, milli_value: i32) -> Option<i32> {
    if spec.scale <= 0 {
        return None;
    }
    let scaled = (milli_value as i64).checked_mul(spec.scale as i64)?;
    if scaled % 1_000 != 0 {
        return None;
    }
    i32::try_from(scaled / 1_000).ok()
}

pub(crate) fn status_from_error(error: EndpointResponseError) -> Option<i32> {
    match error {
        EndpointResponseError::UnexpectedStatus(status) => Some(status),
        EndpointResponseError::Body(_) => Some(200),
        EndpointResponseError::Http(_) => None,
    }
}

pub(crate) const fn endpoint_from_values(values: &EndpointValues) -> Endpoint {
    match values {
        EndpointValues::Process(_) => Endpoint::Process,
        EndpointValues::Settings(_) => Endpoint::Settings,
        EndpointValues::Info(_) => Endpoint::Info,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeOwner {
    None,
    Single(Subsystem),
    Vacuum,
}

pub(crate) const fn attached_indicator_subsystem(node: RuntimeNode) -> Option<Subsystem> {
    match node {
        RuntimeNode::InfoBathAttached => Some(Subsystem::Bath),
        RuntimeNode::InfoChillerAttached => Some(Subsystem::Chiller),
        RuntimeNode::InfoRotavaporAttached => Some(Subsystem::Rotavapor),
        RuntimeNode::InfoPumpAttached => Some(Subsystem::Pump),
        RuntimeNode::InfoVacuboxAttached => Some(Subsystem::Vacubox),
        _ => None,
    }
}

pub(crate) const fn attachment_indicator_read(state: AttachmentState) -> CacheRead {
    match state {
        AttachmentState::Unknown => CacheRead {
            status: CacheReadStatus::NeverPublished,
            value: None,
        },
        AttachmentState::Attached => CacheRead {
            status: CacheReadStatus::Ok,
            value: Some(ScalarValue::Boolean(true)),
        },
        AttachmentState::Detached => CacheRead {
            status: CacheReadStatus::Ok,
            value: Some(ScalarValue::Boolean(false)),
        },
    }
}

pub(crate) const fn subsystem_owner(node: RuntimeNode) -> NodeOwner {
    match node {
        RuntimeNode::ProcessHeatingSet
        | RuntimeNode::ProcessBathTemperature
        | RuntimeNode::ProcessHeatingRunning
        | RuntimeNode::SettingsHeatingMaxTemperature
        | RuntimeNode::SettingsHeatingStopOnFinish
        | RuntimeNode::SettingsProgramEcoHeatingBathTemperature
        | RuntimeNode::InfoBathOperatingTimeHours
        | RuntimeNode::InfoBathHoursOver190c => NodeOwner::Single(Subsystem::Bath),

        RuntimeNode::ProcessCoolingSet
        | RuntimeNode::ProcessCoolingActual
        | RuntimeNode::ProcessCoolingRunning
        | RuntimeNode::SettingsCoolingStopOnFinish
        | RuntimeNode::SettingsProgramEcoCoolantTemperature
        | RuntimeNode::InfoChillerOperatingTimeHours
        | RuntimeNode::InfoChillerPumpHours
        | RuntimeNode::InfoChillerCompressorHours
        | RuntimeNode::InfoChillerValveCounter => NodeOwner::Single(Subsystem::Chiller),

        RuntimeNode::ProcessRotationSpeed
        | RuntimeNode::ProcessRotationSet
        | RuntimeNode::ProcessRotationRunning
        | RuntimeNode::ProcessLiftSet
        | RuntimeNode::ProcessLiftActual
        | RuntimeNode::ProcessLiftLimit
        | RuntimeNode::SettingsRotationStopOnFinish
        | RuntimeNode::SettingsLiftDepthStop
        | RuntimeNode::SettingsLiftImmerseOnStart
        | RuntimeNode::SettingsLiftOutFlaskOnFinish
        | RuntimeNode::SettingsRotationStartOnStart
        | RuntimeNode::InfoRotavaporOperatingTimeHours
        | RuntimeNode::InfoRotavaporRotationHours
        | RuntimeNode::InfoRotavaporLiftMoves => NodeOwner::Single(Subsystem::Rotavapor),

        RuntimeNode::ProcessVacuumSet
        | RuntimeNode::ProcessPressure
        | RuntimeNode::ProcessVacuumAerateValveOpen
        | RuntimeNode::ProcessVacuumAerateValvePulse
        | RuntimeNode::ProcessVacuumValveOpen
        | RuntimeNode::ProcessVacuumVaporTemperature
        | RuntimeNode::ProcessVacuumAutoDestinationIn
        | RuntimeNode::ProcessVacuumAutoDestinationOut
        | RuntimeNode::ProcessVacuumPowerPercent
        | RuntimeNode::ProcessVacuumRunning
        | RuntimeNode::SettingsVacuumPressureHysteresis
        | RuntimeNode::SettingsVacuumAltitude
        | RuntimeNode::SettingsVacuumMaxPermPressure
        | RuntimeNode::SettingsVacuumMaxPumpOutput
        | RuntimeNode::SettingsVacuumVentOnFinish => NodeOwner::Vacuum,

        RuntimeNode::InfoPumpOperatingTimeHours
        | RuntimeNode::InfoPumpModule1SwitchOn
        | RuntimeNode::InfoPumpModule1OverCurrent
        | RuntimeNode::InfoPumpModule1MaxCurrent
        | RuntimeNode::InfoPumpModule1MaxTemperature
        | RuntimeNode::InfoPumpModule2SwitchOn
        | RuntimeNode::InfoPumpModule2OverCurrent
        | RuntimeNode::InfoPumpModule2MaxCurrent
        | RuntimeNode::InfoPumpModule2MaxTemperature => NodeOwner::Single(Subsystem::Pump),

        RuntimeNode::InfoVacuboxOperatingTimeHours => NodeOwner::Single(Subsystem::Vacubox),

        RuntimeNode::ProcessState
        | RuntimeNode::ProcessGlobalStatusProcessTime
        | RuntimeNode::ProcessGlobalStatusRunId
        | RuntimeNode::ProcessGlobalStatusRunning
        | RuntimeNode::ProcessGlobalStatusOnHold
        | RuntimeNode::ProcessGlobalStatusFoamActive
        | RuntimeNode::ProcessGlobalStatusCurrentError
        | RuntimeNode::SettingsDisplayBrightness
        | RuntimeNode::SettingsDisplayUtcOffset
        | RuntimeNode::SettingsSoundsButtonTone
        | RuntimeNode::SettingsSoundsPlaySoundOnFinish
        | RuntimeNode::SettingsProgramEcoEnabled
        | RuntimeNode::SettingsProgramEcoActivationAfterMins
        | RuntimeNode::InfoControllerOperatingTimeHours
        | RuntimeNode::InfoControllerRunTotalRuns
        | RuntimeNode::InfoControllerRunManual
        | RuntimeNode::InfoControllerRunTimer
        | RuntimeNode::InfoControllerRunContinuous
        | RuntimeNode::InfoControllerRunSolvent
        | RuntimeNode::InfoControllerRunMethod
        | RuntimeNode::InfoControllerRunAutoDest
        | RuntimeNode::InfoControllerRunCloudDest
        | RuntimeNode::InfoControllerRunDrying
        | RuntimeNode::InfoControllerRunLeakTest
        | RuntimeNode::InfoControllerRunCalibration
        | RuntimeNode::InfoBathAttached
        | RuntimeNode::InfoChillerAttached
        | RuntimeNode::InfoRotavaporAttached
        | RuntimeNode::InfoPumpAttached
        | RuntimeNode::InfoVacuboxAttached => NodeOwner::None,
    }
}

pub(crate) fn health_u32(value: u32) -> (u32, Option<ScalarValue>) {
    (opcua_status::GOOD, Some(ScalarValue::UInt32(value)))
}

pub(crate) fn bool_value(value: Option<bool>) -> Option<ScalarValue> {
    value.map(ScalarValue::Boolean)
}

pub(crate) fn i32_value(value: Option<i32>) -> Option<ScalarValue> {
    value.map(ScalarValue::Int32)
}

pub(crate) fn u32_value(value: Option<u32>) -> Option<ScalarValue> {
    value.map(ScalarValue::UInt32)
}

pub(crate) fn milli_float_value(value: Option<i32>) -> Option<ScalarValue> {
    value.map(ScalarValue::FloatMilli)
}

pub(crate) fn integer_unit_as_milli_float(value: Option<i32>) -> Option<ScalarValue> {
    value.and_then(|value| value.checked_mul(1_000).map(ScalarValue::FloatMilli))
}

pub(crate) fn nonnegative_i32_value(value: Option<i32>) -> Option<ScalarValue> {
    value.map(ScalarValue::Int32)
}

pub(crate) fn process_state_as_running(value: Option<i32>) -> Option<ScalarValue> {
    value.map(|value| ScalarValue::Boolean(value != 0))
}
