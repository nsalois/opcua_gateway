use opta_buchi::{
    parse_endpoint_http_response, Endpoint, EndpointResponseError, EndpointValues, InfoValues,
    ProcessValues, SettingsValues,
};
use opta_gateway_contracts::freshness::{CacheRead, CacheReadStatus, FixedValueCache, ScalarValue};

use crate::{
    attached_indicator_subsystem, attachment_indicator_read, bool_value, endpoint_from_values,
    i32_value, integer_unit_as_milli_float, milli_float_value, nonnegative_i32_value,
    process_state_as_running, runtime_node_contract_by_index, status_from_error, subsystem_owner,
    u32_value, AttachmentState, NodeOwner, RuntimeNode, Subsystem, SubsystemAttachments,
    NODE_COUNT,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishSummary {
    pub endpoint: Endpoint,
    pub parsed_fields: usize,
    pub published_values: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointPollReport {
    pub summary: PublishSummary,
    pub completed_fetches: u32,
    pub failed_fetches: u32,
    pub last_http_status: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointPollFailure {
    pub endpoint: Endpoint,
    pub error: EndpointPollError,
    pub completed_fetches: u32,
    pub failed_fetches: u32,
    pub last_http_status: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPollError {
    TrustNotVerified,
    Response(EndpointResponseError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCache {
    values: FixedValueCache<NODE_COUNT>,
    attachments: SubsystemAttachments,
    completed_fetches: u32,
    failed_fetches: u32,
    last_endpoint: Option<Endpoint>,
    last_http_status: Option<i32>,
    last_fetch_ok: bool,
}

impl RuntimeCache {
    #[cfg(feature = "diagnostic-cache-ages")]
    pub(crate) fn diagnostic_begin_age(
        &mut self,
        node: RuntimeNode,
        now: u64,
        age: opta_gateway_contracts::freshness::DiagnosticAge,
    ) -> Option<opta_gateway_contracts::freshness::DiagnosticAgeRestore> {
        self.values.diagnostic_begin_age(node.index(), now, age)
    }

    #[cfg(feature = "diagnostic-cache-ages")]
    pub(crate) fn diagnostic_restore_age(
        &mut self,
        restore: opta_gateway_contracts::freshness::DiagnosticAgeRestore,
    ) {
        self.values.diagnostic_restore_age(restore);
    }

    /// Read-only target diagnostic state, independently of freshness classification.
    #[cfg(any(
        feature = "diagnostic-runtime-counters",
        feature = "diagnostic-cache-ages"
    ))]
    pub fn diagnostic_publication(
        &self,
        node: RuntimeNode,
    ) -> opta_gateway_contracts::freshness::EntryMetadata {
        self.values
            .diagnostic_metadata(node.index())
            .expect("runtime node index")
    }

    /// Raw state for independent host admission; absent from product builds.
    #[cfg(any(test, feature = "host-validation"))]
    pub fn validation_metadata(
        &self,
        node: RuntimeNode,
    ) -> opta_gateway_contracts::freshness::EntryMetadata {
        self.values
            .validation_metadata(node.index())
            .expect("runtime node index")
    }

    pub const fn new() -> Self {
        Self {
            values: FixedValueCache::new(0),
            attachments: SubsystemAttachments::new(),
            completed_fetches: 0,
            failed_fetches: 0,
            last_endpoint: None,
            last_http_status: None,
            last_fetch_ok: false,
        }
    }

    pub const fn completed_fetches(&self) -> u32 {
        self.completed_fetches
    }

    /// Only the enclosing data-access owner admits this finite initialization.
    #[cfg(feature = "diagnostic-runtime-counters")]
    pub(crate) fn diagnostic_seed_successful_fetches(
        &mut self,
        seed: crate::DiagnosticCounterSeed,
    ) {
        self.completed_fetches = seed.value();
    }

    pub const fn failed_fetches(&self) -> u32 {
        self.failed_fetches
    }

    pub const fn last_endpoint(&self) -> Option<Endpoint> {
        self.last_endpoint
    }

    pub const fn last_http_status(&self) -> Option<i32> {
        self.last_http_status
    }

    pub const fn last_fetch_ok(&self) -> bool {
        self.last_fetch_ok
    }

    pub const fn attachment_state(&self, subsystem: Subsystem) -> AttachmentState {
        self.attachments.state(subsystem)
    }

    pub fn read(&self, node: RuntimeNode, freshness_now_ms: u64) -> CacheRead {
        if let Some(read) = self.attachment_overlay_read(node) {
            return read;
        }
        self.values.read(node.index(), freshness_now_ms)
    }

    pub fn read_index(&self, index: usize, freshness_now_ms: u64) -> CacheRead {
        let Some(contract) = runtime_node_contract_by_index(index) else {
            return self.values.read(index, freshness_now_ms);
        };
        if let Some(read) = self.attachment_overlay_read(contract.node) {
            return read;
        }
        self.values.read(index, freshness_now_ms)
    }

    pub fn apply_http_response(
        &mut self,
        endpoint: Endpoint,
        response: &[u8],
        response_limit: usize,
        freshness_now_ms: u64,
    ) -> Result<EndpointPollReport, EndpointPollFailure> {
        match parse_endpoint_http_response(endpoint, response, response_limit) {
            Ok(values) => Ok(self.apply_endpoint_values_report(values, freshness_now_ms)),
            Err(error) => Err(self.record_endpoint_failure(endpoint, error)),
        }
    }

    pub fn record_endpoint_failure(
        &mut self,
        endpoint: Endpoint,
        error: EndpointResponseError,
    ) -> EndpointPollFailure {
        self.failed_fetches = self.failed_fetches.wrapping_add(1);
        self.last_endpoint = Some(endpoint);
        self.last_http_status = status_from_error(error);
        self.last_fetch_ok = false;
        EndpointPollFailure {
            endpoint,
            error: EndpointPollError::Response(error),
            completed_fetches: self.completed_fetches,
            failed_fetches: self.failed_fetches,
            last_http_status: self.last_http_status,
        }
    }

    pub fn apply_endpoint_values_report(
        &mut self,
        values: EndpointValues,
        freshness_now_ms: u64,
    ) -> EndpointPollReport {
        self.completed_fetches = self.completed_fetches.wrapping_add(1);
        self.last_endpoint = Some(endpoint_from_values(&values));
        self.last_http_status = Some(200);
        self.last_fetch_ok = true;
        let summary = self.apply_endpoint_values(values, freshness_now_ms);
        EndpointPollReport {
            summary,
            completed_fetches: self.completed_fetches,
            failed_fetches: self.failed_fetches,
            last_http_status: self.last_http_status,
        }
    }

    pub fn apply_endpoint_values(
        &mut self,
        values: EndpointValues,
        freshness_now_ms: u64,
    ) -> PublishSummary {
        self.observe_endpoint_presence(&values);
        match values {
            EndpointValues::Process(values) => self.publish_process(values, freshness_now_ms),
            EndpointValues::Settings(values) => self.publish_settings(values, freshness_now_ms),
            EndpointValues::Info(values) => self.publish_info(values, freshness_now_ms),
        }
    }

    fn observe_endpoint_presence(&mut self, values: &EndpointValues) {
        match values {
            EndpointValues::Process(values) => {
                self.attachments
                    .observe(Subsystem::Bath, values.roots.heating);
                self.attachments
                    .observe(Subsystem::Chiller, values.roots.cooling);
                self.attachments.observe(
                    Subsystem::Rotavapor,
                    values.roots.rotation || values.roots.lift,
                );
                self.attachments
                    .observe(Subsystem::Pump, values.roots.vacuum);
                self.attachments
                    .observe(Subsystem::Vacubox, values.roots.vacuum);
            }
            EndpointValues::Settings(values) => {
                self.attachments
                    .observe(Subsystem::Bath, values.roots.heating);
                self.attachments
                    .observe(Subsystem::Chiller, values.roots.cooling);
                self.attachments.observe(
                    Subsystem::Rotavapor,
                    values.roots.rotation || values.roots.lift,
                );
                self.attachments
                    .observe(Subsystem::Pump, values.roots.vacuum);
                self.attachments
                    .observe(Subsystem::Vacubox, values.roots.vacuum);
            }
            EndpointValues::Info(values) => {
                self.attachments.observe(Subsystem::Bath, values.roots.bath);
                self.attachments
                    .observe(Subsystem::Chiller, values.roots.chiller);
                self.attachments
                    .observe(Subsystem::Rotavapor, values.roots.rotavapor);
                self.attachments.observe(Subsystem::Pump, values.roots.pump);
                self.attachments
                    .observe(Subsystem::Vacubox, values.roots.vacubox);
            }
        }
    }

    fn attachment_overlay_read(&self, node: RuntimeNode) -> Option<CacheRead> {
        if let Some(subsystem) = attached_indicator_subsystem(node) {
            return Some(attachment_indicator_read(self.attachments.state(subsystem)));
        }
        if self.node_owner_detached(node) {
            return Some(CacheRead {
                status: CacheReadStatus::NotConnected,
                value: None,
            });
        }
        None
    }

    fn node_owner_detached(&self, node: RuntimeNode) -> bool {
        match subsystem_owner(node) {
            NodeOwner::None => false,
            NodeOwner::Single(subsystem) => self.attachments.is_detached(subsystem),
            NodeOwner::Vacuum => {
                self.attachments.is_detached(Subsystem::Pump)
                    || self.attachments.is_detached(Subsystem::Vacubox)
            }
        }
    }

    fn publish_process(&mut self, values: ProcessValues, freshness_now_ms: u64) -> PublishSummary {
        let mut summary = PublishSummary {
            endpoint: Endpoint::Process,
            parsed_fields: values.parsed_field_count(),
            published_values: 0,
        };

        // BH-6: on a successful payload, absent optional objects invalidate their
        // owned tags immediately. Attachment hysteresis remains separate and may
        // lag for Attached/Detached indicators only.
        if !values.roots.heating {
            self.invalidate_nodes(&[
                RuntimeNode::ProcessHeatingSet,
                RuntimeNode::ProcessBathTemperature,
                RuntimeNode::ProcessHeatingRunning,
            ]);
        }
        if !values.roots.cooling {
            self.invalidate_nodes(&[
                RuntimeNode::ProcessCoolingSet,
                RuntimeNode::ProcessCoolingActual,
                RuntimeNode::ProcessCoolingRunning,
            ]);
        }
        if !values.roots.vacuum {
            self.invalidate_nodes(&[
                RuntimeNode::ProcessVacuumSet,
                RuntimeNode::ProcessPressure,
                RuntimeNode::ProcessVacuumAerateValveOpen,
                RuntimeNode::ProcessVacuumAerateValvePulse,
                RuntimeNode::ProcessVacuumValveOpen,
                RuntimeNode::ProcessVacuumVaporTemperature,
                RuntimeNode::ProcessVacuumAutoDestinationIn,
                RuntimeNode::ProcessVacuumAutoDestinationOut,
                RuntimeNode::ProcessVacuumPowerPercent,
                RuntimeNode::ProcessVacuumRunning,
            ]);
        }
        if !values.roots.rotation {
            self.invalidate_nodes(&[
                RuntimeNode::ProcessRotationSpeed,
                RuntimeNode::ProcessRotationSet,
                RuntimeNode::ProcessRotationRunning,
            ]);
        }
        if !values.roots.lift {
            self.invalidate_nodes(&[
                RuntimeNode::ProcessLiftSet,
                RuntimeNode::ProcessLiftActual,
                RuntimeNode::ProcessLiftLimit,
            ]);
        }
        if !values.roots.global_status {
            self.invalidate_nodes(&[
                RuntimeNode::ProcessState,
                RuntimeNode::ProcessGlobalStatusProcessTime,
                RuntimeNode::ProcessGlobalStatusRunId,
                RuntimeNode::ProcessGlobalStatusRunning,
                RuntimeNode::ProcessGlobalStatusOnHold,
                RuntimeNode::ProcessGlobalStatusFoamActive,
                RuntimeNode::ProcessGlobalStatusCurrentError,
            ]);
        }

        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessState,
            i32_value(values.process_state),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessHeatingSet,
            milli_float_value(values.heating_set_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessBathTemperature,
            milli_float_value(values.bath_temperature_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessHeatingRunning,
            bool_value(values.heating_running),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessCoolingSet,
            milli_float_value(values.cooling_set_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessCoolingActual,
            milli_float_value(values.cooling_actual_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessCoolingRunning,
            bool_value(values.cooling_running),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumSet,
            integer_unit_as_milli_float(values.vacuum_set_mbar),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessRotationSpeed,
            milli_float_value(values.rotation_speed_milli_rpm),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessPressure,
            milli_float_value(values.pressure_milli_mbar),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumAerateValveOpen,
            bool_value(values.vacuum_aerate_valve_open),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumAerateValvePulse,
            bool_value(values.vacuum_aerate_valve_pulse),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumValveOpen,
            bool_value(values.vacuum_valve_open),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumVaporTemperature,
            milli_float_value(values.vacuum_vapor_temperature_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumAutoDestinationIn,
            milli_float_value(values.vacuum_auto_destination_in_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumAutoDestinationOut,
            milli_float_value(values.vacuum_auto_destination_out_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumPowerPercent,
            milli_float_value(values.vacuum_power_percent_milli_percent),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessVacuumRunning,
            bool_value(values.vacuum_running),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessRotationSet,
            integer_unit_as_milli_float(values.rotation_set_rpm),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessRotationRunning,
            bool_value(values.rotation_running),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessLiftSet,
            milli_float_value(values.lift_set_milli_millimeters),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessLiftActual,
            milli_float_value(values.lift_actual_milli_millimeters),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessLiftLimit,
            milli_float_value(values.lift_limit_milli_millimeters),
            freshness_now_ms,
        );
        // The device omits globalStatus.processTime/runId while no run is
        // active, which would leave these tags Bad forever.
        // A present globalStatus object therefore substitutes
        // Good 0 ("no active run") for absent members; GlobalStatus.Running
        // stays the authoritative run-active signal, and an absent
        // globalStatus object still invalidates the tags above (BH-6).
        let idle_run_u32 = |member: Option<u32>| {
            if values.roots.global_status {
                Some(member.unwrap_or(0))
            } else {
                member
            }
        };
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessGlobalStatusProcessTime,
            u32_value(idle_run_u32(values.global_status_process_time_seconds)),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessGlobalStatusRunId,
            u32_value(idle_run_u32(values.global_status_run_id)),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessGlobalStatusRunning,
            process_state_as_running(values.process_state),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessGlobalStatusOnHold,
            bool_value(values.global_status_on_hold),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessGlobalStatusFoamActive,
            bool_value(values.global_status_foam_active),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::ProcessGlobalStatusCurrentError,
            i32_value(values.global_status_current_error),
            freshness_now_ms,
        );

        summary
    }

    fn publish_settings(
        &mut self,
        values: SettingsValues,
        freshness_now_ms: u64,
    ) -> PublishSummary {
        let mut summary = PublishSummary {
            endpoint: Endpoint::Settings,
            parsed_fields: values.parsed_field_count(),
            published_values: 0,
        };

        // BH-6: same immediate quality invalidation for settings roots.
        if !values.roots.display {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsDisplayBrightness,
                RuntimeNode::SettingsDisplayUtcOffset,
            ]);
        }
        if !values.roots.sounds {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsSoundsButtonTone,
                RuntimeNode::SettingsSoundsPlaySoundOnFinish,
            ]);
        }
        if !values.roots.vacuum {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsVacuumPressureHysteresis,
                RuntimeNode::SettingsVacuumAltitude,
                RuntimeNode::SettingsVacuumMaxPermPressure,
                RuntimeNode::SettingsVacuumMaxPumpOutput,
                RuntimeNode::SettingsVacuumVentOnFinish,
            ]);
        }
        if !values.roots.rotation {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsRotationStopOnFinish,
                RuntimeNode::SettingsRotationStartOnStart,
            ]);
        }
        if !values.roots.heating {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsHeatingMaxTemperature,
                RuntimeNode::SettingsHeatingStopOnFinish,
            ]);
        }
        if !values.roots.cooling {
            self.invalidate_nodes(&[RuntimeNode::SettingsCoolingStopOnFinish]);
        }
        if !values.roots.lift {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsLiftDepthStop,
                RuntimeNode::SettingsLiftImmerseOnStart,
                RuntimeNode::SettingsLiftOutFlaskOnFinish,
            ]);
        }
        if !values.roots.program {
            self.invalidate_nodes(&[
                RuntimeNode::SettingsProgramEcoEnabled,
                RuntimeNode::SettingsProgramEcoActivationAfterMins,
                RuntimeNode::SettingsProgramEcoHeatingBathTemperature,
                RuntimeNode::SettingsProgramEcoCoolantTemperature,
            ]);
        }

        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsDisplayBrightness,
            i32_value(values.display_brightness_percent),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsDisplayUtcOffset,
            i32_value(values.display_utc_offset_minutes),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsSoundsButtonTone,
            bool_value(values.sounds_button_tone),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsSoundsPlaySoundOnFinish,
            bool_value(values.sounds_play_sound_on_finish),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsVacuumPressureHysteresis,
            integer_unit_as_milli_float(values.vacuum_pressure_hysteresis_mbar),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsVacuumAltitude,
            integer_unit_as_milli_float(values.vacuum_altitude_meters),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsVacuumMaxPermPressure,
            integer_unit_as_milli_float(values.vacuum_max_perm_pressure_mbar),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsVacuumMaxPumpOutput,
            i32_value(values.vacuum_max_pump_output_percent),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsVacuumVentOnFinish,
            bool_value(values.vacuum_vent_on_finish),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsRotationStopOnFinish,
            bool_value(values.rotation_stop_on_finish),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsHeatingMaxTemperature,
            milli_float_value(values.heating_max_temperature_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsHeatingStopOnFinish,
            bool_value(values.heating_stop_on_finish),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsCoolingStopOnFinish,
            bool_value(values.cooling_stop_on_finish),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsLiftDepthStop,
            milli_float_value(values.lift_depth_stop_milli_millimeters),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsLiftImmerseOnStart,
            bool_value(values.lift_immerse_on_start),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsLiftOutFlaskOnFinish,
            bool_value(values.lift_out_flask_on_finish),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsRotationStartOnStart,
            bool_value(values.rotation_start_on_start),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsProgramEcoEnabled,
            bool_value(values.program_eco_enabled),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsProgramEcoActivationAfterMins,
            i32_value(values.program_eco_activation_after_mins),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsProgramEcoHeatingBathTemperature,
            milli_float_value(values.program_eco_heating_bath_temperature_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::SettingsProgramEcoCoolantTemperature,
            milli_float_value(values.program_eco_coolant_temperature_milli_celsius),
            freshness_now_ms,
        );

        summary
    }

    fn publish_info(&mut self, values: InfoValues, freshness_now_ms: u64) -> PublishSummary {
        let mut summary = PublishSummary {
            endpoint: Endpoint::Info,
            parsed_fields: values.parsed_field_count(),
            published_values: 0,
        };

        // BH-6: info roots use the same immediate quality invalidation.
        if !values.roots.controller {
            self.invalidate_nodes(&[
                RuntimeNode::InfoControllerOperatingTimeHours,
                RuntimeNode::InfoControllerRunTotalRuns,
                RuntimeNode::InfoControllerRunManual,
                RuntimeNode::InfoControllerRunTimer,
                RuntimeNode::InfoControllerRunContinuous,
                RuntimeNode::InfoControllerRunSolvent,
                RuntimeNode::InfoControllerRunMethod,
                RuntimeNode::InfoControllerRunAutoDest,
                RuntimeNode::InfoControllerRunCloudDest,
                RuntimeNode::InfoControllerRunDrying,
                RuntimeNode::InfoControllerRunLeakTest,
                RuntimeNode::InfoControllerRunCalibration,
            ]);
        }
        if !values.roots.bath {
            self.invalidate_nodes(&[
                RuntimeNode::InfoBathOperatingTimeHours,
                RuntimeNode::InfoBathHoursOver190c,
            ]);
        }
        if !values.roots.chiller {
            self.invalidate_nodes(&[
                RuntimeNode::InfoChillerOperatingTimeHours,
                RuntimeNode::InfoChillerPumpHours,
                RuntimeNode::InfoChillerCompressorHours,
                RuntimeNode::InfoChillerValveCounter,
            ]);
        }
        if !values.roots.rotavapor {
            self.invalidate_nodes(&[
                RuntimeNode::InfoRotavaporOperatingTimeHours,
                RuntimeNode::InfoRotavaporRotationHours,
                RuntimeNode::InfoRotavaporLiftMoves,
            ]);
        }
        if !values.roots.pump {
            self.invalidate_nodes(&[
                RuntimeNode::InfoPumpOperatingTimeHours,
                RuntimeNode::InfoPumpModule1SwitchOn,
                RuntimeNode::InfoPumpModule1OverCurrent,
                RuntimeNode::InfoPumpModule1MaxCurrent,
                RuntimeNode::InfoPumpModule1MaxTemperature,
                RuntimeNode::InfoPumpModule2SwitchOn,
                RuntimeNode::InfoPumpModule2OverCurrent,
                RuntimeNode::InfoPumpModule2MaxCurrent,
                RuntimeNode::InfoPumpModule2MaxTemperature,
            ]);
        }
        if !values.roots.vacubox {
            self.invalidate_nodes(&[RuntimeNode::InfoVacuboxOperatingTimeHours]);
        }

        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerOperatingTimeHours,
            nonnegative_i32_value(values.controller_operating_time_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunTotalRuns,
            nonnegative_i32_value(values.controller_run_total_runs),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunManual,
            nonnegative_i32_value(values.controller_run_manual),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunTimer,
            nonnegative_i32_value(values.controller_run_timer),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunContinuous,
            nonnegative_i32_value(values.controller_run_continuous),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunSolvent,
            nonnegative_i32_value(values.controller_run_solvent),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunMethod,
            nonnegative_i32_value(values.controller_run_method),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunAutoDest,
            nonnegative_i32_value(values.controller_run_auto_dest),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunCloudDest,
            nonnegative_i32_value(values.controller_run_cloud_dest),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunDrying,
            nonnegative_i32_value(values.controller_run_drying),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunLeakTest,
            nonnegative_i32_value(values.controller_run_leak_test),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoControllerRunCalibration,
            nonnegative_i32_value(values.controller_run_calibration),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoBathOperatingTimeHours,
            nonnegative_i32_value(values.bath_operating_time_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoBathHoursOver190c,
            nonnegative_i32_value(values.bath_hours_over_190c),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoChillerOperatingTimeHours,
            nonnegative_i32_value(values.chiller_operating_time_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoChillerPumpHours,
            nonnegative_i32_value(values.chiller_pump_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoChillerCompressorHours,
            nonnegative_i32_value(values.chiller_compressor_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoChillerValveCounter,
            nonnegative_i32_value(values.chiller_valve_counter),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoRotavaporOperatingTimeHours,
            nonnegative_i32_value(values.rotavapor_operating_time_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoRotavaporRotationHours,
            nonnegative_i32_value(values.rotavapor_rotation_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoRotavaporLiftMoves,
            nonnegative_i32_value(values.rotavapor_lift_moves),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpOperatingTimeHours,
            nonnegative_i32_value(values.pump_operating_time_hours),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule1SwitchOn,
            nonnegative_i32_value(values.pump_module1_switch_on),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule1OverCurrent,
            milli_float_value(values.pump_module1_over_current_milli_count),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule1MaxCurrent,
            milli_float_value(values.pump_module1_max_current_milli_amps),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule1MaxTemperature,
            milli_float_value(values.pump_module1_max_temperature_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule2SwitchOn,
            nonnegative_i32_value(values.pump_module2_switch_on),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule2OverCurrent,
            milli_float_value(values.pump_module2_over_current_milli_count),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule2MaxCurrent,
            milli_float_value(values.pump_module2_max_current_milli_amps),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoPumpModule2MaxTemperature,
            milli_float_value(values.pump_module2_max_temperature_milli_celsius),
            freshness_now_ms,
        );
        self.publish_optional(
            &mut summary,
            RuntimeNode::InfoVacuboxOperatingTimeHours,
            nonnegative_i32_value(values.vacubox_operating_time_hours),
            freshness_now_ms,
        );

        summary
    }

    fn publish_optional(
        &mut self,
        summary: &mut PublishSummary,
        node: RuntimeNode,
        value: Option<ScalarValue>,
        freshness_now_ms: u64,
    ) {
        if let Some(value) = value {
            if self
                .values
                .publish(node.index(), value, freshness_now_ms, node.freshness_ms())
            {
                summary.published_values += 1;
            }
        }
    }

    /// Drop previously Good values for nodes whose optional object was omitted
    /// from a successful endpoint payload (BH-6). Attachment hysteresis is not
    /// consulted here; quality is immediate while Attached indicators may lag.
    fn invalidate_nodes(&mut self, nodes: &[RuntimeNode]) {
        for node in nodes {
            let _ = self.values.unpublish(node.index(), node.freshness_ms());
        }
    }
}

impl Default for RuntimeCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod counter_tests {
    use super::RuntimeCache;
    use opta_buchi::{Endpoint, EndpointValues, ProcessValues};

    #[test]
    fn accelerated_fetch_counters_wrap_and_continue() {
        for seed in [u32::MAX - 2, u32::MAX - 1, u32::MAX] {
            let mut cache = RuntimeCache::new();
            cache.completed_fetches = seed;
            cache.failed_fetches = seed;
            assert_eq!(
                (cache.completed_fetches, cache.failed_fetches),
                (seed, seed)
            );
            for operation in 1..=5u64 {
                let expected = ((u64::from(seed) + operation) % 4_294_967_296) as u32;
                let success = cache.apply_endpoint_values_report(
                    EndpointValues::Process(ProcessValues::default()),
                    operation,
                );
                assert_eq!(success.completed_fetches, expected);
                let failure = cache
                    .apply_http_response(Endpoint::Process, b"invalid", 7, operation)
                    .unwrap_err();
                assert_eq!(failure.failed_fetches, expected);
            }
        }
    }
}
