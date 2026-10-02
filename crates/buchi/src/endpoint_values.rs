#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessRootPresence {
    pub heating: bool,
    pub cooling: bool,
    pub vacuum: bool,
    pub rotation: bool,
    pub lift: bool,
    pub global_status: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessValues {
    pub roots: ProcessRootPresence,
    pub process_state: Option<i32>,
    pub heating_set_milli_celsius: Option<i32>,
    pub bath_temperature_milli_celsius: Option<i32>,
    pub heating_running: Option<bool>,
    pub cooling_set_milli_celsius: Option<i32>,
    pub cooling_actual_milli_celsius: Option<i32>,
    pub cooling_running: Option<bool>,
    pub vacuum_set_mbar: Option<i32>,
    pub rotation_speed_milli_rpm: Option<i32>,
    pub pressure_milli_mbar: Option<i32>,
    pub vacuum_aerate_valve_open: Option<bool>,
    pub vacuum_aerate_valve_pulse: Option<bool>,
    pub vacuum_valve_open: Option<bool>,
    pub vacuum_vapor_temperature_milli_celsius: Option<i32>,
    pub vacuum_auto_destination_in_milli_celsius: Option<i32>,
    pub vacuum_auto_destination_out_milli_celsius: Option<i32>,
    pub vacuum_power_percent_milli_percent: Option<i32>,
    pub vacuum_running: Option<bool>,
    pub rotation_set_rpm: Option<i32>,
    pub rotation_running: Option<bool>,
    pub lift_set_milli_millimeters: Option<i32>,
    pub lift_actual_milli_millimeters: Option<i32>,
    pub lift_limit_milli_millimeters: Option<i32>,
    pub global_status_process_time_seconds: Option<u32>,
    pub global_status_run_id: Option<u32>,
    pub global_status_on_hold: Option<bool>,
    pub global_status_foam_active: Option<bool>,
    pub global_status_current_error: Option<i32>,
}

impl ProcessValues {
    pub const fn parsed_field_count(&self) -> usize {
        self.process_state.is_some() as usize
            + self.heating_set_milli_celsius.is_some() as usize
            + self.bath_temperature_milli_celsius.is_some() as usize
            + self.heating_running.is_some() as usize
            + self.cooling_set_milli_celsius.is_some() as usize
            + self.cooling_actual_milli_celsius.is_some() as usize
            + self.cooling_running.is_some() as usize
            + self.vacuum_set_mbar.is_some() as usize
            + self.rotation_speed_milli_rpm.is_some() as usize
            + self.pressure_milli_mbar.is_some() as usize
            + self.vacuum_aerate_valve_open.is_some() as usize
            + self.vacuum_aerate_valve_pulse.is_some() as usize
            + self.vacuum_valve_open.is_some() as usize
            + self.vacuum_vapor_temperature_milli_celsius.is_some() as usize
            + self.vacuum_auto_destination_in_milli_celsius.is_some() as usize
            + self.vacuum_auto_destination_out_milli_celsius.is_some() as usize
            + self.vacuum_power_percent_milli_percent.is_some() as usize
            + self.vacuum_running.is_some() as usize
            + self.rotation_set_rpm.is_some() as usize
            + self.rotation_running.is_some() as usize
            + self.lift_set_milli_millimeters.is_some() as usize
            + self.lift_actual_milli_millimeters.is_some() as usize
            + self.lift_limit_milli_millimeters.is_some() as usize
            + self.global_status_process_time_seconds.is_some() as usize
            + self.global_status_run_id.is_some() as usize
            + self.global_status_on_hold.is_some() as usize
            + self.global_status_foam_active.is_some() as usize
            + self.global_status_current_error.is_some() as usize
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SettingsRootPresence {
    pub display: bool,
    pub sounds: bool,
    pub vacuum: bool,
    pub rotation: bool,
    pub heating: bool,
    pub cooling: bool,
    pub lift: bool,
    pub program: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SettingsValues {
    pub roots: SettingsRootPresence,
    pub display_brightness_percent: Option<i32>,
    pub display_utc_offset_minutes: Option<i32>,
    pub sounds_button_tone: Option<bool>,
    pub sounds_play_sound_on_finish: Option<bool>,
    pub vacuum_pressure_hysteresis_mbar: Option<i32>,
    pub vacuum_altitude_meters: Option<i32>,
    pub vacuum_max_perm_pressure_mbar: Option<i32>,
    pub vacuum_max_pump_output_percent: Option<i32>,
    pub vacuum_vent_on_finish: Option<bool>,
    pub rotation_stop_on_finish: Option<bool>,
    pub heating_max_temperature_milli_celsius: Option<i32>,
    pub heating_stop_on_finish: Option<bool>,
    pub cooling_stop_on_finish: Option<bool>,
    pub lift_depth_stop_milli_millimeters: Option<i32>,
    pub lift_immerse_on_start: Option<bool>,
    pub lift_out_flask_on_finish: Option<bool>,
    pub rotation_start_on_start: Option<bool>,
    pub program_eco_enabled: Option<bool>,
    pub program_eco_activation_after_mins: Option<i32>,
    pub program_eco_heating_bath_temperature_milli_celsius: Option<i32>,
    pub program_eco_coolant_temperature_milli_celsius: Option<i32>,
}

impl SettingsValues {
    pub const fn parsed_field_count(&self) -> usize {
        self.display_brightness_percent.is_some() as usize
            + self.display_utc_offset_minutes.is_some() as usize
            + self.sounds_button_tone.is_some() as usize
            + self.sounds_play_sound_on_finish.is_some() as usize
            + self.vacuum_pressure_hysteresis_mbar.is_some() as usize
            + self.vacuum_altitude_meters.is_some() as usize
            + self.vacuum_max_perm_pressure_mbar.is_some() as usize
            + self.vacuum_max_pump_output_percent.is_some() as usize
            + self.vacuum_vent_on_finish.is_some() as usize
            + self.rotation_stop_on_finish.is_some() as usize
            + self.heating_max_temperature_milli_celsius.is_some() as usize
            + self.heating_stop_on_finish.is_some() as usize
            + self.cooling_stop_on_finish.is_some() as usize
            + self.lift_depth_stop_milli_millimeters.is_some() as usize
            + self.lift_immerse_on_start.is_some() as usize
            + self.lift_out_flask_on_finish.is_some() as usize
            + self.rotation_start_on_start.is_some() as usize
            + self.program_eco_enabled.is_some() as usize
            + self.program_eco_activation_after_mins.is_some() as usize
            + self
                .program_eco_heating_bath_temperature_milli_celsius
                .is_some() as usize
            + self.program_eco_coolant_temperature_milli_celsius.is_some() as usize
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InfoRootPresence {
    pub controller: bool,
    pub bath: bool,
    pub chiller: bool,
    pub rotavapor: bool,
    pub pump: bool,
    pub vacubox: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InfoValues {
    pub roots: InfoRootPresence,
    pub controller_operating_time_hours: Option<i32>,
    pub controller_run_total_runs: Option<i32>,
    pub controller_run_manual: Option<i32>,
    pub controller_run_timer: Option<i32>,
    pub controller_run_continuous: Option<i32>,
    pub controller_run_solvent: Option<i32>,
    pub controller_run_method: Option<i32>,
    pub controller_run_auto_dest: Option<i32>,
    pub controller_run_cloud_dest: Option<i32>,
    pub controller_run_drying: Option<i32>,
    pub controller_run_leak_test: Option<i32>,
    pub controller_run_calibration: Option<i32>,
    pub bath_operating_time_hours: Option<i32>,
    pub bath_hours_over_190c: Option<i32>,
    pub chiller_operating_time_hours: Option<i32>,
    pub chiller_pump_hours: Option<i32>,
    pub chiller_compressor_hours: Option<i32>,
    pub chiller_valve_counter: Option<i32>,
    pub rotavapor_operating_time_hours: Option<i32>,
    pub rotavapor_rotation_hours: Option<i32>,
    pub rotavapor_lift_moves: Option<i32>,
    pub pump_operating_time_hours: Option<i32>,
    pub pump_module1_switch_on: Option<i32>,
    pub pump_module1_over_current_milli_count: Option<i32>,
    pub pump_module1_max_current_milli_amps: Option<i32>,
    pub pump_module1_max_temperature_milli_celsius: Option<i32>,
    pub pump_module2_switch_on: Option<i32>,
    pub pump_module2_over_current_milli_count: Option<i32>,
    pub pump_module2_max_current_milli_amps: Option<i32>,
    pub pump_module2_max_temperature_milli_celsius: Option<i32>,
    pub vacubox_operating_time_hours: Option<i32>,
}

impl InfoValues {
    pub const fn parsed_field_count(&self) -> usize {
        self.controller_operating_time_hours.is_some() as usize
            + self.controller_run_total_runs.is_some() as usize
            + self.controller_run_manual.is_some() as usize
            + self.controller_run_timer.is_some() as usize
            + self.controller_run_continuous.is_some() as usize
            + self.controller_run_solvent.is_some() as usize
            + self.controller_run_method.is_some() as usize
            + self.controller_run_auto_dest.is_some() as usize
            + self.controller_run_cloud_dest.is_some() as usize
            + self.controller_run_drying.is_some() as usize
            + self.controller_run_leak_test.is_some() as usize
            + self.controller_run_calibration.is_some() as usize
            + self.bath_operating_time_hours.is_some() as usize
            + self.bath_hours_over_190c.is_some() as usize
            + self.chiller_operating_time_hours.is_some() as usize
            + self.chiller_pump_hours.is_some() as usize
            + self.chiller_compressor_hours.is_some() as usize
            + self.chiller_valve_counter.is_some() as usize
            + self.rotavapor_operating_time_hours.is_some() as usize
            + self.rotavapor_rotation_hours.is_some() as usize
            + self.rotavapor_lift_moves.is_some() as usize
            + self.pump_operating_time_hours.is_some() as usize
            + self.pump_module1_switch_on.is_some() as usize
            + self.pump_module1_over_current_milli_count.is_some() as usize
            + self.pump_module1_max_current_milli_amps.is_some() as usize
            + self.pump_module1_max_temperature_milli_celsius.is_some() as usize
            + self.pump_module2_switch_on.is_some() as usize
            + self.pump_module2_over_current_milli_count.is_some() as usize
            + self.pump_module2_max_current_milli_amps.is_some() as usize
            + self.pump_module2_max_temperature_milli_celsius.is_some() as usize
            + self.vacubox_operating_time_hours.is_some() as usize
    }
}
