// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Host-only partial-publication inputs. Parsed fixtures stay intact except
//! for the named field. Two idle-run fields deliberately accept absent-as-zero.
use opta_buchi::EndpointValues;

pub fn without_field(node: &str, values: EndpointValues) -> EndpointValues {
    match values {
        EndpointValues::Process(mut values) => {
            match node {
                "ProcessHeatingSet" => values.heating_set_milli_celsius = None,
                "ProcessBathTemperature" => values.bath_temperature_milli_celsius = None,
                "ProcessHeatingRunning" => values.heating_running = None,
                "ProcessCoolingSet" => values.cooling_set_milli_celsius = None,
                "ProcessCoolingActual" => values.cooling_actual_milli_celsius = None,
                "ProcessCoolingRunning" => values.cooling_running = None,
                "ProcessVacuumSet" => values.vacuum_set_mbar = None,
                "ProcessRotationSpeed" => values.rotation_speed_milli_rpm = None,
                "ProcessPressure" => values.pressure_milli_mbar = None,
                "ProcessVacuumAerateValveOpen" => values.vacuum_aerate_valve_open = None,
                "ProcessVacuumAerateValvePulse" => values.vacuum_aerate_valve_pulse = None,
                "ProcessVacuumValveOpen" => values.vacuum_valve_open = None,
                "ProcessVacuumVaporTemperature" => {
                    values.vacuum_vapor_temperature_milli_celsius = None
                }
                "ProcessVacuumAutoDestinationIn" => {
                    values.vacuum_auto_destination_in_milli_celsius = None
                }
                "ProcessVacuumAutoDestinationOut" => {
                    values.vacuum_auto_destination_out_milli_celsius = None
                }
                "ProcessVacuumPowerPercent" => values.vacuum_power_percent_milli_percent = None,
                "ProcessVacuumRunning" => values.vacuum_running = None,
                "ProcessRotationSet" => values.rotation_set_rpm = None,
                "ProcessRotationRunning" => values.rotation_running = None,
                "ProcessLiftSet" => values.lift_set_milli_millimeters = None,
                "ProcessLiftActual" => values.lift_actual_milli_millimeters = None,
                "ProcessLiftLimit" => values.lift_limit_milli_millimeters = None,
                "ProcessGlobalStatusProcessTime" => {
                    values.global_status_process_time_seconds = None
                }
                "ProcessGlobalStatusRunId" => values.global_status_run_id = None,
                "ProcessGlobalStatusRunning" => values.process_state = None,
                "ProcessGlobalStatusOnHold" => values.global_status_on_hold = None,
                "ProcessGlobalStatusFoamActive" => values.global_status_foam_active = None,
                "ProcessGlobalStatusCurrentError" => values.global_status_current_error = None,
                _ => panic!("field does not belong to endpoint: {node}"),
            }
            EndpointValues::Process(values)
        }
        EndpointValues::Settings(mut values) => {
            match node {
                "SettingsDisplayBrightness" => values.display_brightness_percent = None,
                "SettingsDisplayUtcOffset" => values.display_utc_offset_minutes = None,
                "SettingsSoundsButtonTone" => values.sounds_button_tone = None,
                "SettingsSoundsPlaySoundOnFinish" => values.sounds_play_sound_on_finish = None,
                "SettingsVacuumPressureHysteresis" => values.vacuum_pressure_hysteresis_mbar = None,
                "SettingsVacuumAltitude" => values.vacuum_altitude_meters = None,
                "SettingsVacuumMaxPermPressure" => values.vacuum_max_perm_pressure_mbar = None,
                "SettingsVacuumMaxPumpOutput" => values.vacuum_max_pump_output_percent = None,
                "SettingsVacuumVentOnFinish" => values.vacuum_vent_on_finish = None,
                "SettingsRotationStopOnFinish" => values.rotation_stop_on_finish = None,
                "SettingsHeatingMaxTemperature" => {
                    values.heating_max_temperature_milli_celsius = None
                }
                "SettingsHeatingStopOnFinish" => values.heating_stop_on_finish = None,
                "SettingsCoolingStopOnFinish" => values.cooling_stop_on_finish = None,
                "SettingsLiftDepthStop" => values.lift_depth_stop_milli_millimeters = None,
                "SettingsLiftImmerseOnStart" => values.lift_immerse_on_start = None,
                "SettingsLiftOutFlaskOnFinish" => values.lift_out_flask_on_finish = None,
                "SettingsRotationStartOnStart" => values.rotation_start_on_start = None,
                "SettingsProgramEcoEnabled" => values.program_eco_enabled = None,
                "SettingsProgramEcoActivationAfterMins" => {
                    values.program_eco_activation_after_mins = None
                }
                "SettingsProgramEcoHeatingBathTemperature" => {
                    values.program_eco_heating_bath_temperature_milli_celsius = None
                }
                "SettingsProgramEcoCoolantTemperature" => {
                    values.program_eco_coolant_temperature_milli_celsius = None
                }
                _ => panic!("field does not belong to endpoint: {node}"),
            }
            EndpointValues::Settings(values)
        }
        EndpointValues::Info(mut values) => {
            match node {
                "InfoControllerOperatingTimeHours" => values.controller_operating_time_hours = None,
                "InfoControllerRunTotalRuns" => values.controller_run_total_runs = None,
                "InfoControllerRunManual" => values.controller_run_manual = None,
                "InfoControllerRunTimer" => values.controller_run_timer = None,
                "InfoControllerRunContinuous" => values.controller_run_continuous = None,
                "InfoControllerRunSolvent" => values.controller_run_solvent = None,
                "InfoControllerRunMethod" => values.controller_run_method = None,
                "InfoControllerRunAutoDest" => values.controller_run_auto_dest = None,
                "InfoControllerRunCloudDest" => values.controller_run_cloud_dest = None,
                "InfoControllerRunDrying" => values.controller_run_drying = None,
                "InfoControllerRunLeakTest" => values.controller_run_leak_test = None,
                "InfoControllerRunCalibration" => values.controller_run_calibration = None,
                "InfoBathOperatingTimeHours" => values.bath_operating_time_hours = None,
                "InfoBathHoursOver190c" => values.bath_hours_over_190c = None,
                "InfoChillerOperatingTimeHours" => values.chiller_operating_time_hours = None,
                "InfoChillerPumpHours" => values.chiller_pump_hours = None,
                "InfoChillerCompressorHours" => values.chiller_compressor_hours = None,
                "InfoChillerValveCounter" => values.chiller_valve_counter = None,
                "InfoRotavaporOperatingTimeHours" => values.rotavapor_operating_time_hours = None,
                "InfoRotavaporRotationHours" => values.rotavapor_rotation_hours = None,
                "InfoRotavaporLiftMoves" => values.rotavapor_lift_moves = None,
                "InfoPumpOperatingTimeHours" => values.pump_operating_time_hours = None,
                "InfoPumpModule1SwitchOn" => values.pump_module1_switch_on = None,
                "InfoPumpModule1OverCurrent" => values.pump_module1_over_current_milli_count = None,
                "InfoPumpModule1MaxCurrent" => values.pump_module1_max_current_milli_amps = None,
                "InfoPumpModule1MaxTemperature" => {
                    values.pump_module1_max_temperature_milli_celsius = None
                }
                "InfoPumpModule2SwitchOn" => values.pump_module2_switch_on = None,
                "InfoPumpModule2OverCurrent" => values.pump_module2_over_current_milli_count = None,
                "InfoPumpModule2MaxCurrent" => values.pump_module2_max_current_milli_amps = None,
                "InfoPumpModule2MaxTemperature" => {
                    values.pump_module2_max_temperature_milli_celsius = None
                }
                "InfoVacuboxOperatingTimeHours" => values.vacubox_operating_time_hours = None,
                _ => panic!("field does not belong to endpoint: {node}"),
            }
            EndpointValues::Info(values)
        }
    }
}
