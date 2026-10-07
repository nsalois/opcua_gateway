// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use opta_buchi::{
    parse_info_json, parse_process_json, parse_settings_json, Endpoint, EndpointValues,
    InfoRootPresence, InfoValues, ProcessRootPresence, ProcessValues, SettingsRootPresence,
    SettingsValues,
};
use opta_gateway_contracts::freshness::CacheReadStatus;
use opta_runtime::{RuntimeCache, RuntimeNode, RUNTIME_NODE_CONTRACTS};

fn http_ok(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Stable set of nodes ordered by index (`RuntimeNode` is not Ord/Hash).
fn ok_nodes(cache: &RuntimeCache, now: u64) -> Vec<RuntimeNode> {
    let mut nodes: Vec<RuntimeNode> = RUNTIME_NODE_CONTRACTS
        .iter()
        .map(|contract| contract.node)
        .filter(|node| cache.read(*node, now).status == CacheReadStatus::Ok)
        .collect();
    nodes.sort_by_key(|node| node.index());
    nodes
}

fn published_by(values: EndpointValues) -> Vec<RuntimeNode> {
    let mut cache = RuntimeCache::new();
    cache.apply_endpoint_values(values, 100);
    ok_nodes(&cache, 100)
}

fn set_contains(haystack: &[RuntimeNode], needle: RuntimeNode) -> bool {
    haystack.contains(&needle)
}

fn set_difference(left: &[RuntimeNode], right: &[RuntimeNode]) -> Vec<RuntimeNode> {
    left.iter()
        .copied()
        .filter(|node| !set_contains(right, *node))
        .collect()
}

fn set_intersection(left: &[RuntimeNode], right: &[RuntimeNode]) -> Vec<RuntimeNode> {
    left.iter()
        .copied()
        .filter(|node| set_contains(right, *node))
        .collect()
}

/// Nodes published by `full` but not by `minus` — the publish-path ownership of
/// the omitted root (BH-6 drift guard derivation).
fn owned_by_difference(full: EndpointValues, minus: EndpointValues) -> Vec<RuntimeNode> {
    let full_set = published_by(full);
    let minus_set = published_by(minus);
    set_difference(&full_set, &minus_set)
}

fn full_process() -> ProcessValues {
    ProcessValues {
        roots: ProcessRootPresence {
            heating: true,
            cooling: true,
            vacuum: true,
            rotation: true,
            lift: true,
            global_status: true,
        },
        process_state: Some(1),
        heating_set_milli_celsius: Some(42_125),
        bath_temperature_milli_celsius: Some(41_875),
        heating_running: Some(true),
        cooling_set_milli_celsius: Some(-5_500),
        cooling_actual_milli_celsius: Some(4_250),
        cooling_running: Some(false),
        vacuum_set_mbar: Some(125),
        rotation_speed_milli_rpm: Some(120_500),
        pressure_milli_mbar: Some(124_875),
        vacuum_aerate_valve_open: Some(true),
        vacuum_aerate_valve_pulse: Some(false),
        vacuum_valve_open: Some(true),
        vacuum_vapor_temperature_milli_celsius: Some(65_500),
        vacuum_auto_destination_in_milli_celsius: Some(52_250),
        vacuum_auto_destination_out_milli_celsius: Some(48_750),
        vacuum_power_percent_milli_percent: Some(75_000),
        vacuum_running: Some(true),
        rotation_set_rpm: Some(120),
        rotation_running: Some(true),
        lift_set_milli_millimeters: Some(220_000),
        lift_actual_milli_millimeters: Some(110_250),
        lift_limit_milli_millimeters: Some(200_500),
        global_status_process_time_seconds: Some(1_234),
        global_status_run_id: Some(42),
        global_status_on_hold: Some(false),
        global_status_foam_active: Some(true),
        global_status_current_error: Some(-12),
    }
}

fn process_without(root: &str) -> ProcessValues {
    let mut values = full_process();
    match root {
        "heating" => {
            values.roots.heating = false;
            values.heating_set_milli_celsius = None;
            values.bath_temperature_milli_celsius = None;
            values.heating_running = None;
        }
        "cooling" => {
            values.roots.cooling = false;
            values.cooling_set_milli_celsius = None;
            values.cooling_actual_milli_celsius = None;
            values.cooling_running = None;
        }
        "vacuum" => {
            values.roots.vacuum = false;
            values.vacuum_set_mbar = None;
            values.pressure_milli_mbar = None;
            values.vacuum_aerate_valve_open = None;
            values.vacuum_aerate_valve_pulse = None;
            values.vacuum_valve_open = None;
            values.vacuum_vapor_temperature_milli_celsius = None;
            values.vacuum_auto_destination_in_milli_celsius = None;
            values.vacuum_auto_destination_out_milli_celsius = None;
            values.vacuum_power_percent_milli_percent = None;
            values.vacuum_running = None;
        }
        "rotation" => {
            values.roots.rotation = false;
            values.rotation_speed_milli_rpm = None;
            values.rotation_set_rpm = None;
            values.rotation_running = None;
        }
        "lift" => {
            values.roots.lift = false;
            values.lift_set_milli_millimeters = None;
            values.lift_actual_milli_millimeters = None;
            values.lift_limit_milli_millimeters = None;
        }
        "global_status" => {
            values.roots.global_status = false;
            values.process_state = None;
            values.global_status_process_time_seconds = None;
            values.global_status_run_id = None;
            values.global_status_on_hold = None;
            values.global_status_foam_active = None;
            values.global_status_current_error = None;
        }
        other => panic!("unknown process root {other}"),
    }
    values
}

fn full_settings() -> SettingsValues {
    SettingsValues {
        roots: SettingsRootPresence {
            display: true,
            sounds: true,
            vacuum: true,
            rotation: true,
            heating: true,
            cooling: true,
            lift: true,
            program: true,
        },
        display_brightness_percent: Some(75),
        display_utc_offset_minutes: Some(-330),
        sounds_button_tone: Some(true),
        sounds_play_sound_on_finish: Some(false),
        vacuum_pressure_hysteresis_mbar: Some(125),
        vacuum_altitude_meters: Some(1_234),
        vacuum_max_perm_pressure_mbar: Some(1_000),
        vacuum_max_pump_output_percent: Some(80),
        vacuum_vent_on_finish: Some(true),
        rotation_stop_on_finish: Some(false),
        heating_max_temperature_milli_celsius: Some(180_000),
        heating_stop_on_finish: Some(true),
        cooling_stop_on_finish: Some(false),
        lift_depth_stop_milli_millimeters: Some(120_500),
        lift_immerse_on_start: Some(true),
        lift_out_flask_on_finish: Some(false),
        rotation_start_on_start: Some(true),
        program_eco_enabled: Some(true),
        program_eco_activation_after_mins: Some(15),
        program_eco_heating_bath_temperature_milli_celsius: Some(42_125),
        program_eco_coolant_temperature_milli_celsius: Some(12_500),
    }
}

fn settings_without(root: &str) -> SettingsValues {
    let mut values = full_settings();
    match root {
        "display" => {
            values.roots.display = false;
            values.display_brightness_percent = None;
            values.display_utc_offset_minutes = None;
        }
        "sounds" => {
            values.roots.sounds = false;
            values.sounds_button_tone = None;
            values.sounds_play_sound_on_finish = None;
        }
        "vacuum" => {
            values.roots.vacuum = false;
            values.vacuum_pressure_hysteresis_mbar = None;
            values.vacuum_altitude_meters = None;
            values.vacuum_max_perm_pressure_mbar = None;
            values.vacuum_max_pump_output_percent = None;
            values.vacuum_vent_on_finish = None;
        }
        "rotation" => {
            values.roots.rotation = false;
            values.rotation_stop_on_finish = None;
            values.rotation_start_on_start = None;
        }
        "heating" => {
            values.roots.heating = false;
            values.heating_max_temperature_milli_celsius = None;
            values.heating_stop_on_finish = None;
        }
        "cooling" => {
            values.roots.cooling = false;
            values.cooling_stop_on_finish = None;
        }
        "lift" => {
            values.roots.lift = false;
            values.lift_depth_stop_milli_millimeters = None;
            values.lift_immerse_on_start = None;
            values.lift_out_flask_on_finish = None;
        }
        "program" => {
            values.roots.program = false;
            values.program_eco_enabled = None;
            values.program_eco_activation_after_mins = None;
            values.program_eco_heating_bath_temperature_milli_celsius = None;
            values.program_eco_coolant_temperature_milli_celsius = None;
        }
        other => panic!("unknown settings root {other}"),
    }
    values
}

fn full_info() -> InfoValues {
    InfoValues {
        roots: InfoRootPresence {
            controller: true,
            bath: true,
            chiller: true,
            rotavapor: true,
            pump: true,
            vacubox: true,
        },
        controller_operating_time_hours: Some(100),
        controller_run_total_runs: Some(10),
        controller_run_manual: Some(1),
        controller_run_timer: Some(2),
        controller_run_continuous: Some(3),
        controller_run_solvent: Some(4),
        controller_run_method: Some(5),
        controller_run_auto_dest: Some(6),
        controller_run_cloud_dest: Some(7),
        controller_run_drying: Some(8),
        controller_run_leak_test: Some(9),
        controller_run_calibration: Some(11),
        bath_operating_time_hours: Some(200),
        bath_hours_over_190c: Some(12),
        chiller_operating_time_hours: Some(300),
        chiller_pump_hours: Some(301),
        chiller_compressor_hours: Some(302),
        chiller_valve_counter: Some(303),
        rotavapor_operating_time_hours: Some(400),
        rotavapor_rotation_hours: Some(401),
        rotavapor_lift_moves: Some(402),
        pump_operating_time_hours: Some(500),
        pump_module1_switch_on: Some(501),
        pump_module1_over_current_milli_count: Some(1_250),
        pump_module1_max_current_milli_amps: Some(2_500),
        pump_module1_max_temperature_milli_celsius: Some(-3_750),
        pump_module2_switch_on: Some(601),
        pump_module2_over_current_milli_count: Some(4_125),
        pump_module2_max_current_milli_amps: Some(5_875),
        pump_module2_max_temperature_milli_celsius: Some(6_500),
        vacubox_operating_time_hours: Some(700),
    }
}

fn info_without(root: &str) -> InfoValues {
    let mut values = full_info();
    match root {
        "controller" => {
            values.roots.controller = false;
            values.controller_operating_time_hours = None;
            values.controller_run_total_runs = None;
            values.controller_run_manual = None;
            values.controller_run_timer = None;
            values.controller_run_continuous = None;
            values.controller_run_solvent = None;
            values.controller_run_method = None;
            values.controller_run_auto_dest = None;
            values.controller_run_cloud_dest = None;
            values.controller_run_drying = None;
            values.controller_run_leak_test = None;
            values.controller_run_calibration = None;
        }
        "bath" => {
            values.roots.bath = false;
            values.bath_operating_time_hours = None;
            values.bath_hours_over_190c = None;
        }
        "chiller" => {
            values.roots.chiller = false;
            values.chiller_operating_time_hours = None;
            values.chiller_pump_hours = None;
            values.chiller_compressor_hours = None;
            values.chiller_valve_counter = None;
        }
        "rotavapor" => {
            values.roots.rotavapor = false;
            values.rotavapor_operating_time_hours = None;
            values.rotavapor_rotation_hours = None;
            values.rotavapor_lift_moves = None;
        }
        "pump" => {
            values.roots.pump = false;
            values.pump_operating_time_hours = None;
            values.pump_module1_switch_on = None;
            values.pump_module1_over_current_milli_count = None;
            values.pump_module1_max_current_milli_amps = None;
            values.pump_module1_max_temperature_milli_celsius = None;
            values.pump_module2_switch_on = None;
            values.pump_module2_over_current_milli_count = None;
            values.pump_module2_max_current_milli_amps = None;
            values.pump_module2_max_temperature_milli_celsius = None;
        }
        "vacubox" => {
            values.roots.vacubox = false;
            values.vacubox_operating_time_hours = None;
        }
        other => panic!("unknown info root {other}"),
    }
    values
}

fn assert_omit_root_invalidates_exactly(
    full: EndpointValues,
    minus: EndpointValues,
    root_label: &str,
) {
    let owned = owned_by_difference(full, minus);
    assert!(
        !owned.is_empty(),
        "{root_label}: publish-path derived ownership must not be empty"
    );

    let mut cache = RuntimeCache::new();
    // Three applies so attachment indicators can reach Attached without
    // polluting the data-node ownership check (indicators lag independently).
    for now in [100_u64, 200, 300] {
        cache.apply_endpoint_values(full, now);
    }
    let before = ok_nodes(&cache, 300);
    let missing: Vec<_> = set_difference(&owned, &before);
    assert!(
        missing.is_empty(),
        "{root_label}: derived owned set must be Good after full payload; missing {missing:?}"
    );

    cache.apply_endpoint_values(minus, 400);
    let after = ok_nodes(&cache, 400);

    for node in &owned {
        assert_ne!(
            cache.read(*node, 400).status,
            CacheReadStatus::Ok,
            "{root_label}: owned node {node:?} must not stay Good after omit"
        );
    }
    let expected_still_ok = set_difference(&before, &owned);
    let unexpected_loss = set_difference(&expected_still_ok, &after);
    assert!(
        unexpected_loss.is_empty(),
        "{root_label}: sibling nodes lost Good quality: {unexpected_loss:?}"
    );
    let unexpected_gain = set_difference(&after, &before);
    assert!(
        unexpected_gain.is_empty(),
        "{root_label}: omit must not newly publish nodes: {unexpected_gain:?}"
    );
}

#[test]
fn optional_null_unknown_and_missing_global_status_are_tolerated() {
    let process =
        parse_process_json(br#"{"heating":{"act":42.5},"cooling":null,"unknown":{"x":1}}"#)
            .expect("one supported sibling field keeps partial payload usable");
    assert_eq!(process.bath_temperature_milli_celsius, Some(42_500));
    assert!(!process.roots.cooling);
    assert!(!process.roots.global_status);
    assert_eq!(process.process_state, None);

    let settings =
        parse_settings_json(br#"{"display":{"brightness":50},"sounds":null,"extra":[]}"#)
            .expect("partial settings");
    assert_eq!(settings.display_brightness_percent, Some(50));
    assert!(!settings.roots.sounds);

    let info =
        parse_info_json(br#"{"controller":{"operatingTimeCounter":1},"chiller":null,"extra":[]}"#)
            .expect("partial info");
    assert_eq!(info.controller_operating_time_hours, Some(1));
    assert!(!info.roots.chiller);
}

#[test]
fn wrong_scalar_types_do_not_poison_valid_siblings() {
    let values =
        parse_process_json(br#"{"heating":{"act":"42.5","running":null},"vacuum":{"act":125}}"#)
            .expect("valid vacuum sibling remains publishable");
    assert_eq!(values.bath_temperature_milli_celsius, None);
    assert_eq!(values.heating_running, None);
    assert_eq!(values.pressure_milli_mbar, Some(125_000));
}

#[test]
fn first_absent_optional_object_invalidates_previously_good_owned_tags() {
    let mut cache = RuntimeCache::new();
    let full = http_ok(
        br#"{"cooling":{"act":4.25},"vacuum":{"act":125},"globalStatus":{"running":true}}"#,
    );
    // Reach current three-poll Attached hysteresis first.
    for now in [100, 200, 300] {
        cache
            .apply_http_response(Endpoint::Process, &full, 4096, now)
            .unwrap();
    }
    assert_eq!(
        cache.read(RuntimeNode::ProcessCoolingActual, 300).status,
        CacheReadStatus::Ok
    );

    let missing_cooling = http_ok(br#"{"vacuum":{"act":126},"globalStatus":{"running":true}}"#);
    cache
        .apply_http_response(Endpoint::Process, &missing_cooling, 4096, 400)
        .unwrap();

    assert_ne!(
        cache.read(RuntimeNode::ProcessCoolingActual, 400).status,
        CacheReadStatus::Ok,
        "an absent optional subdevice object must not leave its old value Good"
    );
    assert_eq!(
        cache.read(RuntimeNode::ProcessPressure, 400).status,
        CacheReadStatus::Ok,
        "missing cooling must not poison the valid vacuum sibling"
    );
}

#[test]
fn startup_503_on_each_endpoint_never_creates_good_data() {
    let mut cache = RuntimeCache::new();
    let response =
        b"HTTP/1.1 503 Starting\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    for endpoint in [Endpoint::Process, Endpoint::Settings, Endpoint::Info] {
        assert!(cache
            .apply_http_response(endpoint, response, 4096, 100)
            .is_err());
    }
    for node in [
        RuntimeNode::ProcessHeatingSet,
        RuntimeNode::SettingsDisplayBrightness,
        RuntimeNode::InfoControllerOperatingTimeHours,
    ] {
        assert_ne!(cache.read(node, 100).status, CacheReadStatus::Ok);
    }
}

/// Exhaustive BH-6 drift guard: for every optional root, derive the owned node
/// set from the publish path (full vs payload-minus-root on a fresh cache), then
/// assert full→minus invalidates exactly that set.
#[test]
fn omitting_any_optional_root_invalidates_exactly_publish_owned_nodes() {
    let process_roots = [
        "heating",
        "cooling",
        "vacuum",
        "rotation",
        "lift",
        "global_status",
    ];
    let mut process_owned: Vec<Vec<RuntimeNode>> = Vec::new();
    for root in process_roots {
        let full = EndpointValues::Process(full_process());
        let minus = EndpointValues::Process(process_without(root));
        let owned = owned_by_difference(full, minus);
        process_owned.push(owned);
        assert_omit_root_invalidates_exactly(full, minus, &format!("process.{root}"));
    }
    assert_pairwise_disjoint(&process_owned, "process");

    let settings_roots = [
        "display", "sounds", "vacuum", "rotation", "heating", "cooling", "lift", "program",
    ];
    let mut settings_owned: Vec<Vec<RuntimeNode>> = Vec::new();
    for root in settings_roots {
        let full = EndpointValues::Settings(full_settings());
        let minus = EndpointValues::Settings(settings_without(root));
        let owned = owned_by_difference(full, minus);
        settings_owned.push(owned);
        assert_omit_root_invalidates_exactly(full, minus, &format!("settings.{root}"));
    }
    assert_pairwise_disjoint(&settings_owned, "settings");

    let info_roots = [
        "controller",
        "bath",
        "chiller",
        "rotavapor",
        "pump",
        "vacubox",
    ];
    let mut info_owned: Vec<Vec<RuntimeNode>> = Vec::new();
    for root in info_roots {
        let full = EndpointValues::Info(full_info());
        let minus = EndpointValues::Info(info_without(root));
        let owned = owned_by_difference(full, minus);
        info_owned.push(owned);
        assert_omit_root_invalidates_exactly(full, minus, &format!("info.{root}"));
    }
    assert_pairwise_disjoint(&info_owned, "info");
}

fn assert_pairwise_disjoint(sets: &[Vec<RuntimeNode>], endpoint: &str) {
    for (i, left) in sets.iter().enumerate() {
        for (j, right) in sets.iter().enumerate() {
            if i >= j {
                continue;
            }
            let overlap = set_intersection(left, right);
            assert!(
                overlap.is_empty(),
                "{endpoint}: roots {i} and {j} share owned nodes {overlap:?}; \
                 stop and ask operator — dual ownership is not assumed"
            );
        }
    }
}
