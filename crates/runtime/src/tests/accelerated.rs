use super::{
    http_ok, http_status, verified_client_task, verified_data_access, ScriptedTransport, INFO_JSON,
    PROCESS_JSON, SETTINGS_JSON,
};
use crate::{
    lookup_default_namespace_runtime_node, BuchiClientTaskStep, DataChangeSubscription,
    EndpointPollScheduler, RuntimeDataAccess, RuntimeNode, RUNTIME_NODE_CONTRACTS,
};
use opta_buchi::{BuchiTransportIoError, Endpoint};
use opta_gateway_contracts::{freshness::ScalarValue, opcua_status, product};

#[path = "../../../../tools/accelerated_time_test_support.rs"]
mod support;
#[path = "../../../../tools/accelerated_tag_test_support.rs"]
mod tag_support;

fn load_all<const CAPACITY: usize>(data: &mut RuntimeDataAccess<CAPACITY>, stamp: u64) {
    for (endpoint, body) in [
        (Endpoint::Process, PROCESS_JSON),
        (Endpoint::Settings, SETTINGS_JSON),
        (Endpoint::Info, INFO_JSON),
    ] {
        let response = http_ok(body);
        data.apply_http_response(endpoint, &response, response.len(), stamp)
            .unwrap();
    }
    for contract in RUNTIME_NODE_CONTRACTS
        .iter()
        .filter(|c| c.node.index() < RuntimeNode::InfoBathAttached.index())
    {
        let metadata = data.cache().validation_metadata(contract.node);
        support::admit_publication(
            stamp,
            contract.node.freshness_ms(),
            metadata.last_publish_monotonic_ms,
            metadata.freshness_ms,
            metadata.published,
        )
        .unwrap();
    }
}

#[test]
fn accelerated_every_field_stalls_with_live_siblings_then_recovers() {
    let mut cases = 0;
    let mut default_cases = 0;
    for origin in support::origins() {
        let mut baseline = verified_data_access::<4>();
        assert!(baseline.trust_verified());
        assert_eq!(baseline.write_queue_depth(), 0);
        load_all(&mut baseline, origin);
        for contract in RUNTIME_NODE_CONTRACTS {
            if contract.node.index() >= RuntimeNode::InfoBathAttached.index()
                || lookup_default_namespace_runtime_node(contract.node).is_none()
            {
                continue;
            }
            let node = contract.node;
            let body = match contract.endpoint {
                Endpoint::Process => PROCESS_JSON,
                Endpoint::Settings => SETTINGS_JSON,
                Endpoint::Info => INFO_JSON,
            };
            let http = http_ok(body);
            let values =
                opta_buchi::parse_endpoint_http_response(contract.endpoint, &http, http.len())
                    .unwrap();
            let stalled = tag_support::without_field(&format!("{node:?}"), values);
            let absent_is_zero = matches!(
                node,
                RuntimeNode::ProcessGlobalStatusProcessTime | RuntimeNode::ProcessGlobalStatusRunId
            );
            let limit = u64::from(node.freshness_ms());
            for age in [limit - 1, limit, limit + 1]
                .into_iter()
                .chain((1..=8).map(|k| k * support::EPOCH_MS))
            {
                let mut data = baseline.clone();
                let mut observer = DataChangeSubscription::<1>::new();
                assert!(observer.add_runtime_node(node, 1).slot.is_some());
                assert_eq!(
                    observer.sample_slot(0, &data, origin).unwrap().opcua_status,
                    opcua_status::GOOD
                );
                let now = origin + age;
                data.apply_endpoint_values(stalled, now);
                let metadata = data.cache().validation_metadata(node);
                support::admit_publication(
                    if absent_is_zero { now } else { origin },
                    node.freshness_ms(),
                    metadata.last_publish_monotonic_ms,
                    metadata.freshness_ms,
                    metadata.published,
                )
                .unwrap();
                for sibling in RUNTIME_NODE_CONTRACTS.iter().filter(|c| {
                    c.endpoint == contract.endpoint
                        && c.node != node
                        && c.node.index() < RuntimeNode::InfoBathAttached.index()
                        && lookup_default_namespace_runtime_node(c.node).is_some()
                }) {
                    let metadata = data.cache().validation_metadata(sibling.node);
                    support::admit_publication(
                        now,
                        sibling.node.freshness_ms(),
                        metadata.last_publish_monotonic_ms,
                        metadata.freshness_ms,
                        metadata.published,
                    )
                    .unwrap();
                    assert_eq!(
                        data.read_node(sibling.node, now).opcua_status,
                        opcua_status::GOOD
                    );
                }
                let good = absent_is_zero || age <= limit;
                assert_eq!(
                    data.read_node(node, now).opcua_status == opcua_status::GOOD,
                    good
                );
                assert_eq!(
                    observer.sample_slot(0, &data, now).unwrap().opcua_status == opcua_status::GOOD,
                    good
                );
                if absent_is_zero {
                    assert_eq!(
                        data.read_node(node, now).value,
                        Some(ScalarValue::UInt32(0))
                    );
                    default_cases += 1;
                }
                data.apply_endpoint_values(values, now + 1000);
                assert_eq!(
                    data.read_node(node, now + 1000).opcua_status,
                    opcua_status::GOOD
                );
                let recovered = observer.sample_slot(0, &data, now + 1000).unwrap();
                assert_eq!(recovered.opcua_status, opcua_status::GOOD);
                if !good {
                    assert!(recovered.changed);
                }
                assert_eq!(
                    data.read_node(node, now + 1000).value,
                    baseline.read_node(node, origin).value
                );
                println!("field_case origin={origin} node={node:?} endpoint={:?} freshness={limit} age={age} missing_zero={absent_is_zero} good={good} recovered=true", contract.endpoint);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 80 * 106 * 11);
    assert_eq!(default_cases, 2 * 106 * 11);
    println!(
        "PASS per-field live-sibling recovery cases={cases} accepted-zero-cases={default_cases}"
    );
}

#[test]
fn accelerated_sparse_subscription_does_not_alias_whole_epochs() {
    let mut data = verified_data_access::<4>();
    let origin = 1_000;
    load_all(&mut data, origin);
    let mut subscription = DataChangeSubscription::<1>::new();
    subscription.add_runtime_node(RuntimeNode::ProcessHeatingSet, 1);
    assert_eq!(
        subscription
            .sample_slot(0, &data, origin)
            .unwrap()
            .opcua_status,
        opcua_status::GOOD
    );
    let now = origin + support::EPOCH_MS;
    assert_ne!(
        data.read_node(RuntimeNode::ProcessHeatingSet, now)
            .opcua_status,
        opcua_status::GOOD
    );
    let sample = subscription
        .sample_slot(0, &data, now)
        .expect("a whole elapsed epoch must not look like zero sampling age");
    assert_ne!(sample.opcua_status, opcua_status::GOOD);
    assert!(sample.changed);
}

#[test]
fn accelerated_all_data_tags_direct_and_sampled_quality() {
    let mut cases = 0;
    for origin in support::origins() {
        let mut data = verified_data_access::<4>();
        load_all(&mut data, origin);
        for contract in RUNTIME_NODE_CONTRACTS {
            // Attachment indicators express retained discovery state, not a
            // timestamped numeric measurement; their hysteresis has its own tests.
            if contract.node.index() >= RuntimeNode::InfoBathAttached.index() {
                continue;
            }
            if lookup_default_namespace_runtime_node(contract.node).is_none() {
                continue;
            }
            let mut subscription = DataChangeSubscription::<1>::new();
            let added = subscription.add_runtime_node(contract.node, 1);
            assert!(added.slot.is_some(), "unmapped node: {:?}", contract.node);
            let initial = subscription.sample_slot(0, &data, origin).unwrap();
            assert_eq!(
                initial.opcua_status,
                opcua_status::GOOD,
                "{:?}",
                contract.node
            );
            for age in [
                u64::from(contract.node.freshness_ms()) - 1,
                u64::from(contract.node.freshness_ms()),
                u64::from(contract.node.freshness_ms()) + 1,
                support::EPOCH_MS,
                2 * support::EPOCH_MS,
                8 * support::EPOCH_MS,
            ] {
                let now = origin + age;
                let expected_good = age <= u64::from(contract.node.freshness_ms());
                let read = data.read_node(contract.node, now);
                assert_eq!(
                    read.opcua_status == opcua_status::GOOD,
                    expected_good,
                    "node={:?} origin={origin} age={age}",
                    contract.node
                );
                // Each independent sparse observation retains the original
                // sampled object, with no intermediate callbacks or reseeding.
                let mut observer = subscription;
                let sampled = observer.sample_slot(0, &data, now).unwrap();
                assert_eq!(sampled.opcua_status == opcua_status::GOOD, expected_good);
                cases += 1;
            }
        }
    }
    println!("PASS runtime direct/sample quality cases={cases}");
}

#[test]
fn accelerated_poll_groups_deadline_edges_and_late_rescheduling() {
    for origin in support::origins() {
        let mut scheduler = EndpointPollScheduler::new(origin as u32);
        // Check every actual initial deadline before mark_polled overwrites it.
        for endpoint in [Endpoint::Process, Endpoint::Settings, Endpoint::Info] {
            support::admit_origin(
                origin % support::EPOCH_MS,
                u64::from(scheduler.next_due_ms(endpoint)),
                scheduler.last_poll_ms(endpoint).is_none(),
            )
            .unwrap();
        }
        for (phase, endpoint) in [Endpoint::Process, Endpoint::Settings, Endpoint::Info]
            .into_iter()
            .enumerate()
        {
            let polled = origin + phase as u64 * 137;
            scheduler.mark_polled(endpoint, polled as u32);
            support::admit_deadline(polled, endpoint.poll_ms(), scheduler.next_due_ms(endpoint))
                .unwrap();
        }
        for endpoint in [Endpoint::Process, Endpoint::Settings, Endpoint::Info] {
            let due = scheduler.next_due_ms(endpoint);
            assert!(!scheduler
                .due_endpoints(due.wrapping_sub(1))
                .contains(endpoint));
            assert!(scheduler.due_endpoints(due).contains(endpoint));
            assert!(scheduler
                .due_endpoints(due.wrapping_add(1))
                .contains(endpoint));
            let late = due.wrapping_add(700);
            scheduler.mark_polled(endpoint, late);
            let expected =
                ((u64::from(late) + u64::from(endpoint.poll_ms())) % support::EPOCH_MS) as u32;
            assert_eq!(scheduler.next_due_ms(endpoint), expected);
            assert!(!scheduler.due_endpoints(late).contains(endpoint));
        }
    }
}

#[test]
fn accelerated_repeated_poll_and_write_transport_lifecycles() {
    let mut task = verified_client_task::<
        { product::BUCHI_WRITE_QUEUE_CAPACITY },
        { product::BUCHI_WRITE_JSON_BYTES },
        { product::BUCHI_HTTP_REQUEST_BYTES },
        { product::BUCHI_HTTP_RESPONSE_BYTES },
    >(0);
    let mut scratch = [0u8; product::BUCHI_HTTP_RESPONSE_BYTES];
    let mut now = 0u64;
    let mut counts = [0usize; 3];
    let mut writes = 0;
    let mut errors = 0;
    let mut write_errors = 0;
    let mut operations = 0;
    // The same owner is retained through every acquire/use/release cycle.
    for cycle in 0..10_000 {
        for (index, endpoint, body) in [
            (0, Endpoint::Process, PROCESS_JSON),
            (1, Endpoint::Settings, SETTINGS_JSON),
            (2, Endpoint::Info, INFO_JSON),
        ] {
            let response = if cycle % 17 == 0 {
                http_status(503, b"{}")
            } else {
                http_ok(body)
            };
            let reads = [Ok(response.as_slice())];
            let mut transport = ScriptedTransport::new(&[], &reads);
            assert_eq!(task.in_flight_kind(), None);
            for step in 0..8 {
                operations += 1;
                let result = task
                    .poll_transport_step(
                        now,
                        "simulator.local",
                        "cm86cm8=",
                        "cndyOnJ3",
                        0,
                        &mut transport,
                        &mut scratch,
                    )
                    .unwrap();
                if let BuchiClientTaskStep::Completed(completion) = result {
                    let crate::BuchiClientTransactionCompletion::Poll(completion) = completion
                    else {
                        panic!("wrong lifecycle")
                    };
                    assert_eq!(completion.endpoint, endpoint);
                    assert_eq!(completion.result.is_err(), cycle % 17 == 0,
                        "poll outcome differs from declared response: cycle={cycle} endpoint={endpoint:?}");
                    if let Ok(report) = completion.result {
                        assert_eq!(report.last_http_status, Some(200));
                        assert!(report.summary.published_values > 0);
                    } else {
                        errors += 1;
                    }
                    counts[index] += 1;
                    break;
                }
                assert!(step < 7, "poll exceeded bounded transport steps");
            }
            assert_eq!(task.in_flight_kind(), None);
        }
        // Observe failed groups only after their cache deadlines have elapsed.
        // Advance the workload clock itself so later writes/polls never rewind.
        if cycle % 17 == 0 {
            now += u64::from(product::BUCHI_INFO_FRESHNESS_MS) + 1;
        }
        for node in [
            RuntimeNode::ProcessHeatingSet,
            RuntimeNode::SettingsProgramEcoEnabled,
            RuntimeNode::InfoControllerOperatingTimeHours,
        ] {
            assert_eq!(
                task.runtime()
                    .data_access()
                    .read_node(node, now)
                    .opcua_status
                    == opcua_status::GOOD,
                cycle % 17 != 0,
                "poll quality/recovery cycle={cycle} node={node:?}"
            );
        }
        assert!(
            task.runtime_mut()
                .data_access_mut()
                .enqueue_write_node(
                    RuntimeNode::ProcessHeatingSet,
                    ScalarValue::FloatMilli(42_000)
                )
                .accepted
        );
        let response = if cycle % 19 == 0 {
            http_status(503, b"{}")
        } else {
            http_ok(b"{}")
        };
        let reads = [Ok(response.as_slice())];
        let mut transport = ScriptedTransport::new(&[], &reads);
        for step in 0..8 {
            operations += 1;
            let result = task
                .poll_transport_step(
                    now,
                    "simulator.local",
                    "cm86cm8=",
                    "cndyOnJ3",
                    0,
                    &mut transport,
                    &mut scratch,
                )
                .unwrap();
            if let BuchiClientTaskStep::Completed(crate::BuchiClientTransactionCompletion::Write(
                completion,
            )) = result
            {
                assert_eq!(
                    completion.http_status,
                    if cycle % 19 == 0 { 503 } else { 200 }
                );
                assert_eq!(
                    completion.opcua_status,
                    if cycle % 19 == 0 {
                        opcua_status::BAD_RESOURCE_UNAVAILABLE
                    } else {
                        opcua_status::GOOD
                    }
                );
                if cycle % 19 == 0 {
                    write_errors += 1;
                }
                writes += 1;
                break;
            }
            assert!(step < 7, "write exceeded bounded transport steps");
        }
        assert_eq!(task.in_flight_kind(), None);
        assert_eq!(task.runtime().data_access().write_queue_depth(), 0);
        if (cycle + 1) % 100 == 0 {
            println!(
                "checkpoint cycles={} in_flight=0 queue=0 polls={counts:?} writes={writes}",
                cycle + 1
            );
        }
        now += u64::from(product::INFO_POLL_MS);
    }
    assert_eq!(counts, [10_000; 3]);
    assert_eq!(writes, 10_000);
    assert_eq!(errors, 1_767);
    assert_eq!(write_errors, 527);
    println!("PASS polling/write completed cycles={counts:?}/{writes} operations={operations} response_errors={errors} write_errors={write_errors}");
}

#[test]
fn accelerated_transport_failure_releases_in_flight_owner() {
    let mut task = verified_client_task::<4, 256, 1_024, 8_192>(0);
    let mut scratch = [0u8; 8_192];
    let steps = [Err(BuchiTransportIoError::WriteFailed)];
    let mut transport = ScriptedTransport::new(&steps, &[]);
    task.poll_transport_step(
        0,
        "simulator.local",
        "ro",
        "rw",
        0,
        &mut transport,
        &mut scratch,
    )
    .unwrap();
    assert!(task
        .poll_transport_step(
            0,
            "simulator.local",
            "ro",
            "rw",
            0,
            &mut transport,
            &mut scratch
        )
        .is_err());
    assert_eq!(
        task.in_flight_kind(),
        None,
        "transport error retained its transaction"
    );
    // Fresh admission and successful exchange after cleanup prove reuse.
    let response = http_ok(PROCESS_JSON);
    let reads = [Ok(response.as_slice())];
    let mut recovered = ScriptedTransport::new(&[], &reads);
    let mut completed = false;
    for _ in 0..8 {
        let step = task
            .poll_transport_step(
                1_000,
                "simulator.local",
                "ro",
                "rw",
                0,
                &mut recovered,
                &mut scratch,
            )
            .unwrap();
        if matches!(step, BuchiClientTaskStep::Completed(_)) {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(task.in_flight_kind(), None);
}

#[test]
fn accelerated_mixed_traces_100_seeds_1000_events() {
    let origins = support::origins();
    for trace in 0..100u64 {
        let seed = 0xacce_1e7a_0000_0000u64 + trace;
        let mut random = seed;
        let mut now = origins[trace as usize % origins.len()];
        let mut data = verified_data_access::<4>();
        load_all(&mut data, now);
        let mut stamp = now;
        let mut trusted = true;
        let mut observer = DataChangeSubscription::<1>::new();
        observer.add_runtime_node(RuntimeNode::ProcessHeatingSet, 1);
        let start = std::time::Instant::now();
        for event in 0..1_000 {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let action = (random >> 32) % 6;
            now += if action == 5 {
                support::EPOCH_MS
            } else {
                1_000 + random % 2_001
            };
            match action {
                0 | 1 => {
                    if trusted {
                        let response = http_ok(PROCESS_JSON);
                        data.apply_http_response(Endpoint::Process, &response, response.len(), now)
                            .unwrap();
                        stamp = now;
                    }
                }
                2 => {
                    data.revoke_upstream_trust();
                    trusted = false;
                }
                3 => {
                    data.set_trust_state(opta_gateway_contracts::config::TrustState::Verified);
                    load_all(&mut data, now);
                    stamp = now;
                    trusted = true;
                }
                4 | 5 => {}
                _ => unreachable!(),
            }
            let good = trusted && now - stamp <= u64::from(product::BUCHI_PROCESS_FRESHNESS_MS);
            let direct = data.read_node(RuntimeNode::ProcessHeatingSet, now);
            let sample = observer.sample_slot(0, &data, now).unwrap();
            println!("trace={trace} seed={seed} event={event} action={action} now_ms={now} last_accepted_ms={stamp} trusted={trusted} expected_good={good} direct={} sample={}", direct.opcua_status, sample.opcua_status);
            assert_eq!(direct.opcua_status == opcua_status::GOOD, good);
            assert_eq!(sample.opcua_status == opcua_status::GOOD, good);
        }
        // A two-second directed host batch established the baseline. A sixty
        // second per-trace guard permits host contention without masking hangs.
        assert!(
            start.elapsed().as_secs() < 60,
            "trace wall-time guard exceeded"
        );
    }
    println!("PASS mixed traces=100 events=100000");
}

#[test]
fn accelerated_repeated_write_coalescing_refusal_and_trust_cleanup() {
    let mut data = verified_data_access::<1>();
    let mut completed = 0;
    let mut revoked = 0;
    for cycle in 0..10_000 {
        assert_eq!(data.write_queue_depth(), 0);
        let first = data.enqueue_write_node(
            RuntimeNode::ProcessHeatingSet,
            ScalarValue::FloatMilli(1_000),
        );
        assert!(first.accepted && !first.coalesced);
        let replacement = data.enqueue_write_node(
            RuntimeNode::ProcessHeatingSet,
            ScalarValue::FloatMilli(2_000),
        );
        assert!(replacement.accepted && replacement.coalesced);
        let full = data.enqueue_write_node(
            RuntimeNode::ProcessRotationRunning,
            ScalarValue::Boolean(true),
        );
        assert!(!full.accepted);
        assert_eq!(full.opcua_status, opcua_status::BAD_RESOURCE_UNAVAILABLE);
        assert_eq!(data.write_queue_depth(), 1);
        if cycle % 2 == 0 {
            let request = data.pop_write_request().unwrap();
            assert_eq!(request.raw_value, 2_000);
            assert_eq!(request.sequence, replacement.sequence.unwrap());
            completed += 1;
        } else {
            data.revoke_upstream_trust();
            assert_eq!(data.write_queue_depth(), 0);
            assert!(!data.writes_allowed());
            data.set_trust_state(opta_gateway_contracts::config::TrustState::Verified);
            // Match reprovisioning: restore the explicit preference only once
            // usable trust has been established again.
            data.set_write_enabled(true);
            revoked += 1;
        }
        assert_eq!(data.pop_write_request(), None);
        // A distinct key succeeds after refusal cleanup, every cycle.
        assert!(
            data.enqueue_write_node(
                RuntimeNode::ProcessRotationRunning,
                ScalarValue::Boolean(true)
            )
            .accepted
        );
        assert!(data.pop_write_request().is_some());
        assert_eq!(data.write_queue_depth(), 0);
        if (cycle + 1) % 100 == 0 {
            println!(
                "checkpoint queue_cycles={} depth=0 completed={completed} revoked={revoked}",
                cycle + 1
            );
        }
    }
    assert_eq!((completed, revoked), (5_000, 5_000));
    assert!(
        data.enqueue_write_node(
            RuntimeNode::ProcessHeatingSet,
            ScalarValue::FloatMilli(3_000)
        )
        .accepted
    );
    assert!(data.pop_write_request().is_some());
    assert_eq!(data.write_queue_depth(), 0);
    println!("PASS queue cycles=10000 coalesced=10000 refused=10000 recovered=10001; capacity-one generic refusal fixture");
}
