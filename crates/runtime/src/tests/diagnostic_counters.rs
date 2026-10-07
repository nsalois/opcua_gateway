// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Host component proof only: setters below do not establish real TLS trust.
use super::{http_ok, http_status, PROCESS_JSON};
use crate::{
    DiagnosticCounterSeed, DiagnosticCounterSnapshot, EndpointPollError, RuntimeDataAccess,
    RuntimeNode,
};
use opta_buchi::{Endpoint, EndpointResponseError, ParseError};
use opta_gateway_contracts::{config::TrustState, freshness::ScalarValue, opcua_status};

const SEEDS: [(DiagnosticCounterSeed, u32); 3] = [
    (DiagnosticCounterSeed::MaxMinusTwo, 4_294_967_293),
    (DiagnosticCounterSeed::MaxMinusOne, 4_294_967_294),
    (DiagnosticCounterSeed::Max, 4_294_967_295),
];

fn ready() -> RuntimeDataAccess<2> {
    let mut owner = RuntimeDataAccess::new();
    owner.set_verified_trust_session(true);
    owner.set_write_enabled(true);
    fetch(&mut owner, 1_000);
    let baseline = owner.read_node(RuntimeNode::ProcessHeatingSet, 1_000);
    assert_eq!(baseline.opcua_status, opcua_status::GOOD);
    assert_eq!(baseline.value, Some(ScalarValue::FloatMilli(42_125)));
    owner
}

fn fetch(owner: &mut RuntimeDataAccess<2>, now: u64) {
    let response = http_ok(PROCESS_JSON);
    owner
        .apply_http_response(Endpoint::Process, &response, response.len(), now)
        .unwrap();
}

fn write(owner: &mut RuntimeDataAccess<2>, success: bool) -> u32 {
    let accepted = owner.enqueue_write_node(
        RuntimeNode::SettingsProgramEcoEnabled,
        ScalarValue::Boolean(success),
    );
    assert!(accepted.accepted && !accepted.coalesced);
    let mut transaction = owner
        .pop_next_write_transaction::<96, 384, 128>("r300.local", "cndyOnJ3")
        .unwrap();
    assert_eq!(
        transaction.write_request().sequence,
        accepted.sequence.unwrap()
    );
    assert!(transaction
        .request()
        .starts_with(b"PUT /api/v1/settings HTTP/1.1\r\n"));
    transaction.record_write(transaction.request_len()).unwrap();
    let response = if success {
        http_ok(b"{}")
    } else {
        http_status(503, b"{}")
    };
    transaction.append_response(&response).unwrap();
    transaction.finish_extra_body_probe().unwrap();
    let result = owner
        .record_write_transaction_completion(&transaction, 0)
        .unwrap();
    assert_eq!(result.http_status, if success { 200 } else { 503 });
    assert_eq!(result.opcua_status == opcua_status::GOOD, success);
    assert_eq!(owner.write_queue_depth(), 0);
    accepted.sequence.unwrap()
}

#[test]
fn fixed_seed_reads_actual_fields_without_changing_baseline() {
    for (recipe, seed) in SEEDS {
        let mut owner = ready();
        let before = owner.read_node(RuntimeNode::ProcessHeatingSet, 1_000);
        let health_before = *owner.health();
        let admitted = owner.diagnostic_seed_counters(recipe).expect("ready owner");
        assert_eq!(
            admitted,
            DiagnosticCounterSnapshot {
                next_write_sequence: seed,
                accepted_writes: seed,
                completed_writes: seed,
                failed_writes: seed,
                successful_fetches: seed,
            }
        );
        assert_eq!(admitted, owner.diagnostic_counters());
        assert_eq!(owner.cache().completed_fetches(), seed);
        assert_eq!(owner.health().buchi_write_accepted_count, seed);
        assert_eq!(owner.health().buchi_write_completed_count, seed);
        assert_eq!(owner.health().buchi_write_failed_count, seed);
        assert_eq!(
            owner.read_node(RuntimeNode::ProcessHeatingSet, 1_000),
            before
        );
        assert_eq!(owner.cache().failed_fetches(), 0);
        assert_eq!(
            owner.health().buchi_write_queue_full_count,
            health_before.buchi_write_queue_full_count
        );
        assert_eq!(
            owner.health().buchi_write_last_target_node_id,
            health_before.buchi_write_last_target_node_id
        );
        assert!(owner.health().buchi_verifier_time_trusted);
    }
}

#[test]
fn distinct_write_lifecycles_wrap_sequence_and_saturate_health() {
    for (recipe, seed) in SEEDS {
        let mut owner = ready();
        owner.diagnostic_seed_counters(recipe).unwrap();
        let (mut good, mut bad) = (0_u64, 0_u64);
        for index in 0..10_u64 {
            let success = index % 2 == 0;
            assert_eq!(
                write(&mut owner, success),
                ((u64::from(seed) + index) % (1_u64 << 32)) as u32
            );
            if success {
                good += 1
            } else {
                bad += 1
            }
            let actual = owner.diagnostic_counters();
            assert_eq!(
                actual.next_write_sequence,
                ((u64::from(seed) + index + 1) % (1_u64 << 32)) as u32
            );
            assert_eq!(
                actual.accepted_writes,
                (u64::from(seed) + index + 1).min(u64::from(u32::MAX)) as u32
            );
            assert_eq!(
                actual.completed_writes,
                (u64::from(seed) + good).min(u64::from(u32::MAX)) as u32
            );
            assert_eq!(
                actual.failed_writes,
                (u64::from(seed) + bad).min(u64::from(u32::MAX)) as u32
            );
            assert_eq!(actual.successful_fetches, seed);
        }
        assert_eq!((good, bad), (5, 5));
    }
}

#[test]
fn parsed_fetches_wrap_the_real_cache_and_preserve_write_counts() {
    for (recipe, seed) in SEEDS {
        let mut owner = ready();
        let baseline = owner.read_node(RuntimeNode::ProcessHeatingSet, 1_000);
        owner.diagnostic_seed_counters(recipe).unwrap();
        for event in 1..=5_u64 {
            fetch(&mut owner, 1_000 + event);
            assert_eq!(
                owner.cache().completed_fetches(),
                ((u64::from(seed) + event) % (1_u64 << 32)) as u32
            );
            assert_eq!(
                owner.diagnostic_counters().successful_fetches,
                owner.cache().completed_fetches()
            );
            assert_eq!(owner.diagnostic_counters().accepted_writes, seed);
            assert_eq!(
                owner.read_node(RuntimeNode::ProcessHeatingSet, 1_000 + event),
                baseline
            );
            assert_eq!(owner.cache().failed_fetches(), 0);
        }
    }
}

#[test]
fn admission_rejects_nonverified_disabled_and_missing_baseline_without_changes() {
    for state in [
        TrustState::Missing,
        TrustState::Provisioned,
        TrustState::VerifyRejected,
        TrustState::Revoked,
    ] {
        let mut owner = ready();
        owner.set_trust_state(state);
        // Re-populate via the actual cache owner is intentionally impossible here.
        let before = owner.diagnostic_counters();
        assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_none());
        assert_eq!(owner.diagnostic_counters(), before);
    }
    let mut owner = ready();
    owner.set_write_enabled(false);
    let before = owner.diagnostic_counters();
    assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_none());
    assert_eq!(owner.diagnostic_counters(), before);
    owner.set_write_enabled(true);
    assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_some());
    let mut owner = RuntimeDataAccess::<2>::new();
    owner.set_verified_trust_session(false);
    owner.set_write_enabled(true);
    let before = owner.diagnostic_counters();
    assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_none());
    assert_eq!(owner.diagnostic_counters(), before);
    fetch(&mut owner, 1_000);
    assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_some());
    assert!(!owner.health().buchi_verifier_time_trusted);
    let mut owner = ready();
    let response = http_status(503, b"{}");
    owner
        .apply_http_response(Endpoint::Process, &response, response.len(), 2_000)
        .unwrap_err();
    let before = owner.diagnostic_counters();
    assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_none());
    assert_eq!(owner.diagnostic_counters(), before);
    fetch(&mut owner, 3_000);
    assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_some());
    assert_eq!(owner.cache().failed_fetches(), 1);
}

#[test]
fn queued_and_already_dequeued_writes_prevent_admission() {
    for dequeue in [false, true] {
        let mut owner = ready();
        assert!(
            owner
                .enqueue_write_node(
                    RuntimeNode::SettingsProgramEcoEnabled,
                    ScalarValue::Boolean(true)
                )
                .accepted
        );
        if dequeue {
            owner.pop_write_request().unwrap();
        }
        let before = owner.diagnostic_counters();
        assert!(owner.diagnostic_seed_counters(SEEDS[0].0).is_none());
        assert_eq!(owner.diagnostic_counters(), before);
    }
}

#[test]
fn cache_reset_and_reverification_cannot_rearm_seed() {
    let mut owner = ready();
    owner.diagnostic_seed_counters(SEEDS[0].0).unwrap();
    for state in [TrustState::Provisioned, TrustState::Revoked] {
        if state == TrustState::Revoked {
            owner.revoke_upstream_trust();
        } else {
            owner.set_trust_state(state);
        }
        assert_eq!(owner.cache().completed_fetches(), 0);
        owner.set_verified_trust_session(false);
        owner.set_write_enabled(true);
        fetch(&mut owner, 2_000);
        let before = owner.diagnostic_counters();
        assert!(owner.diagnostic_seed_counters(SEEDS[1].0).is_none());
        assert_eq!(owner.diagnostic_counters(), before);
    }
}

#[test]
fn failed_fetch_is_separate_and_cache_reset_remains_real() {
    let mut owner = ready();
    owner.diagnostic_seed_counters(SEEDS[0].0).unwrap();
    let response = http_status(503, b"{}");
    let failure = owner
        .apply_http_response(Endpoint::Process, &response, response.len(), 2_000)
        .unwrap_err();
    assert_eq!(failure.failed_fetches, 1);
    assert_eq!(failure.completed_fetches, SEEDS[0].1);
    owner.set_trust_state(TrustState::Provisioned);
    assert_eq!(owner.cache().completed_fetches(), 0);
    assert_eq!(owner.cache().failed_fetches(), 0);
    assert!(!owner.write_send_authorized());
    assert_ne!(
        owner
            .read_node(RuntimeNode::ProcessHeatingSet, 2_000)
            .opcua_status,
        opcua_status::GOOD
    );
    assert_eq!(owner.diagnostic_counters().accepted_writes, SEEDS[0].1);
}

#[test]
fn parsed_response_prerequisite_does_not_admit_good_baseline() {
    for (recipe, seed) in SEEDS {
        let mut owner = RuntimeDataAccess::<2>::new();
        owner.set_verified_trust_session(true);
        owner.set_write_enabled(true);

        // The actual HTTP parser rejects an empty object; no successful fetch.
        let empty = http_ok(b"{}");
        let failure = owner
            .apply_http_response(Endpoint::Process, &empty, empty.len(), 1_000)
            .unwrap_err();
        assert_eq!(
            failure.error,
            EndpointPollError::Response(EndpointResponseError::Body(ParseError::NoSupportedFields))
        );
        assert_eq!((failure.completed_fetches, failure.failed_fetches), (0, 1));
        assert!(!owner.cache().last_fetch_ok());
        assert!(owner.diagnostic_seed_counters(recipe).is_none());

        // Parsing one supported sibling succeeds without publishing heating.set.
        let sibling = http_ok(br#"{"cooling":{"set":4}}"#);
        let report = owner
            .apply_http_response(Endpoint::Process, &sibling, sibling.len(), 2_000)
            .unwrap();
        assert_eq!(
            (
                report.summary.parsed_fields,
                report.summary.published_values
            ),
            (1, 1)
        );
        assert_eq!(report.completed_fetches, 1);
        assert!(owner.cache().last_fetch_ok());
        let missing = owner.read_node(RuntimeNode::ProcessHeatingSet, 2_000);
        assert_eq!(
            missing.opcua_status,
            opcua_status::BAD_WAITING_FOR_INITIAL_DATA
        );
        assert_eq!(missing.value, None);
        let snapshot = owner
            .diagnostic_seed_counters(recipe)
            .expect("parsed-response prerequisite only");
        assert_eq!(snapshot.successful_fetches, seed);
        assert_eq!(
            owner.read_node(RuntimeNode::ProcessHeatingSet, 2_000),
            missing
        );
        assert_eq!(owner.cache().failed_fetches(), 1);
    }
}
