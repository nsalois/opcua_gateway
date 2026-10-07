// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

#[path = "../../../tools/accelerated_time_test_support.rs"]
mod support;

use opta_gateway_contracts::{
    config::{ConfigSource, FactoryResetState},
    freshness::{classify, CacheReadStatus, EntryMetadata},
    last_fault,
    trust_time::verifier_now_seconds,
    uptime::seconds_from_monotonic_ms,
    watchdog::{
        classify_slots, FlashMaintenanceMonitorAction, FlashMaintenanceState, SupervisionClass,
        WatchdogSlot, WatchdogSlotCheckin, WATCHDOG_SLOT_COUNT,
    },
};

#[test]
fn accelerated_setup_rejects_wrong_origins_deadlines_and_partial_state() {
    assert!(support::admit_publication(1000, 3000, 1000, 3000, true).is_ok());
    for (stamp, limit, published) in [(999, 3000, true), (1000, 2999, true), (1000, 3000, false)] {
        assert!(support::admit_publication(1000, 3000, stamp, limit, published).is_err());
    }
    assert!(support::admit_origin(1_000, 1_000_000, true).is_err());
    assert!(support::admit_origin(1_000, 1_000, false).is_err());
    assert!(support::admit_deadline(1_000, 1_000, 1_999).is_err());
    assert!(support::admit_deadline(1_000, 2_147_483_648, 2_147_484_648).is_err());
    assert!(support::admit_deadline(support::EPOCH_MS - 1, 1_000, 999).is_ok());
}

#[test]
fn accelerated_freshness_verifier_and_uptime_all_epochs_and_days() {
    let mut cases = 0;
    for origin in support::origins() {
        let metadata = EntryMetadata::published_at(origin, 3_000);
        support::admit_origin(
            origin,
            metadata.last_publish_monotonic_ms,
            metadata.published,
        )
        .unwrap();
        for age in [
            0,
            2_999,
            3_000,
            3_001,
            support::EPOCH_MS,
            2 * support::EPOCH_MS,
            8 * support::EPOCH_MS,
        ] {
            let now = origin + age;
            assert_eq!(
                classify(metadata, now),
                if age <= 3_000 {
                    CacheReadStatus::Ok
                } else {
                    CacheReadStatus::Stale
                }
            );
            assert_eq!(
                verifier_now_seconds(1_750_000_000, origin, now),
                1_750_000_000 + age / 1_000
            );
            assert_eq!(seconds_from_monotonic_ms(now), (now / 1_000) as u32);
            cases += 1;
        }
        // A future publication is the declared negative input, not an origin error.
        assert_eq!(
            classify(EntryMetadata::published_at(origin + 1, 3_000), origin),
            CacheReadStatus::Stale
        );
    }
    println!("PASS freshness/verifier/uptime directed cases={cases}");
}

#[test]
fn accelerated_watchdog_every_slot_policy_and_maintenance_boundary() {
    let mut cases = 0;
    for origin in support::origins() {
        for index in 0..WATCHDOG_SLOT_COUNT {
            let slot = WatchdogSlot::from_index(index).unwrap();
            for age in [1_999, 2_000, 2_001] {
                let checkin = WatchdogSlotCheckin::new(slot, origin as u32, 2_000);
                support::admit_origin(
                    origin % support::EPOCH_MS,
                    u64::from(checkin.last_checkin_ms),
                    true,
                )
                .unwrap();
                let snapshot = classify_slots((origin + age) as u32, &[checkin]);
                let stale = age > 2_000;
                assert_eq!(checkin.age_ms((origin + age) as u32), age as u32);
                assert_eq!(
                    snapshot.observed_stale_slots_mask,
                    if stale { 1 << index } else { 0 }
                );
                let critical = matches!(slot.supervision_class(), SupervisionClass::ResetCritical);
                assert_eq!(snapshot.all_reset_critical_fresh, !(stale && critical));
                assert!(
                    classify_slots((origin + age) as u32, &[checkin.exempt()])
                        .all_reset_critical_fresh
                );
                cases += 1;
            }
        }
        let maintenance = FlashMaintenanceState::inactive().enter(origin as u32);
        assert_eq!(maintenance.depth(), 1);
        for age in [4_999, 5_000, 5_001] {
            assert_eq!(
                maintenance.monitor_action((origin + age) as u32),
                if age < 5_000 {
                    FlashMaintenanceMonitorAction::RefreshAndSkipClassification
                } else {
                    FlashMaintenanceMonitorAction::OrdinaryContainment
                }
            );
            assert_eq!(maintenance.leave((origin + age) as u32).state.depth(), 0);
        }
    }
    println!("PASS watchdog slot/policy cases={cases}");
}

#[test]
fn accelerated_retained_sequences_wrap_to_reserved_safe_values() {
    for seed in [u32::MAX - 2, u32::MAX - 1, u32::MAX] {
        let mut value = seed;
        for _ in 0..5 {
            let expected = if value == u32::MAX { 1 } else { value + 1 };
            value = last_fault::next_sequence(true, value);
            assert_eq!(value, expected);
        }
    }
    for seed in [u64::MAX - 2, u64::MAX - 1, u64::MAX] {
        let mut value = seed;
        for _ in 0..5 {
            let expected = if value == u64::MAX { 1 } else { value + 1 };
            value = FactoryResetState::new(ConfigSource::SlotA, value).tombstone_sequence();
            assert_eq!(value, expected);
        }
    }
}

#[test]
fn accelerated_persisted_config_selects_actual_successor_after_wrap() {
    use opta_gateway_contracts::config::{encode_slot, select_config, GatewayConfig, GatewayTrust};
    let mac = [2, 1, 2, 3, 4, 5];
    let config = GatewayConfig::defaults_from_mac(mac);
    let trust = GatewayTrust::missing();
    for seed in [u64::MAX - 2, u64::MAX - 1, u64::MAX] {
        let mut slots = [encode_slot(seed, &config, &trust).unwrap(); 2];
        let mut sequence = seed;
        for operation in 1..=5usize {
            sequence = if sequence == u64::MAX {
                1
            } else {
                sequence + 1
            };
            let written = operation % 2;
            slots[written] = encode_slot(sequence, &config, &trust).unwrap();
            let loaded = select_config(&slots[0], &slots[1], mac);
            assert_eq!(
                loaded.sequence, sequence,
                "seed={seed} operation={operation}"
            );
            assert_eq!(
                loaded.source,
                if written == 0 {
                    ConfigSource::SlotA
                } else {
                    ConfigSource::SlotB
                }
            );
        }
    }
}
