use opta_gateway_contracts::config::{
    encode_reset_slot, encode_slot, select_config, ConfigKey, ConfigSource,
    FactoryResetCommitEvidence, FactoryResetOutcome, FactoryResetState, FactoryResetStep,
    GatewayConfig, GatewayTrust, RecordKind, FLASH_WRITE_GRANULE, RECORD_BODY_SIZE, RECORD_SIZE,
};

const MAC: [u8; 6] = [0x02, 0xa7, 0x5c, 0xe5, 0x27, 0x84];
const ERASED: [u8; RECORD_SIZE] = [0xff; RECORD_SIZE];

fn named_config(name: &str) -> GatewayConfig {
    let mut config = GatewayConfig::defaults_from_mac(MAC);
    config.set_key_value(ConfigKey::DeviceName, name).unwrap();
    config
        .set_key_value(ConfigKey::BuchiUser, "pre-reset-user")
        .unwrap();
    config
        .set_key_value(ConfigKey::BuchiPassword, "pre-reset-password")
        .unwrap();
    config
}

fn anchored_trust() -> GatewayTrust {
    GatewayTrust::from_ca_der(&[0x30, 0x03, 0x02, 0x01, 0x00], true).unwrap()
}

fn place_slots(
    active_source: ConfigSource,
    active: [u8; RECORD_SIZE],
    inactive: [u8; RECORD_SIZE],
) -> ([u8; RECORD_SIZE], [u8; RECORD_SIZE]) {
    match active_source {
        ConfigSource::SlotA => (active, inactive),
        ConfigSource::SlotB => (inactive, active),
        ConfigSource::Defaults => panic!("factory-reset matrix requires a physical active slot"),
    }
}

fn assert_loaded_exact(
    slot_a: &[u8],
    slot_b: &[u8],
    source: ConfigSource,
    sequence: u64,
    kind: RecordKind,
    config: &GatewayConfig,
    trust: &GatewayTrust,
) {
    let loaded = select_config(slot_a, slot_b, MAC);
    assert_eq!(loaded.source, source);
    assert_eq!(loaded.sequence, sequence);
    assert_eq!(loaded.kind, Some(kind));
    assert_eq!(loaded.config, *config);
    assert_eq!(loaded.trust, *trust);
}

fn assert_loaded_reset(slot_a: &[u8], slot_b: &[u8], source: ConfigSource, sequence: u64) {
    let loaded = select_config(slot_a, slot_b, MAC);
    assert_eq!(loaded.source, source);
    assert_eq!(loaded.sequence, sequence);
    assert_eq!(loaded.kind, Some(RecordKind::Reset));
    assert_eq!(loaded.config, GatewayConfig::defaults_from_mac(MAC));
    assert_eq!(loaded.trust, GatewayTrust::missing());
    assert!(loaded.trust.ca_der().is_empty());
    assert!(!loaded.trust.time_provisioned());
}

fn assert_interrupted_commit_selects_only_old_or_new(new_trust: GatewayTrust) {
    let old_config = named_config("old-config");
    let new_config = named_config("new-config");
    let old_trust = anchored_trust();
    let active = encode_slot(10, &old_config, &old_trust).unwrap();
    let stale_inactive = encode_slot(9, &named_config("stale-config"), &old_trust).unwrap();
    let new_record = encode_slot(11, &new_config, &new_trust).unwrap();

    for erased_prefix in 0..=RECORD_SIZE {
        let mut inactive = stale_inactive;
        inactive[..erased_prefix].fill(0xff);
        assert_loaded_exact(
            &active,
            &inactive,
            ConfigSource::SlotA,
            10,
            RecordKind::Normal,
            &old_config,
            &old_trust,
        );
    }

    for programmed in 0..=RECORD_BODY_SIZE {
        let mut inactive = ERASED;
        inactive[..programmed].copy_from_slice(&new_record[..programmed]);
        assert_loaded_exact(
            &active,
            &inactive,
            ConfigSource::SlotA,
            10,
            RecordKind::Normal,
            &old_config,
            &old_trust,
        );
    }

    for marker_prefix in 0..=FLASH_WRITE_GRANULE {
        let mut inactive = ERASED;
        inactive[..RECORD_BODY_SIZE].copy_from_slice(&new_record[..RECORD_BODY_SIZE]);
        inactive[RECORD_BODY_SIZE..RECORD_BODY_SIZE + marker_prefix]
            .copy_from_slice(&new_record[RECORD_BODY_SIZE..RECORD_BODY_SIZE + marker_prefix]);
        if marker_prefix < 4 {
            assert_loaded_exact(
                &active,
                &inactive,
                ConfigSource::SlotA,
                10,
                RecordKind::Normal,
                &old_config,
                &old_trust,
            );
        } else {
            assert_loaded_exact(
                &active,
                &inactive,
                ConfigSource::SlotB,
                11,
                RecordKind::Normal,
                &new_config,
                &new_trust,
            );
        }
    }

    assert_loaded_exact(
        &active,
        &new_record,
        ConfigSource::SlotB,
        11,
        RecordKind::Normal,
        &new_config,
        &new_trust,
    );
}

#[test]
fn ab_commit_is_power_cut_safe_at_every_erase_program_and_ram_boundary() {
    assert_interrupted_commit_selects_only_old_or_new(anchored_trust());
}

#[test]
fn trust_clear_commit_is_power_cut_safe_at_every_boundary() {
    assert_interrupted_commit_selects_only_old_or_new(GatewayTrust::missing());
}

fn assert_factory_reset_cut_matrix(active_kind: RecordKind) -> usize {
    let defaults = GatewayConfig::defaults_from_mac(MAC);
    let missing = GatewayTrust::missing();
    let old_config = named_config("pre-reset-config");
    let old_trust = anchored_trust();
    let mut cases = 0;

    for active_source in [ConfigSource::SlotA, ConfigSource::SlotB] {
        for inactive_valid in [false, true] {
            for live_sequence in [10, u64::MAX] {
                let stale_sequence = live_sequence - 1;
                let active = match active_kind {
                    RecordKind::Normal => {
                        encode_slot(live_sequence, &old_config, &old_trust).unwrap()
                    }
                    RecordKind::Reset => encode_reset_slot(live_sequence, MAC).unwrap(),
                };
                let inactive = if inactive_valid {
                    encode_slot(stale_sequence, &named_config("stale-config"), &old_trust).unwrap()
                } else {
                    ERASED
                };
                let (initial_a, initial_b) = place_slots(active_source, active, inactive);
                let selected_before = select_config(&initial_a, &initial_b, MAC);
                assert_eq!(selected_before.source, active_source);
                assert_eq!(selected_before.kind, Some(active_kind));

                let mut reset = FactoryResetState::new(active_source, live_sequence);
                let target = reset.target_slot();
                let old_slot = reset.old_slot();
                let tombstone_sequence = reset.tombstone_sequence();
                let tombstone = encode_reset_slot(tombstone_sequence, MAC).unwrap();
                assert_eq!(reset.step(), FactoryResetStep::EraseInactive);
                assert_eq!(reset.failure_outcome(), FactoryResetOutcome::NotCommitted);
                assert!(!reset.failure_outcome().requires_ram_revocation());

                for erased_prefix in 0..=RECORD_SIZE {
                    let mut cut_a = initial_a;
                    let mut cut_b = initial_b;
                    let target_bytes = match target {
                        ConfigSource::SlotA => &mut cut_a,
                        ConfigSource::SlotB => &mut cut_b,
                        ConfigSource::Defaults => unreachable!(),
                    };
                    target_bytes[..erased_prefix].fill(0xff);
                    match active_kind {
                        RecordKind::Normal => assert_loaded_exact(
                            &cut_a,
                            &cut_b,
                            active_source,
                            live_sequence,
                            RecordKind::Normal,
                            &old_config,
                            &old_trust,
                        ),
                        RecordKind::Reset => {
                            assert_loaded_reset(&cut_a, &cut_b, active_source, live_sequence)
                        }
                    }
                    cases += 1;
                }
                assert!(reset.complete_step(FactoryResetStep::EraseInactive));
                assert_eq!(reset.step(), FactoryResetStep::ProgramTombstoneBody);
                assert_eq!(reset.failure_outcome(), FactoryResetOutcome::NotCommitted);

                for programmed in 0..=RECORD_BODY_SIZE {
                    let mut target_bytes = ERASED;
                    target_bytes[..programmed].copy_from_slice(&tombstone[..programmed]);
                    let (cut_a, cut_b) = place_slots(old_slot, active, target_bytes);
                    match active_kind {
                        RecordKind::Normal => assert_loaded_exact(
                            &cut_a,
                            &cut_b,
                            active_source,
                            live_sequence,
                            RecordKind::Normal,
                            &old_config,
                            &old_trust,
                        ),
                        RecordKind::Reset => {
                            assert_loaded_reset(&cut_a, &cut_b, active_source, live_sequence)
                        }
                    }
                    cases += 1;
                }
                assert!(reset.complete_step(FactoryResetStep::ProgramTombstoneBody));
                assert_eq!(reset.step(), FactoryResetStep::ProgramTombstoneMarker);
                assert_eq!(
                    reset.failure_outcome(),
                    FactoryResetOutcome::CommittedCleanupIncomplete {
                        commit: FactoryResetCommitEvidence::Uncertain
                    }
                );
                assert!(reset.failure_outcome().requires_ram_revocation());

                for marker_prefix in 0..=FLASH_WRITE_GRANULE {
                    let mut target_bytes = ERASED;
                    target_bytes[..RECORD_BODY_SIZE]
                        .copy_from_slice(&tombstone[..RECORD_BODY_SIZE]);
                    target_bytes[RECORD_BODY_SIZE..RECORD_BODY_SIZE + marker_prefix]
                        .copy_from_slice(
                            &tombstone[RECORD_BODY_SIZE..RECORD_BODY_SIZE + marker_prefix],
                        );
                    let (cut_a, cut_b) = place_slots(old_slot, active, target_bytes);
                    if marker_prefix < 4 {
                        match active_kind {
                            RecordKind::Normal => assert_loaded_exact(
                                &cut_a,
                                &cut_b,
                                active_source,
                                live_sequence,
                                RecordKind::Normal,
                                &old_config,
                                &old_trust,
                            ),
                            RecordKind::Reset => {
                                assert_loaded_reset(&cut_a, &cut_b, active_source, live_sequence)
                            }
                        }
                    } else {
                        assert_loaded_reset(&cut_a, &cut_b, target, tombstone_sequence);
                    }
                    cases += 1;
                }
                assert!(reset.complete_step(FactoryResetStep::ProgramTombstoneMarker));
                assert_eq!(reset.step(), FactoryResetStep::EraseOldSlot);
                assert_eq!(
                    reset.failure_outcome(),
                    FactoryResetOutcome::CommittedCleanupIncomplete {
                        commit: FactoryResetCommitEvidence::Confirmed
                    }
                );
                assert!(reset.failure_outcome().requires_ram_revocation());

                for erased_prefix in 0..=RECORD_SIZE {
                    let mut old_bytes = active;
                    old_bytes[..erased_prefix].fill(0xff);
                    let (cut_a, cut_b) = place_slots(old_slot, old_bytes, tombstone);
                    assert_loaded_reset(&cut_a, &cut_b, target, tombstone_sequence);
                    cases += 1;
                }
                assert!(reset.complete_step(FactoryResetStep::EraseOldSlot));
                assert_eq!(reset.step(), FactoryResetStep::Readback);
                assert_eq!(
                    reset.failure_outcome(),
                    FactoryResetOutcome::CommittedCleanupIncomplete {
                        commit: FactoryResetCommitEvidence::Confirmed
                    }
                );

                let (clean_a, clean_b) = place_slots(old_slot, ERASED, tombstone);
                assert_loaded_reset(&clean_a, &clean_b, target, tombstone_sequence);
                cases += 1;
                assert!(reset.complete_step(FactoryResetStep::Readback));
                assert_eq!(reset.step(), FactoryResetStep::RevokeRam);

                assert_loaded_reset(&clean_a, &clean_b, target, tombstone_sequence);
                cases += 1;
                assert!(reset.complete_step(FactoryResetStep::RevokeRam));
                assert_eq!(reset.step(), FactoryResetStep::Complete);
                assert_eq!(
                    reset.failure_outcome(),
                    FactoryResetOutcome::CommittedCleanupComplete
                );

                if active_kind == RecordKind::Reset {
                    assert_eq!(selected_before.config, defaults);
                    assert_eq!(selected_before.trust, missing);
                }
            }
        }
    }
    cases
}

#[test]
fn factory_reset_cut_matrix_has_exact_marker_boundary_and_never_resurrects_trust() {
    let first_reset_cases = assert_factory_reset_cut_matrix(RecordKind::Normal);
    let repeated_reset_cases = assert_factory_reset_cut_matrix(RecordKind::Reset);
    assert_eq!(first_reset_cases, 56_112);
    assert_eq!(repeated_reset_cases, 56_112);
}

#[test]
fn factory_reset_cut_after_first_erase_never_reloads_old_trust() {
    let old_trust = anchored_trust();
    let old = encode_slot(u64::MAX, &named_config("current-config"), &old_trust).unwrap();
    let reset = encode_reset_slot(1, MAC).unwrap();

    // New ordering commits the tombstone in B before the cleanup erase of A.
    // A reset after that cleanup erase must therefore keep physical B authoritative.
    assert_loaded_reset(&ERASED, &reset, ConfigSource::SlotB, 1);
    assert_ne!(old, ERASED);
}

fn assert_first_post_reset_commit_matrix(new_trust: GatewayTrust) -> usize {
    let reset_defaults = GatewayConfig::defaults_from_mac(MAC);
    let new_config = if new_trust == GatewayTrust::missing() {
        named_config("post-reset-config")
    } else {
        reset_defaults
    };
    let old_config = named_config("pre-reset-stale");
    let old_trust = anchored_trust();
    let mut cases = 0;

    for reset_source in [ConfigSource::SlotA, ConfigSource::SlotB] {
        for stale_old_present in [false, true] {
            for reset_sequence in [11, u64::MAX] {
                let reset = encode_reset_slot(reset_sequence, MAC).unwrap();
                let stale = if stale_old_present {
                    encode_slot(reset_sequence.wrapping_sub(1), &old_config, &old_trust).unwrap()
                } else {
                    ERASED
                };
                let target = match reset_source {
                    ConfigSource::SlotA => ConfigSource::SlotB,
                    ConfigSource::SlotB => ConfigSource::SlotA,
                    ConfigSource::Defaults => unreachable!(),
                };
                let sequence = if reset_sequence == u64::MAX {
                    1
                } else {
                    reset_sequence + 1
                };
                let new_record = encode_slot(sequence, &new_config, &new_trust).unwrap();
                let (initial_a, initial_b) = place_slots(reset_source, reset, stale);

                for erased_prefix in 0..=RECORD_SIZE {
                    let mut cut_a = initial_a;
                    let mut cut_b = initial_b;
                    let target_bytes = match target {
                        ConfigSource::SlotA => &mut cut_a,
                        ConfigSource::SlotB => &mut cut_b,
                        ConfigSource::Defaults => unreachable!(),
                    };
                    target_bytes[..erased_prefix].fill(0xff);
                    assert_loaded_reset(&cut_a, &cut_b, reset_source, reset_sequence);
                    cases += 1;
                }

                for programmed in 0..=RECORD_BODY_SIZE {
                    let mut target_bytes = ERASED;
                    target_bytes[..programmed].copy_from_slice(&new_record[..programmed]);
                    let (cut_a, cut_b) = place_slots(reset_source, reset, target_bytes);
                    assert_loaded_reset(&cut_a, &cut_b, reset_source, reset_sequence);
                    cases += 1;
                }

                for marker_prefix in 0..=FLASH_WRITE_GRANULE {
                    let mut target_bytes = ERASED;
                    target_bytes[..RECORD_BODY_SIZE]
                        .copy_from_slice(&new_record[..RECORD_BODY_SIZE]);
                    target_bytes[RECORD_BODY_SIZE..RECORD_BODY_SIZE + marker_prefix]
                        .copy_from_slice(
                            &new_record[RECORD_BODY_SIZE..RECORD_BODY_SIZE + marker_prefix],
                        );
                    let (cut_a, cut_b) = place_slots(reset_source, reset, target_bytes);
                    if marker_prefix < 4 {
                        assert_loaded_reset(&cut_a, &cut_b, reset_source, reset_sequence);
                    } else {
                        assert_loaded_exact(
                            &cut_a,
                            &cut_b,
                            target,
                            sequence,
                            RecordKind::Normal,
                            &new_config,
                            &new_trust,
                        );
                    }
                    cases += 1;
                }

                let (committed_a, committed_b) = place_slots(reset_source, reset, new_record);
                assert_loaded_exact(
                    &committed_a,
                    &committed_b,
                    target,
                    sequence,
                    RecordKind::Normal,
                    &new_config,
                    &new_trust,
                );
                cases += 1;

                let mut erased_tombstone_a = committed_a;
                let mut erased_tombstone_b = committed_b;
                match reset_source {
                    ConfigSource::SlotA => erased_tombstone_a.fill(0xff),
                    ConfigSource::SlotB => erased_tombstone_b.fill(0xff),
                    ConfigSource::Defaults => unreachable!(),
                }
                assert_loaded_exact(
                    &erased_tombstone_a,
                    &erased_tombstone_b,
                    target,
                    sequence,
                    RecordKind::Normal,
                    &new_config,
                    &new_trust,
                );
            }
        }
    }
    cases
}

#[test]
fn first_post_reset_config_and_trust_commits_replace_the_tombstone_safely() {
    let config_cases = assert_first_post_reset_commit_matrix(GatewayTrust::missing());
    let trust_cases = assert_first_post_reset_commit_matrix(anchored_trust());
    assert_eq!(config_cases, 37_408);
    assert_eq!(trust_cases, 37_408);
}
