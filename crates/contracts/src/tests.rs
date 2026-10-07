use super::backup_domain::{self, BackupRegisterOwner, BackupRegisterUse, ProjectRecordDomain};
use super::boot::{self, BootStage};
use super::cm4::{self, Cm4AuthorizationState};
use super::freshness::{
    self, CacheReadStatus, EntryMetadata, FixedStateCache, FixedValueCache, ScalarValue,
};
use super::last_fault::{self, LastFaultReason};
use super::namespace::{self, Access, ValueKind};
use super::opcua_status;
use super::product::*;
use super::watchdog;

#[test]
fn cm4_authorization_state_covers_every_bcm4_and_boot_c2_combination() {
    use Cm4AuthorizationState::{BootEnabledByOption, BootReleasedBySoftware, HeldByOption};

    assert_eq!(cm4::authorization_state(0, 0), HeldByOption);
    assert_eq!(
        cm4::authorization_state(cm4::SYSCFG_UR1_BCM4, 0),
        BootEnabledByOption
    );
    assert_eq!(
        cm4::authorization_state(0, cm4::RCC_GCR_BOOT_C2),
        BootReleasedBySoftware
    );
    assert_eq!(
        cm4::authorization_state(cm4::SYSCFG_UR1_BCM4, cm4::RCC_GCR_BOOT_C2),
        BootReleasedBySoftware
    );
    assert_eq!(Cm4AuthorizationState::Unknown.as_word(), 0);
    assert_eq!(HeldByOption.as_word(), 1);
    assert_eq!(BootEnabledByOption.as_word(), 2);
    assert_eq!(BootReleasedBySoftware.as_word(), 3);
}

#[test]
fn cm4_raw_bit_extractors_ignore_unrelated_register_bits() {
    let unrelated = 0xA5A5_0000;
    assert!(!cm4::bcm4_enabled(unrelated));
    assert!(cm4::bcm4_enabled(unrelated | cm4::SYSCFG_UR1_BCM4));
    assert!(!cm4::boot_c2_set(unrelated));
    assert!(cm4::boot_c2_set(unrelated | cm4::RCC_GCR_BOOT_C2));
    assert!(!cm4::d2_clocks_ready(unrelated));
    assert!(cm4::d2_clocks_ready(unrelated | cm4::RCC_CR_D2CKRDY));
    assert_eq!(cm4::RCC_GCR_WW1RSC, 1);
}

#[test]
fn poll_cadence_matches_default_contract() {
    assert_eq!(PROCESS_POLL_MS, 1_000);
    assert_eq!(SETTINGS_POLL_MS, 5_000);
    assert_eq!(INFO_POLL_MS, 60_000);
}

#[test]
fn freshness_windows_match_current_contract() {
    assert_eq!(BUCHI_STATUS_FRESHNESS_MS, 5_000);
    assert_eq!(BUCHI_PROCESS_FRESHNESS_MS, 2_500);
    assert_eq!(BUCHI_SETTINGS_FRESHNESS_MS, 70_000);
    assert_eq!(BUCHI_INFO_FRESHNESS_MS, 70_000);
}

#[test]
fn datachange_bounds_match_default_contract() {
    assert_eq!(MAX_ACTIVE_SUBSCRIPTIONS, 1);
    assert_eq!(MAX_MONITORED_ITEMS, 135);
    assert_eq!(DATA_CHANGE_INTERVAL_MS, 1_000);
}

#[test]
fn buchi_buffer_bounds_match_current_contract() {
    assert_eq!(BUCHI_WRITE_QUEUE_CAPACITY, 32);
    assert_eq!(BUCHI_WRITE_JSON_BYTES, 128);
    assert_eq!(BUCHI_HTTP_REQUEST_BYTES, 512);
    assert_eq!(BUCHI_HTTP_RESPONSE_BYTES, 4_352);
}

#[test]
fn supervision_timing_matches_product_behavior_contract() {
    assert_eq!(M7_HEARTBEAT_MS, 200);
    assert_eq!(M7_STATUS_SNAPSHOT_MS, 1_000);
    assert_eq!(M4_HEARTBEAT_TIMEOUT_MS, 2_000);
    assert_eq!(M4_HEARTBEAT_TIMEOUT_MS, M7_HEARTBEAT_MS * 10);
    assert_eq!(M4_SYSTEM_RESET_AFTER_FAULT_MS, 250);
}

#[test]
fn backup_domain_register_contract_keeps_bootloader_and_records_disjoint() {
    assert_eq!(backup_domain::BACKUP_REGISTER_COUNT, 16);
    assert_eq!(
        backup_domain::classify(0),
        Some(BackupRegisterUse::DfuHandshake)
    );
    assert_eq!(
        backup_domain::classify(1),
        Some(BackupRegisterUse::FactoryResetLatch)
    );
    assert_eq!(
        backup_domain::classify(8),
        Some(BackupRegisterUse::BootloaderScratch)
    );
    assert_eq!(
        backup_domain::classify(15),
        Some(BackupRegisterUse::LastFaultChecksum)
    );
    assert_eq!(backup_domain::classify(16), None);

    assert_eq!(
        backup_domain::owner_of(BackupRegisterUse::DfuHandshake),
        BackupRegisterOwner::BootloaderReserved
    );
    assert_eq!(
        backup_domain::owner_of(BackupRegisterUse::BootloaderScratch),
        BackupRegisterOwner::BootloaderScratch
    );
    assert_eq!(
        backup_domain::owner_of(BackupRegisterUse::LastFaultMagic),
        BackupRegisterOwner::M7Project
    );
    assert!(backup_domain::is_bootloader_reserved(0));
    assert!(backup_domain::is_bootloader_reserved(8));
    assert!(!backup_domain::is_project_owned(0));
    assert!(!backup_domain::is_project_owned(8));
    assert!(backup_domain::is_project_owned(1));
    assert!(backup_domain::is_project_owned(2));
    assert!(backup_domain::is_project_owned(15));

    for register in 2..=7 {
        let use_ = backup_domain::classify(register).unwrap();
        assert_eq!(
            backup_domain::project_domain_of(use_),
            ProjectRecordDomain::LastFault
        );
    }
    for register in 9..=14 {
        let use_ = backup_domain::classify(register).unwrap();
        assert_eq!(
            backup_domain::project_domain_of(use_),
            ProjectRecordDomain::BootBreadcrumb
        );
    }
    assert_eq!(
        backup_domain::project_domain_of(BackupRegisterUse::FactoryResetLatch),
        ProjectRecordDomain::FactoryResetLatch
    );
    assert_eq!(
        backup_domain::project_domain_of(BackupRegisterUse::DfuHandshake),
        ProjectRecordDomain::None
    );
}

#[test]
fn last_fault_record_checksum_and_reason_values_are_stable() {
    assert_eq!(core::mem::size_of::<last_fault::LastFaultWords>(), 7 * 4);
    assert_eq!(last_fault::LAST_FAULT_MAGIC, 0x504D_3032);
    assert_eq!(last_fault::LAST_FAULT_PENDING_MAGIC, 0x504D_5032);
    assert_eq!(last_fault::LEGACY_LAST_FAULT_MAGIC, 0x504D_3031);
    assert_eq!(last_fault::LEGACY_LAST_FAULT_PENDING_MAGIC, 0x504D_5031);
    assert_eq!(LastFaultReason::None.as_word(), 0);
    assert_eq!(LastFaultReason::M4HeartbeatFault.as_word(), 1);
    assert_eq!(
        LastFaultReason::from_word(1),
        Some(LastFaultReason::M4HeartbeatFault)
    );
    assert_eq!(LastFaultReason::HardFault.as_word(), 2);
    assert_eq!(LastFaultReason::MemManageFault.as_word(), 3);
    assert_eq!(LastFaultReason::BusFault.as_word(), 4);
    assert_eq!(LastFaultReason::UsageFault.as_word(), 5);
    assert_eq!(LastFaultReason::StackOverflow.as_word(), 6);
    assert_eq!(LastFaultReason::Assert.as_word(), 7);
    assert_eq!(LastFaultReason::IwdgReset.as_word(), 8);
    assert_eq!(LastFaultReason::EthInitSwrTimeout.as_word(), 9);
    assert_eq!(
        LastFaultReason::from_word(9),
        Some(LastFaultReason::EthInitSwrTimeout)
    );
    assert_eq!(LastFaultReason::EthInitStrapLatch.as_word(), 10);
    assert_eq!(
        LastFaultReason::from_word(10),
        Some(LastFaultReason::EthInitStrapLatch)
    );
    assert_eq!(LastFaultReason::from_word(11), None);

    let detail = last_fault::fault_detail_from_frame(0x0804_1234, 0xFFFF_FFFD, 0x2100_0000);
    assert_eq!(detail, 0x0804_FFFD);
    let words = last_fault::encode_record(
        LastFaultReason::HardFault,
        0x0804_0009,
        0,
        detail,
        0xA5A5_5A5A,
    );
    assert_eq!(words.checksum, 0x959F_7D9B);

    let decoded = last_fault::decode_record(words);
    assert!(decoded.valid);
    assert_eq!(decoded.reason_word, 2);
    assert_eq!(decoded.known_reason, Some(LastFaultReason::HardFault));
    assert_eq!(decoded.sequence, 0x0804_0009);
    assert_eq!(decoded.uptime_seconds(), Some(0));
    assert_eq!(decoded.legacy_uptime_ms(), None);
    assert_eq!(decoded.detail, detail);
    assert_eq!(decoded.reset_flags, 0xA5A5_5A5A);
    assert!(!last_fault::is_reset_classification_pending(words));
    assert_eq!(last_fault::classify_reset_once(words, 0x1234_5678), None);

    let mut corrupt = words;
    corrupt.checksum ^= 1;
    assert!(!last_fault::decode_record(corrupt).valid);

    let mut wrong_magic = words;
    wrong_magic.magic ^= 1;
    assert!(!last_fault::decode_record(wrong_magic).valid);

    let unknown_reason = last_fault::LastFaultWords {
        magic: last_fault::LAST_FAULT_MAGIC,
        reason: 99,
        sequence: 7,
        uptime_word: 8,
        detail: 9,
        reset_flags: 10,
        checksum: last_fault::checksum(99, 7, 8, 9, 10),
    };
    let decoded_unknown = last_fault::decode_record(unknown_reason);
    assert!(decoded_unknown.valid);
    assert_eq!(decoded_unknown.known_reason, None);
    assert_eq!(decoded_unknown.reason_word, 99);
    assert_eq!(
        last_fault::decode_record(last_fault::encode_record_words(99, 4, 5, 6, 7)).reason_word,
        99
    );
    assert_eq!(last_fault::next_sequence(false, 0), 1);
    assert_eq!(last_fault::next_sequence(true, 41), 42);
    assert_eq!(last_fault::next_sequence(true, u32::MAX), 1);
}

#[test]
fn new_fault_clears_previous_reset_classification_and_marks_pending() {
    let previous =
        last_fault::encode_record(LastFaultReason::HardFault, 4, 1_000, 0xAA, 0xA000_0000);
    let previous_record = last_fault::decode_record(previous);
    let pending = last_fault::encode_pending_record(
        LastFaultReason::Assert,
        last_fault::next_sequence(previous_record.valid, previous_record.sequence),
        2_000,
        0xBB,
    );
    let record = last_fault::decode_record(pending);

    assert!(record.valid);
    assert_eq!(record.known_reason, Some(LastFaultReason::Assert));
    assert_eq!(record.sequence, 5);
    assert_eq!(record.reset_flags, 0);
    assert!(last_fault::is_reset_classification_pending(pending));
}

#[test]
fn immediately_following_boot_classifies_pending_fault_once() {
    let pending = last_fault::encode_pending_record(LastFaultReason::HardFault, 7, 3_000, 0xCC);
    let classified = last_fault::classify_reset_once(pending, 0x1000_0000)
        .expect("first boot classifies a pending fault");
    let record = last_fault::decode_record(classified);

    assert!(record.valid);
    assert_eq!(record.known_reason, Some(LastFaultReason::HardFault));
    assert_eq!(record.sequence, 7);
    assert_eq!(record.reset_flags, 0x1000_0000);
    assert!(!last_fault::is_reset_classification_pending(classified));
}

#[test]
fn later_unrelated_boot_preserves_classified_fault() {
    let pending =
        last_fault::encode_pending_record(LastFaultReason::MemManageFault, 8, 4_000, 0xDD);
    let classified = last_fault::classify_reset_once(pending, 0x1000_0000)
        .expect("first boot classifies a pending fault");

    assert_eq!(
        last_fault::classify_reset_once(classified, 0x0040_0000),
        None,
        "an ordinary later boot must not overwrite the fault's reset flags"
    );
    assert_eq!(
        last_fault::decode_record(classified).reset_flags,
        0x1000_0000
    );
}

#[test]
fn later_different_fault_starts_a_new_pending_lifecycle() {
    let first_pending =
        last_fault::encode_pending_record(LastFaultReason::HardFault, 9, 5_000, 0xEE);
    let first_classified = last_fault::classify_reset_once(first_pending, 0x1000_0000)
        .expect("first boot classifies the first fault");
    let first_record = last_fault::decode_record(first_classified);

    let second_pending = last_fault::encode_pending_record(
        LastFaultReason::EthInitSwrTimeout,
        last_fault::next_sequence(first_record.valid, first_record.sequence),
        6_000,
        0xFF,
    );
    let second_pending_record = last_fault::decode_record(second_pending);
    assert_eq!(
        second_pending_record.known_reason,
        Some(LastFaultReason::EthInitSwrTimeout)
    );
    assert_eq!(second_pending_record.sequence, 10);
    assert_eq!(second_pending_record.reset_flags, 0);
    assert!(last_fault::is_reset_classification_pending(second_pending));

    let second_classified = last_fault::classify_reset_once(second_pending, 0x0400_0000)
        .expect("first boot after the second fault classifies that fault");
    assert_eq!(
        last_fault::decode_record(second_classified).reset_flags,
        0x0400_0000
    );
}

#[test]
fn pending_fault_state_is_checksum_protected() {
    let pending = last_fault::encode_pending_record(LastFaultReason::HardFault, 11, 7_000, 0x1234);
    assert_eq!(pending.checksum, 0x9FB3_680C);
    assert!(last_fault::decode_record(pending).valid);

    let mut corrupted_state = pending;
    corrupted_state.magic = last_fault::LAST_FAULT_MAGIC;
    assert!(!last_fault::decode_record(corrupted_state).valid);

    let mut corrupted_reset_flags = pending;
    corrupted_reset_flags.reset_flags = 1;
    assert!(!last_fault::decode_record(corrupted_reset_flags).valid);
}

#[test]
fn public_uptime_seconds_comes_from_untruncated_milliseconds() {
    use crate::uptime::seconds_from_monotonic_ms;

    assert_eq!(seconds_from_monotonic_ms(0), 0);
    assert_eq!(seconds_from_monotonic_ms(999), 0);
    assert_eq!(seconds_from_monotonic_ms(1_000), 1);
    assert_eq!(seconds_from_monotonic_ms(1_001), 1);

    let old_wrap = u32::MAX as u64 + 1;
    assert_eq!(seconds_from_monotonic_ms(old_wrap - 1), 4_294_967);
    assert_eq!(seconds_from_monotonic_ms(old_wrap), 4_294_967);
    assert_eq!(seconds_from_monotonic_ms(old_wrap + 1_000), 4_294_968);
    assert_eq!(seconds_from_monotonic_ms(old_wrap * 2), 8_589_934);

    let max_seconds_ms = u32::MAX as u64 * 1_000;
    assert_eq!(seconds_from_monotonic_ms(max_seconds_ms), u32::MAX);
    assert_eq!(seconds_from_monotonic_ms(max_seconds_ms + 999), u32::MAX);
    assert_eq!(seconds_from_monotonic_ms(max_seconds_ms + 1_000), 0);
}

#[test]
fn legacy_last_fault_records_preserve_units_and_classify_once() {
    let final_words = last_fault::encode_legacy_record_words(2, 7, 4_294_000, 9, 10);
    let final_record = last_fault::decode_record(final_words);
    assert!(final_record.valid);
    assert_eq!(final_record.uptime_seconds(), None);
    assert_eq!(final_record.legacy_uptime_ms(), Some(4_294_000));
    assert_eq!(last_fault::classify_reset_once(final_words, 11), None);

    let pending =
        last_fault::encode_legacy_pending_record(LastFaultReason::HardFault, 8, 123_456, 12);
    assert!(last_fault::is_reset_classification_pending(pending));
    let classified = last_fault::classify_reset_once(pending, 0x1000_0000)
        .expect("new firmware classifies a valid legacy pending record");
    assert_eq!(classified.magic, last_fault::LEGACY_LAST_FAULT_MAGIC);
    let record = last_fault::decode_record(classified);
    assert_eq!(record.legacy_uptime_ms(), Some(123_456));
    assert_eq!(record.uptime_seconds(), None);
    assert_eq!(record.reset_flags, 0x1000_0000);
    assert_eq!(last_fault::classify_reset_once(classified, 1), None);
}

#[test]
fn last_fault_formats_cannot_be_changed_by_mutating_only_magic() {
    for words in [
        last_fault::encode_record(LastFaultReason::Assert, 1, 2, 3, 4),
        last_fault::encode_pending_record(LastFaultReason::Assert, 1, 2, 3),
        last_fault::encode_legacy_record_words(7, 1, 2_000, 3, 4),
        last_fault::encode_legacy_pending_record(LastFaultReason::Assert, 1, 2_000, 3),
    ] {
        for magic in [
            last_fault::LAST_FAULT_MAGIC,
            last_fault::LAST_FAULT_PENDING_MAGIC,
            last_fault::LEGACY_LAST_FAULT_MAGIC,
            last_fault::LEGACY_LAST_FAULT_PENDING_MAGIC,
            0,
        ] {
            if magic == words.magic {
                continue;
            }
            let mut mutated = words;
            mutated.magic = magic;
            assert!(
                !last_fault::decode_record(mutated).valid,
                "magic-only mutation from {:#x} to {:#x} was accepted",
                words.magic,
                magic
            );
        }
    }
}

#[test]
fn legacy_decoder_contract_rejects_new_seconds_magic() {
    let new_words = last_fault::encode_record(LastFaultReason::IwdgReset, 9, 12, 13, 14);
    let legacy_would_accept = new_words.magic == last_fault::LEGACY_LAST_FAULT_MAGIC
        && new_words.checksum
            == last_fault::legacy_checksum(
                new_words.reason,
                new_words.sequence,
                new_words.uptime_word,
                new_words.detail,
                new_words.reset_flags,
            );
    assert!(!legacy_would_accept);
}

#[test]
fn boot_breadcrumb_record_checksum_stage_names_and_sequence_are_stable() {
    assert_eq!(boot::BOOT_BREADCRUMB_MAGIC, 0x4254_3031);
    assert_eq!(BootStage::SetupEntry.as_word(), 1);
    assert_eq!(BootStage::MailboxReady.as_word(), 10);
    assert_eq!(BootStage::OpcuaReady.as_word(), 17);
    assert_eq!(BootStage::LoopEntered.as_word(), 22);
    assert_eq!(BootStage::from_word(23), None);
    assert_eq!(boot::stage_name(BootStage::SetupEntry), "setup-entry");
    assert_eq!(boot::stage_name(BootStage::OpcuaReady), "opcua-ready");
    assert_eq!(boot::stage_name_from_word(23), "unknown");

    assert_eq!(boot::next_sequence(false, 0), 1);
    assert_eq!(boot::next_sequence(true, 41), 42);
    assert_eq!(boot::next_sequence(true, u32::MAX), 1);

    let words = boot::encode_breadcrumb(BootStage::OpcuaReady, true, 2, 1_234, 0xABCD_0001);
    assert_eq!(words.sequence, 3);
    assert_eq!(words.checksum, 0xFBB8_164C);

    let decoded = boot::decode_breadcrumb(words);
    assert!(decoded.valid);
    assert_eq!(decoded.stage_word, 17);
    assert_eq!(decoded.known_stage, Some(BootStage::OpcuaReady));
    assert_eq!(decoded.sequence, 3);
    assert_eq!(decoded.uptime_ms, 1_234);
    assert_eq!(decoded.detail, 0xABCD_0001);

    let mut corrupt = words;
    corrupt.magic = 0;
    assert!(!boot::decode_breadcrumb(corrupt).valid);
}

#[test]
fn opcua_capacity_status_codes_match_source_backed_open62541_values() {
    assert_eq!(opcua_status::BAD_TOO_MANY_OPERATIONS, 0x8010_0000);
    assert_eq!(opcua_status::BAD_NOT_CONNECTED, 0x808A_0000);
    assert_eq!(opcua_status::BAD_TOO_MANY_MONITORED_ITEMS, 0x80DB_0000);
}

#[test]
fn stale_and_unpublished_do_not_map_to_fresh_good_values() {
    let unpublished = EntryMetadata::unpublished(BUCHI_PROCESS_FRESHNESS_MS);
    let stale = EntryMetadata::published_at(1_000, BUCHI_PROCESS_FRESHNESS_MS);
    let fresh = EntryMetadata::published_at(1_000, BUCHI_PROCESS_FRESHNESS_MS);

    assert_eq!(
        freshness::classify(unpublished, 1_000),
        CacheReadStatus::NeverPublished
    );
    assert_eq!(freshness::classify(stale, 3_501), CacheReadStatus::Stale);
    assert_eq!(freshness::classify(fresh, 3_500), CacheReadStatus::Ok);

    assert_eq!(
        freshness::opcua_status_for_cache_read(CacheReadStatus::NeverPublished),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(
        freshness::opcua_status_for_cache_read(CacheReadStatus::Stale),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert_eq!(
        freshness::opcua_status_for_cache_read(CacheReadStatus::NotConnected),
        opcua_status::BAD_NOT_CONNECTED
    );
    assert!(!freshness::maps_to_fresh_value(
        CacheReadStatus::NeverPublished
    ));
    assert!(!freshness::maps_to_fresh_value(CacheReadStatus::Stale));
    assert!(!freshness::maps_to_fresh_value(
        CacheReadStatus::NotConnected
    ));
    assert!(freshness::maps_to_fresh_value(CacheReadStatus::Ok));
}

#[test]
fn future_publish_timestamp_is_not_fresh_without_wraparound() {
    let entry = EntryMetadata::published_at(5_000, BUCHI_PROCESS_FRESHNESS_MS);
    assert_eq!(freshness::classify(entry, 1_000), CacheReadStatus::Stale);
    assert_eq!(
        freshness::opcua_status_for_cache_read(CacheReadStatus::Stale),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
}

#[test]
fn freshness_uses_wraparound_safe_elapsed_time() {
    const EPOCH_MS: u64 = 1_u64 << 32;
    let entry = EntryMetadata::published_at(EPOCH_MS - 51, 100);

    assert!(freshness::is_fresh(entry, EPOCH_MS + 25));
    assert!(!freshness::is_fresh(entry, EPOCH_MS + 75));
}

#[test]
fn frozen_entry_never_reclassifies_ok_across_multiple_u32_epochs() {
    const EPOCH_MS: u64 = 1_u64 << 32;
    const PUBLISHED_AT_MS: u64 = 123_456;
    const FRESHNESS_MS: u32 = 100;
    let entry = EntryMetadata::published_at(PUBLISHED_AT_MS, FRESHNESS_MS);
    let checkpoints = [
        PUBLISHED_AT_MS + u64::from(FRESHNESS_MS) + 1,
        PUBLISHED_AT_MS + EPOCH_MS,
        PUBLISHED_AT_MS + EPOCH_MS + u64::from(FRESHNESS_MS),
        PUBLISHED_AT_MS + 2 * EPOCH_MS,
        PUBLISHED_AT_MS + 2 * EPOCH_MS + u64::from(FRESHNESS_MS),
        PUBLISHED_AT_MS + 3 * EPOCH_MS,
    ];
    let observations = checkpoints.map(|now| (now, freshness::classify(entry, now)));
    println!("frozen-entry wrap observations: {observations:?}");

    assert!(
        observations
            .iter()
            .all(|(_, status)| *status == CacheReadStatus::Stale),
        "frozen-entry wrap observations: {observations:?}"
    );
}

#[test]
fn fixed_cache_model_is_bounded_and_status_coded() {
    let mut cache = FixedStateCache::<2>::new(BUCHI_PROCESS_FRESHNESS_MS);
    assert_eq!(cache.read_status(0, 0), CacheReadStatus::NeverPublished);
    assert_eq!(cache.read_status(3, 0), CacheReadStatus::InvalidIndex);
    assert!(cache.publish(1, 10, 20));
    assert!(!cache.publish(2, 10, 20));
    assert_eq!(cache.read_status(1, 30), CacheReadStatus::Ok);
    assert_eq!(cache.read_status(1, 31), CacheReadStatus::Stale);
}

#[test]
fn fixed_value_cache_returns_values_only_when_fresh() {
    let mut cache = FixedValueCache::<2>::new(BUCHI_PROCESS_FRESHNESS_MS);

    let unpublished = cache.read(0, 0);
    assert_eq!(unpublished.status, CacheReadStatus::NeverPublished);
    assert_eq!(unpublished.value, None);
    assert_eq!(
        unpublished.opcua_status(),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );
    assert!(!unpublished.has_fresh_value());

    let invalid = cache.read(3, 0);
    assert_eq!(invalid.status, CacheReadStatus::InvalidIndex);
    assert_eq!(invalid.value, None);
    assert_eq!(
        invalid.opcua_status(),
        opcua_status::BAD_INDEX_RANGE_INVALID
    );

    assert!(cache.publish(
        0,
        ScalarValue::FloatMilli(42_125),
        1_000,
        BUCHI_PROCESS_FRESHNESS_MS,
    ));
    assert!(cache.publish(
        1,
        ScalarValue::Boolean(true),
        (1_u64 << 32) - 26,
        BUCHI_PROCESS_FRESHNESS_MS,
    ));
    assert!(!cache.publish(2, ScalarValue::Int32(7), 0, BUCHI_PROCESS_FRESHNESS_MS));

    let fresh = cache.read(0, 3_500);
    assert_eq!(fresh.status, CacheReadStatus::Ok);
    assert_eq!(fresh.value, Some(ScalarValue::FloatMilli(42_125)));
    assert_eq!(fresh.opcua_status(), opcua_status::GOOD);
    assert!(fresh.has_fresh_value());

    let stale = cache.read(0, 3_501);
    assert_eq!(stale.status, CacheReadStatus::Stale);
    assert_eq!(stale.value, None);
    assert_eq!(
        stale.opcua_status(),
        opcua_status::BAD_WAITING_FOR_INITIAL_DATA
    );

    let wrapped = cache.read(1, (1_u64 << 32) + 25);
    assert_eq!(wrapped.status, CacheReadStatus::Ok);
    assert_eq!(wrapped.value, Some(ScalarValue::Boolean(true)));
}

#[test]
fn writable_surface_is_numeric_boolean_only_and_bounded() {
    assert_eq!(namespace::WRITABLE_NODES.len(), 30);
    assert_eq!(namespace::max_write_queue_capacity(), 32);
    for node in namespace::WRITABLE_NODES {
        assert_eq!(node.access, Access::WritableNumericBoolean);
        assert!(matches!(
            node.value_kind,
            ValueKind::Boolean | ValueKind::Int32 | ValueKind::Float
        ));
        assert_ne!(node.endpoint, namespace::EndpointClass::Health);
    }
    assert!(namespace::is_default_writable_node(2001));
    assert!(namespace::is_default_writable_node(2030));
    assert!(namespace::is_default_writable_node(3001));
    assert!(namespace::is_default_writable_node(3021));
    assert!(!namespace::is_default_writable_node(2002));
    assert!(!namespace::is_default_writable_node(4028));
    assert_eq!(namespace::HEALTH_NODES.len(), 49);
    assert!(namespace::is_default_health_node(4001));
    assert!(namespace::is_default_health_node(4003));
    assert!(namespace::is_default_health_node(4013));
    assert!(namespace::is_default_health_node(4022));
    assert!(namespace::is_default_health_node(4028));
    assert!(namespace::is_default_health_node(4035));
    assert!(!namespace::is_default_health_node(4037));
    assert!(namespace::is_default_health_node(4042));
    assert!(namespace::is_default_health_node(4043));
    assert!(namespace::is_default_health_node(4049));
    assert!(namespace::is_default_health_node(4050));
    assert!(!namespace::is_default_health_node(4051));
    assert_eq!(
        namespace::lookup_health_node(4013).map(|node| node.browse_name),
        Some("Health.BuchiStatusFlags")
    );
    assert_eq!(
        namespace::lookup_health_node(4022).map(|node| node.browse_name),
        Some("Health.UptimeSeconds")
    );
    let verifier_time =
        namespace::lookup_health_node(4050).expect("Buchi verifier-time trust health node exists");
    assert_eq!(verifier_time.browse_name, "Health.BuchiVerifierTimeTrusted");
    assert_eq!(verifier_time.value_kind, ValueKind::Boolean);
    assert_eq!(verifier_time.access, Access::ReadOnly);
}

#[test]
fn single_core_health_contract_replaces_m4_placeholders() {
    let expected_runtime_nodes = [
        (4022, "Health.UptimeSeconds", ValueKind::UInt32),
        (4023, "Health.IwdgLastKickAgeMs", ValueKind::UInt32),
        (4024, "Health.WatchdogStaleMask", ValueKind::UInt32),
        (4025, "Health.TaskCheckinRegisteredMask", ValueKind::UInt32),
        (4026, "Health.TaskCheckinFreshMask", ValueKind::UInt32),
        (4027, "Health.TaskCheckinDeadlineMs", ValueKind::UInt32),
    ];
    for (node_id, browse_name, value_kind) in expected_runtime_nodes {
        let node = namespace::lookup_health_node(node_id).expect("single-core node exists");
        assert_eq!(node.browse_name, browse_name);
        assert_eq!(node.value_kind, value_kind);
        assert_eq!(node.access, Access::ReadOnly);
    }

    for forbidden in [
        "Health.M4StatusValid",
        "Health.M4HeartbeatFaultActive",
        "Health.M4FaultCount",
        "Health.M4ObservedM7Sequence",
        "Health.M4ObservedM7ServiceFlags",
        "Health.M4FactoryResetRequestSequence",
    ] {
        assert!(
            namespace::HEALTH_NODES
                .iter()
                .all(|node| node.browse_name != forbidden),
            "{forbidden} must not remain in the ADR 0010 Rust Health contract"
        );
    }
}

#[test]
fn single_core_task_age_health_nodes_follow_compacted_watchdog_order() {
    let expected_task_age_nodes = [
        (4036, "Health.TaskCheckin.MainHeartbeatAgeMs", 0),
        (4038, "Health.TaskCheckin.MdnsResponderAgeMs", 1),
        (4039, "Health.TaskCheckin.NetStatusAgeMs", 2),
        (4040, "Health.TaskCheckin.UsbConsoleAgeMs", 3),
        (4041, "Health.TaskCheckin.BuchiTlsClientAgeMs", 4),
        (4042, "Health.TaskCheckin.OpcUaServerAgeMs", 5),
    ];
    for (node_id, browse_name, bit) in expected_task_age_nodes {
        let node = namespace::lookup_health_node(node_id).expect("task age node exists");
        assert_eq!(node.browse_name, browse_name);
        assert_eq!(node.value_kind, ValueKind::UInt32);
        assert_eq!(node.node_id, node_id);
        #[cfg(feature = "product")]
        assert!(bit < watchdog::TASK_COUNT);
        #[cfg(not(feature = "product"))]
        assert_eq!(bit < watchdog::TASK_COUNT, bit < 4);
    }

    assert_eq!(watchdog::TaskId::MainHeartbeat.index(), 0);
    assert_eq!(watchdog::TaskId::MdnsResponder.index(), 1);
    assert_eq!(watchdog::TaskId::NetStatus.index(), 2);
    assert_eq!(watchdog::TaskId::UsbConsole.index(), 3);
    #[cfg(feature = "product")]
    assert_eq!(watchdog::TaskId::BuchiTlsClient.index(), 4);
    #[cfg(feature = "product")]
    assert_eq!(watchdog::TaskId::OpcUaServer.index(), 5);
}

#[test]
fn retained_last_fault_contract_keeps_presence_separate_from_numeric_data() {
    let present = namespace::HEALTH_NODES
        .iter()
        .find(|node| node.node_id == namespace::HEALTH_LAST_FAULT_PRESENT_NODE_ID)
        .expect("last fault presence node exists");
    assert_eq!(present.value_kind, ValueKind::Boolean);
    assert_eq!(present.access, Access::ReadOnly);

    for node_id in 4029..=4033 {
        let node = namespace::HEALTH_NODES
            .iter()
            .find(|node| node.node_id == node_id)
            .expect("last fault numeric node exists");
        assert_eq!(node.value_kind, ValueKind::UInt32);
        assert_eq!(node.access, Access::ReadOnly);
    }
    assert_eq!(opcua_status::BAD_NO_DATA, 0x809B_0000);
}

#[test]
fn watchdog_contract_uses_fixed_task_ids_and_10s_iwdg_settings() {
    assert_eq!(watchdog::IWDG_TIMEOUT_MS, 10_000);
    assert_eq!(watchdog::MONITOR_INTERVAL_MS, 250);
    assert_eq!(watchdog::TASK_DEADLINE_MS, 2_000);
    #[cfg(not(feature = "product"))]
    assert_eq!(watchdog::TASK_COUNT, 4);
    #[cfg(feature = "product")]
    assert_eq!(watchdog::TASK_COUNT, 6);
    assert_eq!(watchdog::TaskId::MainHeartbeat.index(), 0);
    assert_eq!(watchdog::TaskId::MdnsResponder.index(), 1);
    assert_eq!(watchdog::TaskId::NetStatus.index(), 2);
    assert_eq!(watchdog::TaskId::UsbConsole.index(), 3);
    #[cfg(not(feature = "product"))]
    assert_eq!(watchdog::TaskId::from_index(4), None);
    #[cfg(feature = "product")]
    assert_eq!(
        watchdog::TaskId::from_index(4),
        Some(watchdog::TaskId::BuchiTlsClient)
    );
    #[cfg(feature = "product")]
    assert_eq!(
        watchdog::TaskId::from_index(5),
        Some(watchdog::TaskId::OpcUaServer)
    );
    #[cfg(not(feature = "product"))]
    assert_eq!(watchdog::ALL_TASKS_MASK, 0b1111);
    #[cfg(feature = "product")]
    assert_eq!(watchdog::ALL_TASKS_MASK, 0b11_1111);

    assert_eq!(watchdog::LSI_HZ_NOMINAL, 32_000);
    assert_eq!(watchdog::IWDG_PR_DIV256_CODE, 6);
    assert_eq!(watchdog::IWDG_RELOAD_10S_DIV256, 1_249);
    let effective_timeout_ms =
        (watchdog::IWDG_RELOAD_10S_DIV256 + 1) * 1_000 * watchdog::IWDG_PR_DIV256
            / watchdog::LSI_HZ_NOMINAL;
    assert_eq!(effective_timeout_ms, 10_000);
}

fn valid_early_iwdg_readback() -> watchdog::EarlyIwdgReadback {
    watchdog::EarlyIwdgReadback {
        rcc_gcr: 1 << 0,
        rcc_csr: (1 << 0) | (1 << 1),
        iwdg_sr: 0,
        iwdg_pr: watchdog::IWDG_PR_DIV256_CODE,
        iwdg_rlr: watchdog::IWDG_RELOAD_10S_DIV256,
        iwdg_winr: watchdog::IWDG_WINDOW_DISABLED,
    }
}

#[test]
fn lsi_readiness_rejects_repeated_enable_only_observations() {
    for observation_index in 1..=1_024 {
        assert!(
            !watchdog::lsi_observation_is_ready(1 << 0),
            "LSION-only observation {observation_index} became ready"
        );
    }
}

#[test]
fn lsi_readiness_accepts_delayed_ready_only_on_third_observation() {
    let observations = [1 << 0, 1 << 0, (1 << 0) | (1 << 1)];
    let readiness = observations.map(watchdog::lsi_observation_is_ready);

    assert_eq!(readiness, [false, false, true]);
    assert_eq!(
        readiness
            .iter()
            .position(|ready| *ready)
            .map(|index| index + 1),
        Some(3)
    );
}

#[test]
fn early_iwdg_readback_accepts_complete_valid_state() {
    let readback = valid_early_iwdg_readback();
    assert_eq!(watchdog::early_iwdg_failure_mask(readback), 0);
    assert!(watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_missing_full_system_scope() {
    let mut readback = valid_early_iwdg_readback();
    readback.rcc_gcr = 0;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_RESET_SCOPE
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_disabled_lsi() {
    let mut readback = valid_early_iwdg_readback();
    readback.rcc_csr = 1 << 1;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_LSI_STATE
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_unready_lsi() {
    let mut readback = valid_early_iwdg_readback();
    readback.rcc_csr = 1 << 0;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_LSI_STATE
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_pending_update() {
    let mut readback = valid_early_iwdg_readback();
    readback.iwdg_sr = 1;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_UPDATE_PENDING
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_wrong_prescaler() {
    let mut readback = valid_early_iwdg_readback();
    readback.iwdg_pr = watchdog::IWDG_PR_DIV256_CODE - 1;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_PRESCALER
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_wrong_reload() {
    let mut readback = valid_early_iwdg_readback();
    readback.iwdg_rlr = watchdog::IWDG_RELOAD_10S_DIV256 - 1;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_RELOAD
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_readback_rejects_enabled_window() {
    let mut readback = valid_early_iwdg_readback();
    readback.iwdg_winr = watchdog::IWDG_WINDOW_DISABLED - 1;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_WINDOW
    );
    assert!(!watchdog::early_iwdg_readback_valid(readback));
}

#[test]
fn early_iwdg_failure_mask_preserves_multiple_failures() {
    let mut readback = valid_early_iwdg_readback();
    readback.rcc_gcr = 0;
    readback.iwdg_sr = 0b101;
    readback.iwdg_rlr = watchdog::IWDG_RELOAD_10S_DIV256 - 1;
    assert_eq!(
        watchdog::early_iwdg_failure_mask(readback),
        watchdog::EARLY_IWDG_FAILURE_RESET_SCOPE
            | watchdog::EARLY_IWDG_FAILURE_UPDATE_PENDING
            | watchdog::EARLY_IWDG_FAILURE_RELOAD
    );
}

#[test]
fn watchdog_slot_classification_wraparound_and_boundaries() {
    use watchdog::{TaskId, WatchdogSlot as Slot, WatchdogSlotCheckin};

    let slots = Slot::MainHeartbeat.mask() | Slot::MdnsResponder.mask();
    let tasks = TaskId::MainHeartbeat.mask() | TaskId::MdnsResponder.mask();
    for (last, now, deadline, age, stale) in [
        (1_000, 3_000, 2_000, 2_000, false),
        (1_000, 3_001, 2_000, 2_001, true),
        // MAX-100 -> 0 takes 101 ticks; another 149 ticks reaches the deadline.
        (u32::MAX - 100, 149, 250, 250, false),
        (u32::MAX - 100, 150, 250, 251, true),
    ] {
        let checkins = [
            WatchdogSlotCheckin::new(Slot::MainHeartbeat, last, deadline),
            WatchdogSlotCheckin::new(Slot::MdnsResponder, last, deadline),
        ];
        let snapshot = watchdog::classify_slots(now, &checkins);
        assert_eq!(
            snapshot.observed_stale_slots_mask,
            if stale { slots } else { 0 }
        );
        assert_eq!(snapshot.public_registered_mask, tasks);
        assert_eq!(snapshot.public_fresh_mask, if stale { 0 } else { tasks });
        assert_eq!(
            snapshot.reset_critical_stale_slots_mask,
            if stale { Slot::MdnsResponder.mask() } else { 0 }
        );
        assert_eq!(
            snapshot.public_reset_critical_stale_mask,
            if stale {
                TaskId::MdnsResponder.mask()
            } else {
                0
            }
        );
        assert_eq!(snapshot.all_reset_critical_fresh, !stale);
        for checkin in checkins {
            assert_eq!(checkin.is_fresh(now), !stale);
            assert_eq!(
                snapshot.public_age_ms[checkin.slot.public_task().index()],
                Some(age)
            );
        }
    }
}

#[test]
fn flash_maintenance_longer_than_task_deadline_refreshes_within_bound() {
    use watchdog::{FlashMaintenanceMonitorAction as Action, FlashMaintenanceState as State};

    let maintenance = State::inactive().enter(10_000);
    assert_eq!(
        maintenance.monitor_action(10_000 + watchdog::TASK_DEADLINE_MS + 1),
        Action::RefreshAndSkipClassification
    );
}

#[test]
fn flash_maintenance_exact_bound_and_over_bound_use_ordinary_containment() {
    use watchdog::{FlashMaintenanceMonitorAction as Action, FlashMaintenanceState as State};

    let start_ms = 123;
    let maintenance = State::inactive().enter(start_ms);
    assert_eq!(
        maintenance.monitor_action(start_ms + watchdog::FLASH_MAINTENANCE_BOUND_MS - 1),
        Action::RefreshAndSkipClassification
    );
    assert_eq!(
        maintenance.monitor_action(start_ms + watchdog::FLASH_MAINTENANCE_BOUND_MS),
        Action::OrdinaryContainment
    );
    assert_eq!(
        maintenance.monitor_action(start_ms + watchdog::FLASH_MAINTENANCE_BOUND_MS + 1),
        Action::OrdinaryContainment
    );
}

#[test]
fn flash_maintenance_elapsed_time_wraps_without_extending_bound() {
    use watchdog::{FlashMaintenanceMonitorAction as Action, FlashMaintenanceState as State};

    let start_ms = u32::MAX - 1_000;
    let maintenance = State::inactive().enter(start_ms);
    assert_eq!(
        maintenance.monitor_action(1_999),
        Action::RefreshAndSkipClassification
    );
    assert_eq!(
        maintenance.monitor_action(3_999),
        Action::OrdinaryContainment
    );
}

#[test]
fn flash_maintenance_nesting_preserves_outermost_start_until_outer_leave() {
    use watchdog::{FlashMaintenanceLeaveOutcome as Outcome, FlashMaintenanceState as State};

    let outer = State::inactive().enter(1_000);
    let nested = outer.enter(2_500);
    assert_eq!(nested.depth(), 2);
    assert_eq!(nested.outermost_start_ms(), 1_000);

    let inner_leave = nested.leave(3_000);
    assert_eq!(inner_leave.outcome, Outcome::NestedStillActive);
    assert_eq!(inner_leave.state.depth(), 1);
    assert_eq!(inner_leave.state.outermost_start_ms(), 1_000);

    let outer_leave = inner_leave.state.leave(4_500);
    assert_eq!(
        outer_leave.outcome,
        Outcome::CompletedWithinBound { excluded_ms: 3_500 }
    );
    assert_eq!(outer_leave.state, State::inactive());
}

#[test]
fn under_bound_completion_rebases_only_live_deadlines() {
    use watchdog::{FlashMaintenanceLeaveOutcome as Outcome, FlashMaintenanceState as State};

    let start_ms = 10_000;
    let leave_ms = 14_000;
    let excluded_ms = match State::inactive().enter(start_ms).leave(leave_ms).outcome {
        Outcome::CompletedWithinBound { excluded_ms } => excluded_ms,
        other => panic!("unexpected completion: {other:?}"),
    };
    assert_eq!(excluded_ms, 4_000);

    let live_checkin = start_ms.wrapping_sub(1_700);
    let rebased_live = watchdog::rebase_live_checkin_after_maintenance(
        live_checkin,
        watchdog::TASK_DEADLINE_MS,
        start_ms,
        excluded_ms,
    );
    assert_eq!(leave_ms.wrapping_sub(rebased_live), 1_700);

    let stale_checkin = start_ms.wrapping_sub(2_100);
    let preserved_stale = watchdog::rebase_live_checkin_after_maintenance(
        stale_checkin,
        watchdog::TASK_DEADLINE_MS,
        start_ms,
        excluded_ms,
    );
    assert_eq!(preserved_stale, stale_checkin);
    assert!(leave_ms.wrapping_sub(preserved_stale) > watchdog::TASK_DEADLINE_MS);

    let during_maintenance = start_ms + 100;
    assert_eq!(
        watchdog::rebase_live_checkin_after_maintenance(
            during_maintenance,
            watchdog::TASK_DEADLINE_MS,
            start_ms,
            excluded_ms,
        ),
        during_maintenance,
        "a check-in newer than entry must never be shifted into the future"
    );
}

#[test]
fn completion_at_or_over_bound_never_reports_deadline_rebase() {
    use watchdog::{FlashMaintenanceLeaveOutcome as Outcome, FlashMaintenanceState as State};

    let start_ms = 5_000;
    let exact = State::inactive()
        .enter(start_ms)
        .leave(start_ms + watchdog::FLASH_MAINTENANCE_BOUND_MS);
    assert_eq!(
        exact.outcome,
        Outcome::CompletedAtOrBeyondBound {
            elapsed_ms: watchdog::FLASH_MAINTENANCE_BOUND_MS
        }
    );

    let over = State::inactive()
        .enter(start_ms)
        .leave(start_ms + watchdog::FLASH_MAINTENANCE_BOUND_MS + 250);
    assert_eq!(
        over.outcome,
        Outcome::CompletedAtOrBeyondBound {
            elapsed_ms: watchdog::FLASH_MAINTENANCE_BOUND_MS + 250
        }
    );
}

#[cfg(feature = "product")]
fn product_slot_checkins(last_checkin_ms: u32) -> [watchdog::WatchdogSlotCheckin; 10] {
    use watchdog::{WatchdogSlot as Slot, WatchdogSlotCheckin as Checkin};
    [
        Checkin::new(Slot::MainHeartbeat, last_checkin_ms, 2_000),
        Checkin::new(Slot::MdnsResponder, last_checkin_ms, 2_000),
        Checkin::new(Slot::NetStatus, last_checkin_ms, 2_000),
        Checkin::new(Slot::UsbConsole, last_checkin_ms, 2_000),
        Checkin::new(Slot::BuchiTlsClient, last_checkin_ms, 2_000),
        Checkin::new(Slot::OpcUaListener0, last_checkin_ms, 2_000),
        Checkin::new(Slot::OpcUaListener1, last_checkin_ms, 2_000),
        Checkin::new(Slot::OpcUaListener2, last_checkin_ms, 2_000),
        Checkin::new(Slot::NetRunner, last_checkin_ms, 2_000),
        Checkin::new(Slot::UsbDevice, last_checkin_ms, 2_000),
    ]
}

#[cfg(feature = "product")]
#[test]
fn watchdog_slots_pin_classes_and_public_projection() {
    use watchdog::{SupervisionClass as Class, TaskId, WatchdogSlot as Slot};

    assert_eq!(watchdog::WATCHDOG_SLOT_COUNT, 10);
    let expected = [
        (
            Slot::MainHeartbeat,
            TaskId::MainHeartbeat,
            Class::HealthOnly,
        ),
        (
            Slot::MdnsResponder,
            TaskId::MdnsResponder,
            Class::ResetCritical,
        ),
        (Slot::NetStatus, TaskId::NetStatus, Class::HealthOnly),
        (Slot::UsbConsole, TaskId::UsbConsole, Class::HealthOnly),
        (
            Slot::BuchiTlsClient,
            TaskId::BuchiTlsClient,
            Class::ResetCritical,
        ),
        (
            Slot::OpcUaListener0,
            TaskId::OpcUaServer,
            Class::ResetCritical,
        ),
        (
            Slot::OpcUaListener1,
            TaskId::OpcUaServer,
            Class::ResetCritical,
        ),
        (
            Slot::OpcUaListener2,
            TaskId::OpcUaServer,
            Class::ResetCritical,
        ),
        (Slot::NetRunner, TaskId::NetStatus, Class::ResetCritical),
        (Slot::UsbDevice, TaskId::UsbConsole, Class::HealthOnly),
    ];
    for (index, (slot, public, class)) in expected.into_iter().enumerate() {
        assert_eq!(slot.index(), index);
        assert_eq!(Slot::from_index(index), Some(slot));
        assert_eq!(slot.public_task(), public);
        assert_eq!(slot.supervision_class(), class);
    }
    assert_eq!(Slot::from_index(watchdog::WATCHDOG_SLOT_COUNT), None);
}

#[cfg(feature = "product")]
#[test]
fn health_only_stale_is_visible_without_reset_inhibition() {
    use watchdog::{TaskId, WatchdogSlot as Slot};

    let mut checkins = product_slot_checkins(4_000);
    checkins[Slot::MainHeartbeat.index()].last_checkin_ms = 1_000;
    checkins[Slot::NetStatus.index()].last_checkin_ms = 1_500;
    checkins[Slot::UsbConsole.index()].last_checkin_ms = 1_750;
    checkins[Slot::UsbDevice.index()].last_checkin_ms = 1_900;
    let snapshot = watchdog::classify_slots(4_000, &checkins);

    assert_eq!(
        snapshot.observed_stale_slots_mask,
        Slot::MainHeartbeat.mask()
            | Slot::NetStatus.mask()
            | Slot::UsbConsole.mask()
            | Slot::UsbDevice.mask()
    );
    assert_eq!(snapshot.reset_critical_stale_slots_mask, 0);
    assert_eq!(snapshot.public_reset_critical_stale_mask, 0);
    assert!(snapshot.all_reset_critical_fresh);
    assert_eq!(snapshot.public_registered_mask, watchdog::ALL_TASKS_MASK);
    assert_eq!(
        snapshot.public_fresh_mask,
        watchdog::ALL_TASKS_MASK
            & !(TaskId::MainHeartbeat.mask()
                | TaskId::NetStatus.mask()
                | TaskId::UsbConsole.mask())
    );
    assert_eq!(
        snapshot.public_age_ms[TaskId::MainHeartbeat.index()],
        Some(3_000)
    );
    assert_eq!(
        snapshot.public_age_ms[TaskId::NetStatus.index()],
        Some(2_500)
    );
    assert_eq!(
        snapshot.public_age_ms[TaskId::UsbConsole.index()],
        Some(2_250)
    );
}

#[cfg(feature = "product")]
#[test]
fn reset_critical_constituent_controls_folded_reset_mask() {
    use watchdog::{TaskId, WatchdogSlot as Slot};

    let mut checkins = product_slot_checkins(4_000);
    checkins[Slot::NetRunner.index()].last_checkin_ms = 1_000;
    checkins[Slot::OpcUaListener1.index()].last_checkin_ms = 500;
    let snapshot = watchdog::classify_slots(4_000, &checkins);

    assert_eq!(
        snapshot.reset_critical_stale_slots_mask,
        Slot::NetRunner.mask() | Slot::OpcUaListener1.mask()
    );
    assert_eq!(
        snapshot.public_reset_critical_stale_mask,
        TaskId::NetStatus.mask() | TaskId::OpcUaServer.mask()
    );
    assert!(!snapshot.all_reset_critical_fresh);
    assert_eq!(
        snapshot.public_fresh_mask & TaskId::NetStatus.mask(),
        0,
        "fresh NetStatus reporter must not hide stale NetRunner"
    );
    assert_eq!(
        snapshot.public_fresh_mask & TaskId::OpcUaServer.mask(),
        0,
        "two fresh listeners must not hide one stale listener"
    );
    assert_eq!(
        snapshot.public_age_ms[TaskId::OpcUaServer.index()],
        Some(3_500),
        "the stalest listener age must win"
    );
}

#[cfg(feature = "product")]
#[test]
fn dynamic_exemption_ignores_age_without_hiding_other_constituents() {
    use watchdog::{TaskId, WatchdogSlot as Slot};

    let mut checkins = product_slot_checkins(4_000);
    checkins[Slot::UsbDevice.index()] =
        watchdog::WatchdogSlotCheckin::new(Slot::UsbDevice, 0, 2_000).exempt();
    let exempt = watchdog::classify_slots(4_000, &checkins);
    assert_eq!(exempt.observed_stale_slots_mask, 0);
    assert_eq!(
        exempt.public_age_ms[TaskId::UsbConsole.index()],
        Some(0),
        "the non-exempt console constituent still supplies public age"
    );

    checkins[Slot::UsbConsole.index()].last_checkin_ms = 0;
    let stale_console = watchdog::classify_slots(4_000, &checkins);
    assert_eq!(
        stale_console.observed_stale_slots_mask,
        Slot::UsbConsole.mask()
    );
    assert_eq!(stale_console.public_reset_critical_stale_mask, 0);
    assert_eq!(
        stale_console.public_fresh_mask & TaskId::UsbConsole.mask(),
        0
    );
}

#[cfg(not(feature = "product"))]
#[test]
fn non_product_watchdog_slot_count_stays_four() {
    assert_eq!(watchdog::WATCHDOG_SLOT_COUNT, 4);
    assert_eq!(
        watchdog::WatchdogSlot::from_index(3),
        Some(watchdog::WatchdogSlot::UsbConsole)
    );
    assert_eq!(watchdog::WatchdogSlot::from_index(4), None);
}
