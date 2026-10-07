use opta_gateway_contracts::config::{
    decode_slot, encode_legacy_slot, encode_reset_slot, encode_slot, select_config, ConfigSource,
    GatewayConfig, GatewayTrust, RecordKind, TrustUpload, TrustUploadError, LEGACY_VERSION,
    MAX_TRUST_CA_DER_BYTES, RECORD_BODY_SIZE, RECORD_KIND_OFFSET, RECORD_SIZE, VERSION,
};

const MAC: [u8; 6] = [0x02, 0xa7, 0x5c, 0xe5, 0x27, 0x84];

fn config() -> GatewayConfig {
    GatewayConfig::defaults_from_mac(MAC)
}

fn trust() -> GatewayTrust {
    GatewayTrust::from_ca_der(&[0x30, 0x03, 0x02, 0x01, 0x00], true).unwrap()
}

fn rewrite_record_crc(record: &mut [u8; RECORD_SIZE]) {
    let mut crc = 0xFFFF_FFFFu32;
    for (offset, &byte) in record[..RECORD_BODY_SIZE].iter().enumerate() {
        let byte = if (20..24).contains(&offset) { 0 } else { byte };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    record[20..24].copy_from_slice(&(!crc).to_le_bytes());
}

#[test]
fn every_meaningful_record_byte_flip_fails_closed() {
    let fallback = config();
    let original = encode_slot(42, &fallback, &trust()).unwrap();
    // CRC-covered body plus the four-byte final marker. The remaining bytes
    // are flash-write-granule padding and are pinned separately below.
    for offset in 0..RECORD_BODY_SIZE + 4 {
        let mut corrupt = original;
        corrupt[offset] ^= 0x01;
        let decoded = decode_slot(&corrupt, fallback);
        assert!(!decoded.valid, "byte flip at {offset} decoded valid");
        assert_eq!(
            decoded.config, fallback,
            "attacker data escaped at {offset}"
        );
        assert_eq!(
            decoded.trust,
            GatewayTrust::missing(),
            "trust escaped at {offset}"
        );
    }
}

#[test]
fn every_header_bit_flip_fails_closed() {
    let fallback = config();
    let original = encode_slot(42, &fallback, &trust()).unwrap();
    for offset in 0..24 {
        for bit in 0..8 {
            let mut corrupt = original;
            corrupt[offset] ^= 1 << bit;
            let decoded = decode_slot(&corrupt, fallback);
            assert!(!decoded.valid, "header bit {offset}:{bit} decoded valid");
            assert_eq!(decoded.trust, GatewayTrust::missing());
        }
    }
}

#[test]
fn truncation_at_every_offset_fails_closed() {
    let fallback = config();
    let original = encode_slot(42, &fallback, &trust()).unwrap();
    for end in 0..RECORD_SIZE {
        let decoded = decode_slot(&original[..end], fallback);
        assert!(!decoded.valid, "truncation at {end} decoded valid");
        assert_eq!(decoded.config, fallback);
        assert_eq!(decoded.trust, GatewayTrust::missing());
    }
}

#[test]
fn versions_and_ab_selection_fail_closed_under_loser_corruption() {
    let fallback = config();
    let legacy = encode_legacy_slot(9, &fallback).unwrap();
    let decoded = decode_slot(&legacy, fallback);
    assert!(decoded.valid);
    assert_eq!(decoded.version, LEGACY_VERSION);
    assert_eq!(decoded.trust, GatewayTrust::missing());

    let mut future = encode_slot(10, &fallback, &trust()).unwrap();
    future[4..6].copy_from_slice(&(VERSION + 1).to_le_bytes());
    assert!(!decode_slot(&future, fallback).valid);

    let a = encode_slot(10, &fallback, &trust()).unwrap();
    let mut b = encode_slot(11, &fallback, &trust()).unwrap();
    b[300] ^= 1;
    assert_eq!(select_config(&a, &b, MAC).source, ConfigSource::SlotA);

    let mut a_bad = a;
    a_bad[301] ^= 1;
    let b_good = encode_slot(11, &fallback, &trust()).unwrap();
    assert_eq!(
        select_config(&a_bad, &b_good, MAC).source,
        ConfigSource::SlotB
    );

    let both = select_config(&a_bad, &b, MAC);
    assert_eq!(both.source, ConfigSource::Defaults);
    assert_eq!(both.trust, GatewayTrust::missing());
}

#[test]
#[ignore = "pins open finding BH-4"]
fn every_encoded_record_byte_is_integrity_checked() {
    let fallback = config();
    let original = encode_slot(42, &fallback, &trust()).unwrap();
    for offset in 0..RECORD_SIZE {
        let mut corrupt = original;
        corrupt[offset] ^= 1;
        assert!(
            !decode_slot(&corrupt, fallback).valid,
            "byte {offset} not covered"
        );
    }
}

#[test]
#[ignore = "pins open finding BH-5"]
fn sequence_rollover_selects_new_commit() {
    let fallback = config();
    let old = encode_slot(u64::MAX, &fallback, &trust()).unwrap();
    let new = encode_slot(1, &fallback, &trust()).unwrap();
    assert_eq!(select_config(&old, &new, MAC).source, ConfigSource::SlotB);
}

#[test]
fn reset_kind_fits_reserved_crc_covered_body_space_without_record_growth() {
    assert_eq!(RECORD_BODY_SIZE, 2304);
    assert_eq!(RECORD_SIZE, 2336);
    assert_eq!(RECORD_KIND_OFFSET, 228);
    let reset = encode_reset_slot(7, MAC).unwrap();
    let decoded = decode_slot(&reset, config());
    assert!(decoded.valid);
    assert_eq!(decoded.kind, Some(RecordKind::Reset));

    let mut corrupt_reserved_kind = reset;
    corrupt_reserved_kind[RECORD_KIND_OFFSET] ^= 1;
    assert!(!decode_slot(&corrupt_reserved_kind, config()).valid);

    let mut unknown_kind_with_valid_crc = reset;
    unknown_kind_with_valid_crc[RECORD_KIND_OFFSET] = 2;
    rewrite_record_crc(&mut unknown_kind_with_valid_crc);
    assert!(!decode_slot(&unknown_kind_with_valid_crc, config()).valid);
}

#[test]
fn reset_kind_beats_pre_reset_max_sequence_but_not_its_first_successor() {
    let old = encode_slot(u64::MAX, &config(), &trust()).unwrap();
    let reset = encode_reset_slot(1, MAC).unwrap();
    let selected_reset = select_config(&old, &reset, MAC);
    assert_eq!(selected_reset.source, ConfigSource::SlotB);
    assert_eq!(selected_reset.kind, Some(RecordKind::Reset));
    assert_eq!(selected_reset.trust, GatewayTrust::missing());

    let first_post_reset = encode_slot(2, &config(), &GatewayTrust::missing()).unwrap();
    let selected_normal = select_config(&first_post_reset, &reset, MAC);
    assert_eq!(selected_normal.source, ConfigSource::SlotA);
    assert_eq!(selected_normal.kind, Some(RecordKind::Normal));
}

#[test]
#[ignore = "pins open finding BH-9"]
fn rejected_rebegin_aborts_and_zeroizes_the_old_upload() {
    let mut upload = TrustUpload::new();
    upload.begin(4).unwrap();
    upload.append_hex("3003").unwrap();
    assert_eq!(
        upload.begin(MAX_TRUST_CA_DER_BYTES + 1),
        Err(TrustUploadError::InvalidLength)
    );
    assert_eq!(
        upload.received_len(),
        0,
        "rejected begin retained prior bytes"
    );
    assert_eq!(upload.ca_der(), Err(TrustUploadError::NotStarted));
}
