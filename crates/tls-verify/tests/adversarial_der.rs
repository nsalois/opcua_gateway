// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use opta_tls_verify::{
    parse_certificate_der, verify_ca_certificate, verify_ca_certificate_with_optional_time,
    verify_leaf_chain, verify_leaf_chain_with_optional_time, ServerName, UnixTime,
    MAX_CERT_DER_BYTES,
};
use proptest::prelude::*;

const LEAF: &[u8] = include_bytes!("../testdata/mock-leaf.der");

fn valid_time() -> UnixTime {
    UnixTime::from_ymdhms(2026, 6, 25, 12, 0, 0).expect("fixed valid time")
}

#[test]
fn valid_certificate_truncation_at_every_offset_fails_cleanly() {
    for end in 0..LEAF.len() {
        assert!(
            parse_certificate_der(&LEAF[..end]).is_err(),
            "truncation at byte {end} unexpectedly parsed"
        );
    }
}

#[test]
fn trailing_bytes_after_certificate_fail_cleanly() {
    for suffix_len in 1..=32 {
        let mut bytes = LEAF.to_vec();
        bytes.extend(std::iter::repeat_n(0xa5, suffix_len));
        assert!(
            parse_certificate_der(&bytes).is_err(),
            "suffix={suffix_len}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn public_certificate_entry_points_never_panic_on_bounded_bytes(
        leaf in prop::collection::vec(any::<u8>(), 0..=MAX_CERT_DER_BYTES),
        ca in prop::collection::vec(any::<u8>(), 0..=MAX_CERT_DER_BYTES),
    ) {
        let now = valid_time();
        let _ = parse_certificate_der(&leaf);
        let _ = verify_ca_certificate(&ca, now);
        let _ = verify_ca_certificate_with_optional_time(&ca, None);
        let _ = verify_leaf_chain(
            &leaf,
            &ca,
            ServerName::Ipv4([192, 0, 2, 1]),
            now,
        );
        let _ = verify_leaf_chain(&leaf, &ca, ServerName::Dns("localhost"), now);
        let _ = verify_leaf_chain_with_optional_time(
            &leaf,
            &ca,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        );
        let _ = verify_leaf_chain_with_optional_time(
            &leaf,
            &ca,
            ServerName::Dns("localhost"),
            None,
        );
    }
}
