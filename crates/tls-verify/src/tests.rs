use super::certificate::OID_SHA256_WITH_RSA_ENCRYPTION;
use super::*;

const MOCK_CA: &[u8] = include_bytes!("../testdata/mock-ca.der");
const MOCK_CA_BAD_KEY_USAGE: &[u8] = include_bytes!("../testdata/mock-ca-bad-key-usage.der");
const MOCK_LEAF: &[u8] = include_bytes!("../testdata/mock-leaf.der");
const MOCK_LEAF_BAD_KEY_USAGE: &[u8] = include_bytes!("../testdata/mock-leaf-bad-key-usage.der");
const MOCK_LEAF_CN_ONLY: &[u8] = include_bytes!("../testdata/mock-leaf-cn-only.der");
const UNRELATED_CA: &[u8] = include_bytes!("../testdata/unrelated-ca.der");
const MOCK_LEAF_TLS13_PSS_SIG: &[u8] = include_bytes!("../testdata/mock-leaf-tls13-pss-sha256.sig");

fn valid_time() -> UnixTime {
    UnixTime::from_ymdhms(2026, 6, 25, 12, 0, 0).unwrap()
}

#[test]
fn accelerated_ca_and_leaf_validity_endpoints_with_supplied_time() {
    // Parse independently, then exercise the production validity predicate.
    // Chain, signature, SAN and clockless mandatory checks remain covered by
    // the existing full verifier tests; endpoint arithmetic is not a bypass.
    for der in [MOCK_CA, MOCK_LEAF] {
        let parsed = parse_certificate_der(der).unwrap();
        let before = parsed.not_before();
        let after = parsed.not_after();
        for (seconds, expected) in [
            (before.0 - 1, false),
            (before.0, true),
            (before.0 + 1, true),
            (after.0 - 1, true),
            (after.0, true),
            (after.0 + 1, false),
        ] {
            assert_eq!(
                super::certificate::verify_time(&parsed, UnixTime::from_seconds(seconds)).is_ok(),
                expected
            );
        }
    }
}

#[test]
fn synthetic_ca_self_signatures_verify() {
    let mock_ca = verify_ca_certificate(MOCK_CA, valid_time()).expect("mock CA verifies");
    assert_eq!(mock_ca.public_key().exponent(), 65_537);
    let unrelated_ca =
        verify_ca_certificate(UNRELATED_CA, valid_time()).expect("Unrelated synthetic CA verifies");
    assert_eq!(unrelated_ca.public_key().exponent(), 65_537);
}

#[test]
fn mock_leaf_chain_and_san_verify() {
    verify_leaf_chain(
        MOCK_LEAF,
        MOCK_CA,
        ServerName::Ipv4([192, 0, 2, 1]),
        valid_time(),
    )
    .expect("IP SAN verifies");
    verify_leaf_chain(
        MOCK_LEAF,
        MOCK_CA,
        ServerName::Dns("LOCALHOST"),
        valid_time(),
    )
    .expect("DNS SAN verifies case-insensitively");
}

#[test]
fn clock_optional_valid_chain_verifies_without_time() {
    verify_ca_certificate_with_optional_time(MOCK_CA, None)
        .expect("CA mandatory checks pass without verifier time");
    verify_leaf_chain_with_optional_time(
        MOCK_LEAF,
        MOCK_CA,
        ServerName::Ipv4([192, 0, 2, 1]),
        None,
    )
    .expect("leaf mandatory checks pass without verifier time");
}

#[test]
fn clock_optional_wrong_ca_still_fails() {
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            MOCK_LEAF,
            UNRELATED_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        ),
        Err(VerifyError::BadCaConstraints)
    );
}

#[test]
fn clock_optional_wrong_san_still_fails() {
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            MOCK_LEAF,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 2]),
            None,
        ),
        Err(VerifyError::NameMismatch)
    );
}

#[test]
fn clock_optional_bad_signature_still_fails() {
    let mut leaf = MOCK_LEAF.to_vec();
    let last = leaf.len() - 1;
    leaf[last] ^= 0x01;
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            &leaf,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        ),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn clock_optional_bad_ca_self_signature_still_fails() {
    let mut ca = MOCK_CA.to_vec();
    let last = ca.len() - 1;
    ca[last] ^= 0x01;
    assert!(matches!(
        verify_ca_certificate_with_optional_time(&ca, None),
        Err(VerifyError::InvalidSignature)
    ));
}

#[test]
fn clock_optional_malformed_der_still_fails() {
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            &MOCK_LEAF[..MOCK_LEAF.len() - 5],
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        ),
        Err(VerifyError::MalformedDer)
    );
}

#[test]
fn clock_optional_bad_constraints_still_fail() {
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            MOCK_CA,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        ),
        Err(VerifyError::BadCaConstraints)
    );
}

#[test]
fn clock_optional_bad_ca_key_usage_still_fails() {
    assert!(matches!(
        verify_ca_certificate_with_optional_time(MOCK_CA_BAD_KEY_USAGE, None),
        Err(VerifyError::BadKeyUsage)
    ));
}

#[test]
fn clock_optional_bad_key_usage_still_fails() {
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            MOCK_LEAF_BAD_KEY_USAGE,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        ),
        Err(VerifyError::BadKeyUsage)
    );
}

#[test]
fn clock_optional_does_not_fall_back_to_common_name() {
    assert_eq!(
        verify_leaf_chain_with_optional_time(
            MOCK_LEAF_CN_ONLY,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            None,
        ),
        Err(VerifyError::MissingSan)
    );
}

#[test]
fn expired_chain_still_fails_when_time_is_present() {
    let expired = UnixTime::from_ymdhms(2040, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
        verify_leaf_chain(
            MOCK_LEAF,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            expired,
        ),
        Err(VerifyError::InvalidTime)
    );
}

#[cfg(feature = "embedded-tls-019")]
#[test]
fn embedded_tls_verifier_constructor_carries_absent_time() {
    let verifier = EmbeddedTlsRsaVerifier::new_with_optional_time(MOCK_CA, None);
    assert_eq!(verifier.now, None);
}

#[test]
fn tls13_rsa_pss_certificate_verify_signature_verifies() {
    let leaf = verify_leaf_chain_with_public_key(
        MOCK_LEAF,
        MOCK_CA,
        ServerName::Dns("localhost"),
        valid_time(),
    )
    .expect("mock leaf chain verifies");
    let transcript_hash = [0x42; 32];

    verify_tls13_certificate_verify_rsa_pss_sha256(
        leaf.public_key(),
        &transcript_hash,
        MOCK_LEAF_TLS13_PSS_SIG,
    )
    .expect("Synthetic TLS 1.3 RSA-PSS signature verifies");

    assert_eq!(
        verify_tls13_certificate_verify_rsa_sha256(
            leaf.public_key(),
            &transcript_hash,
            MOCK_LEAF_TLS13_PSS_SIG,
        ),
        Err(VerifyError::InvalidSignature),
        "PSS signature must not be accepted as PKCS#1 v1.5"
    );
}

#[test]
fn tls13_rsa_pss_certificate_verify_signature_tamper_fails() {
    let leaf = verify_leaf_chain_with_public_key(
        MOCK_LEAF,
        MOCK_CA,
        ServerName::Dns("localhost"),
        valid_time(),
    )
    .expect("mock leaf chain verifies");
    let transcript_hash = [0x42; 32];
    let mut sig = [0u8; RSA2048_MODULUS_BYTES];
    sig.copy_from_slice(MOCK_LEAF_TLS13_PSS_SIG);
    sig[17] ^= 0x55;

    assert_eq!(
        verify_tls13_certificate_verify_rsa_pss_sha256(leaf.public_key(), &transcript_hash, &sig,),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn rsa_signature_length_and_modulus_bounds_fail_closed() {
    let leaf = parse_certificate_der(MOCK_LEAF).expect("mock leaf parses");
    let key = leaf.public_key();
    let too_long = [0u8; RSA2048_MODULUS_BYTES + 1];
    let above_modulus = [0xffu8; RSA2048_MODULUS_BYTES];
    for signature in [
        &too_long[..RSA2048_MODULUS_BYTES - 1],
        &too_long[..],
        &key.modulus()[..],
        &above_modulus[..],
    ] {
        assert_eq!(
            verify_rsa2048_pkcs1v15_sha256(key, b"message", signature),
            Err(VerifyError::InvalidSignature)
        );
        assert_eq!(
            verify_rsa2048_pss_sha256(key, b"message", signature),
            Err(VerifyError::InvalidSignature)
        );
    }
}

#[test]
fn tampered_leaf_signature_fails() {
    let mut leaf = MOCK_LEAF.to_vec();
    let last = leaf.len() - 1;
    leaf[last] ^= 0x01;
    assert_eq!(
        verify_leaf_chain(
            &leaf,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            valid_time(),
        ),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn wrong_name_fails() {
    assert_eq!(
        verify_leaf_chain(
            MOCK_LEAF,
            MOCK_CA,
            ServerName::Dns("wrong.local"),
            valid_time()
        ),
        Err(VerifyError::NameMismatch)
    );
}

#[test]
fn invalid_time_fails() {
    let before = UnixTime::from_ymdhms(2026, 6, 1, 0, 0, 0).unwrap();
    assert_eq!(
        verify_leaf_chain(MOCK_LEAF, MOCK_CA, ServerName::Ipv4([192, 0, 2, 1]), before,),
        Err(VerifyError::InvalidTime)
    );
}

#[test]
fn bad_ca_constraints_fail() {
    assert_eq!(
        verify_leaf_chain(
            MOCK_LEAF,
            MOCK_LEAF,
            ServerName::Ipv4([192, 0, 2, 1]),
            valid_time(),
        ),
        Err(VerifyError::BadCaConstraints)
    );
}

#[test]
fn unsupported_algorithm_fails() {
    let mut leaf = MOCK_LEAF.to_vec();
    let oid = OID_SHA256_WITH_RSA_ENCRYPTION;
    let pos = leaf
        .windows(oid.len())
        .position(|window| window == oid)
        .expect("signature OID present");
    leaf[pos + oid.len() - 1] = 0x0d;
    assert_eq!(
        verify_leaf_chain(
            &leaf,
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            valid_time(),
        ),
        Err(VerifyError::UnsupportedAlgorithm)
    );
}

#[test]
fn malformed_der_fails() {
    assert_eq!(
        verify_leaf_chain(
            &MOCK_LEAF[..MOCK_LEAF.len() - 5],
            MOCK_CA,
            ServerName::Ipv4([192, 0, 2, 1]),
            valid_time(),
        ),
        Err(VerifyError::MalformedDer)
    );
}

#[test]
fn oversized_exponent_fails() {
    let modulus = [0x55u8; RSA2048_MODULUS_BYTES];
    let exponent = [0x01, 0x00, 0x00, 0x01];
    assert_eq!(
        Rsa2048PublicKey::from_components(&modulus, &exponent),
        Err(VerifyError::OversizedField)
    );
}

#[test]
fn oversized_certificate_fails_closed() {
    let mut large = [0u8; MAX_CERT_DER_BYTES + 1];
    large[..MOCK_CA.len()].copy_from_slice(MOCK_CA);
    assert!(matches!(
        parse_certificate_der(&large),
        Err(VerifyError::CertificateTooLarge)
    ));
}
