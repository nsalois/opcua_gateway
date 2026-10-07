// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Static pins for target-only ADR 0018 trust authorization boundaries.

const TRANSPORT: &str = include_str!("../../../firmware/opta-m7/src/buchi_tls_transport.rs");
const TRUST: &str = include_str!("../../../firmware/opta-m7/src/trust.rs");
const USB_CONSOLE: &str = include_str!("../../../firmware/opta-m7/src/usb_console.rs");

#[test]
fn runtime_transport_carries_optional_time_without_removing_completeness_gate() {
    let load = source_region(
        TRANSPORT,
        "async fn load_attempt_trust",
        "async fn transition_trust_source",
        "runtime attempt trust loader",
    );
    assert!(load.contains("!snapshot.material.is_complete()"));
    assert!(load.contains(".map(UnixTime::from_seconds)"));
    assert!(!load.contains("let Some(now_seconds)"));

    assert!(TRANSPORT.contains("EmbeddedTlsRsaVerifier::new_with_optional_time"));
}

#[test]
fn ca_commit_preserves_persisted_marker_and_accepts_absent_current_time() {
    let commit = source_region(
        USB_CONSOLE,
        "\"trust-ca-commit\" =>",
        "\"trust-time\" =>",
        "trust CA commit handler",
    );
    assert!(commit.contains("verify_ca_certificate_with_optional_time"));
    assert!(commit.contains("now_seconds.map(UnixTime::from_seconds)"));
    assert!(commit.contains("let mut provisioned = GatewayTrust::missing()"));
    assert!(commit.contains("load_field_config(uid_words, &mut provisioned)"));
    assert!(commit.contains("replace_ca_der(ca_der)"));
    assert!(commit.contains("match (provisioned.time_provisioned(), now_seconds)"));
    assert!(commit.contains("(true, Some(now_seconds))"));
    assert!(commit.contains("install_without_time(provisioned)"));
    assert!(!commit.contains("GatewayTrust::from_ca_der"));
    assert!(!commit.contains("trust-time-unavailable"));
}

#[test]
fn trust_time_invalidates_clockless_session_before_time_aware_retry() {
    let provision_time = source_region(
        USB_CONSOLE,
        "\"trust-time\" =>",
        "\"trust-clear\" =>",
        "trust time handler",
    );
    assert!(provision_time
        .contains("verify_ca_certificate_with_optional_time(current_trust.ca_der(), None)"));
    let install = provision_time
        .find("trust.install(updated, readback_seconds)")
        .expect("trust-time no longer installs the time-bearing material");
    let invalidate = provision_time
        .find("data_access.revoke_upstream_trust()")
        .expect("trust-time no longer invalidates live upstream authorization");
    assert!(install < invalidate);

    let install_impl = source_region(
        TRUST,
        "pub(crate) fn install(",
        "pub(crate) fn revoke(",
        "runtime trust install implementation",
    );
    assert!(install_impl.contains("install_inner(material, Some(rtc_unix_seconds))"));
    assert!(install_impl.contains("install_inner(material, None)"));
    assert!(install_impl.contains("self.generation = self.generation.wrapping_add(1)"));
}

#[test]
fn complete_clockless_boot_validates_ca_without_synthesizing_time_error() {
    let boot = source_region(
        TRUST,
        "pub(crate) fn from_boot(",
        "pub(crate) fn verifier_now_seconds(",
        "runtime trust boot classification",
    );
    assert!(boot.contains("if material.is_complete()"));
    assert!(boot.contains("verify_ca_certificate_with_optional_time"));
    assert!(boot.contains("let mut last_verify_error = 0"));
    assert!(!boot.contains("last_verify_error = 1"));
}

#[test]
fn clockless_boot_returns_no_verifier_time() {
    let boot = source_region(
        TRUST,
        "pub(crate) fn from_boot(",
        "pub(crate) fn verifier_now_seconds(",
        "runtime trust boot classification",
    );
    let verifier = source_region(
        TRUST,
        "pub(crate) fn verifier_now_seconds(",
        "pub(crate) fn snapshot(",
        "runtime verifier clock",
    );
    assert!(boot.contains("let rtc_usable = rtc_unix_seconds.is_some()"));
    assert!(boot.contains("self.rtc_usable = rtc_usable;"));
    assert!(verifier.contains("if !self.rtc_usable"));
    assert!(verifier.contains("return None;"));
}

#[test]
fn clockless_install_returns_no_verifier_time() {
    let install = source_region(
        TRUST,
        "pub(crate) fn install(",
        "pub(crate) fn revoke(",
        "runtime trust install implementation",
    );
    let verifier = source_region(
        TRUST,
        "pub(crate) fn verifier_now_seconds(",
        "pub(crate) fn snapshot(",
        "runtime verifier clock",
    );
    assert!(install.contains("install_inner(material, None)"));
    assert!(install.contains("self.rtc_usable = rtc_unix_seconds.is_some()"));
    assert!(verifier.contains("if !self.rtc_usable"));
    assert!(verifier.contains("return None;"));
}

#[test]
fn revoke_returns_no_verifier_time() {
    let revoke = source_region(
        TRUST,
        "pub(crate) fn revoke(",
        "pub(crate) type SharedTrust",
        "runtime trust revoke implementation",
    );
    let verifier = source_region(
        TRUST,
        "pub(crate) fn verifier_now_seconds(",
        "pub(crate) fn snapshot(",
        "runtime verifier clock",
    );
    assert!(revoke.contains("self.rtc_usable = false;"));
    assert!(verifier.contains("if !self.rtc_usable"));
    assert!(verifier.contains("return None;"));
}

#[test]
fn verified_session_health_uses_the_exact_attempt_time_mode() {
    let success = source_region(
        TRANSPORT,
        "M7_BUCHI_TRUST_VERIFIED_SESSIONS.fetch_add",
        "let mut connection_failed",
        "successful Buchi TLS session transition",
    );
    assert!(success.contains("set_verified_trust_session(attempt_trust.verifier_time().is_some())"));
    assert!(!success.contains("set_trust_state(TrustState::Verified)"));
}

fn source_region<'a>(source: &'a str, start: &str, end: &str, label: &str) -> &'a str {
    let start_offset = source
        .find(start)
        .unwrap_or_else(|| panic!("{label} start marker changed"));
    let remainder = &source[start_offset..];
    let end_offset = remainder
        .find(end)
        .unwrap_or_else(|| panic!("{label} end marker changed"));
    &remainder[..end_offset]
}
