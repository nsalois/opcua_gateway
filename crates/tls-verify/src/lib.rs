#![no_std]
#![forbid(unsafe_code)]

//! Bounded verifier for the gateway's deliberately narrow upstream TLS profile.
//!
//! This is not a general X.509 implementation: it accepts the ADR 0012/0014
//! depth-one RSA-2048 CA/leaf shape, SHA-256 signatures, explicit DNS/IP SAN
//! identity, and caller-supplied verifier time when available. Unsupported
//! certificate shapes fail closed before the adapter authorizes an
//! `embedded-tls` session.

mod der;
pub use der::MAX_CERT_DER_BYTES;
pub(crate) use der::{
    normalize_positive_integer, parse_bit_string_bytes, parse_bit_string_with_unused,
    parse_boolean, parse_small_integer, DerReader, Tlv, TAG_BIT_STRING, TAG_BOOLEAN, TAG_CONTEXT_0,
    TAG_CONTEXT_1, TAG_CONTEXT_2, TAG_CONTEXT_3_CONSTRUCTED, TAG_CONTEXT_7, TAG_GENERALIZED_TIME,
    TAG_INTEGER, TAG_NULL, TAG_OBJECT_ID, TAG_OCTET_STRING, TAG_SEQUENCE, TAG_UTC_TIME,
};

mod certificate;
pub use certificate::parse_certificate_der;
pub(crate) use certificate::{verify_subject_alt_name, verify_time};

mod rsa;
pub use rsa::{
    verify_rsa2048_pkcs1v15_sha256, verify_rsa2048_pss_sha256,
    verify_tls13_certificate_verify_rsa_pss_sha256, verify_tls13_certificate_verify_rsa_sha256,
    MAX_TLS13_CERT_VERIFY_MESSAGE_BYTES, RSA2048_LIMBS, RSA2048_MODULUS_BYTES,
};

#[cfg(feature = "embedded-tls-019")]
mod embedded_tls_adapter;
#[cfg(feature = "embedded-tls-019")]
pub use embedded_tls_adapter::EmbeddedTlsRsaVerifier;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VerifyError {
    CertificateTooLarge,
    MalformedDer,
    UnsupportedAlgorithm,
    UnsupportedKey,
    OversizedField,
    InvalidSignature,
    InvalidTime,
    BadCaConstraints,
    BadKeyUsage,
    MissingSan,
    NameMismatch,
    UnsupportedCriticalExtension,
    UnsupportedCertificateProfile,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct UnixTime(u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerName<'a> {
    Dns(&'a str),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rsa2048PublicKey {
    modulus: [u8; RSA2048_MODULUS_BYTES],
    exponent: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct BasicConstraints {
    present: bool,
    ca: bool,
}

impl BasicConstraints {
    const ABSENT: Self = Self {
        present: false,
        ca: false,
    };
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct KeyUsage {
    bytes: [u8; 2],
    bit_len: u8,
}

impl KeyUsage {
    fn bit(self, bit: u8) -> bool {
        if bit >= self.bit_len {
            return false;
        }
        let idx = (bit / 8) as usize;
        let mask = 0x80 >> (bit % 8);
        (self.bytes[idx] & mask) != 0
    }

    fn digital_signature(self) -> bool {
        self.bit(0)
    }

    fn key_cert_sign(self) -> bool {
        self.bit(5)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Certificate<'a> {
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: UnixTime,
    not_after: UnixTime,
    public_key: Rsa2048PublicKey,
    signature: &'a [u8],
    basic_constraints: BasicConstraints,
    key_usage: Option<KeyUsage>,
    subject_alt_name: Option<&'a [u8]>,
}

pub fn verify_ca_certificate<'a>(
    ca_der: &'a [u8],
    now: UnixTime,
) -> Result<Certificate<'a>, VerifyError> {
    verify_ca_certificate_with_optional_time(ca_der, Some(now))
}

pub fn verify_ca_certificate_with_optional_time<'a>(
    ca_der: &'a [u8],
    now: Option<UnixTime>,
) -> Result<Certificate<'a>, VerifyError> {
    let ca = parse_certificate_der(ca_der)?;
    if let Some(now) = now {
        verify_time(&ca, now)?;
    }
    if ca.issuer != ca.subject {
        return Err(VerifyError::BadCaConstraints);
    }
    if !ca.basic_constraints.present || !ca.basic_constraints.ca {
        return Err(VerifyError::BadCaConstraints);
    }
    if let Some(key_usage) = ca.key_usage {
        if !key_usage.key_cert_sign() {
            return Err(VerifyError::BadKeyUsage);
        }
    }
    verify_rsa2048_pkcs1v15_sha256(&ca.public_key, ca.tbs, ca.signature)?;
    Ok(ca)
}

pub fn verify_leaf_chain(
    leaf_der: &[u8],
    ca_der: &[u8],
    name: ServerName<'_>,
    now: UnixTime,
) -> Result<(), VerifyError> {
    verify_leaf_chain_with_optional_time(leaf_der, ca_der, name, Some(now))
}

pub fn verify_leaf_chain_with_optional_time(
    leaf_der: &[u8],
    ca_der: &[u8],
    name: ServerName<'_>,
    now: Option<UnixTime>,
) -> Result<(), VerifyError> {
    verify_leaf_chain_with_public_key_and_optional_time(leaf_der, ca_der, name, now).map(|_| ())
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct VerifiedLeaf {
    public_key: Rsa2048PublicKey,
}

impl VerifiedLeaf {
    pub const fn public_key(&self) -> &Rsa2048PublicKey {
        &self.public_key
    }
}

pub fn verify_leaf_chain_with_public_key(
    leaf_der: &[u8],
    ca_der: &[u8],
    name: ServerName<'_>,
    now: UnixTime,
) -> Result<VerifiedLeaf, VerifyError> {
    verify_leaf_chain_with_public_key_and_optional_time(leaf_der, ca_der, name, Some(now))
}

pub fn verify_leaf_chain_with_public_key_and_optional_time(
    leaf_der: &[u8],
    ca_der: &[u8],
    name: ServerName<'_>,
    now: Option<UnixTime>,
) -> Result<VerifiedLeaf, VerifyError> {
    let ca = verify_ca_certificate_with_optional_time(ca_der, now)?;
    let leaf = parse_certificate_der(leaf_der)?;
    if let Some(now) = now {
        verify_time(&leaf, now)?;
    }
    if leaf.issuer != ca.subject {
        return Err(VerifyError::BadCaConstraints);
    }
    if leaf.basic_constraints.ca {
        return Err(VerifyError::BadCaConstraints);
    }
    if let Some(key_usage) = leaf.key_usage {
        if !key_usage.digital_signature() {
            return Err(VerifyError::BadKeyUsage);
        }
    }
    verify_subject_alt_name(&leaf, name)?;
    verify_rsa2048_pkcs1v15_sha256(&ca.public_key, leaf.tbs, leaf.signature)?;
    Ok(VerifiedLeaf {
        public_key: leaf.public_key,
    })
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
