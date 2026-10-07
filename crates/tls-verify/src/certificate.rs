// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use super::{
    parse_bit_string_bytes, parse_bit_string_with_unused, parse_boolean, parse_small_integer,
    BasicConstraints, Certificate, DerReader, KeyUsage, Rsa2048PublicKey, ServerName, Tlv,
    UnixTime, VerifyError, MAX_CERT_DER_BYTES, RSA2048_MODULUS_BYTES, TAG_BIT_STRING, TAG_BOOLEAN,
    TAG_CONTEXT_0, TAG_CONTEXT_1, TAG_CONTEXT_2, TAG_CONTEXT_3_CONSTRUCTED, TAG_CONTEXT_7,
    TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_NULL, TAG_OBJECT_ID, TAG_OCTET_STRING, TAG_SEQUENCE,
    TAG_UTC_TIME,
};

const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub(crate) const OID_SHA256_WITH_RSA_ENCRYPTION: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const OID_SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

impl UnixTime {
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub fn from_ymdhms(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, VerifyError> {
        validate_datetime(year, month, day, hour, minute, second)?;
        let days = days_from_civil(year as i32, month as u32, day as u32);
        if days < 0 {
            return Err(VerifyError::InvalidTime);
        }
        let seconds =
            days as u64 * 86_400 + hour as u64 * 3_600 + minute as u64 * 60 + second as u64;
        Ok(Self(seconds))
    }
}

impl<'a> Certificate<'a> {
    pub const fn public_key(&self) -> &Rsa2048PublicKey {
        &self.public_key
    }

    pub const fn not_before(&self) -> UnixTime {
        self.not_before
    }

    pub const fn not_after(&self) -> UnixTime {
        self.not_after
    }
}

pub fn parse_certificate_der(der: &[u8]) -> Result<Certificate<'_>, VerifyError> {
    if der.len() > MAX_CERT_DER_BYTES {
        return Err(VerifyError::CertificateTooLarge);
    }

    let mut outer = DerReader::new(der);
    let certificate = outer.read_expected(TAG_SEQUENCE)?;
    outer.finish()?;

    let mut cert = DerReader::new(certificate.value);
    let tbs = cert.read_expected(TAG_SEQUENCE)?;
    let outer_sig_alg = parse_algorithm_identifier(cert.read_expected(TAG_SEQUENCE)?.value)?;
    if outer_sig_alg != Algorithm::Sha256WithRsaEncryption {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    let signature = parse_bit_string_bytes(cert.read_expected(TAG_BIT_STRING)?.value)?;
    cert.finish()?;

    let parsed = parse_tbs_certificate(tbs.full, tbs.value)?;
    if signature.len() != RSA2048_MODULUS_BYTES {
        return Err(VerifyError::UnsupportedKey);
    }

    Ok(Certificate {
        tbs: tbs.full,
        issuer: parsed.issuer,
        subject: parsed.subject,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
        public_key: parsed.public_key,
        signature,
        basic_constraints: parsed.basic_constraints,
        key_usage: parsed.key_usage,
        subject_alt_name: parsed.subject_alt_name,
    })
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Algorithm {
    RsaEncryption,
    Sha256WithRsaEncryption,
}

#[derive(Debug, Copy, Clone)]
struct ParsedTbs<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: UnixTime,
    not_after: UnixTime,
    public_key: Rsa2048PublicKey,
    basic_constraints: BasicConstraints,
    key_usage: Option<KeyUsage>,
    subject_alt_name: Option<&'a [u8]>,
}

fn parse_tbs_certificate<'a>(
    full: &'a [u8],
    value: &'a [u8],
) -> Result<ParsedTbs<'a>, VerifyError> {
    let mut tbs = DerReader::new(value);

    if tbs.peek_tag() == Some(TAG_CONTEXT_0) {
        let version = tbs.read_expected(TAG_CONTEXT_0)?;
        let mut explicit = DerReader::new(version.value);
        let version_value = parse_small_integer(explicit.read_expected(TAG_INTEGER)?.value)?;
        explicit.finish()?;
        if version_value != 2 {
            return Err(VerifyError::UnsupportedCertificateProfile);
        }
    } else {
        return Err(VerifyError::UnsupportedCertificateProfile);
    }

    let _serial = tbs.read_expected(TAG_INTEGER)?;
    let sig_alg = parse_algorithm_identifier(tbs.read_expected(TAG_SEQUENCE)?.value)?;
    if sig_alg != Algorithm::Sha256WithRsaEncryption {
        return Err(VerifyError::UnsupportedAlgorithm);
    }

    let issuer = tbs.read_expected(TAG_SEQUENCE)?.full;
    let validity = tbs.read_expected(TAG_SEQUENCE)?;
    let (not_before, not_after) = parse_validity(validity.value)?;
    let subject = tbs.read_expected(TAG_SEQUENCE)?.full;
    let public_key = parse_spki(tbs.read_expected(TAG_SEQUENCE)?.value)?;

    let mut basic_constraints = BasicConstraints::ABSENT;
    let mut key_usage = None;
    let mut subject_alt_name = None;

    while !tbs.is_empty() {
        match tbs.peek_tag() {
            Some(TAG_CONTEXT_1) | Some(0xa1) | Some(0x82) | Some(0xa2) => {
                return Err(VerifyError::UnsupportedCertificateProfile);
            }
            Some(TAG_CONTEXT_3_CONSTRUCTED) => {
                let extensions = tbs.read_expected(TAG_CONTEXT_3_CONSTRUCTED)?;
                let parsed = parse_extensions(extensions.value)?;
                basic_constraints = parsed.basic_constraints;
                key_usage = parsed.key_usage;
                subject_alt_name = parsed.subject_alt_name;
            }
            Some(_) => return Err(VerifyError::MalformedDer),
            None => break,
        }
    }

    let _ = full;
    Ok(ParsedTbs {
        issuer,
        subject,
        not_before,
        not_after,
        public_key,
        basic_constraints,
        key_usage,
        subject_alt_name,
    })
}

#[derive(Debug, Copy, Clone)]
struct ParsedExtensions<'a> {
    basic_constraints: BasicConstraints,
    key_usage: Option<KeyUsage>,
    subject_alt_name: Option<&'a [u8]>,
}

fn parse_extensions(value: &[u8]) -> Result<ParsedExtensions<'_>, VerifyError> {
    let mut explicit = DerReader::new(value);
    let seq = explicit.read_expected(TAG_SEQUENCE)?;
    explicit.finish()?;

    let mut extensions = DerReader::new(seq.value);
    let mut parsed = ParsedExtensions {
        basic_constraints: BasicConstraints::ABSENT,
        key_usage: None,
        subject_alt_name: None,
    };

    while !extensions.is_empty() {
        let ext = extensions.read_expected(TAG_SEQUENCE)?;
        let mut fields = DerReader::new(ext.value);
        let oid = fields.read_expected(TAG_OBJECT_ID)?.value;
        let critical = if fields.peek_tag() == Some(TAG_BOOLEAN) {
            parse_boolean(fields.read_expected(TAG_BOOLEAN)?.value)?
        } else {
            false
        };
        let octets = fields.read_expected(TAG_OCTET_STRING)?.value;
        fields.finish()?;

        if oid == OID_BASIC_CONSTRAINTS {
            if parsed.basic_constraints.present {
                return Err(VerifyError::MalformedDer);
            }
            parsed.basic_constraints = parse_basic_constraints(octets)?;
        } else if oid == OID_KEY_USAGE {
            if parsed.key_usage.is_some() {
                return Err(VerifyError::MalformedDer);
            }
            parsed.key_usage = Some(parse_key_usage(octets)?);
        } else if oid == OID_SUBJECT_ALT_NAME {
            if parsed.subject_alt_name.is_some() {
                return Err(VerifyError::MalformedDer);
            }
            validate_subject_alt_name(octets)?;
            parsed.subject_alt_name = Some(octets);
        } else if oid == OID_SUBJECT_KEY_IDENTIFIER
            || oid == OID_AUTHORITY_KEY_IDENTIFIER
            || oid == OID_EXTENDED_KEY_USAGE
        {
            if critical {
                return Err(VerifyError::UnsupportedCriticalExtension);
            }
        } else if critical {
            return Err(VerifyError::UnsupportedCriticalExtension);
        }
    }

    Ok(parsed)
}

fn parse_basic_constraints(value: &[u8]) -> Result<BasicConstraints, VerifyError> {
    let mut outer = DerReader::new(value);
    let seq = outer.read_expected(TAG_SEQUENCE)?;
    outer.finish()?;
    let mut fields = DerReader::new(seq.value);
    let ca = if fields.peek_tag() == Some(TAG_BOOLEAN) {
        parse_boolean(fields.read_expected(TAG_BOOLEAN)?.value)?
    } else {
        false
    };
    if fields.peek_tag() == Some(TAG_INTEGER) {
        let _ = fields.read_expected(TAG_INTEGER)?;
    }
    fields.finish()?;
    Ok(BasicConstraints { present: true, ca })
}

fn parse_key_usage(value: &[u8]) -> Result<KeyUsage, VerifyError> {
    let mut outer = DerReader::new(value);
    let bits = parse_bit_string_with_unused(outer.read_expected(TAG_BIT_STRING)?.value)?;
    outer.finish()?;
    if bits.bytes.is_empty() || bits.bytes.len() > 2 || bits.unused_bits > 7 {
        return Err(VerifyError::MalformedDer);
    }
    let bit_len = (bits.bytes.len() * 8 - bits.unused_bits as usize) as u8;
    let mut bytes = [0u8; 2];
    bytes[..bits.bytes.len()].copy_from_slice(bits.bytes);
    Ok(KeyUsage { bytes, bit_len })
}

fn validate_subject_alt_name(value: &[u8]) -> Result<(), VerifyError> {
    let mut outer = DerReader::new(value);
    let seq = outer.read_expected(TAG_SEQUENCE)?;
    outer.finish()?;
    let mut names = DerReader::new(seq.value);
    while !names.is_empty() {
        let name = names.read_any()?;
        // Keep the explicit if-return checks: the guard form clippy suggests
        // falls through to the no-op catch-all arm, hiding the fail-closed
        // intent of each SAN validation arm.
        #[allow(clippy::collapsible_match)]
        match name.tag {
            TAG_CONTEXT_2 => {
                if core::str::from_utf8(name.value).is_err() {
                    return Err(VerifyError::MalformedDer);
                }
            }
            TAG_CONTEXT_7 => {
                if name.value.len() != 4 && name.value.len() != 16 {
                    return Err(VerifyError::MalformedDer);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn verify_subject_alt_name(
    cert: &Certificate<'_>,
    name: ServerName<'_>,
) -> Result<(), VerifyError> {
    let Some(san) = cert.subject_alt_name else {
        return Err(VerifyError::MissingSan);
    };
    let mut outer = DerReader::new(san);
    let seq = outer.read_expected(TAG_SEQUENCE)?;
    outer.finish()?;
    let mut names = DerReader::new(seq.value);
    while !names.is_empty() {
        let entry = names.read_any()?;
        match (name, entry.tag) {
            (ServerName::Dns(expected), TAG_CONTEXT_2) => {
                let candidate =
                    core::str::from_utf8(entry.value).map_err(|_| VerifyError::MalformedDer)?;
                if ascii_eq_ignore_case(candidate.as_bytes(), expected.as_bytes()) {
                    return Ok(());
                }
            }
            (ServerName::Ipv4(expected), TAG_CONTEXT_7) if entry.value == expected => return Ok(()),
            (ServerName::Ipv6(expected), TAG_CONTEXT_7) if entry.value == expected => return Ok(()),
            _ => {}
        }
    }
    Err(VerifyError::NameMismatch)
}

fn parse_spki(value: &[u8]) -> Result<Rsa2048PublicKey, VerifyError> {
    let mut spki = DerReader::new(value);
    let alg = parse_algorithm_identifier(spki.read_expected(TAG_SEQUENCE)?.value)?;
    if alg != Algorithm::RsaEncryption {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    let public_key_bits = parse_bit_string_bytes(spki.read_expected(TAG_BIT_STRING)?.value)?;
    spki.finish()?;
    parse_rsa_public_key(public_key_bits)
}

fn parse_rsa_public_key(der: &[u8]) -> Result<Rsa2048PublicKey, VerifyError> {
    let mut outer = DerReader::new(der);
    let seq = outer.read_expected(TAG_SEQUENCE)?;
    outer.finish()?;
    let mut fields = DerReader::new(seq.value);
    let modulus = fields.read_expected(TAG_INTEGER)?.value;
    let exponent = fields.read_expected(TAG_INTEGER)?.value;
    fields.finish()?;
    Rsa2048PublicKey::from_components(modulus, exponent)
}

fn parse_algorithm_identifier(value: &[u8]) -> Result<Algorithm, VerifyError> {
    let mut alg = DerReader::new(value);
    let oid = alg.read_expected(TAG_OBJECT_ID)?.value;
    if !alg.is_empty() {
        let params = alg.read_any()?;
        if params.tag != TAG_NULL || !params.value.is_empty() {
            return Err(VerifyError::UnsupportedAlgorithm);
        }
    }
    alg.finish()?;

    if oid == OID_RSA_ENCRYPTION {
        Ok(Algorithm::RsaEncryption)
    } else if oid == OID_SHA256_WITH_RSA_ENCRYPTION {
        Ok(Algorithm::Sha256WithRsaEncryption)
    } else {
        Err(VerifyError::UnsupportedAlgorithm)
    }
}

fn parse_validity(value: &[u8]) -> Result<(UnixTime, UnixTime), VerifyError> {
    let mut validity = DerReader::new(value);
    let not_before = parse_time(validity.read_any()?)?;
    let not_after = parse_time(validity.read_any()?)?;
    validity.finish()?;
    Ok((not_before, not_after))
}

fn parse_time(tlv: Tlv<'_>) -> Result<UnixTime, VerifyError> {
    match tlv.tag {
        TAG_UTC_TIME => parse_utc_time(tlv.value),
        TAG_GENERALIZED_TIME => parse_generalized_time(tlv.value),
        _ => Err(VerifyError::InvalidTime),
    }
}

fn parse_utc_time(value: &[u8]) -> Result<UnixTime, VerifyError> {
    if value.len() != 13 || value[12] != b'Z' {
        return Err(VerifyError::InvalidTime);
    }
    let yy = parse_2digits(&value[0..2])?;
    let year = if yy >= 50 {
        1900 + yy as u16
    } else {
        2000 + yy as u16
    };
    let month = parse_2digits(&value[2..4])?;
    let day = parse_2digits(&value[4..6])?;
    let hour = parse_2digits(&value[6..8])?;
    let minute = parse_2digits(&value[8..10])?;
    let second = parse_2digits(&value[10..12])?;
    UnixTime::from_ymdhms(year, month, day, hour, minute, second)
}

fn parse_generalized_time(value: &[u8]) -> Result<UnixTime, VerifyError> {
    if value.len() != 15 || value[14] != b'Z' {
        return Err(VerifyError::InvalidTime);
    }
    let year = parse_4digits(&value[0..4])?;
    let month = parse_2digits(&value[4..6])?;
    let day = parse_2digits(&value[6..8])?;
    let hour = parse_2digits(&value[8..10])?;
    let minute = parse_2digits(&value[10..12])?;
    let second = parse_2digits(&value[12..14])?;
    UnixTime::from_ymdhms(year, month, day, hour, minute, second)
}

pub(crate) fn verify_time(cert: &Certificate<'_>, now: UnixTime) -> Result<(), VerifyError> {
    if now < cert.not_before || now > cert.not_after {
        Err(VerifyError::InvalidTime)
    } else {
        Ok(())
    }
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn parse_2digits(bytes: &[u8]) -> Result<u8, VerifyError> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(VerifyError::InvalidTime);
    }
    Ok((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn parse_4digits(bytes: &[u8]) -> Result<u16, VerifyError> {
    if bytes.len() != 4 || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(VerifyError::InvalidTime);
    }
    Ok(u16::from(bytes[0] - b'0') * 1000
        + u16::from(bytes[1] - b'0') * 100
        + u16::from(bytes[2] - b'0') * 10
        + u16::from(bytes[3] - b'0'))
}

fn validate_datetime(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Result<(), VerifyError> {
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return Err(VerifyError::InvalidTime);
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return Err(VerifyError::InvalidTime);
    }
    Ok(())
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = month as i32 + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era * 146_097 + doe - 719_468)
}
