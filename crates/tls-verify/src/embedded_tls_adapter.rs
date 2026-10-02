use super::{
    verify_leaf_chain_with_public_key_and_optional_time,
    verify_tls13_certificate_verify_rsa_pss_sha256, Rsa2048PublicKey, ServerName, UnixTime,
    VerifyError,
};

#[cfg(feature = "embedded-tls-019")]
pub struct EmbeddedTlsRsaVerifier<'ca> {
    ca_der: &'ca [u8],
    pub(crate) now: Option<UnixTime>,
    host: [u8; 64],
    host_len: usize,
    leaf_public_key: Option<Rsa2048PublicKey>,
    handshake_hash: Option<[u8; 32]>,
}

#[cfg(feature = "embedded-tls-019")]
impl<'ca> EmbeddedTlsRsaVerifier<'ca> {
    pub const fn new(ca_der: &'ca [u8], now: UnixTime) -> Self {
        Self::new_with_optional_time(ca_der, Some(now))
    }

    pub const fn new_with_optional_time(ca_der: &'ca [u8], now: Option<UnixTime>) -> Self {
        Self {
            ca_der,
            now,
            host: [0; 64],
            host_len: 0,
            leaf_public_key: None,
            handshake_hash: None,
        }
    }

    fn configured_server_name(&self) -> Result<ServerName<'_>, embedded_tls::TlsError> {
        let host = core::str::from_utf8(&self.host[..self.host_len])
            .map_err(|_| embedded_tls::TlsError::InvalidCertificate)?;
        if let Some(ipv4) = parse_dotted_ipv4(host) {
            Ok(ServerName::Ipv4(ipv4))
        } else {
            Ok(ServerName::Dns(host))
        }
    }
}

#[cfg(feature = "embedded-tls-019")]
impl embedded_tls::TlsVerifier<embedded_tls::Aes128GcmSha256> for EmbeddedTlsRsaVerifier<'_> {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), embedded_tls::TlsError> {
        if hostname.len() > self.host.len() {
            return Err(embedded_tls::TlsError::InsufficientSpace);
        }
        self.host[..hostname.len()].copy_from_slice(hostname.as_bytes());
        self.host_len = hostname.len();
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &<embedded_tls::Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        cert: embedded_tls::CertificateRef,
    ) -> Result<(), embedded_tls::TlsError> {
        use digest::Digest as _;

        let Some(entry) = cert.entries.first() else {
            return Err(embedded_tls::TlsError::InvalidCertificate);
        };
        let embedded_tls::CertificateEntryRef::X509(leaf_der) = entry else {
            return Err(embedded_tls::TlsError::InvalidCertificateEntry);
        };

        let name = self.configured_server_name()?;
        let leaf = verify_leaf_chain_with_public_key_and_optional_time(
            leaf_der,
            self.ca_der,
            name,
            self.now,
        )
        .map_err(certificate_error_to_tls)?;

        let hash = transcript.clone().finalize();
        let mut handshake_hash = [0u8; 32];
        handshake_hash.copy_from_slice(hash.as_ref());
        self.handshake_hash = Some(handshake_hash);
        self.leaf_public_key = Some(*leaf.public_key());
        Ok(())
    }

    fn verify_signature(
        &mut self,
        verify: embedded_tls::CertificateVerifyRef,
    ) -> Result<(), embedded_tls::TlsError> {
        if verify.signature_scheme != embedded_tls::SignatureScheme::RsaPssRsaeSha256 {
            return Err(embedded_tls::TlsError::InvalidSignatureScheme);
        }
        let Some(public_key) = self.leaf_public_key.as_ref() else {
            return Err(embedded_tls::TlsError::MissingHandshake);
        };
        let Some(handshake_hash) = self.handshake_hash.as_ref() else {
            return Err(embedded_tls::TlsError::MissingHandshake);
        };
        verify_tls13_certificate_verify_rsa_pss_sha256(public_key, handshake_hash, verify.signature)
            .map_err(signature_error_to_tls)
    }
}

#[cfg(feature = "embedded-tls-019")]
fn certificate_error_to_tls(error: VerifyError) -> embedded_tls::TlsError {
    match error {
        VerifyError::CertificateTooLarge => embedded_tls::TlsError::InsufficientSpace,
        VerifyError::MalformedDer
        | VerifyError::UnsupportedAlgorithm
        | VerifyError::UnsupportedKey
        | VerifyError::OversizedField
        | VerifyError::InvalidTime
        | VerifyError::BadCaConstraints
        | VerifyError::BadKeyUsage
        | VerifyError::MissingSan
        | VerifyError::NameMismatch
        | VerifyError::UnsupportedCriticalExtension
        | VerifyError::UnsupportedCertificateProfile => embedded_tls::TlsError::InvalidCertificate,
        VerifyError::InvalidSignature => embedded_tls::TlsError::InvalidSignature,
    }
}

#[cfg(feature = "embedded-tls-019")]
fn signature_error_to_tls(error: VerifyError) -> embedded_tls::TlsError {
    match error {
        VerifyError::InvalidSignature => embedded_tls::TlsError::InvalidSignature,
        VerifyError::CertificateTooLarge => embedded_tls::TlsError::InsufficientSpace,
        VerifyError::MalformedDer
        | VerifyError::UnsupportedAlgorithm
        | VerifyError::UnsupportedKey
        | VerifyError::OversizedField
        | VerifyError::InvalidTime
        | VerifyError::BadCaConstraints
        | VerifyError::BadKeyUsage
        | VerifyError::MissingSan
        | VerifyError::NameMismatch
        | VerifyError::UnsupportedCriticalExtension
        | VerifyError::UnsupportedCertificateProfile => embedded_tls::TlsError::InvalidSignature,
    }
}

#[cfg(feature = "embedded-tls-019")]
fn parse_dotted_ipv4(host: &str) -> Option<[u8; 4]> {
    let bytes = host.as_bytes();
    let mut out = [0u8; 4];
    let mut part = 0usize;
    let mut value: u16 = 0;
    let mut digits = 0u8;

    for &byte in bytes {
        match byte {
            b'0'..=b'9' => {
                value = value * 10 + u16::from(byte - b'0');
                if value > u16::from(u8::MAX) {
                    return None;
                }
                digits = digits.saturating_add(1);
                if digits > 3 {
                    return None;
                }
            }
            b'.' => {
                if digits == 0 || part >= 3 {
                    return None;
                }
                out[part] = value as u8;
                part += 1;
                value = 0;
                digits = 0;
            }
            _ => return None,
        }
    }

    if digits == 0 || part != 3 {
        return None;
    }
    out[part] = value as u8;
    Some(out)
}
