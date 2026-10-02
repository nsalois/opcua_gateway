use core::cmp::Ordering;

use purecrypto::bignum::{MontModulus, Uint};
use purecrypto::hash::{Digest, Sha256};

use super::{normalize_positive_integer, Rsa2048PublicKey, VerifyError};

const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub const RSA2048_MODULUS_BYTES: usize = 256;
pub const RSA2048_LIMBS: usize = RSA2048_MODULUS_BYTES / 8;
pub const MAX_TLS13_CERT_VERIFY_MESSAGE_BYTES: usize = 64 + 33 + 1 + 32;

impl Rsa2048PublicKey {
    pub fn from_components(modulus_der: &[u8], exponent_der: &[u8]) -> Result<Self, VerifyError> {
        let modulus = normalize_rsa2048_modulus(modulus_der)?;
        let exponent = parse_public_exponent(exponent_der)?;
        Ok(Self { modulus, exponent })
    }

    pub const fn exponent(&self) -> u32 {
        self.exponent
    }

    pub const fn modulus(&self) -> &[u8; RSA2048_MODULUS_BYTES] {
        &self.modulus
    }
}

pub fn verify_rsa2048_pkcs1v15_sha256(
    public_key: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let encoded = rsa2048_public_representative(public_key, signature)?;

    let digest = Sha256::digest(message);
    let digest_bytes = digest.as_ref();
    if pkcs1v15_sha256_encoded_message_matches(&encoded, digest_bytes) {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}

pub fn verify_rsa2048_pss_sha256(
    public_key: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let encoded = rsa2048_public_representative(public_key, signature)?;
    let digest = Sha256::digest(message);
    let digest_bytes = digest.as_ref();
    if pss_sha256_encoded_message_matches(&encoded, digest_bytes) {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}

pub fn verify_tls13_certificate_verify_rsa_sha256(
    public_key: &Rsa2048PublicKey,
    handshake_hash: &[u8; 32],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let message = tls13_certificate_verify_message(handshake_hash);
    verify_rsa2048_pkcs1v15_sha256(public_key, &message, signature)
}

pub fn verify_tls13_certificate_verify_rsa_pss_sha256(
    public_key: &Rsa2048PublicKey,
    handshake_hash: &[u8; 32],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let message = tls13_certificate_verify_message(handshake_hash);
    verify_rsa2048_pss_sha256(public_key, &message, signature)
}

fn rsa2048_public_representative(
    public_key: &Rsa2048PublicKey,
    signature: &[u8],
) -> Result<[u8; RSA2048_MODULUS_BYTES], VerifyError> {
    if signature.len() != RSA2048_MODULUS_BYTES {
        return Err(VerifyError::InvalidSignature);
    }
    if cmp_be_fixed(signature, &public_key.modulus) != Ordering::Less {
        return Err(VerifyError::InvalidSignature);
    }

    let modulus = Uint::<RSA2048_LIMBS>::from_be_bytes(&public_key.modulus);
    let exponent = Uint::<RSA2048_LIMBS>::from_u64(public_key.exponent as u64);
    let sig = Uint::<RSA2048_LIMBS>::from_be_bytes(signature);
    let representative = MontModulus::new(modulus).pow_public(&sig, &exponent);
    let mut encoded = [0u8; RSA2048_MODULUS_BYTES];
    representative.write_be_bytes(&mut encoded);
    Ok(encoded)
}

fn tls13_certificate_verify_message(
    handshake_hash: &[u8; 32],
) -> [u8; MAX_TLS13_CERT_VERIFY_MESSAGE_BYTES] {
    let mut message = [0u8; MAX_TLS13_CERT_VERIFY_MESSAGE_BYTES];
    message[..64].fill(0x20);
    let context = b"TLS 1.3, server CertificateVerify";
    message[64..64 + context.len()].copy_from_slice(context);
    message[64 + context.len()] = 0;
    let hash_start = 64 + context.len() + 1;
    message[hash_start..hash_start + handshake_hash.len()].copy_from_slice(handshake_hash);
    message
}

fn pss_sha256_encoded_message_matches(
    encoded: &[u8; RSA2048_MODULUS_BYTES],
    m_hash: &[u8],
) -> bool {
    const HASH_LEN: usize = 32;
    const SALT_LEN: usize = HASH_LEN;
    const DB_LEN: usize = RSA2048_MODULUS_BYTES - HASH_LEN - 1;
    const PS_LEN: usize = RSA2048_MODULUS_BYTES - HASH_LEN - SALT_LEN - 2;

    if m_hash.len() != HASH_LEN || encoded[RSA2048_MODULUS_BYTES - 1] != 0xbc {
        return false;
    }
    if encoded[0] & 0x80 != 0 {
        return false;
    }

    let h = &encoded[DB_LEN..DB_LEN + HASH_LEN];
    let mut db = [0u8; DB_LEN];
    mgf1_sha256_xor(h, &encoded[..DB_LEN], &mut db);
    db[0] &= 0x7f;

    if db[..PS_LEN].iter().any(|&byte| byte != 0) || db[PS_LEN] != 0x01 {
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(&[0u8; 8]);
    hasher.update(m_hash);
    hasher.update(&db[PS_LEN + 1..]);
    let expected = hasher.finalize();
    expected.as_ref() == h
}

fn mgf1_sha256_xor(seed: &[u8], input: &[u8], output: &mut [u8]) {
    let mut written = 0usize;
    let mut counter = 0u32;
    while written < output.len() {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        let block = hasher.finalize();
        let remaining = output.len() - written;
        let take = remaining.min(32);
        for idx in 0..take {
            output[written + idx] = input[written + idx] ^ block.as_ref()[idx];
        }
        written += take;
        counter = counter.wrapping_add(1);
    }
}

fn normalize_rsa2048_modulus(value: &[u8]) -> Result<[u8; RSA2048_MODULUS_BYTES], VerifyError> {
    let unsigned = normalize_positive_integer(value)?;
    if unsigned.len() != RSA2048_MODULUS_BYTES {
        return Err(VerifyError::UnsupportedKey);
    }
    if unsigned[0] == 0 || (unsigned[RSA2048_MODULUS_BYTES - 1] & 1) == 0 {
        return Err(VerifyError::UnsupportedKey);
    }
    let mut out = [0u8; RSA2048_MODULUS_BYTES];
    out.copy_from_slice(unsigned);
    Ok(out)
}

fn parse_public_exponent(value: &[u8]) -> Result<u32, VerifyError> {
    let unsigned = normalize_positive_integer(value)?;
    if unsigned.len() > 3 {
        return Err(VerifyError::OversizedField);
    }
    let mut exponent = 0u32;
    for byte in unsigned {
        exponent = (exponent << 8) | u32::from(*byte);
    }
    if exponent != 65_537 {
        return Err(VerifyError::UnsupportedKey);
    }
    Ok(exponent)
}

fn pkcs1v15_sha256_encoded_message_matches(
    encoded: &[u8; RSA2048_MODULUS_BYTES],
    digest: &[u8],
) -> bool {
    let digest_info_len = SHA256_DIGEST_INFO_PREFIX.len() + digest.len();
    let ps_len = RSA2048_MODULUS_BYTES - 3 - digest_info_len;
    if ps_len < 8 {
        return false;
    }
    if encoded[0] != 0x00 || encoded[1] != 0x01 {
        return false;
    }
    if encoded[2..2 + ps_len].iter().any(|byte| *byte != 0xff) {
        return false;
    }
    if encoded[2 + ps_len] != 0x00 {
        return false;
    }
    let prefix_start = 3 + ps_len;
    if &encoded[prefix_start..prefix_start + SHA256_DIGEST_INFO_PREFIX.len()]
        != SHA256_DIGEST_INFO_PREFIX
    {
        return false;
    }
    &encoded[prefix_start + SHA256_DIGEST_INFO_PREFIX.len()..] == digest
}

fn cmp_be_fixed(left: &[u8], right: &[u8; RSA2048_MODULUS_BYTES]) -> Ordering {
    debug_assert_eq!(left.len(), RSA2048_MODULUS_BYTES);
    for (a, b) in left.iter().zip(right.iter()) {
        match a.cmp(b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}
