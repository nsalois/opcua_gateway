"""Regenerate synthetic public test fixtures; never serialize private keys.

Maintainer-only dependency: cryptography. Ordinary builds/tests use the committed
DER files. Random keys mean regeneration intentionally changes fixture bytes.
"""
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

OUTPUT = Path(__file__).resolve().parents[1] / "crates/tls-verify/testdata"


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic gateway test CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "192.0.2.1")])
    unrelated_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated synthetic CA")])

    def certificate(name, key, issuer, signing_key, serial, *, ca, bad_usage=False, san=False):
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(serial)
                   .not_valid_before(datetime(2026, 6, 10, tzinfo=timezone.utc))
                   .not_valid_after(datetime(2036, 6, 10, tzinfo=timezone.utc))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=(bad_usage if ca else not bad_usage),
                       content_commitment=False, key_encipherment=not ca,
                       data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca and not bad_usage, crl_sign=ca and not bad_usage,
                       encipher_only=False, decipher_only=False), critical=True))
        if san:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ip_address("192.0.2.1")), x509.DNSName("localhost")]), critical=False)
        return builder.sign(signing_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    fixtures = {
        "mock-ca.der": certificate(ca_name, ca_key, ca_name, ca_key, 1, ca=True),
        "mock-ca-bad-key-usage.der": certificate(ca_name, ca_key, ca_name, ca_key, 2, ca=True, bad_usage=True),
        "mock-leaf.der": certificate(leaf_name, leaf_key, ca_name, ca_key, 3, ca=False, san=True),
        "mock-leaf-bad-key-usage.der": certificate(leaf_name, leaf_key, ca_name, ca_key, 4, ca=False, bad_usage=True, san=True),
        "mock-leaf-cn-only.der": certificate(leaf_name, leaf_key, ca_name, ca_key, 5, ca=False),
        "unrelated-ca.der": certificate(unrelated_name, unrelated_key, unrelated_name, unrelated_key, 6, ca=True),
    }
    message = b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + b"\x42" * 32
    signature = leaf_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    leaf_key.public_key().verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    fixtures["mock-leaf-tls13-pss-sha256.sig"] = signature
    for name, data in fixtures.items():
        (OUTPUT / name).write_bytes(data)
    print(f"Wrote {len(fixtures)} synthetic fixtures; private keys were never serialized.")


if __name__ == "__main__":
    main()
