# Synthetic certificate fixtures

All DER certificates and the signature in this directory were generated for
this public source on 2026-10-06 using `cryptography` 49.0.0. They are original
test assets, Copyright 2026 Nicholas Salois, Apache-2.0. They contain no vendor
certificate, captured device identity, credentials, or private key.

`tools/generate_test_certificates.py` documents generation. It uses ephemeral
RSA-2048 keys with exponent 65537, SHA-256 certificate signatures, validity
2026-06-10 through 2036-06-10, and documentation IP `192.0.2.1` plus DNS
`localhost`. Negative fixtures exercise missing SAN, incorrect key usage and
an unrelated authority. The TLS 1.3 RSA-PSS signature uses the server
CertificateVerify context, a 32-byte `0x42` transcript hash and a 32-byte salt.
Keys are kept only in memory and never serialized.

Tests use these committed bytes; Python cryptography is not a build or test
dependency. Regeneration uses random keys, changes bytes and requires rerunning
all verifier tests. These fixtures cannot authenticate the development bench.
