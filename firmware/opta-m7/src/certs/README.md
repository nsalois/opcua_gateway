# Synthetic diagnostic certificate

`mock_buchi_test_ca.der` is a new self-signed RSA-2048/SHA-256 test CA,
created on 2026-10-01 specifically for this source export. It contains no
Buchi or other real device certificate, identity, credentials or captured data.
Copyright 2026 Nicholas Salois; licensed under the root Apache-2.0 license.

SHA-256: `9e6ed9ba975e91b7ea99cef1da61f691cf561800f160f34fea8efa1d4e38ffd6`.
Subject and issuer: `CN=Opta synthetic diagnostic CA`. Serial: 1. Validity:
2026-01-01 through 2036-01-01 UTC. Critical basic constraints: CA true,
path length zero. Critical key usage: certificate signing and CRL signing.

Generated with Python cryptography 49.0.0: `rsa.generate_private_key` with
exponent 65537 and 2048 bits, `x509.CertificateBuilder` with the fields above,
and `.sign(key, hashes.SHA256())`, serialized as DER. The key existed only in
the generator's memory, was never serialized, and was discarded. Regeneration
would produce new bytes and requires a new certificate hash and validation;
cryptography is not a normal build dependency.

The canonical checker requires this asset to prove that it is absent from
the default product image. It also checks that diagnostic transport probes
are absent and mock-only assumptions stay within the diagnostic module.
Those gates have not been removed. This CA cannot authenticate an existing
mock server; no matching server certificate or private key is distributed.
