# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Certificate handling for the provisioning client (pouch server role).

The client presents a self-signed P-256 certificate as its pouch "server"
identity and collects the device's certificate (trust-on-first-use). The
public keys drive the ECDH session key derivation in :mod:`saead`.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Fixed epoch instead of datetime.now(): reproducible, and the device does
# not validate notBefore/notAfter for local (TOFU) provisioning.
_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)

CERT_REF_LEN = 6


@dataclass
class Identity:
    """A P-256 key pair and its self-signed certificate (DER)."""

    private_key: ec.EllipticCurvePrivateKey
    cert_der: bytes

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()

    @property
    def cert_ref(self) -> bytes:
        """First 6 bytes of SHA-256(cert DER), per pouch cert_ref."""
        return hashlib.sha256(self.cert_der).digest()[:CERT_REF_LEN]


def generate_server_identity(common_name: str = "pouch-prov-cli") -> Identity:
    """Generate a fresh self-signed P-256 server identity."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .sign(key, hashes.SHA256())
    )
    return Identity(key, cert.public_bytes(serialization.Encoding.DER))


def device_public_key(cert_der: bytes) -> ec.EllipticCurvePublicKey:
    """Extract the P-256 public key from a device certificate (DER or PEM)."""
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError:
        cert = x509.load_pem_x509_certificate(cert_der)
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("device certificate is not an EC key")
    return pub


def cert_fingerprint(cert_der: bytes) -> str:
    """Human-readable SHA-256 fingerprint for TOFU display."""
    digest = hashlib.sha256(cert_der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 16, 2)).upper()


def pem_to_der(data: bytes) -> bytes:
    """Normalize a PEM or DER certificate/key to DER."""
    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        if b"PRIVATE KEY" in stripped[:64]:
            key = serialization.load_pem_private_key(data, password=None)
            return key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        return x509.load_pem_x509_certificate(data).public_bytes(serialization.Encoding.DER)
    return data
