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
import secrets
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


@dataclass
class Credentials:
    """PEM-encoded credentials (accepted directly by the provision path)."""

    cert_pem: bytes
    key_pem: bytes


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _build_cert(subject: x509.Name, issuer: x509.Name, public_key: ec.EllipticCurvePublicKey,
                signing_key: ec.EllipticCurvePrivateKey, validity_days: int,
                ca: bool) -> x509.Certificate:
    """Mirror of the mobile SDKs' DeviceCert.buildCert: SHA256withECDSA, 64-bit
    random serial, 60 s notBefore backdate for clock skew."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(secrets.randbits(64) or 1)
        .not_valid_before(now - datetime.timedelta(seconds=60))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(signing_key, hashes.SHA256())


def generate_self_signed(common_name: str, validity_days: int = 28) -> Credentials:
    """P-256 key pair + self-signed certificate with CN=common_name."""
    key = _new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = _build_cert(name, name, key.public_key(), key, validity_days, ca=False)
    return Credentials(cert.public_bytes(serialization.Encoding.PEM), _key_pem(key))


def generate_ca(common_name: str, validity_days: int = 28) -> Credentials:
    """P-256 key pair + self-signed CA certificate (CA:TRUE, keyCertSign|cRLSign)."""
    key = _new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = _build_cert(name, name, key.public_key(), key, validity_days, ca=True)
    return Credentials(cert.public_bytes(serialization.Encoding.PEM), _key_pem(key))


def sign_device_cert(ca: Credentials, device_common_name: str,
                     validity_days: int = 28) -> Credentials:
    """Device key pair + certificate with CN=device_common_name signed by *ca*."""
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
    ca_key = serialization.load_pem_private_key(ca.key_pem, password=None)
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise ValueError("CA key is not an EC key")
    key = _new_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_common_name)])
    cert = _build_cert(subject, ca_cert.subject, key.public_key(), ca_key,
                       validity_days, ca=False)
    return Credentials(cert.public_bytes(serialization.Encoding.PEM), _key_pem(key))


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
