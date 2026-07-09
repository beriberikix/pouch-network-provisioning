# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Server identity generation, device cert parsing, PEM/DER handling."""

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from pouchprov.pouchlink import cert, info


def test_generate_server_identity_round_trips():
    ident = cert.generate_server_identity()
    assert len(ident.cert_ref) == 6
    # public key extractable from the generated cert
    pub = cert.device_public_key(ident.cert_der)
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    # and it matches the private key's public key
    assert pub.public_numbers() == ident.public_key.public_numbers()


def test_cert_ref_is_sha256_prefix():
    import hashlib

    ident = cert.generate_server_identity()
    assert ident.cert_ref == hashlib.sha256(ident.cert_der).digest()[:6]


def test_two_identities_differ():
    a = cert.generate_server_identity()
    b = cert.generate_server_identity()
    assert a.cert_der != b.cert_der
    assert a.cert_ref != b.cert_ref


def test_pem_to_der_cert():
    from cryptography.hazmat.primitives import serialization

    ident = cert.generate_server_identity()
    pem = (
        __import__("cryptography.x509", fromlist=["load_der_x509_certificate"])
        .load_der_x509_certificate(ident.cert_der)
        .public_bytes(serialization.Encoding.PEM)
    )
    assert cert.pem_to_der(pem) == ident.cert_der
    # DER passes through unchanged
    assert cert.pem_to_der(ident.cert_der) == ident.cert_der


def test_pem_to_der_key():
    from cryptography.hazmat.primitives import serialization

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    der = cert.pem_to_der(pem)
    reloaded = serialization.load_der_private_key(der, password=None)
    assert reloaded.private_numbers() == key.private_numbers()


def test_fingerprint_format():
    ident = cert.generate_server_identity()
    fp = cert.cert_fingerprint(ident.cert_der)
    assert fp.count(":") == 7 and fp.isupper() or ":" in fp


def test_info_decode():
    encoded = cbor2.dumps({"flags": 1, "server_cert_snr": b"\x01\x02\x03"})
    parsed = info.GattInfo.decode(encoded)
    assert parsed.flags == 1
    assert parsed.has_server_cert
    assert parsed.server_cert_serial == b"\x01\x02\x03"


def test_info_no_cert():
    parsed = info.GattInfo.decode(cbor2.dumps({"flags": 0, "server_cert_snr": b""}))
    assert not parsed.has_server_cert


class TestMintedCredentials:
    """Local cert generation mirroring the mobile SDKs' DeviceCert."""

    def test_self_signed(self):
        import datetime

        from cryptography import x509

        creds = cert.generate_self_signed("my-device", validity_days=7)
        parsed = x509.load_pem_x509_certificate(creds.cert_pem)
        cn = parsed.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "my-device"
        assert parsed.issuer == parsed.subject
        now = datetime.datetime.now(datetime.timezone.utc)
        assert parsed.not_valid_before_utc <= now  # 60s backdate
        assert abs((parsed.not_valid_after_utc - now).days - 7) <= 1
        # key PEM parses and matches the cert's public key
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(creds.key_pem, password=None)
        assert key.public_key().public_numbers() == parsed.public_key().public_numbers()

    def test_ca_and_signed_device_cert(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        ca = cert.generate_ca("pouch-demo-CA")
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca and bc.critical
        ku = ca_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign and ku.value.crl_sign

        dev = cert.sign_device_cert(ca, "dev-42")
        dev_cert = x509.load_pem_x509_certificate(dev.cert_pem)
        assert dev_cert.issuer == ca_cert.subject
        cn = dev_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "dev-42"
        # signature verifies against the CA public key
        ca_cert.public_key().verify(
            dev_cert.signature,
            dev_cert.tbs_certificate_bytes,
            ec_mod.ECDSA(dev_cert.signature_hash_algorithm),
        )

    def test_pem_round_trip_through_pem_to_der(self):
        creds = cert.generate_self_signed("x")
        assert cert.pem_to_der(creds.cert_pem)[:1] == b"\x30"
        assert cert.pem_to_der(creds.key_pem)[:1] == b"\x30"
