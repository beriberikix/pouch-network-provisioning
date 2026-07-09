# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""TOFU server-cert exchange + autodetected saead sessions over the mock."""

import cbor2
import pytest

from pouchprov import codec, flows, tofu
from pouchprov.pouchlink import cert
from pouchprov.session import ProvSession
from pouchprov.transport.mock import MockDeviceTransport

POP = "abcd1234"


def _saead_device(handler, **kwargs):
    identity = cert.generate_server_identity(common_name="mock-device")
    return MockDeviceTransport(handler, saead_identity=identity, **kwargs), identity


def _simple_handler(path, payload):
    if path == codec.PATH_VER:
        return cbor2.dumps([0, 0, {"proto": 1, "caps": ["cred"], "blk": 512,
                                   "lib": "tofu-test", "pop": False}])
    if path == codec.PATH_CTRL:
        return cbor2.dumps([cbor2.loads(payload)[0], 0])
    return None


class TestSerialHandling:
    def test_normalize_strips_leading_zeros(self):
        assert tofu.normalize_serial(b"\x00\x01\x02") == b"\x01\x02"
        assert tofu.normalize_serial(b"\x01\x02") == b"\x01\x02"
        assert tofu.normalize_serial(b"\x00") == b"\x00"
        assert tofu.normalize_serial(b"") == b"\x00"

    def test_cert_serial_matches_x509(self):
        from cryptography import x509

        ident = cert.generate_server_identity()
        serial = tofu.cert_serial(ident.cert_der)
        assert int.from_bytes(serial, "big") == \
            x509.load_der_x509_certificate(ident.cert_der).serial_number


class TestSupportsSaead:
    def test_plain_mock_has_no_saead(self):
        transport = MockDeviceTransport(_simple_handler)
        assert not transport.supports_saead

    def test_saead_mock_detected(self):
        transport, _ = _saead_device(_simple_handler)
        assert transport.supports_saead


async def test_read_info_empty_then_stored():
    transport, _ = _saead_device(_simple_handler)
    info = await tofu.read_info(transport)
    assert not info.has_server_cert

    server = cert.generate_server_identity()
    await tofu.sar_write(transport.server_cert, server.cert_der, maxlen=244)
    info = await tofu.read_info(transport)
    assert info.has_server_cert
    assert tofu.normalize_serial(info.server_cert_serial) == \
        tofu.normalize_serial(tofu.cert_serial(server.cert_der))


async def test_exchange_pushes_when_missing_and_skips_when_stored():
    transport, device_identity = _saead_device(_simple_handler)
    server = cert.generate_server_identity()

    dev_der = await tofu.exchange_certs(transport, server, maxlen=244)
    assert dev_der == device_identity.cert_der
    assert transport.stored_server_cert == server.cert_der

    # Second exchange: serial matches, no re-push (stored cert unchanged object).
    transport.stored_server_cert = server.cert_der
    marker = transport.stored_server_cert
    dev_der = await tofu.exchange_certs(transport, server, maxlen=244)
    assert dev_der == device_identity.cert_der
    assert transport.stored_server_cert is marker


async def test_exchange_replaces_different_cert():
    transport, _ = _saead_device(_simple_handler)
    other = cert.generate_server_identity()
    await tofu.sar_write(transport.server_cert, other.cert_der, maxlen=244)
    assert transport.stored_server_cert == other.cert_der

    ours = cert.generate_server_identity()
    await tofu.exchange_certs(transport, ours, maxlen=244)
    assert transport.stored_server_cert == ours.cert_der


async def test_secure_session_end_to_end():
    """Autodetect -> TOFU -> encrypted request round trip."""
    transport, _ = _saead_device(_simple_handler)
    session = ProvSession(transport)
    assert not session.encrypted

    server = cert.generate_server_identity()
    await tofu.secure_session(transport, session, server)
    assert session.encrypted

    info = await flows.get_version(session)
    assert info.lib == "tofu-test"
    await flows.end_session(session)


async def test_secure_session_wrong_server_key_fails():
    """A session keyed to a different server identity than the one the device
    stores must fail to decrypt."""
    transport, _ = _saead_device(_simple_handler)
    server = cert.generate_server_identity()
    session = ProvSession(transport)
    await tofu.secure_session(transport, session, server)

    # Device now re-keys to a different server cert behind our back.
    other = cert.generate_server_identity()
    await tofu.sar_write(transport.server_cert, other.cert_der, maxlen=244)

    with pytest.raises(Exception):
        await flows.get_version(session)
