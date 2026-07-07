# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""CLI credential-bootstrap flow against a mock device that stages chunks."""

import cbor2
import pytest

from pouchprov import codec, flows
from pouchprov.pouchlink import cert
from pouchprov.session import ProvSession
from pouchprov.transport.mock import MockDeviceTransport


class CredDevice:
    """Mock device implementing .prov/cred chunk staging + finalize."""

    def __init__(self):
        self.staged = {0: b"", 1: b"", 2: b""}
        self.expected = {}
        self.finalized = False

    def handle(self, path, payload):
        if path != codec.PATH_CRED:
            return None
        msg = cbor2.loads(payload)
        op = msg[0]
        if op == 0:  # write chunk
            c = msg[1]
            kind, off, total, data = c["kind"], c["off"], c["total"], bytes(c["data"])
            if off != len(self.staged[kind]):
                return cbor2.dumps([0, 2, 0])  # invalid-argument
            self.staged[kind] += data
            self.expected[kind] = total
            return cbor2.dumps([0, 0, len(self.staged[kind])])
        if op == 1:  # finalize
            cert_ok = self.staged[0] and len(self.staged[0]) == self.expected.get(0)
            key_ok = self.staged[1] and len(self.staged[1]) == self.expected.get(1)
            if cert_ok and key_ok:
                self.finalized = True
                return cbor2.dumps([1, 0])
            return cbor2.dumps([1, 2])
        # status
        return cbor2.dumps([2, 0, {str(k): len(v) for k, v in self.staged.items() if v}])


async def test_bootstrap_credentials():
    ident = cert.generate_server_identity()  # reuse as a stand-in DER cert
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key_der = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())

    dev = CredDevice()
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.bootstrap_credentials(session, ident.cert_der, key_der)

    assert dev.finalized
    assert dev.staged[0] == ident.cert_der  # reassembled across chunks
    assert dev.staged[1] == key_der


async def test_bootstrap_multi_chunk():
    """A cert larger than one chunk must reassemble correctly."""
    big_cert = bytes(range(256)) * 5  # 1280 bytes -> several 256B chunks
    key = bytes(range(120))

    dev = CredDevice()
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.bootstrap_credentials(session, big_cert, key)
    assert dev.staged[0] == big_cert
    assert dev.staged[1] == key


async def test_finalize_requires_cert_and_key():
    dev = CredDevice()
    session = ProvSession(MockDeviceTransport(dev.handle))
    # Push only a cert, no key -> finalize should fail.
    await flows.push_credential(session, codec.CredKind.DEVICE_CERT, bytes(64))
    with pytest.raises(codec.ProvError):
        codec.decode_cred_finalize_rsp(
            await session.request(codec.PATH_CRED, codec.encode_cred_finalize())
        )
    assert not dev.finalized
