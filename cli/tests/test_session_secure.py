# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Encrypted (saead) RPC loopback: ProvSession <-> saead-capable mock device."""

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pouchprov import codec
from pouchprov.pouchlink import cert, saead
from pouchprov.session import ProvSession
from pouchprov.transport.mock import DeviceSaead, MockDeviceTransport


def _pair(algorithm):
    server = cert.generate_server_identity()
    device_priv = ec.generate_private_key(ec.SECP256R1())
    device_pub = device_priv.public_key()

    client_session = saead.SaeadSession(
        server.private_key, device_pub, server.cert_ref, algorithm=algorithm
    )
    device_saead = DeviceSaead(device_priv, server.public_key, algorithm=algorithm)
    return client_session, device_saead


@pytest.mark.parametrize("algorithm", [saead.ALG_CHACHA20_POLY1305, saead.ALG_AES_GCM])
async def test_encrypted_ver_round_trip(algorithm):
    client_session, device_saead = _pair(algorithm)

    def handler(path, payload):
        if path == codec.PATH_VER:
            return cbor2.dumps([0, 0, {"proto": 1, "caps": ["wifi", "auth"],
                                       "blk": 512, "lib": "sec", "pop": True}])
        return None

    transport = MockDeviceTransport(handler, device_saead=device_saead)
    session = ProvSession(transport, saead=client_session)

    info = codec.decode_ver_rsp(await session.request(codec.PATH_VER, codec.encode_ver_req()))
    assert info.proto == 1
    assert info.pop_required


async def test_encrypted_multiblock_request():
    """A request too big for one block must chain AD correctly."""
    client_session, device_saead = _pair(saead.ALG_AES_GCM)
    seen = []

    def handler(path, payload):
        seen.append((path, len(payload)))
        return cbor2.dumps([0, 0, len(payload)])  # cred-write-rsp shape

    transport = MockDeviceTransport(handler, device_saead=device_saead)
    session = ProvSession(transport, saead=client_session)
    session.block_size = 96  # force multi-block

    entries = await session.request_entries([
        __import__("pouchprov.pouchlink.pouch", fromlist=["Entry"]).Entry(
            codec.PATH_CRED, 60, codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 0, 40, bytes(30))
        ),
        __import__("pouchprov.pouchlink.pouch", fromlist=["Entry"]).Entry(
            codec.PATH_CRED, 60, codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 30, 40, bytes(10))
        ),
    ])
    assert len(seen) == 2
    assert len(entries) == 2


async def test_wrong_key_fails_to_decrypt():
    """A client whose key doesn't match the device cannot read responses."""
    _, device_saead = _pair(saead.ALG_AES_GCM)
    # Client built against a DIFFERENT device public key.
    server = cert.generate_server_identity()
    bogus_device = ec.generate_private_key(ec.SECP256R1()).public_key()
    mismatched = saead.SaeadSession(server.private_key, bogus_device, server.cert_ref,
                                    algorithm=saead.ALG_AES_GCM)

    transport = MockDeviceTransport(lambda p, d: cbor2.dumps([0, 0]), device_saead=device_saead)
    session = ProvSession(transport, saead=mismatched)
    with pytest.raises(Exception):
        await session.request(codec.PATH_VER, codec.encode_ver_req(), timeout=2.0)
