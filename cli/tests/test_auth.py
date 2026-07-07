# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""PoP mutual authorization over the (encrypted) session."""

import hmac
import secrets

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pouchprov import auth, codec
from pouchprov.pouchlink import cert, saead
from pouchprov.session import ProvSession
from pouchprov.transport.mock import DeviceSaead, MockDeviceTransport


class DeviceAuth:
    """Mock device PoP responder mirroring the firmware."""

    def __init__(self, pop: str):
        self.pop = pop
        self.cli_nonce = None
        self.authorized = False

    def handle(self, path: str, payload: bytes) -> bytes | None:
        if path != codec.PATH_AUTH:
            return None
        msg = cbor2.loads(payload)
        if msg[0] == 0:  # challenge
            self.cli_nonce = bytes(msg[1])
            dev_nonce = secrets.token_bytes(16)
            self._dev_nonce = dev_nonce
            proof = auth.device_proof(self.pop, self.cli_nonce, dev_nonce)
            return cbor2.dumps([0, 0, dev_nonce, proof])
        # proof
        expected = auth.client_proof(self.pop, self._dev_nonce, self.cli_nonce)
        if hmac.compare_digest(bytes(msg[1]), expected):
            self.authorized = True
            return cbor2.dumps([1, 0])
        return cbor2.dumps([1, 4])  # unauthorized


def _secure(algorithm=saead.ALG_AES_GCM):
    server = cert.generate_server_identity()
    device_priv = ec.generate_private_key(ec.SECP256R1())
    client = saead.SaeadSession(server.private_key, device_priv.public_key(),
                                server.cert_ref, algorithm=algorithm)
    dev = DeviceSaead(device_priv, server.public_key, algorithm=algorithm)
    return client, dev


async def test_authorize_success():
    client, dev = _secure()
    responder = DeviceAuth("abcd1234")
    transport = MockDeviceTransport(responder.handle, device_saead=dev)
    session = ProvSession(transport, saead=client)
    await auth.authorize(session, "abcd1234")
    assert responder.authorized


async def test_wrong_pop_rejected_by_client():
    client, dev = _secure()
    responder = DeviceAuth("realpop")
    transport = MockDeviceTransport(responder.handle, device_saead=dev)
    session = ProvSession(transport, saead=client)
    # Client uses the wrong PoP: the device's proof won't verify.
    with pytest.raises(auth.AuthError):
        await auth.authorize(session, "wrongpop")
    assert not responder.authorized


async def test_impostor_device_rejected():
    """A device that doesn't know the PoP cannot produce a valid proof."""
    client, dev = _secure()
    responder = DeviceAuth("impostor-does-not-know")
    transport = MockDeviceTransport(responder.handle, device_saead=dev)
    session = ProvSession(transport, saead=client)
    with pytest.raises(auth.AuthError):
        await auth.authorize(session, "the-real-pop")
