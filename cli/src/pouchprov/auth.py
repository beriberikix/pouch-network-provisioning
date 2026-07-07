# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Proof-of-possession mutual authorization (.prov/auth).

Both proofs are HMAC-SHA256 keyed with the UTF-8 PoP secret:

    dev_proof = HMAC(pop, b"dev" + cli_nonce + dev_nonce)
    cli_proof = HMAC(pop, b"cli" + dev_nonce + cli_nonce)

The client verifies the device's proof before sending its own, so a device
that doesn't know the PoP learns nothing and receives no credentials.
"""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256

from . import codec
from .session import ProvSession


class AuthError(Exception):
    pass


def _proof(pop: str, tag: bytes, first: bytes, second: bytes) -> bytes:
    return hmac.new(pop.encode(), tag + first + second, sha256).digest()


def device_proof(pop: str, cli_nonce: bytes, dev_nonce: bytes) -> bytes:
    return _proof(pop, b"dev", cli_nonce, dev_nonce)


def client_proof(pop: str, dev_nonce: bytes, cli_nonce: bytes) -> bytes:
    return _proof(pop, b"cli", dev_nonce, cli_nonce)


async def authorize(session: ProvSession, pop: str, timeout: float = 15.0) -> None:
    """Run the mutual PoP handshake. Raises AuthError on mismatch."""
    cli_nonce = secrets.token_bytes(16)
    dev_nonce, dev_proof = codec.decode_auth_challenge_rsp(
        await session.request(codec.PATH_AUTH, codec.encode_auth_challenge(cli_nonce), timeout)
    )
    expected = device_proof(pop, cli_nonce, dev_nonce)
    if not hmac.compare_digest(dev_proof, expected):
        raise AuthError("device proof mismatch — wrong PoP or impostor device")

    cli_proof = client_proof(pop, dev_nonce, cli_nonce)
    codec.decode_auth_proof_rsp(
        await session.request(codec.PATH_AUTH, codec.encode_auth_proof(cli_proof), timeout)
    )
