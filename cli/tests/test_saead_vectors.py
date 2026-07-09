# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""saead against the frozen cross-client vectors in tests/vectors/saead_kdf.json.

The same file pins the Kotlin and Swift saead ports; a failure here means the
Python reference and the vectors have drifted.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pouchprov.pouchlink import saead

VECTORS = json.loads(
    (Path(__file__).parent.parent.parent / "tests" / "vectors" / "saead_kdf.json").read_text()
)


def _keys():
    server = ec.derive_private_key(int(VECTORS["server_private"], 16), ec.SECP256R1())
    device = ec.derive_private_key(int(VECTORS["device_private"], 16), ec.SECP256R1())
    return server, device


def test_fixed_scalars_match_public_points():
    from cryptography.hazmat.primitives import serialization

    server, device = _keys()
    for key, expected in ((server, VECTORS["server_public_uncompressed"]),
                          (device, VECTORS["device_public_uncompressed"])):
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        assert point.hex() == expected


@pytest.mark.parametrize("name", ["chacha_downlink", "aes_downlink",
                                  "chacha_uplink", "aes_uplink"])
def test_kdf_and_seal_chain(name):
    case = VECTORS["cases"][name]
    server, device = _keys()

    # Server-side derivation (the client's view).
    key = saead.derive_session_key(
        server, device.public_key(), bytes.fromhex(case["session_id"]),
        case["initiator"], case["algorithm"], VECTORS["block_log"],
    )
    assert key.hex() == case["key"]

    # Mirror derivation (the device's view) must agree.
    mirror = saead.derive_session_key(
        device, server.public_key(), bytes.fromhex(case["session_id"]),
        case["initiator"], case["algorithm"], VECTORS["block_log"],
    )
    assert mirror == key

    # Seal chain: nonce layout and tag-chained AAD.
    prev_tag = b""
    for block in case["blocks"]:
        nonce = saead._nonce(VECTORS["pouch_id"], block["index"], case["initiator"])
        assert nonce.hex() == block["nonce"]
        aad = prev_tag if block["index"] > 0 else b""
        assert aad.hex() == block["aad"]
        sealed = saead._aead(case["algorithm"], key).encrypt(
            nonce, bytes.fromhex(block["plaintext"]), aad
        )
        assert sealed.hex() == block["sealed"]
        prev_tag = sealed[-saead.AUTH_TAG_LEN:]


def test_downlink_session_reproduces_vector_chain():
    """SaeadSession.encrypt_downlink_block matches the raw chain for the
    server-initiated cases."""
    case = VECTORS["cases"]["chacha_downlink"]
    server, device = _keys()
    session = saead.SaeadSession(
        server, device.public_key(), b"\xaa" * 6,
        algorithm=case["algorithm"], max_block_size_log=VECTORS["block_log"],
    )
    session.new_downlink(bytes.fromhex(case["session_id"]), VECTORS["pouch_id"])
    prev_tag = b""
    for block in case["blocks"]:
        sealed, prev_tag = session.encrypt_downlink_block(
            bytes.fromhex(block["plaintext"]), block["index"], VECTORS["pouch_id"], prev_tag
        )
        assert sealed.hex() == block["sealed"]
