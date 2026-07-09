#!/usr/bin/env python3
# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Generate golden test vectors from the CLI codec.

Vectors are generated once, hand-reviewed, and frozen; both the pytest
suite and the device ztest suite assert against the same JSON files. Do
not regenerate casually — a diff here is a wire-format change.

Usage: uv run --project cli scripts/gen_vectors.py
"""

import json
import sys
from pathlib import Path

import cbor2

sys.path.insert(0, str(Path(__file__).parent.parent / "cli" / "src"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from pouchprov import codec  # noqa: E402
from pouchprov.pouchlink import pouch, saead  # noqa: E402

VECTOR_DIR = Path(__file__).parent.parent / "tests" / "vectors"


def prov_messages() -> dict:
    """Request vectors (CLI encodes, device decodes) and response vectors
    (device encodes, CLI decodes)."""
    requests = {
        "ver_req": codec.encode_ver_req(),
        "auth_challenge": codec.encode_auth_challenge(bytes(range(16))),
        "auth_proof": codec.encode_auth_proof(bytes(range(32))),
        "config_get_status": codec.encode_config_get_status(),
        "config_set_full": codec.encode_config_set(
            b"myssid", b"hunter22", bytes.fromhex("a1b2c3d4e5f6"), 11
        ),
        "config_set_minimal": codec.encode_config_set(b"open-net"),
        "config_apply": codec.encode_config_apply(),
        "scan_start_defaults": codec.encode_scan_start(),
        "scan_start_passive": codec.encode_scan_start(passive=True, period_ms=120),
        "scan_get_status": codec.encode_scan_get_status(),
        "scan_get_results": codec.encode_scan_get_results(4, 6),
        "cred_write": codec.encode_cred_write(
            codec.CredKind.DEVICE_CERT, 0, 6, bytes.fromhex("30820102aabb")
        ),
        "cred_finalize": codec.encode_cred_finalize(),
        "cred_get_status": codec.encode_cred_get_status(),
        "ctrl_reset": codec.encode_ctrl(codec.CtrlOp.RESET),
        "ctrl_reprov": codec.encode_ctrl(codec.CtrlOp.REPROVISION),
        "ctrl_end": codec.encode_ctrl(codec.CtrlOp.END),
    }
    responses = {
        "ver_rsp": cbor2.dumps(
            [0, 0, {"proto": 1, "caps": ["wifi", "scan", "cred", "auth"],
                    "blk": 512, "lib": "0.1.0", "pop": True}]
        ),
        "auth_challenge_rsp": cbor2.dumps([0, 0, bytes(range(16, 32)), bytes(range(32, 64))]),
        "auth_proof_rsp": cbor2.dumps([1, 0]),
        "auth_proof_rsp_unauthorized": cbor2.dumps([1, 4]),
        "config_status_connecting": cbor2.dumps([0, 0, 1]),
        "config_status_failed_auth": cbor2.dumps([0, 0, 3, 0]),
        "config_status_connected": cbor2.dumps(
            [0, 0, 0, {"ip4": bytes([192, 168, 1, 7]), "ssid": b"myssid", "rssi": -41}]
        ),
        "config_set_rsp": cbor2.dumps([1, 0]),
        "config_apply_rsp": cbor2.dumps([2, 0]),
        "scan_start_rsp": cbor2.dumps([0, 0]),
        "scan_status_rsp": cbor2.dumps([1, 0, True, 9]),
        "scan_results_rsp": cbor2.dumps(
            [2, 0, [
                {"ssid": b"myssid", "bssid": bytes.fromhex("a1b2c3d4e5f6"),
                 "ch": 11, "rssi": -41, "auth": 1},
                {"ssid": b"guest", "bssid": bytes.fromhex("0611223344ff"),
                 "ch": 1, "rssi": -73, "auth": 0},
            ]]
        ),
        "cred_write_rsp": cbor2.dumps([0, 0, 6]),
        "cred_finalize_rsp": cbor2.dumps([1, 0]),
        "cred_status_rsp": cbor2.dumps([2, 0, {"0": 1042, "1": 121}]),
        "ctrl_end_rsp": cbor2.dumps([2, 0]),
    }
    return {
        "requests": {k: v.hex() for k, v in requests.items()},
        "responses": {k: v.hex() for k, v in responses.items()},
    }


def pouch_frames() -> dict:
    """Plaintext pouch frames exercising header/block/entry framing."""
    single = pouch.build_entry_pouch(
        "dev-1", [pouch.Entry(codec.PATH_VER, pouch.CONTENT_TYPE_CBOR, codec.encode_ver_req())]
    )
    multi = pouch.build_entry_pouch(
        "dev-1",
        [
            pouch.Entry(codec.PATH_CONFIG, pouch.CONTENT_TYPE_CBOR,
                        codec.encode_config_set(b"myssid", b"hunter22")),
            pouch.Entry(codec.PATH_CONFIG, pouch.CONTENT_TYPE_CBOR, codec.encode_config_apply()),
        ],
    )
    # Force multi-block: two entries that cannot share a 64-byte block.
    multiblock = pouch.build_entry_pouch(
        "dev-1",
        [
            pouch.Entry(codec.PATH_CRED, pouch.CONTENT_TYPE_CBOR,
                        codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 0, 48, bytes(24))),
            pouch.Entry(codec.PATH_CRED, pouch.CONTENT_TYPE_CBOR,
                        codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 24, 48, bytes(24))),
        ],
        block_size=96,
    )
    empty = pouch.Pouch(
        pouch.PouchHeader(pouch.ENCRYPTION_NONE, device_id="dev-1"),
        [pouch.Block(b"")],
    ).encode()
    return {k: v.hex() for k, v in
            {"single_entry": single, "two_entries_one_block": multi,
             "two_blocks": multiblock, "empty": empty}.items()}


def saead_kdf() -> dict:
    """Deterministic saead vectors: fixed P-256 scalars -> INFO string, derived
    key, and a two-block seal chain per algorithm/direction. Everything derives
    from fixed inputs, so regeneration is byte-stable. These pin the Kotlin and
    Swift saead ports to the Python reference (cli/src/pouchprov/pouchlink/saead.py)."""
    server_scalar = int.from_bytes(bytes(range(1, 33)), "big")   # 0x0102...20
    device_scalar = int.from_bytes(bytes(range(33, 65)), "big")  # 0x2122...40
    server_key = ec.derive_private_key(server_scalar, ec.SECP256R1())
    device_key = ec.derive_private_key(device_scalar, ec.SECP256R1())

    def uncompressed(key: ec.EllipticCurvePrivateKey) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    block_log = 9
    pouch_id = 0
    plaintexts = [
        bytes([pouch.BLOCK_ID_ENTRY | pouch.BLOCK_FIRST]) + b"saead vector block 0",
        bytes([pouch.BLOCK_ID_ENTRY | pouch.BLOCK_LAST]) + b"and block 1",
    ]

    def info_string(initiator: int, session_id: bytes, algorithm: int) -> str:
        import base64

        return "E0:{d}:{sid}:C{alg}R:{log:02X}".format(
            d="D" if initiator == saead.ROLE_DEVICE else "S",
            sid=base64.b64encode(session_id).decode(),
            alg="C" if algorithm == saead.ALG_CHACHA20_POLY1305 else "A",
            log=block_log,
        )

    def case(algorithm: int, initiator: int, session_id: bytes) -> dict:
        # Both sides derive the same key from mirrored ECDH inputs.
        key = saead.derive_session_key(
            server_key, device_key.public_key(), session_id, initiator, algorithm, block_log
        )
        sender_role = initiator  # blocks in these vectors are sealed by the initiator
        blocks = []
        prev_tag = b""
        for index, plaintext in enumerate(plaintexts):
            nonce = saead._nonce(pouch_id, index, sender_role)
            aad = prev_tag if index > 0 else b""
            sealed = saead._aead(algorithm, key).encrypt(nonce, plaintext, aad)
            blocks.append({
                "index": index,
                "plaintext": plaintext.hex(),
                "nonce": nonce.hex(),
                "aad": aad.hex(),
                "sealed": sealed.hex(),
            })
            prev_tag = sealed[-saead.AUTH_TAG_LEN:]
        return {
            "algorithm": algorithm,
            "initiator": initiator,
            "session_id": session_id.hex(),
            "info": info_string(initiator, session_id, algorithm),
            "key": key.hex(),
            "blocks": blocks,
        }

    downlink_sid = bytes(range(16))       # 000102...0f
    uplink_sid = bytes(range(16, 32))     # 101112...1f
    return {
        "server_private": server_scalar.to_bytes(32, "big").hex(),
        "device_private": device_scalar.to_bytes(32, "big").hex(),
        "server_public_uncompressed": uncompressed(server_key).hex(),
        "device_public_uncompressed": uncompressed(device_key).hex(),
        "block_log": block_log,
        "pouch_id": pouch_id,
        "cases": {
            "chacha_downlink": case(saead.ALG_CHACHA20_POLY1305, saead.ROLE_SERVER, downlink_sid),
            "aes_downlink": case(saead.ALG_AES_GCM, saead.ROLE_SERVER, downlink_sid),
            "chacha_uplink": case(saead.ALG_CHACHA20_POLY1305, saead.ROLE_DEVICE, uplink_sid),
            "aes_uplink": case(saead.ALG_AES_GCM, saead.ROLE_DEVICE, uplink_sid),
        },
    }


def main() -> None:
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in (("prov_messages", prov_messages()), ("pouch_frames", pouch_frames()),
                       ("saead_kdf", saead_kdf())):
        path = VECTOR_DIR / f"{name}.json"
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
