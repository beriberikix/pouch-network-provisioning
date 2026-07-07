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

from pouchprov import codec  # noqa: E402
from pouchprov.pouchlink import pouch  # noqa: E402

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


def main() -> None:
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in (("prov_messages", prov_messages()), ("pouch_frames", pouch_frames())):
        path = VECTOR_DIR / f"{name}.json"
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
