# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Pin the CLI codec to the frozen golden vectors."""

import json
from pathlib import Path

import pytest

from pouchprov import codec

VECTORS = json.loads(
    (Path(__file__).parent.parent.parent / "tests" / "vectors" / "prov_messages.json").read_text()
)
REQ = {k: bytes.fromhex(v) for k, v in VECTORS["requests"].items()}
RSP = {k: bytes.fromhex(v) for k, v in VECTORS["responses"].items()}


class TestRequestEncoding:
    def test_ver_req(self):
        assert codec.encode_ver_req() == REQ["ver_req"]

    def test_auth(self):
        assert codec.encode_auth_challenge(bytes(range(16))) == REQ["auth_challenge"]
        assert codec.encode_auth_proof(bytes(range(32))) == REQ["auth_proof"]

    def test_config(self):
        assert codec.encode_config_get_status() == REQ["config_get_status"]
        assert (
            codec.encode_config_set(b"myssid", b"hunter22", bytes.fromhex("a1b2c3d4e5f6"), 11)
            == REQ["config_set_full"]
        )
        assert codec.encode_config_set(b"open-net") == REQ["config_set_minimal"]
        assert codec.encode_config_apply() == REQ["config_apply"]

    def test_scan(self):
        assert codec.encode_scan_start() == REQ["scan_start_defaults"]
        assert codec.encode_scan_start(passive=True, period_ms=120) == REQ["scan_start_passive"]
        assert codec.encode_scan_get_status() == REQ["scan_get_status"]
        assert codec.encode_scan_get_results(4, 6) == REQ["scan_get_results"]

    def test_cred(self):
        assert (
            codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 0, 6, bytes.fromhex("30820102aabb"))
            == REQ["cred_write"]
        )
        assert codec.encode_cred_finalize() == REQ["cred_finalize"]
        assert codec.encode_cred_get_status() == REQ["cred_get_status"]

    def test_ctrl(self):
        assert codec.encode_ctrl(codec.CtrlOp.RESET) == REQ["ctrl_reset"]
        assert codec.encode_ctrl(codec.CtrlOp.REPROVISION) == REQ["ctrl_reprov"]
        assert codec.encode_ctrl(codec.CtrlOp.END) == REQ["ctrl_end"]


class TestResponseDecoding:
    def test_ver_rsp(self):
        info = codec.decode_ver_rsp(RSP["ver_rsp"])
        assert info.proto == 1
        assert info.caps == ["wifi", "scan", "cred", "auth"]
        assert info.block_size == 512
        assert info.pop_required is True

    def test_auth(self):
        nonce, proof = codec.decode_auth_challenge_rsp(RSP["auth_challenge_rsp"])
        assert nonce == bytes(range(16, 32))
        assert proof == bytes(range(32, 64))
        codec.decode_auth_proof_rsp(RSP["auth_proof_rsp"])

    def test_auth_unauthorized(self):
        with pytest.raises(codec.ProvError) as exc:
            codec.decode_auth_proof_rsp(RSP["auth_proof_rsp_unauthorized"])
        assert exc.value.status == codec.Status.UNAUTHORIZED

    def test_config_status(self):
        connecting = codec.decode_config_status_rsp(RSP["config_status_connecting"])
        assert connecting.state == codec.StaState.CONNECTING
        assert connecting.fail_reason is None

        failed = codec.decode_config_status_rsp(RSP["config_status_failed_auth"])
        assert failed.state == codec.StaState.FAILED
        assert failed.fail_reason == codec.FailReason.AUTH_ERROR

        connected = codec.decode_config_status_rsp(RSP["config_status_connected"])
        assert connected.state == codec.StaState.CONNECTED
        assert connected.ip4 == bytes([192, 168, 1, 7])
        assert connected.ssid == b"myssid"
        assert connected.rssi == -41

    def test_scan(self):
        codec.decode_scan_start_rsp(RSP["scan_start_rsp"])
        finished, total = codec.decode_scan_status_rsp(RSP["scan_status_rsp"])
        assert finished and total == 9
        entries = codec.decode_scan_results_rsp(RSP["scan_results_rsp"])
        assert len(entries) == 2
        assert entries[0].ssid == b"myssid"
        assert entries[0].rssi == -41
        assert entries[1].auth == 0

    def test_cred(self):
        assert codec.decode_cred_write_rsp(RSP["cred_write_rsp"]) == 6
        codec.decode_cred_finalize_rsp(RSP["cred_finalize_rsp"])
        status = codec.decode_cred_status_rsp(RSP["cred_status_rsp"])
        assert status == {codec.CredKind.DEVICE_CERT: 1042, codec.CredKind.PRIVATE_KEY: 121}

    def test_ctrl(self):
        codec.decode_ctrl_rsp(RSP["ctrl_end_rsp"], codec.CtrlOp.END)

    def test_wrong_op_rejected(self):
        with pytest.raises(codec.DecodeError):
            codec.decode_ver_rsp(RSP["config_set_rsp"])


class TestSecurityName:
    def test_known_types(self):
        expected = {
            0: "Open",
            1: "WPA2-PSK",
            2: "WPA2-PSK-SHA256",
            3: "WPA3-SAE",
            4: "WPA3-SAE-H2E",
            5: "WPA3-SAE-AUTO",
            6: "WAPI",
            7: "EAP-TLS",
            8: "WEP",
            9: "WPA-PSK",
            10: "WPA/WPA2-Auto",
            11: "DPP",
        }
        for auth, name in expected.items():
            assert codec.security_name(auth) == name

    def test_unknown_type(self):
        assert codec.security_name(42) == "unknown(42)"
        assert codec.security_name(-1) == "unknown(-1)"

    def test_scan_entry_auth_name(self):
        entry = codec.ScanEntry(ssid=b"x", bssid=b"", channel=1, rssi=-40, auth=3)
        assert entry.auth_name == "WPA3-SAE"
