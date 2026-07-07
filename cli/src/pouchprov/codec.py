# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Provisioning message codec (cddl/prov.cddl, protocol version 1).

Every message is a CBOR array [op, ...]. This module keeps encoding
explicit and boring so it can be pinned to the device's zcbor codec via
the shared golden vectors in tests/vectors/.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

import cbor2

PROTO_VERSION = 1

# Reserved provisioning paths (pouch downlink/uplink entry paths).
PATH_VER = ".prov/ver"
PATH_AUTH = ".prov/auth"
PATH_CONFIG = ".prov/config"
PATH_SCAN = ".prov/scan"
PATH_CRED = ".prov/cred"
PATH_CTRL = ".prov/ctrl"


class Status(IntEnum):
    OK = 0
    INVALID_PROTO = 1
    INVALID_ARGUMENT = 2
    INTERNAL_ERROR = 3
    UNAUTHORIZED = 4
    INVALID_STATE = 5
    BUSY = 6


class StaState(IntEnum):
    CONNECTED = 0
    CONNECTING = 1
    DISCONNECTED = 2
    FAILED = 3


class FailReason(IntEnum):
    AUTH_ERROR = 0
    NETWORK_NOT_FOUND = 1


class CredKind(IntEnum):
    DEVICE_CERT = 0
    PRIVATE_KEY = 1
    CA_CERT = 2


class CtrlOp(IntEnum):
    RESET = 0
    REPROVISION = 1
    END = 2


class ProvError(Exception):
    """Protocol-level error reported by the device."""

    def __init__(self, status: Status, context: str = ""):
        self.status = status
        super().__init__(f"{context}: {status.name}" if context else status.name)


class DecodeError(Exception):
    """Response did not match the schema."""


def _decode(data: bytes, expect_op: int, context: str) -> list:
    try:
        msg = cbor2.loads(data)
    except Exception as exc:
        raise DecodeError(f"{context}: bad CBOR: {exc}") from exc
    if not isinstance(msg, list) or len(msg) < 2:
        raise DecodeError(f"{context}: not a response array")
    if msg[0] != expect_op:
        raise DecodeError(f"{context}: op {msg[0]}, expected {expect_op}")
    status = Status(msg[1])
    if status != Status.OK:
        raise ProvError(status, context)
    return msg


# ---- .prov/ver -----------------------------------------------------------


@dataclass
class VersionInfo:
    proto: int
    caps: list[str]
    block_size: int
    lib: str
    pop_required: bool


def encode_ver_req() -> bytes:
    return cbor2.dumps([0])


def decode_ver_rsp(data: bytes) -> VersionInfo:
    msg = _decode(data, 0, "ver")
    info = msg[2]
    return VersionInfo(
        proto=info["proto"],
        caps=list(info["caps"]),
        block_size=info["blk"],
        lib=info["lib"],
        pop_required=bool(info.get("pop", False)),
    )


# ---- .prov/auth ----------------------------------------------------------


def encode_auth_challenge(cli_nonce: bytes) -> bytes:
    assert len(cli_nonce) == 16
    return cbor2.dumps([0, cli_nonce])


def decode_auth_challenge_rsp(data: bytes) -> tuple[bytes, bytes]:
    """Returns (dev_nonce, dev_proof)."""
    msg = _decode(data, 0, "auth")
    dev_nonce, dev_proof = bytes(msg[2]), bytes(msg[3])
    if len(dev_nonce) != 16 or len(dev_proof) != 32:
        raise DecodeError("auth: bad nonce/proof size")
    return dev_nonce, dev_proof


def encode_auth_proof(cli_proof: bytes) -> bytes:
    assert len(cli_proof) == 32
    return cbor2.dumps([1, cli_proof])


def decode_auth_proof_rsp(data: bytes) -> None:
    _decode(data, 1, "auth")


# ---- .prov/config ---------------------------------------------------------


@dataclass
class WifiStatus:
    state: StaState
    fail_reason: FailReason | None = None
    ip4: bytes | None = None
    ssid: bytes | None = None
    rssi: int | None = None


def encode_config_get_status() -> bytes:
    return cbor2.dumps([0])


def encode_config_set(
    ssid: bytes, password: bytes | None = None, bssid: bytes | None = None, channel: int | None = None
) -> bytes:
    cfg: dict = {"ssid": ssid}
    if password is not None:
        cfg["pass"] = password
    if bssid is not None:
        cfg["bssid"] = bssid
    if channel is not None:
        cfg["ch"] = channel
    return cbor2.dumps([1, cfg])


def encode_config_apply() -> bytes:
    return cbor2.dumps([2])


def decode_config_status_rsp(data: bytes) -> WifiStatus:
    msg = _decode(data, 0, "config")
    state = StaState(msg[2])
    status = WifiStatus(state)
    if len(msg) > 3:
        detail = msg[3]
        if isinstance(detail, int):
            status.fail_reason = FailReason(detail)
        elif isinstance(detail, dict):
            status.ip4 = bytes(detail["ip4"])
            status.ssid = bytes(detail["ssid"])
            status.rssi = detail.get("rssi")
        else:
            raise DecodeError("config: bad status detail")
    return status


def decode_config_set_rsp(data: bytes) -> None:
    _decode(data, 1, "config")


def decode_config_apply_rsp(data: bytes) -> None:
    _decode(data, 2, "config")


# ---- .prov/scan ------------------------------------------------------------


@dataclass
class ScanEntry:
    ssid: bytes
    bssid: bytes
    channel: int
    rssi: int
    auth: int


def encode_scan_start(passive: bool | None = None, period_ms: int | None = None) -> bytes:
    params: dict = {}
    if passive is not None:
        params["passive"] = passive
    if period_ms is not None:
        params["period-ms"] = period_ms
    return cbor2.dumps([0, params])


def encode_scan_get_status() -> bytes:
    return cbor2.dumps([1])


def encode_scan_get_results(start: int, count: int) -> bytes:
    return cbor2.dumps([2, start, count])


def decode_scan_start_rsp(data: bytes) -> None:
    _decode(data, 0, "scan")


def decode_scan_status_rsp(data: bytes) -> tuple[bool, int]:
    """Returns (finished, total)."""
    msg = _decode(data, 1, "scan")
    return bool(msg[2]), int(msg[3])


def decode_scan_results_rsp(data: bytes) -> list[ScanEntry]:
    msg = _decode(data, 2, "scan")
    return [
        ScanEntry(
            ssid=bytes(e["ssid"]),
            bssid=bytes(e["bssid"]),
            channel=e["ch"],
            rssi=e["rssi"],
            auth=e["auth"],
        )
        for e in msg[2]
    ]


# ---- .prov/cred -------------------------------------------------------------


def encode_cred_write(kind: CredKind, offset: int, total: int, data: bytes) -> bytes:
    return cbor2.dumps([0, {"kind": int(kind), "off": offset, "total": total, "data": data}])


def encode_cred_finalize() -> bytes:
    return cbor2.dumps([1])


def encode_cred_get_status() -> bytes:
    return cbor2.dumps([2])


def decode_cred_write_rsp(data: bytes) -> int:
    """Returns total bytes received for the written kind."""
    msg = _decode(data, 0, "cred")
    return int(msg[2])


def decode_cred_finalize_rsp(data: bytes) -> None:
    _decode(data, 1, "cred")


def decode_cred_status_rsp(data: bytes) -> dict[CredKind, int]:
    msg = _decode(data, 2, "cred")
    return {CredKind(int(k)): int(v) for k, v in msg[2].items()}


# ---- .prov/ctrl --------------------------------------------------------------


def encode_ctrl(op: CtrlOp) -> bytes:
    return cbor2.dumps([int(op)])


def decode_ctrl_rsp(data: bytes, op: CtrlOp) -> None:
    _decode(data, int(op), "ctrl")
