# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Full RPC loopback: ProvSession against the mock device transport."""

import cbor2
import pytest

from pouchprov import codec
from pouchprov.session import ProvSession, SessionError
from pouchprov.transport.mock import MockDeviceTransport


def ver_handler(path: str, payload: bytes) -> bytes | None:
    if path == codec.PATH_VER:
        return cbor2.dumps(
            [0, 0, {"proto": 1, "caps": ["wifi"], "blk": 512, "lib": "test", "pop": False}]
        )
    return None


async def test_ver_round_trip():
    transport = MockDeviceTransport(ver_handler)
    session = ProvSession(transport)
    info = codec.decode_ver_rsp(await session.request(codec.PATH_VER, codec.encode_ver_req()))
    assert info.proto == 1
    assert info.caps == ["wifi"]
    assert session.device_id == "mock-dev"


async def test_multi_entry_batch():
    calls: list[str] = []

    def handler(path: str, payload: bytes) -> bytes | None:
        calls.append(path)
        return cbor2.dumps([cbor2.loads(payload)[0], 0])

    transport = MockDeviceTransport(handler)
    session = ProvSession(transport)
    entries = await session.request_entries(
        [
            codec_entry(codec.PATH_CTRL, codec.encode_ctrl(codec.CtrlOp.RESET)),
            codec_entry(codec.PATH_CTRL, codec.encode_ctrl(codec.CtrlOp.END)),
        ]
    )
    assert calls == [codec.PATH_CTRL, codec.PATH_CTRL]
    assert len(entries) == 2
    codec.decode_ctrl_rsp(entries[0].data, codec.CtrlOp.RESET)
    codec.decode_ctrl_rsp(entries[1].data, codec.CtrlOp.END)


async def test_empty_pouch_retry():
    transport = MockDeviceTransport(ver_handler, defer_responses=2)
    session = ProvSession(transport)
    info = codec.decode_ver_rsp(await session.request(codec.PATH_VER, codec.encode_ver_req()))
    assert info.proto == 1  # succeeded on the 3rd uplink cycle


async def test_no_response_raises():
    transport = MockDeviceTransport(lambda p, d: None)  # handler never responds
    session = ProvSession(transport)
    with pytest.raises(SessionError):
        await session.request(codec.PATH_VER, codec.encode_ver_req(), timeout=1.0)


async def test_large_response_multi_fragment():
    big = cbor2.dumps([2, 0, [{"ssid": bytes(30), "bssid": bytes(6), "ch": 1,
                               "rssi": -40, "auth": 1} for _ in range(6)]])
    assert len(big) > 244  # forces >1 SAR fragment on the uplink

    transport = MockDeviceTransport(lambda p, d: big if p == codec.PATH_SCAN else None)
    session = ProvSession(transport)
    entries = codec.decode_scan_results_rsp(
        await session.request(codec.PATH_SCAN, codec.encode_scan_get_results(0, 6))
    )
    assert len(entries) == 6


def codec_entry(path: str, msg: bytes):
    from pouchprov.pouchlink import pouch

    return pouch.Entry(path, pouch.CONTENT_TYPE_CBOR, msg)
