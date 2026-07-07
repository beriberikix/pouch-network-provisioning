# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""CLI Wi-Fi flows against a stateful mock device (scan + config)."""

import cbor2
import pytest

from pouchprov import codec, flows
from pouchprov.session import ProvSession
from pouchprov.transport.mock import MockDeviceTransport


class WifiDevice:
    """Mock device implementing .prov/{ver,scan,config,ctrl} state."""

    def __init__(self, aps, expected_ssid, expected_pass, pop_required=False):
        self.aps = aps  # list of dicts
        self.expected = (expected_ssid, expected_pass)
        self.pop_required = pop_required
        self.staged = None
        self.sta = codec.StaState.DISCONNECTED
        self.fail = None
        self.scan_started = False

    def handle(self, path, payload):
        msg = cbor2.loads(payload)
        op = msg[0]
        if path == codec.PATH_VER:
            return cbor2.dumps([0, 0, {"proto": 1, "caps": ["wifi", "scan"],
                                       "blk": 512, "lib": "t", "pop": self.pop_required}])
        if path == codec.PATH_SCAN:
            return self._scan(op, msg)
        if path == codec.PATH_CONFIG:
            return self._config(op, msg)
        if path == codec.PATH_CTRL:
            return cbor2.dumps([op, 0])
        return None

    def _scan(self, op, msg):
        if op == 0:
            self.scan_started = True
            return cbor2.dumps([0, 0])
        if op == 1:
            return cbor2.dumps([1, 0, True, len(self.aps)])
        start, count = msg[1], msg[2]
        page = self.aps[start:start + count]
        return cbor2.dumps([2, 0, page])

    def _config(self, op, msg):
        if op == 1:  # set
            cfg = msg[1]
            self.staged = (bytes(cfg["ssid"]), bytes(cfg.get("pass", b"")))
            return cbor2.dumps([1, 0])
        if op == 2:  # apply -> evaluate credentials
            ssid, pw = self.staged
            exp_ssid, exp_pass = self.expected
            if ssid != exp_ssid or not any(ssid == bytes(a["ssid"]) for a in self.aps):
                self.sta, self.fail = codec.StaState.FAILED, codec.FailReason.NETWORK_NOT_FOUND
            elif pw != exp_pass:
                self.sta, self.fail = codec.StaState.FAILED, codec.FailReason.AUTH_ERROR
            else:
                self.sta, self.fail = codec.StaState.CONNECTED, None
            return cbor2.dumps([2, 0])
        # get status
        if self.sta == codec.StaState.CONNECTED:
            return cbor2.dumps([0, 0, 0, {"ip4": bytes([192, 168, 1, 5]),
                                          "ssid": self.expected[0], "rssi": -40}])
        if self.sta == codec.StaState.FAILED:
            return cbor2.dumps([0, 0, 3, int(self.fail)])
        return cbor2.dumps([0, 0, int(self.sta)])


def _ap(ssid):
    return {"ssid": ssid, "bssid": bytes(6), "ch": 6, "rssi": -50, "auth": 1}


async def test_scan_flow():
    dev = WifiDevice([_ap(b"netA"), _ap(b"netB")], b"netA", b"pass1234")
    session = ProvSession(MockDeviceTransport(dev.handle))
    info = await flows.get_version(session)
    assert "scan" in info.caps
    results = await flows.scan(session)
    assert [e.ssid for e in results] == [b"netA", b"netB"]


async def test_configure_success():
    dev = WifiDevice([_ap(b"netA")], b"netA", b"pass1234")
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.get_version(session)
    status = await flows.configure_wifi(session, b"netA", b"pass1234")
    assert status.state == codec.StaState.CONNECTED
    assert status.ip4 == bytes([192, 168, 1, 5])


async def test_configure_wrong_password():
    dev = WifiDevice([_ap(b"netA")], b"netA", b"right-pass")
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.get_version(session)
    status = await flows.configure_wifi(session, b"netA", b"wrong-pass")
    assert status.state == codec.StaState.FAILED
    assert status.fail_reason == codec.FailReason.AUTH_ERROR


async def test_configure_not_found():
    dev = WifiDevice([_ap(b"netA")], b"ghost", b"pass1234")
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.get_version(session)
    status = await flows.configure_wifi(session, b"ghost", b"pass1234")
    assert status.state == codec.StaState.FAILED
    assert status.fail_reason == codec.FailReason.NETWORK_NOT_FOUND


async def test_pop_required_without_pop_raises():
    dev = WifiDevice([], b"x", b"y", pop_required=True)
    session = ProvSession(MockDeviceTransport(dev.handle))
    info = await flows.get_version(session)
    with pytest.raises(RuntimeError):
        await flows.authorize_if_needed(session, info, None)


async def test_end_session():
    dev = WifiDevice([], b"x", b"y")
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.end_session(session)  # should not raise
