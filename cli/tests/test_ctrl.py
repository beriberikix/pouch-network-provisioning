# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Device control flows (reset / reprovision) and the credential status query."""

import cbor2
import pytest

from pouchprov import codec, flows
from pouchprov.session import ProvSession
from pouchprov.transport.mock import MockDeviceTransport


class CtrlDevice:
    """Mock device implementing .prov/ctrl and the cred status op."""

    def __init__(self):
        self.ops = []
        self.staged = {0: b"x" * 1042, 1: b"y" * 121, 2: b""}

    def handle(self, path, payload):
        if path == codec.PATH_CTRL:
            op = cbor2.loads(payload)[0]
            self.ops.append(op)
            if op == int(codec.CtrlOp.REPROVISION):
                self.staged = {0: b"", 1: b"", 2: b""}
            return cbor2.dumps([op, 0])
        if path == codec.PATH_CRED:
            assert cbor2.loads(payload)[0] == 2  # only the status op is expected here
            return cbor2.dumps([2, 0, {k: len(v) for k, v in self.staged.items() if v}])
        return None


async def test_reset():
    dev = CtrlDevice()
    session = ProvSession(MockDeviceTransport(dev.handle))
    await flows.reset(session)
    assert dev.ops == [int(codec.CtrlOp.RESET)]


async def test_reprovision_wipes_and_status_reflects_it():
    dev = CtrlDevice()
    session = ProvSession(MockDeviceTransport(dev.handle))

    before = await flows.cred_status(session)
    assert before == {codec.CredKind.DEVICE_CERT: 1042, codec.CredKind.PRIVATE_KEY: 121}

    await flows.reprovision(session)
    assert dev.ops == [int(codec.CtrlOp.REPROVISION)]

    after = await flows.cred_status(session)
    assert after == {}


async def test_ctrl_error_raises():
    def handle(path, payload):
        assert path == codec.PATH_CTRL
        return cbor2.dumps([cbor2.loads(payload)[0], int(codec.Status.INVALID_STATE)])

    session = ProvSession(MockDeviceTransport(handle))
    with pytest.raises(codec.ProvError):
        await flows.reset(session)
