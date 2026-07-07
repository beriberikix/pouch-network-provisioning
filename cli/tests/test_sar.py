# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""SAR state machines against a scripted peer."""

import asyncio

import pytest

from pouchprov.pouchlink import sar


class Wire:
    def __init__(self):
        self.sent: list[bytes] = []

    async def write(self, data: bytes) -> None:
        self.sent.append(bytes(data))


async def test_sender_single_fragment():
    wire = Wire()
    sender = sar.SarSender(wire.write, maxlen=64)
    task = asyncio.create_task(sender.send(b"hello"))

    sender.feed(bytes([sar.CODE_ACK, 0xFF, 3]))  # initial ack, window 3
    await asyncio.sleep(0.01)
    # single fragment: FIRST|LAST, seq 0
    assert wire.sent[0][0] == sar.FLAG_FIRST | sar.FLAG_LAST
    assert wire.sent[0][1] == 0
    assert wire.sent[0][2:] == b"hello"

    sender.feed(bytes([sar.CODE_ACK, 0, 3]))  # ack of seq 0 -> FIN
    await asyncio.wait_for(task, 1)
    assert wire.sent[-1] == bytes([sar.FLAG_FIN, sar.CODE_ACK])


async def test_sender_windowed_fragments():
    wire = Wire()
    sender = sar.SarSender(wire.write, maxlen=12)  # 10-byte fragments
    data = bytes(range(35))  # 4 fragments
    task = asyncio.create_task(sender.send(data))

    sender.feed(bytes([sar.CODE_ACK, 0xFF, 2]))  # window 2: seq 0,1
    await asyncio.sleep(0.01)
    assert len(wire.sent) == 2
    assert wire.sent[0][0] == sar.FLAG_FIRST
    assert wire.sent[1][0] == 0

    sender.feed(bytes([sar.CODE_ACK, 1, 2]))  # ack 1 -> seq 2,3 (3 is LAST)
    await asyncio.sleep(0.01)
    assert len(wire.sent) == 4
    assert wire.sent[3][0] == sar.FLAG_LAST

    sender.feed(bytes([sar.CODE_ACK, 3, 2]))  # ack LAST -> FIN
    await asyncio.wait_for(task, 1)
    assert wire.sent[-1] == bytes([sar.FLAG_FIN, sar.CODE_ACK])
    assert b"".join(p[2:] for p in wire.sent[:-1]) == data


async def test_sender_nack_aborts():
    wire = Wire()
    sender = sar.SarSender(wire.write, maxlen=32)
    task = asyncio.create_task(sender.send(b"x"))
    sender.feed(bytes([sar.CODE_NACK_UNKNOWN, 0xFF, 3]))
    with pytest.raises(sar.SarError):
        await asyncio.wait_for(task, 1)


async def test_receiver_reassembles():
    wire = Wire()
    recv = sar.SarReceiver(wire.write, window=3)
    task = asyncio.create_task(recv.receive())
    await asyncio.sleep(0.01)
    assert wire.sent[0] == bytes([sar.CODE_ACK, 0xFF, 3])  # initial ack

    recv.feed(bytes([sar.FLAG_FIRST, 0]) + b"ab")
    recv.feed(bytes([0, 1]) + b"cd")
    recv.feed(bytes([sar.FLAG_LAST, 2]) + b"e")
    recv.feed(bytes([sar.FLAG_FIN, sar.CODE_ACK]))  # success FIN
    data = await asyncio.wait_for(task, 1)
    assert data == b"abcde"
    # in-order acks for 0,1,2
    assert [p[1] for p in wire.sent[1:4]] == [0, 1, 2]


async def test_receiver_ignores_out_of_order():
    wire = Wire()
    recv = sar.SarReceiver(wire.write, window=3)
    task = asyncio.create_task(recv.receive())
    await asyncio.sleep(0.01)

    recv.feed(bytes([sar.FLAG_FIRST, 0]) + b"ab")
    recv.feed(bytes([0, 2]) + b"zz")  # skips seq 1: ignored, re-acked
    recv.feed(bytes([sar.FLAG_LAST, 1]) + b"cd")
    recv.feed(bytes([sar.FLAG_FIN, sar.CODE_ACK]))
    assert await asyncio.wait_for(task, 1) == b"abcd"


async def test_receiver_failure_fin():
    wire = Wire()
    recv = sar.SarReceiver(wire.write, window=3)
    task = asyncio.create_task(recv.receive())
    await asyncio.sleep(0.01)
    recv.feed(bytes([sar.FLAG_FIRST | sar.FLAG_LAST, 0]) + b"ab")
    recv.feed(bytes([sar.FLAG_FIN, sar.CODE_NACK_IDLE]))  # retransmit FIN = not success
    with pytest.raises(sar.SarError):
        await asyncio.wait_for(task, 1)


async def test_receiver_polls_with_reacks():
    wire = Wire()
    recv = sar.SarReceiver(wire.write, window=3, reack_interval=0.05)
    task = asyncio.create_task(recv.receive(timeout=1.0))
    await asyncio.sleep(0.2)  # no data: should have re-acked several times
    assert len(wire.sent) >= 3
    assert all(p == bytes([sar.CODE_ACK, 0xFF, 3]) for p in wire.sent)
    recv.feed(bytes([sar.FLAG_FIRST | sar.FLAG_LAST, 0]) + b"x")
    recv.feed(bytes([sar.FLAG_FIN, sar.CODE_ACK]))
    assert await asyncio.wait_for(task, 1) == b"x"
