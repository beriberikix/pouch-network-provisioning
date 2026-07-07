# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Pouch SAR (segmentation and reassembly) — client side.

Wire format per pouch src/transport/sar/packet.{h,c}:

TX packet (sender -> receiver):
    byte 0: flags — FIRST=0x01, LAST=0x02, FIN=0x04
    byte 1: sequence number (mod 256); for FIN packets this is a code
            byte instead: 0 on the first FIN (success), 2 on retransmits
    2..:    fragment payload

ACK packet (receiver -> sender):
    byte 0: code — 0 ACK, 1 NACK_UNKNOWN, 2 NACK_IDLE
    byte 1: last in-order sequence received (0xFF before any)
    byte 2: window (<= 127)

Sender flow: open, wait for an ack, then keep `seq != (ack.seq +
ack.window + 1) & 0xFF` fragments in flight. When the last fragment
(flagged LAST) is acked, send FIN [0x04, 0x00].

Receiver flow: ack immediately on open ([0, 0xFF, window]) and after
every in-order fragment; re-ack periodically as a poll (the device
treats a repeated ack as "push more when ready"). A FIN with code 0 is
success.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

FLAG_FIRST = 0x01
FLAG_LAST = 0x02
FLAG_FIN = 0x04

CODE_ACK = 0
CODE_NACK_UNKNOWN = 1
CODE_NACK_IDLE = 2

SEQ_MASK = 0xFF
HEADER_LEN = 2

WriteCb = Callable[[bytes], Awaitable[None]]


class SarError(Exception):
    pass


class SarSender:
    """Send one blob as a SAR transaction."""

    def __init__(self, write: WriteCb, maxlen: int):
        if maxlen <= HEADER_LEN:
            raise ValueError("maxlen too small")
        self._write = write
        self._frag = maxlen - HEADER_LEN
        self._acks: asyncio.Queue[bytes] = asyncio.Queue()

    def feed(self, pkt: bytes) -> None:
        """Feed an incoming ACK notification."""
        self._acks.put_nowait(bytes(pkt))

    async def send(self, data: bytes, timeout: float = 10.0) -> None:
        frags = [data[i : i + self._frag] for i in range(0, len(data), self._frag)] or [b""]
        seq = 0
        target = 0  # advances with acks
        sent_last = False

        while True:
            try:
                ack = await asyncio.wait_for(self._acks.get(), timeout)
            except asyncio.TimeoutError:
                raise SarError("timed out waiting for ack") from None
            if len(ack) != 3:
                raise SarError(f"bad ack length {len(ack)}")
            code, ack_seq, window = ack
            if code != CODE_ACK:
                raise SarError(f"receiver NACK (code {code})")
            target = (ack_seq + window + 1) & SEQ_MASK

            if sent_last:
                if ack_seq == (seq - 1) & SEQ_MASK:
                    await self._write(bytes([FLAG_FIN, CODE_ACK]))
                    return
                continue  # stale ack; wait for the ack of the LAST fragment

            while seq != target and not sent_last:
                idx = seq  # fragments are < 256 for provisioning payloads
                flags = 0
                if idx == 0:
                    flags |= FLAG_FIRST
                if idx == len(frags) - 1:
                    flags |= FLAG_LAST
                    sent_last = True
                await self._write(bytes([flags, seq]) + frags[idx])
                seq = (seq + 1) & SEQ_MASK


class SarReceiver:
    """Receive one blob as a SAR transaction."""

    def __init__(self, write: WriteCb, window: int = 8, reack_interval: float = 0.5):
        if not 1 <= window <= 127:
            raise ValueError("window out of range")
        self._write = write
        self._window = window
        self._reack = reack_interval
        self._pkts: asyncio.Queue[bytes] = asyncio.Queue()

    def feed(self, pkt: bytes) -> None:
        """Feed an incoming TX-packet notification."""
        self._pkts.put_nowait(bytes(pkt))

    async def _ack(self, seq: int) -> None:
        await self._write(bytes([CODE_ACK, seq, self._window]))

    async def receive(self, timeout: float = 15.0) -> bytes:
        """Run the transaction to completion; returns the reassembled blob."""
        chunks: list[bytes] = []
        expected = 0
        last = 0xFF
        ended = False
        deadline = asyncio.get_running_loop().time() + timeout

        await self._ack(last)

        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise SarError("timed out waiting for data")
            try:
                pkt = await asyncio.wait_for(self._pkts.get(), min(self._reack, remaining))
            except asyncio.TimeoutError:
                await self._ack(last)  # periodic re-ack doubles as a poll
                continue

            if len(pkt) < HEADER_LEN:
                raise SarError("short packet")
            flags = pkt[0]

            if flags & FLAG_FIN:
                if not ended:
                    raise SarError("FIN before LAST fragment")
                if pkt[1] == CODE_ACK:
                    return b"".join(chunks)
                raise SarError(f"transfer failed (FIN code {pkt[1]})")

            seq = pkt[1]
            if seq != expected:
                await self._ack(last)  # out of order: re-ack last in-order
                continue

            if ended:
                raise SarError("fragment after LAST")

            chunks.append(pkt[HEADER_LEN:])
            last = seq
            expected = (seq + 1) & SEQ_MASK
            if flags & FLAG_LAST:
                ended = True
            await self._ack(last)
