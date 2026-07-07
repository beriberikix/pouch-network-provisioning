# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""In-memory mock of a provisioning device for tests.

Implements the device side of the SAR + pouch RPC contract faithfully
enough to exercise the full client stack: initial-ack-on-subscribe,
in-order acking, LAST/FIN handshake ([0x04, 0x00] success FIN), and the
one-transaction-per-subscribe rule. Requests are dispatched to a
handler: (path, payload) -> response payload | None.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from ..pouchlink import pouch, sar
from .base import Channel, Transport

Handler = Callable[[str, bytes], bytes | None]


class _MockChannel(Channel):
    def __init__(self):
        self._notify: Callable[[bytes], None] | None = None
        self.on_write: Callable[[bytes], None] | None = None
        self.on_subscribe: Callable[[], None] | None = None
        self.on_unsubscribe: Callable[[], None] | None = None

    async def write(self, data: bytes) -> None:
        assert self.on_write is not None
        self.on_write(bytes(data))
        await asyncio.sleep(0)  # yield, as a real transport would

    async def subscribe(self, cb) -> None:
        self._notify = cb
        if self.on_subscribe:
            self.on_subscribe()

    async def unsubscribe(self) -> None:
        self._notify = None
        if self.on_unsubscribe:
            self.on_unsubscribe()

    def notify(self, data: bytes) -> None:
        if self._notify is not None:
            self._notify(bytes(data))


class MockDeviceTransport(Transport):
    """Device-side state machine behind two mock channels."""

    def __init__(self, handler: Handler, device_id: str = "mock-dev",
                 window: int = 3, defer_responses: int = 0):
        self.downlink = _MockChannel()
        self.uplink = _MockChannel()
        self._handler = handler
        self._device_id = device_id
        self._window = window
        # Number of uplink cycles to answer with an empty pouch first
        # (simulates "response not ready").
        self._defer = defer_responses
        self._responses: list[pouch.Entry] = []
        self._rx_chunks: list[bytes] = []
        self._rx_expected = 0
        self._rx_ended = False

        self.downlink.on_subscribe = self._dl_open
        self.downlink.on_write = self._dl_write
        self.uplink.on_subscribe = self._ul_open
        self.uplink.on_write = self._ul_write

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    # -- downlink: device is the SAR receiver --------------------------------

    def _dl_ack(self, seq: int) -> None:
        self.downlink.notify(bytes([sar.CODE_ACK, seq, self._window]))

    def _dl_open(self) -> None:
        self._rx_chunks = []
        self._rx_expected = 0
        self._rx_ended = False
        self._dl_ack(0xFF)

    def _dl_write(self, pkt: bytes) -> None:
        flags = pkt[0]
        if flags & sar.FLAG_FIN:
            assert self._rx_ended, "FIN before LAST"
            if pkt[1] == sar.CODE_ACK:
                self._process_request(b"".join(self._rx_chunks))
            return
        seq = pkt[1]
        assert seq == self._rx_expected, f"mock expects in-order (got {seq})"
        self._rx_chunks.append(pkt[2:])
        self._rx_expected = (seq + 1) & 0xFF
        if flags & sar.FLAG_LAST:
            self._rx_ended = True
        self._dl_ack(seq)

    def _process_request(self, data: bytes) -> None:
        _header, entries = pouch.parse_pouch(data)
        for entry in entries:
            rsp = self._handler(entry.path, entry.data)
            if rsp is not None:
                self._responses.append(pouch.Entry(entry.path, entry.content_type, rsp))

    # -- uplink: device is the SAR sender -------------------------------------

    def _ul_open(self) -> None:
        if self._defer > 0:
            self._defer -= 1
            entries: list[pouch.Entry] = []
        else:
            entries, self._responses = self._responses, []
        if entries:
            data = pouch.build_entry_pouch(self._device_id, entries)
        else:
            data = pouch.Pouch(
                pouch.PouchHeader(pouch.ENCRYPTION_NONE, device_id=self._device_id),
                [pouch.Block(b"")],
            ).encode()
        frag = 244 - sar.HEADER_LEN
        self._ul_frags = [data[i : i + frag] for i in range(0, len(data), frag)]
        self._ul_seq = 0
        self._ul_finished = False

    def _ul_write(self, ack: bytes) -> None:
        code, ack_seq, window = ack
        assert code == sar.CODE_ACK
        if self._ul_finished:
            return
        if self._ul_seq >= len(self._ul_frags):
            # All fragments sent; ack of the last one triggers FIN.
            if ack_seq == (self._ul_seq - 1) & 0xFF:
                self._ul_finished = True
                self.uplink.notify(bytes([sar.FLAG_FIN, sar.CODE_ACK]))
            return
        target = (ack_seq + window + 1) & 0xFF
        while self._ul_seq != target and self._ul_seq < len(self._ul_frags):
            flags = 0
            if self._ul_seq == 0:
                flags |= sar.FLAG_FIRST
            if self._ul_seq == len(self._ul_frags) - 1:
                flags |= sar.FLAG_LAST
            self.uplink.notify(bytes([flags, self._ul_seq]) + self._ul_frags[self._ul_seq])
            self._ul_seq += 1
