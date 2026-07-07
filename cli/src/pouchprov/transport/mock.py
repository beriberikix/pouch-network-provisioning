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
import struct
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..pouchlink import pouch, saead
from ..pouchlink import sar
from .base import Channel, Transport

Handler = Callable[[str, bytes], bytes | None]


class DeviceSaead:
    """Device-side saead for the mock: decrypt downlink, encrypt uplink.

    Mirrors the firmware: for a server-initiated downlink it derives
    ECDH(device_priv, server_pub) with the header's session params; for
    its own uplink it initiates a device session with a fresh id.
    """

    def __init__(self, device_priv: ec.EllipticCurvePrivateKey,
                 server_pub: ec.EllipticCurvePublicKey,
                 algorithm: int = saead.ALG_CHACHA20_POLY1305, block_log: int = 9):
        self._priv = device_priv
        self._server_pub = server_pub
        self._algorithm = algorithm
        self._block_log = block_log

    def _aead(self, key: bytes):
        return (ChaCha20Poly1305(key) if self._algorithm == saead.ALG_CHACHA20_POLY1305
                else AESGCM(key))

    def decrypt_downlink(self, data: bytes) -> list[pouch.Entry]:
        header, consumed = pouch.PouchHeader.decode(data)
        info = header.session
        key = saead.derive_session_key(self._priv, self._server_pub, info.session_id,
                                       saead.ROLE_SERVER, info.algorithm, info.max_block_size_log)
        aead = self._aead(key)
        pos, idx, prev_tag, payloads = consumed, 0, b"", []
        while pos < len(data):
            (size,) = struct.unpack_from(">H", data, pos)
            pos += 2
            sealed = data[pos:pos + size]
            pos += size
            nonce = struct.pack(">HHB", header.pouch_id, idx, saead.ROLE_SERVER) + b"\x00" * 7
            plain = aead.decrypt(nonce, sealed, prev_tag if idx > 0 else b"")
            prev_tag = sealed[-16:]
            payloads.append(plain[1:])
            idx += 1
        return pouch.parse_entry_blocks(payloads)

    def encrypt_uplink(self, entries: list[pouch.Entry], session_id: bytes,
                       pouch_id: int = 1) -> bytes:
        key = saead.derive_session_key(self._priv, self._server_pub, session_id,
                                       saead.ROLE_DEVICE, self._algorithm, self._block_log)
        aead = self._aead(key)
        cert_ref = b"\x00" * 6
        info = pouch.SessionInfo(session_id, saead.ROLE_DEVICE, self._algorithm,
                                 self._block_log, cert_ref)
        header = pouch.PouchHeader(pouch.ENCRYPTION_SAEAD, session=info, pouch_id=pouch_id)
        payload = b"".join(e.encode() for e in entries)
        id_byte = pouch.BLOCK_ID_ENTRY | pouch.BLOCK_FIRST | pouch.BLOCK_LAST
        block_plain = bytes([id_byte]) + payload
        nonce = struct.pack(">HHB", pouch_id, 0, saead.ROLE_DEVICE) + b"\x00" * 7
        sealed = aead.encrypt(nonce, block_plain, b"")
        return header.encode() + struct.pack(">H", len(sealed)) + sealed


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
                 window: int = 3, defer_responses: int = 0,
                 device_saead: "DeviceSaead | None" = None):
        self.downlink = _MockChannel()
        self.uplink = _MockChannel()
        self._handler = handler
        self._device_id = device_id
        self._window = window
        self._saead = device_saead
        self._uplink_sid = bytes(range(16))
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
        if self._saead is not None:
            entries = self._saead.decrypt_downlink(data)
        else:
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
        if self._saead is not None:
            if entries:
                data = self._saead.encrypt_uplink(entries, self._uplink_sid)
            else:
                info = pouch.SessionInfo(self._uplink_sid, saead.ROLE_DEVICE,
                                         self._saead._algorithm, self._saead._block_log, bytes(6))
                data = pouch.PouchHeader(pouch.ENCRYPTION_SAEAD, session=info, pouch_id=1).encode()
        elif entries:
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
