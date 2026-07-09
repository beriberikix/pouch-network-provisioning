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

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..pouchlink import cert as certmod
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


class _DeviceSarSender:
    """Device-side SAR sender behind a mock channel (info / device_cert)."""

    def __init__(self, channel: _MockChannel, payload_fn: Callable[[], bytes],
                 frag: int = 244 - sar.HEADER_LEN):
        self._channel = channel
        self._payload_fn = payload_fn
        self._frag = frag
        self._frags: list[bytes] = []
        self._seq = 0
        self._finished = False
        channel.on_subscribe = self._open
        channel.on_write = self._on_ack

    def _open(self) -> None:
        data = self._payload_fn()
        self._frags = [data[i:i + self._frag] for i in range(0, len(data), self._frag)]
        self._seq = 0
        self._finished = False

    def _on_ack(self, ack: bytes) -> None:
        code, ack_seq, window = ack
        assert code == sar.CODE_ACK
        if self._finished:
            return
        if self._seq >= len(self._frags):
            if ack_seq == (self._seq - 1) & 0xFF:
                self._finished = True
                self._channel.notify(bytes([sar.FLAG_FIN, sar.CODE_ACK]))
            return
        target = (ack_seq + window + 1) & 0xFF
        while self._seq != target and self._seq < len(self._frags):
            flags = 0
            if self._seq == 0:
                flags |= sar.FLAG_FIRST
            if self._seq == len(self._frags) - 1:
                flags |= sar.FLAG_LAST
            self._channel.notify(bytes([flags, self._seq]) + self._frags[self._seq])
            self._seq += 1


class _DeviceSarReceiver:
    """Device-side SAR receiver behind a mock channel (server_cert)."""

    def __init__(self, channel: _MockChannel, on_data: Callable[[bytes], None],
                 window: int = 3):
        self._channel = channel
        self._on_data = on_data
        self._window = window
        self._chunks: list[bytes] = []
        self._expected = 0
        self._ended = False
        channel.on_subscribe = self._open
        channel.on_write = self._on_write

    def _ack(self, seq: int) -> None:
        self._channel.notify(bytes([sar.CODE_ACK, seq, self._window]))

    def _open(self) -> None:
        self._chunks = []
        self._expected = 0
        self._ended = False
        self._ack(0xFF)

    def _on_write(self, pkt: bytes) -> None:
        flags = pkt[0]
        if flags & sar.FLAG_FIN:
            assert self._ended, "FIN before LAST"
            if pkt[1] == sar.CODE_ACK:
                self._on_data(b"".join(self._chunks))
            return
        seq = pkt[1]
        assert seq == self._expected, f"mock expects in-order (got {seq})"
        self._chunks.append(pkt[2:])
        self._expected = (seq + 1) & 0xFF
        if flags & sar.FLAG_LAST:
            self._ended = True
        self._ack(seq)


class MockDeviceTransport(Transport):
    """Device-side state machine behind two mock channels.

    Pass `saead_identity` (a device Identity) to model a saead firmware
    build: the transport grows the info/server_cert/device_cert TOFU
    endpoints, stores the pushed server cert, and encrypts the pouch path
    once the exchange completes — mirroring the firmware, where saead is a
    compile-time choice.
    """

    def __init__(self, handler: Handler, device_id: str = "mock-dev",
                 window: int = 3, defer_responses: int = 0,
                 device_saead: "DeviceSaead | None" = None,
                 saead_identity: "certmod.Identity | None" = None,
                 saead_algorithm: int = saead.ALG_CHACHA20_POLY1305):
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

        self._identity = saead_identity
        self._saead_algorithm = saead_algorithm
        self.stored_server_cert: bytes | None = None
        if saead_identity is not None:
            self.info = _MockChannel()
            self.server_cert = _MockChannel()
            self.device_cert = _MockChannel()
            _DeviceSarSender(self.info, self._info_payload)
            _DeviceSarSender(self.device_cert, lambda: saead_identity.cert_der)
            _DeviceSarReceiver(self.server_cert, self._store_server_cert)

    # -- TOFU endpoints (saead builds) ----------------------------------------

    def _info_payload(self) -> bytes:
        if self.stored_server_cert is None:
            serial = b""
        else:
            from cryptography import x509

            n = x509.load_der_x509_certificate(self.stored_server_cert).serial_number
            serial = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
            # mbedtls keeps the DER sign byte; model that worst case.
            if serial[0] & 0x80:
                serial = b"\x00" + serial
        return cbor2.dumps({"flags": 0, "server_cert_snr": serial})

    def _store_server_cert(self, der: bytes) -> None:
        assert self._identity is not None
        self.stored_server_cert = der
        self._saead = DeviceSaead(
            self._identity.private_key,
            certmod.device_public_key(der),
            algorithm=self._saead_algorithm,
        )

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
