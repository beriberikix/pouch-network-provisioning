# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Pouch saead session crypto — the server (client-terminated) side.

Mirrors pouch src/saead/session.c. A session key is derived as:

    shared = ECDH(our_private_key, peer_public_key)          # P-256
    key    = HKDF-SHA256(ikm=shared, salt="", info=INFO)     # no salt
    INFO   = "E0:{D|S}:{b64(session_id)}:C{C|A}{S|R}:{block_log:02X}"

where the D/S letter and session id are the session *initiator*'s (not the
per-block sender's). Each block is AEAD-sealed (ChaCha20-Poly1305 or
AES-256-GCM) with:

    nonce = be16(pouch_id) | be16(block_index) | sender_role | 00*7
    aad   = previous block's 16-byte auth tag (empty for block 0)

A pouch has two independent sessions: the client initiates the downlink
(initiator = server), the device initiates the uplink (initiator =
device). Both derive from the same ECDH secret but with different INFO
(different session id + initiator letter), so different keys.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import pouch

AUTH_TAG_LEN = 16
NONCE_LEN = 12
SESSION_ID_LEN = 16
CERT_REF_LEN = 6

ROLE_DEVICE = pouch.ROLE_DEVICE  # 0
ROLE_SERVER = pouch.ROLE_SERVER  # 1

ALG_CHACHA20_POLY1305 = pouch.ALG_CHACHA20_POLY1305  # 1
ALG_AES_GCM = pouch.ALG_AES_GCM  # 2


def _key_size(algorithm: int) -> int:
    return 32 if algorithm == ALG_CHACHA20_POLY1305 else 16


def _aead(algorithm: int, key: bytes):
    return ChaCha20Poly1305(key) if algorithm == ALG_CHACHA20_POLY1305 else AESGCM(key)


def derive_session_key(
    our_private: ec.EllipticCurvePrivateKey,
    peer_public: ec.EllipticCurvePublicKey,
    session_id_value: bytes,
    initiator: int,
    algorithm: int,
    max_block_size_log: int,
) -> bytes:
    """Derive the AEAD key for one session (matches session_key_generate)."""
    shared = our_private.exchange(ec.ECDH(), peer_public)
    b64 = base64.b64encode(session_id_value).decode()
    info = "E0:{d}:{sid}:C{alg}{typ}:{log:02X}".format(
        d="D" if initiator == ROLE_DEVICE else "S",
        sid=b64,
        alg="C" if algorithm == ALG_CHACHA20_POLY1305 else "A",
        typ="R",  # random session ids only (phase 1)
        log=max_block_size_log,
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_key_size(algorithm),
        salt=None,  # PSA feeds no salt
        info=info.encode(),
    ).derive(shared)


def _nonce(pouch_id: int, block_index: int, sender_role: int) -> bytes:
    return struct.pack(">HHB", pouch_id, block_index, sender_role) + b"\x00" * 7


@dataclass
class _SessionState:
    key: bytes
    algorithm: int
    session_id: bytes
    initiator: int
    max_block_size_log: int


class SaeadSession:
    """Client-side (server-role) saead session over one BLE connection.

    The downlink session is created by us (the server); the uplink session
    is adopted from the device's uplink pouch header.
    """

    def __init__(
        self,
        server_private: ec.EllipticCurvePrivateKey,
        device_public: ec.EllipticCurvePublicKey,
        server_cert_ref: bytes,
        algorithm: int = ALG_CHACHA20_POLY1305,
        max_block_size_log: int = 9,
    ):
        self._server_private = server_private
        self._device_public = device_public
        self._cert_ref = server_cert_ref[:CERT_REF_LEN].ljust(CERT_REF_LEN, b"\x00")
        self._algorithm = algorithm
        self._block_log = max_block_size_log
        self._down: _SessionState | None = None
        self._up: _SessionState | None = None

    # -- downlink (client -> device), we are the initiator/server -------------

    def new_downlink(self, session_id: bytes, pouch_id: int = 0) -> pouch.SessionInfo:
        """Start a fresh server-initiated downlink session, returning the
        SessionInfo to place in the pouch header."""
        assert len(session_id) == SESSION_ID_LEN
        key = derive_session_key(
            self._server_private, self._device_public, session_id,
            ROLE_SERVER, self._algorithm, self._block_log,
        )
        self._down = _SessionState(key, self._algorithm, session_id, ROLE_SERVER, self._block_log)
        return pouch.SessionInfo(
            session_id=session_id,
            initiator=ROLE_SERVER,
            algorithm=self._algorithm,
            max_block_size_log=self._block_log,
            cert_ref=self._cert_ref,
        )

    def encrypt_downlink_block(self, plaintext: bytes, block_index: int, pouch_id: int,
                               prev_tag: bytes) -> tuple[bytes, bytes]:
        """Seal one downlink block. `plaintext` is the block-id byte followed
        by its entry bytes. Returns (ciphertext_with_tag, this_tag)."""
        assert self._down is not None
        nonce = _nonce(pouch_id, block_index, ROLE_SERVER)
        aad = prev_tag if block_index > 0 else b""
        sealed = _aead(self._down.algorithm, self._down.key).encrypt(nonce, plaintext, aad)
        return sealed, sealed[-AUTH_TAG_LEN:]

    # -- uplink (device -> client), device is the initiator -------------------

    def adopt_uplink(self, info: pouch.SessionInfo) -> None:
        """Derive the uplink key from the device's uplink pouch header."""
        if info.initiator != ROLE_DEVICE:
            raise ValueError("uplink header initiator is not the device")
        key = derive_session_key(
            self._server_private, self._device_public, info.session_id,
            ROLE_DEVICE, info.algorithm, info.max_block_size_log,
        )
        self._up = _SessionState(key, info.algorithm, info.session_id, ROLE_DEVICE,
                                 info.max_block_size_log)

    def decrypt_uplink_block(self, ciphertext: bytes, block_index: int, pouch_id: int,
                             prev_tag: bytes) -> tuple[bytes, bytes]:
        """Open one uplink block. Returns (plaintext, this_tag)."""
        assert self._up is not None
        nonce = _nonce(pouch_id, block_index, ROLE_DEVICE)
        aad = prev_tag if block_index > 0 else b""
        plaintext = _aead(self._up.algorithm, self._up.key).decrypt(nonce, ciphertext, aad)
        return plaintext, ciphertext[-AUTH_TAG_LEN:]


def build_downlink_pouch(session: SaeadSession, session_id: bytes, entries: list[pouch.Entry],
                         pouch_id: int = 0, block_size: int = 512) -> bytes:
    """Encode an encrypted downlink pouch carrying `entries`.

    Entries are packed into entry blocks (id byte 0xC0 = first+last) whose
    plaintext is sealed per :meth:`SaeadSession.encrypt_downlink_block`.
    """
    info = session.new_downlink(session_id, pouch_id)
    header = pouch.PouchHeader(pouch.ENCRYPTION_SAEAD, session=info, pouch_id=pouch_id)

    # Pack entries into plaintext blocks (block-id byte + entries), same
    # rule as the plaintext path: an entry never spans a block.
    plaintext_blocks: list[bytes] = []
    current = b""
    for entry in entries:
        encoded = entry.encode()
        if current and len(current) + len(encoded) > block_size:
            plaintext_blocks.append(current)
            current = b""
        current += encoded
    plaintext_blocks.append(current)

    out = header.encode()
    prev_tag = b""
    for i, payload in enumerate(plaintext_blocks):
        first = i == 0
        last = i == len(plaintext_blocks) - 1
        id_byte = pouch.BLOCK_ID_ENTRY
        if first:
            id_byte |= pouch.BLOCK_FIRST
        if last:
            id_byte |= pouch.BLOCK_LAST
        block_plaintext = bytes([id_byte]) + payload
        sealed, prev_tag = session.encrypt_downlink_block(block_plaintext, i, pouch_id, prev_tag)
        out += struct.pack(">H", len(sealed)) + sealed
    return out


def parse_uplink_pouch(session: SaeadSession, data: bytes) -> list[pouch.Entry]:
    """Decode an encrypted uplink pouch into its entries."""
    header, consumed = pouch.PouchHeader.decode(data)
    if header.encryption != pouch.ENCRYPTION_SAEAD or header.session is None:
        raise pouch.PouchDecodeError("uplink pouch is not saead")
    session.adopt_uplink(header.session)

    payloads: list[bytes] = []
    pos = consumed
    block_index = 0
    prev_tag = b""
    while pos < len(data):
        (size,) = struct.unpack_from(">H", data, pos)
        pos += 2
        sealed = data[pos : pos + size]
        pos += size
        plaintext, prev_tag = session.decrypt_uplink_block(
            sealed, block_index, header.pouch_id, prev_tag
        )
        block_index += 1
        # plaintext = block-id byte + entry bytes
        if plaintext and (plaintext[0] & pouch.BLOCK_ID_MASK) == pouch.BLOCK_ID_ENTRY:
            payloads.append(plaintext[1:])
    return pouch.parse_entry_blocks(payloads)
