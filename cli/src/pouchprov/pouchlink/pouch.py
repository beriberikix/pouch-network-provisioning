# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Pouch wire framing: header, blocks and entries.

Formats mirror the pouch reference implementation
(github.com/golioth/pouch: src/header.cddl, src/block.c, src/entry.c).

Block:
    0..1  size (be16, excluding the size field itself)
    2     id byte: low 5 bits stream id (0 = entry block),
          0x40 = first, 0x80 = last
    3..   payload

Entry (within an entry block):
    0..1  data_len (be16)
    2..3  content_type (be16, IANA CoAP content format)
    4     path_len
    5..   path, then data
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field

import cbor2

POUCH_VERSION = 1

CONTENT_TYPE_OCTET_STREAM = 42
CONTENT_TYPE_JSON = 50
CONTENT_TYPE_CBOR = 60

BLOCK_ID_ENTRY = 0x00
BLOCK_ID_MASK = 0x1F
BLOCK_FIRST = 0x40
BLOCK_LAST = 0x80
BLOCK_HEADER_SIZE = 3

ENTRY_HEADER_OVERHEAD = 5

ENCRYPTION_NONE = 0
ENCRYPTION_SAEAD = 1

ROLE_DEVICE = 0
ROLE_SERVER = 1

ALG_CHACHA20_POLY1305 = 1
ALG_AES_GCM = 2


class PouchDecodeError(Exception):
    """Malformed pouch frame."""


@dataclass
class Entry:
    path: str
    content_type: int
    data: bytes

    def encode(self) -> bytes:
        path_bytes = self.path.encode()
        if len(path_bytes) > 255:
            raise ValueError("path too long")
        return (
            struct.pack(">HHB", len(self.data), self.content_type, len(path_bytes))
            + path_bytes
            + self.data
        )


@dataclass
class SessionInfo:
    """saead session parameters carried in the pouch header."""

    session_id: bytes  # 16 bytes random, or 8-byte tag + seq for sequential
    initiator: int  # ROLE_DEVICE / ROLE_SERVER
    algorithm: int  # ALG_CHACHA20_POLY1305 / ALG_AES_GCM
    max_block_size_log: int
    cert_ref: bytes  # 6-byte server certificate serial reference
    sequential_seq: int | None = None  # set for sequential session ids

    def to_cbor_obj(self) -> list:
        if self.sequential_seq is not None:
            sid = [self.session_id, self.sequential_seq]
        else:
            sid = [self.session_id]
        return [sid, self.initiator, self.algorithm, self.max_block_size_log, self.cert_ref]

    @classmethod
    def from_cbor_obj(cls, obj: list) -> "SessionInfo":
        sid, initiator, algorithm, mbsl, cert_ref = obj
        if len(sid) == 2:
            return cls(bytes(sid[0]), initiator, algorithm, mbsl, bytes(cert_ref), int(sid[1]))
        return cls(bytes(sid[0]), initiator, algorithm, mbsl, bytes(cert_ref))


@dataclass
class PouchHeader:
    """Pouch header per src/header.cddl.

    Plaintext: [1, [0, device_id]]
    saead:     [1, [1, session_info, pouch_id]]
    """

    encryption: int = ENCRYPTION_NONE
    device_id: str | None = None
    session: SessionInfo | None = None
    pouch_id: int = 0

    def encode(self) -> bytes:
        if self.encryption == ENCRYPTION_NONE:
            if self.device_id is None:
                raise ValueError("plaintext header requires device_id")
            info: list = [ENCRYPTION_NONE, self.device_id]
        else:
            if self.session is None:
                raise ValueError("saead header requires session info")
            info = [ENCRYPTION_SAEAD, self.session.to_cbor_obj(), self.pouch_id]
        return cbor2.dumps([POUCH_VERSION, info])

    @classmethod
    def decode(cls, data: bytes) -> tuple["PouchHeader", int]:
        """Decode a header from the start of ``data``.

        Returns the header and the number of bytes consumed.
        """
        try:
            fp = io.BytesIO(data)
            obj = cbor2.CBORDecoder(fp).decode()
            consumed = fp.tell()
        except Exception as exc:  # cbor2 raises various error types
            raise PouchDecodeError(f"bad pouch header: {exc}") from exc
        if not isinstance(obj, list) or len(obj) != 2:
            raise PouchDecodeError("pouch header is not a 2-element array")
        version, info = obj
        if version != POUCH_VERSION:
            raise PouchDecodeError(f"unsupported pouch version {version}")
        if not isinstance(info, list) or not info:
            raise PouchDecodeError("bad encryption info")
        if info[0] == ENCRYPTION_NONE:
            return cls(ENCRYPTION_NONE, device_id=info[1]), consumed
        if info[0] == ENCRYPTION_SAEAD:
            return (
                cls(
                    ENCRYPTION_SAEAD,
                    session=SessionInfo.from_cbor_obj(info[1]),
                    pouch_id=info[2],
                ),
                consumed,
            )
        raise PouchDecodeError(f"unknown encryption type {info[0]}")


@dataclass
class Block:
    payload: bytes
    stream_id: int = BLOCK_ID_ENTRY
    first: bool = True
    last: bool = True

    def encode(self) -> bytes:
        id_byte = (self.stream_id & BLOCK_ID_MASK)
        if self.first:
            id_byte |= BLOCK_FIRST
        if self.last:
            id_byte |= BLOCK_LAST
        # size excludes the 2-byte size field but includes the id byte
        return struct.pack(">HB", len(self.payload) + 1, id_byte) + self.payload


@dataclass
class Pouch:
    header: PouchHeader
    blocks: list[Block] = field(default_factory=list)

    def encode(self) -> bytes:
        return self.header.encode() + b"".join(b.encode() for b in self.blocks)


def build_entry_pouch(device_id: str, entries: list[Entry], block_size: int = 512) -> bytes:
    """Build a plaintext (encryption-none) pouch carrying ``entries``.

    Entries are packed into entry blocks of at most ``block_size`` payload
    bytes; an entry never spans blocks (pouch src/entry.c contract).
    """
    blocks: list[Block] = []
    current = b""
    for entry in entries:
        encoded = entry.encode()
        if len(encoded) > block_size:
            raise ValueError(f"entry for {entry.path!r} exceeds block size {block_size}")
        if current and len(current) + len(encoded) > block_size:
            blocks.append(Block(current, first=not blocks, last=False))
            current = b""
        current += encoded
    blocks.append(Block(current, first=not blocks, last=True))
    return Pouch(PouchHeader(ENCRYPTION_NONE, device_id=device_id), blocks).encode()


def parse_entry_blocks(payloads: list[bytes]) -> list[Entry]:
    """Parse entries out of concatenated entry-block payloads."""
    entries: list[Entry] = []
    data = b"".join(payloads)
    pos = 0
    while pos < len(data):
        if len(data) - pos < ENTRY_HEADER_OVERHEAD:
            raise PouchDecodeError("truncated entry header")
        data_len, content_type, path_len = struct.unpack_from(">HHB", data, pos)
        pos += ENTRY_HEADER_OVERHEAD
        if len(data) - pos < path_len + data_len:
            raise PouchDecodeError("truncated entry")
        path = data[pos : pos + path_len].decode()
        pos += path_len
        payload = data[pos : pos + data_len]
        pos += data_len
        entries.append(Entry(path, content_type, bytes(payload)))
    return entries


def parse_pouch(data: bytes) -> tuple[PouchHeader, list[Entry]]:
    """Parse a plaintext pouch into its header and entries.

    saead pouches must have their blocks decrypted first; use
    :func:`split_blocks` and the saead session for that.
    """
    header, consumed = PouchHeader.decode(data)
    raw_blocks = split_blocks(data[consumed:])
    if header.encryption != ENCRYPTION_NONE:
        raise PouchDecodeError("encrypted pouch passed to parse_pouch")
    payloads = []
    for stream_id, _first, _last, payload in raw_blocks:
        if stream_id != BLOCK_ID_ENTRY:
            continue  # streams are out of scope for provisioning
        payloads.append(payload)
    return header, parse_entry_blocks(payloads)


def split_blocks(data: bytes) -> list[tuple[int, bool, bool, bytes]]:
    """Split the block section into (stream_id, first, last, payload) tuples."""
    blocks = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < BLOCK_HEADER_SIZE:
            raise PouchDecodeError("truncated block header")
        size = struct.unpack_from(">H", data, pos)[0]
        id_byte = data[pos + 2]
        payload_len = size - 1  # size includes the id byte
        pos += BLOCK_HEADER_SIZE
        if payload_len < 0 or len(data) - pos < payload_len:
            raise PouchDecodeError("truncated block payload")
        blocks.append(
            (
                id_byte & BLOCK_ID_MASK,
                bool(id_byte & BLOCK_FIRST),
                bool(id_byte & BLOCK_LAST),
                bytes(data[pos : pos + payload_len]),
            )
        )
        pos += payload_len
    return blocks
