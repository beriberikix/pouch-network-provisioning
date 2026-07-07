# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Pouch framing codec vs golden vectors and round-trips."""

import json
from pathlib import Path

import pytest

from pouchprov import codec
from pouchprov.pouchlink import pouch

FRAMES = {
    k: bytes.fromhex(v)
    for k, v in json.loads(
        (Path(__file__).parent.parent.parent / "tests" / "vectors" / "pouch_frames.json").read_text()
    ).items()
}


def test_single_entry_vector():
    built = pouch.build_entry_pouch(
        "dev-1", [pouch.Entry(codec.PATH_VER, pouch.CONTENT_TYPE_CBOR, codec.encode_ver_req())]
    )
    assert built == FRAMES["single_entry"]


def test_parse_single_entry():
    header, entries = pouch.parse_pouch(FRAMES["single_entry"])
    assert header.encryption == pouch.ENCRYPTION_NONE
    assert header.device_id == "dev-1"
    assert len(entries) == 1
    assert entries[0].path == codec.PATH_VER
    assert entries[0].content_type == pouch.CONTENT_TYPE_CBOR
    assert entries[0].data == codec.encode_ver_req()


def test_two_entries_share_block():
    header, entries = pouch.parse_pouch(FRAMES["two_entries_one_block"])
    assert [e.path for e in entries] == [codec.PATH_CONFIG, codec.PATH_CONFIG]
    raw = FRAMES["two_entries_one_block"]
    _, consumed = pouch.PouchHeader.decode(raw)
    blocks = pouch.split_blocks(raw[consumed:])
    assert len(blocks) == 1
    assert blocks[0][1] and blocks[0][2]  # first and last


def test_multiblock_flags():
    raw = FRAMES["two_blocks"]
    _, consumed = pouch.PouchHeader.decode(raw)
    blocks = pouch.split_blocks(raw[consumed:])
    assert len(blocks) == 2
    assert blocks[0][1] and not blocks[0][2]  # first, not last
    assert not blocks[1][1] and blocks[1][2]  # last, not first
    _, entries = pouch.parse_pouch(raw)
    assert len(entries) == 2


def test_empty_pouch():
    header, entries = pouch.parse_pouch(FRAMES["empty"])
    assert header.device_id == "dev-1"
    assert entries == []


def test_entry_too_big_rejected():
    with pytest.raises(ValueError):
        pouch.build_entry_pouch(
            "dev-1",
            [pouch.Entry(codec.PATH_CRED, pouch.CONTENT_TYPE_CBOR, bytes(600))],
            block_size=512,
        )


def test_round_trip_saead_header():
    session = pouch.SessionInfo(
        session_id=bytes(range(16)),
        initiator=pouch.ROLE_SERVER,
        algorithm=pouch.ALG_CHACHA20_POLY1305,
        max_block_size_log=9,
        cert_ref=bytes(6),
    )
    hdr = pouch.PouchHeader(pouch.ENCRYPTION_SAEAD, session=session, pouch_id=3)
    decoded, consumed = pouch.PouchHeader.decode(hdr.encode())
    assert consumed == len(hdr.encode())
    assert decoded.pouch_id == 3
    assert decoded.session.session_id == bytes(range(16))
    assert decoded.session.initiator == pouch.ROLE_SERVER
    assert decoded.session.sequential_seq is None


def test_truncated_frames_rejected():
    raw = FRAMES["single_entry"]
    with pytest.raises(pouch.PouchDecodeError):
        pouch.parse_pouch(raw[:-3])
