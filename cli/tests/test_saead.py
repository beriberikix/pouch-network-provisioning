# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""saead session crypto: ECDH symmetry, INFO string, nonce, AD chaining.

The device side is simulated in-test by deriving the mirror key
(ECDH(device_priv, server_pub) with the same INFO) and running the same
AEAD, so a passing round-trip proves the two independent derivations
agree — the property the real device relies on.
"""

import base64
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pouchprov import codec
from pouchprov.pouchlink import pouch, saead


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def _device_derive(device_priv, server_pub, session_id, initiator, algorithm, block_log):
    """Independent re-derivation, as the device firmware would do it."""
    shared = device_priv.exchange(ec.ECDH(), server_pub)
    info = "E0:{d}:{sid}:C{a}R:{log:02X}".format(
        d="D" if initiator == saead.ROLE_DEVICE else "S",
        sid=base64.b64encode(session_id).decode(),
        a="C" if algorithm == saead.ALG_CHACHA20_POLY1305 else "A",
        log=block_log,
    )
    return HKDF(algorithm=hashes.SHA256(),
               length=32 if algorithm == saead.ALG_CHACHA20_POLY1305 else 16,
               salt=None, info=info.encode()).derive(shared)


@pytest.mark.parametrize("algorithm", [saead.ALG_CHACHA20_POLY1305, saead.ALG_AES_GCM])
def test_ecdh_derivation_symmetric(algorithm):
    server_priv, server_pub = _keypair()
    device_priv, device_pub = _keypair()
    sid = bytes(range(16))

    server_key = saead.derive_session_key(
        server_priv, device_pub, sid, saead.ROLE_SERVER, algorithm, 9
    )
    device_key = _device_derive(device_priv, server_pub, sid, saead.ROLE_SERVER, algorithm, 9)
    assert server_key == device_key


@pytest.mark.parametrize("algorithm", [saead.ALG_CHACHA20_POLY1305, saead.ALG_AES_GCM])
def test_downlink_block_decryptable_by_device(algorithm):
    server_priv, server_pub = _keypair()
    device_priv, device_pub = _keypair()
    cert_ref = bytes(range(6))
    session = saead.SaeadSession(server_priv, device_pub, cert_ref, algorithm=algorithm)

    entries = [pouch.Entry(codec.PATH_VER, pouch.CONTENT_TYPE_CBOR, codec.encode_ver_req())]
    sid = bytes([7] * 16)
    wire = saead.build_downlink_pouch(session, sid, entries, pouch_id=0)

    # Device side: parse header, re-derive key, decrypt blocks.
    header, consumed = pouch.PouchHeader.decode(wire)
    assert header.encryption == pouch.ENCRYPTION_SAEAD
    assert header.session.initiator == saead.ROLE_SERVER
    assert header.session.cert_ref == cert_ref
    dev_key = _device_derive(device_priv, server_pub, header.session.session_id,
                             saead.ROLE_SERVER, algorithm, header.session.max_block_size_log)
    aead = (ChaCha20Poly1305(dev_key) if algorithm == saead.ALG_CHACHA20_POLY1305
            else AESGCM(dev_key))

    pos, idx, prev_tag, payloads = consumed, 0, b"", []
    while pos < len(wire):
        (size,) = struct.unpack_from(">H", wire, pos)
        pos += 2
        sealed = wire[pos:pos + size]
        pos += size
        nonce = struct.pack(">HHB", 0, idx, saead.ROLE_SERVER) + b"\x00" * 7
        plaintext = aead.decrypt(nonce, sealed, prev_tag if idx > 0 else b"")
        prev_tag = sealed[-16:]
        payloads.append(plaintext[1:])  # strip block-id byte
        idx += 1

    got = pouch.parse_entry_blocks(payloads)
    assert len(got) == 1 and got[0].path == codec.PATH_VER
    assert got[0].data == codec.encode_ver_req()


@pytest.mark.parametrize("algorithm", [saead.ALG_CHACHA20_POLY1305, saead.ALG_AES_GCM])
def test_uplink_round_trip(algorithm):
    """Device encrypts an uplink pouch; client adopts the header and decrypts."""
    server_priv, server_pub = _keypair()
    device_priv, device_pub = _keypair()
    session = saead.SaeadSession(server_priv, device_pub, bytes(6), algorithm=algorithm)

    # Device builds an uplink pouch (initiator = device).
    sid = bytes([3] * 16)
    dev_key = _device_derive(device_priv, server_pub, sid, saead.ROLE_DEVICE, algorithm, 9)
    aead = (ChaCha20Poly1305(dev_key) if algorithm == saead.ALG_CHACHA20_POLY1305
            else AESGCM(dev_key))
    info = pouch.SessionInfo(sid, saead.ROLE_DEVICE, algorithm, 9, bytes(6))
    header = pouch.PouchHeader(pouch.ENCRYPTION_SAEAD, session=info, pouch_id=5)

    rsp = pouch.Entry(
        codec.PATH_CTRL, pouch.CONTENT_TYPE_CBOR, codec.encode_ctrl(codec.CtrlOp.END))
    block_plain = bytes([pouch.BLOCK_ID_ENTRY | pouch.BLOCK_FIRST | pouch.BLOCK_LAST]) + rsp.encode()
    nonce = struct.pack(">HHB", 5, 0, saead.ROLE_DEVICE) + b"\x00" * 7
    sealed = aead.encrypt(nonce, block_plain, b"")
    wire = header.encode() + struct.pack(">H", len(sealed)) + sealed

    entries = saead.parse_uplink_pouch(session, wire)
    assert len(entries) == 1 and entries[0].path == codec.PATH_CTRL


def test_multiblock_ad_chaining():
    """AD chaining across >1 block must match between the two sides."""
    server_priv, server_pub = _keypair()
    device_priv, device_pub = _keypair()
    session = saead.SaeadSession(server_priv, device_pub, bytes(6),
                                 algorithm=saead.ALG_AES_GCM)

    # Two entries that cannot share a small block -> two blocks.
    entries = [
        pouch.Entry(codec.PATH_CRED, pouch.CONTENT_TYPE_CBOR,
                    codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 0, 40, bytes(20))),
        pouch.Entry(codec.PATH_CRED, pouch.CONTENT_TYPE_CBOR,
                    codec.encode_cred_write(codec.CredKind.DEVICE_CERT, 20, 40, bytes(20))),
    ]
    sid = bytes([9] * 16)
    wire = saead.build_downlink_pouch(session, sid, entries, pouch_id=1, block_size=64)

    header, consumed = pouch.PouchHeader.decode(wire)
    dev_key = _device_derive(device_priv, server_pub, sid, saead.ROLE_SERVER,
                             saead.ALG_AES_GCM, header.session.max_block_size_log)
    aead = AESGCM(dev_key)
    pos, idx, prev_tag, payloads = consumed, 0, b"", []
    while pos < len(wire):
        (size,) = struct.unpack_from(">H", wire, pos)
        pos += 2
        sealed = wire[pos:pos + size]
        pos += size
        nonce = struct.pack(">HHB", 1, idx, saead.ROLE_SERVER) + b"\x00" * 7
        payloads.append(aead.decrypt(nonce, sealed, prev_tag if idx > 0 else b"")[1:])
        prev_tag = sealed[-16:]
        idx += 1
    assert idx == 2  # two blocks
    got = pouch.parse_entry_blocks(payloads)
    assert len(got) == 2
