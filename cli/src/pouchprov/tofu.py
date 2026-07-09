# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""TOFU server-certificate exchange and saead session setup.

On saead firmware builds the pouch GATT service exposes three extra SAR
endpoints (raw payloads, not pouch-framed):

- ``info`` (device sender): CBOR ``{flags, server_cert_snr}`` — the X.509
  serial of the server certificate the device currently stores.
- ``server_cert`` (device receiver): the client SAR-writes its self-signed
  server certificate (DER) when the stored serial differs.
- ``device_cert`` (device sender): the device's self-signed identity
  certificate, collected trust-on-first-use.

The exchanged public keys drive the ECDH session-key derivation in
:mod:`pouchlink.saead`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .pouchlink import cert as certmod
from .pouchlink import saead
from .pouchlink.info import GattInfo
from .pouchlink.sar import SarReceiver, SarSender
from .session import ProvSession
from .transport.base import Channel, Transport

logger = logging.getLogger(__name__)

_IDENTITY_CERT = "server_identity.crt.pem"
_IDENTITY_KEY = "server_identity.key.pem"


def normalize_serial(serial: bytes) -> bytes:
    """Strip leading zero bytes: mbedtls keeps the DER sign byte, most big-int
    serializations do not. Normalized forms compare equal."""
    return serial.lstrip(b"\x00") or b"\x00"


def cert_serial(cert_der: bytes) -> bytes:
    """The X.509 serial number bytes of a DER certificate."""
    number = x509.load_der_x509_certificate(cert_der).serial_number
    length = (number.bit_length() + 7) // 8 or 1
    return number.to_bytes(length, "big")


def load_or_create_server_identity(directory: Path) -> certmod.Identity:
    """The persistent TOFU server identity presented to devices. Created on
    first use, then reused so devices keep trusting the same certificate."""
    cert_path, key_path = directory / _IDENTITY_CERT, directory / _IDENTITY_KEY
    if cert_path.exists() and key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert_der = certmod.pem_to_der(cert_path.read_bytes())
        return certmod.Identity(key, cert_der)
    identity = certmod.generate_server_identity()
    cert = x509.load_der_x509_certificate(identity.cert_der)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        identity.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    import os

    os.chmod(key_path, 0o600)
    return identity


async def sar_read(channel: Channel, timeout: float = 15.0) -> bytes:
    """One SAR receive cycle on a device-sender endpoint (info, device_cert)."""
    receiver = SarReceiver(channel.write)
    await channel.subscribe(receiver.feed)
    try:
        return await receiver.receive(timeout)
    finally:
        await channel.unsubscribe()


async def sar_write(channel: Channel, data: bytes, maxlen: int, timeout: float = 15.0) -> None:
    """One SAR send cycle on a device-receiver endpoint (server_cert)."""
    sender = SarSender(channel.write, maxlen)
    await channel.subscribe(sender.feed)
    try:
        await sender.send(data, timeout)
    finally:
        await channel.unsubscribe()


async def read_info(transport: Transport, timeout: float = 15.0) -> GattInfo:
    """Read the pouch GATT info endpoint (a SAR cycle, not a GATT read)."""
    assert transport.info is not None
    return GattInfo.decode(await sar_read(transport.info, timeout))


async def exchange_certs(transport: Transport, identity: certmod.Identity,
                         maxlen: int, timeout: float = 15.0) -> bytes:
    """Run the TOFU cert exchange; returns the device certificate (DER).

    Pushes our server certificate only when the device's stored serial
    differs from ours (or it has none)."""
    info = await read_info(transport, timeout)
    ours = normalize_serial(cert_serial(identity.cert_der))
    theirs = normalize_serial(info.server_cert_serial)
    if not info.has_server_cert or theirs != ours:
        assert transport.server_cert is not None
        logger.info("pushing server certificate (device has %s)",
                    "a different one" if info.has_server_cert else "none")
        await sar_write(transport.server_cert, identity.cert_der, maxlen, timeout)
    else:
        logger.debug("device already stores our server certificate")

    assert transport.device_cert is not None
    device_der = await sar_read(transport.device_cert, timeout)
    logger.info("device certificate fingerprint (TOFU): %s",
                certmod.cert_fingerprint(device_der))
    return device_der


async def secure_session(transport: Transport, session: ProvSession,
                         identity: certmod.Identity, timeout: float = 15.0) -> None:
    """TOFU exchange + switch `session` to encrypted (saead) framing."""
    device_der = await exchange_certs(transport, identity, session.maxlen, timeout)
    session.enable_encryption(
        saead.SaeadSession(
            identity.private_key,
            certmod.device_public_key(device_der),
            identity.cert_ref,
        )
    )
