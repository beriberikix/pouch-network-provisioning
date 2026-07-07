# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Provisioning RPC session over a pouch transport.

Implements the client-driven RPC cycle (docs/protocol.md):
request = subscribe downlink -> SAR-send one pouch -> unsubscribe;
response = subscribe uplink -> SAR-receive one pouch -> unsubscribe.
An empty response pouch means "not ready, retry".
"""

from __future__ import annotations

import asyncio
import logging

import secrets

from .pouchlink import pouch
from .pouchlink.saead import SaeadSession, build_downlink_pouch, parse_uplink_pouch
from .pouchlink.sar import SarReceiver, SarSender
from .transport.base import Transport

logger = logging.getLogger(__name__)

# ATT MTU 247 => 244-byte payloads on write-without-response / notification.
DEFAULT_MAXLEN = 244


class SessionError(Exception):
    pass


class ProvSession:
    """Lockstep request/response engine. One request pouch at a time."""

    def __init__(self, transport: Transport, device_id: str = "", maxlen: int = DEFAULT_MAXLEN,
                 saead: SaeadSession | None = None):
        self._transport = transport
        self._maxlen = maxlen
        self._lock = asyncio.Lock()
        self._saead = saead  # when set, downlink is encrypted / uplink decrypted
        self.device_id = device_id  # from the plaintext response header
        self.block_size = 512  # updated from .prov/ver

    def enable_encryption(self, saead: SaeadSession) -> None:
        """Switch the session to encrypted (saead) framing."""
        self._saead = saead

    async def request_entries(
        self,
        entries: list[pouch.Entry],
        timeout: float = 15.0,
        poll_attempts: int = 5,
    ) -> list[pouch.Entry]:
        """Send request entries in one pouch, return the response entries."""
        async with self._lock:
            await self._send_pouch(entries, timeout)

            backoff = 0.2
            for _ in range(poll_attempts):
                header, rsp = await self._receive_pouch(timeout)
                self.device_id = header.device_id or self.device_id
                if rsp:
                    return rsp
                # Empty pouch: responses were not ready; back off and re-poll.
                logger.debug("empty response pouch; retrying in %.1fs", backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 2.0)

        raise SessionError("no response after retries")

    async def request(self, path: str, msg: bytes, timeout: float = 15.0) -> bytes:
        """Single-entry convenience: request `msg` on `path`."""
        entries = await self.request_entries(
            [pouch.Entry(path, pouch.CONTENT_TYPE_CBOR, msg)], timeout
        )
        for entry in entries:
            if entry.path == path:
                return entry.data
        raise SessionError(f"no response entry for {path}")

    async def _send_pouch(self, entries: list[pouch.Entry], timeout: float) -> None:
        # The CLI is the pouch "server" writing a downlink pouch.
        if self._saead is not None:
            data = build_downlink_pouch(self._saead, secrets.token_bytes(16), entries,
                                        block_size=self.block_size)
        else:
            data = pouch.build_entry_pouch(self.device_id or "?", entries,
                                           block_size=self.block_size)
        ch = self._transport.downlink
        sender = SarSender(ch.write, self._maxlen)
        await ch.subscribe(sender.feed)
        try:
            await sender.send(data, timeout)
        finally:
            await ch.unsubscribe()

    async def _receive_pouch(self, timeout: float) -> tuple[pouch.PouchHeader, list[pouch.Entry]]:
        ch = self._transport.uplink
        receiver = SarReceiver(ch.write)
        await ch.subscribe(receiver.feed)
        try:
            data = await receiver.receive(timeout)
        finally:
            await ch.unsubscribe()
        header, _ = pouch.PouchHeader.decode(data)
        if self._saead is not None and header.encryption == pouch.ENCRYPTION_SAEAD:
            # An empty uplink pouch (header only) still parses to no entries.
            if len(data) > len(header.encode()):
                return header, parse_uplink_pouch(self._saead, data)
            return header, []
        return pouch.parse_pouch(data)
