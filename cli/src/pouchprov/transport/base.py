# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Transport abstraction.

A provisioning transport exposes the pouch uplink and downlink
characteristics as :class:`Channel` objects. A channel supports
write-without-response toward the device and a subscribe/unsubscribe
cycle delivering notifications; one subscribe == one SAR transaction
(pouch CCC semantics).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable


class Channel(ABC):
    @abstractmethod
    async def write(self, data: bytes) -> None:
        """Write without response toward the device."""

    @abstractmethod
    async def subscribe(self, cb: Callable[[bytes], None]) -> None:
        """Enable notifications; the device side opens its SAR endpoint."""

    @abstractmethod
    async def unsubscribe(self) -> None:
        """Disable notifications; the device side closes its SAR endpoint."""


class Transport(ABC):
    downlink: Channel  # client -> device requests
    uplink: Channel  # device -> client responses

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    async def __aenter__(self) -> "Transport":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()
