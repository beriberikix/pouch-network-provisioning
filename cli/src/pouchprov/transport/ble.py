# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""BLE transport: pouch GATT service via bleak.

UUIDs from pouch port/zephyr/transport/gatt/common.h. The device is the
GATT server; requests are written without response to the downlink
characteristic and its ACKs arrive as notifications on the same
characteristic (mirrored for uplink).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

from .base import Channel, Transport

logger = logging.getLogger(__name__)

SVC_UUID16 = 0xFC49
SVC_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d272"
UPLINK_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d273"
DOWNLINK_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d274"
INFO_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d275"
SERVER_CERT_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d276"  # saead builds only
DEVICE_CERT_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d277"  # saead builds only

ADV_FLAG_SYNC_REQUEST = 1 << 0
ADV_FLAG_PROVISIONING = 1 << 1

# bleak represents 16-bit service-data UUIDs in canonical 128-bit form.
SVC_DATA_KEY = "0000fc49-0000-1000-8000-00805f9b34fb"


def _looks_like_address(target: str) -> bool:
    """A macOS CoreBluetooth UUID or a colon MAC address, vs a device name."""
    return len(target) == 36 and target.count("-") == 4 or target.count(":") == 5


@dataclass
class Discovered:
    name: str
    address: str
    rssi: int
    provisioning: bool
    pouch_version: int
    gatt_version: int


async def discover(timeout: float = 5.0, provisioning_only: bool = True) -> list[Discovered]:
    """Scan for pouch devices advertising the provisioning flag."""
    found: dict[str, Discovered] = {}

    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for device, adv in devices.values():
        svc_data = adv.service_data.get(SVC_DATA_KEY)
        if svc_data is None or len(svc_data) < 2:
            continue
        version, flags = svc_data[0], svc_data[1]
        prov = bool(flags & ADV_FLAG_PROVISIONING)
        if provisioning_only and not prov:
            continue
        found[device.address] = Discovered(
            name=device.name or adv.local_name or "?",
            address=device.address,
            rssi=adv.rssi if adv.rssi is not None else 0,
            provisioning=prov,
            pouch_version=version >> 4,
            gatt_version=version & 0x0F,
        )

    return sorted(found.values(), key=lambda d: -d.rssi)


class _BleChannel(Channel):
    def __init__(self, client_ref: Callable[[], BleakClient], uuid: str):
        self._client_ref = client_ref
        self._uuid = uuid

    async def write(self, data: bytes) -> None:
        # Write WITH response: pouch's characteristics require an encrypted
        # (LESC) link for writes. The device sends an SMP Security Request on
        # connect, so pairing runs concurrently and takes a few seconds; until
        # it completes, writes fail with "Insufficient Encryption". Retry
        # through that window (it only occurs before the link is encrypted, so
        # retrying can never duplicate an accepted write).
        deadline = asyncio.get_running_loop().time() + 12.0
        while True:
            try:
                await self._client_ref().write_gatt_char(self._uuid, data, response=True)
                return
            except BleakError as exc:
                if "Encryption" not in str(exc) or asyncio.get_running_loop().time() > deadline:
                    raise
                await asyncio.sleep(0.4)

    async def subscribe(self, cb) -> None:
        await self._client_ref().start_notify(self._uuid, lambda _h, d: cb(bytes(d)))

    async def unsubscribe(self) -> None:
        try:
            await self._client_ref().stop_notify(self._uuid)
        except Exception as exc:  # device may have dropped; session layer handles it
            logger.debug("stop_notify: %s", exc)


class BleTransport(Transport):
    def __init__(self, address_or_name: str | None = None, timeout: float = 15.0):
        """Target a device by address/name, or pass None to auto-select the
        nearest device advertising the provisioning flag."""
        self._target = address_or_name
        self._timeout = timeout
        self._client: BleakClient | None = None
        self.downlink = _BleChannel(self._get_client, DOWNLINK_UUID)
        self.uplink = _BleChannel(self._get_client, UPLINK_UUID)
        # Populated after connect when the device is a saead build.
        self.info = None
        self.server_cert = None
        self.device_cert = None

    def _get_client(self) -> BleakClient:
        if self._client is None:
            raise RuntimeError("not connected")
        return self._client

    @property
    def att_payload(self) -> int:
        """Max write-without-response payload (ATT MTU - 3)."""
        return self._get_client().mtu_size - 3

    async def connect(self) -> None:
        target: str | object = self._target
        # Resolve to a concrete device object via a scan. macOS reports the
        # GAP device name (not the advertised name) and rotates the address
        # per boot, so matching on the provisioning service data is the only
        # reliable path. Auto-select when no target is given.
        if self._target is None or not _looks_like_address(self._target):
            device = await self._scan_for(self._target)
            if device is None:
                what = f"named {self._target!r}" if self._target else "in provisioning mode"
                raise ConnectionError(f"no device {what} found")
            target = device
        self._client = BleakClient(target, timeout=self._timeout)
        await self._client.connect()
        logger.info("connected, MTU %d", self._client.mtu_size)
        # saead builds expose server-cert/device-cert SAR endpoints; their
        # presence is the autodetection signal (compile-time firmware choice).
        if self._client.services.get_characteristic(SERVER_CERT_UUID) is not None:
            self.info = _BleChannel(self._get_client, INFO_UUID)
            self.server_cert = _BleChannel(self._get_client, SERVER_CERT_UUID)
            self.device_cert = _BleChannel(self._get_client, DEVICE_CERT_UUID)
            logger.info("device is a saead build")
        # The device sends an SMP Security Request on connect; let pairing
        # settle before any session I/O so the first writes land on an already
        # encrypted link (racing GATT traffic against pairing destabilises the
        # connection on macOS). Prime encryption with a retrying dummy write to
        # the downlink CCC path via a short settle.
        await self._await_encryption()

    async def _await_encryption(self, settle: float = 6.0) -> None:
        """Give the device-initiated pairing time to complete."""
        await asyncio.sleep(settle)
        if not self._get_client().is_connected:
            raise ConnectionError("link dropped during pairing")

    async def _scan_for(self, name: str | None):
        """Return the BLEDevice for `name`, or the strongest provisioning
        device when name is None."""
        best = None
        best_rssi = -999
        devices = await BleakScanner.discover(timeout=self._timeout, return_adv=True)
        for device, adv in devices.values():
            svc = adv.service_data.get(SVC_DATA_KEY)
            if svc is None or len(svc) < 2 or not (svc[1] & ADV_FLAG_PROVISIONING):
                continue
            if name is not None and name not in (device.name, adv.local_name):
                continue
            rssi = adv.rssi if adv.rssi is not None else -999
            if rssi > best_rssi:
                best, best_rssi = device, rssi
        return best

    async def disconnect(self) -> None:
        if self._client is not None:
            await asyncio.shield(self._client.disconnect())
            self._client = None
