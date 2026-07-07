# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""pouchprov command-line interface."""

from __future__ import annotations

import asyncio
import logging

import click

from . import codec
from .session import ProvSession
from .transport import ble


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Debug logging.")
def cli(verbose: bool) -> None:
    """Provision pouch devices over BLE."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")


@cli.command()
@click.option("--timeout", default=5.0, show_default=True)
@click.option("--all", "show_all", is_flag=True,
              help="Include pouch devices not in provisioning mode.")
def discover(timeout: float, show_all: bool) -> None:
    """Scan for provisioning-mode pouch devices."""

    async def run() -> None:
        devices = await ble.discover(timeout, provisioning_only=not show_all)
        if not devices:
            click.echo("no devices found")
            return
        for d in devices:
            flags = "provisioning" if d.provisioning else "pouch"
            click.echo(f"{d.name}  {d.address}  rssi={d.rssi}  [{flags}, "
                       f"pouch v{d.pouch_version}, gatt v{d.gatt_version}]")

    asyncio.run(run())


@cli.command()
@click.option("--name", "-n", default=None,
              help="Device name or address (default: auto-select provisioning device).")
def version(name: str | None) -> None:
    """Query .prov/ver on a device."""

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = ProvSession(transport, maxlen=transport.att_payload)
            info = codec.decode_ver_rsp(
                await session.request(codec.PATH_VER, codec.encode_ver_req())
            )
            session.block_size = info.block_size
            click.echo(f"device:   {session.device_id}")
            click.echo(f"protocol: v{info.proto}")
            click.echo(f"library:  {info.lib}")
            click.echo(f"caps:     {', '.join(info.caps)}")
            click.echo(f"block:    {info.block_size}")
            click.echo(f"pop:      {'required' if info.pop_required else 'not required'}")

    asyncio.run(run())


if __name__ == "__main__":
    cli()
