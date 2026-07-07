# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""pouchprov command-line interface."""

from __future__ import annotations

import asyncio
import logging

import click

from . import codec, flows
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


@cli.command("wifi-scan")
@click.option("--name", "-n", default=None, help="Device name/address (default: auto-select).")
@click.option("--pop", default=None, help="Proof-of-possession secret.")
def wifi_scan(name: str | None, pop: str | None) -> None:
    """Scan for Wi-Fi networks visible to the device."""

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = ProvSession(transport, maxlen=transport.att_payload)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)
            for e in await flows.scan(session):
                click.echo(f"{e.ssid.decode(errors='replace'):<32} "
                           f"ch={e.channel:<3} rssi={e.rssi:<4} auth={e.auth}")

    asyncio.run(run())


@cli.command()
@click.option("--name", "-n", default=None, help="Device name/address (default: auto-select).")
@click.option("--pop", default=None, help="Proof-of-possession secret.")
@click.option("--ssid", required=True, help="Wi-Fi SSID to provision.")
@click.option("--password", default=None, help="Wi-Fi passphrase (omit for open networks).")
@click.option("--cert", type=click.Path(exists=True), default=None,
              help="Device certificate (PEM or DER) to bootstrap.")
@click.option("--key", type=click.Path(exists=True), default=None,
              help="Device private key (PEM or DER) to bootstrap.")
@click.option("--ca", type=click.Path(exists=True), default=None,
              help="CA certificate (PEM or DER) to bootstrap.")
def provision(name: str | None, pop: str | None, ssid: str, password: str | None,
              cert: str | None, key: str | None, ca: str | None) -> None:
    """Provision Wi-Fi credentials (and optionally cloud certificates)."""
    from pathlib import Path

    from .pouchlink import cert as certmod

    if bool(cert) ^ bool(key):
        raise click.UsageError("--cert and --key must be provided together")

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = ProvSession(transport, maxlen=transport.att_payload)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)

            if cert:
                await flows.bootstrap_credentials(
                    session,
                    certmod.pem_to_der(Path(cert).read_bytes()),
                    certmod.pem_to_der(Path(key).read_bytes()),
                    certmod.pem_to_der(Path(ca).read_bytes()) if ca else None,
                )
                click.echo("cloud credentials stored")

            status = await flows.configure_wifi(
                session, ssid.encode(), password.encode() if password else None
            )
            if status.state == codec.StaState.CONNECTED:
                ip = ".".join(str(b) for b in status.ip4) if status.ip4 else "?"
                click.echo(f"connected: {status.ssid.decode(errors='replace')} ({ip})")
                await flows.end_session(session)
            else:
                reason = status.fail_reason.name if status.fail_reason is not None else "unknown"
                raise SystemExit(f"provisioning failed: {reason}")

    asyncio.run(run())


if __name__ == "__main__":
    cli()
