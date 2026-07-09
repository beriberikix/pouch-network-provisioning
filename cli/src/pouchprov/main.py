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


async def _open_session(transport, state_dir_opt: str | None = None) -> ProvSession:
    """Open a ProvSession, autodetecting the firmware's encryption mode: on a
    saead build, run the TOFU cert exchange and switch to encrypted framing."""
    session = ProvSession(transport, maxlen=transport.att_payload)
    if transport.supports_saead:
        from . import state, tofu

        identity = tofu.load_or_create_server_identity(state.state_dir(state_dir_opt))
        await tofu.secure_session(transport, session, identity)
        click.echo("session: saead (ChaCha20-Poly1305)")
    else:
        click.echo("session: plaintext")
    return session


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
            session = await _open_session(transport)
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
            session = await _open_session(transport)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)
            for e in await flows.scan(session):
                click.echo(f"{e.ssid.decode(errors='replace'):<32} "
                           f"ch={e.channel:<3} rssi={e.rssi:<4} auth={e.auth_name}")

    asyncio.run(run())


@cli.command()
@click.argument("cn")
@click.option("--self-signed", "self_signed", is_flag=True,
              help="Generate a lone self-signed certificate instead of a demo-CA-signed one.")
@click.option("--validity-days", default=28, show_default=True,
              help="Certificate validity, in days from now.")
@click.option("--out", type=click.Path(file_okay=False), default=".", show_default=True,
              help="Directory to write the PEM files into.")
@click.option("--state-dir", "state_dir_opt", default=None,
              help="Client state directory (default: ~/.pouchprov).")
@click.option("--golioth-api-key", "golioth_api_key", default=None,
              help="Also register the demo CA with this Golioth project.")
def mint(cn: str, self_signed: bool, validity_days: int, out: str,
         state_dir_opt: str | None, golioth_api_key: str | None) -> None:
    """Mint device credentials offline with CN as the device ID.

    By default the device certificate is signed by a persistent local demo CA
    (created on first use in the state directory); --self-signed generates a
    standalone certificate instead. Mirrors the mobile apps' cert modes.
    """
    from pathlib import Path

    from . import state
    from .pouchlink import cert as certmod

    if self_signed and golioth_api_key:
        raise click.UsageError("--self-signed and --golioth-api-key are mutually exclusive")

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if self_signed:
        creds = certmod.generate_self_signed(cn, validity_days)
    else:
        ca = state.load_or_create_demo_ca(state.state_dir(state_dir_opt))
        creds = certmod.sign_device_cert(ca, cn, validity_days)
        ca_path = out_dir / "ca.crt.pem"
        ca_path.write_bytes(ca.cert_pem)
        click.echo(f"CA:   {ca_path}")
        if golioth_api_key:
            from .golioth import GoliothCertProvider

            provider = GoliothCertProvider(golioth_api_key)
            cert_id = provider.register_ca(ca.cert_pem)
            click.echo(f"demo CA registered with Golioth project "
                       f"{provider.project_id()} (cert id {cert_id or '?'})")

    cert_path = out_dir / f"{cn}.crt.pem"
    key_path = out_dir / f"{cn}.key.pem"
    cert_path.write_bytes(creds.cert_pem)
    key_path.write_bytes(creds.key_pem)
    click.echo(f"cert: {cert_path}")
    click.echo(f"key:  {key_path}")
    click.echo(f"CN={cn}, valid {validity_days} days"
               + (" (self-signed)" if self_signed else " (signed by demo CA)"))


@cli.command("cred-status")
@click.option("--name", "-n", default=None, help="Device name/address (default: auto-select).")
@click.option("--pop", default=None, help="Proof-of-possession secret.")
def cred_status(name: str | None, pop: str | None) -> None:
    """Show per-kind byte counts of credentials stored on the device."""

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = await _open_session(transport)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)
            status = await flows.cred_status(session)
            if not status:
                click.echo("no credentials received")
                return
            for kind, received in sorted(status.items()):
                click.echo(f"{kind.name:<12} {received} bytes")

    asyncio.run(run())


@cli.command()
@click.option("--name", "-n", default=None, help="Device name/address (default: auto-select).")
@click.option("--pop", default=None, help="Proof-of-possession secret.")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
def reset(name: str | None, pop: str | None, yes: bool) -> None:
    """Reset the device's Wi-Fi state machine (credentials are kept)."""
    if not yes:
        click.confirm("Reset the device's Wi-Fi state?", abort=True)

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = await _open_session(transport)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)
            await flows.reset(session)
            click.echo("Wi-Fi state reset")

    asyncio.run(run())


@cli.command()
@click.option("--name", "-n", default=None, help="Device name/address (default: auto-select).")
@click.option("--pop", default=None, help="Proof-of-possession secret.")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
def reprovision(name: str | None, pop: str | None, yes: bool) -> None:
    """Wipe stored Wi-Fi and cloud credentials (factory reset provisioning)."""
    if not yes:
        click.confirm("Wipe ALL stored Wi-Fi and cloud credentials?", abort=True)

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = await _open_session(transport)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)
            await flows.reprovision(session)
            click.echo("credentials wiped — device is ready to re-provision")

    asyncio.run(run())


@cli.command()
@click.option("--name", "-n", default=None, help="Device name/address (default: auto-select).")
@click.option("--pop", default=None, help="Proof-of-possession secret.")
@click.option("--ssid", default=None,
              help="Wi-Fi SSID to provision (omit for a BLE-only, cred-only device).")
@click.option("--password", default=None, help="Wi-Fi passphrase (omit for open networks).")
@click.option("--cert", type=click.Path(exists=True), default=None,
              help="Device certificate (PEM or DER) to bootstrap.")
@click.option("--key", type=click.Path(exists=True), default=None,
              help="Device private key (PEM or DER) to bootstrap.")
@click.option("--ca", type=click.Path(exists=True), default=None,
              help="CA certificate (PEM or DER) to bootstrap.")
@click.option("--self-signed", "self_signed", is_flag=True,
              help="Mint a self-signed device certificate (CN = device id) on the fly.")
@click.option("--golioth-api-key", "golioth_api_key", default=None,
              help="Mint a demo-CA-signed device certificate and register the CA "
                   "with this Golioth project.")
@click.option("--validity-days", default=28, show_default=True,
              help="Validity for minted certificates, in days.")
@click.option("--state-dir", "state_dir_opt", default=None,
              help="Client state directory (default: ~/.pouchprov).")
def provision(name: str | None, pop: str | None, ssid: str | None, password: str | None,
              cert: str | None, key: str | None, ca: str | None, self_signed: bool,
              golioth_api_key: str | None, validity_days: int,
              state_dir_opt: str | None) -> None:
    """Provision cloud certificates and/or Wi-Fi credentials.

    Provide --ssid for a Wi-Fi device and/or credentials for cloud bootstrap:
    either your own --cert/--key files, or mint them on the fly with
    --self-signed / --golioth-api-key (CN = the device id, like the mobile
    apps). A BLE-only device is provisioned with certificates alone.
    """
    from pathlib import Path

    from .pouchlink import cert as certmod

    minting = self_signed or bool(golioth_api_key)
    if self_signed and golioth_api_key:
        raise click.UsageError("--self-signed and --golioth-api-key are mutually exclusive")
    if minting and (cert or key or ca):
        raise click.UsageError("minting options are mutually exclusive with --cert/--key/--ca")
    if bool(cert) ^ bool(key):
        raise click.UsageError("--cert and --key must be provided together")
    if not ssid and not cert and not minting:
        raise click.UsageError("provide --ssid and/or credentials (--cert/--key, "
                               "--self-signed or --golioth-api-key)")

    async def run() -> None:
        async with ble.BleTransport(name) as transport:
            session = await _open_session(transport, state_dir_opt)
            info = await flows.get_version(session)
            await flows.authorize_if_needed(session, info, pop)

            cert_der = key_der = ca_der = None
            if cert:
                cert_der = certmod.pem_to_der(Path(cert).read_bytes())
                key_der = certmod.pem_to_der(Path(key).read_bytes())
                ca_der = certmod.pem_to_der(Path(ca).read_bytes()) if ca else None
            elif minting:
                if "cred" not in info.caps:
                    raise SystemExit("device does not support credential provisioning")
                cn = session.device_id or "pouch-device"
                if golioth_api_key:
                    from .golioth import GoliothCertProvider

                    from . import state
                    demo_ca = state.load_or_create_demo_ca(state.state_dir(state_dir_opt))
                    provider = GoliothCertProvider(golioth_api_key, ca=demo_ca)
                    minted = provider.mint_device_credentials(cn, validity_days)
                    cert_der = certmod.pem_to_der(minted.cert_pem)
                    key_der = certmod.pem_to_der(minted.key_pem)
                    ca_der = certmod.pem_to_der(minted.ca_cert_pem)
                    click.echo(f"minted Golioth demo credentials (CN={cn}, "
                               f"valid {validity_days} days)")
                else:
                    minted_ss = certmod.generate_self_signed(cn, validity_days)
                    cert_der = certmod.pem_to_der(minted_ss.cert_pem)
                    key_der = certmod.pem_to_der(minted_ss.key_pem)
                    click.echo(f"minted self-signed credentials (CN={cn}, "
                               f"valid {validity_days} days)")

            if cert_der:
                await flows.bootstrap_credentials(session, cert_der, key_der, ca_der)
                received = await flows.cred_status(session)
                stored = ", ".join(f"{k.name}={v}B" for k, v in sorted(received.items()))
                click.echo(f"cloud credentials stored ({stored})")

            if ssid:
                if "wifi" not in info.caps:
                    raise SystemExit("device does not support Wi-Fi provisioning")
                status = await flows.configure_wifi(
                    session, ssid.encode(), password.encode() if password else None
                )
                if status.state == codec.StaState.CONNECTED:
                    ip = ".".join(str(b) for b in status.ip4) if status.ip4 else "?"
                    click.echo(f"connected: {status.ssid.decode(errors='replace')} ({ip})")
                else:
                    reason = (status.fail_reason.name
                              if status.fail_reason is not None else "unknown")
                    raise SystemExit(f"provisioning failed: {reason}")

            await flows.end_session(session)

    asyncio.run(run())


if __name__ == "__main__":
    cli()
