# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""High-level provisioning flows composed over a ProvSession."""

from __future__ import annotations

import asyncio
import logging

from . import auth, codec
from .session import ProvSession

logger = logging.getLogger(__name__)


async def get_version(session: ProvSession) -> codec.VersionInfo:
    info = codec.decode_ver_rsp(await session.request(codec.PATH_VER, codec.encode_ver_req()))
    if info.proto != codec.PROTO_VERSION:
        raise RuntimeError(f"unsupported device protocol v{info.proto}")
    session.block_size = info.block_size
    return info


async def authorize_if_needed(session: ProvSession, info: codec.VersionInfo, pop: str | None) -> None:
    if info.pop_required:
        if not pop:
            raise RuntimeError("device requires a proof-of-possession (--pop)")
        await auth.authorize(session, pop)
        logger.info("session authorized")


async def scan(session: ProvSession, timeout: float = 20.0) -> list[codec.ScanEntry]:
    """Trigger a scan, poll until finished, and collect all result pages."""
    codec.decode_scan_start_rsp(await session.request(codec.PATH_SCAN, codec.encode_scan_start()))

    deadline = asyncio.get_running_loop().time() + timeout
    total = 0
    while True:
        finished, total = codec.decode_scan_status_rsp(
            await session.request(codec.PATH_SCAN, codec.encode_scan_get_status())
        )
        if finished:
            break
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError("scan did not finish")
        await asyncio.sleep(0.5)

    results: list[codec.ScanEntry] = []
    while len(results) < total:
        page = codec.decode_scan_results_rsp(
            await session.request(codec.PATH_SCAN, codec.encode_scan_get_results(len(results), 6))
        )
        if not page:
            break
        results.extend(page)
    return results


async def configure_wifi(session: ProvSession, ssid: bytes, password: bytes | None,
                         timeout: float = 40.0) -> codec.WifiStatus:
    """Set + apply credentials, then poll status until connected or failed."""
    codec.decode_config_set_rsp(
        await session.request(codec.PATH_CONFIG, codec.encode_config_set(ssid, password))
    )
    codec.decode_config_apply_rsp(
        await session.request(codec.PATH_CONFIG, codec.encode_config_apply())
    )

    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        status = codec.decode_config_status_rsp(
            await session.request(codec.PATH_CONFIG, codec.encode_config_get_status())
        )
        if status.state in (codec.StaState.CONNECTED, codec.StaState.FAILED):
            return status
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError("connection did not settle")
        await asyncio.sleep(1.0)


async def push_credential(session: ProvSession, kind: codec.CredKind, der: bytes,
                          chunk: int = 256) -> None:
    """Write one DER credential to the device in ordered chunks."""
    total = len(der)
    off = 0
    while off < total:
        piece = der[off:off + chunk]
        received = codec.decode_cred_write_rsp(
            await session.request(
                codec.PATH_CRED, codec.encode_cred_write(kind, off, total, piece)
            )
        )
        off += len(piece)
        if received != off:
            raise RuntimeError(f"cred write desync: device has {received}, sent {off}")


async def bootstrap_credentials(session: ProvSession, cert_der: bytes, key_der: bytes,
                                ca_der: bytes | None = None) -> None:
    """Push device cert + key (+ optional CA), then finalize."""
    await push_credential(session, codec.CredKind.DEVICE_CERT, cert_der)
    await push_credential(session, codec.CredKind.PRIVATE_KEY, key_der)
    if ca_der is not None:
        await push_credential(session, codec.CredKind.CA_CERT, ca_der)
    codec.decode_cred_finalize_rsp(
        await session.request(codec.PATH_CRED, codec.encode_cred_finalize())
    )
    logger.info("cloud credentials stored")


async def cred_status(session: ProvSession) -> dict[codec.CredKind, int]:
    """Query per-kind byte counts of credentials the device has received."""
    return codec.decode_cred_status_rsp(
        await session.request(codec.PATH_CRED, codec.encode_cred_get_status())
    )


async def reset(session: ProvSession) -> None:
    """Reset the device's Wi-Fi state machine without wiping credentials."""
    codec.decode_ctrl_rsp(
        await session.request(codec.PATH_CTRL, codec.encode_ctrl(codec.CtrlOp.RESET)),
        codec.CtrlOp.RESET,
    )
    logger.info("device Wi-Fi state reset")


async def reprovision(session: ProvSession) -> None:
    """Wipe stored Wi-Fi and cloud credentials so the device can be re-provisioned."""
    codec.decode_ctrl_rsp(
        await session.request(codec.PATH_CTRL, codec.encode_ctrl(codec.CtrlOp.REPROVISION)),
        codec.CtrlOp.REPROVISION,
    )
    logger.info("device credentials wiped")


async def end_session(session: ProvSession) -> None:
    codec.decode_ctrl_rsp(
        await session.request(codec.PATH_CTRL, codec.encode_ctrl(codec.CtrlOp.END)),
        codec.CtrlOp.END,
    )
