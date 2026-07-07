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


async def end_session(session: ProvSession) -> None:
    codec.decode_ctrl_rsp(
        await session.request(codec.PATH_CTRL, codec.encode_ctrl(codec.CtrlOp.END)),
        codec.CtrlOp.END,
    )
