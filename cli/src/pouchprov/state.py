# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Persistent client state under ~/.pouchprov (demo CA, TOFU server identity)."""

from __future__ import annotations

import os
from pathlib import Path

from .pouchlink import cert as certmod

DEMO_CA_CN = "pouch-demo-CA"
_CA_CERT = "golioth-demo-ca.crt.pem"
_CA_KEY = "golioth-demo-ca.key.pem"


def state_dir(override: str | None = None) -> Path:
    path = Path(override) if override else Path.home() / ".pouchprov"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600)


def load_or_create_demo_ca(directory: Path, validity_days: int = 3650) -> certmod.Credentials:
    """The local demo CA that signs minted device certs (mirrors the apps'
    one-time "pouch-demo-CA"). Created on first use, then reused."""
    cert_path, key_path = directory / _CA_CERT, directory / _CA_KEY
    if cert_path.exists() and key_path.exists():
        return certmod.Credentials(cert_path.read_bytes(), key_path.read_bytes())
    ca = certmod.generate_ca(DEMO_CA_CN, validity_days)
    cert_path.write_bytes(ca.cert_pem)
    _write_private(key_path, ca.key_pem)
    return ca
