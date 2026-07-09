# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Golioth demo-certificate provider — a port of the mobile apps'
GoliothCertProvider (see docs/golioth-demo-certs.md).

Mints Golioth-ready device credentials: generates a demo root CA, registers it
with the project (the same public-API flow the console's "temporary
certificate" button uses), then signs a per-device certificate (CN = device
ID) with that CA. Uses only the standard library for HTTP.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .pouchlink import cert as certmod
from .state import DEMO_CA_CN

_TIMEOUT = 15.0
_ID_RE = re.compile(r'"id"\s*:\s*"([^"]+)"')

# http(method, url, api_key, body) -> response text; injectable for tests.
HttpFn = Callable[[str, str, str, str | None], str]


@dataclass
class DeviceCredentials:
    """Device credentials plus the CA cert that signed them (for the CA slot)."""

    cert_pem: bytes
    key_pem: bytes
    ca_cert_pem: bytes


class GoliothError(Exception):
    """Golioth API error."""


def _urllib_http(method: str, url: str, api_key: str, body: str | None) -> str:
    headers = {"x-api-key": api_key, "Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = body.encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as rsp:
            return rsp.read().decode()
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        raise GoliothError(f"Golioth API {method} {url} -> {exc.code}: {text}") from exc
    except urllib.error.URLError as exc:
        raise GoliothError(f"Golioth API {method} {url}: {exc.reason}") from exc


class GoliothCertProvider:
    """Discovers the project from the API key, registers a demo root CA once,
    and signs per-device certificates with it."""

    def __init__(self, api_key: str, base_url: str = "https://api.golioth.io",
                 http: HttpFn = _urllib_http,
                 ca: certmod.Credentials | None = None):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http = http
        self._project: str | None = None
        self._ca = ca
        self._ca_registered = False
        self.ca_cert_id: str | None = None

    def _request(self, method: str, path: str, body: str | None = None) -> str:
        return self._http(method, f"{self._base_url}{path}", self._api_key, body)

    def project_id(self) -> str:
        """The project id the API key belongs to (discovered + cached)."""
        if self._project is None:
            rsp = self._request("GET", "/v1/projects")
            match = _ID_RE.search(rsp)
            if not match:
                raise GoliothError("no Golioth project found for this API key")
            self._project = match.group(1)
        return self._project

    def mint_device_credentials(self, device_id: str,
                                validity_days: int = 28) -> DeviceCredentials:
        """Mint (device cert, key, CA cert) for *device_id*. Registers the demo
        CA on first call and reuses it after."""
        pid = self.project_id()
        if self._ca is None:
            self._ca = certmod.generate_ca(DEMO_CA_CN)
        if not self._ca_registered:
            self.ca_cert_id = self._register_ca(pid, self._ca.cert_pem)
            self._ca_registered = True
        device = certmod.sign_device_cert(self._ca, device_id, validity_days)
        return DeviceCredentials(device.cert_pem, device.key_pem, self._ca.cert_pem)

    def register_ca(self, ca_cert_pem: bytes) -> str:
        """POST a CA as a temporary (demo) root cert; returns its certificate id."""
        return self._register_ca(self.project_id(), ca_cert_pem)

    def _register_ca(self, pid: str, ca_cert_pem: bytes) -> str:
        body = json.dumps({
            "certType": "root",
            "certFile": base64.b64encode(ca_cert_pem).decode(),
            "demo": True,
        })
        rsp = self._request("POST", f"/v1/projects/{pid}/certificates", body)
        match = _ID_RE.search(rsp)
        return match.group(1) if match else ""

    def list_cert_ids(self) -> list[str]:
        """List registered certificate ids (for cleanup)."""
        rsp = self._request("GET", f"/v1/projects/{self.project_id()}/certificates")
        return _ID_RE.findall(rsp)

    def delete_cert(self, cert_id: str) -> None:
        """Delete a registered certificate (e.g. to garbage-collect a demo CA)."""
        self._request("DELETE", f"/v1/projects/{self.project_id()}/certificates/{cert_id}")
