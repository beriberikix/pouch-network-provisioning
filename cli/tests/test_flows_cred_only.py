# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""BLE-only (credential-only) provisioning: a device advertising no `wifi`
cap is provisioned with certificates alone and ended over `.prov/ctrl`.
"""

import hmac
import secrets

import cbor2
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pouchprov import auth, codec, flows
from pouchprov.main import cli
from pouchprov.pouchlink import cert
from pouchprov.session import ProvSession
from pouchprov.transport import ble
from pouchprov.transport.mock import MockDeviceTransport

POP = "abcd1234"


class CredOnlyDevice:
    """Mock device with the cred bootstrap feature but no Wi-Fi.

    Services .prov/ver (caps ["cred","auth"], no "wifi"), .prov/auth,
    .prov/cred and .prov/ctrl — mirroring a POUCH_PROV_WIFI=n build.
    """

    def __init__(self, pop=POP, wifi=False):
        self.pop = pop
        self.wifi = wifi
        self.authorized = not pop
        self._dev_nonce = None
        self._cli_nonce = None
        self.creds = {0: b"", 1: b"", 2: b""}
        self.expected_len = {}
        self.cred_finalized = False
        self.ended = False

    def _caps(self):
        caps = ["wifi", "scan", "cred"] if self.wifi else ["cred"]
        if self.pop:
            caps.append("auth")
        return caps

    def handle(self, path, payload):
        msg = cbor2.loads(payload)
        op = msg[0]
        if path == codec.PATH_VER:
            return cbor2.dumps([0, 0, {"proto": 1, "caps": self._caps(),
                                       "blk": 512, "lib": "cred-only",
                                       "pop": bool(self.pop)}])
        if path == codec.PATH_AUTH:
            return self._auth(op, msg)
        if not self.authorized:
            return cbor2.dumps([op, 4])  # unauthorized
        if path == codec.PATH_CRED:
            return self._cred(op, msg)
        if path == codec.PATH_CTRL:
            if op == 2:
                self.ended = True
            return cbor2.dumps([op, 0])
        return None

    def _auth(self, op, msg):
        if op == 0:
            self._cli_nonce = bytes(msg[1])
            self._dev_nonce = secrets.token_bytes(16)
            proof = auth.device_proof(self.pop, self._cli_nonce, self._dev_nonce)
            return cbor2.dumps([0, 0, self._dev_nonce, proof])
        expected = auth.client_proof(self.pop, self._dev_nonce, self._cli_nonce)
        if hmac.compare_digest(bytes(msg[1]), expected):
            self.authorized = True
            return cbor2.dumps([1, 0])
        return cbor2.dumps([1, 4])

    def _cred(self, op, msg):
        if op == 0:
            c = msg[1]
            kind, total, data = c["kind"], c["total"], bytes(c["data"])
            self.creds[kind] += data
            self.expected_len[kind] = total
            return cbor2.dumps([0, 0, len(self.creds[kind])])
        if op == 1:
            ok = (self.creds[0] and self.creds[1] and
                  len(self.creds[0]) == self.expected_len.get(0) and
                  len(self.creds[1]) == self.expected_len.get(1))
            self.cred_finalized = bool(ok)
            return cbor2.dumps([1, 0 if ok else 2])
        return cbor2.dumps([2, 0, {}])


def _cloud_cert_and_key():
    cloud_cert = cert.generate_server_identity("cloud-device").cert_der
    cloud_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return cloud_cert, cloud_key


async def test_cred_only_flow():
    """ver -> auth -> cred bootstrap -> end, with no Wi-Fi step."""
    dev = CredOnlyDevice()
    session = ProvSession(MockDeviceTransport(dev.handle))

    info = await flows.get_version(session)
    assert "wifi" not in info.caps
    assert "cred" in info.caps

    await flows.authorize_if_needed(session, info, POP)
    assert dev.authorized

    cloud_cert, cloud_key = _cloud_cert_and_key()
    await flows.bootstrap_credentials(session, cloud_cert, cloud_key)
    assert dev.cred_finalized
    assert dev.creds[0] == cloud_cert

    await flows.end_session(session)
    assert dev.ended


# -- CLI-level coverage of the provision command --------------------------------


def _patch_transport(monkeypatch, dev):
    """Point ble.BleTransport at an in-memory cred-only device."""

    class _Adapter(MockDeviceTransport):
        att_payload = 244

        async def __aenter__(self):
            await self.connect()
            return self

        async def __aexit__(self, *exc):
            await self.disconnect()
            return False

    monkeypatch.setattr(ble, "BleTransport", lambda name=None: _Adapter(dev.handle))


def test_provision_requires_ssid_or_cert():
    result = CliRunner().invoke(cli, ["provision", "--pop", POP])
    assert result.exit_code != 0
    assert "provide --ssid" in result.output


def test_provision_cert_requires_key(tmp_path):
    cert_pem = tmp_path / "c.pem"
    cert_pem.write_bytes(b"x")
    result = CliRunner().invoke(cli, ["provision", "--pop", POP, "--cert", str(cert_pem)])
    assert result.exit_code != 0
    assert "--cert and --key" in result.output


def test_provision_cred_only(monkeypatch, tmp_path):
    dev = CredOnlyDevice()
    _patch_transport(monkeypatch, dev)

    cloud_cert, cloud_key = _cloud_cert_and_key()
    cert_file = tmp_path / "device.crt.der"
    key_file = tmp_path / "device.key.der"
    cert_file.write_bytes(cloud_cert)
    key_file.write_bytes(cloud_key)

    result = CliRunner().invoke(
        cli, ["provision", "--pop", POP, "--cert", str(cert_file), "--key", str(key_file)]
    )
    assert result.exit_code == 0, result.output
    assert "cloud credentials stored" in result.output
    assert dev.cred_finalized
    assert dev.ended  # session ended cleanly over .prov/ctrl


def test_provision_wifi_against_cred_only_device_errors(monkeypatch):
    dev = CredOnlyDevice(wifi=False)
    _patch_transport(monkeypatch, dev)

    result = CliRunner().invoke(cli, ["provision", "--pop", POP, "--ssid", "MyNet"])
    assert result.exit_code != 0
    assert "does not support Wi-Fi" in result.output
    assert not dev.ended
