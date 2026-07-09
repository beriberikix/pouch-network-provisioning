# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""End-to-end: the full provisioning sequence over an encrypted session.

Composes ver -> auth -> cred bootstrap -> wifi config -> end against a
single saead-encrypted mock device implementing every endpoint.
"""

import hmac
import secrets

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pouchprov import auth, codec, flows
from pouchprov.pouchlink import cert, saead
from pouchprov.session import ProvSession
from pouchprov.transport.mock import DeviceSaead, MockDeviceTransport

POP = "abcd1234"


class FullDevice:
    def __init__(self, pop, expected_ssid, expected_pass):
        self.pop = pop
        self.expected = (expected_ssid, expected_pass)
        self.authorized = False
        self._dev_nonce = None
        self._cli_nonce = None
        self.creds = {0: b"", 1: b"", 2: b""}
        self.expected_len = {}
        self.cred_finalized = False
        self.staged = None
        self.sta = codec.StaState.DISCONNECTED

    def handle(self, path, payload):
        msg = cbor2.loads(payload)
        op = msg[0]
        if path == codec.PATH_VER:
            return cbor2.dumps([0, 0, {"proto": 1, "caps": ["wifi", "cred", "auth"],
                                       "blk": 512, "lib": "e2e", "pop": True}])
        if path == codec.PATH_AUTH:
            return self._auth(op, msg)
        # everything below is gated
        if not self.authorized:
            return cbor2.dumps([op, 4])  # unauthorized
        if path == codec.PATH_CRED:
            return self._cred(op, msg)
        if path == codec.PATH_CONFIG:
            return self._config(op, msg)
        if path == codec.PATH_CTRL:
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

    def _config(self, op, msg):
        if op == 1:
            cfg = msg[1]
            self.staged = (bytes(cfg["ssid"]), bytes(cfg.get("pass", b"")))
            return cbor2.dumps([1, 0])
        if op == 2:
            self.sta = (codec.StaState.CONNECTED if self.staged == self.expected
                        else codec.StaState.FAILED)
            return cbor2.dumps([2, 0])
        if self.sta == codec.StaState.CONNECTED:
            return cbor2.dumps([0, 0, 0, {"ip4": bytes([10, 0, 0, 9]),
                                          "ssid": self.expected[0], "rssi": -33}])
        return cbor2.dumps([0, 0, int(self.sta), 0])


async def test_full_provision_encrypted():
    server = cert.generate_server_identity()
    device_priv = ec.generate_private_key(ec.SECP256R1())
    client_saead = saead.SaeadSession(server.private_key, device_priv.public_key(),
                                      server.cert_ref, algorithm=saead.ALG_AES_GCM)
    dev_saead = DeviceSaead(device_priv, server.public_key, algorithm=saead.ALG_AES_GCM)

    dev = FullDevice(POP, b"HomeNet", b"s3cretpass")
    transport = MockDeviceTransport(dev.handle, device_saead=dev_saead)
    session = ProvSession(transport, saead=client_saead)

    # 1. version + capabilities
    info = await flows.get_version(session)
    assert set(["wifi", "cred", "auth"]).issubset(info.caps)

    # 2. authorize (mutual PoP)
    await flows.authorize_if_needed(session, info, POP)
    assert dev.authorized

    # 3. bootstrap cloud credentials
    cloud_cert = cert.generate_server_identity("cloud-device").cert_der
    cloud_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    await flows.bootstrap_credentials(session, cloud_cert, cloud_key)
    assert dev.cred_finalized
    assert dev.creds[0] == cloud_cert

    # 4. Wi-Fi config
    status = await flows.configure_wifi(session, b"HomeNet", b"s3cretpass")
    assert status.state == codec.StaState.CONNECTED

    # 5. end
    await flows.end_session(session)


async def test_gated_before_auth():
    """Endpoints must reject before PoP authorization."""
    server = cert.generate_server_identity()
    device_priv = ec.generate_private_key(ec.SECP256R1())
    client_saead = saead.SaeadSession(server.private_key, device_priv.public_key(),
                                      server.cert_ref, algorithm=saead.ALG_AES_GCM)
    dev_saead = DeviceSaead(device_priv, server.public_key, algorithm=saead.ALG_AES_GCM)
    dev = FullDevice(POP, b"x", b"y")
    session = ProvSession(MockDeviceTransport(dev.handle, device_saead=dev_saead),
                          saead=client_saead)

    import pytest
    with pytest.raises(codec.ProvError) as exc:
        codec.decode_config_status_rsp(
            await session.request(codec.PATH_CONFIG, codec.encode_config_get_status())
        )
    assert exc.value.status == codec.Status.UNAUTHORIZED


def test_cli_provision_self_signed(monkeypatch, tmp_path):
    """`pouchprov provision --self-signed` end-to-end via CliRunner: the minted
    cert reaches the device and its CN is the session device id."""
    from click.testing import CliRunner
    from cryptography import x509

    from pouchprov import main as cli_main
    from pouchprov.transport.mock import MockDeviceTransport

    device = FullDevice(POP, expected_ssid=None, expected_pass=None)

    class CliMockTransport(MockDeviceTransport):
        att_payload = 244

        def __init__(self, name=None):
            super().__init__(device.handle, device_id="cli-e2e-dev")

    monkeypatch.setattr(cli_main.ble, "BleTransport", CliMockTransport)

    result = CliRunner().invoke(
        cli_main.cli,
        ["provision", "--pop", POP, "--self-signed",
         "--state-dir", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert device.cred_finalized

    stored = x509.load_der_x509_certificate(device.creds[0])
    cn = stored.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "cli-e2e-dev"
    assert "minted self-signed credentials" in result.output


def test_cli_provision_autodetects_saead(monkeypatch, tmp_path):
    """`pouchprov provision` against a saead-build mock: the session autodetects
    the TOFU endpoints, exchanges certs, and provisions fully encrypted."""
    from click.testing import CliRunner

    from pouchprov import main as cli_main
    from pouchprov.pouchlink import cert as certmod
    from pouchprov.transport.mock import MockDeviceTransport

    device = FullDevice(POP, expected_ssid=None, expected_pass=None)
    identity = certmod.generate_server_identity(common_name="e2e-saead-dev")

    class CliMockTransport(MockDeviceTransport):
        att_payload = 244

        def __init__(self, name=None):
            super().__init__(device.handle, device_id="e2e-saead-dev",
                             saead_identity=identity)

    monkeypatch.setattr(cli_main.ble, "BleTransport", CliMockTransport)

    result = CliRunner().invoke(
        cli_main.cli,
        ["provision", "--pop", POP, "--self-signed", "--state-dir", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert "session: saead (ChaCha20-Poly1305)" in result.output
    assert device.cred_finalized
    # The TOFU server identity persisted for reuse.
    assert (tmp_path / "server_identity.crt.pem").exists()
