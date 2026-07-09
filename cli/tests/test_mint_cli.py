# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""The `pouchprov mint` command (offline credential minting)."""

from click.testing import CliRunner
from cryptography import x509

from pouchprov.main import cli
from pouchprov.state import DEMO_CA_CN, load_or_create_demo_ca, state_dir


def test_mint_demo_ca_signed(tmp_path):
    out = tmp_path / "out"
    state = tmp_path / "state"
    result = CliRunner().invoke(
        cli, ["mint", "dev-1", "--out", str(out), "--state-dir", str(state)]
    )
    assert result.exit_code == 0, result.output

    dev = x509.load_pem_x509_certificate((out / "dev-1.crt.pem").read_bytes())
    ca = x509.load_pem_x509_certificate((out / "ca.crt.pem").read_bytes())
    assert dev.issuer == ca.subject
    assert ca.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == DEMO_CA_CN
    assert (out / "dev-1.key.pem").exists()

    # CA persists: a second mint reuses it
    result = CliRunner().invoke(
        cli, ["mint", "dev-2", "--out", str(out), "--state-dir", str(state)]
    )
    assert result.exit_code == 0, result.output
    dev2 = x509.load_pem_x509_certificate((out / "dev-2.crt.pem").read_bytes())
    assert dev2.issuer == dev.issuer
    assert (state / "golioth-demo-ca.key.pem").exists()


def test_mint_self_signed(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["mint", "dev-ss", "--self-signed", "--validity-days", "3",
         "--out", str(tmp_path), "--state-dir", str(tmp_path / "state")],
    )
    assert result.exit_code == 0, result.output
    dev = x509.load_pem_x509_certificate((tmp_path / "dev-ss.crt.pem").read_bytes())
    assert dev.issuer == dev.subject
    assert not (tmp_path / "ca.crt.pem").exists()


def test_demo_ca_reused_not_regenerated(tmp_path):
    d = state_dir(str(tmp_path))
    first = load_or_create_demo_ca(d)
    second = load_or_create_demo_ca(d)
    assert first.cert_pem == second.cert_pem
    assert first.key_pem == second.key_pem
