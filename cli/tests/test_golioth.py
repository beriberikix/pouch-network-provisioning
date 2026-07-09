# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""GoliothCertProvider against a recording fake HTTP transport (no network)."""

import base64
import json

import pytest
from cryptography import x509

from pouchprov.golioth import GoliothCertProvider, GoliothError
from pouchprov.pouchlink import cert as certmod
from pouchprov.state import DEMO_CA_CN


class FakeHttp:
    """Records requests and plays back canned Golioth responses."""

    def __init__(self):
        self.requests = []

    def __call__(self, method, url, api_key, body):
        self.requests.append((method, url, api_key, body))
        if method == "GET" and url.endswith("/v1/projects"):
            return '{"list":[{"id":"my-project","name":"My Project"}]}'
        if method == "POST" and url.endswith("/certificates"):
            return '{"data":{"id":"cert-123","certType":"root"}}'
        if method == "GET" and url.endswith("/certificates"):
            return '{"list":[{"id":"cert-123"},{"id":"cert-456"}]}'
        if method == "DELETE":
            return "{}"
        raise AssertionError(f"unexpected request {method} {url}")


def test_project_discovery_cached():
    http = FakeHttp()
    provider = GoliothCertProvider("k3y", http=http)
    assert provider.project_id() == "my-project"
    assert provider.project_id() == "my-project"
    assert len(http.requests) == 1
    method, url, api_key, body = http.requests[0]
    assert (method, url, api_key, body) == (
        "GET", "https://api.golioth.io/v1/projects", "k3y", None)


def test_mint_registers_demo_ca_once():
    http = FakeHttp()
    provider = GoliothCertProvider("k3y", http=http)

    first = provider.mint_device_credentials("dev-1", validity_days=7)
    second = provider.mint_device_credentials("dev-2", validity_days=7)

    posts = [r for r in http.requests if r[0] == "POST"]
    assert len(posts) == 1  # CA registered exactly once
    _, url, _, body = posts[0]
    assert url == "https://api.golioth.io/v1/projects/my-project/certificates"
    payload = json.loads(body)
    assert payload["certType"] == "root"
    assert payload["demo"] is True

    ca_pem = base64.b64decode(payload["certFile"])
    ca_cert = x509.load_pem_x509_certificate(ca_pem)
    cn = ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == DEMO_CA_CN
    assert provider.ca_cert_id == "cert-123"

    # both device certs chain to the same CA
    for creds, cn_expected in ((first, "dev-1"), (second, "dev-2")):
        dev = x509.load_pem_x509_certificate(creds.cert_pem)
        assert dev.issuer == ca_cert.subject
        got = dev.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert got == cn_expected
        assert creds.ca_cert_pem == ca_pem


def test_mint_with_preloaded_ca_still_registers_it():
    http = FakeHttp()
    ca = certmod.generate_ca(DEMO_CA_CN)
    provider = GoliothCertProvider("k3y", http=http, ca=ca)
    minted = provider.mint_device_credentials("dev-1")
    posts = [r for r in http.requests if r[0] == "POST"]
    assert len(posts) == 1
    assert base64.b64decode(json.loads(posts[0][3])["certFile"]) == ca.cert_pem
    assert minted.ca_cert_pem == ca.cert_pem


def test_list_and_delete():
    http = FakeHttp()
    provider = GoliothCertProvider("k3y", http=http)
    assert provider.list_cert_ids() == ["cert-123", "cert-456"]
    provider.delete_cert("cert-123")
    method, url, _, _ = http.requests[-1]
    assert method == "DELETE"
    assert url.endswith("/v1/projects/my-project/certificates/cert-123")


def test_no_project_raises():
    def http(method, url, api_key, body):
        return "{}"

    with pytest.raises(GoliothError):
        GoliothCertProvider("k3y", http=http).project_id()
