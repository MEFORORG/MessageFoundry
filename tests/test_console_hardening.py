# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-6 console hardening: refuse plaintext http to a remote host (CONSOLE-3) and report
keyring failures on sign-out (CONSOLE-2)."""

from __future__ import annotations

import pytest

from messagefoundry.console.client import ApiError, EngineClient


# --- CONSOLE-3: transport guard ----------------------------------------------


def test_client_refuses_plaintext_http_to_remote_host() -> None:
    with pytest.raises(ApiError, match="cleartext"):
        EngineClient("http://hospital.example.com:8765")


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:8765", "http://localhost:8765", "https://hospital.example.com"],
)
def test_client_allows_loopback_http_and_any_https(url: str) -> None:
    EngineClient(url).close()  # constructs without raising; loopback http and https are safe


def test_client_insecure_opt_in_allows_remote_http() -> None:
    EngineClient("http://hospital.example.com:8765", allow_insecure=True).close()


# --- 12.3.5: console presents a client certificate for mutual TLS ------------


def test_client_presents_configured_client_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    # ASVS 12.3.5: when configured, the console hands httpx a client certificate so it authenticates
    # to an mTLS-requiring engine API by certificate, not only the bearer token. Default = no cert.
    import messagefoundry.console.client as client_module

    captured: dict[str, object] = {}

    class _SpyClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(client_module.httpx, "Client", _SpyClient)

    EngineClient("https://engine.example")
    assert captured["cert"] is None  # unchanged default — no client cert

    captured.clear()
    EngineClient(
        "https://engine.example", tls_client_cert="/c/cert.pem", tls_client_key="/c/key.pem"
    )
    assert captured["cert"] == ("/c/cert.pem", "/c/key.pem")  # cert + separate key

    captured.clear()
    EngineClient("https://engine.example", tls_client_cert="/c/bundle.pem")
    assert captured["cert"] == "/c/bundle.pem"  # key bundled in the cert PEM


# --- CONSOLE-2: keyring failure is reported, not swallowed --------------------


def test_delete_token_reports_keyring_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = pytest.importorskip("keyring")
    from keyring.errors import KeyringError

    from messagefoundry.console.__main__ import _delete_token

    def _boom(*_a: object, **_k: object) -> None:
        raise KeyringError("vault locked")

    monkeypatch.setattr(keyring, "delete_password", _boom)
    assert _delete_token("http://127.0.0.1:8765") is False  # surfaced, not silently swallowed


def test_delete_token_success(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = pytest.importorskip("keyring")
    from messagefoundry.console.__main__ import _delete_token

    monkeypatch.setattr(keyring, "delete_password", lambda *_a, **_k: None)
    assert _delete_token("http://127.0.0.1:8765") is True
