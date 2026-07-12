# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-6 console hardening: refuse plaintext http to a remote host (CONSOLE-3) and report
keyring failures on sign-out (CONSOLE-2)."""

from __future__ import annotations

import sys

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


def test_http_client_constructs_without_truststore(monkeypatch: pytest.MonkeyPatch) -> None:
    # `truststore` is a [console]-extra dep; an *http* EngineClient (the load harness, any non-[console]
    # install) must construct WITHOUT it — building a TLS verify context (which imports truststore) is
    # only meaningful for https. Regression for the load-test ModuleNotFoundError: No module named
    # 'truststore', where EngineClient.__init__ built the context even for an http base_url.
    monkeypatch.setitem(sys.modules, "truststore", None)  # makes `import truststore` raise
    EngineClient("http://127.0.0.1:8765").close()  # must NOT raise


# --- 12.3.5: console presents a client certificate for mutual TLS ------------


def test_client_presents_configured_client_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    # ASVS 12.3.5: when configured, the console loads a client certificate onto the TLS verification
    # context (via _build_verify_context -> load_cert_chain) so it authenticates to an mTLS-requiring
    # engine API by certificate, not only the bearer token. httpx 0.28's deprecated `cert=` was dropped
    # — the client cert now rides the `verify` SSLContext — so this checks that delegation: EngineClient
    # forwards (cacert, client_cert, client_key) to the context builder and hands httpx the result as
    # verify=, with no cert= kwarg. (The actual load_cert_chain is unit-tested in test_console_client.)
    # The client body lives in messagefoundry.apiclient.client (ADR 0088); monkeypatch it there so
    # the name resolution inside EngineClient.__init__ actually sees the spy (console.client is a shim).
    import messagefoundry.apiclient.client as client_module

    seen: list[tuple[str | None, str | None, str | None]] = []
    sentinel = object()

    def _spy_build(cacert: str | None, client_cert: str | None, client_key: str | None) -> object:
        seen.append((cacert, client_cert, client_key))
        return sentinel

    captured: dict[str, object] = {}

    class _SpyClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(client_module, "_build_verify_context", _spy_build)
    monkeypatch.setattr(client_module.httpx, "Client", _SpyClient)

    EngineClient("https://engine.example")
    assert seen[-1] == (None, None, None)  # default — no cacert, no client cert
    assert captured.get("verify") is sentinel  # the built context is handed to httpx as verify=
    assert "cert" not in captured  # the deprecated httpx cert= kwarg is gone

    seen.clear()
    EngineClient(
        "https://engine.example", tls_client_cert="/c/cert.pem", tls_client_key="/c/key.pem"
    )
    assert seen[-1] == (None, "/c/cert.pem", "/c/key.pem")  # cert + separate key

    seen.clear()
    EngineClient("https://engine.example", tls_client_cert="/c/bundle.pem")
    assert seen[-1] == (None, "/c/bundle.pem", None)  # key bundled in the cert PEM


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
