"""Tokenless engine probes (ADR 0113 §2/§5) — classifiers are pure; probes use httpx MockTransport."""

from __future__ import annotations

import ast
import inspect
import ssl
from pathlib import Path

import httpx
import pytest

from messagefoundry.tray import probe as probe_module
from messagefoundry.tray.probe import (
    build_verify,
    classify_health,
    classify_ui,
    make_probe_client,
    probe_health,
    probe_ui,
)
from messagefoundry.tray.state import HealthProbe, UiProbe


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (None, None, HealthProbe.DOWN),  # connection error
        (200, {"status": "ok", "version": None}, HealthProbe.OK),
        (200, {"status": "ok"}, HealthProbe.OK),
        (200, {}, HealthProbe.FOREIGN),  # 200 but no status key → foreign
        (200, "hello", HealthProbe.FOREIGN),  # 200 non-dict body
        (200, None, HealthProbe.FOREIGN),  # 200 non-JSON
        (404, None, HealthProbe.FOREIGN),
        (500, {"status": "ok"}, HealthProbe.FOREIGN),  # non-200 is never OK
    ],
)
def test_classify_health(status: int | None, body: object, expected: HealthProbe) -> None:
    assert classify_health(status, body) is expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, UiProbe.UNKNOWN),
        (404, UiProbe.DISABLED),
        (303, UiProbe.ENABLED),
        (200, UiProbe.ENABLED),
        (401, UiProbe.ENABLED),
    ],
)
def test_classify_ui(status: int | None, expected: UiProbe) -> None:
    assert classify_ui(status) is expected


def _client(handler) -> httpx.Client:  # type: ignore[no-untyped-def]
    return httpx.Client(base_url="http://127.0.0.1:8765", transport=httpx.MockTransport(handler))


def test_probe_health_ok() -> None:
    with _client(lambda req: httpx.Response(200, json={"status": "ok", "version": None})) as c:
        assert probe_health(c) is HealthProbe.OK


def test_probe_health_foreign() -> None:
    with _client(lambda req: httpx.Response(200, json={"nope": 1})) as c:
        assert probe_health(c) is HealthProbe.FOREIGN


def test_probe_health_down_on_connect_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with _client(boom) as c:
        assert probe_health(c) is HealthProbe.DOWN


def test_probe_ui_enabled_does_not_follow_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # A followed redirect would turn 303 into a 200 login page; the probe must see the 303.
        return httpx.Response(303, headers={"Location": "/ui/login"})

    with _client(handler) as c:
        assert probe_ui(c) is UiProbe.ENABLED


def test_probe_ui_disabled_on_404() -> None:
    with _client(lambda req: httpx.Response(404)) as c:
        assert probe_ui(c) is UiProbe.DISABLED


def test_probe_ui_unknown_when_down() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with _client(boom) as c:
        assert probe_ui(c) is UiProbe.UNKNOWN


# --- TLS posture (ADR 0113 amendment 2026-07-22) ------------------------------------------------


def test_build_verify_http_is_httpx_default_not_a_relaxation() -> None:
    """http gets plain True: httpx ignores verify for plaintext, and an http-only tray must not
    have to import truststore just to build a client."""
    assert build_verify("http://127.0.0.1:8765") is True


def test_build_verify_https_uses_the_os_trust_store() -> None:
    ctx = build_verify("https://127.0.0.1:8765")
    assert isinstance(ctx, ssl.SSLContext)
    assert "truststore" in type(ctx).__module__
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_build_verify_returns_a_fresh_context_per_client() -> None:
    """truststore mutates a SHARED inner context mid-handshake (the CERT_NONE race documented in
    auth/oidc_http.py). One context per client keeps two clients from ever racing into it."""
    first = build_verify("https://127.0.0.1:8765")
    second = build_verify("https://127.0.0.1:8765")
    assert first is not second


def test_build_verify_never_returns_false() -> None:
    """The refusal path: there is no configuration under which the tray skips verification."""
    for url in (
        "https://127.0.0.1:8765",
        "https://localhost:8765",
        "https://engine.example.internal",
        "http://127.0.0.1:8765",
        "",
    ):
        assert build_verify(url) is not False


def test_probe_module_has_no_verify_false_escape_hatch() -> None:
    """Frozen (AST, so prose about the rule doesn't trip it): a future 'just make the self-signed
    cert work' edit must not slip an insecure default into the tray's probe client. The OS trust
    store — into which an operator can install a self-signed engine root — is the only path."""
    tree = ast.parse(Path(inspect.getfile(probe_module)).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                insecure = kw.arg in {"verify", "check_hostname"} and (
                    isinstance(kw.value, ast.Constant) and kw.value.value is False
                )
                assert not insecure, f"insecure TLS keyword {kw.arg}=False in tray/probe.py"
        if isinstance(node, ast.Attribute):
            assert node.attr != "CERT_NONE", "tray/probe.py must never name ssl.CERT_NONE"
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.attr for t in targets if isinstance(t, ast.Attribute)}
            if {"check_hostname", "verify_mode"} & names:
                raise AssertionError("tray/probe.py must not weaken an SSLContext's verification")


def test_make_probe_client_https_carries_a_verifying_context() -> None:
    with make_probe_client("https://127.0.0.1:8765/") as client:
        assert str(client.base_url) == "https://127.0.0.1:8765"
        assert client.follow_redirects is False
        assert "authorization" not in {k.lower() for k in client.headers}


def test_make_probe_client_http_still_works() -> None:
    with make_probe_client("http://127.0.0.1:8765") as client:
        assert str(client.base_url) == "http://127.0.0.1:8765"


def test_make_probe_client_https_does_not_reach_a_dead_socket_silently() -> None:
    """A TLS failure surfaces as an httpx error → DOWN/UNKNOWN, never a silent downgrade."""

    def tls_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("certificate verify failed", request=request)

    with httpx.Client(
        base_url="https://127.0.0.1:8765", transport=httpx.MockTransport(tls_error)
    ) as c:
        assert probe_health(c) is HealthProbe.DOWN
        assert probe_ui(c) is UiProbe.UNKNOWN
