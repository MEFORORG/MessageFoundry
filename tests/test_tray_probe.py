# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tokenless engine probes (ADR 0113 §2/§5) — classifiers are pure; probes use httpx MockTransport."""

from __future__ import annotations

import ast
import inspect
import json
import ssl
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.tray import probe as probe_module
from messagefoundry.tray.probe import (
    ENGINE_HEALTH_KEYS,
    build_verify,
    classify_health,
    classify_ui,
    make_probe_client,
    probe_health,
    probe_ui,
)
from messagefoundry.tray.state import HealthProbe, UiProbe

#: The body the engine's tokenless ``GET /health`` actually returns on a stock deployment.
#: ``tests/test_client_network_allowlist.py`` builds the real app in-process and proves this is the
#: shape, so the table below is a fixture of a measured payload rather than a guess at one.
STOCK_HEALTH_BODY = {"status": "ok", "version": None, "observed_client": None}


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (None, None, HealthProbe.DOWN),  # connection error
        (200, STOCK_HEALTH_BODY, HealthProbe.OK),
        # An AUTHENTICATED /health fills the same three keys in (ASVS 13.4.6 withholds the version
        # from the tokenless probe, it does not remove the key). Values are never the signal.
        (200, {"status": "ok", "version": "0.3.2", "observed_client": "127.0.0.1"}, HealthProbe.OK),
        # CONTAINMENT, not equality: a newer engine that adds a Health field is still our engine.
        # The tray can point at an engine on another box, so the two versions can differ.
        (200, {**STOCK_HEALTH_BODY, "uptime_seconds": 12.0}, HealthProbe.OK),
        # --- BACKLOG #1715: the generic health bodies that used to read OK ---
        # The commonest health body in the industry. Any other server on the port answers this.
        (200, {"status": "ok"}, HealthProbe.FOREIGN),
        (200, {"status": "UP"}, HealthProbe.FOREIGN),
        # A PARTIAL key set is still not our engine — the whole set or nothing.
        (200, {"status": "ok", "version": None}, HealthProbe.FOREIGN),
        (200, {"status": "ok", "observed_client": None}, HealthProbe.FOREIGN),
        (200, {"version": None, "observed_client": None}, HealthProbe.FOREIGN),
        # --- shapes that were already FOREIGN and must stay so ---
        (200, {}, HealthProbe.FOREIGN),
        (200, "hello", HealthProbe.FOREIGN),  # 200 non-dict body
        (200, None, HealthProbe.FOREIGN),  # 200 non-JSON
        (404, None, HealthProbe.FOREIGN),
        # The STATUS-CODE arm on its own: the body is the real engine's, so the 500 is the only
        # thing making this FOREIGN. (It used to carry {"status": "ok"}, which now fails the key
        # test too — the case would have passed without the status check ever running.)
        (500, STOCK_HEALTH_BODY, HealthProbe.FOREIGN),
    ],
)
def test_classify_health(status: int | None, body: object, expected: HealthProbe) -> None:
    assert classify_health(status, body) is expected


def test_classify_health_keys_on_the_whole_tokenless_key_set() -> None:
    """BACKLOG #1715: dropping ANY ONE of the three keys must lose the OK verdict.

    The table above pins chosen shapes; this drives the set itself, so a future key added to
    ``ENGINE_HEALTH_KEYS`` is covered without anyone remembering to add a row.

    Mutation: relax ``classify_health`` back to ``"status" in body``. Red: every subset is OK."""
    assert classify_health(200, dict.fromkeys(ENGINE_HEALTH_KEYS)) is HealthProbe.OK
    for dropped in ENGINE_HEALTH_KEYS:
        body = dict.fromkeys(ENGINE_HEALTH_KEYS - {dropped})
        assert classify_health(200, body) is HealthProbe.FOREIGN, (
            f"a body missing only {dropped!r} still read as the engine"
        )


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
    with _client(lambda req: httpx.Response(200, json=STOCK_HEALTH_BODY)) as c:
        assert probe_health(c) is HealthProbe.OK


def test_probe_health_foreign() -> None:
    with _client(lambda req: httpx.Response(200, json={"nope": 1})) as c:
        assert probe_health(c) is HealthProbe.FOREIGN


def test_probe_health_foreign_for_a_generic_health_responder() -> None:
    """BACKLOG #1715, end to end through the transport: some OTHER program on the engine's port
    answering the industry-default body must move the tray to FOREIGN, not RUNNING."""
    with _client(lambda req: httpx.Response(200, json={"status": "ok"})) as c:
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


# --- ASVS 15.2.2 (BACKLOG #1577): both probes bound the reply body ------------------------------
#
# Both probes read a body from a port the tray does not control -- `classify_health` exists
# precisely because a NON-ENGINE server can answer it. `client.get(...)` reads to EOF, and the
# poller calls both probes on a repeating schedule, so a squatting process could drive the tray's
# memory one tick at a time. `probe_ui` was the quieter half: it buffered a body it never parses.


class _CountingStream(httpx.SyncByteStream):
    """A reply body that records how many chunks were pulled and whether it was closed."""

    def __init__(self, chunk: bytes, count: int) -> None:
        self._chunk = chunk
        self._count = count
        self.yielded = 0
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(self._count):
            self.yielded += 1
            yield self._chunk

    def close(self) -> None:
        self.closed = True


class _StreamTransport(httpx.BaseTransport):
    def __init__(self, stream: _CountingStream, status: int = 200) -> None:
        self._stream = stream
        self._status = status

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            self._status, headers={"content-type": "application/json"}, stream=self._stream
        )


def _streaming_client(stream: _CountingStream, status: int = 200) -> httpx.Client:
    return httpx.Client(
        base_url="http://127.0.0.1:8765",
        transport=_StreamTransport(stream, status),
        follow_redirects=False,
    )


def test_probe_health_refuses_an_oversized_reply_without_buffering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bound FIRES on ``/health``, and it fires ON THE STREAM.

    FOREIGN is the right verdict, not a fallback: the engine's ``/health`` is a few hundred bytes, so
    whatever answered with a megabyte is some other server -- which is exactly what
    ``classify_health`` exists to say. The pull count is the real assertion; a probe that read the
    whole body and then returned FOREIGN would pass the verdict check alone while still buffering
    everything.

    Mutation: drop ``stream=True`` from ``_get_bounded``. Red: ``yielded`` is 8, not 2."""
    from messagefoundry.tray import probe as probe_mod

    monkeypatch.setattr(probe_mod, "MAX_PROBE_RESPONSE_BYTES", 4096)
    stream = _CountingStream(b"a" * 4096, count=8)
    with _streaming_client(stream) as c:
        assert probe_health(c) is HealthProbe.FOREIGN
    assert stream.yielded == 2, (
        f"the read pulled {stream.yielded} of 8 chunks; a stream-enforced bound stops at the first "
        "chunk past the ceiling, so 8 means the whole body was buffered first"
    )
    assert stream.closed, "the oversized reply leaked the connection"


def test_probe_health_still_reads_a_normal_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    """NEGATIVE CONTROL: a probe that refused EVERY reply would pass the test above.

    The body sits exactly on the ceiling -- the largest ``/health`` that must still classify OK. It
    carries the full tokenless key set (BACKLOG #1715), so the padding is sized against that shape."""
    from messagefoundry.tray import probe as probe_mod

    monkeypatch.setattr(probe_mod, "MAX_PROBE_RESPONSE_BYTES", 4096)
    padding = "v" * (4096 - len(json.dumps({**STOCK_HEALTH_BODY, "version": ""}).encode()))
    body = json.dumps({**STOCK_HEALTH_BODY, "version": padding}).encode()
    assert len(body) == 4096, "the control is only a control if the body sits exactly on the bound"

    stream = _CountingStream(body, count=1)
    with _streaming_client(stream) as c:
        assert probe_health(c) is HealthProbe.OK
    assert stream.closed


def test_probe_ui_bounds_the_body_it_never_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    """``/ui`` is read for its STATUS CODE alone, and the body was buffered anyway.

    Two claims. The body is bounded (the pull count), and the verdict is unchanged by the body
    hitting that bound -- ``classify_ui`` reads the status, which arrived before any of the body did,
    so an oversized ``/ui`` page cannot flip the tray to DISABLED or UNKNOWN. It just is not
    buffered.

    Mutation: leave ``probe_ui`` on ``client.get(...)``. Red: ``yielded`` is 8, not 2."""
    from messagefoundry.tray import probe as probe_mod

    monkeypatch.setattr(probe_mod, "MAX_PROBE_RESPONSE_BYTES", 4096)
    stream = _CountingStream(b"a" * 4096, count=8)
    with _streaming_client(stream, status=200) as c:
        assert probe_ui(c) is UiProbe.ENABLED
    assert stream.yielded == 2, f"probe_ui pulled {stream.yielded} of 8 chunks; its body is unbound"
    assert stream.closed


def test_probe_ui_404_still_reads_disabled_under_the_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """NEGATIVE CONTROL for the verdict half: the status still decides, oversized body or not."""
    from messagefoundry.tray import probe as probe_mod

    monkeypatch.setattr(probe_mod, "MAX_PROBE_RESPONSE_BYTES", 4096)
    stream = _CountingStream(b"a" * 4096, count=8)
    with _streaming_client(stream, status=404) as c:
        assert probe_ui(c) is UiProbe.DISABLED


def test_probe_read_error_mid_body_is_down_not_a_raw_httpx_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming moves the failure point: a socket that dies mid-body used to fail inside
    ``client.get``, and now fails while iterating. Both probes must still map it to their own
    down-state rather than letting ``httpx.ReadError`` escape into the poller thread.

    Mutation: narrow the ``try`` in ``probe_health`` to the request build alone. Red: ReadError."""
    from messagefoundry.tray import probe as probe_mod

    monkeypatch.setattr(probe_mod, "MAX_PROBE_RESPONSE_BYTES", 4096)

    class _DyingStream(httpx.SyncByteStream):
        def __iter__(self) -> Iterator[bytes]:
            yield b"{"
            raise httpx.ReadError("connection reset mid-body")

    class _DyingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, stream=_DyingStream())

    with httpx.Client(base_url="http://127.0.0.1:8765", transport=_DyingTransport()) as c:
        assert probe_health(c) is HealthProbe.DOWN
        assert probe_ui(c) is UiProbe.UNKNOWN


def test_tray_probe_bound_is_generous_for_health_and_far_under_the_apiclient() -> None:
    """The SIZE of the tray's ceiling, and why it is not the apiclient's.

    Two different jobs. The apiclient has to be able to receive a whole HL7 message back inside a
    JSON envelope, so its bound clears a 6x escape of the engine's 16 MiB message ceiling. The tray
    reads a status object and a status code, so a ceiling sized for the apiclient's job would be
    dead headroom on a hop the tray polls on a schedule.

    Mutation: raise the tray bound to the apiclient's. Red: the second assertion names both."""
    from messagefoundry.apiclient.client import MAX_RESPONSE_BYTES
    from messagefoundry.tray.probe import MAX_PROBE_RESPONSE_BYTES

    assert MAX_PROBE_RESPONSE_BYTES >= 64 * 1024, (
        "the tray bound has to clear a real /health object with room to spare; a tight one would "
        "turn a healthy engine FOREIGN"
    )
    assert MAX_PROBE_RESPONSE_BYTES < MAX_RESPONSE_BYTES // 16, (
        f"the tray bound is {MAX_PROBE_RESPONSE_BYTES} against the apiclient's {MAX_RESPONSE_BYTES};"
        " the tray never asks for a message body, so it must not carry a message-sized ceiling"
    )


def test_every_request_in_the_probe_module_goes_through_the_bounded_helper() -> None:
    """Frozen (AST): ``_get_bounded`` is a helper a future probe has to REMEMBER to call, and this
    is what stops that being the weak link.

    ``make_probe_client`` already bakes the module's other two cross-cutting properties into the
    client itself -- TLS verification and the no-redirect policy -- so neither depends on a call site
    behaving. The response bound cannot be baked in the same way without a transport subclass, so it
    is guarded here instead, beside the escape-hatch test that exists for the same reason. A version
    or metrics probe added to this file later with a bare ``client.get(...)`` reintroduces exactly
    the unbounded read BACKLOG #1577 closed, and nothing else in the module would notice.

    Mutation: add ``client.get("/version")`` anywhere in tray/probe.py. Red: the call is named."""
    source = Path(inspect.getfile(probe_module)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    bounded = {
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_get_bounded"
    }
    inside_helper = {n for root in bounded for n in ast.walk(root)}

    verbs = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
        "stream",
        "send",
    }
    for node in ast.walk(tree):
        if node in inside_helper or not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in verbs:
            raise AssertionError(
                f"tray/probe.py line {node.lineno} issues `.{func.attr}(...)` outside "
                "`_get_bounded`; every probe read must go through the bounded helper"
            )
