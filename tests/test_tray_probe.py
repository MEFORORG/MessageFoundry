# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tokenless engine probes (ADR 0113 §2/§5) — classifiers are pure; probes use httpx MockTransport."""

from __future__ import annotations

import ast
import inspect
import json
import ssl
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

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

    The body sits exactly on the ceiling -- the largest ``/health`` that must still classify OK."""
    from messagefoundry.tray import probe as probe_mod

    monkeypatch.setattr(probe_mod, "MAX_PROBE_RESPONSE_BYTES", 4096)
    padding = "v" * (4096 - len(json.dumps({"status": "ok", "version": ""}).encode()))
    body = json.dumps({"status": "ok", "version": padding}).encode()
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


# --- the bounded-read guard, and what it is allowed to see (BACKLOG #1577, narrowed by #1831) ---

#: Verbs that belong to an HTTP client and to essentially nothing else a probe would be holding. A
#: call to one of these outside ``_get_bounded`` is an unbounded read whatever the receiver is, so
#: the sweep over them is as broad as it ever was.
_CLIENT_ONLY_VERBS = frozenset(
    {"post", "put", "patch", "delete", "head", "options", "request", "stream"}
)

#: ...and the two an ordinary Python object answers to as well: ``dict.get`` and ``generator.send``.
#: Swept on any receiver, ``body.get("status")`` in ``classify_health`` was indistinguishable from
#: ``client.get(url)`` -- a false positive worked around at the call site, which is how a guard gets
#: deleted by the next reader who does not know why it exists (BACKLOG #1831). These two are flagged
#: only where the receiver could be holding a client.
_AMBIGUOUS_VERBS = frozenset({"get", "send"})

#: Module-local call targets that hand an httpx client back, named so :func:`_inert_functions`
#: can exclude them: everything else defined here is judged inert by its own return annotation,
#: and a factory would otherwise clear itself.
_CLIENT_FACTORIES = frozenset({"httpx.Client", "httpx.AsyncClient", "make_probe_client"})


def _names_a_client(annotation: ast.expr | None) -> bool:
    """Does ``annotation`` name an httpx client -- ``httpx.Client``, ``AsyncClient``, a union?

    Spelled against the unparsed text rather than the node shape so a union, an optional or a plain
    ``Client`` import all read the same. mypy runs strict over this package, so every parameter that
    takes a client carries an annotation saying so -- that is what makes an annotation a reliable
    discriminator here and not a guess.
    """
    return annotation is not None and "Client" in ast.unparse(annotation)


class _Names(NamedTuple):
    """What the module shows about the names it uses, for :func:`_may_hold_a_client`."""

    #: Names this module SHOWS holding a non-client. The ONLY thing that clears a bare name.
    non_client: frozenset[str]
    #: Every name the module binds at all. Used only to judge an attribute chain's ROOT.
    bound: frozenset[str]
    #: Module-local functions that do not hand a client back.
    inert_functions: frozenset[str]


def _inert_functions(tree: ast.Module) -> frozenset[str]:
    """Module-local functions whose result cannot be a client, by their own return annotation."""
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name not in _CLIENT_FACTORIES
        and not _names_a_client(node.returns)
    )


def _is_inert(value: ast.expr, inert_functions: frozenset[str]) -> bool:
    """Is ``value`` an expression this module SHOWS is not a client?

    A literal or a display holds what it says. A call to a module-local function whose return
    annotation does not name a client cannot hand one back under mypy strict. Nothing else here
    resolves, and anything that does not resolve is treated as a client by the caller.
    """
    if isinstance(value, ast.Constant | ast.Dict | ast.List | ast.Set | ast.Tuple | ast.JoinedStr):
        return True
    if isinstance(value, ast.ListComp | ast.DictComp | ast.SetComp | ast.GeneratorExp):
        return True
    if isinstance(value, ast.Call):
        return ast.unparse(value.func) in inert_functions
    return False


def _module_names(tree: ast.Module) -> _Names:
    """Read the module once and answer what :func:`_may_hold_a_client` needs.

    **The clearing side is enumerated, and that is the whole design (BACKLOG #1831).** An earlier
    cut enumerated the CLIENT-bearing bindings instead and cleared every other bound name, which
    conflates knowing a name EXISTS with knowing what it HOLDS. Measured: `with make_probe_client(u)
    as c`, `for c in clients`, `c, _x = make_probe_client(u), None` and a walrus all bound a real
    client that the guard then let through, because none of them is a parameter or a simple
    assignment. Every binding form Python has, or that this walk simply failed to enumerate, was a
    silent bypass. Asking instead what the module SHOWS a name holding makes an unenumerated form
    fail closed by construction rather than by diligence.
    """
    inert = _inert_functions(tree)
    non_client: set[str] = set()
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)  # assignment, for/with target, walrus, comprehension
        elif isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bound.add(node.name)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:  # `except E as e` binds; a bare `except E` binds nothing
                bound.add(node.name)
        elif isinstance(node, ast.Global | ast.Nonlocal):
            bound.update(node.names)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
            # mypy runs strict here, so a parameter that takes a client says so.
            if node.annotation is not None and not _names_a_client(node.annotation):
                non_client.add(node.arg)
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            annotated_client = isinstance(node, ast.AnnAssign) and _names_a_client(node.annotation)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not annotated_client and node.value is not None and _is_inert(node.value, inert):
                non_client |= {t.id for t in targets if isinstance(t, ast.Name)}
    return _Names(frozenset(non_client), frozenset(bound), inert)


def _may_hold_a_client(receiver: ast.expr, names: _Names) -> bool:
    """Could ``receiver`` be an httpx client? Answered so that UNKNOWN reads as YES.

    Two things clear, and nothing else does: an expression the module SHOWS is inert, and a bare
    name it shows bound to something inert. A name it binds without showing what to, a name it does
    not bind at all, an attribute whose last segment is client-named, a subscript, a call that is
    not provably inert -- all read as a client.

    The asymmetry is the design. A false positive costs a workaround at a call site and, eventually,
    somebody deleting the guard; a false negative costs the unbounded read BACKLOG #1577 closed. So
    the unknown cases go to the flagging side, and the fallthrough at the bottom is a flag, not a
    clear -- an earlier cut had it the other way and let a subscripted client through.
    """
    if _is_inert(receiver, names.inert_functions):
        return False
    if isinstance(receiver, ast.Name):
        return receiver.id not in names.non_client
    if isinstance(receiver, ast.NamedExpr):
        return _may_hold_a_client(receiver.value, names)  # `(c := make_probe_client(u)).get(...)`
    if isinstance(receiver, ast.Attribute):
        # The LAST segment is the value being called, so that is the one to judge:
        # ``self._client.get(...)`` is a client, ``client.headers.get(...)`` is a mapping ON one.
        # Judging the root instead would flag every mapping an httpx client exposes -- the same
        # false positive one level up.
        if receiver.attr.lower().endswith("client"):
            return True
        root: ast.expr = receiver
        while isinstance(root, ast.Attribute):
            root = root.value
        # ...but a chain rooted in a name nothing here binds came from outside this walk.
        return not (isinstance(root, ast.Name) and root.id in names.bound)
    return True  # a subscript, an await, a call that builds who knows what


def _unbounded_reads(source: str) -> list[str]:
    """Every call in ``source`` that issues a request without going through ``_get_bounded``."""
    tree = ast.parse(source)
    bounded = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "_get_bounded"
    ]
    assert bounded, "tray/probe.py defines no `_get_bounded`; this guard is aimed at nothing"
    inside_helper = {n for root in bounded for n in ast.walk(root)}
    names = _module_names(tree)

    found: list[str] = []
    for node in ast.walk(tree):
        if node in inside_helper or not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        ambiguous = func.attr in _AMBIGUOUS_VERBS and _may_hold_a_client(func.value, names)
        if func.attr in _CLIENT_ONLY_VERBS or ambiguous:
            found.append(f"line {node.lineno}: `{ast.unparse(func)}(...)`")
    return found


def _probe_source() -> str:
    return Path(inspect.getfile(probe_module)).read_text(encoding="utf-8")


#: The frame a planted arm is given: one name annotated as a client, one that plainly is not.
_PLANT_SIG = "client: httpx.Client, body: dict[str, str]"


def _flags_the_plant(body: str, sig: str = _PLANT_SIG) -> bool:
    """Plant ``body`` in the real probe source and report whether the guard flags THE PLANT.

    Two things, and the second is the one that makes an arm mean something. The plant goes into real
    ``tray/probe.py`` source, so no arm can pass against a toy tree that has drifted from it.
    And the verdict is keyed on the planted REGION, not on the finding list being non-empty: a bare
    ``assert found`` answers "did the guard flag anything", which is a different sentence from "did
    the guard flag this", and it stays green off an unrelated defect elsewhere in the module. That
    was not hypothetical -- while this was being written, a real ``client.get`` planted in
    ``probe_ui`` reddened the negative-control arms too, because they were reading the whole list.

    ``body`` may be several statements: it is dedented and re-indented into the frame, and the
    verdict is any finding BELOW the frame's ``def``. An earlier cut matched one exact line with
    ``rindex`` and so could only express a single-line arm -- which is part of why the binding-form
    holes had no arm to catch them.

    ``sig`` is the planted frame's parameter list, so an arm can carry the annotation an existing
    function actually has. It APPENDS a frame and never rewrites an existing one: a guard test that
    pins some other function's current spelling reds the day somebody legitimately edits that line,
    and on this module those edits belong to other sessions.
    """
    source = _probe_source()
    planted = textwrap.indent(textwrap.dedent(body).strip("\n"), "    ")
    frame = f"\n\ndef _planted({sig}) -> object:\n{planted}\n"
    def_line = source.count("\n") + 3  # two blank lines, then the `def`
    return any(
        int(finding.split()[1].rstrip(":")) > def_line
        for finding in _unbounded_reads(source + frame)
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
    assert _unbounded_reads(_probe_source()) == []


@pytest.mark.parametrize(
    "planted",
    [
        'return client.get("/version")',  # the canonical regression BACKLOG #1577 closed
        'return client.send(client.build_request("GET", "/version"))',
        'return client.post("/version", json={})',  # an unambiguous verb, unchanged sweep
        'return client.stream("GET", "/version")',
        'return httpx.get("http://127.0.0.1:8765/version")',  # no client named at all
        'return make_probe_client("http://x").get("/version")',  # built inline
        'return _POLLER_CLIENT.get("/version")',  # a name this module never binds: fail closed
        'return _state.poller.get("/version")',  # ...and so does a chain rooted in one
        'return body.client.get("/version")',  # a client-named attribute on a BOUND root
        'return client.headers.get("x") or client.get("/version")',  # legal beside illegal
    ],
)
def test_the_narrowed_guard_still_catches_a_real_unbounded_read(planted: str) -> None:
    """POSITIVE CONTROL for the narrowing. Narrowing a guard is how a guard stops working, so every
    shape the broad sweep caught has to be shown still caught -- not reasoned about.

    Every arm is a shape the broad sweep flagged, and the arms are deliberately non-overlapping so a
    red names which rule stopped working. The three ways a client reaches a call site without being
    a plainly annotated local are separated on purpose: ``_POLLER_CLIENT`` is an unbound NAME,
    ``_state.poller`` is a chain rooted in one, and ``body.client`` is a client-named attribute on a
    root this module DOES bind -- only the last exercises the attribute spelling by itself.

    Mutation: make ``_may_hold_a_client`` return ``False`` for an unbound name. Red: the
    ``_POLLER_CLIENT`` arm alone, which is the point of separating it from ``_state.poller``."""
    assert _flags_the_plant(planted), (
        f"the guard did not flag {planted!r}; a real unbounded read now passes it"
    )


@pytest.mark.parametrize(
    ("form", "planted"),
    [
        ("with-bound", 'with make_probe_client("http://x") as c:\n    return c.get("/version")'),
        ("for-bound", 'for c in clients:\n    return c.get("/version")\nreturn None'),
        ("walrus", 'return (c := make_probe_client("http://x")).get("/version")'),
        ("tuple-unpacked", 'c, _x = make_probe_client("http://x"), None\nreturn c.get("/version")'),
        ("subscripted", 'return clients[0].get("/version")'),
    ],
)
def test_the_guard_catches_a_client_reached_by_any_binding_form(form: str, planted: str) -> None:
    """The regression this file actually shipped, and the reason the clearing side is enumerated.

    The first cut of BACKLOG #1831 resolved client names from PARAMETERS and SIMPLE ASSIGNMENTS
    only, then cleared every other name the module bound. All five forms below hold a real client,
    all five were caught by the pre-narrowing sweep, and all five were MEASURED passing the narrowed
    guard -- with ``c = make_probe_client(u)`` and ``c: httpx.Client`` still caught, so the binding
    form alone decided. The first is the idiomatic httpx spelling and the one this very file uses.

    Nothing in the suite could see it: the arms above cover parameters, unbound names, chain roots,
    inline construction and attributes, and the plant helper could express only ONE LINE, so no
    statement-shaped arm was writable. 50 tests passed over the hole.

    Mutation: clear a bare name on ``receiver.id in bound_names`` instead of on
    ``not in non_client_names``. Red: every arm here, with the arms above still green."""
    assert _flags_the_plant(planted, "clients: list[object]"), (
        f"a client bound by {form} passes the guard; the narrowing dropped a shape the broad "
        "sweep caught, which is the one thing BACKLOG #1831 was not allowed to do"
    )


@pytest.mark.parametrize(
    "planted",
    [
        'return body.get("status")',  # BACKLOG #1831: the false positive that started this
        'return body.get("status", "")',
        'return {"a": 1}.get("a")',
        'return client.headers.get("x")',  # a mapping ON a client is not a client
        'return body.headers.get("x")',  # ...and neither is an attribute of a plain value
    ],
)
def test_the_guard_leaves_ordinary_python_alone(planted: str) -> None:
    """NEGATIVE CONTROL. A guard that flagged everything would pass the arms above uniformly.

    ``body`` is the measured case (BACKLOG #1831): it is annotated, it is not a client, and sweeping
    ``.get`` on any receiver made it indistinguishable from ``client.get(url)``. The cost was not
    the red -- it was the workaround the red bought at the call site, and a reader who meets one of
    those without the reason concludes the guard is noise.

    The two ``.headers`` arms are the level-up form of the same mistake, and one of them was a live
    false positive in the first cut of this narrowing: a mapping ON a client is not a client, so
    judging an attribute chain by its ROOT rather than its last segment reintroduces the bug.

    Mutation: sweep ``_AMBIGUOUS_VERBS`` on any receiver, as before. Red: every arm here."""
    assert not _flags_the_plant(planted), (
        f"the guard flagged {planted!r}; ordinary Python is reddening a guard about HTTP reads"
    )


def test_the_guard_permits_classify_healths_own_signature_reading_the_status_value() -> None:
    """The arm ``classify_health`` is waiting on, written so it pins nothing that session will edit.

    ``classify_health(status_code: int | None, body: object)`` tests key PRESENCE today; reading the
    VALUE is the obvious next edit and it is spelled ``body.get("status")``. Under the old sweep that
    spelling reddened this file, which is the whole of BACKLOG #1831.

    The annotation is the reason this is not just another negative-control arm. Those plant into a
    frame whose ``body`` is a ``dict[str, str]``; ``classify_health``'s is a bare ``object``, and a
    reader is entitled to ask whether the resolver treats the two differently. It does not -- neither
    is client-bearing -- and that is asserted rather than argued.

    **It plants a frame instead of rewriting the real line, deliberately.** An earlier cut of this
    substituted ``classify_health``'s current text and asserted on the result, which pinned a line
    BACKLOG #1715 is claimed to change. That arm would have gone red on ``main`` the day #1715
    landed, blaming this guard for somebody else's correct edit. A guard must not make another
    session's work look like a regression."""
    assert not _flags_the_plant(
        'return body.get("status")', "status_code: int | None, body: object"
    )
