# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every response the harness HTTP sink writes carries the baseline security headers (BACKLOG #1120;
ASVS 3.4.3, 3.4.4 and 3.4.6).

``harness/sinks/_http.py`` is the loopback server behind the REST, SOAP, FHIR and DICOMweb sinks. It
answers through the stdlib ``BaseHTTPRequestHandler``, which also writes answers of its own before
the sink's handler runs: a malformed request line, an unsupported method, an over-long line. This
suite drives the real sink over a loopback socket and reads the bytes back.

**The expectation is the engine listener's baseline**, ``transports/http_listener.py``'s
``_BASELINE_RESPONSE_HEADERS``, read from that module. The sink keeps its own copy, because the
harness may not import ``messagefoundry.transports`` (``tests/test_dependency_boundaries.py``), and
one test here pins the copy equal so the two cannot drift.

**Every case is paired with a control.** The same request against a sink whose one choke point has
been removed must be found WITHOUT the headers. A probe that cannot report absence proves nothing by
reporting presence.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from harness.sinks import _http as http_sink
from harness.sinks.rest import RestSink
from messagefoundry.api.header_floor import HSTS_HEADER
from messagefoundry.transports.http_listener import _BASELINE_RESPONSE_HEADERS

_Block = tuple[int, list[tuple[str, str]]]

#: What must be on every answer: the listener's baseline, which names nosniff and a CSP.
_EXPECTED = [(name.lower(), value) for name, value in _BASELINE_RESPONSE_HEADERS]


def _exchange(port: int, request: bytes) -> bytes:
    """Send raw bytes and read until the sink closes the connection."""
    with socket.create_connection(("127.0.0.1", port), 5.0) as conn:
        conn.sendall(request)
        chunks = []
        try:
            while chunk := conn.recv(65536):
                chunks.append(chunk)
        except ConnectionError:
            pass  # the sink closed with unread input still queued; what arrived is the answer
    return b"".join(chunks)


def _blocks(raw: bytes) -> list[_Block]:
    """Each header block in ``raw``, as (status, headers). An interim answer is a block of its own,
    so a ``100 Continue`` and the final answer after it are two."""
    found: list[_Block] = []
    rest = raw
    while rest.startswith(b"HTTP/"):
        head, _, rest = rest.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers = []
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers.append((name.strip().lower(), value.strip()))
        found.append((status, headers))
        if status >= 200:
            break  # what follows a final answer is its body
    return found


def _assert_floored(raw: bytes, statuses: list[int]) -> None:
    blocks = _blocks(raw)
    assert [status for status, _ in blocks] == statuses, raw[:200]
    for status, headers in blocks:
        names = [name for name, _ in headers]
        for name, value in _EXPECTED:
            assert (name, value) in headers, f"the {status} lacks {name}: {headers}"
            assert names.count(name) == 1, f"the {status} carries {name} more than once"
        assert HSTS_HEADER.lower() not in names, "HSTS on a cleartext loopback answer"


_POST = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"

#: (sink status, request, the statuses of the header blocks the sink must write).
_CASES: list[Any] = [
    pytest.param(200, _POST, [200], id="200"),
    pytest.param(400, _POST, [400], id="configured-400"),
    pytest.param(503, _POST, [503], id="configured-503"),
    pytest.param(200, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n", [200], id="get"),
    pytest.param(200, b"HEAD /x HTTP/1.1\r\nHost: x\r\n\r\n", [200], id="head"),
    # --- the sink's own refusals -----------------------------------------------------------------
    pytest.param(
        200,
        b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n",
        [413],
        id="413-over-cap",
    ),
    pytest.param(200, b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n", [411], id="411-no-length"),
    pytest.param(
        200,
        b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        [400],
        id="400-transfer-encoding",
    ),
    pytest.param(
        200,
        b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nonly ten b",
        [408],
        id="408-stalled-body",
    ),
    # --- answers the stdlib handler writes itself, before the sink's handler runs --------------
    pytest.param(200, b"NOT A REQUEST\r\n\r\n", [400], id="stdlib-400-malformed"),
    pytest.param(200, b"BREW /x HTTP/1.1\r\nHost: x\r\n\r\n", [501], id="stdlib-501-method"),
    pytest.param(200, b"GET /x HTTP/3.0\r\nHost: x\r\n\r\n", [505], id="stdlib-505-version"),
    pytest.param(
        200, b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", [414], id="stdlib-414-long-line"
    ),
    pytest.param(
        200,
        b"GET /x HTTP/1.1\r\nX-Long: " + b"a" * 70000 + b"\r\n\r\n",
        [431],
        id="stdlib-431-long-header",
    ),
    pytest.param(
        200,
        b"POST /x HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}",
        [100, 200],
        id="stdlib-100-continue",
    ),
    # An HTTP/0.9 answer has no status line and no header block, so there would be nowhere to
    # put the headers. The stdlib writes one for each of these three; the sink answers in
    # HTTP/1.0 form. test_the_stdlib_alone_answers_these_bare is the control for that half.
    pytest.param(200, b"GET /x\r\n\r\n", [200], id="http-0.9-two-word-request"),
    pytest.param(200, b"GET /x HTTP/0.9\r\n\r\n", [200], id="http-0.9-named-version"),
    pytest.param(200, b"BREW /x HTTP/0.9\r\n\r\n", [501], id="http-0.9-stdlib-501"),
]

#: The cases above that the stdlib would answer with no header block at all, by id.
_BARE_UNDER_THE_STDLIB = [
    pytest.param(case.values[1], id=case.id)
    for case in _CASES
    if case.id in ("stdlib-400-malformed", "stdlib-505-version") or case.id.startswith("http-0.9-")
]


@pytest.fixture(autouse=True)
def _short_read_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_sink, "READ_TIMEOUT_SECONDS", 0.3)


def _without(monkeypatch: pytest.MonkeyPatch, override: str) -> None:
    """Remove one of the sink handler's overrides, leaving the stdlib's own behaviour there."""
    real = http_sink._handler_for

    def _stdlib_there(sink: Any) -> Any:
        handler = real(sink)
        delattr(handler, override)
        return handler

    monkeypatch.setattr(http_sink, "_handler_for", _stdlib_there)


@pytest.mark.parametrize(("status", "request_bytes", "statuses"), _CASES)
def test_every_answer_carries_the_baseline_headers(
    status: int, request_bytes: bytes, statuses: list[int]
) -> None:
    with RestSink(status=status, reply_body=b'{"ok":1}') as sink:
        raw = _exchange(sink.port, request_bytes)
    _assert_floored(raw, statuses)


@pytest.mark.parametrize(("status", "request_bytes", "statuses"), _CASES)
def test_the_probe_sees_absence_when_the_choke_point_is_removed(
    status: int, request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control. One override puts the headers on every case above, so removing it must leave
    every case bare, and the assertion the suite relies on must fire."""
    _without(monkeypatch, "end_headers")
    with RestSink(status=status, reply_body=b'{"ok":1}') as sink:
        raw = _exchange(sink.port, request_bytes)
    with pytest.raises(AssertionError, match="lacks x-content-type-options"):
        _assert_floored(raw, statuses)


@pytest.mark.parametrize("request_bytes", _BARE_UNDER_THE_STDLIB)
def test_the_stdlib_alone_answers_these_bare(
    request_bytes: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the HTTP/0.9 half. With the sink's request_version override removed, the
    stdlib answers each of these with no status line, so no header block exists to carry
    anything. With it, each is a floored answer (the cases above)."""
    _without(monkeypatch, "request_version")
    with RestSink(reply_body=b'{"ok":1}') as sink:
        raw = _exchange(sink.port, request_bytes)
    assert raw, "the sink wrote nothing, so this says nothing about its form"
    assert _blocks(raw) == [], raw[:80]


def test_the_bare_control_covers_five_cases() -> None:
    assert len(_BARE_UNDER_THE_STDLIB) == 5, [case.id for case in _BARE_UNDER_THE_STDLIB]


def test_the_sink_baseline_is_the_engine_listeners() -> None:
    """The sink's copy and the listener's are separate constants across a dependency boundary. This
    is the one place a divergence turns red."""
    assert http_sink.BASELINE_RESPONSE_HEADERS == _BASELINE_RESPONSE_HEADERS
    names = {name for name, _ in http_sink.BASELINE_RESPONSE_HEADERS}
    assert {"X-Content-Type-Options", "Content-Security-Policy"} <= names
    csp = dict(http_sink.BASELINE_RESPONSE_HEADERS)["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp


def test_the_body_and_the_record_are_unchanged() -> None:
    """Adding headers changes no status, body or record."""
    with RestSink(reply_body=b'{"ok":1}') as sink:
        raw = _exchange(sink.port, _POST)
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 ") and body == b'{"ok":1}'
    assert b"Content-Type: application/json\r\n" in head + b"\r\n"
    assert b"Content-Length: 8\r\n" in head + b"\r\n"
    assert record.payload == b"{}" and record.meta["status"] == "200"
    assert "refused" not in record.meta
