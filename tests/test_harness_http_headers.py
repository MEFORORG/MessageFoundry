# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every response the harness HTTP sink writes carries the baseline security headers (BACKLOG #1120;
ASVS 3.4.4 and 3.4.6, and the base-uri part of 3.4.3).

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

import http.client
import http.server
import platform
import socket
import threading
from typing import Any, cast

import pytest

from harness.sinks import _http as http_sink
from harness.sinks.rest import RestSink
from messagefoundry.api.header_floor import HSTS_HEADER
from messagefoundry.transports.http_listener import _BASELINE_RESPONSE_HEADERS

_Block = tuple[int, list[tuple[str, str]]]

#: What must be on every answer: the listener's baseline, which names nosniff and a CSP.
_EXPECTED = [(name.lower(), value) for name, value in _BASELINE_RESPONSE_HEADERS]


def _exchange(port: int, request: bytes, *, half_close: bool) -> bytes:
    """Send raw bytes and read until the sink closes the connection. ``half_close`` tells the sink
    no more is coming, so a refusal that discards the rest of the request ends at once and not on
    the read timeout."""
    with socket.create_connection(("127.0.0.1", port), 5.0) as conn:
        conn.sendall(request)
        if half_close:
            conn.shutdown(socket.SHUT_WR)
        chunks = []
        try:
            while chunk := conn.recv(65536):
                chunks.append(chunk)
        except ConnectionError:
            # The sink closed with unread input still queued. What arrived is the answer; with
            # nothing arrived, the reset is the finding, and it is raised as itself.
            if not chunks:
                raise
    return b"".join(chunks)


def _answer(monkeypatch: pytest.MonkeyPatch, request: bytes, status: int = 200) -> bytes:
    """What a fresh sink writes back for ``request``. Only the stalled-body case shortens the read
    timeout and keeps its side open: every other case leaves the sink its normal five seconds."""
    stalled = request is _STALLED_BODY
    if stalled:
        monkeypatch.setattr(http_sink, "READ_TIMEOUT_SECONDS", 0.3)
    with RestSink(status=status, reply_body=b'{"ok":1}') as sink:
        return _exchange(sink.port, request, half_close=not stalled)


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

#: Declares a hundred bytes and sends ten, then waits: the sink's 408.
_STALLED_BODY = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nonly ten b"

#: The longest line the stdlib reads. http.client holds it as the private _MAXLINE for a header
#: line, and http/server.py spells the same 65536 as a literal for the request line. A release
#: that raises either leaves the 414 or 431 case waiting for bytes that never come.
_STDLIB_LINE_LIMIT: int = getattr(http.client, "_MAXLINE", 65536)
_GET_LINE = b"GET /x HTTP/1.1\r\n"
_LONG_REQUEST_LINE = b"GET /".ljust(_STDLIB_LINE_LIMIT + 1, b"a")
_LONG_HEADER_LINE = b"X-Long: ".ljust(_STDLIB_LINE_LIMIT + 1, b"a")

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
    pytest.param(200, _STALLED_BODY, [408], id="408-stalled-body"),
    # --- answers the stdlib handler writes itself, before the sink's handler runs --------------
    #
    # The stdlib answers these and closes without draining, and a close with input still unread
    # can reset the connection and discard the answer before this client reads it. So each one,
    # and each HTTP/0.9 case below, ends where the stdlib stops reading on Python 3.14: after the
    # request line when it answers from that line alone, after the blank line when it reads
    # headers first.
    pytest.param(200, b"NOT A REQUEST\r\n", [400], id="stdlib-400-malformed"),
    pytest.param(200, b"BREW /x HTTP/1.1\r\nHost: x\r\n\r\n", [501], id="stdlib-501-method"),
    pytest.param(200, b"GET /x HTTP/3.0\r\n", [505], id="stdlib-505-version"),
    pytest.param(200, _LONG_REQUEST_LINE, [414], id="stdlib-414-long-line"),
    pytest.param(200, _GET_LINE + _LONG_HEADER_LINE, [431], id="stdlib-431-long-header"),
    pytest.param(
        200,
        b"POST /x HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}",
        [100, 200],
        id="stdlib-100-continue",
    ),
    # An HTTP/0.9 answer has no status line and no header block, so there would be nowhere to
    # put the headers. Which of these the stdlib answers that way depends on the Python patch
    # level; _BARE_UNDER_THE_STDLIB below says how. The sink answers each with a status line and
    # a header block.
    pytest.param(200, b"GET /x\r\n", [200], id="http-0.9-two-word-request"),
    pytest.param(200, b"GET /x HTTP/0.9\r\n\r\n", [200], id="http-0.9-named-version"),
    pytest.param(200, b"BREW /x HTTP/0.9\r\n\r\n", [501], id="http-0.9-stdlib-501"),
    pytest.param(200, b"FOO\r\n", [400], id="http-0.9-one-word-line"),
    pytest.param(200, b"POST /x\r\n", [400], id="http-0.9-two-word-not-get"),
]

#: The cases above that SOME stdlib answers with no header block at all, by id, each with the
#: statuses the sink must answer it with. Which of them a given Python answers bare is observed by
#: the control below, never assumed: CPython 3.14.6 answers all seven bare. 3.14.8 no longer
#: leaves request_version at "HTTP/0.9" on four of those paths (the bad version, the 505, the
#: one-word line and the two-word line that is not a GET), so it answers them with a status line
#: of its own.
_BARE_UNDER_THE_STDLIB = [
    pytest.param(case.values[1], case.values[2], id=case.id)
    for case in _CASES
    if case.id in ("stdlib-400-malformed", "stdlib-505-version") or case.id.startswith("http-0.9-")
]


class _PlainHandler(http.server.BaseHTTPRequestHandler):
    """The stdlib handler with nothing of the sink's: the reference for what this Python does."""

    protocol_version = "HTTP/1.1"
    timeout = 5.0

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002  (stdlib name)
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
        self.close_connection = True


def _plain_stdlib_answer(request: bytes) -> bytes:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PlainHandler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        return _exchange(int(server.server_address[1]), request, half_close=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
    status: int, request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    _assert_floored(_answer(monkeypatch, request_bytes, status), statuses)


@pytest.mark.parametrize(("status", "request_bytes", "statuses"), _CASES)
def test_the_probe_sees_absence_when_the_choke_point_is_removed(
    status: int, request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control. One override puts the headers on every case above, so removing it must leave
    every case bare, and the assertion the suite relies on must fire."""
    _without(monkeypatch, "end_headers")
    raw = _answer(monkeypatch, request_bytes, status)
    with pytest.raises(AssertionError, match="lacks x-content-type-options"):
        _assert_floored(raw, statuses)


@pytest.mark.parametrize(("request_bytes", "statuses"), _BARE_UNDER_THE_STDLIB)
def test_the_request_version_override_is_what_gives_a_bare_answer_its_headers(
    request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the HTTP/0.9 half, and it OBSERVES what this Python's stdlib does.

    A plain stdlib handler, with nothing of the sink's in it, is asked first. That is the
    reference: bare on this Python, or not. The sink's answer is then asserted, on every Python:
    the baseline, each header once. Last, the same request goes to a sink whose request_version
    override is removed, and its answer must have the form the plain handler's had. Bare there
    means the override is what made the difference. A status line there means this Python's stdlib
    writes the header block itself, and end_headers must then floor it once, with nothing doubled.
    Either way the test passes or fails; it never skips, and a broken removal fails on a Python
    whose stdlib is bare."""
    bare_on_this_python = not _blocks(_plain_stdlib_answer(request_bytes))
    _assert_floored(_answer(monkeypatch, request_bytes), statuses)

    _without(monkeypatch, "request_version")
    raw = _answer(monkeypatch, request_bytes)
    assert raw, "the sink wrote nothing, so this says nothing about its form"
    if bare_on_this_python:
        assert _blocks(raw) == [], raw[:80]
    else:
        _assert_floored(raw, statuses)


def test_the_bare_control_covers_seven_cases() -> None:
    assert len(_BARE_UNDER_THE_STDLIB) == 7, [case.id for case in _BARE_UNDER_THE_STDLIB]


#: The cases a plain stdlib handler answers bare on every CPython read so far: 3.14.6 by running
#: it, 3.14.8 by its source. Each is a request the stdlib accepts as HTTP/0.9.
_BARE_ON_EVERY_PYTHON_READ = (
    "http-0.9-two-word-request",
    "http-0.9-named-version",
    "http-0.9-stdlib-501",
)


def test_the_stdlib_still_answers_http_0_9_requests_bare() -> None:
    """So the control above cannot drift to all-status-line unnoticed. If a case here stops being
    bare, the stdlib changed again: re-read it, and if none is bare, the override can go."""
    bare = [
        case.id
        for case in _BARE_UNDER_THE_STDLIB
        if not _blocks(_plain_stdlib_answer(cast(bytes, case.values[0])))
    ]
    for case_id in _BARE_ON_EVERY_PYTHON_READ:
        assert case_id in bare, f"Python {platform.python_version()} answers {case_id} unbare"


@pytest.mark.parametrize(("request_bytes", "statuses"), _BARE_UNDER_THE_STDLIB)
def test_an_answer_the_stdlib_would_write_bare_has_a_status_line(
    request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The status line names the handler's protocol_version, HTTP/1.1, whatever the request said,
    and the status the case expects."""
    expected = f"HTTP/1.1 {statuses[0]} ".encode()
    assert _answer(monkeypatch, request_bytes).startswith(expected)


#: The cases above whose final answer is an error page the stdlib writes through send_error, by id.
#: The sink's own refusals are not here: they go through _serve and carry no body.
_STDLIB_ERROR_PAGES = [
    pytest.param(case.values[1], case.values[2], id=case.id)
    for case in _CASES
    if case.id.startswith(("stdlib-", "http-0.9-")) and case.values[2][-1] >= 400
]


def _error_page(raw: bytes) -> tuple[str, bytes]:
    """(Content-Type, body) of the one answer in ``raw``."""
    ((_, headers),) = _blocks(raw)
    _, _, body = raw.partition(b"\r\n\r\n")
    return dict(headers).get("content-type", ""), body


@pytest.mark.parametrize(("request_bytes", "statuses"), _STDLIB_ERROR_PAGES)
def test_a_stdlib_error_page_is_plain_text(
    request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stdlib's own error answers are text/plain, so nothing in them is rendered as HTML."""
    content_type, body = _error_page(_answer(monkeypatch, request_bytes))
    assert content_type == "text/plain; charset=utf-8", content_type
    assert body.startswith(f"{statuses[-1]} ".encode()), body[:80]
    assert b"<" not in body, body[:80]


@pytest.mark.parametrize(("request_bytes", "statuses"), _STDLIB_ERROR_PAGES)
def test_the_stdlib_error_page_is_html_without_the_override(
    request_bytes: bytes, statuses: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with the two overrides removed, the same request gets the stdlib's HTML page."""
    _without(monkeypatch, "error_content_type")
    _without(monkeypatch, "error_message_format")
    content_type, body = _error_page(_answer(monkeypatch, request_bytes))
    assert content_type.startswith("text/html"), content_type
    assert body.lstrip().startswith(b"<!DOCTYPE HTML>"), body[:80]


def test_the_error_page_cases_cover_every_stdlib_error_class() -> None:
    """At least the 400, 414 and 501 the brief names, and the 431 and 505 beside them."""
    ids = [case.id for case in _STDLIB_ERROR_PAGES]
    assert len(ids) == 8, ids
    finals = {cast(list[int], case.values[1])[-1] for case in _STDLIB_ERROR_PAGES}
    assert {400, 414, 431, 501, 505} <= finals


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
        raw = _exchange(sink.port, _POST, half_close=True)
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 ") and body == b'{"ok":1}'
    assert b"Content-Type: application/json\r\n" in head + b"\r\n"
    assert b"Content-Length: 8\r\n" in head + b"\r\n"
    assert record.payload == b"{}" and record.meta["status"] == "200"
    assert "refused" not in record.meta
