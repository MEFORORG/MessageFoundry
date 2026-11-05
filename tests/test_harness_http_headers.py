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

**The case table is the sink's** (``SELF_TEST_CASES``), because the sink drives the same table
before it starts and refuses to start when an answer lacks the baseline (BACKLOG #1121; owner
ruling R1 of the vault's ``ASVS-OWNER-RULINGS-2026-10-23-BATCH340``). The tests at the end pin that
self-test: it passes on the real sink, and a sink with a header stripped does not start.

**Every case is paired with a control.** The same request against a sink whose one choke point has
been removed must be found WITHOUT the headers. A probe that cannot report absence proves nothing by
reporting presence.
"""

from __future__ import annotations

import http.server
import logging
import platform
import socket
import threading
from collections.abc import Callable
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
    stalled = request in _STALLING_REQUESTS
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
    """The baseline, once each, on every FINAL answer, and no HSTS or Server line on any block.
    An interim 1xx is not required to carry the baseline: R3 in the vault's ASVS-OWNER-RULINGS-2026-09-28-BATCH171 puts it
    outside the verb (BACKLOG #1120, #3358 item 9). The sink happens to add it there too."""
    blocks = _blocks(raw)
    assert [status for status, _ in blocks] == statuses, raw[:200]
    for status, headers in blocks:
        names = [name for name, _ in headers]
        if status >= 200:
            for name, value in _EXPECTED:
                assert (name, value) in headers, f"the {status} lacks {name}: {headers}"
                assert names.count(name) == 1, f"the {status} carries {name} more than once"
        assert HSTS_HEADER.lower() not in names, "HSTS on a cleartext loopback answer"
        assert "server" not in names, f"the {status} names the server software: {headers}"


def _is_bare(raw: bytes) -> bool:
    """Whether ``raw`` is an HTTP/0.9-form answer: something, with no header block. An empty read
    is no answer at all, so it is refused rather than counted as bare."""
    assert raw, "nothing was read, so this says nothing about the answer's form"
    return not _blocks(raw)


#: The answer families, from the sink's own table: the self-test the sink runs before every start
#: drives the same list on the running Python (BACKLOG #1121). This suite drives it with its own
#: socket code and its own parser, so the two instruments can disagree.
_CASES: list[Any] = [
    pytest.param(case.sink_status, case.request, list(case.statuses), id=case.name)
    for case in http_sink.SELF_TEST_CASES
]
_POST = next(case.request for case in http_sink.SELF_TEST_CASES if case.name == "200")
_STALLING_REQUESTS = frozenset(case.request for case in http_sink.SELF_TEST_CASES if case.stalls)


#: The cases above that SOME stdlib answers with no header block at all, by id, each with the
#: statuses the sink must answer it with. Which of them a given Python answers bare is observed by
#: the control below, never assumed. The sink's request_version comment says which patch levels
#: were read.
_BARE_ON_SOME_PYTHON = [
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


def _change_handler(monkeypatch: pytest.MonkeyPatch, change: Callable[[Any], None]) -> None:
    """Apply ``change`` to every handler class the sink module builds, the self-test's included."""
    real = http_sink._handler_for

    def _changed(sink: Any, **kwargs: Any) -> Any:
        handler = real(sink, **kwargs)
        change(handler)
        return handler

    monkeypatch.setattr(http_sink, "_handler_for", _changed)


def _without(monkeypatch: pytest.MonkeyPatch, override: str) -> None:
    """Remove one of the sink handler's overrides, leaving the stdlib's own behaviour there."""
    _change_handler(monkeypatch, lambda handler: delattr(handler, override))
    # The controls build a sink missing an override on purpose, which is what the self-test exists
    # to refuse. The tests at the end of this file pin that refusal.
    monkeypatch.setattr(http_sink, "self_test", lambda: None)


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


@pytest.mark.parametrize(("request_bytes", "statuses"), _BARE_ON_SOME_PYTHON)
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
    bare_on_this_python = _is_bare(_plain_stdlib_answer(request_bytes))
    _assert_floored(_answer(monkeypatch, request_bytes), statuses)

    _without(monkeypatch, "request_version")
    raw = _answer(monkeypatch, request_bytes)
    if bare_on_this_python:
        assert _is_bare(raw), raw[:80]
    else:
        _assert_floored(raw, statuses)


def test_the_bare_control_covers_seven_cases() -> None:
    assert len(_BARE_ON_SOME_PYTHON) == 7, [case.id for case in _BARE_ON_SOME_PYTHON]


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
    requests = {case.id: cast(bytes, case.values[0]) for case in _BARE_ON_SOME_PYTHON}
    for case_id in _BARE_ON_EVERY_PYTHON_READ:
        assert case_id in requests, f"{case_id} is no longer among the bare-on-some cases"
        assert _is_bare(_plain_stdlib_answer(requests[case_id])), (
            f"Python {platform.python_version()} answers {case_id} unbare"
        )


@pytest.mark.parametrize(("request_bytes", "statuses"), _BARE_ON_SOME_PYTHON)
def test_an_answer_some_stdlib_writes_bare_has_a_status_line(
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
    assert b"<" in body, body[:80]


_MARKUP_REQUEST_LINE = b"GET /a<b>&c HTTP/x&<\r\n"


def test_a_stdlib_error_page_body_does_not_echo_the_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stdlib puts the bad part of a request line in its reason phrase. The plain-text body
    leaves that out, so markup in the request reaches the body neither raw nor as entities. The
    status line still carries the phrase as the stdlib writes it; this test is about the body."""
    raw = _answer(monkeypatch, _MARKUP_REQUEST_LINE)
    assert raw.startswith(b"HTTP/1.1 400 "), raw[:80]
    _, body = _error_page(raw)
    assert body.startswith(b"400 ") and b"<" not in body and b"&" not in body, body


def test_the_stdlib_error_page_body_echoes_the_request_without_the_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the stdlib's own format puts the escaped request bytes in the body."""
    _without(monkeypatch, "error_message_format")
    _, body = _error_page(_answer(monkeypatch, _MARKUP_REQUEST_LINE))
    assert b"&lt;" in body, body


def test_the_error_page_cases_cover_every_stdlib_error_class() -> None:
    """At least the 400, 414, 431 (both paths), 501 and 505 that BACKLOG #1120 drives."""
    ids = [case.id for case in _STDLIB_ERROR_PAGES]
    assert len(ids) == 9, ids
    finals = {cast(list[int], case.values[1])[-1] for case in _STDLIB_ERROR_PAGES}
    assert {400, 414, 431, 501, 505} <= finals


def test_the_stdlib_names_the_server_software_without_the_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the Server line _assert_floored refuses (BACKLOG #3358 item 8): without the
    sink's send_header filter the stdlib adds one, naming the Python version, and the assertion
    the suite relies on fires."""
    _without(monkeypatch, "send_header")
    raw = _answer(monkeypatch, _POST)
    ((_, headers),) = _blocks(raw)
    assert "Python/" in dict(headers).get("server", ""), headers
    with pytest.raises(AssertionError, match="names the server software"):
        _assert_floored(raw, [200])


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


# --- the self-test the sink runs before it starts (BACKLOG #1121, owner ruling R1) ----------------


def test_the_case_table_names_every_answer_family() -> None:
    """The self-test drives exactly this table, so a case dropped from it would leave that answer
    family unchecked on a new Python. This pin is where a drop turns red."""
    assert [case.name for case in http_sink.SELF_TEST_CASES] == [
        "200",
        "configured-400",
        "configured-503",
        "get",
        "head",
        "413-over-cap",
        "411-no-length",
        "400-transfer-encoding",
        "408-stalled-body",
        "stdlib-400-malformed",
        "stdlib-501-method",
        "stdlib-505-version",
        "stdlib-414-long-line",
        "stdlib-431-long-header",
        "stdlib-431-many-headers",
        "stdlib-100-continue",
        "http-0.9-two-word-request",
        "http-0.9-named-version",
        "http-0.9-stdlib-501",
        "http-0.9-one-word-line",
        "http-0.9-two-word-not-get",
    ]


def test_the_self_test_passes_on_the_real_sink(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """On the running Python, every case is driven and none is refused."""
    driven: list[str] = []
    real_probe = http_sink._probe

    def _counting(case: http_sink.SelfTestCase) -> list[str]:
        driven.append(case.name)
        return real_probe(case)

    monkeypatch.setattr(http_sink, "_probe", _counting)
    with caplog.at_level(logging.ERROR, logger=http_sink.__name__):
        http_sink.self_test()
    assert sorted(driven) == sorted(case.name for case in http_sink.SELF_TEST_CASES)
    assert not caplog.records, caplog.text


def _refusal(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> str:
    """Start a sink, which must refuse before its own port is bound; return the refusal."""
    names: list[str] = []
    real_listen = http_sink._listen

    def _recording(*args: Any, **kwargs: Any) -> Any:
        names.append(args[3])
        return real_listen(*args, **kwargs)

    monkeypatch.setattr(http_sink, "_listen", _recording)
    sink = RestSink()
    with (
        caplog.at_level(logging.ERROR, logger=http_sink.__name__),
        pytest.raises(http_sink.SinkSelfTestError) as refused,
    ):
        sink.start()
    assert names and set(names) == {"harness-http-sink-self-test"}, names
    assert sink._server is None and sink.port == 0
    assert [record.getMessage() for record in caplog.records] == [str(refused.value)]
    return str(refused.value)


@pytest.mark.parametrize("header", [name for name, _ in http_sink.BASELINE_RESPONSE_HEADERS])
def test_a_sink_that_strips_a_baseline_header_refuses_to_start(
    header: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _strip(handler: Any) -> None:
        send_header = handler.send_header

        def _stripped(self: Any, keyword: str, value: str) -> None:
            if keyword.lower() != header.lower():
                send_header(self, keyword, value)

        handler.send_header = _stripped

    _change_handler(monkeypatch, _strip)
    message = _refusal(monkeypatch, caplog)
    assert f"lacks {header}:" in message, message
    # Every final answer goes through the one choke point, so every case is named.
    for case in http_sink.SELF_TEST_CASES:
        assert f"{case.name}: " in message, case.name
    if header == "Content-Security-Policy":
        assert "names no frame-ancestors 'none' policy" in message


@pytest.mark.parametrize("override", ["end_headers", "request_version"])
def test_a_sink_missing_an_override_refuses_to_start(
    override: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Without end_headers no answer carries the baseline. Without request_version the stdlib's
    HTTP/0.9-form answers have nowhere to carry it: at least the cases every CPython read so far
    answers bare (``_BARE_ON_EVERY_PYTHON_READ``) are refused."""
    _change_handler(monkeypatch, lambda handler: delattr(handler, override))
    message = _refusal(monkeypatch, caplog)
    if override == "request_version":
        for case_id in _BARE_ON_EVERY_PYTHON_READ:
            assert f"{case_id}: the answer has no final status line" in message, message


def test_a_baseline_whose_policy_allows_framing_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The frame-ancestors check reads the answer, not the constant: a baseline edited to drop the
    directive is sent faithfully, and still refused."""
    weakened = tuple(
        (name, "base-uri 'none'" if name == "Content-Security-Policy" else value)
        for name, value in http_sink.BASELINE_RESPONSE_HEADERS
    )
    monkeypatch.setattr(http_sink, "BASELINE_RESPONSE_HEADERS", weakened)
    message = _refusal(monkeypatch, caplog)
    assert "names no frame-ancestors 'none' policy" in message
    assert "lacks " not in message, message


@pytest.mark.parametrize(
    ("policy", "denies"),
    [
        ("frame-ancestors 'none'; base-uri 'none'", True),
        ("base-uri 'none';  FRAME-ANCESTORS 'NONE' ;", True),
        ("frame-ancestors 'self'", False),
        ("frame-ancestors 'none' https://a.example", False),
        ("frame-ancestors 'self'; frame-ancestors 'none'", False),
        ("default-src 'none'", False),
        ("report-uri /frame-ancestors 'none'", False),
        ("", False),
    ],
)
def test_the_frame_ancestors_check_parses_directives(policy: str, denies: bool) -> None:
    assert http_sink._csp_denies_framing(policy) is denies
