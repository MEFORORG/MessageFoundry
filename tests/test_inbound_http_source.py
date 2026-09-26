# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Inbound HTTP listen source (ADR 0023): body-POST -> ingress, 202 respond-with-receipt-after-commit,
content_type payload selection, the oversize/malformed/allowlist/slow-loris pre-ingress refusals (each
emitting a metadata-only connection_event), the TLS/allowlist wiring guards, and bounded teardown.

Modeled on ``MLLPSource``: the source binds its own loopback socket, decodes the POSTed body, hands it
to the pipeline handler that commits it to the ingress stage and returns the engine message_id, and the
source maps that to a ``202`` BEFORE any routing/transform runs. Synthetic, PHI-free payloads only.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.config.wiring import (
    Http,
    WiringError,
    build_inbound_connection,
)
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    _source_config,
    check_http_tls_exposure,
)
from messagefoundry.store.store import MessageStatus, MessageStore, Stage
from messagefoundry.transports import http_listener as http_mod
from messagefoundry.transports.base import build_source
from messagefoundry.transports.http_listener import (
    _BASELINE_RESPONSE_HEADERS,
    DEFAULT_MAX_BODY_BYTES,
    HttpRequestError,
    HttpSource,
    _read_body,
    _read_head,
    _read_request,
    _status_line,
    build_response,
)

HL7 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
JSON_BODY = '{"mrn": "100", "type": "obs"}'


# --- a tiny raw HTTP client over the loopback socket -------------------------


class _Response:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


async def _http(
    port: int,
    *,
    method: str = "POST",
    target: str = "/ingest",
    body: bytes = b"",
    extra_headers: dict[str, str] | None = None,
    raw_override: bytes | None = None,
    half_close: bool = False,
) -> _Response:
    """Open one connection, send a request, read the full response (Connection: close).

    ``half_close`` sends a TCP FIN right after the request bytes (via ``write_eof``) while the read
    side stays open — simulating a peer that stops mid-body rather than one that never connects, so
    the server's ``readexactly`` sees a real EOF instead of blocking for more bytes that never come.
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        if raw_override is not None:
            writer.write(raw_override)
        else:
            head = [f"{method} {target} HTTP/1.1", "Host: localhost"]
            if method in ("POST", "PUT", "PATCH"):
                head.append(f"Content-Length: {len(body)}")
            for k, v in (extra_headers or {}).items():
                head.append(f"{k}: {v}")
            head.extend(["", ""])
            writer.write("\r\n".join(head).encode("ascii") + body)
        await writer.drain()
        if half_close:
            writer.write_eof()
        try:
            data = await asyncio.wait_for(reader.read(-1), 5.0)  # read to EOF
        except (ConnectionResetError, OSError):
            data = b""  # a refused connection may reset mid-read on the Windows Proactor loop
    finally:
        writer.close()
        try:  # noqa: SIM105
            await writer.wait_closed()
        except OSError:
            pass
    head_bytes, _, resp_body = data.partition(b"\r\n\r\n")
    if not head_bytes:
        # A refused connection may be reset before its 4xx flushes on the Windows Proactor loop; the
        # refusal is asserted via the connection_event + the absent ingress row, not this status.
        return _Response(0, {}, b"")
    lines = head_bytes.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return _Response(status, headers, resp_body)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "http.db")
    yield s
    await s.close()


async def _runner(store: MessageStore, ic) -> RegistryRunner:
    from messagefoundry.config.wiring import Registry

    reg = Registry()
    reg.add_inbound(ic)
    return RegistryRunner(reg, store)


async def _start_source(
    store: MessageStore, ic, *, events: list[tuple] | None = None
) -> HttpSource:
    """Build + start the HTTP source for ``ic`` with the runner's HTTP receipt handler wired in (so the
    202 carries the committed message_id), optionally capturing connection events into ``events``."""
    runner = await _runner(store, ic)
    cfg = _source_config(ic, "127.0.0.1", {})
    cfg.settings["port"] = 0  # ephemeral test port
    source = build_source(cfg)
    assert isinstance(source, HttpSource)
    if events is not None:

        async def sink(kind: str, peer_host: str | None, reason: str | None) -> None:
            events.append((kind, peer_host, reason))

        source.on_connection_event = sink
    await source.start(runner._make_http_handler(ic))
    return source


# --- AC-1 + AC-2: POST -> ingress, 202 respond-with-receipt-after-commit ------


async def test_post_body_enqueues_ingress(store: MessageStore) -> None:
    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    try:
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src.stop()
    assert resp.status == 202
    # The body was durably committed to the ingress stage BEFORE the response (count-and-log).
    cur = await store._db.execute("SELECT id, status, raw FROM messages")
    rows = await cur.fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value
    assert rows[0]["raw"] == JSON_BODY


async def test_respond_with_receipt_on_ingress(store: MessageStore) -> None:
    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    try:
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src.stop()
    assert resp.status == 202
    payload = resp.json()
    assert payload["status"] == "accepted"
    # The receipt carries the engine message_id (AC-2), returned the instant ingress committed.
    msg = await store.get_message(payload["message_id"])
    assert msg["status"] == MessageStatus.RECEIVED.value


async def test_post_ingress_failure_does_not_change_http_status(store: MessageStore) -> None:
    """AC-3: the 202 is returned at ingress, BEFORE any routing/transform runs — no worker is draining
    here, so a downstream failure (which would happen later) cannot retroactively change the status."""
    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="missing_router", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    try:
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src.stop()
    # Receipt returned even though no router/worker exists to process it (post-ingress is decoupled).
    assert resp.status == 202
    # Exactly one ingress row, still RECEIVED — routing never ran in the synchronous response path.
    cur = await store._db.execute(
        "SELECT stage FROM queue WHERE message_id=?", (resp.json()["message_id"],)
    )
    rows = await cur.fetchall()
    assert [r["stage"] for r in rows] == [Stage.INGRESS.value]


# --- AC-6: content_type selects the payload object ---------------------------


async def test_content_type_selects_payload_object(store: MessageStore) -> None:
    # hl7v2 over HTTP commits the HL7 control id + message type (the HL7 path ran); json does not.
    ic_hl7 = build_inbound_connection("IB_H", Http(port=0), router="r")  # default hl7v2
    src = await _start_source(store, ic_hl7)
    try:
        resp = await _http(src.sockport, body=HL7.encode("utf-8"))
    finally:
        await src.stop()
    assert resp.status == 202
    msg = await store.get_message(resp.json()["message_id"])
    assert msg["control_id"] == "MSG1" and msg["message_type"] == "ADT^A01"

    ic_json = build_inbound_connection(
        "IB_J", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src2 = await _start_source(store, ic_json)
    try:
        resp2 = await _http(src2.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src2.stop()
    msg2 = await store.get_message(resp2.json()["message_id"])
    assert msg2["raw"] == JSON_BODY  # routed verbatim as a RawMessage body (no HL7 parse)
    assert msg2["control_id"] is None


# --- health probe: GET/HEAD do not write an ingress row ----------------------


async def test_get_health_probe_no_ingress_row(store: MessageStore) -> None:
    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    try:
        resp = await _http(src.sockport, method="GET", target="/health")
    finally:
        await src.stop()
    assert resp.status == 200
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0


# --- oversize / malformed refused + connection_event (AC-5 shape) ------------


async def test_oversize_body_refused_and_event(store: MessageStore) -> None:
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0, max_body_bytes=16),
        router="r",
        content_type=ContentType.TEXT,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        resp = await _http(
            src.sockport, body=b"x" * 64
        )  # declared Content-Length over the 16-byte cap
    finally:
        await src.stop()
    assert resp.status == 413
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0  # refused BEFORE any ingress row
    assert any(kind == "frame_oversize" for kind, *_ in events)


async def test_malformed_request_refused_and_event(store: MessageStore) -> None:
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0),
        router="r",
        content_type=ContentType.TEXT,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        # A request line with no HTTP version, then a blank-line terminator.
        resp = await _http(src.sockport, raw_override=b"GET\r\n\r\n")
    finally:
        await src.stop()
    assert resp.status == 400
    assert any(kind == "framing_error" for kind, *_ in events)


async def test_incomplete_declared_body_refused_and_event(store: MessageStore) -> None:
    """A POST declares a larger Content-Length than it actually sends, then closes -- a broken
    framing declaration on the body side, the twin of the header framing refusals above. It must
    not flow on to become an ingress row and a 202 receipt for a body shorter than declared
    (BACKLOG #1657)."""
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0),
        router="r",
        content_type=ContentType.TEXT,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        # Declares 100 bytes, sends 5, then half-closes -- the server's readexactly sees a real EOF.
        resp = await _http(
            src.sockport,
            raw_override=b"POST /ingest HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\nshort",
            half_close=True,
        )
    finally:
        await src.stop()
    assert resp.status == 400
    assert any(kind == "framing_error" for kind, *_ in events)
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0  # refused BEFORE any ingress row -- no handler ran


# --- AC-5: peer-IP allowlist refuse + connection_event -----------------------


async def test_ip_allowlist_refuse_and_connection_event(store: MessageStore) -> None:
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0),
        router="r",
        content_type=ContentType.JSON,
        source_ip_allowlist=["10.0.0.1"],  # the loopback test peer (127.0.0.1) is NOT listed
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src.stop()
    assert resp.status in (403, 0)  # 403 when it flushed; 0 = reset before flush (Windows Proactor)
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0  # fail-closed: never reached ingress
    assert any(kind == "peer_not_allowlisted" for kind, *_ in events)


async def test_allowlisted_peer_accepted(store: MessageStore) -> None:
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0),
        router="r",
        content_type=ContentType.JSON,
        source_ip_allowlist=["127.0.0.1"],
    )
    src = await _start_source(store, ic)
    try:
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src.stop()
    assert resp.status == 202  # loopback peer is allowlisted -> committed


# --- AC-7: bounded teardown --------------------------------------------------


async def test_stop_is_bounded(store: MessageStore) -> None:
    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    # Open a client and leave it idle (no request) — stop() must still return promptly.
    reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        await asyncio.wait_for(src.stop(), 8.0)  # must not hang on the established client
    finally:
        writer.close()
        try:  # noqa: SIM105
            await writer.wait_closed()
        except OSError:
            pass


# --- AC-4 + wiring guards (exposed-gate / TLS / host rejection) --------------


def test_exposed_without_tls_refused() -> None:
    ic = build_inbound_connection("IB_HTTP", Http(port=8080), router="r")
    cfg = _source_config(ic, "0.0.0.0", {})  # non-loopback service bind_host
    with pytest.raises(WiringError, match="without TLS"):
        check_http_tls_exposure(cfg, "IB_HTTP", allow_insecure_bind=False)


def test_exposed_with_tls_passes() -> None:
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=8080, tls=True, tls_cert_file="c.pem", tls_key_file="k.pem"),
        router="r",
    )
    cfg = _source_config(ic, "0.0.0.0", {})
    check_http_tls_exposure(cfg, "IB_HTTP", allow_insecure_bind=False)  # no raise


def test_loopback_without_tls_passes() -> None:
    ic = build_inbound_connection("IB_HTTP", Http(port=8080), router="r")
    cfg = _source_config(ic, "127.0.0.1", {})
    check_http_tls_exposure(cfg, "IB_HTTP", allow_insecure_bind=False)  # loopback is fine plaintext


def test_http_inbound_rejects_host() -> None:
    spec = Http(port=8080)
    spec.settings["host"] = "0.0.0.0"  # an author can't set the bind interface on an inbound
    with pytest.raises(WiringError, match="takes no host"):
        build_inbound_connection("IB_HTTP", spec, router="r")


# --- unit: the request reader's caps + parsing -------------------------------


async def _reader_from(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def test_read_request_parses_post() -> None:
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"
    req = await _read_request(
        await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
    )
    assert req.method == "POST" and req.target == "/x" and req.body == b"abc"


async def test_read_request_rejects_declared_oversize() -> None:
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(await _reader_from(raw), max_header_bytes=8192, max_body_bytes=16)
    assert exc.value.status == 413 and exc.value.kind == "frame_oversize"


async def test_read_request_rejects_chunked() -> None:
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400


async def test_read_request_rejects_duplicate_content_length() -> None:  # DELTA-06
    # Two Content-Length headers are an ambiguous-framing / request-smuggling signal (a dict would
    # silently keep the last); reject rather than pick one.
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400 and exc.value.kind == "framing_error"


async def test_read_request_rejects_content_length_with_transfer_encoding() -> None:  # DELTA-06
    # Both Content-Length and Transfer-Encoding present: RFC 7230 §3.3.3 mandates rejection.
    raw = (
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"
    )
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400 and exc.value.kind == "framing_error"


async def test_read_request_rejects_duplicate_transfer_encoding() -> None:  # DELTA-06
    # A duplicated Transfer-Encoding is how an obfuscated encoding is smuggled past the chunked check.
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400 and exc.value.kind == "framing_error"


async def test_read_request_allows_single_content_length_get() -> None:
    # Regression: a lone Content-Length (no duplicate, no Transfer-Encoding) is still accepted.
    raw = b"GET /health HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
    req = await _read_request(
        await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
    )
    assert req.method == "GET" and req.body == b""


async def test_read_head_returns_before_the_body_arrives() -> None:
    # The point of the ADR 0154 D6 split, and the only way AC-11's "before any request body byte is
    # read" is satisfiable. This head DECLARES a 1 MiB body and never sends a byte of it; if
    # _read_head waited on the body — as the combined _read_request does — this would hang until the
    # timeout instead of handing back a request whose credentials can be checked.
    reader = asyncio.StreamReader()
    reader.feed_data(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1048576\r\n\r\n")
    head = await asyncio.wait_for(_read_head(reader, max_header_bytes=8192), 2.0)
    assert head.method == "POST"
    assert head.body == b""


async def test_read_head_then_read_body_reassembles_the_request() -> None:
    # The halves compose losslessly: the head read must not consume or discard the body.
    reader = await _reader_from(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nHELLO")
    head = await _read_head(reader, max_header_bytes=8192)
    assert head.body == b""
    assert await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES) == b"HELLO"


async def test_read_body_rejects_incomplete_declared_body() -> None:  # BACKLOG #1657
    # Content-Length declares 10 bytes; the peer sends 5 and the stream ends there (feed_eof). Must
    # raise rather than silently return the short bytes -- a truncated body must not become an
    # ingress row and a 202 for a peer that broke its own declared framing.
    reader = await _reader_from(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nshort")
    head = await _read_head(reader, max_header_bytes=8192)
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES)
    assert excinfo.value.status == 400 and excinfo.value.kind == "framing_error"


async def test_framing_is_decided_for_every_method_in_the_head_phase() -> None:
    """THE ORDERING THIS ONCE PINNED WAS DELIBERATELY REVERSED (BACKLOG #1125, ASVS 4.2.1).

    This test used to assert the opposite, and its comment warned that hoisting the refusal "would
    look like hardening and would change shipped behaviour". That was a fair warning and it worked:
    it turned an edit into a decision. The decision went to adversarial review, which measured that
    a GET carrying framing headers left its declared bytes unread on the socket, and that the
    authoring commit (`f2ef0ea92`, the ADR 0154 intake-auth increment) names no ruling and no
    incident -- it was change-control caution, not a requirement.

    RFC 9112 makes framing a property of the MESSAGE, not of the method, so it is now settled in
    `_read_head` for every method before dispatch. Rewritten rather than deleted, so the reversal is
    recorded where the next reader will look for it.
    """
    # A bodyless method carrying Transfer-Encoding is now REFUSED, in the head phase.
    reader = await _reader_from(
        b"GET /health HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 400

    # ... and so is a POST carrying it, now also in the head phase rather than the body phase.
    reader = await _reader_from(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 400

    # REFUSE, NEVER CONSUME -- and this is the carve-out that keeps a health checker green.
    # `Content-Length: 0` on a bodyless method declares no body, desyncs nothing, and is the one
    # shape this tree actually exercises (test_read_request_allows_single_content_length_get).
    reader = await _reader_from(b"GET /health HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n")
    head = await _read_head(reader, max_header_bytes=8192)
    assert await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES) == b""

    # ... while a NON-ZERO length on the same method is refused: those are the declared bytes that
    # would otherwise sit on the wire for a pooling front end to read as a second request.
    reader = await _reader_from(
        b"GET /health HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nHELLO"
    )
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 400


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        # Transfer-Encoding is refused by PRESENCE. Exact equality on "chunked" measurably missed
        # all three of these, and they reached the POST path and were ingested as clinical payload.
        (
            "te gzip,chunked",
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        ),
        ("te trailing comma", b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked,\r\n\r\n"),
        ("te identity", b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity\r\n\r\n"),
        # Content-Length is 1*DIGIT, not int(). int() takes a leading plus and PEP 515 underscores,
        # so "1_0" framed TEN bytes against a proxy that would have read one.
        ("cl leading plus", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +3\r\n\r\nabc"),
        ("cl underscore", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1_0\r\n\r\n0123456789"),
        # Whitespace before the colon is a MUST-reject: strip() turned this into valid framing,
        # which is the shape a strict proxy drops and a lenient origin honours.
        ("space before colon", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length : 3\r\n\r\nabc"),
        # A bare LF fused two headers into one and the Content-Length VANISHED from the dict, so
        # both framing guards inspected a request whose framing header they could no longer see.
        ("bare lf in head", b"POST / HTTP/1.1\r\nHost: h\nContent-Length: 3\r\n\r\nabc"),
        # ... and a bare LF in the request line left the header dict EMPTY while the body was read.
        ("bare lf request line", b"POST /x HTTP/1.1\nHost: h\r\n\r\n"),
        # HTTP-version is DIGIT "." DIGIT; a startswith("HTTP/") test accepted this.
        ("non-token version", b"POST / HTTP/1.1x\r\nHost: h\r\n\r\n"),
        # An obs-fold continuation line. `.strip()` read it as a real Content-Length, while a proxy
        # that unfolds reads it as more of the Host value (RFC 9112 section 5.2).
        (
            "obs-fold framing header",
            b"POST / HTTP/1.1\r\nHost: h\r\n Content-Length: 3\r\n\r\nabc",
        ),
        ("obs-fold with tab", b"POST / HTTP/1.1\r\nHost: h\r\n\tContent-Length: 3\r\n\r\nabc"),
        # A bare CR hid the Content-Length inside the Host value here; a proxy that splits on CR
        # sees it as its own header.
        ("bare cr in head", b"POST / HTTP/1.1\r\nHost: h\rContent-Length: 3\r\n\r\nabc"),
        # The method now selects the framing rule, so it must be a token.
        ("non-token method", b"PO(ST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"),
        ("non-token header name", b"POST / HTTP/1.1\r\nHost: h\r\nContent(Length: 3\r\n\r\nabc"),
        # HEAD is bodyless like GET, so the same framing refusals apply to it.
        ("head te", b"HEAD / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ("head cl", b"HEAD / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nHELLO"),
        # A method this listener reads no body for may not declare one either; it used to be
        # buffered in full only to be answered 405.
        ("delete cl", b"DELETE / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nHELLO"),
        # str.strip() removed VT, FF, NBSP and NEL, so each of these framed three bytes.
        ("cl trailing vt", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\x0b\r\n\r\nabc"),
        ("cl leading ff", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length:\x0c3\r\n\r\nabc"),
        ("cl trailing nbsp", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\xa0\r\n\r\nabc"),
        ("nul in a value", b"POST / HTTP/1.1\r\nHost: h\x00\r\nContent-Length: 3\r\n\r\nabc"),
        # int() raises past 4300 digits, which escaped as a 500.
        (
            "cl too many digits",
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: " + b"9" * 4400 + b"\r\n\r\nabc",
        ),
        # The request-target must be visible ASCII; some recipients split a line on HTAB or VT.
        ("target with tab", b"POST /a\tb HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"),
        ("target with nul", b"POST /a\x00b HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"),
        ("empty target", b"POST  HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"),
        # Only HTTP/1.x is parsed with HTTP/1.1 framing.
        ("http/2.0", b"POST / HTTP/2.0\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"),
        ("http/0.9", b"GET / HTTP/0.9\r\nHost: h\r\n\r\n"),
    ],
)
async def test_the_head_parse_refuses_the_rfc_9112_desync_grammar(label: str, raw: bytes) -> None:
    """Shapes this parser accepted before BACKLOG #1125 and now refuses in the head phase.

    Every one is a desync primitive: it parses one way here and another way in a fronting proxy.
    The accept-controls live in the tests around this one -- a plain GET, a plain POST carrying a
    Content-Length, and GET + `Content-Length: 0` -- so a parser that had gone refuse-everything
    would redden those rather than pass here.
    """
    reader = await _reader_from(raw)
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 400, label
    assert excinfo.value.kind == "framing_error", label


_CHUNKED_BODY = b"3\r\nabc\r\n0\r\n\r\n"

# The reason each framing guard in `_read_head` gives, so a case can name the guard it pins.
_TE_REFUSED = "transfer-encoding is not supported; use Content-Length"
_CL_TE_REFUSED = "ambiguous framing: Content-Length with Transfer-Encoding"
_UNDERSCORE_REFUSED = "underscore in a framing header name"


@pytest.mark.parametrize(
    ("label", "request_line", "framing", "reason"),
    [
        ("exact", b"POST /ingest", b"Transfer-Encoding: chunked\r\n", _TE_REFUSED),
        ("value title case", b"POST /ingest", b"Transfer-Encoding: Chunked\r\n", _TE_REFUSED),
        ("value upper case", b"POST /ingest", b"Transfer-Encoding: CHUNKED\r\n", _TE_REFUSED),
        ("name upper case", b"POST /ingest", b"TRANSFER-ENCODING: chunked\r\n", _TE_REFUSED),
        ("name and value mixed", b"POST /ingest", b"transfer-Encoding: cHuNkEd\r\n", _TE_REFUSED),
        (
            "gzip then chunked",
            b"POST /ingest",
            b"Transfer-Encoding: gzip, chunked\r\n",
            _TE_REFUSED,
        ),
        (
            "gzip then upper chunked",
            b"POST /ingest",
            b"Transfer-Encoding: gzip, CHUNKED\r\n",
            _TE_REFUSED,
        ),
        (
            "no space after comma",
            b"POST /ingest",
            b"Transfer-Encoding: gzip,chunked\r\n",
            _TE_REFUSED,
        ),
        (
            "chunked then gzip",
            b"POST /ingest",
            b"Transfer-Encoding: chunked, gzip\r\n",
            _TE_REFUSED,
        ),
        ("surrounding ows", b"POST /ingest", b"Transfer-Encoding: \t chunked \t\r\n", _TE_REFUSED),
        ("coding parameter", b"POST /ingest", b"Transfer-Encoding: chunked;x=1\r\n", _TE_REFUSED),
        ("quoted coding", b"POST /ingest", b'Transfer-Encoding: "chunked"\r\n', _TE_REFUSED),
        ("gzip alone", b"POST /ingest", b"Transfer-Encoding: gzip\r\n", _TE_REFUSED),
        ("deflate alone", b"POST /ingest", b"Transfer-Encoding: Deflate\r\n", _TE_REFUSED),
        ("empty value", b"POST /ingest", b"Transfer-Encoding:\r\n", _TE_REFUSED),
        (
            "list with empty member",
            b"POST /ingest",
            b"Transfer-Encoding: ,chunked\r\n",
            _TE_REFUSED,
        ),
        # A bodyless method gets the same refusal for a non-chunked coding.
        ("get with gzip", b"GET /health", b"Transfer-Encoding: gzip\r\n", _TE_REFUSED),
        ("delete with identity", b"DELETE /x", b"Transfer-Encoding: identity\r\n", _TE_REFUSED),
        # `Transfer_Encoding` is a valid token, so it used to pass both guards and be framed by its
        # Content-Length, while a front end that folds `_` into `-` reads it as chunked.
        ("underscore te", b"POST /ingest", b"Transfer_Encoding: chunked\r\n", _UNDERSCORE_REFUSED),
        (
            "underscore te with cl",
            b"POST /ingest",
            b"Transfer_Encoding: chunked\r\nContent-Length: 3\r\n",
            _UNDERSCORE_REFUSED,
        ),
        (
            "underscore cl with te",
            b"POST /ingest",
            b"Content_Length: 3\r\nTransfer-Encoding: chunked\r\n",
            _UNDERSCORE_REFUSED,
        ),
        # With a Content-Length beside it the OLDER ambiguity guard fires first, whatever the
        # coding: RFC 9112 section 6.1 lets TE override CL, so the pair is the CL.TE shape.
        (
            "cl with gzip",
            b"POST /ingest",
            b"Content-Length: 3\r\nTransfer-Encoding: gzip\r\n",
            _CL_TE_REFUSED,
        ),
        (
            "cl with mixed-case chunked",
            b"POST /ingest",
            b"Content-Length: 3\r\nTransfer-Encoding: Chunked\r\n",
            _CL_TE_REFUSED,
        ),
        (
            "te before cl",
            b"POST /ingest",
            b"Transfer-Encoding: identity\r\nContent-Length: 3\r\n",
            _CL_TE_REFUSED,
        ),
    ],
)
async def test_any_transfer_encoding_is_refused_whatever_its_spelling(
    label: str, request_line: bytes, framing: bytes, reason: str
) -> None:
    """BACKLOG #1913. The listener decodes no transfer coding, so ANY Transfer-Encoding is refused
    in the head phase, and the body is left unread.

    Before #1125 the test was exact equality on the lowered value, so a coding list such as
    `gzip, chunked` fell through and its body was read raw. The spellings here are at least these:
    case in the name and the value, coding lists in either order, OWS, a parameter, a quoted
    coding, empty lists, a bodyless method, and an underscore name. Each case names the guard it
    pins, so deleting one guard reds its own rows. The accept-controls are the test below this one.
    """
    raw = request_line + b" HTTP/1.1\r\nHost: h\r\n" + framing + b"\r\n" + _CHUNKED_BODY
    reader = await _reader_from(raw)
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 400, label
    assert excinfo.value.kind == "framing_error", label
    assert excinfo.value.reason == reason, label
    # Refused from the head alone: not one body byte was consumed.
    assert await reader.read() == _CHUNKED_BODY, label


@pytest.mark.parametrize(
    "lookalike",
    [
        b"",
        # The hop-by-hop `TE` request header names codings the CLIENT accepts in a response. It
        # frames nothing, and gRPC-style senders set it.
        b"TE: trailers\r\n",
        b"X-Transfer-Encoding: chunked\r\n",
        b"Transfer-Encodings: chunked\r\n",
        b"X_Custom_Header: 1\r\n",
    ],
)
async def test_a_post_framed_by_content_length_alone_is_read(lookalike: bytes) -> None:
    # Accept-controls for the refusals above: the same request framed by Content-Length alone,
    # beside a header that only resembles a framing header, parses and yields its declared bytes.
    # A guard that over-matches the header name reds here rather than passing there.
    raw = b"POST /ingest HTTP/1.1\r\nHost: h\r\n" + lookalike + b"Content-Length: 3\r\n\r\nabc"
    req = await _read_request(
        await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
    )
    assert req.method == "POST" and req.body == b"abc"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
async def test_a_body_method_with_no_framing_is_refused_411_not_read_to_eof(method: str) -> None:
    """BACKLOG #1125. A body method with neither Content-Length nor Transfer-Encoding used to be
    read to EOF, so the bytes after the head were ingested as this request's body. RFC 9112
    section 6.3 gives such a request a ZERO-length body, so a proxy reads those same bytes as the
    next request. It is refused in the head phase with 411, the RFC 9110 answer.
    """
    reader = await _reader_from(f"{method} / HTTP/1.1\r\nHost: h\r\n\r\nabc".encode("ascii"))
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 411
    assert excinfo.value.kind == "framing_error"


async def test_a_method_with_no_body_needs_no_framing() -> None:
    # Accept-control for the 411 above: this listener reads no body for GET or DELETE, so neither
    # needs framing, and a zero-length declaration written with leading zeros is still zero.
    for raw in (
        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"DELETE / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 00\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: " + b"0" * 4400 + b"\r\n\r\n",
    ):
        reader = await _reader_from(raw)
        head = await _read_head(reader, max_header_bytes=8192)
        assert await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES) == b""


async def test_a_long_but_valid_content_length_reads_normally() -> None:
    # Accept-control for the digit cap: leading zeros do not count against it, and the value and
    # its OWS are read exactly. 4400 zeros is past int()'s 4300-digit limit, which counts leading
    # zeros, so this raised ValueError and escaped as a 500 until the head parse normalised it.
    raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: \t" + b"0" * 4400 + b"3 \r\n\r\nabc"
    req = await _read_request(
        await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
    )
    assert req.body == b"abc"


async def test_a_lowercase_method_is_not_folded_into_a_known_one() -> None:
    # RFC 9110 section 9.1: methods are case-sensitive. `post` is not POST, so it gets no body
    # rule of POST's; with no body declared it parses, and the listener answers it 405 later.
    reader = await _reader_from(b"post / HTTP/1.1\r\nHost: h\r\n\r\n")
    head = await _read_head(reader, max_header_bytes=8192)
    assert head.method == "post"
    assert await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES) == b""


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (b"POST /ingest HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\nabc", 400),
        # A non-chunked coding beside a Content-Length (the ambiguity guard, DELTA-06), and an
        # underscore alias of Transfer-Encoding beside one (BACKLOG #1913).
        (
            b"POST /ingest HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n"
            b"Transfer-Encoding: Gzip\r\n\r\nabc",
            400,
        ),
        (
            b"POST /ingest HTTP/1.1\r\nHost: h\r\nTransfer_Encoding: chunked\r\n"
            b"Content-Length: 3\r\n\r\nabc",
            400,
        ),
        (b"POST /ingest HTTP/1.1\r\nHost: h\r\n\r\nabc", 411),
        (b"POST /ingest HTTP/1.1\r\nHost: h\r\n Content-Length: 3\r\n\r\nabc", 400),
        (b"GET /health HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nHELLO", 400),
    ],
)
async def test_a_framing_refusal_is_answered_logged_and_never_ingested(
    store: MessageStore, raw: bytes, status: int
) -> None:
    """End to end over a socket (BACKLOG #1125): the refusal is a clean 4xx, the connection is
    closed, a `framing_error` connection_event records it, and no ingress row is written. This is
    the same record every other pre-ingress refusal on this listener leaves.
    """
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0),
        router="r",
        content_type=ContentType.TEXT,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        # half_close so the old read-to-EOF path would have finished and ingested "abc".
        resp = await _http(src.sockport, raw_override=raw, half_close=True)
    finally:
        await src.stop()
    assert resp.status == status
    assert resp.headers.get("connection") == "close"
    assert any(kind == "framing_error" for kind, *_ in events)
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0


# --- Host header: exactly one on HTTP/1.1, never two (RFC 9112 section 3.2, BACKLOG #1972) --------

_NO_HOST = "missing Host header"
_TWO_HOSTS = "duplicate Host header"
_DUP_FRAMING = "duplicate framing header"


@pytest.mark.parametrize(
    ("label", "raw", "reason"),
    [
        ("post no host", b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", _NO_HOST),
        ("get no host", b"GET /health HTTP/1.1\r\n\r\n", _NO_HOST),
        ("head no host", b"HEAD /health HTTP/1.1\r\n\r\n", _NO_HOST),
        # Every 1.x minor past 0 is read as 1.1 (RFC 9110 section 2.5), so it owes a Host too.
        ("http/1.2 no host", b"GET / HTTP/1.2\r\n\r\n", _NO_HOST),
        # The dict kept the LAST value, so this used to parse with Host `b` and no refusal.
        (
            "two hosts differing",
            b"POST / HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 3\r\n\r\nabc",
            _TWO_HOSTS,
        ),
        ("two hosts equal", b"GET / HTTP/1.1\r\nHost: h\r\nHost: h\r\n\r\n", _TWO_HOSTS),
        # Field names are case-insensitive, so a case change is still a second Host.
        ("two hosts by case", b"GET / HTTP/1.1\r\nHost: h\r\nhOST: h\r\n\r\n", _TWO_HOSTS),
        # An empty value counts as a line, so it cannot hide a second one.
        ("empty then host", b"GET / HTTP/1.1\r\nHost:\r\nHost: h\r\n\r\n", _TWO_HOSTS),
        # The "more than one" MUST is not scoped to 1.1.
        ("two hosts on 1.0", b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n", _TWO_HOSTS),
    ],
)
async def test_the_head_parse_refuses_a_missing_or_repeated_host(
    label: str, raw: bytes, reason: str
) -> None:
    reader = await _reader_from(raw)
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(reader, max_header_bytes=8192)
    assert excinfo.value.status == 400, label
    assert excinfo.value.kind == "framing_error", label
    assert excinfo.value.reason == reason, label


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", _TE_REFUSED),
        (b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc", _DUP_FRAMING),
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n",
            _TE_REFUSED,
        ),
    ],
)
async def test_a_smuggling_probe_keeps_its_framing_reason_when_host_is_also_wrong(
    raw: bytes, reason: str
) -> None:
    # The Host check runs AFTER the framing refusals, so an operator filtering `framing_error`
    # events for smuggling probes still sees the framing reason when the probe also omits Host.
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_head(await _reader_from(raw), max_header_bytes=8192)
    assert excinfo.value.reason == reason


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("one host", b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"),
        ("one host with port", b"GET / HTTP/1.1\r\nhost: example.test:8080\r\n\r\n"),
        # RFC 9112 section 3.2 has a client send an EMPTY Host when the target has no authority.
        # This listener routes on no Host value, so empty is pinned as present, not refused.
        ("empty host", b"GET / HTTP/1.1\r\nHost:\r\n\r\n"),
        ("whitespace-only host", b"GET / HTTP/1.1\r\nHost: \t\r\n\r\n"),
        # HTTP/1.0 predates the field, and a 1.0 health check commonly omits it.
        ("http/1.0 no host", b"GET /health HTTP/1.0\r\n\r\n"),
        ("http/1.0 one host", b"GET /health HTTP/1.0\r\nHost: h\r\n\r\n"),
    ],
)
async def test_a_single_or_empty_host_and_a_hostless_http_1_0_still_parse(
    label: str, raw: bytes
) -> None:
    # Accept-controls for the refusals above, so a parser gone refuse-everything reddens here.
    head = await _read_head(await _reader_from(raw), max_header_bytes=8192)
    assert head.method == "GET", label


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"POST /ingest HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", _NO_HOST),
        (
            b"POST /ingest HTTP/1.1\r\nHost: localhost\r\nHost: SENTINEL-HOST-VALUE\r\n"
            b"Content-Length: 3\r\n\r\nabc",
            _TWO_HOSTS,
        ),
    ],
)
async def test_a_host_refusal_is_answered_400_content_free_and_never_ingested(
    store: MessageStore, raw: bytes, reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    """End to end over a socket: a closed 400 before dispatch, a `framing_error` event whose reason
    is the fixed refusal text, and no ingress row. The duplicate row carries a sentinel Host value,
    which must appear nowhere: not in the response, the event, or the log at any level."""
    caplog.set_level(logging.DEBUG)
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0),
        router="r",
        content_type=ContentType.TEXT,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        resp = await _http(src.sockport, raw_override=raw, half_close=True)
    finally:
        await src.stop()
    assert resp.status == 400
    assert resp.headers.get("connection") == "close"
    assert resp.json() == {"error": reason}
    assert ("framing_error", reason) in [(kind, why) for kind, _peer, why in events]
    assert b"SENTINEL" not in resp.body
    assert not any("SENTINEL" in str(event) for event in events)
    assert "SENTINEL" not in caplog.text
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0


def test_build_response_shape() -> None:
    out = build_response(202, '{"ok":1}')
    assert out.startswith(b"HTTP/1.1 202 Accepted\r\n")
    assert b"Content-Length: 8\r\n" in out
    assert b"Connection: close\r\n" in out
    assert out.endswith(b'{"ok":1}')


def test_build_response_carries_the_browser_safety_baseline() -> None:
    """ASVS 3.4.4 / 3.4.6. This listener is a SECOND HTTP server in the tree and it emitted no
    security header in any configuration. The sharpest case is the ADR 0154 sync-reply path, which
    echoes a downstream partner's Content-Type verbatim beside partner-supplied bytes — so it can
    serve a partner-derived `text/html` document over this listener's own TLS.

    Driven through the chokepoint every one of the twelve call sites feeds, with the negative control
    beside it: a name NOT in the baseline is absent from the same bytes, so this is evidence about the
    baseline rather than about the instrument."""
    out = build_response(200, "<p>hi</p>", content_type="text/html")
    for name, value in _BASELINE_RESPONSE_HEADERS:
        assert f"\r\n{name}: {value}\r\n".encode() in out, name
    assert b"\r\nX-Not-A-Real-Header:" not in out
    # It rides every status this listener answers with, refusals included — a 405 or a 503 is as
    # framable and as sniffable as a 200.
    for status in (202, 204, 400, 403, 405, 413, 422, 500, 503):
        body = build_response(status)
        for name, value in _BASELINE_RESPONSE_HEADERS:
            assert f"\r\n{name}: {value}\r\n".encode() in body, (status, name)


def test_the_listener_baseline_has_not_drifted_from_the_api_header_floor() -> None:
    """The listener carries its OWN copy of the baseline because `transports/` must not import
    `api/` (this module's docstring states that rule, and `header_floor` pulls in Starlette). A copy
    that can drift silently is the exact failure `header_floor` exists to end, so this is the single
    place a divergence reds — and it asserts the VALUES, not just the names."""
    from messagefoundry.api.header_floor import (
        BASELINE_SECURITY_HEADERS,
        CSP_HEADER,
        FRAME_ANCESTORS_CSP,
    )

    assert (
        *BASELINE_SECURITY_HEADERS,
        (CSP_HEADER, FRAME_ANCESTORS_CSP),
    ) == _BASELINE_RESPONSE_HEADERS


def test_a_caller_supplied_header_wins_over_the_baseline() -> None:
    """setdefault semantics, not an unconditional write: a name the caller decided is emitted ONCE,
    with the caller's value. A duplicated Content-Security-Policy would be a second policy the
    intersection then enforces, which is not what a caller overriding one means."""
    out = build_response(
        200, "{}", extra_headers={"content-security-policy": "frame-ancestors 'self'"}
    )
    assert out.count(b"Content-Security-Policy") == 0  # only the caller's spelling appears
    assert out.count(b"content-security-policy: frame-ancestors 'self'") == 1
    assert (
        b"\r\nX-Content-Type-Options: nosniff\r\n" in out
    )  # the names it did not decide still ride


def test_build_response_carries_extra_headers() -> None:
    # What lets a 401 carry WWW-Authenticate and a 429 carry Retry-After (ADR 0154 D6 wire shapes).
    out = build_response(
        401,
        '{"error":"unauthorized"}',
        extra_headers={"WWW-Authenticate": "Bearer", "Retry-After": "60"},
    )
    assert out.startswith(b"HTTP/1.1 401 Unauthorized\r\n")
    assert b"WWW-Authenticate: Bearer\r\n" in out
    assert b"Retry-After: 60\r\n" in out
    assert b"Connection: close\r\n" in out


def test_build_response_rejects_header_injection_rather_than_stripping_it() -> None:
    # AC-9: REJECT, do not sanitise. _strip_header_control_chars removes offending characters, which
    # would silently reshape a partner's Content-Type into something they never sent.
    with pytest.raises(ValueError, match="header value"):
        build_response(200, "{}", content_type="text/plain\r\nX-Injected: 1")
    with pytest.raises(ValueError, match="header value"):
        build_response(200, "{}", extra_headers={"Retry-After": "60\r\nX-Injected: 1"})
    with pytest.raises(ValueError, match="header name"):
        build_response(200, "{}", extra_headers={"X-Bad\r\nInjected": "1"})
    with pytest.raises(ValueError, match="header name"):
        build_response(200, "{}", extra_headers={"X Bad": "1"})  # space is not a tchar

    # The specific trap the guard is written against: a $-anchored re.match ACCEPTS a trailing
    # newline, so a lone LF at the end must be rejected too — not just an embedded CRLF.
    with pytest.raises(ValueError, match="header value"):
        build_response(200, "{}", content_type="text/plain\n")
    with pytest.raises(ValueError, match="header value"):
        build_response(200, "{}", content_type="text/plain\r")

    # A rejected value must not leak into the error text: on the capture path it is partner
    # controlled and potentially PHI. The header NAME is enough to diagnose.
    with pytest.raises(ValueError) as excinfo:
        build_response(200, "{}", extra_headers={"X-Reply-Type": "application/json\r\nMRN: 100"})
    assert "100" not in str(excinfo.value)
    assert "X-Reply-Type" in str(excinfo.value)


def test_status_line_reason_phrases() -> None:
    # The at-capacity refusal (_on_client) has always emitted 503, and _status_line's "OK" default
    # serialised it as `HTTP/1.1 503 OK` — a success phrase on a failure code. Asserted here rather
    # than through the flood test because the in-file _http() client parses only the numeric code,
    # so no end-to-end test in this suite can see a wrong reason phrase.
    assert _status_line(503) == "HTTP/1.1 503 Service Unavailable"

    for status, reason in (
        (200, "OK"),
        (202, "Accepted"),
        (204, "No Content"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (405, "Method Not Allowed"),
        (408, "Request Timeout"),
        (413, "Payload Too Large"),
        (422, "Unprocessable Content"),
        (429, "Too Many Requests"),
        (500, "Internal Server Error"),
        (502, "Bad Gateway"),
        (504, "Gateway Timeout"),
    ):
        assert _status_line(status) == f"HTTP/1.1 {status} {reason}"

    # An unmapped code must not inherit a phrase that contradicts it. RFC 9110 §15 allows an empty
    # reason-phrase; the SP before it is still required, so the line stays well-formed.
    assert _status_line(599) == "HTTP/1.1 599 "


async def test_accepted_socket_disables_nagle(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # asyncio already sets TCP_NODELAY on selector-loop transports, so asserting the option value on
    # the accepted socket would pass whether or not _on_client calls _set_tcp_nodelay — vacuous. Spy
    # instead, the same way tests/test_mllp_tcp_nodelay.py proves the outbound dial.
    calls: list[Any] = []
    real_set = http_mod._set_tcp_nodelay

    def spy(writer: Any) -> None:
        calls.append(writer)
        real_set(writer)  # keep the real effect so the round-trip below is unaffected

    monkeypatch.setattr(http_mod, "_set_tcp_nodelay", spy)

    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    try:
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
    finally:
        await src.stop()
    assert resp.status == 202
    assert calls, "_on_client accepted a connection without disabling Nagle"


async def test_respond_drain_is_bounded(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The success-path drain was unbounded, so a peer that stopped reading held its max_connections
    # slot indefinitely — receive_timeout bounds the READ, nothing bounded the write. _write_safely
    # already bounded the refuse path; only _respond did not.
    assert issubclass(TimeoutError, OSError)  # so _on_client's existing OSError arm catches this

    ic = build_inbound_connection(
        "IB_HTTP", Http(port=0), router="r", content_type=ContentType.JSON
    )
    src = await _start_source(store, ic)
    monkeypatch.setattr(http_mod, "_CLIENT_SHUTDOWN_GRACE", 0.05)

    class _StalledWriter:
        """A peer that accepts the write but never drains."""

        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            await asyncio.sleep(30)

    try:
        with pytest.raises(TimeoutError):
            await src._respond(_StalledWriter(), b"x")  # type: ignore[arg-type]
    finally:
        await src.stop()


# --- API-18: bounded functional DoS-guard tests (slow-loris / max_connections / body-flood) ------
#
# Each proves ONE HTTP guard refuses under a SMALL flood or slow client — a functional pass/fail, NOT
# a scale/soak measurement (the sustained thousands-of-connection flood + throughput-under-load run is
# rig-deferred). Modeled on the MLLP analogs test_emits_at_capacity / test_idle_timeout_close_reason
# (tests/test_connection_event_emit.py) and the in-file _http() raw client + events=[] sink wiring.
# GOTCHA (carried from this suite): a refused/reset connection on the Windows Proactor loop may reset
# before its 4xx flushes, so the load-bearing assertion is the connection_event kind + the ABSENT
# ingress row (status is asserted with the same (4xx, 0) tolerance the file already uses).


async def _wait_for(predicate, timeout: float = 2.0) -> bool:  # type: ignore[no-untyped-def]
    """Poll ``predicate`` until true or ``timeout`` — mirrors the MLLP analog rather than sleeping."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


async def test_slow_loris_refused_and_listener_stays_live(store: MessageStore) -> None:
    """A client that dribbles a partial request head (never sends the CRLFCRLF terminator) must be cut
    off by ``receive_timeout`` with a 408 + an ``idle_timeout`` connection_event, write NO ingress row,
    and leave the listener LIVE — a follow-on well-formed POST still commits + 202s."""
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(
            port=0, receive_timeout=0.2
        ),  # bound the whole-request read to 0.2s (slow-loris guard)
        router="r",
        content_type=ContentType.JSON,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        # Partial head, no terminating blank line: _read_request blocks in readuntil until the guard trips.
        resp = await _http(
            src.sockport, raw_override=b"POST /ingest HTTP/1.1\r\nHost: localhost\r\n"
        )
        assert resp.status in (
            408,
            0,
        )  # 408 when flushed; 0 = reset before flush (Windows Proactor)
        assert await _wait_for(lambda: any(k == "idle_timeout" for k, *_ in events))
        cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
        assert (await cur.fetchone())["n"] == 0  # slow-loris refused pre-ingress: no row

        # Listener stays live: a follow-on well-formed POST is accepted + committed.
        ok = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
        assert ok.status == 202
        cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
        assert (await cur.fetchone())["n"] == 1  # only the good POST reached ingress
    finally:
        await asyncio.wait_for(src.stop(), timeout=8.0)


async def test_max_connections_flood_refused_and_event(store: MessageStore) -> None:
    """With ``max_connections=2``, hold 2 clients open (established, mid-read) then a 3rd is refused with
    an ``at_capacity`` connection_event (503, or a Proactor reset) and writes NO ingress row."""
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(
            port=0, max_connections=2
        ),  # receive_timeout default (60s) keeps the 2 holders established
        router="r",
        content_type=ContentType.JSON,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    holders: list[asyncio.StreamWriter] = []
    try:
        # Open 2 clients that connect but never send a full request — each occupies a slot mid-read.
        for _ in range(2):
            _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
            holders.append(writer)
        assert await _wait_for(lambda: src._active == 2)  # both established (at the cap)

        # The 3rd client is over the cap: refused at accept, before any request is read.
        resp = await _http(src.sockport, body=JSON_BODY.encode("utf-8"))
        assert resp.status in (
            503,
            0,
        )  # 503 when flushed; 0 = reset before flush (Windows Proactor)
        assert await _wait_for(lambda: any(k == "at_capacity" for k, *_ in events))
        cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
        assert (await cur.fetchone())["n"] == 0  # capacity refusal never reaches ingress
    finally:
        for writer in holders:
            writer.close()
        await asyncio.wait_for(src.stop(), timeout=8.0)


async def test_body_flood_no_content_length_refused(store: MessageStore) -> None:
    """A POST with NO Content-Length flooding past ``max_body_bytes`` is refused before one body byte
    is read. It used to stream to EOF and trip the cap with 413; since BACKLOG #1125 the read-to-EOF
    path is gone and the head parse refuses the missing framing with 411."""
    events: list[tuple] = []
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0, max_body_bytes=16),  # tiny cap; the flood body is 64 bytes
        router="r",
        content_type=ContentType.TEXT,
        capture_connection_errors=True,
    )
    src = await _start_source(store, ic, events=events)
    try:
        # No Content-Length header -> refused in the head phase; the 64 flood bytes are never read.
        resp = await _http(
            src.sockport,
            raw_override=b"POST /ingest HTTP/1.1\r\nHost: localhost\r\n\r\n" + b"x" * 64,
        )
        assert resp.status in (
            411,
            0,
        )  # 411 when flushed; 0 = reset before flush (Windows Proactor)
        assert await _wait_for(lambda: any(k == "framing_error" for k, *_ in events))
        cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
        assert (await cur.fetchone())["n"] == 0  # refused before any ingress row
    finally:
        await asyncio.wait_for(src.stop(), timeout=8.0)


def test_a_204_carries_no_entity_headers() -> None:
    # RFC 9110 §15.3.5 forbids a body on a 204, and Content-Length beside it is at best noise and at
    # worst a parser tripwire. Ordinary traffic rather than an edge case: reply_on_empty="204" is the
    # default answer for a partner reply that is deliberately empty.
    out = build_response(204)
    assert out.startswith(b"HTTP/1.1 204 No Content\r\n")
    # The field line, not the substring: the baseline carries `X-Content-Type-Options`, in which
    # `Content-Type` is a substring, so a bare `not in` here would red on a change that adds no
    # entity header at all.
    assert b"\r\nContent-Type:" not in out
    assert b"\r\nContent-Length:" not in out
    assert b"Connection: close\r\n" in out
    assert out.endswith(b"\r\n\r\n")

    # extra_headers still ride a 204 — Retry-After and friends are not entity headers.
    assert b"Retry-After: 5\r\n" in build_response(204, extra_headers={"Retry-After": "5"})

    # ... and every other status is unchanged.
    assert b"Content-Length: 0\r\n" in build_response(200)
