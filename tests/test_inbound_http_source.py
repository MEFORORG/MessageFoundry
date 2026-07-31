# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
) -> _Response:
    """Open one connection, send a request, read the full response (Connection: close)."""
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
    raw = b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\n"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(await _reader_from(raw), max_header_bytes=8192, max_body_bytes=16)
    assert exc.value.status == 413 and exc.value.kind == "frame_oversize"


async def test_read_request_rejects_chunked() -> None:
    raw = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400


async def test_read_request_rejects_duplicate_content_length() -> None:  # DELTA-06
    # Two Content-Length headers are an ambiguous-framing / request-smuggling signal (a dict would
    # silently keep the last); reject rather than pick one.
    raw = b"POST /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400 and exc.value.kind == "framing_error"


async def test_read_request_rejects_content_length_with_transfer_encoding() -> None:  # DELTA-06
    # Both Content-Length and Transfer-Encoding present: RFC 7230 §3.3.3 mandates rejection.
    raw = b"POST /x HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"
    with pytest.raises(HttpRequestError) as exc:
        await _read_request(
            await _reader_from(raw), max_header_bytes=8192, max_body_bytes=DEFAULT_MAX_BODY_BYTES
        )
    assert exc.value.status == 400 and exc.value.kind == "framing_error"


async def test_read_request_rejects_duplicate_transfer_encoding() -> None:  # DELTA-06
    # A duplicated Transfer-Encoding is how an obfuscated encoding is smuggled past the chunked check.
    raw = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n"
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


async def test_read_body_keeps_the_get_before_chunked_ordering() -> None:
    # Pins a quirk the split could silently "fix": the GET/HEAD short-circuit runs BEFORE the chunked
    # refusal, so a GET carrying Transfer-Encoding: chunked is accepted with an empty body. Hoisting
    # the refusal into the head phase would look like hardening and would change shipped behaviour.
    reader = await _reader_from(
        b"GET /health HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    head = await _read_head(reader, max_header_bytes=8192)
    assert await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES) == b""

    # ... while a POST carrying it is still refused, in the body phase.
    reader = await _reader_from(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
    head = await _read_head(reader, max_header_bytes=8192)
    with pytest.raises(HttpRequestError) as excinfo:
        await _read_body(reader, head, max_body_bytes=DEFAULT_MAX_BODY_BYTES)
    assert excinfo.value.status == 400


def test_build_response_shape() -> None:
    out = build_response(202, '{"ok":1}')
    assert out.startswith(b"HTTP/1.1 202 Accepted\r\n")
    assert b"Content-Length: 8\r\n" in out
    assert b"Connection: close\r\n" in out
    assert out.endswith(b'{"ok":1}')


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
    """A POST with NO Content-Length streams its body to EOF; a body past ``max_body_bytes`` is refused
    with 413 + ``frame_oversize`` on the read-to-EOF path (complements the declared-CL socket test)."""
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
        # No Content-Length header -> the read-to-EOF path; body 64 bytes trips the 16-byte cap.
        resp = await _http(
            src.sockport,
            raw_override=b"POST /ingest HTTP/1.1\r\nHost: localhost\r\n\r\n" + b"x" * 64,
        )
        assert resp.status in (
            413,
            0,
        )  # 413 when flushed; 0 = reset before flush (Windows Proactor)
        assert await _wait_for(lambda: any(k == "frame_oversize" for k, *_ in events))
        cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
        assert (await cur.fetchone())["n"] == 0  # oversize body refused before any ingress row
    finally:
        await asyncio.wait_for(src.stop(), timeout=8.0)
