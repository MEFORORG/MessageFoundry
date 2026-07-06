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
from messagefoundry.transports.base import build_source
from messagefoundry.transports.http_listener import (
    DEFAULT_MAX_BODY_BYTES,
    HttpRequestError,
    HttpSource,
    _read_request,
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
        try:
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
        try:
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


def test_build_response_shape() -> None:
    out = build_response(202, '{"ok":1}')
    assert out.startswith(b"HTTP/1.1 202 Accepted\r\n")
    assert b"Content-Length: 8\r\n" in out
    assert b"Connection: close\r\n" in out
    assert out.endswith(b'{"ok":1}')
