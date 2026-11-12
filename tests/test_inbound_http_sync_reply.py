# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Synchronous captured-downstream reply on the inbound HTTP listener (ADR 0154 increment B).

Starts with the **factory-local** half of D4: everything decidable from one ``Http()`` call with no
store, no posture and no registry, so it fires identically in ``messagefoundry check``, in dry-run,
and through the ``connections.toml`` desugar (which routes through this same factory).

The cross-registry half — ``reply_from`` naming a deployed outbound, that outbound capturing
responses, the ``passthrough`` content-type requirement, and the effective ``ordering`` /
``max_attempts`` refusals — is not knowable here and is tested against ``build_check_registry``.
"""

from __future__ import annotations

import asyncio
import inspect
import json as _json
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Http, WiringError
from messagefoundry.transports.base import InboundReply, ReplyOutcome
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.receipt import IngressReceipt, RefusalKind, receipt_handler
from tests.test_inbound_http_source import _reader_from


def test_valid_configurations_build() -> None:
    Http(port=8080)  # no reply_from: the shipped 202 path, byte-identical
    Http(port=8080, reply_from="OB_PARTNER")
    Http(
        port=8080,
        reply_from="OB_PARTNER",
        reply_timeout=5.0,
        reply_on_timeout="202",
        reply_content_type="application/json",
        reply_on_empty="200",
        reply_write_timeout=10.0,
    )


def test_settings_are_carried_onto_the_spec() -> None:
    spec = Http(port=8080, reply_from="OB_PARTNER", reply_timeout=7.5)
    assert spec.settings["reply_from"] == "OB_PARTNER"
    assert spec.settings["reply_timeout"] == 7.5
    assert spec.settings["reply_on_timeout"] == "504"  # default
    assert spec.settings["reply_content_type"] == "passthrough"  # default
    assert spec.settings["reply_on_empty"] == "204"  # default
    assert spec.settings["reply_write_timeout"] == 30.0  # default

    # An inbound with no reply_from still carries the key, so the listener reads one shape.
    assert Http(port=8080).settings["reply_from"] is None


def test_knobs_without_reply_from_are_refused() -> None:
    # Same defect class as a credential configured with intake_auth="none": every one of these is
    # inert without reply_from, so the config would silently do nothing while reading as if it did.
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_timeout=5.0)
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_on_timeout="202")
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_content_type="application/json")
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_on_empty="200")
    with pytest.raises(WiringError, match="no reply_from"):
        Http(port=8080, reply_write_timeout=10.0)

    # ... and the message names the offending knob, so the fix is obvious from the error alone.
    with pytest.raises(WiringError, match="reply_timeout"):
        Http(port=8080, reply_timeout=5.0)


def test_the_default_table_is_derived_from_the_signature_not_copied() -> None:
    # Drift guard on the guard. If the defaults were hand-copied, changing one in the signature would
    # silently stop the "configured but never read" refusal from firing for that knob.
    from messagefoundry.config.wiring import _SYNC_REPLY_KNOBS, _sync_reply_defaults

    params = inspect.signature(Http).parameters
    assert _sync_reply_defaults() == {name: params[name].default for name in _SYNC_REPLY_KNOBS}
    # And every knob named really is a parameter — a rename would otherwise leave a dead entry.
    assert set(_SYNC_REPLY_KNOBS) <= set(params)


def test_an_empty_reply_from_is_refused() -> None:
    # "" is falsy, so it would read as "no sync reply" while looking configured in the file.
    with pytest.raises(WiringError, match="must name an outbound"):
        Http(port=8080, reply_from="")
    with pytest.raises(WiringError, match="must name an outbound"):
        Http(port=8080, reply_from="   ")


@pytest.mark.parametrize("knob", ["reply_timeout", "reply_write_timeout"])
@pytest.mark.parametrize("bad", [0, 0.0, -1, -0.5])
def test_a_non_positive_budget_is_refused(knob: str, bad: float) -> None:
    # Both bound a BLOCKED HTTP turn. Zero or negative is not "no timeout", it is a turn that cannot
    # succeed — and an operator writing 0 almost certainly means "unbounded", which is worse.
    with pytest.raises(WiringError, match="positive number of seconds"):
        Http(port=8080, reply_from="OB_PARTNER", **{knob: bad})


def test_the_status_choices_are_closed() -> None:
    with pytest.raises(WiringError, match="reply_on_timeout"):
        Http(port=8080, reply_from="OB_PARTNER", reply_on_timeout="500")  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="reply_on_empty"):
        Http(port=8080, reply_from="OB_PARTNER", reply_on_empty="204 No Content")  # type: ignore[arg-type]


def test_reply_content_type_must_be_passthrough_or_a_mime_type() -> None:
    with pytest.raises(WiringError, match="not empty"):
        Http(port=8080, reply_from="OB_PARTNER", reply_content_type="")
    # The refusal says what a value must look like and quotes none: 'application/json' is its example.
    with pytest.raises(WiringError, match=r"or a MIME type \(value withheld") as refused:
        Http(port=8080, reply_from="OB_PARTNER", reply_content_type="json")
    assert "'json'" not in str(refused.value)
    # A real MIME type and the passthrough sentinel both pass.
    Http(port=8080, reply_from="OB_PARTNER", reply_content_type="application/soap+xml")
    Http(port=8080, reply_from="OB_PARTNER", reply_content_type="passthrough")


def test_sync_reply_and_intake_auth_compose() -> None:
    # The two increments' surfaces are orthogonal and must not interfere.
    from messagefoundry.config.wiring import env

    spec = Http(
        port=8443,
        intake_auth="api_key",
        intake_api_key=env("acme_intake_key"),
        reply_from="OB_PARTNER",
        reply_timeout=15.0,
    )
    assert spec.settings["intake_auth"] == "api_key"
    assert spec.settings["reply_from"] == "OB_PARTNER"


# --- the wire: outcome -> HTTP (ADR 0154 D5) -----------------------------------------------------
#
# Drives a real listener with an injected resolver, so these assert the actual bytes a caller sees.
# The resolver itself is unit-tested separately; here the subject is the mapping and the fact that an
# inbound WITHOUT reply_from still takes the shipped 202 path byte for byte (AC-8).

REPLY_BODY = '{"partner":"ok","mrn":"100"}'


async def _serve(
    reply: InboundReply | None, *, events: list[str] | None = None, **settings: Any
) -> tuple[int, dict[str, str], bytes]:
    """POST once to a listener wired with a resolver that returns ``reply``; return the raw answer.

    ``events``, when given, collects the connection-event kinds the listener emits."""
    base: dict[str, Any] = {"host": "127.0.0.1", "port": 0}
    if reply is not None:
        base["reply_from"] = "OB_PARTNER"
    base.update(settings)
    src = HttpSource(Source(type=ConnectorType.HTTP, settings=base))

    declined = settings.get("_decline")

    async def handler(raw: bytes) -> IngressReceipt:
        if not declined:
            return IngressReceipt.accepted("msg-1")
        kind = declined if isinstance(declined, RefusalKind) else RefusalKind.PERMANENT
        return IngressReceipt.refused(kind, "err-1")

    if reply is not None:

        async def resolver(message_id: str) -> InboundReply:
            return reply

        src.sync_reply = resolver
    if events is not None:
        sink_events = events

        async def sink(kind: str, peer_host: str | None, reason: str | None) -> None:
            sink_events.append(kind)

        src.on_connection_event = sink
    await src.start(receipt_handler(handler))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        try:
            writer.write(b"POST /ingest HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), 5.0)
        finally:
            writer.close()
            await asyncio.gather(writer.wait_closed(), return_exceptions=True)
    finally:
        await src.stop()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return int(lines[0].split(" ", 2)[1]), headers, body


async def test_an_inbound_without_reply_from_still_gets_the_202() -> None:
    # AC-8, on the real socket: no reply_from means the shipped receipt path, untouched.
    status, _, body = await _serve(None)
    assert status == 202
    assert _json.loads(body)["status"] == "accepted"


async def test_a_captured_reply_is_returned_verbatim_with_its_content_type() -> None:
    status, headers, body = await _serve(
        InboundReply(ReplyOutcome.REPLY, body=REPLY_BODY, content_type="application/json")
    )
    assert status == 200
    assert body.decode() == REPLY_BODY  # verbatim — this is the whole feature
    assert headers["content-type"] == "application/json"


async def test_a_rejected_reply_returns_the_partners_body_with_502() -> None:
    status, _, body = await _serve(
        InboundReply(ReplyOutcome.REJECTED, body="<Fault>no</Fault>", content_type="text/xml")
    )
    assert status == 502
    assert body == b"<Fault>no</Fault>", "the partner's own answer is the useful thing to return"


async def test_an_empty_reply_is_204_with_no_entity_headers() -> None:
    status, headers, body = await _serve(InboundReply(ReplyOutcome.EMPTY))
    assert status == 204 and body == b""
    assert "content-length" not in headers and "content-type" not in headers

    # ... and the escape hatch for toolchains that mishandle a bodyless 204.
    status, _, _ = await _serve(InboundReply(ReplyOutcome.EMPTY), reply_on_empty="200")
    assert status == 200


async def test_a_timeout_answers_the_configured_status_and_names_the_message() -> None:
    status, _, body = await _serve(InboundReply(ReplyOutcome.TIMEOUT, waited_ms=30000))
    assert status == 504
    payload = _json.loads(body)
    assert payload["status"] == "timeout"
    assert payload["message_id"] == "msg-1", "the caller needs the id to reconcile later"

    status, _, _ = await _serve(InboundReply(ReplyOutcome.TIMEOUT), reply_on_timeout="202")
    assert status == 202


async def test_a_shutdown_is_503_with_retry_after_never_504() -> None:
    # Never a 504 on demotion: the new leader is about to deliver this message, so claiming the
    # partner timed out would be a lie about a message still in flight.
    status, headers, body = await _serve(InboundReply(ReplyOutcome.SHUTTING_DOWN))
    assert status == 503
    assert headers["retry-after"] == "5"
    assert _json.loads(body)["status"] == "shutting_down"


async def test_the_refusal_bodies_are_fixed_non_phi_json() -> None:
    for outcome, expected_status, tag in (
        (ReplyOutcome.FAILED, 502, "delivery_failed"),
        (ReplyOutcome.PURGED, 502, "reply_purged"),
        (ReplyOutcome.DEGRADED, 504, "degraded"),
        (ReplyOutcome.NO_ROUTE, 504, "no_route"),
    ):
        status, _, body = await _serve(InboundReply(outcome))
        assert status == expected_status
        payload = _json.loads(body)
        assert payload["status"] == tag
        assert payload["message_id"] == "msg-1"
        assert "mrn" not in body.decode(), "a refusal body carried partner data"


async def test_a_declined_handler_is_422_on_the_sync_path() -> None:
    # A caller blocked on a reply deserves to be told the submission itself failed. Post-record, so
    # count-and-log holds: the handler already wrote the message with status ERROR.
    status, _, body = await _serve(InboundReply(ReplyOutcome.REPLY, body="x"), _decline=True)
    assert status == 422
    assert "not accepted" in body.decode()


async def test_a_declined_handler_gets_the_same_422_on_both_paths() -> None:
    # Owner ruling 2026-09-26 (BACKLOG #1960): the receipt path used to answer "202 without a
    # message_id" here, which told the caller a refused body was accepted. Both paths now answer the
    # same status and the same bytes, so a caller cannot tell which mode refused it.
    #
    # The connection log must match too. The sync path's 422 used to return True from _serve_one,
    # which suppresses the outer "closed" event, although a post-record refusal emits no event kind
    # of its own. So that log showed "established" with no end.
    sync_events: list[str] = []
    receipt_events: list[str] = []
    sync = await _serve(
        InboundReply(ReplyOutcome.REPLY, body="x"), events=sync_events, _decline=True
    )
    receipt = await _serve(None, events=receipt_events, _decline=True)
    assert receipt == sync  # status, headers and body alike
    assert receipt[0] == 422
    assert receipt[2] == b'{"error": "message was not accepted", "refused_message_id": "err-1"}'
    assert sync_events == receipt_events == ["established", "closed"]


async def test_a_temporary_refusal_is_the_same_503_on_both_paths() -> None:
    # BACKLOG #2105: the one refusal branch answers both modes, so a temporary refusal is the 503 with
    # Retry-After on the sync path too, never a wait for a reply to a message that was not committed.
    sync = await _serve(InboundReply(ReplyOutcome.REPLY, body="x"), _decline=RefusalKind.TEMPORARY)
    receipt = await _serve(None, _decline=RefusalKind.TEMPORARY)
    assert receipt == sync
    assert receipt[0] == 503
    assert receipt[1]["retry-after"] == "5"


async def test_a_hostile_partner_content_type_cannot_take_the_turn_down() -> None:
    # The header guard rejects CR/LF. The body is still good, so fall back to our own content type
    # rather than 500 the caller — a partner controls this value.
    status, headers, body = await _serve(
        InboundReply(ReplyOutcome.REPLY, body=REPLY_BODY, content_type="text/plain\r\nX-Evil: 1")
    )
    assert status == 200
    assert body.decode() == REPLY_BODY
    assert "x-evil" not in headers, "a partner injected a header through Content-Type"
    assert headers["content-type"] == "application/json"


async def test_a_turn_woken_by_stop_writes_its_503_before_the_writers_close() -> None:
    # BACKLOG #5715: stop() wakes the blocked reply waiters and then closes every client writer. With
    # no yield between, the woken turn would write its 503 to a closing transport, and a demoted
    # caller would get a bare connection close instead of the answer the HA design depends on.
    src = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={"host": "127.0.0.1", "port": 0, "reply_from": "OB_PARTNER"},
        )
    )
    blocked = asyncio.Event()
    drained = asyncio.Event()

    async def handler(raw: bytes) -> IngressReceipt:
        return IngressReceipt.accepted("msg-1")

    async def resolver(message_id: str) -> InboundReply:
        blocked.set()
        await drained.wait()
        return InboundReply(ReplyOutcome.SHUTTING_DOWN)

    reasons: list[str] = []

    def drain(reason: str) -> None:
        reasons.append(reason)
        drained.set()

    src.sync_reply = resolver
    src.reply_drain = drain
    data = await _post_then_stop(src, handler, blocked)
    assert reasons == ["shutting_down"]
    head, _, body = data.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 503 "), f"the woken turn's answer was lost: {data!r}"
    assert b"\r\nRetry-After: 5" in head
    assert _json.loads(body)["status"] == "shutting_down"


async def _post_then_stop(src: HttpSource, handler: Any, blocked: asyncio.Event) -> bytes:
    """Start ``src``, POST once, run stop() once ``blocked`` is set, and return all the peer read."""
    await src.start(receipt_handler(handler))
    stopped = False
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        try:
            writer.write(b"POST /ingest HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}")
            await writer.drain()
            await asyncio.wait_for(blocked.wait(), 5.0)
            await src.stop()
            stopped = True
            return await asyncio.wait_for(reader.read(-1), 5.0)
        finally:
            writer.close()
            await asyncio.gather(writer.wait_closed(), return_exceptions=True)
    finally:
        if not stopped:
            await src.stop()


async def test_a_request_mid_commit_at_stop_still_gets_its_202() -> None:
    # BACKLOG #5715, the receipt path: stop() closed the writer of a request whose commit was still
    # running, so its 202 was discarded and the sender would resend a body already committed. A
    # request read in full now keeps its writer until its answer is written.
    src = HttpSource(Source(type=ConnectorType.HTTP, settings={"host": "127.0.0.1", "port": 0}))
    blocked = asyncio.Event()

    async def handler(raw: bytes) -> IngressReceipt:
        blocked.set()
        await asyncio.sleep(0.2)  # the commit, still running when stop() begins
        return IngressReceipt.accepted("msg-1")

    data = await _post_then_stop(src, handler, blocked)
    assert data.startswith(b"HTTP/1.1 202 "), f"the committed request's 202 was lost: {data!r}"


async def test_a_reply_turn_mid_commit_at_stop_answers_503_never_degraded() -> None:
    # A reply_from turn whose commit finishes after stop() began must not arm the drained rendezvous
    # and answer `degraded` (a 504 by default): ADR 0154 D5 never answers 504 on a demotion.
    src = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={"host": "127.0.0.1", "port": 0, "reply_from": "OB_PARTNER"},
        )
    )
    blocked = asyncio.Event()
    resolved: list[str] = []

    async def handler(raw: bytes) -> IngressReceipt:
        blocked.set()
        await asyncio.sleep(0.2)  # the commit, still running when stop() begins
        return IngressReceipt.accepted("msg-1")

    async def resolver(message_id: str) -> InboundReply:
        resolved.append(message_id)
        return InboundReply(ReplyOutcome.DEGRADED)

    src.sync_reply = resolver
    src.reply_drain = lambda reason: None
    data = await _post_then_stop(src, handler, blocked)
    head, _, body = data.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 503 "), f"a stopping listener answered {data!r}"
    assert b"\r\nRetry-After: 5" in head
    assert _json.loads(body)["status"] == "shutting_down"
    assert resolved == [], "a stopping listener armed the rendezvous"


async def test_stop_stays_bounded_when_a_reply_turn_never_leaves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The writer stop() leaves open is still bounded by the shutdown grace: a turn the drain does not
    # wake is cancelled at the grace, as every client task is, and stop() returns.
    import messagefoundry.transports.http_listener as http_listener

    monkeypatch.setattr(http_listener, "_CLIENT_SHUTDOWN_GRACE", 0.3)
    src = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={"host": "127.0.0.1", "port": 0, "reply_from": "OB_PARTNER"},
        )
    )
    blocked = asyncio.Event()

    async def handler(raw: bytes) -> IngressReceipt:
        return IngressReceipt.accepted("msg-1")

    async def resolver(message_id: str) -> InboundReply:
        blocked.set()
        await asyncio.Event().wait()  # ignores the drain
        raise AssertionError("unreachable")

    src.sync_reply = resolver
    src.reply_drain = lambda reason: None
    loop = asyncio.get_running_loop()
    started = loop.time()
    data = await _post_then_stop(src, handler, blocked)
    assert loop.time() - started < 3.0, "stop() outlived its grace"
    assert not data.startswith(b"HTTP/1.1 2"), "a cancelled turn must not read as answered"


class _ClosedWriter:
    """A writer whose transport is already closing. Its drain raises, as a real closed one's does."""

    def __init__(self) -> None:
        self.written: list[bytes] = []

    def is_closing(self) -> bool:
        return True

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        raise ConnectionResetError("closed")


_COMPLETE_POST = b"POST /ingest HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}"


async def test_a_request_read_in_full_is_committed_when_the_peer_already_closed() -> None:
    # BACKLOG #5715, a regression its round-2 commit made: `_serve_one` dropped a request read in
    # full whenever its writer was closing. A peer's TLS close_notify or reset right after a
    # complete POST closes the writer too (a plain-TCP FIN does not), so that request would have
    # been taken off the wire with no ingress row. Only a stopping listener may decline it; a
    # serving one commits it as before, and only its answer is lost.
    src = HttpSource(Source(type=ConnectorType.HTTP, settings={"host": "127.0.0.1", "port": 0}))
    committed: list[bytes] = []

    async def handler(raw: bytes) -> IngressReceipt:
        committed.append(raw)
        return IngressReceipt.accepted("msg-1")

    await src.start(receipt_handler(handler))
    try:
        writer: Any = _ClosedWriter()
        # The lost answer raises out to `_on_client`'s OSError arm, which records `peer_reset`.
        with pytest.raises(ConnectionResetError):
            await src._serve_one(await _reader_from(_COMPLETE_POST), writer, peer_host="127.0.0.1")
    finally:
        await src.stop()
    assert committed == [b"{}"], "a request read in full was dropped with no ingress row"


async def test_a_request_read_in_full_on_a_stopped_listener_is_not_handed_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The state the early return exists for: stop() closed this writer while the request's last
    # bytes sat in the reader's buffer, so no answer could reach the peer. Nothing is handed on. Its
    # `closed` event reads as an ordinary close, so a WARNING records the declined body; a health
    # probe would never have been committed, so it logs nothing.
    src = HttpSource(Source(type=ConnectorType.HTTP, settings={"host": "127.0.0.1", "port": 0}))
    committed: list[bytes] = []

    async def handler(raw: bytes) -> IngressReceipt:
        committed.append(raw)
        return IngressReceipt.accepted("msg-1")

    await src.start(receipt_handler(handler))
    await src.stop()
    closed = _ClosedWriter()
    writer: Any = closed
    with caplog.at_level("WARNING", logger="messagefoundry.transports.http_listener"):
        result = await src._serve_one(
            await _reader_from(_COMPLETE_POST), writer, peer_host="127.0.0.1"
        )
        assert "was not committed or answered" in caplog.text
        caplog.clear()
        probe = await _reader_from(b"HEAD /health HTTP/1.1\r\nHost: h\r\n\r\n")
        assert await src._serve_one(probe, writer, peer_host="127.0.0.1") is False
        assert caplog.text == ""
    assert result is False
    assert committed == []
    assert closed.written == []
