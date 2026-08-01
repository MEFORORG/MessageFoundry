# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    with pytest.raises(WiringError, match="which is neither"):
        Http(port=8080, reply_from="OB_PARTNER", reply_content_type="json")
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


async def _serve(reply: InboundReply | None, **settings: Any) -> tuple[int, dict[str, str], bytes]:
    """POST once to a listener wired with a resolver that returns ``reply``; return the raw answer."""
    base: dict[str, Any] = {"host": "127.0.0.1", "port": 0}
    if reply is not None:
        base["reply_from"] = "OB_PARTNER"
    base.update(settings)
    src = HttpSource(Source(type=ConnectorType.HTTP, settings=base))

    async def handler(raw: bytes) -> str | None:
        return None if settings.get("_decline") else "msg-1"

    if reply is not None:

        async def resolver(message_id: str) -> InboundReply:
            return reply

        src.sync_reply = resolver
    await src.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        writer.write(b"POST /ingest HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), 5.0)
        writer.close()
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
    # The shipped 202 path answers "202 without a message_id", which is a lie to a proxy client. A
    # caller blocked on a reply deserves to be told the submission itself failed. Post-record, so
    # count-and-log holds: the handler already wrote the message with status ERROR.
    status, _, body = await _serve(InboundReply(ReplyOutcome.REPLY, body="x"), _decline=True)
    assert status == 422
    assert "not accepted" in body.decode()


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
