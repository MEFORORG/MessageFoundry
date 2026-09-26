# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Localhost API: connections, message tracking/detail/replay, stats, audit, WebSocket.

REST is exercised with httpx's ASGI transport (async, shares this test's event loop, so
the real async engine/store work). The WebSocket test uses starlette's TestClient against
a lifespan-managed app, which owns its engine on the client's own loop."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from starlette.testclient import TestClient

from messagefoundry.api import create_app, create_managed_app
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import EmptyClaimCounters
from messagefoundry.store import MessageStatus, OutboxStatus

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

# A well-formed message id that no test seeds, and a malformed one. Since BACKLOG #1108 the two get
# DIFFERENT answers, and both matter: an id the store has never seen is a 404, and a value that could
# not be an id at all is refused (422) before any lookup runs. A single "missing" probe conflated
# them, and would go on passing if the id rule were removed.
ABSENT_ID = "0" * 32
MALFORMED_ID = "missing"

# A transformed outbound body, deliberately distinct from the raw inbound (different sending app + an
# extra segment), so a test can prove the /outbound endpoint returns the *transformed* payload — not
# the raw — and that it was decrypted at rest (#14).
TRANSFORMED = (
    "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
    "ZXF|transformed-by-mefor\r"
)


@pytest.fixture
async def engine(tmp_path: Path):
    eng = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine):
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def _seed_message(engine: Engine) -> str:
    """Enqueue one message directly through the store and return its id."""
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


# --- health ------------------------------------------------------------------


async def test_health(client: httpx.AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_unsupported_method_returns_405(client: httpx.AsyncClient) -> None:
    # WP-L3-08 / ASVS 4.1.4: each route declares exactly one HTTP method, so an unsupported method on a
    # known path is rejected with 405 by the router (before any handler runs) — that per-route
    # single-method declaration IS the intentional method-blocking control. No CORS/OPTIONS surface.
    assert (await client.request("DELETE", "/health")).status_code == 405
    assert (await client.request("PUT", "/messages")).status_code == 405


async def test_chunked_request_body_rejected(client: httpx.AsyncClient) -> None:
    # M-19: a chunked body (no Content-Length) can't be size-bounded up front, so it's refused with
    # 411 rather than buffered unbounded (pre-auth memory DoS guard).
    async def _stream():  # type: ignore[no-untyped-def]
        yield b"{}"

    r = await client.post("/auth/login", content=_stream())
    assert r.status_code == 411


async def test_both_content_length_and_transfer_encoding_rejected(
    client: httpx.AsyncClient,
) -> None:
    # ASVS 4.2.1: a request carrying BOTH Content-Length and Transfer-Encoding is ambiguously framed
    # (the CL.TE request-smuggling vector) and is refused with 400 before routing/auth.
    r = await client.post("/auth/login", content=b"{}", headers={"transfer-encoding": "chunked"})
    assert r.status_code == 400


async def test_query_param_pollution_last_value_still_validated(client: httpx.AsyncClient) -> None:
    # ASVS 15.3.7: duplicate scalar query params resolve last-wins (Starlette) and the surviving value
    # is still Pydantic-validated — a polluted duplicate can't smuggle past the bound. limit is capped
    # le=500, so a trailing over-cap duplicate is rejected (422), not silently aggregated/accepted.
    r = await client.get("/messages", params=[("limit", "1"), ("limit", "999")])
    assert r.status_code == 422
    # An in-bounds trailing duplicate is accepted (last wins = 2).
    r = await client.get("/messages", params=[("limit", "999"), ("limit", "2")])
    assert r.status_code == 200


async def test_dead_letters_query_params_length_capped(client: httpx.AsyncClient) -> None:
    # Parity with /messages (ASVS 1.2.10 / 15.3.7): the /dead-letters channel_id/destination_name
    # scalar query params are now length-capped, so an over-length value is rejected up front.
    assert (await client.get("/dead-letters", params={"channel_id": "x" * 257})).status_code == 422
    assert (await client.get("/dead-letters", params={"channel_id": "x" * 256})).status_code == 200


def test_docs_endpoints_disabled_by_default() -> None:
    # /docs, /redoc, /openapi.json widen the attack surface and disclose the schema — off by default.
    with TestClient(create_app(allow_no_auth=True)) as c:
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/docs").status_code == 404


def test_docs_endpoints_enabled_when_opted_in() -> None:
    with TestClient(create_app(expose_docs=True, allow_no_auth=True)) as c:
        assert c.get("/openapi.json").status_code == 200


# --- messages ----------------------------------------------------------------


async def test_list_messages_with_filters_and_pagination(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    for _ in range(3):
        await _seed_message(engine)

    r = await client.get("/messages")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["messages"]) == 3
    # List view is metadata only — no raw body leaks here.
    assert "raw" not in body["messages"][0]

    r = await client.get("/messages", params={"limit": 2})
    assert len(r.json()["messages"]) == 2
    assert r.json()["total"] == 3  # total ignores the page size

    r = await client.get("/messages", params={"channel_id": "other"})
    assert r.json()["total"] == 0


async def test_message_detail_includes_body_and_records_audit_view(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid = await _seed_message(engine)
    r = await client.get(f"/messages/{mid}")
    assert r.status_code == 200
    detail = r.json()
    assert detail["raw"] == ADT
    assert detail["outbox"][0]["destination_name"] == "archive"
    assert detail["events"][0]["event"] == "received"
    # Opening the body must have appended a 'viewed' audit event.
    events = await engine.store.events_for(mid)
    assert any(e["event"] == "viewed" for e in events)

    assert (await client.get(f"/messages/{ABSENT_ID}")).status_code == 404
    assert (await client.get(f"/messages/{MALFORMED_ID}")).status_code == 422


async def test_message_outbound_returns_transformed_payload_and_audits(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # #14: the parity tool reads MEFOR's transformed outbound body per destination. Seed a transformed
    # payload distinct from the raw inbound to prove we return the decrypted transform, not the raw.
    mid = await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", TRANSFORMED)], control_id="MSG1"
    )
    r = await client.get(f"/messages/{mid}/outbound")
    assert r.status_code == 200
    body = r.json()
    assert body["message_id"] == mid
    assert len(body["payloads"]) == 1
    p = body["payloads"][0]
    assert p["destination_name"] == "archive"
    assert p["payload"] == TRANSFORMED  # the decrypted, transformed outbound body...
    assert p["payload"] != ADT  # ...not the raw inbound
    # Returning a PHI body is audited: a per-message 'viewed' event + an 'outbound.read' audit action.
    assert any(e["event"] == "viewed" for e in await engine.store.events_for(mid))
    assert "outbound.read" in [a["action"] for a in await engine.store.list_audit()]

    assert (await client.get(f"/messages/{ABSENT_ID}/outbound")).status_code == 404
    assert (await client.get(f"/messages/{MALFORMED_ID}/outbound")).status_code == 422


async def test_message_outbound_no_deliveries_is_empty_and_unviewed(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # No outbound rows → empty payload list, and no body was opened, so no 'viewed' event is recorded
    # (the read itself is still audited as outbound.read).
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    r = await client.get(f"/messages/{mid}/outbound")
    assert r.status_code == 200
    assert r.json()["payloads"] == []
    assert not any(e["event"] == "viewed" for e in await engine.store.events_for(mid))
    assert "outbound.read" in [a["action"] for a in await engine.store.list_audit()]


async def test_audit_and_event_detail_never_contain_message_body(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # PHI-access auditing must record *metadata* (ids/counts), never the raw body (AUDIT-INTEGRITY).
    mid = await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        summary="MRN 1 · DOE",
    )
    await client.get(f"/messages/{mid}")  # view → 'viewed' event
    await client.get(f"/messages/{mid}/outbound")  # transformed-body view → 'outbound.read' audit
    await client.get("/messages")  # exposes the summary → server-audited, no opt-in
    blobs = [a["detail"] or "" for a in await engine.store.list_audit()]
    blobs += [e["detail"] or "" for e in await engine.store.events_for(mid)]
    # 'MSH|' / 'PID|' only appear in a raw HL7 body, never in legitimate audit metadata.
    assert all("MSH|" not in b and "PID|" not in b for b in blobs)


async def test_replay_requeues(engine: Engine, client: httpx.AsyncClient) -> None:
    mid = await _seed_message(engine)
    # Drain + dead-letter the delivery so there's something to replay.
    item = (await engine.store.claim_ready())[0]
    from messagefoundry.config.models import RetryPolicy

    await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))

    r = await client.post(f"/messages/{mid}/replay")
    assert r.status_code == 200
    assert r.json()["requeued"] == 1
    rows = await engine.store.outbox_for(mid)
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert rows[0]["attempts"] == 0

    assert (await client.post(f"/messages/{ABSENT_ID}/replay")).status_code == 404
    assert (await client.post(f"/messages/{MALFORMED_ID}/replay")).status_code == 422


async def test_replay_no_deliveries_is_409_and_preserves_error(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # A message with no outbox rows (an ERROR disposition) has nothing to replay: 409, and the store
    # must NOT flip it to RECEIVED or clear its error (review M-2).
    mid = await engine.store.record_received(
        channel_id="ch1",
        raw=ADT,
        status=MessageStatus.ERROR,
        error="parse error: boom",
        source_type="file",
    )
    r = await client.post(f"/messages/{mid}/replay")
    assert r.status_code == 409
    row = await engine.store.get_message(mid)
    assert row is not None
    assert row["status"] == MessageStatus.ERROR.value  # disposition intact
    assert row["error"] == "parse error: boom"  # error record preserved, not destroyed


async def test_message_view_recorded_in_tamper_evident_audit_log(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # M-3: opening a raw body writes an audit_log row (visible to GET /audit), not just message_events.
    mid = await _seed_message(engine)
    await client.get(f"/messages/{mid}")
    views = [a for a in await engine.store.list_audit() if a["action"] == "message_view"]
    assert len(views) == 1
    assert views[0]["channel_id"] == "ch1" and mid in (views[0]["detail"] or "")


async def test_replay_actions_are_audited(engine: Engine, client: httpx.AsyncClient) -> None:
    from messagefoundry.config.models import RetryPolicy

    # M-4: an actual message replay is attributed in the audit_log; a no-op (409) replay is not.
    mid = await _seed_message(engine)
    item = (await engine.store.claim_ready())[0]
    await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))
    assert (await client.post(f"/messages/{mid}/replay")).status_code == 200
    repl = [a for a in await engine.store.list_audit() if a["action"] == "message_replay"]
    assert len(repl) == 1 and repl[0]["channel_id"] == "ch1" and mid in (repl[0]["detail"] or "")

    # a no-outbox-rows message → 409 → no message_replay audit (nothing was re-transmitted)
    eid = await engine.store.record_received(
        channel_id="ch1", raw=ADT, status=MessageStatus.ERROR, error="boom"
    )
    assert (await client.post(f"/messages/{eid}/replay")).status_code == 409
    assert not any(eid in (a["detail"] or "") for a in await engine.store.list_audit())


async def test_dead_letter_replay_is_audited(engine: Engine, client: httpx.AsyncClient) -> None:
    # M-4: a bulk dead-letter replay is attributed in the audit_log.
    await _seed_message(engine)
    await _dead_letter(engine)
    assert (await client.post("/dead-letters/replay", json={})).status_code == 200
    assert any(a["action"] == "dead_letter_replay" for a in await engine.store.list_audit())


# --- dead letters ------------------------------------------------------------


async def _dead_letter(engine: Engine) -> None:
    from messagefoundry.config.models import RetryPolicy

    item = (await engine.store.claim_ready())[0]
    await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))


async def test_dead_letters_list_and_replay(engine: Engine, client: httpx.AsyncClient) -> None:
    mid = await _seed_message(engine)  # delivery to "archive"
    await _dead_letter(engine)

    body = (await client.get("/dead-letters")).json()
    assert body["total"] == 1
    row = body["dead_letters"][0]
    assert row["message_id"] == mid
    assert row["destination_name"] == "archive"
    assert row["channel_id"] == "ch1"
    assert row["attempts"] == 1 and row["last_error"] == "boom"

    r = await client.post("/dead-letters/replay", json={})
    assert r.status_code == 200
    assert r.json()["requeued"] == 1
    assert (await client.get("/dead-letters")).json()["total"] == 0
    assert (await engine.store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value


async def test_dead_letters_replay_scoped_by_destination(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    a = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[("d1", ADT)])
    b = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[("d2", ADT)])
    from messagefoundry.config.models import RetryPolicy

    for dest, mid in (("d1", a), ("d2", b)):  # noqa: B007
        item = (await engine.store.claim_ready(destination_name=dest))[0]
        await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))

    r = await client.post("/dead-letters/replay", json={"destination_name": "d1"})
    assert r.json()["requeued"] == 1
    remaining = (await client.get("/dead-letters")).json()
    assert remaining["total"] == 1
    assert remaining["dead_letters"][0]["destination_name"] == "d2"


async def test_dead_letter_summary_access_audited_server_side(engine: Engine) -> None:
    # M-5: dead-letter summary access is audited server-side (coalesced) too — no client flag needed.
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)], summary="DOE^JANE"
    )
    await _dead_letter(engine)
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.get("/dead-letters")  # returns a summary -> counted
        await app.state.summary_auditor.flush(engine.store)
    assert any(a["action"] == "summary_access" for a in await engine.store.list_audit())


async def test_connections_retired_outbound_shows_draining(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """A destination with queued/failed rows but no live outbound (removed by a reload) is reported
    as 'draining' with an unknown method — not mislabeled as a running File connector."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "adt_in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("adt_in", m))
    engine.add_registry(reg)
    # An outbox row to a destination the registry does not declare (a retired/draining outbound).
    await engine.store.enqueue_message(
        channel_id="adt_in", raw=ADT, deliveries=[("gone_dest", ADT)], now=100.0
    )

    by_name = {row["name"]: row for row in (await client.get("/connections")).json()}
    retired = by_name["adt_in ▸ gone_dest"]
    assert retired["status"] == "draining"
    assert retired["method"] == "—"
    assert retired["peer"] is None and retired["port"] is None


# --- stats -------------------------------------------------------------------


async def test_stats(engine: Engine, client: httpx.AsyncClient) -> None:
    await _seed_message(engine)
    r = await client.get("/stats")
    assert r.status_code == 200
    assert r.json()["outbox_by_status"][OutboxStatus.PENDING.value] == 1
    assert r.json()["in_pipeline"] == 1  # whole-pipeline gauge (one outbound row, pending)


async def test_stats_reads_the_runners_claim_counters_rather_than_constants(
    engine: Engine, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1270: /stats must be WIRED to the runner's counters, not hard-coded.

    Every one of these four fields was replaceable with a literal ``0`` in ``app.py`` without a
    single test noticing — which is what an operator-facing number emitted into a vacuum looks like,
    and is how #1270's first attempt shipped its ``/stats`` half with two source lines and no reader.

    A DISTINCT VALUE PER FIELD, on purpose. Equal values would let a crossed wiring (idle_poll read
    into wake_fanout, say) pass; these cannot be permuted without failing.

    THE LAST TWO ARE DIFFERENT UNITS AGAIN and the numbers say so: eight LANES were booked empty
    while THREE claim ROUND-TRIPS aborted, and SEVEN outbound ROWS were refused at the halted claim
    gate (#122, ADR 0189 — a counter on the runner itself, not on ``EmptyClaimCounters``). Nothing
    here divides them.
    """
    ec = EmptyClaimCounters()
    for _ in range(3):
        ec.record_empty(woken=False)  # idle_poll
    for _ in range(5):
        ec.record_empty(woken=True)  # wake_fanout
    for _ in range(3):
        ec.record_claim_lock_timeout()
    # monkeypatch, not a bare assignment: the engine fixture's teardown calls runner.stop(), so the
    # stub must be off the engine again before this test returns.
    monkeypatch.setattr(
        engine,
        "_registry_runner",
        SimpleNamespace(empty_claims=ec, halted_claim_gate_hits=7),
    )

    body = (await client.get("/stats")).json()
    assert body["empty_claims"] == 8
    assert body["empty_claims_idle_poll"] == 3
    assert body["empty_claims_wake_fanout"] == 5
    assert body["claim_lock_timeouts"] == 3
    assert body["halted_claim_gate_hits"] == 7


# --- connections -------------------------------------------------------------


async def test_connections_lists_source_and_destination_rows(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """A source row per inbound + a destination edge row, with metrics, over MLLP→file."""
    outdir = tmp_path / "out"
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "adt_in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "adt_archive",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("adt_archive", m))
    engine.add_registry(reg)

    await engine.store.enqueue_message(
        channel_id="adt_in", raw=ADT, deliveries=[("adt_archive", ADT)], now=100.0
    )
    item = (await engine.store.claim_ready(now=100.0))[0]
    await engine.store.mark_done(item.id, now=101.0)

    by_name = {row["name"]: row for row in (await client.get("/connections")).json()}
    src = by_name["adt_in ▸ in"]
    assert src["direction"] == "in"
    assert src["peer"] == "0.0.0.0" and src["port"] == 2575
    assert src["read"] == 1  # one inbound message
    assert src["queue_depth"] is None  # source rows carry no queue metrics

    dst = by_name["adt_in ▸ adt_archive"]
    assert dst["destination"] == "adt_archive"
    assert dst["peer"] == str(outdir) and dst["port"] is None  # file dir, no port
    assert dst["written"] == 1 and dst["queue_depth"] == 0
    assert dst["read"] is None


async def test_messages_expose_event_summary_metadata(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        summary="MRN 100001 · DOE, JANE",
    )
    msg = (await client.get("/messages")).json()["messages"][0]
    # List surface: the summary is display-masked until a per-message open reveals it (ASVS 14.2.6).
    # The shape survives -- label, separator, name comma -- so the row still reads as a row.
    assert msg["summary"] == "MRN ****0001 · D**, J**"
    assert msg["event"] == "received"
    assert msg["metadata"] is None


async def test_list_masks_the_summary_and_opening_one_message_reveals_it(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """The mask and its reveal, end to end and in one place (ASVS 14.2.6, BACKLOG #1187).

    Opening a single message IS the reveal act: it is deliberate, per-record, and already audited
    (``record_view`` plus the tamper-evident chain). The list is the surface where complete
    identifiers could be read off a screen opened for another reason, so it stays masked.

    Both halves are asserted against the SAME stored value, so this cannot pass by the list and the
    detail simply carrying different data.
    """
    stored = "MRN 100001 · DOE, JANE"
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG-REVEAL",
        message_type="ADT^A01",
        summary=stored,
    )
    listed = (await client.get("/messages")).json()["messages"][0]
    assert listed["summary"] == "MRN ****0001 · D**, J**"  # census surface: masked

    opened = (await client.get(f"/messages/{listed['id']}")).json()
    assert opened["summary"] == stored  # the per-message open is the act that lifts it

    # And the list is still masked afterwards -- the reveal did not become a status.
    again = (await client.get("/messages")).json()["messages"][0]
    assert again["summary"] == "MRN ****0001 · D**, J**"


async def test_summary_access_audited_server_side_and_coalesced(engine: Engine) -> None:
    # M-5: summary access is audited SERVER-SIDE (no client flag needed), coalesced into one
    # summary_access row per actor/hour carrying the running count.
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)], summary="MRN 1 · DOE"
    )
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.get("/messages")  # a summary is returned -> counted, even with no client flag
        await c.get(
            "/messages"
        )  # same hour -> accumulates; no row emitted while the window is open
        assert not [a for a in await engine.store.list_audit() if a["action"] == "summary_access"]
        await app.state.summary_auditor.flush(engine.store)  # e.g. shutdown flush
    rows = [a for a in await engine.store.list_audit() if a["action"] == "summary_access"]
    assert len(rows) == 1  # both calls coalesced into one window
    detail = rows[0]["detail"] or ""
    # The LIST surface masks, so these two accesses disclosed nothing -- but a bulk fetch must still
    # be visible in the audit, or a 5,000-row scrape would look like no request at all (ASVS 14.2.6,
    # BACKLOG #1187). The two counts are kept apart so one can never be read as the other.
    assert '"masked": 2' in detail  # accumulated across both calls
    assert '"count": 0' in detail  # and nothing was actually readable


async def test_the_audit_separates_a_masked_list_from_a_real_disclosure(engine: Engine) -> None:
    """Listing and opening the SAME message must land in different counters (BACKLOG #1187).

    Before this split every list row counted as a PHI exposure, so the audit could not tell a
    console poll from someone reading a patient's identifiers -- the false positives buried the one
    event the record exists for.
    """
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)], summary="MRN 100001 · DOE, JANE"
    )
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        listed = (await c.get("/messages")).json()["messages"][0]
        await c.get(f"/messages/{listed['id']}")  # the open IS the reveal act
        await app.state.summary_auditor.flush(engine.store)

    rows = [a for a in await engine.store.list_audit() if a["action"] == "summary_access"]
    details = [r["detail"] or "" for r in rows]

    # The LIST: one row returned, nothing readable.
    assert any('"count": 0' in d and '"masked": 1' in d for d in details)

    # The OPEN: a real disclosure, and nothing masked. The count is 3 rather than 1 because the
    # detail route audits [detail, *outbox, *events] together -- the nested delivery and event rows
    # carry their own `last_error` / `detail` PHI, which is NOT in MASKED_UNTIL_REVEALED and so was
    # readable all along. Asserted exactly, because a looser "> 0" would pass if the summary reveal
    # silently stopped counting and only the nested rows carried it.
    assert any('"count": 3' in d and '"masked": 0' in d for d in details)


async def test_summary_audit_coalescer_rolls_over_with_count() -> None:
    from messagefoundry.api.app import _SummaryAuditCoalescer

    class _Rec:
        def __init__(self) -> None:
            self.rows: list[tuple[str, str | None, str | None, str | None]] = []

        async def record_audit(self, action, *, actor=None, channel_id=None, detail=None):  # type: ignore[no-untyped-def]
            self.rows.append((action, actor, channel_id, detail))

    store = _Rec()
    c = _SummaryAuditCoalescer()
    await c.note(store, "alice", "ch1", 3, 0.0)  # hour 0
    await c.note(store, "alice", "ch1", 2, 60.0)  # same hour -> accumulate (count 5), no emit
    assert store.rows == []
    await c.note(store, "alice", "ch1", 1, 3600.0)  # hour 1 -> flush hour-0 window (count 5)
    assert len(store.rows) == 1
    action, actor, channel_id, detail = store.rows[0]
    assert action == "summary_access" and actor == "alice" and channel_id == "ch1"
    assert detail is not None and '"count": 5' in detail
    # a different actor's later access sweeps alice's still-open hour-1 window
    await c.note(store, "bob", "ch2", 1, 7200.0)  # hour 2
    assert any(r[1] == "alice" and r[3] and '"count": 1' in r[3] for r in store.rows)
    await c.flush(store)  # remaining (bob's hour-2 window)
    assert any(r[1] == "bob" for r in store.rows)


async def test_no_summary_audit_when_the_listed_messages_have_no_summaries(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """Summary auditing is server-enforced (M-5), but it is driven by what the response actually
    EXPOSES: a list carrying no summaries exposes no PHI, so it records no audit row."""
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)]
    )  # no summary
    await client.get("/messages")
    assert len(await engine.store.list_audit()) == 0


async def test_status_reports_engine_and_db(engine: Engine, client: httpx.AsyncClient) -> None:
    await _seed_message(engine)
    body = (await client.get("/status")).json()
    assert body["engine"]["version"]
    assert "outbox_by_status" in body["engine"]
    assert body["db"]["messages"] == 1
    assert body["db"]["journal_mode"].lower() == "wal"
    assert body["db"]["size_bytes"] > 0


async def test_status_kpis_rollup_combines_endpoints_and_reuses_recent_done(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # #93 engine-wide KPI headline: combined inbound+outbound endpoint count (running/stopped) + total
    # messages + an engine-wide msg/s rate REUSING the recent_done window (no second sampler).
    import time as _time

    from messagefoundry.config.wiring import (
        ConnectionSpec,
        InboundConnection,
        OutboundConnection,
        Registry,
        Send,
    )

    reg = Registry()
    reg.add_inbound(
        InboundConnection("adt_in", ConnectionSpec(ConnectorType.MLLP, {"port": 2575}), router="r")
    )
    reg.add_outbound(
        OutboundConnection(
            "adt_archive", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"})
        )
    )
    reg.add_router("r", lambda msg: ["h"])
    reg.add_handler("h", lambda msg: Send("adt_archive", msg))
    engine.add_registry(reg)  # wired but not started → every endpoint reads "stopped"

    # Drive one outbound row to done with a recent updated_at so it lands in the recent_done window.
    now = _time.time()
    await engine.store.enqueue_message(
        channel_id="adt_in", raw=ADT, deliveries=[("adt_archive", ADT)], source_type="mllp", now=now
    )
    item = (await engine.store.claim_ready(now=now, destination_name="adt_archive"))[0]
    await engine.store.mark_done(item.id, now=now)

    kpis = (await client.get("/status")).json()["kpis"]
    # Combined inbound + outbound endpoints (vs channels_*, which count inbound only).
    assert kpis["connections_total"] == 2  # 1 inbound + 1 outbound (both DEPLOYED)
    assert kpis["connections_running"] == 0  # runner built but not started
    assert kpis["connections_stopped"] == 2
    assert kpis["connections_not_deployed"] == 0  # #233: none flagged deployed=false here
    # The pinned identity survives the third bucket unchanged: not-deployed connections are excluded
    # from total (they are in the registry but are not lanes), so stopped still == total - running.
    assert kpis["connections_stopped"] == kpis["connections_total"] - kpis["connections_running"]
    # messages_total mirrors the store-wide message count.
    assert kpis["messages_total"] == 1
    # The engine-wide rate is derived from recent_done (1 completion) / the 60s rate window — proving it
    # reuses the same window that powers backlog_seconds rather than adding a second sampler.
    assert kpis["messages_per_second"] == pytest.approx(1 / 60.0)


async def test_status_log_metering_absent_when_no_log_dir(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # #50: with no [logging].log_dir configured (the engine logs to stdout under NSSM), the app-log
    # metering field is absent/None — /status must degrade gracefully, never raise.
    body = (await client.get("/status")).json()
    assert body.get("logs") is None


async def test_status_log_metering_present_when_log_dir_set(engine: Engine, tmp_path: Path) -> None:
    # #50: with a log dir configured, /status meters its total file bytes + filesystem free space,
    # mirroring the DB metrics' size_bytes / disk_free_bytes shape. Metadata only — no log content.
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("x" * 1234)
    (log_dir / "engine.log.1").write_text("y" * 766)
    app = create_app(engine, allow_no_auth=True, log_dir=str(log_dir))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/status")).json()
    assert body["logs"] is not None
    assert body["logs"]["path"] == str(log_dir)
    assert body["logs"]["size_bytes"] == 2000  # 1234 + 766
    assert body["logs"]["disk_free_bytes"] > 0


async def test_status_log_metering_distinguishes_a_missing_dir_from_stdout_only(
    engine: Engine, tmp_path: Path
) -> None:
    """BACKLOG #1563: a configured-but-missing log dir must not raise — and must not come back as a
    bare ``None`` either, because that is the stdout-only answer.

    Reusing it here made a log directory that had VANISHED indistinguishable from an engine that was
    deliberately never given one: the operator saw no log section in both cases. The section is now
    present and names the configured path, with ``None`` in each field the probe could not measure.
    ``None`` is "not measured"; ``0`` would be the different claim that the directory is empty."""
    missing = tmp_path / "does_not_exist"
    app = create_app(engine, allow_no_auth=True, log_dir=str(missing))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/status")).json()
    assert body["logs"] is not None  # configured, so reported — never read as stdout-only
    assert body["logs"]["path"] == str(missing)
    assert body["logs"]["disk_free_bytes"] is None
    assert body["logs"]["size_bytes"] is None


async def test_status_log_metering_reports_a_real_empty_dir_as_zero_not_unmeasured(
    engine: Engine, tmp_path: Path
) -> None:
    """The other half of #1563's distinction: an existing, readable, EMPTY log dir measures 0 bytes
    of files and a real free-space figure. Zero is a measurement and must stay spelled as ``0`` —
    if this ever reports ``None`` the probe has started confusing "nothing there" with "did not
    look", which is the defect in the opposite direction."""
    log_dir = tmp_path / "empty_logs"
    log_dir.mkdir()
    app = create_app(engine, allow_no_auth=True, log_dir=str(log_dir))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/status")).json()
    assert body["logs"]["size_bytes"] == 0
    assert body["logs"]["disk_free_bytes"] is not None and body["logs"]["disk_free_bytes"] > 0


async def test_status_update_field_absent_by_default(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # #30 (ADR 0026): with no update-check runner wired/passed (the default test engine), the additive
    # /status `update` field is None — the existing payload is unchanged when off.
    body = (await client.get("/status")).json()
    assert body.get("update") is None


async def test_status_update_field_surfaces_diff(engine: Engine, client: httpx.AsyncClient) -> None:
    # #30 (ADR 0026): when the no-network diff finds a newer pinned version, /status carries the
    # version strings + the bool (PHI-free). Drive the runner with an injected pinned source so the
    # test doesn't depend on the installed distribution metadata.
    from messagefoundry.config.settings import UpdateCheckSettings
    from messagefoundry.pipeline.update_check import UpdateCheckRunner

    runner = UpdateCheckRunner(
        UpdateCheckSettings(),
        current_version="0.0.1",
        pinned_source=lambda: "9.9.9",
    )
    runner.run_once()
    engine._update_check_runner = runner  # the engine would wire this in start()
    body = (await client.get("/status")).json()
    assert body["update"] == {
        "current_version": "0.0.1",
        "pinned_version": "9.9.9",
        "update_available": True,
    }


async def test_integrity_check_endpoint(engine: Engine, client: httpx.AsyncClient) -> None:
    r = await client.post("/status/integrity-check")
    assert r.status_code == 200
    assert r.json()["ok"] is True


async def test_cluster_status_single_node(client: httpx.AsyncClient) -> None:
    # Track B Step 7: a default Engine.create → NullCoordinator → single-node posture.
    r = await client.get("/cluster/status")
    assert r.status_code == 200
    body = r.json()
    assert body["clustered"] is False
    assert body["is_leader"] is True
    assert body["role"] == "single-node"  # Workstream A5: active-passive role
    assert body["node_id"]  # non-empty stable identity
    assert body["config_version"] == 0


async def test_cluster_nodes_single_node(client: httpx.AsyncClient) -> None:
    # Single-node /cluster/nodes synthesizes exactly one self-member, leader, with the matching
    # leader_node_id and lease state (Workstream A5).
    r = await client.get("/cluster/nodes")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) == 1
    node = body["nodes"][0]
    assert node["is_leader"] is True
    assert node["status"] == "active"
    assert body["leader_node_id"] == node["node_id"]
    # A5: single-node reports itself as the lease owner with no expiry (permanently leader, no lease row).
    assert body["lease_owner"] == node["node_id"]
    assert body["lease_expires_at"] is None
    # The single-node synthetic entry has no heartbeat history.
    assert node["started_at"] is None and node["last_seen"] is None
    # ADR 0096: single-node is unhandicapped + promotable (surfaced in /cluster/nodes).
    assert node["acquire_delay_seconds"] == 0.0
    assert node["promotable"] is True
    # BACKLOG #1509: the freshness verdict is published; the synthetic entry has no heartbeat.
    assert node["fresh"] is False


async def test_connections_includes_registry_connections(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        InboundConnection,
        OutboundConnection,
        Registry,
        Send,
    )

    reg = Registry()
    reg.add_inbound(
        InboundConnection("adt_in", ConnectionSpec(ConnectorType.MLLP, {"port": 2575}), router="r")
    )
    reg.add_outbound(
        OutboundConnection(
            "adt_archive", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"})
        )
    )
    reg.add_router("r", lambda msg: ["h"])
    reg.add_handler("h", lambda msg: Send("adt_archive", msg))
    engine.add_registry(reg)
    # Simulate traffic so the inbound→outbound edge metric exists.
    await engine.store.enqueue_message(
        channel_id="adt_in", raw=ADT, deliveries=[("adt_archive", ADT)], source_type="mllp"
    )

    by_name = {r["name"]: r for r in (await client.get("/connections")).json()}
    assert by_name["adt_in ▸ in"]["direction"] == "in"
    assert by_name["adt_in ▸ in"]["method"] == "MLLP"
    assert by_name["adt_in ▸ in"]["read"] == 1
    assert by_name["adt_in ▸ adt_archive"]["destination"] == "adt_archive"

    assert any(c["id"] == "adt_in" for c in (await client.get("/channels")).json())
    assert (await client.get("/status")).json()["engine"]["channels_total"] >= 1


async def test_connection_operations(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        InboundConnection,
        OutboundConnection,
        Registry,
        Send,
    )

    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out1", m))
    (tmp_path / "out").mkdir()
    engine.add_registry(reg)
    await (
        engine.start()
    )  # start the runner so the pooled delivery dispatcher exists (outbound pause)
    rr = engine.registry_runner
    assert rr is not None

    # start / stop / restart an INBOUND connection (the dual-role handler routes to the inbound path)
    assert (await client.post("/connections/in1/start")).json()["running"] is True
    assert (await client.post("/connections/in1/stop")).json()["running"] is False
    assert (await client.post("/connections/in1/restart")).json()["running"] is True

    # The SAME start/stop/restart handlers are now DUAL-ROLE — they also drive an OUTBOUND (previously a
    # 404), returning the outbound's running state (restart keeps it running/warm).
    assert (await client.post("/connections/out1/restart")).json()["running"] is True

    # require-stopped-before-purge: a RUNNING outbound 409s (its queue can't be cleanly cleared while a
    # row may be inflight); an unknown name still 404s FIRST (ordered before the 409).
    assert (await client.post("/connections/out1/purge")).status_code == 409
    assert (await client.post("/connections/nope/purge")).status_code == 404
    assert (await client.post("/connections/nope/start")).status_code == 404

    # Stop the outbound → delivery pauses and the idle lane quiesces (zero in-flight); status → 'stopped'.
    await _quiesced_stopped_outbound(engine, client)
    assert rr.outbound_status("out1") == "stopped"

    # A queued delivery to the STOPPED outbound stays PENDING (never delivered) and can now be purged.
    await engine.store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[("out1", ADT)])
    assert (await client.post("/connections/out1/purge")).json()["cancelled"] == 1


async def _quiesced_stopped_outbound(engine: Engine, client: httpx.AsyncClient) -> None:
    """Stop ``out1`` and wait for the lane to quiesce — the precondition purge requires."""
    rr = engine.registry_runner
    assert rr is not None
    assert (await client.post("/connections/out1/stop")).json()["running"] is False
    for _ in range(200):
        if rr.outbound_quiesced("out1"):
            break
        await asyncio.sleep(0.02)
    assert rr.outbound_quiesced("out1") is True


async def _started_outbound_engine(engine: Engine, tmp_path: Path, inbounds: int = 1) -> None:
    """Attach an N-inbound→one-outbound FILE graph and start the runner (so the pooled delivery
    dispatcher exists for outbound pause/quiesce). ``inbounds`` defaults to 1; raise it to give one
    shared outbound several inbound edges."""
    (tmp_path / "out").mkdir()
    reg = Registry()
    for n in range(1, inbounds + 1):
        inbox = tmp_path / f"in{n}"
        inbox.mkdir()
        reg.add_inbound(
            InboundConnection(
                f"in{n}",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
                ),
                router="r",
            )
        )
    reg.add_outbound(
        OutboundConnection(
            "out1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out1", m))
    engine.add_registry(reg)
    await engine.start()


async def _out1_rows(client: httpx.AsyncClient) -> list[dict[str, object]]:
    """Every /connections row whose control target is out1 — standalone or traffic-derived."""
    return [r for r in (await client.get("/connections")).json() if r["destination"] == "out1"]


async def _await_out1_edges(
    client: httpx.AsyncClient, expected: set[str]
) -> list[dict[str, object]]:
    """Poll until out1's rows are keyed by exactly the ``expected`` inbound names, then return them.

    A traffic edge is keyed off the outbox metrics, which appear once the delivery row is written — so
    a bounded poll rather than a sleep. It returns the WHOLE out1 set, letting the caller assert the
    standalone row went away rather than merely that an edge arrived; on a timeout it returns whatever
    is there, so the caller's own assertion reports the mismatch."""
    for _ in range(200):
        rows = await _out1_rows(client)
        if {r["channel_id"] for r in rows} == expected:
            return rows
        await asyncio.sleep(0.02)
    return await _out1_rows(client)


async def test_outbound_purge_stopping_window_is_409(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # A paused-but-not-yet-quiesced ("stopping") outbound — the window a hung/slow destination sits in
    # while its one in-flight head resolves — still 409s: require-stopped means QUIESCED (zero in-flight),
    # not merely pause-requested. Reproduce that window deterministically by marking the lane paused
    # WITHOUT its quiescence Event set (a real hung destination gets there via the delivery gate).
    await _started_outbound_engine(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    rr._outbound_paused.add("out1")  # white-box: the 'stopping' window (paused, not yet drained)
    assert rr.outbound_quiesced("out1") is False
    assert rr.outbound_status("out1") == "stopping"
    await engine.store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[("out1", ADT)])
    assert (await client.post("/connections/out1/purge")).status_code == 409


async def test_connections_standalone_no_edge_outbound_row_survives_start(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # BACKLOG #1568. A no-traffic outbound (no inbound→outbound edge metric) must carry a STANDALONE
    # destination row in EVERY state, RUNNING INCLUDED, because that row is what a browser client reads
    # its Start/Stop/Restart target from. An earlier form listed only the paused states, so starting an
    # idle outbound deleted the very control that stops it again: on a deploying site an operator would
    # have had to fall back to the JSON API to get the lane back.
    #
    # The `paused` field stays INDEPENDENT of the display status, and that is a SEPARATE property this
    # test goes on pinning: 'running' → paused False, 'stopping' (paused, an in-flight head not yet
    # drained) → paused False, 'stopped' (quiesced) → paused True. Only the last is purge-eligible.
    await _started_outbound_engine(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None

    # Running + no traffic: the row is there, and it names out1 as the control target.
    running = await _out1_rows(client)
    assert len(running) == 1  # exactly one standalone destination row
    assert running[0]["role"] == "destination"
    assert running[0]["channel_id"] == "out1"  # standalone: keyed by the outbound, not an inbound
    assert running[0]["status"] == "running"
    assert running[0]["paused"] is False  # delivering → NOT purge-eligible

    # The 'stopping' window (paused, an in-flight head not yet drained) — reproduced deterministically the
    # same white-box way as test_outbound_purge_stopping_window_is_409 (paused WITHOUT quiescence set).
    rr._outbound_paused.add("out1")
    assert rr.outbound_status("out1") == "stopping"
    stopping = await _out1_rows(client)
    assert len(stopping) == 1  # still exactly one row — not one per state
    assert stopping[0]["role"] == "destination"
    assert stopping[0]["status"] == "stopping"
    assert stopping[0]["paused"] is False  # not yet quiesced → NOT purge-eligible

    # Quiesce it via the real stop_outbound path (an idle no-edge lane drains to zero in-flight at once).
    await rr.stop_outbound("out1")
    for _ in range(200):
        if rr.outbound_quiesced("out1"):
            break
        await asyncio.sleep(0.02)
    assert rr.outbound_status("out1") == "stopped"
    stopped = await _out1_rows(client)
    assert len(stopped) == 1
    assert stopped[0]["status"] == "stopped"
    assert stopped[0]["paused"] is True  # quiesced → purge-eligible


async def test_connections_idle_outbound_is_startable_and_stoppable_from_its_own_row(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # BACKLOG #1568, the acceptance the row asks for: start an idle outbound, see a RUNNING row, then
    # stop it again from that row's target — with no message ever sent. It drives the same control
    # routes a browser posts to, so it measures the operator's whole path rather than the row builder
    # alone; asserting on the row builder only would leave the control unmeasured, which is exactly the
    # gap the defect lived in.
    await _started_outbound_engine(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")
    for _ in range(200):
        if rr.outbound_quiesced("out1"):
            break
        await asyncio.sleep(0.02)
    assert (await _out1_rows(client))[0]["status"] == "stopped"

    assert (await client.post("/connections/out1/start")).status_code == 200
    started = await _out1_rows(client)
    assert len(started) == 1
    assert started[0]["status"] == "running"

    # The Stop the defect removed: it targets the SAME name the running row carries.
    assert (await client.post(f"/connections/{started[0]['destination']}/stop")).status_code == 200
    for _ in range(200):
        if rr.outbound_quiesced("out1"):
            break
        await asyncio.sleep(0.02)
    assert (await _out1_rows(client))[0]["status"] == "stopped"


async def test_connections_first_traffic_replaces_the_standalone_outbound_row(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # BACKLOG #1568: once the first message gives out1 a traffic edge, the standalone row must give way
    # to the edge row rather than sit beside it. The `oname in emitted_dests` dedupe is what does that,
    # and without this arm a regression there would show as a duplicated lane on the dashboard — two
    # rows for one connection, each with its own checkbox.
    await _started_outbound_engine(engine, tmp_path)
    before = await _out1_rows(client)
    assert [r["channel_id"] for r in before] == ["out1"]  # standalone, keyed by the outbound

    await engine.store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[("out1", ADT)])
    after = await _await_out1_edges(client, {"in1"})
    assert [r["channel_id"] for r in after] == ["in1"]  # one row, now keyed by the inbound edge


async def test_connections_one_outbound_with_two_inbound_edges_is_not_also_standalone(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # BACKLOG #1568: a shared outbound carries one row PER EDGE, and the dedupe has to hold when there
    # is more than one of them — a set membership test that passed on a single edge could still be
    # wrong here. Both edges present and no standalone row beside them.
    await _started_outbound_engine(engine, tmp_path, inbounds=2)
    for channel in ("in1", "in2"):
        await engine.store.enqueue_message(channel_id=channel, raw=ADT, deliveries=[("out1", ADT)])
    rows = await _await_out1_edges(client, {"in1", "in2"})
    assert sorted(r["channel_id"] for r in rows) == ["in1", "in2"]
    assert all(r["role"] == "destination" for r in rows)


async def test_connections_standalone_row_reads_stopped_when_the_graph_is_down(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """A standalone row must not say "running" on a node whose graph has been torn down.

    ``outbound_status`` reports "running" for any lane merely ABSENT from ``_outbound_paused`` — it
    never consults the runner's own ``running`` flag (``/status`` documents the same trap at its KPI
    split, which is why that block uses ``outbound_running``). The shape that reaches the API is the
    ADR 0157 demoted follower: ``Engine._stop_graph`` stops ONLY the runner and the node keeps serving
    as standby. Before #1568 an edge-less outbound produced no row at all there, so the contradiction
    below is one this fix would have INTRODUCED had the ``rr.running`` gate been left out.

    The discriminating assertion is the last one: it reads BOTH halves of a single payload, so a
    regression cannot pass by agreeing with itself. Drop the gate in ``list_connections`` and the
    source row still reads "stopped" while the destination row flips to "running"."""
    await _started_outbound_engine(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    assert (await _out1_rows(client))[0]["status"] == "running"

    await rr.stop()  # the demote shape: graph down, store + API still serving
    assert rr.running is False
    assert rr.outbound_status("out1") == "running"  # the raw tri-state, ungated — the trap itself
    assert rr.outbound_running("out1") is False  # what the lane is ACTUALLY doing

    # The row SURVIVES the teardown (that is #1568's whole point) and reports the lane honestly.
    down = await _out1_rows(client)
    assert len(down) == 1
    assert down[0]["status"] == "stopped"
    assert down[0]["paused"] is False  # never operator-paused, so still NOT purge-eligible

    # One payload, both roles, no contradiction: nothing on this node is running.
    rows = (await client.get("/connections")).json()
    assert {r["role"]: r["status"] for r in rows} == {"source": "stopped", "destination": "stopped"}


async def test_connections_standalone_row_reports_measured_zeros_not_nulls(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """BACKLOG #1817: a RUNNING standalone row carries its counters as measured values.

    The store's outbound aggregate groups every outbound-stage queue row, so an outbound with no edge
    has no queue row at all: zero queued, zero written, zero dead. Reporting those as null told a
    console "not measured", which it cannot tell apart from a real zero. Idle stays null because no
    delivery has happened to date it from -- the same null an edge row carries before its first one."""
    await _started_outbound_engine(engine, tmp_path)
    [row] = await _out1_rows(client)
    assert row["channel_id"] == "out1" and row["status"] == "running"  # the standalone row
    assert row["queue_depth"] == 0
    assert row["written"] == 0
    assert row["errored"] == 0
    assert row["backlog_seconds"] == 0.0  # empty queue: nothing to clear, the edge row's rule
    assert row["idle_seconds"] is None  # never delivered
    assert row["delivered_age_seconds"] is None  # nothing queued
    assert row["read"] is None  # a source-only field stays null on a destination row


async def test_connections_standalone_row_stays_null_over_traffic_it_cannot_attribute(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """BACKLOG #1817: the standalone row's zero is a reading, so it must not paper over real traffic.

    A queue row whose inbound this node does not run is skipped by the edge loop, so its outbound
    falls to a standalone row. That is the shape of another engine shard's inbound (the shard
    registry keeps every outbound but only its own inbounds) and of an inbound a reload removed. The
    row must say "not measured" (null) there. A blanket zero would hide a queued message; folding the
    edge in would count a sibling shard's traffic once per shard. This arm is what stops a constant
    zero from passing the test above."""
    await _started_outbound_engine(engine, tmp_path)
    # Stop the lane first so the queued row stays queued and the reading is stable.
    await _quiesced_stopped_outbound(engine, client)
    await engine.store.enqueue_message(channel_id="gone", raw=ADT, deliveries=[("out1", ADT)])
    [row] = await _out1_rows(client)
    assert row["channel_id"] == "out1" and row["status"] == "stopped"  # still the standalone row
    for field in ("queue_depth", "written", "errored", "backlog_seconds"):
        assert row[field] is None, field  # not measured on this row -- and never a false 0

    # Once that row is cancelled it reads zero on every count, so the zero is measured again. The
    # queue row itself stays in the store, so this arm fails if null keys on "any edge ever existed",
    # which would pin the row to null for good after one old message.
    assert (await client.post("/connections/out1/purge")).json()["cancelled"] == 1
    [row] = await _out1_rows(client)
    assert (row["queue_depth"], row["written"], row["errored"]) == (0, 0, 0)
    assert row["backlog_seconds"] == 0.0


async def test_engine_not_started_returns_503(tmp_path: Path) -> None:
    # App with no engine bound (and no lifespan to set one) → 503 on engine routes.
    transport = httpx.ASGITransport(app=create_app(allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/health")).status_code == 200  # health needs no engine
        assert (await c.get("/channels")).status_code == 503


async def test_purge_audits_every_completed_purge_including_zero_cancelled(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """BACKLOG #1641: the ungated purge path writes its own outcome row, ``cancelled=0`` included.

    Why the zero-cancel row is unconditional — and what the GATED path does and does not record —
    is stated once, on the write itself in ``purge_connection``. This test pins both halves of the
    ambiguity that rationale turns on: cancelled=0 writes a row, a 409 does not."""
    await _started_outbound_engine(engine, tmp_path)
    await _quiesced_stopped_outbound(engine, client)

    # Nothing queued: a real, completed purge that cancelled zero rows. Audited anyway, and the
    # requested scope is carried through (a `top` purge and an `all` purge are different commands).
    assert (await client.post("/connections/out1/purge?scope=top")).json()["cancelled"] == 0
    rows = await engine.store.list_audit(action="connection_purge")
    assert len(rows) == 1
    assert json.loads(rows[0]["detail"] or "{}") == {
        "connection": "out1",
        "scope": "top",
        "cancelled": 0,
    }
    # #1641 names the missing client alongside the missing outcome, so both are pinned here.
    # "127.0.0.1" is httpx ASGITransport's default peer, which client_ip() reads off the scope.
    assert rows[0]["actor"] == "system" and rows[0]["client"] == "127.0.0.1"
    assert rows[0]["channel_id"] is None  # an outbound spans channels

    # A purge that DOES cancel records the count.
    await engine.store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[("out1", ADT)])
    assert (await client.post("/connections/out1/purge")).json()["cancelled"] == 1
    rows = await engine.store.list_audit(action="connection_purge")
    assert len(rows) == 2
    assert json.loads(rows[0]["detail"] or "{}") == {
        "connection": "out1",
        "scope": "all",
        "cancelled": 1,
    }

    # A REFUSED purge (409 — the outbound is running again) cancelled nothing and never ran, so it
    # adds no row. This is the other half of the ambiguity: 409 stays silent, cancelled=0 does not.
    assert (await client.post("/connections/out1/start")).json()["running"] is True
    assert (await client.post("/connections/out1/purge")).status_code == 409
    assert len(await engine.store.list_audit(action="connection_purge")) == 2


async def test_connection_control_audits_the_resolved_role(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """BACKLOG #1642: start/stop/restart write a ``connection_control`` row naming the RESOLVED role.

    Why the resolved role is recorded rather than ``_dual_role_control``'s ``role`` argument is
    stated once, in the ``_record_control_audit`` docstring. These assertions pin the resolved
    value, so a change back to the raw argument fails here."""
    await _started_outbound_engine(engine, tmp_path)

    # An INBOUND resolves to `source`, and the connection IS its channel.
    assert (await client.post("/connections/in1/stop")).json()["running"] is False
    rows = await engine.store.list_audit(action="connection_control")
    assert len(rows) == 1
    assert json.loads(rows[0]["detail"] or "{}") == {
        "connection": "in1",
        "action": "stop",
        "role": "source",
        "running": False,
    }
    assert rows[0]["channel_id"] == "in1"
    assert rows[0]["actor"] == "system" and rows[0]["client"] == "127.0.0.1"

    # An OUTBOUND resolves to `destination` and carries no channel.
    assert (await client.post("/connections/out1/restart")).json()["running"] is True
    rows = await engine.store.list_audit(action="connection_control")
    assert len(rows) == 2
    assert json.loads(rows[0]["detail"] or "{}") == {
        "connection": "out1",
        "action": "restart",
        "role": "destination",
        "running": True,
    }
    assert rows[0]["channel_id"] is None

    # All three verbs are recorded, not just the two above.
    assert (await client.post("/connections/in1/start")).json()["running"] is True
    verbs = [
        json.loads(a["detail"] or "{}")["action"]
        for a in await engine.store.list_audit(action="connection_control")
    ]
    assert sorted(verbs) == ["restart", "start", "stop"]

    # A 404 moved no lane, so it writes no row (the denial paths audit as auth.channel_denied).
    assert (await client.post("/connections/nope/start")).status_code == 404
    assert len(await engine.store.list_audit(action="connection_control")) == 3


# --- websocket (sync TestClient against a lifespan-managed app) ---------------


def test_ws_stats_pushes_queue_depth(tmp_path: Path) -> None:
    app = create_managed_app(db_path=tmp_path / "ws.db", poll_interval=0.05)
    # TestClient drives the lifespan, so the engine is created/started on its own loop.
    with TestClient(app) as tc, tc.websocket_connect("/ws/stats") as ws:
        data = ws.receive_json()
        assert "outbox_by_status" in data
        assert isinstance(data["outbox_by_status"], dict)
