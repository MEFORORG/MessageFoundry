# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Localhost API: connections, message tracking/detail/replay, stats, audit, WebSocket.

REST is exercised with httpx's ASGI transport (async, shares this test's event loop, so
the real async engine/store work). The WebSocket test uses starlette's TestClient against
a lifespan-managed app, which owns its engine on the client's own loop."""

from __future__ import annotations

from pathlib import Path

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
from messagefoundry.store import MessageStatus, OutboxStatus

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

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

    assert (await client.get("/messages/missing")).status_code == 404


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

    assert (await client.get("/messages/missing/outbound")).status_code == 404


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
    await client.get("/messages", params={"audit_summary": "true"})  # summary display → audited
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

    assert (await client.post("/messages/missing/replay")).status_code == 404


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

    for dest, mid in (("d1", a), ("d2", b)):
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
    assert msg["summary"] == "MRN 100001 · DOE, JANE"
    assert msg["event"] == "received"
    assert msg["metadata"] is None


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
    assert len(rows) == 1 and '"count": 2' in (rows[0]["detail"] or "")  # both calls coalesced


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


async def test_audit_summary_skips_when_no_summaries(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)]
    )  # no summary
    await client.get("/messages", params={"audit_summary": "true"})
    assert len(await engine.store.list_audit()) == 0


async def test_status_reports_engine_and_db(engine: Engine, client: httpx.AsyncClient) -> None:
    await _seed_message(engine)
    body = (await client.get("/status")).json()
    assert body["engine"]["version"]
    assert "outbox_by_status" in body["engine"]
    assert body["db"]["messages"] == 1
    assert body["db"]["journal_mode"].lower() == "wal"
    assert body["db"]["size_bytes"] > 0


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
    engine.add_registry(reg)

    # start / stop / restart an inbound connection
    assert (await client.post("/connections/in1/start")).json()["running"] is True
    assert (await client.post("/connections/in1/stop")).json()["running"] is False
    assert (await client.post("/connections/in1/restart")).json()["running"] is True
    await client.post("/connections/in1/stop")  # leave the listener stopped for teardown

    # purge an outbound connection's queue (across producers)
    await engine.store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[("out1", ADT)])
    assert (await client.post("/connections/out1/purge")).json()["cancelled"] == 1

    assert (await client.post("/connections/nope/start")).status_code == 404
    assert (await client.post("/connections/nope/purge")).status_code == 404


async def test_engine_not_started_returns_503(tmp_path: Path) -> None:
    # App with no engine bound (and no lifespan to set one) → 503 on engine routes.
    transport = httpx.ASGITransport(app=create_app(allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/health")).status_code == 200  # health needs no engine
        assert (await c.get("/channels")).status_code == 503


# --- websocket (sync TestClient against a lifespan-managed app) ---------------


def test_ws_stats_pushes_queue_depth(tmp_path: Path) -> None:
    app = create_managed_app(db_path=tmp_path / "ws.db", poll_interval=0.05)
    # TestClient drives the lifespan, so the engine is created/started on its own loop.
    with TestClient(app) as tc, tc.websocket_connect("/ws/stats") as ws:
        data = ws.receive_json()
        assert "outbox_by_status" in data
        assert isinstance(data["outbox_by_status"], dict)
