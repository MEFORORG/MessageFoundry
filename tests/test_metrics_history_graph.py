# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Historical-metrics ring + status-colored by-name data-flow graph (BACKLOG #76, ADR 0065 amendment).

Covers the two read-only, ``monitoring:read`` endpoints the console Flow & trends page renders from:
``GET /metrics/history`` (an in-memory ring fed by the ~1s /ws/stats sampler — no durable table, so
``store_schema`` stays false) and ``GET /graph/edges`` (the by-name Registry edge set from
``config.graph.build_wiring_graph`` joined with live status — NO channel/route object). Both are
metadata only (aggregate counts + connection names/status, never a message body)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.metrics import MetricsHistory
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path):
    eng = await Engine.create(tmp_path / "mh.db", poll_interval=0.02)
    yield eng
    await eng.stop()


# --- AC-9: the metrics-history ring ------------------------------------------------------------


def test_metrics_history_ring_dedupes_and_bounds() -> None:
    """record() dedupes on its min-interval (so several open /ws/stats sockets never double-append the
    same instant), keeps samples oldest-first, and never exceeds its capacity."""
    hist = MetricsHistory(capacity=3, min_interval=1.0)
    hist.record(100.0, {"pending": 1})
    hist.record(100.4, {"pending": 9})  # < 1.0s after the last -> dropped (dedupe)
    assert len(hist.samples()) == 1
    hist.record(101.0, {"pending": 2})
    hist.record(102.0, {"pending": 3})
    hist.record(103.0, {"pending": 4})  # capacity 3 -> the oldest (100.0) is evicted
    samples = hist.samples()
    assert [s.ts for s in samples] == [101.0, 102.0, 103.0]  # oldest-first, bounded
    assert samples[0].outbox_by_status == {"pending": 2}
    # The stored dict is a copy — mutating the caller's dict can't rewrite history.
    src = {"pending": 5}
    hist.record(104.0, src)
    src["pending"] = 999
    assert hist.samples()[-1].outbox_by_status == {"pending": 5}


async def test_metrics_history_endpoint_returns_recorded_samples(engine: Engine) -> None:
    """GET /metrics/history returns the ring's samples oldest-first with the ring capacity. The /ws/stats
    sampler feeds the ring in production; here we drive app.state.metrics_history directly."""
    app = create_app(engine, allow_no_auth=True)
    app.state.metrics_history.record(200.0, {"pending": 3, "done": 10})
    app.state.metrics_history.record(201.0, {"pending": 1, "done": 12})
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/metrics/history")).json()
    assert body["capacity"] == app.state.metrics_history.capacity
    assert [s["ts"] for s in body["samples"]] == [200.0, 201.0]
    assert body["samples"][0]["outbox_by_status"] == {"pending": 3, "done": 10}


async def test_metrics_history_empty_when_nothing_recorded(engine: Engine) -> None:
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/metrics/history")).json()
    assert body["samples"] == []


# --- AC-8: the status-colored by-name data-flow graph ------------------------------------------


def _wire(engine: Engine, outdir: Path) -> None:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "adt_in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="adt_router",
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
    reg.add_router("adt_router", lambda m: ["adt_handler"])
    reg.add_handler("adt_handler", lambda m: Send("adt_archive", m))
    engine.add_registry(reg)


async def test_graph_edges_from_registry(engine: Engine, tmp_path: Path) -> None:
    """GET /graph/edges renders the by-name inbound → router → handler → outbound edge set from the
    Registry (build_wiring_graph) with live per-node status — and constructs NO channel/route object."""
    _wire(engine, tmp_path / "out")
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/graph/edges")).json()

    kinds = {n["kind"] for n in body["nodes"]}
    # The ONLY node kinds are the four graph elements — there is deliberately no "channel"/"route" node.
    assert kinds == {"inbound", "router", "handler", "outbound"}
    assert "channel" not in kinds and "route" not in kinds

    by_kind = {(n["kind"], n["name"]): n for n in body["nodes"]}
    assert by_kind[("inbound", "adt_in")]["status"] in {"running", "stopped"}
    assert by_kind[("outbound", "adt_archive")]["status"] in {"running", "stopped"}
    # Router/handler nodes carry no live status.
    assert by_kind[("router", "adt_router")]["status"] is None

    edge_triples = {
        (e["source_kind"], e["source"], e["target_kind"], e["target"]) for e in body["edges"]
    }
    assert ("inbound", "adt_in", "router", "adt_router") in edge_triples  # declared binding
    assert ("router", "adt_router", "handler", "adt_handler") in edge_triples
    assert ("handler", "adt_handler", "outbound", "adt_archive") in edge_triples


async def test_graph_edges_empty_without_registry(engine: Engine) -> None:
    """With no graph loaded the endpoint returns an empty graph (never 500s)."""
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/graph/edges")).json()
    assert body["nodes"] == [] and body["edges"] == []
