# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0114 AC-7's **degraded gauge** — proving the three operator surfaces actually EMIT it.

AC-7 says the store degrades "loudly", and its compensating-control story assumes an operator can
SEE the degraded state. For the whole life of sub-lever A they could not: the two properties existed
on ``SqlServerStore`` and were read by nothing but the store's own tests — no ``/status`` field, no
``/metrics`` series, no console row. The entire signal was one WARNING at ``open()``, in a log nobody
was watching, that (before PR #86) named the wrong cause. That is a load-bearing part of why the gate
could degrade on EVERY open in EVERY deployment without anyone noticing.

So these tests assert **emission**, not the existence of a property:

* ``/metrics`` renders ``messagefoundry_store_claim_proc_effective`` (and the head-form gauge) with
  the right value — and OMITS both when the lever was never requested, because a constant ``0`` on
  every SQLite fleet is noise a scraper cannot alert on.
* ``/status`` carries the human-readable ``degraded_reason``, which Prometheus deliberately does not
  (it is free text embedding a proc name and, on the probe-failure arm, an exception string — a
  label would blow the cardinality budget and break the exporter's strict label allowlist).
* the console's store panel renders the reason on the page an operator actually reads.

The gauge's producer (``SqlServerStore.claim_proc_status``) is driven from the gate's own suite
(``test_adr0114_claim_proc.py``); here the store accessor is substituted so the SURFACES are what is
under test, on a SQLite engine that needs no SQL Server.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families

from messagefoundry.api import create_app
from messagefoundry.api.metrics import render_metrics
from messagefoundry.api.models import (
    ClusterNodeList,
    ClusterStatus,
    DbInfo,
    DrStatus,
    EngineInfo,
    SecurityPosture,
    ServiceStatusInfo,
    SystemStatus,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import ClaimProcStatus
from messagefoundry_webconsole.pages import monitoring

# The exporter's strict label allowlist (the #21 PHI contract). The new gauges are label-LESS, so
# they must not widen it.
ALLOWED_LABELS = {"connection", "destination", "status", "version", "le"}

_GREEN = ClaimProcStatus(
    effective=True,
    degraded_reason=None,
    head_forms={
        "mefor_claim_fifo_heads_cid_v1": "rewritten",
        "mefor_claim_fifo_heads_dst_v1": "rewritten",
    },
)
_DEGRADED = ClaimProcStatus(
    effective=False,
    degraded_reason=(
        "stored procedure dbo.mefor_claim_fifo_heads_cid_v1 is DEPLOYED but its definition is"
        " unreadable — GRANT VIEW DEFINITION"
    ),
    head_forms={},
)
_VERBATIM = ClaimProcStatus(
    effective=True,
    degraded_reason=None,
    head_forms={
        "mefor_claim_fifo_heads_cid_v1": "verbatim",
        "mefor_claim_fifo_heads_dst_v1": "rewritten",
    },
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "gauge.db", poll_interval=0.02)
    eng.started_at = 1.0
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


def _set_gauge(engine: Engine, value: ClaimProcStatus | None) -> None:
    """Substitute the store's gate verdict. The SQLite store answers ``None`` (AC-6: it has no such
    lever), so a value here stands in for a SQL Server store whose gate reached that outcome."""
    engine.store.claim_proc_status = lambda: value  # type: ignore[method-assign]


def _samples(exposition: str, name: str) -> list[float]:
    return [
        s.value
        for fam in text_string_to_metric_families(exposition)
        for s in fam.samples
        if s.name == name
    ]


# --- /metrics -------------------------------------------------------------------------------


async def test_metrics_emits_zero_when_the_gate_degraded(engine: Engine) -> None:
    _set_gauge(engine, _DEGRADED)
    exposition = (await render_metrics(engine)).decode()
    assert _samples(exposition, "messagefoundry_store_claim_proc_effective") == [0.0]


async def test_metrics_emits_one_when_the_gate_passed(engine: Engine) -> None:
    _set_gauge(engine, _GREEN)
    exposition = (await render_metrics(engine)).decode()
    assert _samples(exposition, "messagefoundry_store_claim_proc_effective") == [1.0]


async def test_metrics_omits_the_gauges_when_the_lever_was_never_requested(engine: Engine) -> None:
    """ABSENT, not 0. Every SQLite/Postgres fleet — and every SQL Server fleet with the flag off —
    would otherwise publish a permanent ``claim_proc_effective 0``, which reads as "the proc path is
    broken here" and is unalertable. The default engine must therefore emit neither series."""
    exposition = (await render_metrics(engine)).decode()  # SQLite store -> None, no substitution
    assert _samples(exposition, "messagefoundry_store_claim_proc_effective") == []
    assert _samples(exposition, "messagefoundry_store_claim_proc_head_verbatim") == []


async def test_metrics_head_verbatim_gauge_flags_a_non_rewriting_engine(engine: Engine) -> None:
    """No engine measured to date stores a ``CREATE OR ALTER`` head verbatim, so a fleet reporting 1
    is a live counterexample to the gate's compatibility assumption — worth an alert, not a fault."""
    _set_gauge(engine, _VERBATIM)
    assert _samples(
        (await render_metrics(engine)).decode(), "messagefoundry_store_claim_proc_head_verbatim"
    ) == [1.0]
    _set_gauge(engine, _GREEN)
    assert _samples(
        (await render_metrics(engine)).decode(), "messagefoundry_store_claim_proc_head_verbatim"
    ) == [0.0]


async def test_metrics_gauges_carry_no_labels_and_never_the_reason_string(engine: Engine) -> None:
    """The reason is free text (a proc name; an exception string on the probe-failure arm). Carried
    as a label it would be unbounded cardinality AND a breach of the #21 label allowlist, so it must
    never reach the exposition — it lives on /status and the console instead."""
    _set_gauge(engine, _DEGRADED)
    exposition = (await render_metrics(engine)).decode()
    assert "VIEW DEFINITION" not in exposition
    for fam in text_string_to_metric_families(exposition):
        for sample in fam.samples:
            assert set(sample.labels) <= ALLOWED_LABELS, f"{sample.name} widened the allowlist"


# --- /status --------------------------------------------------------------------------------


async def test_status_carries_the_degraded_reason(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    _set_gauge(engine, _DEGRADED)
    body = (await client.get("/status")).json()
    assert body["claim_proc"]["effective"] is False
    assert "VIEW DEFINITION" in body["claim_proc"]["degraded_reason"]


async def test_status_carries_the_matched_head_forms_when_green(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    _set_gauge(engine, _VERBATIM)
    claim_proc = (await client.get("/status")).json()["claim_proc"]
    assert claim_proc["effective"] is True
    assert claim_proc["degraded_reason"] is None
    assert claim_proc["head_forms"]["mefor_claim_fifo_heads_cid_v1"] == "verbatim"


async def test_status_omits_the_field_when_the_lever_was_never_requested(
    client: httpx.AsyncClient,
) -> None:
    """Additive + defaulted: the default (SQLite) payload is unchanged, so an older client
    deserializes /status exactly as before."""
    assert (await client.get("/status")).json()["claim_proc"] is None


# --- the console store panel ------------------------------------------------------------------


def _page(claim_proc: object) -> str:
    """Render the console status page around a SystemStatus carrying ``claim_proc``."""
    sys_status = SystemStatus(
        engine=EngineInfo(
            version="0.0.0",
            uptime_seconds=1.0,
            pid=1,
            channels_total=0,
            channels_running=0,
            channels_stopped=0,
            outbox_by_status={},
        ),
        db=DbInfo(
            path="mem",
            size_bytes=0,
            disk_free_bytes=10 * 1024**3,
            journal_mode="wal",
            messages=0,
            events=0,
            audit=0,
        ),
        claim_proc=claim_proc,  # type: ignore[arg-type]
    )
    return str(
        monitoring.status(
            sys_status,
            SecurityPosture(
                backend="sqlserver",
                encryption_enabled=True,
                key_source="env",
                require_encryption=True,
                allow_unencrypted_phi=False,
            ),
            ClusterStatus(
                node_id="n1", clustered=False, is_leader=True, role="single-node", config_version=0
            ),
            ClusterNodeList(nodes=[], leader_node_id=None, lease_owner=None, lease_expires_at=None),
            DrStatus(enabled=False, active=False, threshold="0", activation_mode="manual"),
            ServiceStatusInfo(enabled=False, state="unknown", service_name="mefor"),
        )
    )


def test_console_store_panel_shows_the_degrade_and_its_reason() -> None:
    html = _page({"effective": False, "degraded_reason": "GRANT VIEW DEFINITION on dbo.the_proc"})
    assert "DEGRADED" in html
    assert "GRANT VIEW DEFINITION on dbo.the_proc" in html


def test_console_store_panel_shows_the_matched_head_forms_when_green() -> None:
    html = _page({"effective": True, "head_forms": {"mefor_claim_fifo_heads_cid_v1": "verbatim"}})
    assert "DEGRADED" not in html
    assert "mefor_claim_fifo_heads_cid_v1: verbatim" in html


def test_console_store_panel_is_absent_when_the_lever_was_never_requested() -> None:
    """The default page is unchanged — no empty row, no "—" that reads as a broken lever."""
    assert "Claim path" not in _page(None)
