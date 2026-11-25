# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A channel-scoped caller on ``GET /metrics``, ``GET /logs/tail`` and the audit reads (BACKLOG #4346,
the route build of #1152, ASVS 8.2.2).

Each of these answered a caller limited to some channels with data from every channel. Now:

* ``GET /metrics`` NARROWS: a scoped caller reads only its own inbounds' series. Every
  per-destination series and the latency histogram are dropped, as the dashboard drops a shared
  outbound for that caller. The aggregates with no connection or destination label stay, as on
  ``GET /stats``.
* ``GET /logs/tail`` REFUSES a scoped caller: a log line is not attributable to one channel, so
  there is nothing to narrow it by.
* ``GET /audit``, ``GET /audit/export`` and their ``/ui`` twins REFUSE a scoped caller. The owner's
  answer of 2026-10-26 was "narrow or refuse"; an Auditor who needs the whole trail gets the
  all-channels grant.

Every refusal writes an ``auth.channel_denied`` row. Each test has an all-channels caller with the
same roles in the same run as its positive control, so a mis-seeded fixture fails the control
rather than letting the scoped side pass on silence.

NOT-DEPLOYED beta: these are gaps a first deployment would have carried, not a live exposure.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import auth_routes, create_app
from messagefoundry.api.metrics import (
    DEFAULT_LATENCY_BUCKETS,
    _render_snapshot,
    gather_snapshot,
    scoped_snapshot,
)
from messagefoundry.api.security import ExportStopped, recheck_standing
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.sync_reply import SyncReplyMetrics
from messagefoundry.store.store import LatencyHistogram
from tests._admin_account import create_local_user_chosen

# The seeded estate the monitoring-plane probe stands on: inbounds IB_A and IB_B, shared outbound
# OB_X, traffic on both inbounds.
from tests.test_monitoring_scope_doc_drift import (  # noqa: F401
    PW,
    _login,
    engine,
)

#: Every built-in role but Administrator, which is always all-channels and so never scoped.
_ROLES = [r.value for r in Role if r is not Role.ADMINISTRATOR]


async def _user(service: AuthService, username: str, scope: list[str]) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=_ROLES,
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    await service.set_channel_scope(user_id, scope, actor="admin")


async def _setup(eng: Engine, log_dir: Path | None = None) -> tuple[AuthService, httpx.AsyncClient]:
    service = AuthService(
        eng.store, AuthSettings(require_mfa=False, admin_write_rate_limit_enabled=False)
    )
    await service.initialize()
    await _user(service, "scoped", ["IB_A"])
    await _user(service, "wide", [ALL_CHANNELS])
    app = create_app(eng, auth=service, log_dir=str(log_dir) if log_dir else None)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    return service, client


async def _denials(eng: Engine, actor: str) -> int:
    rows = await eng.store.list_audit(limit=1000, action="auth.channel_denied", actor=actor)
    return len(rows)


async def test_metrics_narrows_to_the_callers_inbounds(engine: Engine) -> None:  # noqa: F811
    _service, c = await _setup(engine)
    async with c:
        s = await _login(c, "scoped")
        w = await _login(c, "wide")
        wide = (await c.get("/metrics", headers=w)).text
        scoped_r = await c.get("/metrics", headers=s)
    assert scoped_r.status_code == 200
    scoped = scoped_r.text
    # Positive control: the all-channels caller reads both inbounds and the shared outbound.
    assert 'connection="IB_A"' in wide and 'connection="IB_B"' in wide
    assert 'destination="OB_X"' in wide
    # The scoped caller reads its own inbound, and nothing of another channel or a shared outbound.
    assert 'connection="IB_A"' in scoped
    assert "IB_B" not in scoped
    assert "OB_X" not in scoped
    assert "destination=" not in scoped
    # The aggregates with no connection or destination label stay, as on GET /stats.
    assert any(line.startswith("messagefoundry_in_pipeline ") for line in scoped.splitlines())
    assert "messagefoundry_outbox_status{" in scoped


async def test_scoped_snapshot_keeps_the_aggregates_and_drops_every_destination(
    engine: Engine,  # noqa: F811
) -> None:
    # The fixture has queued deliveries but none done, so it has no latency histogram. One is
    # planted, on the in-scope inbound, so the drop is measured rather than read off an empty list.
    snap = replace(
        await gather_snapshot(engine),
        latency=[LatencyHistogram("IB_A", "OB_X", (1,) * len(DEFAULT_LATENCY_BUCKETS), 0.5, 1)],
    )
    # And a synchronous-reply series on each inbound, which the fixture has none of either.
    snap = replace(snap, sync_replies={n: SyncReplyMetrics(n) for n in ("IB_A", "IB_B")})
    assert snap.destinations
    assert 'destination="OB_X"' in _render_snapshot(snap).decode()
    narrowed = scoped_snapshot(snap, lambda name: name == "IB_A")
    assert set(narrowed.inbound) == {"IB_A"}
    assert set(narrowed.sync_replies) == {"IB_A"}
    assert narrowed.destinations == {}
    assert list(narrowed.latency) == []
    assert narrowed.outbox_by_status == snap.outbox_by_status
    assert narrowed.in_pipeline == snap.in_pipeline
    # A predicate that admits nothing leaves a well-formed exposition with no connection label.
    empty = _render_snapshot(scoped_snapshot(snap, lambda _name: False)).decode()
    assert "connection=" not in empty and "messagefoundry_build_info" in empty


async def test_logs_tail_refuses_a_scoped_caller(engine: Engine, tmp_path: Path) -> None:  # noqa: F811
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text(
        "2026-01-01 INFO messagefoundry wiring started IB_A\n"
        "2026-01-01 INFO messagefoundry wiring started IB_B\n",
        encoding="utf-8",
    )
    _service, c = await _setup(engine, log_dir)
    async with c:
        s = await _login(c, "scoped")
        w = await _login(c, "wide")
        rw = await c.get("/logs/tail", headers=w)
        before = await _denials(engine, "scoped")
        rs = await c.get("/logs/tail", headers=s)
    assert rw.status_code == 200 and any("IB_B" in line for line in rw.json()["lines"])
    assert rs.status_code == 403, rs.text
    assert "IB_B" not in rs.text and "IB_A" not in rs.text
    assert await _denials(engine, "scoped") == before + 1
    # No logs_view row is written for a page that was never served.
    views = await engine.store.list_audit(limit=100, action="logs_view", actor="scoped")
    assert views == []


async def test_audit_reads_refuse_a_scoped_caller(engine: Engine) -> None:  # noqa: F811
    # An audit row naming the out-of-scope channel, so the control has something to read.
    await engine.store.record_audit(
        "connection.flag", actor="someone", channel_id="IB_B", detail=json.dumps({"x": 1})
    )
    _service, c = await _setup(engine)
    async with c:
        s = await _login(c, "scoped")
        w = await _login(c, "wide")
        rw = await c.get("/audit", headers=w)
        ew = await c.get("/audit/export", headers=w)
        before = await _denials(engine, "scoped")
        rs = await c.get("/audit", headers=s)
        es = await c.get("/audit/export", headers=s)
    assert rw.status_code == 200 and any(e["channel_id"] == "IB_B" for e in rw.json()["entries"])
    assert ew.status_code == 200 and "IB_B" in ew.text
    assert rs.status_code == 403, rs.text
    assert es.status_code == 403, es.text
    assert "IB_B" not in rs.text and "IB_B" not in es.text
    assert await _denials(engine, "scoped") == before + 2
    # The refused export wrote no audit.export row.
    exports = await engine.store.list_audit(limit=100, action="audit.export", actor="scoped")
    assert exports == []


async def test_audit_export_stops_when_the_caller_becomes_scoped(
    engine: Engine,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The export re-resolves its caller before each page after the first (BACKLOG #1154). A caller
    that comes back channel-scoped may no longer read the trail, so the stream stops. A scope edit
    through ``set_channel_scope`` also ends the caller's sessions, which stops the export on its
    own, so the re-check is patched here to answer with the same session narrowed, which is the
    case the session rule cannot see."""
    for i in range(6):
        await engine.store.record_audit(
            "connection.flag", actor="someone", channel_id="IB_B", detail=json.dumps({"i": i})
        )
    monkeypatch.setattr(auth_routes, "_AUDIT_EXPORT_PAGE", 2)
    real = recheck_standing

    async def narrowed(*args: Any, **kwargs: Any) -> Identity | None:
        current = await real(*args, **kwargs)
        return None if current is None else replace(current, allowed_channels=frozenset({"IB_A"}))

    monkeypatch.setattr(auth_routes, "recheck_standing", narrowed)
    _service, c = await _setup(engine)
    async with c:
        w = await _login(c, "wide")
        # Over ASGITransport the stop reaches the client as the ExportStopped the handler raised;
        # tests/test_export_stop_wire.py measures how it ends on a real server.
        with pytest.raises((ExportStopped, httpx.HTTPError)):
            async with c.stream("GET", "/audit/export", headers=w) as r:
                assert r.status_code == 200
                async for _line in r.aiter_lines():
                    pass
    stops = await engine.store.list_audit(limit=10, action="audit.export.stopped", actor="wide")
    assert [json.loads(row["detail"])["reason"] for row in stops] == ["channel_scoped"]
