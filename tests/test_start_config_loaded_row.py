# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A start records which config it loaded and sets the provenance baseline (vault BACKLOG #2597).

ADR 0041 D1 named a startup row beside the reload row, and none was written: after a plain start
the audit held no row naming the config, and ``GET /config/provenance`` answered ``loaded: false``
until the first reload. These tests drive the managed app's real lifespan, the path ``serve`` runs.
Each reading sits beside a control: a start with no config writes no row, and an on-disk edit after
the start reads as drift, so the baseline is a real digest and not a placeholder.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from messagefoundry.api import create_managed_app
from messagefoundry.config.fingerprint import config_fingerprint
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests.test_reload_dir_only_moves_on_apply import _write_valid_config


def _app(tmp_path: Path, *, with_config: bool = True) -> tuple[FastAPI, Path]:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    app = create_managed_app(
        db_path=tmp_path / "start.db",
        config_dir=cfg if with_config else None,
        poll_interval=0.05,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    return app, cfg


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _rows(engine: Engine, action: str) -> list[dict[str, Any]]:
    return [json.loads(r["detail"]) for r in await engine.store.list_audit(action=action)]


async def test_a_start_writes_one_config_loaded_row_with_the_loaded_digest(tmp_path: Path) -> None:
    app, cfg = _app(tmp_path)
    async with app.router.lifespan_context(app), _client(app) as c:
        engine: Engine = app.state.engine
        rows = await _rows(engine, "config_loaded")
        posture = (await c.get("/security/posture")).json()
    assert len(rows) == 1
    row = rows[0]
    assert row["dir"] == str(cfg.resolve())
    assert row["fingerprint"] == config_fingerprint(cfg)
    assert row["inbound"] == 1 and row["outbound"] == 1
    assert "shard" in row and row["shard"] is None  # a single-process start owns the whole graph
    assert isinstance(row["node"], str) and row["node"]
    # The row records the list GET /security/posture reports, from the same reader.
    switches = [entry["switch"] for entry in posture["loosenings"]]
    assert switches, "control: this unkeyed test store reports at least one loosening"
    assert row["loosenings"] == switches


async def test_provenance_has_a_baseline_from_the_start(tmp_path: Path) -> None:
    app, cfg = _app(tmp_path)
    started_with = config_fingerprint(cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        before = (await c.get("/config/provenance")).json()
        with (cfg / "cfg.py").open("a", encoding="utf-8") as fh:
            fh.write("# an edit made after the start and never reloaded\n")
        after_edit = (await c.get("/config/provenance")).json()
    assert before["loaded"] is True
    assert before["fingerprint"] == started_with
    assert before["drift"] is False
    # Control: the baseline is a real digest, so an on-disk edit reads as drift.
    assert after_edit["loaded"] is True
    assert after_edit["drift"] is True


async def test_a_start_with_no_config_writes_no_row(tmp_path: Path) -> None:
    app, _cfg = _app(tmp_path, with_config=False)
    async with app.router.lifespan_context(app), _client(app) as c:
        engine: Engine = app.state.engine
        rows = await _rows(engine, "config_loaded")
        prov = (await c.get("/config/provenance")).json()
        health = await c.get("/health")
    assert health.status_code == 200, "control: the app started"
    assert rows == []
    assert prov["loaded"] is False


async def test_a_failed_start_row_does_not_block_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = MessageStore.record_audit

    async def _refuse_start_row(self: MessageStore, action: str, *a: Any, **kw: Any) -> Any:
        if action == "config_loaded":
            raise RuntimeError("audit store unavailable")
        return await real(self, action, *a, **kw)

    monkeypatch.setattr(MessageStore, "record_audit", _refuse_start_row)
    app, _cfg = _app(tmp_path)
    async with app.router.lifespan_context(app), _client(app) as c:
        engine: Engine = app.state.engine
        prov = (await c.get("/config/provenance")).json()
        rr = engine.registry_runner
        assert rr is not None and rr.running, "the graph is serving"
        rows = await _rows(engine, "config_loaded")
    assert rows == []
    assert prov["loaded"] is True


async def test_a_reload_row_names_its_shard_node_and_the_running_digest(tmp_path: Path) -> None:
    app, cfg = _app(tmp_path)
    async with app.router.lifespan_context(app), _client(app) as c:
        engine: Engine = app.state.engine
        r = await c.post("/config/reload", json={"config_dir": str(cfg)})
        assert r.status_code == 200, r.text
        reload_rows = await _rows(engine, "config_reload")
        start_rows = await _rows(engine, "config_loaded")
    assert len(reload_rows) == 1 and len(start_rows) == 1
    # One digest per load: the row names the baseline the provenance route compares against.
    assert reload_rows[0]["fingerprint"] == config_fingerprint(cfg)
    assert reload_rows[0]["dir"] == str(cfg.resolve())
    assert reload_rows[0]["node"] == start_rows[0]["node"]
    assert "shard" in reload_rows[0]
    assert "loosenings" not in reload_rows[0]


async def test_an_unreadable_vcs_head_degrades_the_same_way_at_every_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One best-effort rule for the start, a dry run and an applied reload. The reload used to
    tolerate only OSError while the start also tolerated a decode error, so the same bundle that
    started cleanly would have refused a reload."""
    import messagefoundry.config.fingerprint as fp_mod

    app, cfg = _app(tmp_path)

    def _undecodable(_path: Path) -> dict[str, object]:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(fp_mod, "config_fingerprint_detail", _undecodable)
    async with app.router.lifespan_context(app), _client(app) as c:
        engine: Engine = app.state.engine
        assert engine.loaded_config_fingerprint is None, "the start degraded, it did not refuse"
        dry = await c.post("/config/reload", json={"config_dir": str(cfg), "dry_run": True})
        real = await c.post("/config/reload", json={"config_dir": str(cfg)})
        start_rows = await _rows(engine, "config_loaded")
    assert dry.status_code == 200, dry.text
    assert real.status_code == 200, real.text
    assert real.json()["failures"] == ["config_fingerprint"]
    assert len(start_rows) == 1 and "fingerprint" not in start_rows[0]
    # Marked like a reload's, so a reader can tell a failed digest from a row that never had one.
    assert start_rows[0]["degraded"] is True
    assert start_rows[0]["failed_steps"] == ["config_fingerprint"]
