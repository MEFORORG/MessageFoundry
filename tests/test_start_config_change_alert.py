# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A start compares its config fingerprint with the store's baseline and alerts on a change (vault
BACKLOG #2597, step 4).

The baseline is the newest ``config_loaded``, ``config_reload`` or ``connection_flag_set`` row from
any node, since every engine shard and node shares one config directory. These tests drive the
managed app's real lifespan twice over one store, which is what a restart is. No ``[alerts]``
transport is configured, so the start falls back to ``LoggingAlertSink``; its ``config_changed`` is
wrapped to record each call, and the real method still runs.

The comparison is alert-only (step 5): a failed or slow baseline read costs the comparison and
never the start, so those cases assert that the graph is serving.
"""

from __future__ import annotations

import asyncio
import json
import textwrap
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from fastapi import FastAPI

import messagefoundry.api.app as app_module
import messagefoundry.config.fingerprint as fp_mod
from messagefoundry.api import create_managed_app
from messagefoundry.config.fingerprint import FINGERPRINT_SCHEME, config_fingerprint
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    EgressSettings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.store import MessageStore
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_reload_dir_only_moves_on_apply import _write_valid_config

_ACTIONS = ("config_loaded", "config_reload", "connection_flag_set")


@pytest.fixture
def alerts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Every ``config_changed`` the fallback sink raises, as its keyword payload plus ``name``."""
    seen: list[dict[str, Any]] = []
    real = LoggingAlertSink.config_changed

    def _record(self: LoggingAlertSink, name: str, **kw: Any) -> None:
        seen.append({"name": name, **kw})
        real(self, name, **kw)

    monkeypatch.setattr(LoggingAlertSink, "config_changed", _record)
    return seen


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    d = tmp_path / "cfg"
    _write_valid_config(d, tmp_path / "in", tmp_path / "out")
    return d


def _app(tmp_path: Path, cfg: Path) -> FastAPI:
    return create_managed_app(
        db_path=tmp_path / "start.db",
        config_dir=cfg,
        poll_interval=0.05,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _start_rows(engine: Engine) -> list[dict[str, Any]]:
    """The ``config_loaded`` rows, oldest first."""
    rows = await engine.store.list_audit(action="config_loaded")
    return [json.loads(r["detail"]) for r in reversed(rows)]


async def _start(tmp_path: Path, cfg: Path) -> list[dict[str, Any]]:
    """One start and stop over the shared store; returns every start row so far."""
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app):
        engine: Engine = app.state.engine
        rr = engine.registry_runner
        assert rr is not None and rr.running, "control: the graph is serving"
        return await _start_rows(engine)


def _edit(cfg: Path) -> None:
    with (cfg / "cfg.py").open("a", encoding="utf-8") as fh:
        fh.write("# an edit nobody reloaded\n")


# --- the store read ------------------------------------------------------------------------------


async def test_latest_audit_of_reads_the_newest_matching_row(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        assert await store.latest_audit_of(_ACTIONS) is None, "a fresh store has no baseline"
        await store.record_audit("config_loaded", actor="system", detail='{"fingerprint": "a"}')
        await store.record_audit("config_reload", actor="alice", detail='{"fingerprint": "b"}')
        await store.record_audit("export", actor="bob", detail="not a baseline")
        row = await store.latest_audit_of(_ACTIONS)
        assert row is not None
        # The newest MATCHING row: the later "export" row is skipped, the reload row wins.
        assert (row["action"], row["actor"], row["detail"]) == (
            "config_reload",
            "alice",
            '{"fingerprint": "b"}',
        )
        assert isinstance(row["ts"], float) and row["id"] > 0
        assert await store.latest_audit_of([]) is None
    finally:
        await store.close()


async def test_the_action_index_exists(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        async with store._read() as db:
            cur = await db.execute("PRAGMA index_list('audit_log')")
            names = {r[1] for r in await cur.fetchall()}
    finally:
        await store.close()
    assert "ix_audit_action" in names
    assert "ix_audit_ts" in names, "control: the instrument sees the existing index"


# --- the start comparison ------------------------------------------------------------------------


async def test_a_restart_on_the_same_config_raises_no_alert(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    await _start(tmp_path, cfg)
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is False
    assert rows[-1]["previous_fingerprint"] == config_fingerprint(cfg)


async def test_an_edit_then_a_restart_raises_one_alert_naming_both_digests(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    before = config_fingerprint(cfg)
    await _start(tmp_path, cfg)
    _edit(cfg)
    after = config_fingerprint(cfg)
    assert after != before, "control: the edit changed the digest"
    rows = await _start(tmp_path, cfg)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["name"] == f"config:{after[:12]}"
    assert (alert["fingerprint"], alert["previous_fingerprint"]) == (after, before)
    assert alert["baseline_action"] == "config_loaded"
    assert alert["baseline_actor"] == "system"
    assert alert["baseline_node"] == rows[0]["node"]
    assert alert["baseline_at"].endswith("+00:00")
    assert alert["node"] == rows[1]["node"] and alert["shard"] is None
    # The row records the comparison too, for a reader who never saw the alert.
    assert rows[-1]["changed"] is True and rows[-1]["previous_fingerprint"] == before
    # No path and no commit in the alert (CLAUDE.md sec. 9 discipline: the payload is labels only).
    assert str(cfg) not in json.dumps(alert)
    assert "dir" not in alert and "git_head" not in alert


async def test_a_reload_then_a_restart_raises_no_alert(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        _edit(cfg)
        r = await c.post("/config/reload", json={"config_dir": str(cfg)})
        assert r.status_code == 200, r.text
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is False
    assert rows[-1]["previous_fingerprint"] == config_fingerprint(cfg)


async def test_only_the_first_start_on_a_changed_config_alerts(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    await _start(tmp_path, cfg)
    _edit(cfg)
    await _start(tmp_path, cfg)
    assert len(alerts) == 1, "control: the first start on the changed config alerts"
    await _start(tmp_path, cfg)
    assert len(alerts) == 1, "the second start reads the first one's row as its baseline"


async def test_a_fresh_store_raises_no_alert(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert len(rows) == 1
    assert rows[0]["previous_fingerprint"] is None and rows[0]["changed"] is None


async def test_a_degraded_baseline_raises_no_alert(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    def _unreadable(_path: Path) -> dict[str, object]:
        raise OSError("unreadable bundle")

    with monkeypatch.context() as m:
        m.setattr(fp_mod, "config_fingerprint_detail", _unreadable)
        first = await _start(tmp_path, cfg)
    assert "fingerprint" not in first[0], "control: the first start's row has no digest"
    _edit(cfg)
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is None and rows[-1]["previous_fingerprint"] is None


@pytest.mark.parametrize("scheme", ["mefor-cfg-fp:v0", None], ids=["other-scheme", "no-scheme"])
async def test_a_baseline_under_another_scheme_raises_no_alert(
    tmp_path: Path,
    cfg: Path,
    monkeypatch: pytest.MonkeyPatch,
    alerts: list[dict[str, Any]],
    scheme: str | None,
) -> None:
    real = fp_mod.config_fingerprint_detail

    def _other_scheme(path: Path) -> dict[str, object]:
        detail = real(path)
        if scheme is None:
            del detail["scheme"]  # a row written before the tag existed
        else:
            detail["scheme"] = scheme
        return detail

    with monkeypatch.context() as m:
        m.setattr(fp_mod, "config_fingerprint_detail", _other_scheme)
        first = await _start(tmp_path, cfg)
    assert first[0].get("scheme") == scheme
    _edit(cfg)
    rows = await _start(tmp_path, cfg)
    assert rows[-1]["scheme"] == FINGERPRINT_SCHEME
    assert alerts == []
    assert rows[-1]["changed"] is None


def _failing_read(kind: str) -> Any:
    async def _raise(self: MessageStore, actions: Any) -> Any:
        raise RuntimeError("store unavailable")

    async def _hang(self: MessageStore, actions: Any) -> Any:
        await asyncio.sleep(30)

    async def _undecodable(self: MessageStore, actions: Any) -> Any:
        return {"id": 1, "ts": 0.0, "actor": "system", "action": "config_loaded", "detail": "{no"}

    return {"raises": _raise, "times-out": _hang, "undecodable": _undecodable}[kind]


@pytest.mark.parametrize("kind", ["raises", "times-out", "undecodable"])
async def test_a_failed_baseline_read_never_blocks_the_start(
    tmp_path: Path,
    cfg: Path,
    monkeypatch: pytest.MonkeyPatch,
    alerts: list[dict[str, Any]],
    kind: str,
) -> None:
    await _start(tmp_path, cfg)
    _edit(cfg)
    monkeypatch.setattr(app_module, "_CONFIG_BASELINE_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(MessageStore, "latest_audit_of", _failing_read(kind))
    loop = asyncio.get_running_loop()
    began = loop.time()
    rows = await _start(tmp_path, cfg)  # asserts the graph is serving
    assert loop.time() - began < 15, "the start was held past the bound"
    assert alerts == []
    assert rows[-1]["changed"] is None


async def test_a_reload_after_capture_does_not_change_the_comparison(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """A reload can land between the start's capture and its row (a cluster convergence reload
    runs once the engine starts). The comparison is of what this start loaded, not of that."""
    await _start(tmp_path, cfg)
    real_start = Engine.start
    other = {"fingerprint": "f" * 64, "scheme": FINGERPRINT_SCHEME, "files": 1}

    async def _start_then_swap(self: Engine) -> None:
        await real_start(self)
        self.loaded_config_fingerprint = dict(other)  # what a reload's swap does

    monkeypatch.setattr(Engine, "start", _start_then_swap)
    rows = await _start(tmp_path, cfg)
    assert alerts == [], "the start loaded the baseline's own bytes"
    assert rows[-1]["changed"] is False
    assert rows[-1]["previous_fingerprint"] == config_fingerprint(cfg)
    # Control: the swap did happen, and the row names what is running at the write.
    assert rows[-1]["fingerprint"] == other["fingerprint"]


# --- the flag toggle -----------------------------------------------------------------------------


def _toml_config(tmp_path: Path) -> Path:
    d = tmp_path / "toml_cfg"
    for sub in ("in", "out"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    d.mkdir()
    (d / "logic.py").write_text(
        textwrap.dedent(
            """
            from messagefoundry import Send, handler, router

            @router("r")
            def route(msg):
                return ["h"]

            @handler("h")
            def handle(msg):
                return Send("OB_TOML", msg)
            """
        ),
        encoding="utf-8",
    )
    (d / "connections.toml").write_text(
        textwrap.dedent(
            f"""
            [[inbound]]
            name = "IB_TOML"
            transport = "file"
            router = "r"
            [inbound.settings]
            directory = '{(tmp_path / "in").as_posix()}'
            pattern = "*.hl7"

            [[outbound]]
            name = "OB_TOML"
            transport = "file"
            [outbound.settings]
            directory = '{(tmp_path / "out").as_posix()}'
            """
        ),
        encoding="utf-8",
    )
    return d


async def test_a_flag_toggle_then_a_restart_raises_no_alert(
    tmp_path: Path, alerts: list[dict[str, Any]]
) -> None:
    cfg = _toml_config(tmp_path)
    before = config_fingerprint(cfg)
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        engine: Engine = app.state.engine
        r = await c.post(
            "/connections/OB_TOML/flag", json={"direction": "outbound", "flagged": True}
        )
        assert r.status_code == 200, r.text
        flag_rows = await engine.store.list_audit(action="connection_flag_set")
    after = config_fingerprint(cfg)
    assert after != before, "control: the toggle rewrote connections.toml"
    flag = json.loads(flag_rows[0]["detail"])
    assert flag["fingerprint"] == after and flag["scheme"] == FINGERPRINT_SCHEME
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is False and rows[-1]["previous_fingerprint"] == after


async def test_two_flag_toggles_move_the_provenance_baseline(
    tmp_path: Path, alerts: list[dict[str, Any]]
) -> None:
    """The flag is reflected live, so the loaded digest moves with each toggle: the second toggle
    still counts as the one change since the load, and provenance reports no drift."""
    cfg = _toml_config(tmp_path)
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        for flagged in (True, False):
            r = await c.post(
                "/connections/OB_TOML/flag", json={"direction": "outbound", "flagged": flagged}
            )
            assert r.status_code == 200, r.text
        prov = (await c.get("/config/provenance")).json()
    assert prov["drift"] is False
    assert prov["fingerprint"] == config_fingerprint(cfg)
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is False


async def test_a_flag_toggle_does_not_vouch_for_an_unloaded_edit(
    tmp_path: Path, alerts: list[dict[str, Any]]
) -> None:
    """An edit made on disk and never loaded, then a toggle, then a restart: the toggle's row
    must not carry a digest that covers the edit, or the restart would raise nothing."""
    cfg = _toml_config(tmp_path)
    loaded = config_fingerprint(cfg)
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        with (cfg / "logic.py").open("a", encoding="utf-8") as fh:
            fh.write("# an edit nobody loaded\n")
        r = await c.post(
            "/connections/OB_TOML/flag", json={"direction": "outbound", "flagged": True}
        )
        assert r.status_code == 200, r.text
        engine: Engine = app.state.engine
        flag = json.loads(
            (await engine.store.list_audit(action="connection_flag_set"))[0]["detail"]
        )
    assert flag["fingerprint"] == loaded, "the row keeps the digest the running graph loaded"
    rows = await _start(tmp_path, cfg)
    assert len(alerts) == 1
    assert alerts[0]["previous_fingerprint"] == loaded
    assert alerts[0]["fingerprint"] == config_fingerprint(cfg)
    assert alerts[0]["baseline_action"] == "connection_flag_set"
    assert rows[-1]["changed"] is True


# --- the alert kind ------------------------------------------------------------------------------


def test_config_changed_is_a_routable_type_and_no_control_or_resolve_type() -> None:
    assert "config_changed" in _ALERT_EVENT_TYPES
    assert "config_changed" not in _ALERT_CONTROL_EVENT_TYPES
    assert "config_changed" not in _AUTO_RESOLVE.values()
    assert "config_changed" not in _AUTO_RESOLVE


async def test_the_notifier_pages_config_changed_with_labels_only() -> None:
    transport, store = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, store))
    sink.config_changed(
        "config:aaaaaaaaaaaa",
        fingerprint="a" * 64,
        previous_fingerprint="b" * 64,
        node="host:1:x",
        shard=None,
        baseline_action="config_reload",
        baseline_actor="alice",
        baseline_at="2026-10-04T00:00:00+00:00",
        baseline_node="host:2:y",
    )
    await _drain_transports(sink)
    await _drain_state(sink)
    (event,) = transport.events
    assert event["type"] == "config_changed" and event["connection"] == "config:aaaaaaaaaaaa"
    assert event["detail"] == (
        "this process started with config aaaaaaaaaaaa; the store last recorded config "
        "bbbbbbbbbbbb (node host:2:y, action config_reload, time 2026-10-04T00:00:00+00:00)"
    )
    assert (event["fingerprint"], event["previous_fingerprint"]) == ("a" * 64, "b" * 64)
    assert set(event) <= {
        "type",
        "connection",
        "detail",
        "fingerprint",
        "previous_fingerprint",
        "node",
        "shard",
        "baseline_action",
        "baseline_actor",
        "baseline_at",
        "baseline_node",
        "ts",
        "severity",
    }
