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
import copy
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


async def test_recent_audit_of_reads_the_newest_matching_rows(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        assert await store.recent_audit_of(_ACTIONS, limit=5) == [], "a fresh store: no baseline"
        await store.record_audit("config_loaded", actor="system", detail='{"fingerprint": "a"}')
        await store.record_audit("config_reload", actor="alice", detail='{"fingerprint": "b"}')
        await store.record_audit("export", actor="bob", detail="not a baseline")
        await store.record_audit("config_loaded", actor="system", detail='{"fingerprint": "c"}')
        rows = await store.recent_audit_of(_ACTIONS, limit=2)
        # Newest first, matching actions only (the "export" row is not one), cut at the limit.
        assert [(r["action"], r["detail"]) for r in rows] == [
            ("config_loaded", '{"fingerprint": "c"}'),
            ("config_reload", '{"fingerprint": "b"}'),
        ]
        assert rows[1]["actor"] == "alice"
        assert isinstance(rows[0]["ts"], float) and rows[0]["id"] > rows[1]["id"]
        assert len(await store.recent_audit_of(_ACTIONS, limit=10)) == 3
        assert await store.recent_audit_of([], limit=5) == []
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
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    """A reload whose digest failed writes a row with none. A start without a digest of its own is
    a different case: it is passed over (see the no-digest test below)."""
    await _start(tmp_path, cfg)
    store = await MessageStore.open(tmp_path / "start.db")
    try:
        await store.record_audit(
            "config_reload",
            actor="alice",
            detail='{"degraded": true, "failed_steps": ["config_fingerprint"]}',
        )
    finally:
        await store.close()
    _edit(cfg)
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is None and rows[-1]["previous_fingerprint"] is None
    # A usable row for the next start, not one it passes over: see the scheme test below.
    assert rows[-1]["comparison"] == "degraded_baseline"
    assert "baseline_unchecked" not in rows[-1]


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
    assert rows[-1]["comparison"] == "scheme_mismatch"
    # The mismatched start begins a new baseline. Had it been passed over, every later start
    # would meet the old-scheme row again and never compare anything.
    _edit(cfg)
    await _start(tmp_path, cfg)
    assert len(alerts) == 1, "the next change after the scheme move is reported"


def _failing_read(kind: str) -> Any:
    async def _raise(self: MessageStore, actions: Any, *, limit: int) -> Any:
        raise RuntimeError("store unavailable")

    async def _hang(self: MessageStore, actions: Any, *, limit: int) -> Any:
        await asyncio.sleep(30)

    async def _undecodable(self: MessageStore, actions: Any, *, limit: int) -> Any:
        return [{"id": 1, "ts": 0.0, "actor": "system", "action": "config_loaded", "detail": "{no"}]

    return {"raises": _raise, "times-out": _hang, "undecodable": _undecodable}[kind]


@pytest.mark.parametrize(
    ("kind", "outcome"),
    [("raises", "read_failed"), ("times-out", "read_failed"), ("undecodable", "no_baseline")],
)
async def test_a_failed_baseline_read_never_blocks_the_start(
    tmp_path: Path,
    cfg: Path,
    monkeypatch: pytest.MonkeyPatch,
    alerts: list[dict[str, Any]],
    kind: str,
    outcome: str,
) -> None:
    await _start(tmp_path, cfg)
    _edit(cfg)
    monkeypatch.setattr(app_module, "_CONFIG_BASELINE_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(MessageStore, "recent_audit_of", _failing_read(kind))
    loop = asyncio.get_running_loop()
    began = loop.time()
    rows = await _start(tmp_path, cfg)  # asserts the graph is serving
    assert loop.time() - began < 15, "the start was held past the bound"
    assert alerts == []
    assert rows[-1]["changed"] is None
    assert rows[-1]["comparison"] == outcome


@pytest.mark.parametrize("kind", ["raises", "times-out"])
async def test_a_restart_after_a_failed_read_still_alerts_against_the_older_baseline(
    tmp_path: Path,
    cfg: Path,
    monkeypatch: pytest.MonkeyPatch,
    alerts: list[dict[str, Any]],
    kind: str,
) -> None:
    """Review finding 2: a start whose baseline read failed records the new digest unchecked. If
    the next start took that row as its baseline, the change would never be reported. It passes
    over the row and compares against the last checked one."""
    before = config_fingerprint(cfg)
    await _start(tmp_path, cfg)
    _edit(cfg)
    with monkeypatch.context() as m:
        m.setattr(app_module, "_CONFIG_BASELINE_TIMEOUT_SECONDS", 0.2)
        m.setattr(MessageStore, "recent_audit_of", _failing_read(kind))
        failed = await _start(tmp_path, cfg)
    assert failed[-1]["comparison"] == "read_failed"
    assert failed[-1]["baseline_unchecked"] is True
    assert alerts == [], "control: the failed read raised nothing"
    rows = await _start(tmp_path, cfg)  # the SAME changed bytes, with a working read
    assert len(alerts) == 1
    assert alerts[0]["previous_fingerprint"] == before
    assert alerts[0]["fingerprint"] == config_fingerprint(cfg)
    assert rows[-1]["comparison"] == "compared" and rows[-1]["changed"] is True


async def test_a_start_that_took_no_digest_is_passed_over_too(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """Review round 3: a start with no digest of its own checked nothing either. Stopping at its
    digest-less row would read as a degraded baseline and adopt the change unreported."""
    before = config_fingerprint(cfg)
    await _start(tmp_path, cfg)
    _edit(cfg)

    def _unreadable(_path: Path) -> dict[str, object]:
        raise OSError("unreadable bundle")

    with monkeypatch.context() as m:
        m.setattr(fp_mod, "config_fingerprint_detail", _unreadable)
        failed = await _start(tmp_path, cfg)
    assert failed[-1]["comparison"] == "no_start_digest"
    assert failed[-1]["baseline_unchecked"] is True
    rows = await _start(tmp_path, cfg)
    assert len(alerts) == 1 and alerts[0]["previous_fingerprint"] == before
    assert rows[-1]["comparison"] == "compared"


async def test_a_flag_toggle_in_an_unchecked_process_vouches_for_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """Review round 3: the toggle would vouch for the digest the unchecked start loaded, and the
    next start would take the toggle's row as its baseline. The process marks it unchecked."""
    cfg = _toml_config(tmp_path)
    before = config_fingerprint(cfg)
    await _start(tmp_path, cfg)
    with (cfg / "logic.py").open("a", encoding="utf-8") as fh:
        fh.write("# an edit nobody reloaded\n")
    with monkeypatch.context() as m:
        m.setattr(MessageStore, "recent_audit_of", _failing_read("raises"))
        app = _app(tmp_path, cfg)
        async with app.router.lifespan_context(app), _client(app) as c:
            r = await c.post(
                "/connections/OB_TOML/flag", json={"direction": "outbound", "flagged": True}
            )
            assert r.status_code == 200, r.text
            engine: Engine = app.state.engine
            flag_rows = await engine.store.list_audit(action="connection_flag_set")
    assert json.loads(flag_rows[0]["detail"])["baseline_unchecked"] is True
    rows = await _start(tmp_path, cfg)
    assert len(alerts) == 1
    assert alerts[0]["previous_fingerprint"] == before
    assert rows[-1]["comparison"] == "compared"


@pytest.mark.parametrize("detail", ["{not json", "null", "[1]"], ids=["not-json", "null", "list"])
async def test_a_row_that_is_not_a_json_object_is_passed_over_for_an_older_one(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]], detail: str
) -> None:
    before = config_fingerprint(cfg)
    await _start(tmp_path, cfg)
    store = await MessageStore.open(tmp_path / "start.db")
    try:
        await store.record_audit("config_reload", actor="mallory", detail=detail)
    finally:
        await store.close()
    _edit(cfg)
    rows = await _start(tmp_path, cfg)
    assert len(alerts) == 1
    assert alerts[0]["previous_fingerprint"] == before
    assert alerts[0]["baseline_action"] == "config_loaded"
    assert rows[-1]["comparison"] == "compared"


async def test_a_full_window_of_unusable_rows_begins_a_new_baseline(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    await _start(tmp_path, cfg)
    store = await MessageStore.open(tmp_path / "start.db")
    try:
        for _ in range(2):
            await store.record_audit(
                "config_loaded", actor="system", detail='{"baseline_unchecked": true}'
            )
    finally:
        await store.close()
    _edit(cfg)
    monkeypatch.setattr(app_module, "_CONFIG_BASELINE_WINDOW", 2)
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["comparison"] == "no_baseline"
    assert "baseline_unchecked" not in rows[-1], "a new baseline is a usable row"
    # Control: with room to look past the two rows, the same store reaches the checked one.
    monkeypatch.setattr(app_module, "_CONFIG_BASELINE_WINDOW", 50)
    store = await MessageStore.open(tmp_path / "start.db")
    try:
        for _ in range(2):
            await store.record_audit(
                "config_loaded", actor="system", detail='{"baseline_unchecked": true}'
            )
    finally:
        await store.close()
    _edit(cfg)
    await _start(tmp_path, cfg)
    assert len(alerts) == 1


async def test_a_start_row_records_its_comparison_outcome(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    first = await _start(tmp_path, cfg)
    assert first[-1]["comparison"] == "no_baseline"
    rows = await _start(tmp_path, cfg)
    assert rows[-1]["comparison"] == "compared" and rows[-1]["changed"] is False


@pytest.mark.parametrize("rebound", [True, False], ids=["reload_done", "reload_in_flight"])
async def test_a_reload_after_capture_does_not_change_the_comparison(
    tmp_path: Path,
    cfg: Path,
    monkeypatch: pytest.MonkeyPatch,
    alerts: list[dict[str, Any]],
    rebound: bool,
) -> None:
    """A reload can land between the start's capture and its row (a cluster convergence reload
    runs once the engine starts). The comparison is of what this start loaded, not of that.

    A reload swaps the graph first and rebinds the fingerprint later, so ``reload_in_flight``
    swaps only the graph. The row must see that too (vault BACKLOG #2838)."""
    await _start(tmp_path, cfg)
    real_start = Engine.start
    other = {"fingerprint": "f" * 64, "scheme": FINGERPRINT_SCHEME, "files": 1}
    swapped: list[dict[str, object] | None] = []

    async def _start_then_swap(self: Engine) -> None:
        await real_start(self)
        rr = self.registry_runner
        assert rr is not None
        rr.registry = copy.copy(rr.registry)  # what a reload's swap does first
        if rebound:
            self.loaded_config_fingerprint = dict(other)  # and then, once the reload is done
        swapped.append(self.loaded_config_fingerprint)

    monkeypatch.setattr(Engine, "start", _start_then_swap)
    rows = await _start(tmp_path, cfg)
    expected = other if rebound else {"fingerprint": config_fingerprint(cfg)}
    assert [(s or {}).get("fingerprint") for s in swapped] == [expected["fingerprint"]], (
        "control: the swap ran before the row was written"
    )
    assert alerts == [], "the start loaded the baseline's own bytes"
    assert rows[-1]["changed"] is False
    assert rows[-1]["previous_fingerprint"] == config_fingerprint(cfg)
    # The row names the same snapshot the comparison used, not what is running at the write
    # (vault BACKLOG #2838), and says a reload superseded it.
    assert rows[-1]["fingerprint"] == config_fingerprint(cfg)
    assert rows[-1]["superseded"] is True and rows[-1]["baseline_unchecked"] is True


async def test_a_snapshot_that_cannot_be_taken_never_blocks_the_start(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """vault BACKLOG #2838, under #2597 step 5: the start's config snapshot is audit only, so a
    fault taking it never refuses a start. The start checks nothing, as a start with no digest
    does, and serves. Its row names no graph, even after a reload swapped one in, and a later
    start passes over it and reports the change against the older baseline."""
    before = config_fingerprint(cfg)
    await _start(tmp_path, cfg)  # the baseline
    _edit(cfg)
    calls: list[int] = []

    def _read(cls: type[Any], engine: Engine) -> Any:
        calls.append(1)
        raise RuntimeError("synthetic snapshot fault")

    real_start = Engine.start
    other = {"fingerprint": "f" * 64, "scheme": FINGERPRINT_SCHEME, "files": 1}

    async def _start_then_swap(self: Engine) -> None:
        await real_start(self)
        self.loaded_config_fingerprint = dict(other)  # a reload, before the row is written

    with monkeypatch.context() as patch:
        patch.setattr(app_module._LoadedConfig, "read", classmethod(_read))
        patch.setattr(Engine, "start", _start_then_swap)
        rows = await _start(tmp_path, cfg)  # asserts the graph is serving
    assert len(calls) == 1, "control: the lifespan's read ran, and the row did not read again"
    assert alerts == [], "a start that checked nothing raises nothing"
    assert len(rows) == 2
    row = rows[-1]
    assert row["comparison"] == "no_start_digest" and row["baseline_unchecked"] is True
    assert row["degraded"] is True and row["failed_steps"] == ["start_snapshot"]
    assert "fingerprint" not in row, "the reloaded digest is not named as the start's"
    assert (row["dir"], row["inbound"], row["outbound"], row["loosenings"]) == (None,) * 4

    rows = await _start(tmp_path, cfg)
    assert len(alerts) == 1, "the next start passes over the degraded row"
    assert rows[-1]["previous_fingerprint"] == before


async def test_a_swap_check_that_faults_never_blocks_the_start(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """vault BACKLOG #2838: the row's swap check is audit only too. A fault in it leaves the row
    naming the start's snapshot, degraded and no baseline, and claims no reload ran."""

    def _swapped(self: Any, engine: Engine) -> bool:
        raise RuntimeError("synthetic swap-check fault")

    monkeypatch.setattr(app_module._LoadedConfig, "swapped", _swapped)
    rows = await _start(tmp_path, cfg)  # asserts the graph is serving
    row = rows[-1]
    assert row["fingerprint"] == config_fingerprint(cfg)
    assert row["degraded"] is True and row["failed_steps"] == ["start_swap_check"]
    assert row["baseline_unchecked"] is True and row["loosenings"] is None
    assert "superseded" not in row, "a check that faulted saw no reload"


def _add_a_connection_pair(cfg: Path, tmp_path: Path) -> None:
    """A second inbound and outbound, so a reload of ``cfg`` changes both counts and the digest."""
    inbox, outdir = tmp_path / "in2", tmp_path / "out2"
    for d in (inbox, outdir):
        d.mkdir(parents=True, exist_ok=True)
    with (cfg / "cfg.py").open("a", encoding="utf-8") as fh:
        fh.write(
            f"inbound('IB_T_ADT2', File(directory={str(inbox)!r}, pattern='*.hl7', "
            "poll_seconds=1.0), router='r')\n"
            f"outbound('FILE-OUT_T_ADT2', File(directory={str(outdir)!r}))\n"
        )


async def test_a_convergence_reload_after_capture_leaves_the_start_row_naming_the_start(
    tmp_path: Path, cfg: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """vault BACKLOG #2838: a sibling node reloads a changed directory, and this node's convergence
    reload lands between its start's capture and its config_loaded row. The row names the graph
    this start loaded: its digest and counts, and the comparison it made against them. It marks
    itself superseded, so the next start on the reloaded bytes compares against the convergence
    reload's own row and raises no false config_changed. No sibling row is needed for that: the
    initiator's row may be missing, and this node's row still names the bytes it converged on
    (vault BACKLOG #3076)."""
    start_digest = config_fingerprint(cfg)
    await _start(tmp_path, cfg)  # the baseline, so this start makes a real comparison
    seen: dict[str, Any] = {}
    real_start = Engine.start

    async def _start_then_converge(self: Engine) -> None:
        await real_start(self)
        _add_a_connection_pair(cfg, tmp_path)  # the sibling's change, on the shared directory
        await self._converge_reload()  # what ConfigConvergenceRunner calls on a version bump
        # This node's own row for the reload, written by the lifespan's hook (vault BACKLOG #3076).
        reload_rows = await self.store.list_audit(action="config_reload")
        seen["actors"] = [r["actor"] for r in reload_rows]
        rr = self.registry_runner
        assert rr is not None
        seen["fingerprint"] = (self.loaded_config_fingerprint or {}).get("fingerprint")
        seen["counts"] = (len(rr.registry.inbound), len(rr.registry.outbound))

    monkeypatch.setattr(Engine, "start", _start_then_converge)
    rows = await _start(tmp_path, cfg)
    # Control: the reload did swap the graph before the row was written.
    reloaded_digest = config_fingerprint(cfg)
    assert reloaded_digest != start_digest
    assert seen == {
        "fingerprint": reloaded_digest,
        "counts": (2, 2),
        "actors": ["system:cluster-convergence"],
    }
    row = rows[-1]
    assert row["fingerprint"] == start_digest
    assert (row["inbound"], row["outbound"]) == (1, 1)
    assert row["comparison"] == "compared" and row["changed"] is False
    assert row["previous_fingerprint"] == start_digest
    assert row["superseded"] is True and row["baseline_unchecked"] is True
    assert row["loosenings"] is None, "the reader sees only the reloaded graph"
    assert alerts == []

    monkeypatch.setattr(Engine, "start", real_start)
    rows = await _start(tmp_path, cfg)
    assert alerts == [], "the superseded row is passed over for the convergence row"
    assert rows[-1]["comparison"] == "compared"
    assert rows[-1]["previous_fingerprint"] == reloaded_digest
    assert "superseded" not in rows[-1], "control: an undisturbed start is not marked"


async def test_the_reload_route_row_still_names_the_reloaded_graph(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]]
) -> None:
    """Control for vault BACKLOG #2838: the reload route passes no snapshot, so its config_reload
    row names what the reload put live, read at the write."""
    start_digest = config_fingerprint(cfg)
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        _add_a_connection_pair(cfg, tmp_path)
        r = await c.post("/config/reload", json={"config_dir": str(cfg)})
        assert r.status_code == 200, r.text
        engine: Engine = app.state.engine
        rows = await engine.store.list_audit(action="config_reload")
        start = (await _start_rows(engine))[-1]
        live = engine.running_config_dir
        node = engine.coordinator.node_id
    assert len(rows) == 1
    row = json.loads(rows[0]["detail"])
    assert list(row)[:6] == ["dir", "shard", "node", "inbound", "outbound", "dry_run"]
    assert (row["dir"], row["shard"], row["node"], row["dry_run"]) == (str(live), None, node, False)
    assert row["fingerprint"] == config_fingerprint(cfg) != start_digest
    assert (row["inbound"], row["outbound"]) == (2, 2)
    assert "superseded" not in row and "baseline_unchecked" not in row
    # Control: the start's own row, written before the reload, names the start's graph.
    assert start["fingerprint"] == start_digest
    assert (start["inbound"], start["outbound"]) == (1, 1)


@pytest.mark.parametrize("reverted", [True, False], ids=["reverted", "kept"])
async def test_a_convergence_reload_writes_the_row_the_next_start_compares_against(
    tmp_path: Path, cfg: Path, alerts: list[dict[str, Any]], reverted: bool
) -> None:
    """vault BACKLOG #3076 item 1: a convergence reload that lands after the start's row writes its
    own config_reload row, so the store's newest baseline names the graph the node converged on.

    Without that row the newest baseline was the start's, naming the old digest. ``kept`` restarts
    on the converged bytes and must raise nothing; it alerted falsely before. ``reverted`` puts the
    old bytes back, and the next start must see that; it compared equal to the stale start row
    before, so the revert went unreported."""
    original = (cfg / "cfg.py").read_bytes()
    start_digest = config_fingerprint(cfg)
    await _start(tmp_path, cfg)  # the baseline
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app):
        engine: Engine = app.state.engine
        _add_a_connection_pair(cfg, tmp_path)  # a sibling's change, on the shared directory
        await engine._converge_reload()  # what ConfigConvergenceRunner calls on a version bump
        reload_rows = await engine.store.list_audit(action="config_reload")
        node = engine.coordinator.node_id
    converged_digest = config_fingerprint(cfg)
    assert converged_digest != start_digest, "control: the change moved the digest"
    assert alerts == []
    assert len(reload_rows) == 1
    assert reload_rows[0]["actor"] == "system:cluster-convergence"
    row = json.loads(reload_rows[0]["detail"])
    assert list(row)[:6] == ["dir", "shard", "node", "inbound", "outbound", "dry_run"]
    assert row["initiator"] == "cluster_convergence" and row["node"] == node
    assert row["fingerprint"] == converged_digest and (row["inbound"], row["outbound"]) == (2, 2)
    assert "baseline_unchecked" not in row and "degraded" not in row

    if reverted:
        (cfg / "cfg.py").write_bytes(original)
        assert config_fingerprint(cfg) == start_digest, "control: the revert restored the bytes"
    rows = await _start(tmp_path, cfg)
    assert rows[-1]["comparison"] == "compared"
    assert rows[-1]["previous_fingerprint"] == converged_digest
    if reverted:
        assert len(alerts) == 1, "the revert to the old graph is reported"
        alert = alerts[0]
        assert (alert["fingerprint"], alert["previous_fingerprint"]) == (
            start_digest,
            converged_digest,
        )
        assert alert["baseline_action"] == "config_reload"
        assert alert["baseline_actor"] == "system:cluster-convergence"
    else:
        assert alerts == [], "a start on the converged bytes matches the convergence row"


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


async def test_a_failed_digest_after_the_toggle_vouches_for_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alerts: list[dict[str, Any]]
) -> None:
    """The toggle was the one change, but its after-digest could not be taken. The row carries no
    digest rather than the loaded one, which the next start would read as a change."""
    cfg = _toml_config(tmp_path)
    app = _app(tmp_path, cfg)
    async with app.router.lifespan_context(app), _client(app) as c:
        real = Engine.fingerprint_bundle
        calls = 0

        async def _second_fails(self: Engine, path: Path) -> Any:
            nonlocal calls
            calls += 1
            return (None, "unreadable") if calls == 2 else await real(self, path)

        monkeypatch.setattr(Engine, "fingerprint_bundle", _second_fails)
        r = await c.post(
            "/connections/OB_TOML/flag", json={"direction": "outbound", "flagged": True}
        )
        assert r.status_code == 200, r.text
        monkeypatch.setattr(Engine, "fingerprint_bundle", real)
        engine: Engine = app.state.engine
        flag = json.loads(
            (await engine.store.list_audit(action="connection_flag_set"))[0]["detail"]
        )
    assert calls == 2, "control: the before and after digests were both asked for"
    assert "fingerprint" not in flag
    rows = await _start(tmp_path, cfg)
    assert alerts == []
    assert rows[-1]["changed"] is None


# --- the alert timing ----------------------------------------------------------------------------


@pytest.mark.parametrize("where", ["engine-start", "a-later-step"])
async def test_the_alert_fires_even_when_the_start_then_fails(
    tmp_path: Path,
    cfg: Path,
    monkeypatch: pytest.MonkeyPatch,
    alerts: list[dict[str, Any]],
    where: str,
) -> None:
    """New bytes that make the start fail must still page, on every attempt of a crash loop."""
    await _start(tmp_path, cfg)
    _edit(cfg)

    if where == "engine-start":

        async def _refuse(self: Engine) -> None:
            raise RuntimeError("a listener could not bind")

        monkeypatch.setattr(Engine, "start", _refuse)
    else:

        def _refuse_gate(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("a later startup step failed")

        monkeypatch.setattr(app_module, "_build_approval_gate", _refuse_gate)
    for attempt in (1, 2):
        app = _app(tmp_path, cfg)
        with pytest.raises(RuntimeError):
            async with app.router.lifespan_context(app):
                pass
        assert len(alerts) == attempt, "each failed attempt pages"
    assert alerts[0]["fingerprint"] == config_fingerprint(cfg)


async def test_bounded_turns_a_foreign_cancellation_into_a_failed_read() -> None:
    """A read cancelled by something other than the caller must not surface as CancelledError,
    which the start's teardown would treat as the start itself being cancelled."""

    async def _cancelled_inside() -> None:
        raise asyncio.CancelledError

    with pytest.raises(RuntimeError, match="cancelled"):
        await app_module._bounded(_cancelled_inside(), 1.0)


async def test_bounded_abandons_a_read_past_its_bound() -> None:
    loop = asyncio.get_running_loop()
    began = loop.time()
    with pytest.raises(TimeoutError):
        await app_module._bounded(asyncio.sleep(30), 0.05)
    assert loop.time() - began < 5


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
        "this process started with config aaaaaaaaaaaa; the store's baseline is config "
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
