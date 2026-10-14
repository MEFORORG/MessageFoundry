# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0041 D2 — dual-control config:deploy / POST /config/reload (BACKLOG #53).

WHERE ``config_reload`` is in ``[approvals].operations`` and ``[approvals].enabled``, a non-dry-run
reload is held (202) for a *distinct* second approver — the requester can never self-approve, and both
identities land in the hash-chained audit. Deny-by-default: when ``config_reload`` is NOT gated (the
shipping posture), a reload executes inline exactly as before.

Covers AC-5 (held 202, graph not swapped), AC-6 (self-approval refused 403), AC-7 (released by a
distinct approver; both identities + the fingerprint-bearing config_reload row audited), AC-8 (inline
when not gated).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from fastapi import HTTPException

from messagefoundry.api import create_app
from messagefoundry.api.app import (
    _REFUSAL_LOG_LIMIT,
    _audit_refused_reload,
    _audit_reload_attempt,
    _compare_start_config,
    _record_reload_audit,
)
from messagefoundry.auth import Role
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    EgressSettings,
    LoggingSettings,
    TlsSettings,
)
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore
from tests._admin_account import create_local_user_chosen
from tests.test_config_fingerprint import INVALID_DIR_NAMES, _unreadable
from tests.test_trust_anchors import _block

PW = "a-strong-test-passphrase"
# min_dwell_seconds=0: this suite releases a reload within milliseconds of holding it, which the
# shipped ASVS 2.4.2 floor would refuse. tests/test_approval_min_dwell.py covers the floor.
GATED = ApprovalsSettings(enabled=True, operations=["config_reload"], min_dwell_seconds=0.0)
NOT_GATED = ApprovalsSettings(enabled=True, operations=["dead_letter_replay"])  # reload NOT held


def _write_valid_config(cfg: Path, inbox: Path, outdir: Path) -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound('IB_T_ADT', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n",
        encoding="utf-8",
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    # The engine's startup --config dir is the default (and only allowed) reload root, so the held
    # request can omit config_dir and the approver replays the same on-disk bundle.
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    eng = await Engine.create(
        tmp_path / "dc.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # Dual-control reload is a step-up admin flow, not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the reload before the approval path.
    # Dual control is this file's subject, so a reload keeps the session window here.
    # Vault BACKLOG #2625's action-bound proof is pinned in tests/test_bound_step_up_injection.py.
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, require_mfa=False, require_action_step_up=False
        ),
    )
    await service.initialize()
    return service


def _client(
    engine: Engine,
    service: AuthService,
    approvals: ApprovalsSettings,
    *,
    raise_app_exceptions: bool = True,
) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, approvals=approvals)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _fail_config_reload_audit(
    monkeypatch: pytest.MonkeyPatch, engine: Engine, failing: str = "config_reload"
) -> None:
    """Make only the ``failing`` audit write fail, so every other row (the login, the request)
    still lands."""
    real = engine.store.record_audit

    async def _record(action: str, **kwargs: Any) -> None:
        if action == failing:
            raise sqlite3.OperationalError("disk I/O error")
        await real(action, **kwargs)

    monkeypatch.setattr(engine.store, "record_audit", _record)


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    uid = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(uid)  # clear forced first-login rotation
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )


async def _token(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


# --- AC-5: a gated reload is held (202) and the live graph is not swapped ------


async def test_config_reload_is_held_for_approval(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)  # holds config:deploy
    async with _client(engine, service, GATED) as c:
        r = await c.post("/config/reload", json={}, headers=await _token(c, "deployer"))
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "pending_approval" and body["operation"] == "config_reload"
        # the reload was NOT applied inline — no config_reload row yet (only the request)
        actions = [a["action"] for a in await engine.store.list_audit(limit=50)]
        assert "config_reload" not in actions
        assert "approval.requested" in actions


# --- AC-6: the requester cannot approve their own reload (403) -----------------


async def test_config_reload_requires_distinct_second_approver(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)
    await _add(service, "admin2", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        a1 = await _token(c, "admin1")
        approval_id = (await c.post("/config/reload", json={}, headers=a1)).json()["approval_id"]
        # the requester is not a valid second approver
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=a1)).status_code == 403
        # ...and the reload has still not executed
        assert "config_reload" not in [a["action"] for a in await engine.store.list_audit(limit=50)]
        # a distinct approver releases it; the captured reload now runs
        a2 = await _token(c, "admin2")
        ok = await c.post(f"/approvals/{approval_id}/approve", headers=a2)
        assert ok.status_code == 200, ok.text
        out = ok.json()
        assert out["requested_by"] == "admin1" and out["approved_by"] == "admin2"
        assert out["result"]["inbound"] == 1  # the held reload executed on release


# --- AC-7: release re-executes + audits both identities + the fingerprint -------


async def test_config_reload_audits_both_identities(engine: Engine) -> None:
    import json

    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        approval_id = (
            await c.post("/config/reload", json={}, headers=await _token(c, "op"))
        ).json()["approval_id"]
        admin = await _token(c, "approver")
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=admin)).status_code == 200
    rows = await engine.store.list_audit(limit=50)
    audited = {(str(r["action"]), str(r["actor"])) for r in rows}
    assert ("approval.requested", "op") in audited  # the maker
    assert ("approval.approved", "approver") in audited  # the distinct checker
    # the released reload recorded the ADR 0041 D1 fingerprint-bearing config_reload row
    reload_rows = [r for r in rows if r["action"] == "config_reload"]
    assert reload_rows, "expected a config_reload audit row from the released reload"
    detail = json.loads(reload_rows[-1]["detail"])
    assert "fingerprint" in detail and detail["dry_run"] is False


# --- BACKLOG #1940: a failed trailing audit row does not relabel a swap as failed ----


async def test_released_reload_whose_audit_row_fails_is_not_compensated_to_failed(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The graph swaps, then the executor's config_reload row fails. Pre-fix the raise reached the
    gate's compensation, so the request read 'failed' for a reload that ran."""
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        approval_id = (
            await c.post("/config/reload", json={}, headers=await _token(c, "op"))
        ).json()["approval_id"]
        admin = await _token(c, "approver")
        _fail_config_reload_audit(monkeypatch, engine)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
            ok = await c.post(f"/approvals/{approval_id}/approve", headers=admin)
        assert ok.status_code == 200, ok.text
        assert ok.json()["result"]["inbound"] == 1  # the reload really swapped the graph

        # PR 1607 review finding 7: the release reports the lost row the way the inline route does,
        # so approval.approved records that this reload has no config_reload row.
        assert ok.json()["result"]["degraded"] is True
        assert ok.json()["result"]["failures"] == ["audit"]

    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "approved"
    assert await engine.store.list_audit(action="approval.failed") == []
    approved = await engine.store.list_audit(action="approval.approved")
    assert len(approved) == 1
    assert json.loads(approved[0]["detail"])["result"]["failures"] == ["audit"]
    assert any(
        r.levelno == logging.ERROR and "reload swapped the graph" in r.getMessage()
        for r in caplog.records
    )


async def test_the_reload_audit_takes_no_fingerprint_after_the_swap(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-2 finding on this branch was a post-swap fingerprint whose fault escaped after the graph
    swapped. Since vault BACKLOG #2597 the row reads the digest the engine took BEFORE the swap, so
    the writer hashes nothing after it, and the row names the digest GET /config/provenance
    compares against."""
    import messagefoundry.config.fingerprint as fp_mod

    calls: list[object] = []
    real = fp_mod.config_fingerprint_detail

    def _counting(path: Path) -> dict[str, object]:
        calls.append(path)
        return real(path)

    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    async with _client(engine, service, NOT_GATED, raise_app_exceptions=False) as c:
        headers = await _token(c, "deployer")
        monkeypatch.setattr(fp_mod, "config_fingerprint_detail", _counting)
        r = await c.post("/config/reload", json={}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["inbound"] == 1 and r.json()["failures"] == []
    assert len(calls) == 1, "one digest per applied reload, taken before the swap"
    rows = await engine.store.list_audit(action="config_reload")
    assert len(rows) == 1
    loaded = engine.loaded_config_fingerprint
    assert loaded is not None
    assert json.loads(rows[0]["detail"])["fingerprint"] == loaded["fingerprint"]


async def test_inline_reload_whose_audit_row_fails_reports_the_swap_it_made(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """PR 1607 review finding 7. The ungated route shares _record_reload_audit and had the old shape:
    the graph swapped, the config_reload row failed, and the operator got a 500 for a reload that
    ran. It now answers 200, names the lost row as a degraded step, and logs it at ERROR."""
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    # raise_app_exceptions=False, so the pre-fix 500 arrives as a response rather than a raise.
    async with _client(engine, service, NOT_GATED, raise_app_exceptions=False) as c:
        headers = await _token(c, "deployer")
        _fail_config_reload_audit(monkeypatch, engine)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
            r = await c.post("/config/reload", json={}, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inbound"] == 1 and body["degraded"] is True and body["failures"] == ["audit"]
    live = engine.registry_runner  # the new graph is live: the swap happened
    assert live is not None and len(live.registry.inbound) == 1
    assert any(
        r.levelno == logging.ERROR and "reload swapped the graph" in r.getMessage()
        for r in caplog.records
    )


# --- AC-8: ungated reload executes inline (deny-by-default) --------------------


async def test_config_reload_inline_when_not_gated(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    async with _client(engine, service, NOT_GATED) as c:
        r = await c.post("/config/reload", json={}, headers=await _token(c, "deployer"))
        assert r.status_code == 200, r.text  # executed inline, not held
        assert r.json()["inbound"] == 1
    assert "config_reload" in [a["action"] for a in await engine.store.list_audit(limit=50)]


# --- vault BACKLOG #2254: an ungated reload proves the audit log works before it swaps ----


async def test_an_inline_reload_the_audit_log_refuses_does_not_deploy(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Pre-fix nothing was written before the swap, so an audit log that refused writes still let
    the new config go live, and the only trace was the degraded `audit` step on the answer."""
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    before = engine.registry_runner
    reloads: list[object] = []
    real_reload = engine.reload_detail

    async def _counting(*args: Any, **kwargs: Any) -> Any:
        reloads.append(args)
        return await real_reload(*args, **kwargs)

    async with _client(engine, service, NOT_GATED, raise_app_exceptions=False) as c:
        headers = await _token(c, "deployer")
        monkeypatch.setattr(engine, "reload_detail", _counting)
        _fail_config_reload_audit(monkeypatch, engine, "config_reload_attempted")
        with caplog.at_level(logging.WARNING):
            r = await c.post("/config/reload", json={}, headers=headers)
    assert r.status_code == 503, r.text
    assert "did not run" in r.json()["detail"]
    assert reloads == [], "the engine was never asked to load or swap"
    assert engine.registry_runner is before
    assert engine.last_reload_dir is None
    assert await engine.store.list_audit(action="config_reload") == []
    messages = [rec.getMessage() for rec in caplog.records]
    assert any("refused the config_reload_attempted row" in m for m in messages)
    assert any(
        "audit_write_failed" in m and "config_reload_attempted" in m and "config_reload:inline" in m
        for m in messages
    ), "the default LoggingAlertSink raised the alert"


async def test_an_inline_reload_writes_its_attempt_row_before_the_swap(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    seen: list[tuple[str, object]] = []
    real_record = engine.store.record_audit

    async def _spy(action: str, **kwargs: Any) -> None:
        # What the engine is running at the moment each row is written: last_reload_dir moves only
        # once an applied reload has swapped the graph.
        seen.append((action, engine.last_reload_dir))
        await real_record(action, **kwargs)

    async with _client(engine, service, NOT_GATED) as c:
        headers = await _token(c, "deployer")
        monkeypatch.setattr(engine.store, "record_audit", _spy)
        r = await c.post("/config/reload", json={}, headers=headers)
    assert r.status_code == 200, r.text
    assert dict(seen)["config_reload_attempted"] is None, "written before the swap"
    assert dict(seen)["config_reload"] is not None
    (row,) = await engine.store.list_audit(action="config_reload_attempted")
    assert row["actor"] == "deployer"
    assert json.loads(row["detail"]) == {"requested": None, "dry_run": False}


async def test_a_dry_run_and_a_released_reload_write_no_attempt_row(engine: Engine) -> None:
    """A dry run swaps nothing. A released reload already has the gate's approval.release_attempted
    row before it, so a second pre-swap row would only repeat it."""
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        op = await _token(c, "op")
        dry = await c.post("/config/reload", json={"dry_run": True}, headers=op)
        assert dry.status_code == 200, dry.text
        approval_id = (await c.post("/config/reload", json={}, headers=op)).json()["approval_id"]
        ok = await c.post(f"/approvals/{approval_id}/approve", headers=await _token(c, "approver"))
        assert ok.status_code == 200, ok.text
    assert await engine.store.list_audit(action="config_reload_attempted") == []
    assert len(await engine.store.list_audit(action="approval.release_attempted")) == 1


# --- vault BACKLOG #2257: each reload's row names its own config ---------------


async def test_two_overlapping_reloads_each_record_their_own_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reload's row is written after its swap, outside the runner's swap lock. Pre-fix the row
    read the engine's live state then, so a second reload that swapped in between put its own
    directory, counts and digest on the first reload's row. Here reload A is held in its post-swap
    reference sync while reload B runs to completion."""
    cfg_a, cfg_b = tmp_path / "cfg_a", tmp_path / "cfg_b"
    _write_valid_config(cfg_a, tmp_path / "in_a", tmp_path / "out_a")
    _write_valid_config(cfg_b, tmp_path / "in_b", tmp_path / "out_b")
    # B differs from A by a second inbound, so its counts and digest both differ.
    (cfg_b / "cfg2.py").write_text(
        "from messagefoundry import inbound, File\n"
        f"inbound('IB_T_ORU', File(directory={str(tmp_path / 'in_b2')!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n",
        encoding="utf-8",
    )
    (tmp_path / "in_b2").mkdir()
    engine = await Engine.create(
        tmp_path / "overlap.db",
        poll_interval=0.02,
        config_dir=cfg_a,
        config_reload_roots=[cfg_b],
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await _service(engine)
        await _add(service, "alice", Role.ADMINISTRATOR)
        await _add(service, "bob", Role.ADMINISTRATOR)
        a_held, release_a = asyncio.Event(), asyncio.Event()
        real_sync = engine._reconcile_reference_sync

        async def _hold_a(*, startup: bool) -> None:
            if not a_held.is_set():  # A, after its swap and before its row
                a_held.set()
                await release_a.wait()
            await real_sync(startup=startup)

        async with _client(engine, service, NOT_GATED) as c:
            alice, bob = await _token(c, "alice"), await _token(c, "bob")
            monkeypatch.setattr(engine, "_reconcile_reference_sync", _hold_a)
            reload_a = asyncio.ensure_future(c.post("/config/reload", json={}, headers=alice))
            try:
                await asyncio.wait_for(a_held.wait(), timeout=30)
                # B swaps and writes its row while A sits between its own swap and its row.
                r_b = await c.post("/config/reload", json={"config_dir": str(cfg_b)}, headers=bob)
            finally:
                release_a.set()  # never leave A parked, whatever failed above
            r_a = await asyncio.wait_for(reload_a, timeout=30)
        assert r_a.status_code == 200 and r_b.status_code == 200, (r_a.text, r_b.text)
        assert (r_a.json()["inbound"], r_b.json()["inbound"]) == (1, 2)
        assert engine.last_reload_dir == cfg_b.resolve(), "B's graph is the one running"

        newest_first = await engine.store.list_audit(action="config_reload")
        assert [r["actor"] for r in newest_first] == ["alice", "bob"]
        rows = {r["actor"]: json.loads(r["detail"]) for r in newest_first}
        digest_a, _ = await engine.fingerprint_bundle(cfg_a.resolve())
        digest_b, _ = await engine.fingerprint_bundle(cfg_b.resolve())
        assert digest_a is not None and digest_b is not None
        assert digest_a["fingerprint"] != digest_b["fingerprint"]
        for actor, cfg, inbound, digest in (
            ("alice", cfg_a, 1, digest_a),
            ("bob", cfg_b, 2, digest_b),
        ):
            row = rows[actor]
            assert row["dir"] == str(cfg.resolve()), actor
            assert row["inbound"] == inbound, actor
            assert row["fingerprint"] == digest["fingerprint"], actor
        # A's row is the newest but names a graph the engine no longer runs, so it is no baseline:
        # the next start passes over it to B's.
        assert rows["alice"]["superseded"] is True and rows["alice"]["baseline_unchecked"] is True
        assert "superseded" not in rows["bob"] and "baseline_unchecked" not in rows["bob"]
    finally:
        await engine.stop()


async def test_a_reload_that_swaps_then_rolls_back_marks_no_earlier_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lander hold on PR 2135. Reload A sits between its swap and its row while reload B swaps and
    then fails and rolls back to A's graph. A's row is written while B's graph is briefly live. A
    graph-identity test then marked A's row superseded, so the next start compared against an
    older row and raised a false config_changed. Only a committed reload or a flag toggle moves the
    loaded fingerprint, so A's row must stay a baseline."""
    cfg_a, cfg_b = tmp_path / "cfg_a", tmp_path / "cfg_b"
    _write_valid_config(cfg_a, tmp_path / "in_a", tmp_path / "out_a")
    _write_valid_config(cfg_b, tmp_path / "in_b", tmp_path / "out_b")
    (cfg_b / "extra.py").write_text("# B differs from A\n", encoding="utf-8")
    engine = await Engine.create(
        tmp_path / "rollback.db",
        poll_interval=0.02,
        config_dir=cfg_a,
        config_reload_roots=[cfg_b],
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        digest_a, _ = await engine.fingerprint_bundle(cfg_a.resolve())
        assert digest_a is not None
        # An older baseline under another digest: the row a false alert would compare against.
        await engine.store.record_audit(
            "config_loaded",
            actor="system",
            detail=json.dumps({**digest_a, "fingerprint": "0" * 64, "dry_run": False}),
        )
        service = await _service(engine)
        await _add(service, "alice", Role.ADMINISTRATOR)
        await _add(service, "bob", Role.ADMINISTRATOR)
        a_held, release_a = asyncio.Event(), asyncio.Event()
        b_mid_swap, a_written = asyncio.Event(), asyncio.Event()
        a_written_mid_swap = asyncio.Event()
        real_sync = engine._reconcile_reference_sync
        real_record = engine.store.record_audit

        async def _hold_a(*, startup: bool) -> None:
            if not a_held.is_set():  # A, after its swap and before its row
                a_held.set()
                await release_a.wait()
            await real_sync(startup=startup)

        async def _spy(action: str, **kwargs: Any) -> None:
            await real_record(action, **kwargs)
            if action == "config_reload" and kwargs.get("actor") == "alice":
                a_written.set()

        async def _fail_b(*_args: Any) -> None:
            # B's registry is live here, before the rollback. Let A write its row now, then fail.
            b_mid_swap.set()
            # Bounded: B holds the runner's reload lock here, and runs on past a client timeout.
            await asyncio.wait_for(a_written.wait(), timeout=30)
            a_written_mid_swap.set()  # proves the ordering; a timeout above would skip this
            raise RuntimeError("an outbound would not start")

        async with _client(engine, service, NOT_GATED, raise_app_exceptions=False) as c:
            alice, bob = await _token(c, "alice"), await _token(c, "bob")
            monkeypatch.setattr(engine, "_reconcile_reference_sync", _hold_a)
            monkeypatch.setattr(engine.store, "record_audit", _spy)
            reload_a = asyncio.ensure_future(c.post("/config/reload", json={}, headers=alice))
            reload_b: asyncio.Future[httpx.Response] | None = None
            try:
                await asyncio.wait_for(a_held.wait(), timeout=30)
                rr = engine.registry_runner
                assert rr is not None
                monkeypatch.setattr(rr, "_reconcile_outbounds", _fail_b)
                reload_b = asyncio.ensure_future(
                    c.post("/config/reload", json={"config_dir": str(cfg_b)}, headers=bob)
                )
                await asyncio.wait_for(b_mid_swap.wait(), timeout=30)
            finally:
                release_a.set()  # never leave A parked, whatever failed above
            r_a = await asyncio.wait_for(reload_a, timeout=30)
            assert reload_b is not None
            r_b = await asyncio.wait_for(reload_b, timeout=30)
        assert r_a.status_code == 200, r_a.text
        assert r_b.status_code == 500, r_b.text  # B failed after its swap and rolled back
        assert a_written_mid_swap.is_set(), "A's row was not written while B's graph was live"
        assert engine.last_reload_dir == cfg_a.resolve(), "A's graph is the one running"

        (row,) = await engine.store.list_audit(action="config_reload")
        detail = json.loads(row["detail"])
        assert row["actor"] == "alice" and detail["fingerprint"] == digest_a["fingerprint"]
        assert "superseded" not in detail and "baseline_unchecked" not in detail
        outcome, comparison = await _compare_start_config(engine, digest_a)
        assert outcome == "compared" and comparison is not None
        assert comparison.baseline_action == "config_reload"
        assert not comparison.changed, "a false config_changed on the next start"
    finally:
        await engine.stop()


async def test_a_reload_row_written_after_a_flag_toggle_is_no_baseline(engine: Engine) -> None:
    """vault BACKLOG #2257: a connection flag toggle moves the loaded fingerprint without swapping
    the graph. A reload row written after one names a digest the engine no longer reports, so it
    marks itself superseded too. The toggle is stood in for by the rebind it performs."""
    outcome = await engine.reload_detail(propagate=False)
    assert outcome.fingerprint is not None
    assert await _record_reload_audit(engine, actor="before", outcome=outcome) == []
    loaded = engine.loaded_config_fingerprint
    assert loaded is not None
    engine.loaded_config_fingerprint = dict(loaded)  # what set_connection_flag does
    assert await _record_reload_audit(engine, actor="after", outcome=outcome) == []
    rows = {r["actor"]: json.loads(r["detail"]) for r in await engine.store.list_audit()}
    assert "superseded" not in rows["before"]
    assert rows["after"]["superseded"] is True and rows["after"]["baseline_unchecked"] is True
    assert rows["after"]["fingerprint"] == outcome.fingerprint["fingerprint"]


# --- a dry-run is never held (it swaps nothing) -------------------------------


async def test_dry_run_reload_is_never_held(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        r = await c.post(
            "/config/reload", json={"dry_run": True}, headers=await _token(c, "deployer")
        )
        assert r.status_code == 200, r.text  # dry-run pre-flight is read-only, never held
        assert r.json()["dry_run"] is True


# --- BACKLOG #2034: a released reload runs the settings-anchor preflight ------


async def test_a_released_reload_refuses_a_swapped_settings_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before BACKLOG #2034 only the inline route ran the settings-anchor preflight, so a reload held
    for a second approver went live on a substituted anchor when it was released. The engine now
    runs it on every real reload. The control is a release before the swap, which goes live."""
    good = _block(b"good")
    anchor = tmp_path / "ad-ca.pem"
    anchor.write_bytes(good)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(True))
    auth = AuthSettings(
        admin_write_min_interval_seconds=0,
        ad_tls_ca_cert_file=str(anchor),
        ad_tls_ca_cert_pin=hashlib.sha256(good).hexdigest(),
    )
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    store = await MessageStore.open(tmp_path / "dc.db")
    preflight = ta.make_settings_anchor_preflight(
        ta.collect_anchor_specs(
            auth,
            ApiSettings(),
            tls=TlsSettings(),
            alerts=AlertsSettings(),
            log_settings=LoggingSettings(),
        ),
        store,
        enforcing=True,
    )
    engine = Engine(
        store,
        poll_interval=0.02,
        config_dir=cfg,
        settings_preflight=preflight,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await _service(engine)
        await _add(service, "op", Role.ADMINISTRATOR)
        await _add(service, "approver", Role.ADMINISTRATOR)
        app = create_app(engine, auth=service, approvals=GATED)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            op, admin = await _token(c, "op"), await _token(c, "approver")

            async def hold_and_release() -> httpx.Response:
                held = await c.post("/config/reload", json={}, headers=op)
                assert held.status_code == 202, held.text
                approval_id = held.json()["approval_id"]
                return await c.post(f"/approvals/{approval_id}/approve", headers=admin)

            ok = await hold_and_release()  # the control: an unchanged anchor goes live
            assert ok.status_code == 200, ok.text
            live = engine.registry_runner
            assert live is not None
            before = live.registry

            anchor.write_bytes(_block(b"evil"))
            refused = await hold_and_release()
            # 422 as the inline route answers, not an unhandled 500 (raise_app_exceptions=False
            # would turn a crash into a response, so the exact code is what proves the handling).
            assert refused.status_code == 422, refused.text
            assert engine.registry_runner is live and live.registry is before  # nothing swapped
        rows = await store.list_audit(limit=100)
        assert "approval.failed" in [r["action"] for r in rows]
        failed = [json.loads(r["detail"]) for r in rows if r["action"] == "config_reload_failed"]
        assert failed == [{"requested": None, "dry_run": False, "reason": "trust_anchor"}]
        events = [json.loads(r["detail"])["event"] for r in rows if r["action"] == ta.AUDIT_ACTION]
        assert "pin_mismatch" in events
    finally:
        await engine.stop()


# --- vault BACKLOG #2459: a released reload is refused like an inline one, never a 500 ----------


async def _hold_then_release(
    engine: Engine, service: AuthService, body: dict[str, Any], between: Any = None
) -> tuple[str, httpx.Response]:
    """Hold a reload as one admin, run ``between``, then release it as another."""
    await _add(service, "op", Role.ADMINISTRATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    # raise_app_exceptions=False, so the pre-fix 500 arrives as a response rather than a raise.
    async with _client(engine, service, GATED, raise_app_exceptions=False) as c:
        op, admin = await _token(c, "op"), await _token(c, "approver")
        held = await c.post("/config/reload", json=body, headers=op)
        assert held.status_code == 202, held.text
        approval_id = held.json()["approval_id"]
        if between is not None:
            between()
        return approval_id, await c.post(f"/approvals/{approval_id}/approve", headers=admin)


async def test_a_released_reload_whose_config_dir_vanished_answers_422_and_records_it(
    engine: Engine, tmp_path: Path
) -> None:
    """Before vault BACKLOG #2459 the executor caught WiringError only, so a directory removed
    between the hold and the release raised FileNotFoundError out of the approve route as a 500,
    with no config_reload_failed row. It now answers 422 with the inline route's detail, records
    the row the inline route records, and the gate marks the request failed. 422, not the inline
    404: on the approve route 404 means "no such approval request"."""
    import shutil

    service = await _service(engine)
    live = engine.registry_runner
    before = live.registry if live is not None else None
    approval_id, r = await _hold_then_release(
        engine, service, {}, between=lambda: shutil.rmtree(tmp_path / "cfg")
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == "config directory not found"
    rr = engine.registry_runner
    assert (rr.registry if rr is not None else None) is before  # nothing swapped
    failed = [
        json.loads(row["detail"])
        for row in await engine.store.list_audit(action="config_reload_failed")
    ]
    assert failed == [{"requested": None, "dry_run": False, "reason": "not_found"}]
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "failed"
    assert len(await engine.store.list_audit(action="approval.failed")) == 1


async def test_a_released_reload_outside_the_reload_roots_answers_422_and_records_it(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held request's directory can leave the reload roots before its release, for one when a
    restart narrows them. Before vault BACKLOG #2459 its release raised ConfigReloadDenied as a
    500. It now answers 422 with the inline route's detail and its denied row. A directory already
    outside the roots is refused at request time instead (vault BACKLOG #2596), so the roots
    narrow here between the hold and the release."""
    from messagefoundry.pipeline import ConfigReloadDenied

    def _narrowed(_config_dir: object) -> Path:
        raise ConfigReloadDenied("outside the reload roots")

    service = await _service(engine)
    approval_id, r = await _hold_then_release(
        engine,
        service,
        {},
        between=lambda: monkeypatch.setattr(engine, "_resolve_reload_target", _narrowed),
    )
    assert r.status_code == 422, r.text  # not 403, which means self-approval on this route
    assert r.json()["detail"] == "config directory is not an allowed reload root"
    denied = [
        json.loads(row["detail"])
        for row in await engine.store.list_audit(action="config_reload_denied")
    ]
    assert denied == [{"requested": None, "dry_run": False}]
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "failed"


async def test_a_refused_release_whose_audit_row_fails_still_answers_422(
    engine: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #2255 review: the refusal's own row used to be a hard write, so an audit outage
    turned the mapped refusal into a raw 500. The refusal changed nothing, so it still answers 422
    and the lost row is logged at ERROR."""
    import shutil

    real = engine.store.record_audit

    async def _record(action: str, **kwargs: Any) -> None:
        if action == "config_reload_failed":
            raise sqlite3.OperationalError("disk I/O error")
        await real(action, **kwargs)

    service = await _service(engine)

    def _break() -> None:
        shutil.rmtree(tmp_path / "cfg")
        monkeypatch.setattr(engine.store, "record_audit", _record)

    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
        _approval_id, r = await _hold_then_release(engine, service, {}, between=_break)
    assert r.status_code == 422, r.text
    assert any(
        rec.levelno == logging.ERROR and "config_reload_failed audit row failed" in rec.getMessage()
        for rec in caplog.records
    )


async def _refuse_audit(action: str, **kwargs: Any) -> None:
    raise sqlite3.OperationalError("disk I/O error")


#: An engine whose audit log refuses every write, for the lost-row log tests below.
_AUDIT_DOWN = cast(Engine, SimpleNamespace(store=SimpleNamespace(record_audit=_refuse_audit)))

#: A CR/LF in the actor and in the requested directory, each shaped to forge a log line.
_FORGING_ACTOR = "alice\nFORGED actor=root"
_FORGING_DIR = "/cfg\r\nFORGED config reload succeeded"


def _assert_no_forged_line(caplog: pytest.LogCaptureFixture) -> None:
    """caplog's handler has no ControlCharScrubFilter, so this reads each call site's own scrub."""
    records = [r for r in caplog.records if r.name == "messagefoundry.api.app"]
    assert records
    for record in records:
        message = record.getMessage()
        assert "\r" not in message and "\n" not in message, message


async def test_a_lost_refusal_row_cannot_forge_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """CodeQL py/log-injection on PR 2115. A refused reload logs the caller's requested directory
    twice: in the refusal WARNING and in the lost-row ERROR. Neither message may start a new line,
    and the lost row must still parse back to the detail that was lost. This reads the messages,
    not a traceback: a route's chained refusal is left to the handler filter, as app.py says."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        status, _answer = await _audit_refused_reload(
            _AUDIT_DOWN,
            FileNotFoundError(f"config directory not found: {_FORGING_DIR}"),
            actor=_FORGING_ACTOR,
            requested=_FORGING_DIR,
            dry_run=False,
        )
    assert status == 404
    _assert_no_forged_line(caplog)
    [lost] = [r for r in caplog.records if "Lost row" in r.getMessage()]
    message = lost.getMessage()
    assert "actor=alice\\nFORGED actor=root " in message
    row = message.split(" detail=", 1)[1]
    assert json.loads(row) == {"requested": _FORGING_DIR, "dry_run": False, "reason": "not_found"}


async def test_the_other_lost_reload_rows_cannot_forge_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The same for the two sibling lost-row logs: a reload's own row after the swap, and the
    attempt row an ungated reload writes first. The fake engine has no graph, so the first one
    loses the row before its detail is built and logs the actor alone."""
    lost_actions: list[str] = []
    sink = SimpleNamespace(audit_write_failed=lambda name, *, action: lost_actions.append(action))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        steps = await _record_reload_audit(_AUDIT_DOWN, actor=_FORGING_ACTOR)
        with pytest.raises(HTTPException) as refused:
            await _audit_reload_attempt(
                _AUDIT_DOWN,
                actor=_FORGING_ACTOR,
                requested=_FORGING_DIR,
                client=None,
                alert_sink=cast(Any, sink),
            )
    assert steps and refused.value.status_code == 503
    assert lost_actions == ["config_reload_attempted"]
    _assert_no_forged_line(caplog)
    lost = [r.getMessage() for r in caplog.records if "Lost row" in r.getMessage()]
    assert len(lost) == 2
    assert json.loads(lost[1].split(" detail=", 1)[1]) == {
        "requested": _FORGING_DIR,
        "dry_run": False,
    }


async def _keep_audit(action: str, **kwargs: Any) -> None:
    return None


#: An engine whose audit log takes every write, so a refusal logs its WARNING and nothing else.
_AUDIT_UP = cast(Engine, SimpleNamespace(store=SimpleNamespace(record_audit=_keep_audit)))


def _refusal_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "messagefoundry.api.app"
        and r.levelno == logging.WARNING
        and r.getMessage().startswith("config reload ")
    ]


@pytest.mark.parametrize(
    "long_dir",
    [
        "/opt/messagefoundry/" + "/".join(f"site-{i:02d}-feeds" for i in range(25)),
        "/opt/" + "a" * 4091,  # the longest config_dir FilesystemPath accepts, one token
    ],
)
async def test_a_missing_dir_refusal_logs_the_whole_long_path(
    caplog: pytest.LogCaptureFixture, long_dir: str
) -> None:
    """Lander hold on PR 2115. The refusal WARNING carries the real reload error, and
    ``safe_exc``'s default 200-character cut dropped the directory from a long config path. The
    whole path must reach the line, past where the old cut fell, up to the longest the API takes."""
    assert len(long_dir) > 300
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        status, answer = await _audit_refused_reload(
            _AUDIT_UP,
            FileNotFoundError(f"config directory not found: {long_dir}"),
            actor="alice",
            requested=long_dir,
            dry_run=False,
        )
    assert (status, answer) == (404, "config directory not found")
    [warning] = _refusal_warnings(caplog)
    assert warning == (
        f"config reload failed (missing dir): FileNotFoundError: config directory not found: {long_dir}"
    )


@pytest.mark.parametrize(
    ("cause", "prefix"),
    [
        (None, "config reload failed (invalid config): WiringError: "),
        (
            ta.TrustAnchorError("pin mismatch"),
            "config reload refused (trust anchor): WiringError: ",
        ),
    ],
)
async def test_an_invalid_config_refusal_cannot_forge_a_log_line_and_keeps_its_fix(
    caplog: pytest.LogCaptureFixture, cause: Exception | None, prefix: str
) -> None:
    """The 422 WiringError arm of the same WARNING, in both its wordings. A CR/LF in the error text
    must not start a new log line, and a long error keeps its tail, which is where a WiringError
    puts its fix."""
    fix = "fix: point tls_ca_file at a readable PEM bundle"
    padding = " ".join(f"step-{i:02d}-checked" for i in range(20))
    error = WiringError(
        f"inbound IB_X_ADT at {_FORGING_DIR}: tls_ca_file unreadable; {padding}; {fix}"
    )
    error.__cause__ = cause
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        status, answer = await _audit_refused_reload(
            _AUDIT_UP, error, actor="alice", requested=_FORGING_DIR, dry_run=False
        )
    assert (status, answer) == (422, "invalid configuration")
    _assert_no_forged_line(caplog)
    [warning] = _refusal_warnings(caplog)
    assert warning.startswith(prefix)
    assert "/cfg\\r\\nFORGED config reload succeeded" in warning
    assert warning.endswith(fix)


async def test_a_refusal_warning_is_still_bounded(caplog: pytest.LogCaptureFixture) -> None:
    """The lifted cut is a larger bound, not none: an error past _REFUSAL_LOG_LIMIT is cut, so one
    refusal cannot write a 64 KiB line for every handler to re-scan on the event loop."""
    error = WiringError(" ".join(f"word-{i:05d}" for i in range(2000)))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        await _audit_refused_reload(
            _AUDIT_UP, error, actor="alice", requested="/cfg", dry_run=False
        )
    [warning] = _refusal_warnings(caplog)
    assert "word-00300" in warning  # well past the old 200-character cut
    assert "word-01999" not in warning
    assert len(warning) < _REFUSAL_LOG_LIMIT + 200


async def test_a_refused_release_is_refused_and_recorded_inside_the_outliving_operation(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #2753 made a released reload outlive the approve request; vault BACKLOG #2459
    gave its refusal the inline route's row and answer. Batch 197 merged the two. This pins the
    structure that lets a refusal's row survive a timed-out approve, without timing one out: the
    outliving operation itself ends in the 422, not in the raw FileNotFoundError, and the refusal
    row is already written when it ends."""
    from messagefoundry.api.approvals import ApprovalError
    from messagefoundry.api.outlive import OutlivingOperations

    ended: list[tuple[str, BaseException | None, int]] = []
    real_run = OutlivingOperations.run

    async def _spy(self: OutlivingOperations, coro: Any, label: str) -> Any:
        async def _watched() -> Any:
            try:
                result = await coro
            except BaseException as exc:
                rows = await engine.store.list_audit(action="config_reload_failed")
                ended.append((label, exc, len(rows)))
                raise
            ended.append((label, None, -1))
            return result

        return await real_run(self, _watched(), label)

    secret_dir = "missing-config-dir-text"

    async def _refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError(f"config directory not found: {secret_dir}")

    monkeypatch.setattr(OutlivingOperations, "run", _spy)
    service = await _service(engine)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        _approval_id, r = await _hold_then_release(
            engine,
            service,
            {},
            between=lambda: monkeypatch.setattr(engine, "reload_detail", _refuse),
        )
    assert r.status_code == 422, r.text
    released = [(exc, rows) for label, exc, rows in ended if label == "released config reload"]
    assert len(released) == 1
    exc, rows_when_it_ended = released[0]
    assert isinstance(exc, ApprovalError) and exc.status == 422
    assert rows_when_it_ended == 1  # written inside the operation, not after it
    marks = [
        rec
        for rec in caplog.records
        if rec.getMessage().startswith("released config reload refused")
    ]
    assert len(marks) == 1
    assert marks[0].levelno == logging.WARNING
    # The marker names the type only, never the exception text.
    assert marks[0].getMessage() == "released config reload refused: FileNotFoundError"


# --- BACKLOG #2183: a released reload audits an unreadable inbound CA as trust_anchor -------------


async def test_a_released_reload_audits_an_unreadable_inbound_ca_as_trust_anchor(
    tmp_path: Path,
) -> None:
    """The held-reload half of BACKLOG #2183. The inbound CA preflight raised its WiringError
    straight from the OSError, so the release audited invalid_config while a settings anchor's
    audited trust_anchor. The control is a release of the File graph first, which goes live."""
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    store = await MessageStore.open(tmp_path / "dc.db")
    engine = Engine(
        store,
        poll_interval=0.02,
        config_dir=cfg,
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await _service(engine)
        await _add(service, "op", Role.ADMINISTRATOR)
        await _add(service, "approver", Role.ADMINISTRATOR)
        app = create_app(engine, auth=service, approvals=GATED)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            op, admin = await _token(c, "op"), await _token(c, "approver")

            async def hold_and_release() -> httpx.Response:
                held = await c.post("/config/reload", json={}, headers=op)
                assert held.status_code == 202, held.text
                approval_id = held.json()["approval_id"]
                return await c.post(f"/approvals/{approval_id}/approve", headers=admin)

            ok = await hold_and_release()  # the control: a graph with no inbound CA goes live
            assert ok.status_code == 200, ok.text
            live = engine.registry_runner
            assert live is not None
            before = live.registry

            gone = str(tmp_path / "gone.pem")
            (cfg / "cfg.py").write_text(
                "from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router\n"
                f"inbound('ADT_IN', MLLP(port=21575, tls=True, tls_cert_file={gone!r}, "
                f"tls_ca_file={gone!r}), router='r')\n"
                f"outbound('OUT', File(directory={str(tmp_path / 'out')!r}))\n"
                "@router('r')\n"
                "def route(msg):\n"
                "    return ['h']\n"
                "@handler('h')\n"
                "def handle(msg):\n"
                "    return Send('OUT', msg)\n",
                encoding="utf-8",
            )
            refused = await hold_and_release()
            assert refused.status_code == 422, refused.text
            assert engine.registry_runner is live and live.registry is before  # nothing swapped
        rows = await store.list_audit(limit=100)
        failed = [json.loads(r["detail"]) for r in rows if r["action"] == "config_reload_failed"]
        assert failed == [{"requested": None, "dry_run": False, "reason": "trust_anchor"}]
    finally:
        await engine.stop()


# --- vault BACKLOG #2596, step 3: the approval names the bytes, and the release checks them ------


def _held_params(row: Any) -> dict[str, Any]:
    assert row is not None
    params: dict[str, Any] = json.loads(str(row["params"]))
    return params


def _edit_with_marker(cfg: Path, marker: Path) -> None:
    """Rewrite cfg.py so that loading it leaves ``marker`` behind, proving whether it ran."""
    src = (cfg / "cfg.py").read_text(encoding="utf-8")
    (cfg / "cfg.py").write_text(
        f"open({str(marker)!r}, 'w').write('ran')\n" + src, encoding="utf-8"
    )


def _editing_load(cfg: Path, marker: Path, *, then_raise: bool = False) -> Any:
    """A ``load_config`` that loads ``cfg``, then edits it as a writer would mid-release."""
    from messagefoundry.config.wiring import load_config

    def _load(path: Path) -> Any:
        registry = load_config(path)
        _edit_with_marker(cfg, marker)
        if then_raise:
            raise WiringError("the edited module does not load")
        return registry

    return _load


async def _failed_reload_rows(engine: Engine) -> list[dict[str, Any]]:
    return [
        json.loads(r["detail"])
        for r in await engine.store.list_audit(action="config_reload_failed")
    ]


async def _digest_mismatch_rows(engine: Engine) -> list[dict[str, Any]]:
    return [d for d in await _failed_reload_rows(engine) if d.get("reason") == "digest_mismatch"]


async def test_a_held_reload_names_the_config_digest_taken_at_request_time(
    engine: Engine, tmp_path: Path
) -> None:
    from messagefoundry.config.fingerprint import config_fingerprint

    service = await _service(engine)
    approval_id, r = await _hold_then_release(engine, service, {})
    assert r.status_code == 200, r.text
    params = _held_params(await engine.store.get_pending_approval(approval_id))
    assert params["fingerprint"] == config_fingerprint(tmp_path / "cfg")
    # The released reload's row records the very digest the approver released.
    rows = await engine.store.list_audit(action="config_reload")
    assert [json.loads(row["detail"])["fingerprint"] for row in rows] == [params["fingerprint"]]


async def test_a_release_after_the_config_was_edited_is_refused_before_any_of_it_runs(
    engine: Engine, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The approver saw one set of bytes; the requester, or anyone with write on the directory,
    changed them before the release. Before this the release loaded whatever was on disk."""
    from messagefoundry.config.fingerprint import config_fingerprint

    cfg, marker = tmp_path / "cfg", tmp_path / "ran.txt"
    approved = config_fingerprint(cfg)
    service = await _service(engine)
    live = engine.registry_runner
    before = live.registry if live is not None else None
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        approval_id, r = await _hold_then_release(
            engine, service, {}, between=lambda: _edit_with_marker(cfg, marker)
        )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == (
        "the config changed after this reload was requested; request the reload again"
    )
    assert not marker.exists(), "the edited module ran before the refusal"
    rr = engine.registry_runner
    assert (rr.registry if rr is not None else None) is before  # nothing swapped
    assert await engine.store.list_audit(action="config_reload") == []
    assert await _digest_mismatch_rows(engine) == [
        {
            "requested": None,
            "dry_run": False,
            "reason": "digest_mismatch",
            "approved_fingerprint": approved,
            "current_fingerprint": config_fingerprint(cfg),
        }
    ]
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "failed"
    assert len(await engine.store.list_audit(action="approval.failed")) == 1
    assert any("changed after its approval" in rec.getMessage() for rec in caplog.records)


async def test_an_edit_made_while_the_release_loads_is_refused_before_the_swap(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second check: the bytes matched before load_config and changed during it. The digest
    taken before the swap, the one the audit row records, must still be the approved one."""
    editing = _editing_load(tmp_path / "cfg", tmp_path / "unused.txt")
    service = await _service(engine)
    live = engine.registry_runner
    before = live.registry if live is not None else None
    _approval_id, r = await _hold_then_release(
        engine,
        service,
        {},
        between=lambda: monkeypatch.setattr("messagefoundry.pipeline.engine.load_config", editing),
    )
    assert r.status_code == 422, r.text
    rr = engine.registry_runner
    assert (rr.registry if rr is not None else None) is before  # nothing swapped
    assert len(await _digest_mismatch_rows(engine)) == 1
    assert await engine.store.list_audit(action="config_reload") == []


async def test_a_hold_that_captured_no_digest_is_refused_at_release(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: an approval that names no bytes cannot release any."""

    async def _none(_config_dir: object) -> None:
        return None

    monkeypatch.setattr(engine, "reload_target_digest", _none)
    service = await _service(engine)
    approval_id, r = await _hold_then_release(engine, service, {})
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == (
        "this request named no config digest, so it cannot be released; request the reload again"
    )
    assert _held_params(await engine.store.get_pending_approval(approval_id))["fingerprint"] is None
    [row] = [
        json.loads(r["detail"])
        for r in await engine.store.list_audit(action="config_reload_failed")
    ]
    assert row["reason"] == "no_approved_digest"
    assert row["approved_fingerprint"] is None and isinstance(row["current_fingerprint"], str)
    assert await engine.store.list_audit(action="config_reload") == []


async def test_a_repeat_after_an_edit_is_a_new_request_not_a_rejoin(
    engine: Engine, tmp_path: Path
) -> None:
    """The digest is part of what a hold captures, so a repeat joins an open request only while the
    bytes are the ones that request named. The control is a repeat with nothing edited."""
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        op = await _token(c, "op")
        first = (await c.post("/config/reload", json={}, headers=op)).json()["approval_id"]
        again = (await c.post("/config/reload", json={}, headers=op)).json()["approval_id"]
        assert again == first  # the control: same bytes, same request
        _edit_with_marker(tmp_path / "cfg", tmp_path / "unused.txt")
        edited = (await c.post("/config/reload", json={}, headers=op)).json()["approval_id"]
        assert edited != first


async def test_an_ungated_reload_takes_no_request_time_digest(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An inline reload holds nothing, so it binds nothing and reads the directory no extra time."""

    async def _must_not_run(_config_dir: object) -> str:
        raise AssertionError("an ungated reload took a request-time digest")

    monkeypatch.setattr(engine, "reload_target_digest", _must_not_run)
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    async with _client(engine, service, NOT_GATED) as c:
        r = await c.post("/config/reload", json={}, headers=await _token(c, "deployer"))
    assert r.status_code == 200, r.text


async def test_an_unreadable_vcs_head_does_not_refuse_an_unchanged_release(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approval binds content. A git HEAD that cannot be read loses the whole fingerprint
    detail, so the binding must not rest on that detail, or every held reload would be refused."""
    import messagefoundry.config.fingerprint as fp_mod

    def _bad_head(_start: Path) -> str | None:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(fp_mod, "_git_head", _bad_head)
    service = await _service(engine)
    approval_id, r = await _hold_then_release(engine, service, {})
    assert r.status_code == 200, r.text
    params = _held_params(await engine.store.get_pending_approval(approval_id))
    assert isinstance(params["fingerprint"], str)
    assert r.json()["result"]["failures"] == ["config_fingerprint"]  # reported, not refused
    assert await _digest_mismatch_rows(engine) == []


# --- vault BACKLOG #2596, step 3 follow-ups: a refused release changes nothing, and says why -----


async def test_a_release_refused_at_the_second_check_keeps_the_running_env_values(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The release re-reads the environment's values before it loads. A refusal after that read
    must not leave the new values on the running graph, which no approver saw."""
    from messagefoundry.config.wiring import load_config

    values = {"HOST": "approved.example.invalid"}
    monkeypatch.setattr(engine, "_env_values_provider", lambda: dict(values))
    await engine.reload_detail(dry_run=False)  # a live runner, on the first values
    runner = engine.registry_runner
    assert runner is not None
    eng_any, runner_any = cast(Any, engine), cast(Any, runner)
    assert eng_any._env_values == runner_any._env_values == {"HOST": "approved.example.invalid"}
    editing = _editing_load(tmp_path / "cfg", tmp_path / "unused.txt")

    def _between() -> None:
        values["HOST"] = "unreviewed.example.invalid"
        monkeypatch.setattr("messagefoundry.pipeline.engine.load_config", editing)

    service = await _service(engine)
    _approval_id, r = await _hold_then_release(engine, service, {}, between=_between)
    assert r.status_code == 422, r.text
    assert len(await _digest_mismatch_rows(engine)) == 1
    assert engine.registry_runner is runner
    assert eng_any._env_values == runner_any._env_values == {"HOST": "approved.example.invalid"}
    # The control: an unrefused reload does apply the new values, so the assert above can fail.
    monkeypatch.setattr("messagefoundry.pipeline.engine.load_config", load_config)
    await engine.reload_detail(dry_run=False)
    assert eng_any._env_values == runner_any._env_values == {"HOST": "unreviewed.example.invalid"}


async def test_a_swap_that_rolls_back_restarts_intake_on_the_old_env_values(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The values go live with the swap, and the swap itself can still fail and roll back to the
    old graph. The rollback restarts the old graph's intake on the old values, not the new ones."""
    first, second = {"HOST": "first.example.invalid"}, {"HOST": "second.example.invalid"}
    values = dict(first)
    monkeypatch.setattr(engine, "_env_values_provider", lambda: dict(values))
    await engine.reload_detail(dry_run=False)
    runner = engine.registry_runner
    assert runner is not None
    eng_any, runner_any = cast(Any, engine), cast(Any, runner)
    restarted_on: list[dict[str, Any]] = []
    real_start = runner_any._checked_inbound_start

    async def _recording_start(name: str) -> None:
        restarted_on.append(dict(runner_any._env_values))
        await real_start(name)

    async def _failing_reconcile(_old: object, _new: object) -> None:
        raise RuntimeError("an outbound connection failed to close")

    monkeypatch.setattr(runner, "_checked_inbound_start", _recording_start)
    monkeypatch.setattr(runner, "_reconcile_outbounds", _failing_reconcile)
    values.update(second)
    with pytest.raises(RuntimeError):
        await engine.reload_detail(dry_run=False)
    assert restarted_on and restarted_on[-1] == first  # the rollback's restart
    assert eng_any._env_values == runner_any._env_values == first


async def test_a_dry_run_checks_the_new_env_values_without_applying_them(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = {"HOST": "first.example.invalid"}
    monkeypatch.setattr(engine, "_env_values_provider", lambda: dict(values))
    await engine.reload_detail(dry_run=False)
    runner = engine.registry_runner
    assert runner is not None
    checked: list[object] = []
    real_check = runner.build_check

    def _recording_check(registry: Any, *env_values: Any) -> None:
        # Passes on only what it was given, so a call without the values fails the assert below
        # rather than the spy (the round-2 review).
        checked.append(env_values[0] if env_values else None)
        real_check(registry, *env_values)

    monkeypatch.setattr(runner, "build_check", _recording_check)
    values["HOST"] = "second.example.invalid"
    await engine.reload_detail(dry_run=True)
    assert checked == [{"HOST": "second.example.invalid"}]
    eng_any, runner_any = cast(Any, engine), cast(Any, runner)
    assert eng_any._env_values == runner_any._env_values == {"HOST": "first.example.invalid"}


@pytest.mark.parametrize("breaks_at", ["load", "preflight"])
async def test_a_tamper_that_also_breaks_the_graph_is_audited_as_a_digest_mismatch(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, breaks_at: str
) -> None:
    """An edit during the release that leaves a bad graph was audited as ``invalid_config``, so an
    audit filter on ``digest_mismatch`` never saw the tamper. ``load``: the edited module fails to
    load. ``preflight``: it loads, and a later check would refuse it; that check must not run."""
    editing = _editing_load(
        tmp_path / "cfg", tmp_path / "unused.txt", then_raise=breaks_at == "load"
    )
    preflights: list[object] = []

    async def _refusing_preflight(registry: object, _values: object) -> None:
        preflights.append(registry)
        raise WiringError("the edited graph is refused")

    def _between() -> None:
        monkeypatch.setattr("messagefoundry.pipeline.engine.load_config", editing)
        monkeypatch.setattr(engine, "_registry_preflight", _refusing_preflight)

    service = await _service(engine)
    _approval_id, r = await _hold_then_release(engine, service, {}, between=_between)
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == (
        "the config changed after this reload was requested; request the reload again"
    )
    assert [d["reason"] for d in await _failed_reload_rows(engine)] == ["digest_mismatch"]
    assert preflights == []


async def test_a_load_failure_on_the_approved_bytes_is_still_invalid_config(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: with nothing edited, a bad graph is a bad graph."""

    def _fails(_path: Path) -> Any:
        raise WiringError("bad graph")

    service = await _service(engine)
    _approval_id, r = await _hold_then_release(
        engine,
        service,
        {},
        between=lambda: monkeypatch.setattr("messagefoundry.pipeline.engine.load_config", _fails),
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == "invalid configuration"
    assert [d["reason"] for d in await _failed_reload_rows(engine)] == ["invalid_config"]


async def test_a_digest_that_cannot_be_taken_at_release_says_so(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Not "the config changed": nothing shows it did, and a new request would meet the same
    failure. The release names its own reason, and the cause is logged at WARNING. A file the
    digest cannot read fails it closed: before the round-3 review it was skipped, and the digest of
    the rest refused this as ``digest_mismatch``, or released it with that file unbound."""
    unreadable = {"on": False}
    _unreadable(monkeypatch, "cfg.py", when=unreadable)
    service = await _service(engine)
    with caplog.at_level(logging.WARNING):
        approval_id, r = await _hold_then_release(
            engine, service, {}, between=lambda: unreadable.update(on=True)
        )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == (
        "the engine could not read the config to check it against this request's approval; "
        "see the engine log"
    )
    approved = _held_params(await engine.store.get_pending_approval(approval_id))["fingerprint"]
    assert await _failed_reload_rows(engine) == [
        {
            "requested": None,
            "dry_run": False,
            "reason": "digest_unavailable",
            "approved_fingerprint": approved,
            "current_fingerprint": None,
        }
    ]
    warnings = [rec.getMessage() for rec in caplog.records if rec.levelno == logging.WARNING]
    assert any("config content digest failed" in m and "Permission denied" in m for m in warnings)
    assert not any("changed after its approval" in m for m in warnings)
    assert await engine.store.list_audit(action="config_reload") == []


@pytest.mark.parametrize(
    ("target", "status", "action"),
    [
        ("outside", 403, "config_reload_denied"),
        ("missing", 404, "config_reload_failed"),
    ],
)
async def test_a_hold_whose_target_cannot_resolve_is_refused_and_not_filed(
    engine: Engine, tmp_path: Path, target: str, status: int, action: str
) -> None:
    """Its release could only be refused, so a second approver would spend a review on nothing.
    The request is refused and audited as the inline reload refuses it, and no hold is filed."""
    outside = tmp_path / "elsewhere"
    _write_valid_config(outside, tmp_path / "in2", tmp_path / "out2")
    config_dir = str(outside if target == "outside" else tmp_path / "cfg" / "missing")
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        op = await _token(c, "op")
        r = await c.post("/config/reload", json={"config_dir": config_dir}, headers=op)
        assert r.status_code == status, r.text
        # The control: a target that resolves is still held.
        assert (await c.post("/config/reload", json={}, headers=op)).status_code == 202
    pending = await engine.store.list_pending_approvals(now=0.0, limit=10)
    assert len(pending) == 1
    assert json.loads(str(pending[0]["params"]))["config_dir"] is None
    assert len(await engine.store.list_audit(action=action)) == 1


# --- vault BACKLOG #2596, round 3: the approval digest fails closed, and round 2 is pinned -------


def _unresolvable(_config_dir: object) -> Path:
    raise PermissionError(13, "Permission denied", "a parent of the config directory")


async def test_a_request_made_while_a_file_is_unreadable_is_refused_and_files_no_hold(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The request-time digest fails closed too. Before the round-3 review it skipped the file and
    named the digest of the rest, so a release could load that file with no approval covering it.
    With no digest, the release could only be refused, so no hold is filed."""
    unreadable = {"on": True}
    _unreadable(monkeypatch, "cfg.py", when=unreadable)
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        op = await _token(c, "op")
        r = await c.post("/config/reload", json={}, headers=op)
        assert r.status_code == 422, r.text
        assert r.json()["detail"] == (
            "the engine could not read the config to take its digest for this request; "
            "see the engine log"
        )
        unreadable["on"] = False
        # The control: the same request, with the file readable, is held.
        assert (await c.post("/config/reload", json={}, headers=op)).status_code == 202
    assert len(await engine.store.list_pending_approvals(now=0.0, limit=10)) == 1
    assert await _failed_reload_rows(engine) == [
        {
            "requested": None,
            "dry_run": False,
            "reason": "digest_unavailable",
            "approved_fingerprint": None,
            "current_fingerprint": None,
        }
    ]


@pytest.mark.parametrize("approvals", [GATED, NOT_GATED], ids=["held", "inline"])
async def test_a_target_the_engine_cannot_list_is_unreadable_not_missing(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, approvals: ApprovalsSettings
) -> None:
    """A parent the service account cannot traverse, or a directory it cannot list, fails the
    listing with an access error. ``is_dir`` answered False for the first, so it was audited as a
    missing directory, and an ungated reload of the second loaded an empty graph and was audited
    as ``invalid_config``. Both are refused as ``unreadable``, with no hold filed."""
    cfg = (tmp_path / "cfg").resolve()
    real_scandir = os.scandir

    def _scandir(path: Any) -> Any:
        if isinstance(path, (str, os.PathLike)) and Path(path).resolve() == cfg:
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, approvals, raise_app_exceptions=False) as c:
        op = await _token(c, "op")
        monkeypatch.setattr(os, "scandir", _scandir)
        r = await c.post("/config/reload", json={}, headers=op)
        monkeypatch.undo()
        assert r.status_code == 422, r.text
        assert r.json()["detail"] == (
            "the engine could not read the config directory; see the engine log"
        )
    assert await engine.store.list_pending_approvals(now=0.0, limit=10) == []
    assert [d["reason"] for d in await _failed_reload_rows(engine)] == ["unreadable"]


async def test_a_file_added_during_the_load_and_left_unreadable_is_not_released(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest the audit row records skips a file it cannot read, so on its own it matched the
    approval with the added file unbound. The fail-closed digest runs first."""
    from messagefoundry.config.wiring import load_config

    cfg = tmp_path / "cfg"
    unreadable = {"on": False}
    _unreadable(monkeypatch, "extra.py", when=unreadable)

    def _load(path: Path) -> Any:
        registry = load_config(path)
        (cfg / "extra.py").write_text("X = 1\n", encoding="utf-8")
        unreadable["on"] = True
        return registry

    service = await _service(engine)
    _approval_id, r = await _hold_then_release(
        engine,
        service,
        {},
        between=lambda: monkeypatch.setattr("messagefoundry.pipeline.engine.load_config", _load),
    )
    assert r.status_code == 422, r.text
    assert [d["reason"] for d in await _failed_reload_rows(engine)] == ["digest_unavailable"]
    assert await engine.store.list_audit(action="config_reload") == []


async def test_a_directory_moved_away_after_the_resolve_is_refused_as_missing(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing directory digested as an empty bundle, so a move after the resolve was audited as
    an edit, ``digest_mismatch``. It is a missing directory, and docs/SECURITY.md says so."""
    cfg = tmp_path / "cfg"
    real = engine._existing_reload_target

    async def _then_moved(config_dir: str | Path | None) -> Path:
        path = await real(config_dir)
        cfg.rename(tmp_path / "moved")
        return path

    service = await _service(engine)
    _approval_id, r = await _hold_then_release(
        engine,
        service,
        {},
        between=lambda: monkeypatch.setattr(engine, "_existing_reload_target", _then_moved),
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == "config directory not found"
    assert await _failed_reload_rows(engine) == [
        {"requested": None, "dry_run": False, "reason": "not_found"}
    ]


async def test_a_release_whose_directory_cannot_be_resolved_is_refused_and_recorded(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An OSError other than FileNotFoundError escaped the refusals the executor catches, so the
    approve answered 500 with no config_reload_failed row (the round-2 review's F6)."""
    service = await _service(engine)
    with caplog.at_level(logging.WARNING):
        approval_id, r = await _hold_then_release(
            engine,
            service,
            {},
            between=lambda: monkeypatch.setattr(engine, "_resolve_reload_target", _unresolvable),
        )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == (
        "the engine could not read the config directory; see the engine log"
    )
    assert await _failed_reload_rows(engine) == [
        {"requested": None, "dry_run": False, "reason": "unreadable"}
    ]
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "failed"
    assert any(
        "config reload target could not be resolved" in rec.getMessage() for rec in caplog.records
    )


@pytest.mark.parametrize("approvals", [GATED, NOT_GATED], ids=["held", "inline"])
async def test_a_request_whose_directory_cannot_be_resolved_is_refused_and_files_no_hold(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, approvals: ApprovalsSettings
) -> None:
    """Held, it used to file a hold with no digest that its release could only refuse. Inline, it
    answered 500 with no row. Both are now the audited refusal."""
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, approvals, raise_app_exceptions=False) as c:
        op = await _token(c, "op")
        monkeypatch.setattr(engine, "_resolve_reload_target", _unresolvable)
        r = await c.post("/config/reload", json={}, headers=op)
        assert r.status_code == 422, r.text
        monkeypatch.undo()
        # The control: the same request with a target that resolves.
        again = await c.post("/config/reload", json={}, headers=op)
        assert again.status_code == (202 if approvals is GATED else 200), again.text
    pending = await engine.store.list_pending_approvals(now=0.0, limit=10)
    assert len(pending) == (1 if approvals is GATED else 0)
    assert [d["reason"] for d in await _failed_reload_rows(engine)] == ["unreadable"]


async def test_a_refused_hold_is_recorded_inside_an_outliving_operation(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route's comment says every refusal past the hold is inside an outliving operation, so a
    request deadline cannot cut its row short. The refusal of a hold ran outside one (F4)."""
    from messagefoundry.api.outlive import OutlivingOperations

    ended: list[tuple[str, int]] = []
    real_run = OutlivingOperations.run

    async def _spy(self: OutlivingOperations, coro: Any, label: str) -> Any:
        async def _watched() -> Any:
            try:
                return await coro
            finally:
                rows = await engine.store.list_audit(action="config_reload_failed")
                ended.append((label, len(rows)))

        return await real_run(self, _watched(), label)

    monkeypatch.setattr(OutlivingOperations, "run", _spy)
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        r = await c.post(
            "/config/reload",
            json={"config_dir": str(tmp_path / "cfg" / "missing")},
            headers=await _token(c, "op"),
        )
    assert r.status_code == 404, r.text
    assert ended == [("refused config reload", 1)]  # the row is written inside the operation


async def test_a_reload_cancelled_after_its_swap_committed_keeps_the_new_env_values(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round 2 reads the values back from the runner whatever the swap's outcome. A cancellation
    after the swap committed left the engine on the old values while the runner ran the new ones."""
    first, second = {"HOST": "first.example.invalid"}, {"HOST": "second.example.invalid"}
    values = dict(first)
    monkeypatch.setattr(engine, "_env_values_provider", lambda: dict(values))
    await engine.reload_detail(dry_run=False)
    runner = engine.registry_runner
    assert runner is not None

    async def _cancelled() -> None:
        raise asyncio.CancelledError

    # The first await after the swap commits (RegistryRunner.reload, step 3a).
    monkeypatch.setattr(runner, "_reconcile_schedulers", _cancelled)
    values.update(second)
    with pytest.raises(asyncio.CancelledError):
        await engine.reload_detail(dry_run=False)
    eng_any, runner_any = cast(Any, engine), cast(Any, runner)
    assert engine.registry_runner is runner
    assert eng_any._env_values == runner_any._env_values == second


async def test_a_first_load_whose_runner_cannot_be_built_restores_the_env_values(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no runner yet, the values go live before the runner is built. Round 2 moved the build
    inside the block that puts them back, so a build that raises leaves the old values."""
    assert engine.registry_runner is None
    eng_any = cast(Any, engine)
    before = dict(eng_any._env_values)
    new = {"HOST": "new.example.invalid"}
    monkeypatch.setattr(engine, "_env_values_provider", lambda: dict(new))
    real_add = engine.add_registry

    def _refused(_registry: Any) -> Any:
        raise RuntimeError("the runner could not be built")

    monkeypatch.setattr(engine, "add_registry", _refused)
    with pytest.raises(RuntimeError):
        await engine.reload_detail(dry_run=False)
    assert engine.registry_runner is None
    assert eng_any._env_values == before
    # The control: with the build working, the same reload applies the new values.
    monkeypatch.setattr(engine, "add_registry", real_add)
    await engine.reload_detail(dry_run=False)
    assert eng_any._env_values == new


async def test_a_digest_refusal_after_a_failed_load_does_not_carry_the_load_error(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round 2 raises the digest refusal after the load's handler, so the load error rides neither
    ``__cause__`` nor ``__context__``, where a TOMLDecodeError would keep a whole value file
    (BACKLOG #2307)."""
    from messagefoundry.config.fingerprint import config_fingerprint
    from messagefoundry.pipeline import ApprovedConfig, ConfigDigestMismatch

    cfg = tmp_path / "cfg"
    approval = ApprovedConfig(config_fingerprint(cfg))
    monkeypatch.setattr(
        "messagefoundry.pipeline.engine.load_config",
        _editing_load(cfg, tmp_path / "unused.txt", then_raise=True),
    )
    with pytest.raises(ConfigDigestMismatch) as refused:
        await engine.reload_detail(dry_run=False, approval=approval)
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None


# --- vault BACKLOG #2596, PR 2239 review: a name no directory can have is missing -------------


@pytest.mark.parametrize("name", INVALID_DIR_NAMES)
@pytest.mark.parametrize("approvals", [GATED, NOT_GATED], ids=["held", "inline"])
async def test_a_name_no_directory_can_have_is_refused_as_missing(
    engine: Engine, tmp_path: Path, approvals: ApprovalsSettings, name: str
) -> None:
    """``is_dir`` answered False for such a name, so the reload answered 404 ``not_found``. Listing
    the target instead raised the OS error, and the reload answered 422 ``unreadable``. No
    directory can have the name, so it is missing again, held or inline, and no hold is filed."""
    config_dir = str(tmp_path / "cfg" / name)
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service, approvals, raise_app_exceptions=False) as c:
        op = await _token(c, "op")
        r = await c.post("/config/reload", json={"config_dir": config_dir}, headers=op)
        assert r.status_code == 404, r.text
        assert r.json()["detail"] == "config directory not found"
    assert await engine.store.list_pending_approvals(now=0.0, limit=10) == []
    assert await _failed_reload_rows(engine) == [
        {"requested": config_dir, "dry_run": False, "reason": "not_found"}
    ]


@pytest.mark.parametrize("name", INVALID_DIR_NAMES)
async def test_the_gated_engine_path_refuses_a_name_no_directory_can_have_as_missing(
    engine: Engine, tmp_path: Path, name: str
) -> None:
    """The request-time digest and an approval-bound reload both raise ``FileNotFoundError``, not
    ``ConfigDirUnreadable`` or ``ConfigDigestUnavailable``. The strict digest itself is pinned in
    tests/test_config_fingerprint.py."""
    from messagefoundry.config.fingerprint import config_fingerprint
    from messagefoundry.pipeline import ApprovedConfig

    config_dir = tmp_path / "cfg" / name
    with pytest.raises(FileNotFoundError):
        await engine.reload_target_digest(config_dir)
    approval = ApprovedConfig(config_fingerprint(tmp_path / "cfg"))
    with pytest.raises(FileNotFoundError):
        await engine.reload_detail(config_dir, approval=approval)
