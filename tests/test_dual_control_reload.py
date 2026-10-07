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
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import _compare_start_config, _record_reload_audit
from messagefoundry.auth import Role
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    EgressSettings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore
from tests._admin_account import create_local_user_chosen
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
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
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
        ta.collect_anchor_specs(auth, ApiSettings()), store, enforcing=True
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
    engine: Engine, tmp_path: Path
) -> None:
    """The guard holds a reload before the engine resolves its directory, so a held request can name
    a directory outside the reload roots. Before vault BACKLOG #2459 its release raised
    ConfigReloadDenied as a 500. It now answers 422 with the inline route's detail and its
    denied row."""
    elsewhere = tmp_path / "elsewhere"
    _write_valid_config(elsewhere, tmp_path / "in2", tmp_path / "out2")
    service = await _service(engine)
    approval_id, r = await _hold_then_release(engine, service, {"config_dir": str(elsewhere)})
    assert r.status_code == 422, r.text  # not 403, which means self-approval on this route
    assert r.json()["detail"] == "config directory is not an allowed reload root"
    denied = [
        json.loads(row["detail"])
        for row in await engine.store.list_audit(action="config_reload_denied")
    ]
    assert denied == [{"requested": str(elsewhere), "dry_run": False}]
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


async def test_a_lost_refusal_row_cannot_forge_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """CodeQL py/log-injection on PR 2115: the lost-row ERROR carries the caller's requested
    directory and the actor, so a CR or LF in either must not start a new log line. caplog's
    handler has no ControlCharScrubFilter, so this reads the call site's own scrub. The row must
    still be recoverable: its JSON parses back to the detail that was lost."""
    from types import SimpleNamespace
    from typing import cast

    from messagefoundry.api.app import _audit_refused_reload

    async def _refuse(action: str, **kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    fake = cast(Engine, SimpleNamespace(store=SimpleNamespace(record_audit=_refuse)))
    requested = "/cfg\r\nFORGED config reload succeeded"
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
        status, _answer = await _audit_refused_reload(
            fake,
            FileNotFoundError(requested),
            actor="alice\nFORGED actor=root",
            requested=requested,
            dry_run=False,
        )
    assert status == 404
    [lost] = [r for r in caplog.records if "Lost row" in r.getMessage()]
    message = lost.getMessage()
    assert "\r" not in message and "\n" not in message
    assert "actor=alice\\nFORGED actor=root " in message
    row = message.split(" detail=", 1)[1]
    assert json.loads(row) == {"requested": requested, "dry_run": False, "reason": "not_found"}


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
