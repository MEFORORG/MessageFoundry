# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""POST /config/reload — apply a code-first graph to the running engine over the API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.environments import load_environment_values
from messagefoundry.config.fingerprint import config_fingerprint
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path):
    eng = await Engine.create(tmp_path / "api.db", poll_interval=0.05)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine):
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


def _write_valid_config(cfg: Path, inbox: Path, outdir: Path) -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    body = (
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound('IB_T_ADT', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n"
    )
    (cfg / "cfg.py").write_text(body, encoding="utf-8")


async def test_reload_endpoint_applies_config(client: httpx.AsyncClient, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    r = await client.post("/config/reload", json={"config_dir": str(cfg)})
    assert r.status_code == 200, r.text
    # Compared WHOLE rather than field-by-field on purpose: this is the shape contract the shipped
    # apiclient and console read. BACKLOG #1111 added `degraded` and `failures`, and their values
    # here are the clean-reload NEGATIVE CONTROL -- a route that reported every apply as degraded
    # would satisfy the degraded-path test and only fail here.
    assert r.json() == {
        "inbound": 1,
        "outbound": 1,
        "routers": 1,
        "handlers": 1,
        "running": True,
        "dry_run": False,
        "degraded": False,
        "failures": [],
    }


async def test_a_degraded_apply_is_reported_and_audited_not_answered_as_clean(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reload whose graph SWAPPED but whose follow-on step failed answers 200 with degraded=True.

    RED when: the route calls Engine.reload instead of reload_detail, or drops either field. That
    reverts to reporting a degraded apply as a clean success, which is the defect BACKLOG #1111
    exists to fix -- and it is invisible without this test, because the status code does not move.

    The negative control is test_reload_endpoint_applies_config, which pins degraded False on a
    clean reload; a route hardcoding degraded=True passes this test and fails that one.
    """
    cfg, inbox, outdir = tmp_path / "cfg", tmp_path / "in", tmp_path / "out"
    _write_valid_config(cfg, inbox, outdir)

    async def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("reference sync exploded")

    monkeypatch.setattr(engine, "_reconcile_reference_sync", _boom)
    r = await client.post("/config/reload", json={"config_dir": str(cfg)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["degraded"] is True
    assert body["failures"] == ["reference_sync"]
    # The graph really did swap -- otherwise this is a test about an enum, not about the defect.
    assert body["inbound"] == 1 and body["running"] is True
    rows = [
        json.loads(row["detail"])
        for row in await engine.store.list_audit(limit=50)
        if row["action"] == "config_reload"
    ]
    assert rows and rows[0].get("failed_steps") == ["reference_sync"], (
        "the degraded step must reach the AUDIT row, not only the response body -- the response "
        "goes to one caller once, the audit is what a later reader has"
    )


async def test_reload_failures_are_audited(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # low-7: a failed reload (missing dir / invalid config) writes a config_reload_failed audit row
    # with a COARSE reason — not the raw exception/path.
    assert (
        await client.post("/config/reload", json={"config_dir": str(tmp_path / "nope")})
    ).status_code == 404
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "cfg.py").write_text("x = 1  # declares no connections\n", encoding="utf-8")
    assert (await client.post("/config/reload", json={"config_dir": str(empty)})).status_code == 422

    failed = [a for a in await engine.store.list_audit() if a["action"] == "config_reload_failed"]
    reasons = {r for a in failed for r in [a["detail"] or ""] if r}
    assert any("not_found" in r for r in reasons)
    assert any("invalid_config" in r for r in reasons)


async def test_reload_endpoint_dry_run_validates_without_applying(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    r = await client.post("/config/reload", json={"config_dir": str(cfg), "dry_run": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True and body["inbound"] == 1
    assert body["running"] is False  # the engine had no graph and dry-run swaps nothing


async def test_reload_endpoint_dry_run_missing_env_value_422(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    cfg = tmp_path / "envcfg"
    cfg.mkdir()
    (tmp_path / "in").mkdir(exist_ok=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File, MLLP, env\n"
        f"inbound('IB', File(directory={str(tmp_path / 'in')!r}, pattern='*.hl7'), router='r')\n"
        "outbound('OUT', MLLP(host=env('peer_host'), port=2601))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OUT', msg)\n",
        encoding="utf-8",
    )
    # The instance defines no env values, so the promote pre-flight refuses (a missing env value).
    r = await client.post("/config/reload", json={"config_dir": str(cfg), "dry_run": True})
    assert r.status_code == 422, r.text


async def test_reload_endpoint_missing_dir_404(client: httpx.AsyncClient, tmp_path: Path) -> None:
    r = await client.post("/config/reload", json={"config_dir": str(tmp_path / "nope")})
    assert r.status_code == 404


async def test_reload_endpoint_invalid_config_422(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    cfg = tmp_path / "bad"
    cfg.mkdir()
    (cfg / "bad.py").write_text(
        "from messagefoundry import inbound, File\n"
        "inbound('IB', File(directory='.', pattern='*.hl7'), router='missing')\n",
        encoding="utf-8",
    )
    r = await client.post("/config/reload", json={"config_dir": str(cfg)})
    assert r.status_code == 422


async def test_reload_endpoint_empty_dir_422(client: httpx.AsyncClient, tmp_path: Path) -> None:
    cfg = tmp_path / "empty"
    cfg.mkdir()
    r = await client.post("/config/reload", json={"config_dir": str(cfg)})
    assert r.status_code == 422


# --- allow-list / containment + audit (API-1, API-5) -------------------------


async def test_reload_rejects_path_outside_allowed_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    _write_valid_config(allowed, tmp_path / "in", tmp_path / "out")
    eng = await Engine.create(tmp_path / "a.db", poll_interval=0.05, config_dir=allowed)
    try:
        transport = httpx.ASGITransport(app=create_app(eng, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            outside = tmp_path / "outside"
            _write_valid_config(outside, tmp_path / "in2", tmp_path / "out2")
            r = await c.post("/config/reload", json={"config_dir": str(outside)})
            assert r.status_code == 403, r.text
            assert str(outside) not in r.text  # generic message — no path disclosure (API-5)
            audit = await eng.store.list_audit()
            assert any(a["action"] == "config_reload_denied" for a in audit)
    finally:
        await eng.stop()


async def test_reload_defaults_to_startup_config_dir_and_audits(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    eng = await Engine.create(tmp_path / "a.db", poll_interval=0.05, config_dir=cfg)
    try:
        transport = httpx.ASGITransport(app=create_app(eng, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post("/config/reload", json={})  # no config_dir -> startup --config dir
            assert r.status_code == 200, r.text
            assert r.json()["inbound"] == 1
            audit = await eng.store.list_audit()
            assert any(a["action"] == "config_reload" for a in audit)
    finally:
        await eng.stop()


async def test_reload_audit_records_fingerprint(tmp_path: Path) -> None:
    # ADR 0041 D1: a successful reload's audit detail carries the config content fingerprint, so a
    # reviewer can prove which bytes the reload activated — not just the connection counts.
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    eng = await Engine.create(tmp_path / "a.db", poll_interval=0.05, config_dir=cfg)
    try:
        transport = httpx.ASGITransport(app=create_app(eng, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.post("/config/reload", json={})).status_code == 200
            rows = [a for a in await eng.store.list_audit() if a["action"] == "config_reload"]
            assert rows, "expected a config_reload audit row"
            detail = json.loads(rows[-1]["detail"])
            assert detail["fingerprint"] == config_fingerprint(cfg)
            assert detail["files"] >= 1
    finally:
        await eng.stop()


async def test_dry_run_reload_audits_config_reload_check_under_the_acting_user(
    tmp_path: Path,
) -> None:
    """BACKLOG #1643: the dry-run pre-flight leaves a ``config_reload_check`` row naming the caller.

    RED when the ``config_reload_check`` ``record_audit`` call in ``api/app.py`` is deleted, or when
    the dry-run arm stops auditing separately from the real-apply arm. No file under ``tests/`` or
    ``packaging/messagefoundry-webconsole/tests/`` named that action before this test: the existing
    dry-run test asserts only the response body, which does not move when the write is removed.

    Authenticated rather than ``allow_no_auth``, which is what makes the ACTOR assertion mean
    something -- under no-auth every row is written by the single ``system`` identity, so a route
    auditing under a hardcoded name would pass. ``require_step_up`` is satisfied by the fresh login.

    The negative control is in-test: the real (non-dry-run) apply writes ``config_reload`` through a
    different call, so the two arms are pinned apart and a route collapsing them is caught.
    """
    pw = "Correct-Horse-Battery-Staple-9"
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    eng = await Engine.create(tmp_path / "a.db", poll_interval=0.05, config_dir=cfg)
    try:
        service = AuthService(eng.store, AuthSettings(require_mfa=False))
        await service.initialize()
        uid = await service.create_local_user(
            username="deployer",
            password=pw,
            display_name=None,
            email=None,
            roles=[Role.DEPLOYMENT.value],  # holds config:deploy, and only what this route needs
            actor="test",
        )
        await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
        user = await service.store.get_user(uid)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            uid, password_hash=user.password_hash, must_change_password=False
        )

        transport = httpx.ASGITransport(app=create_app(eng, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            login = await c.post(
                "/auth/login", json={"username": "deployer", "password": pw, "provider": "local"}
            )
            assert login.status_code == 200, login.text
            h = {"Authorization": f"Bearer {login.json()['token']}"}

            r = await c.post("/config/reload", json={"dry_run": True}, headers=h)
            assert r.status_code == 200, r.text
            assert r.json()["dry_run"] is True

        rows = await eng.store.list_audit(action="config_reload_check")
        assert rows, "a dry-run reload must leave a config_reload_check audit row"
        assert [row["actor"] for row in rows] == ["deployer"]
        detail = json.loads(rows[0]["detail"])
        assert detail["dry_run"] is True
        # The dry-run arm must not be recorded as a real apply -- that would report a validated-only
        # pre-flight as a config deploy to every later reader of the audit trail.
        assert not await eng.store.list_audit(action="config_reload")
    finally:
        await eng.stop()


async def test_reload_allows_extra_configured_root(tmp_path: Path) -> None:
    startup = tmp_path / "startup"
    staging = tmp_path / "staging"
    _write_valid_config(startup, tmp_path / "in", tmp_path / "out")
    _write_valid_config(staging, tmp_path / "in2", tmp_path / "out2")
    eng = await Engine.create(
        tmp_path / "a.db",
        poll_interval=0.05,
        config_dir=startup,
        config_reload_roots=[str(staging)],
    )
    try:
        transport = httpx.ASGITransport(app=create_app(eng, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post("/config/reload", json={"config_dir": str(staging)})
            assert r.status_code == 200, r.text  # staging is an allowed root
    finally:
        await eng.stop()


# --- BACKLOG #1652: a malformed environments/<env>.toml at reload is a 422, not a 500 -------------


async def test_reload_with_a_malformed_env_value_file_is_422_and_audited(tmp_path: Path) -> None:
    """BACKLOG #1652. ``reload`` re-reads this environment's values through the provider, which on the
    CLI path is ``tomllib`` over ``environments/<env>.toml``. That call was unguarded, so a malformed
    value file raised ``TOMLDecodeError`` -- not one of the three types this route arms -- and the
    operator got a 500 with NO ``config_reload_failed`` row: a config deploy that failed and left no
    record. It must answer 422 and audit, like every other rejected config.

    The engine fixture elsewhere in this file supplies NO provider, so it cannot reach this path at
    all; this test builds its own engine over a real value file. The first reload is the negative
    control -- it is clean while the file parses, so the 422 is attributable to the broken file.
    """
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    envdir = tmp_path / "environments"
    envdir.mkdir()
    env_file = envdir / "dev.toml"
    env_file.write_text('peer_host = "10.0.0.1"\n', encoding="utf-8")

    def provider() -> dict[str, Any]:
        # Raw, exactly like the CLI's read. A provider that pre-wrapped its own failure would pass
        # even with the engine-side guard deleted.
        return load_environment_values(
            base_dir=tmp_path, dir_name="environments", environment="dev", environ={}
        )

    eng = await Engine.create(
        tmp_path / "a.db", poll_interval=0.05, config_dir=cfg, env_values_provider=provider
    )
    try:
        transport = httpx.ASGITransport(app=create_app(eng, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.post("/config/reload", json={})).status_code == 200

            # The duplicate-inline-key shape, for the reason recorded once at the guard itself
            # (messagefoundry/__main__.py, the env_values() provider): it is the one malformed shape
            # whose tomllib message quotes text FROM the file, so the engine-side WiringError really
            # does carry file content here, which is what makes the containment checks below mean
            # something at THIS boundary.
            env_file.write_text(
                'a = {peer_host = "never-print-this-value", peer_host = 2}\n', encoding="utf-8"
            )
            r = await c.post("/config/reload", json={})
            assert r.status_code == 422, r.text

            failed = [
                a for a in await eng.store.list_audit() if a["action"] == "config_reload_failed"
            ]
            assert failed, "a rejected reload must leave a config_reload_failed audit row"
            details = [a["detail"] or "" for a in failed]
            assert any("invalid_config" in d for d in details)

            # These pin the ROUTE's containment: api/app.py answers a constant body ("invalid
            # configuration", API-5) and stores a constant detail (requested / dry_run / reason), so
            # the guard's message reaches neither. The guard MESSAGE's own redaction is pinned where
            # it is observable, in tests/test_wiring_reload.py (str(excinfo.value)).
            #
            # Compare against DECODED values, never the raw JSON text. A Windows path renders in JSON
            # with doubled backslashes (C:\\Users\\... for C:\Users\...), so a `str(env_file) not in
            # r.text` check is blind to a leaked path on the platform this repo is developed on.
            def _values(payload: str) -> list[str]:
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    return [payload]
                return [str(v) for v in obj.values()] if isinstance(obj, dict) else [str(obj)]

            surfaced = [v for payload in [r.text, *details] for v in _values(payload)]
            assert surfaced, "nothing decoded -- the checks below would be vacuous"
            # The KEY is the token that makes this a live gate rather than a hopeful one. MEASURED:
            # the guard's message provably contains "peer_host" for this fixture (tomllib quotes the
            # duplicate key) and provably contains neither the value nor the path, so checking only
            # those two passes even when the route dumps the whole message -- which is exactly what a
            # mutation of the 422 arm to render str(exc) demonstrated. Checking the key closes that:
            # it fires the moment any part of the guard's sentence reaches an operator surface.
            assert all("peer_host" not in v for v in surfaced)
            # Kept for the shapes the message does not carry today, so a future guard that starts
            # naming the value file or quoting its bytes is caught here too.
            assert all("never-print-this-value" not in v for v in surfaced)
            assert all(str(env_file) not in v for v in surfaced)

            # The guard runs before the swap, so the graph the first reload started is still live.
            assert eng.registry_runner is not None
            assert set(eng.registry_runner.registry.inbound) == {"IB_T_ADT"}

            # Recovery. A guard that latched -- zeroing _env_values or setting a failure flag ahead
            # of the provider call -- would leave every later reload failing after the operator fixed
            # the file, and every assertion above would still pass. Repair it and the route must go
            # back to 200.
            env_file.write_text('peer_host = "10.0.0.2"\n', encoding="utf-8")
            assert (await c.post("/config/reload", json={})).status_code == 200
    finally:
        await eng.stop()
