# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""POST /config/reload — apply a code-first graph to the running engine over the API."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
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
    assert r.json() == {
        "inbound": 1,
        "outbound": 1,
        "routers": 1,
        "handlers": 1,
        "running": True,
        "dry_run": False,
    }


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
