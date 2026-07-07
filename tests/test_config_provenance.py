# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""GET /config/provenance + the web config-page badge (ADR 0041 D1, item C).

Provenance = the content fingerprint + best-effort git commit of the graph the engine currently has
loaded, plus a ``drift`` flag that recomputes the on-disk fingerprint and compares it to that baseline.
Non-secret (a one-way hash + a commit sha); gated by ``monitoring:read`` like ``/status``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.models import ConfigProvenance
from messagefoundry_webconsole.pages.config import config_page
from messagefoundry.config.fingerprint import config_fingerprint
from messagefoundry.pipeline import Engine


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
    eng = await Engine.create(tmp_path / "prov.db", poll_interval=0.05)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


# --- API: GET /config/provenance ---------------------------------------------


async def test_provenance_before_any_load(client: httpx.AsyncClient) -> None:
    # No graph loaded yet -> loaded False, no fingerprint, drift False (nothing to drift from).
    r = await client.get("/config/provenance")
    assert r.status_code == 200, r.text
    assert r.json() == {
        "loaded": False,
        "fingerprint": None,
        "git_head": None,
        "files": None,
        "drift": False,
    }


async def test_provenance_clean_after_load(client: httpx.AsyncClient, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    assert (await client.post("/config/reload", json={"config_dir": str(cfg)})).status_code == 200
    body = (await client.get("/config/provenance")).json()
    assert body["loaded"] is True
    assert body["fingerprint"] == config_fingerprint(cfg)  # reports what actually loaded
    assert body["files"] >= 1
    assert body["drift"] is False  # the running graph matches the config on disk


async def test_provenance_detects_on_disk_drift(client: httpx.AsyncClient, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    assert (await client.post("/config/reload", json={"config_dir": str(cfg)})).status_code == 200
    loaded_fp = config_fingerprint(cfg)
    # Edit a loaded file WITHOUT reloading — the running graph no longer matches disk.
    with (cfg / "cfg.py").open("a", encoding="utf-8") as fh:
        fh.write("# an out-of-band edit that has not been reloaded\n")
    assert config_fingerprint(cfg) != loaded_fp
    body = (await client.get("/config/provenance")).json()
    assert body["loaded"] is True
    assert body["fingerprint"] == loaded_fp  # still reports what is RUNNING, not the edited disk
    assert body["drift"] is True


async def test_provenance_rebaselines_on_reload(client: httpx.AsyncClient, tmp_path: Path) -> None:
    # A reload re-captures the baseline: after an edit, drift clears and the fingerprint advances.
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    assert (await client.post("/config/reload", json={"config_dir": str(cfg)})).status_code == 200
    with (cfg / "cfg.py").open("a", encoding="utf-8") as fh:
        fh.write("# edit then reload\n")
    assert (await client.post("/config/reload", json={"config_dir": str(cfg)})).status_code == 200
    body = (await client.get("/config/provenance")).json()
    assert body["drift"] is False
    assert body["fingerprint"] == config_fingerprint(cfg)


async def test_provenance_requires_auth(engine: Engine) -> None:
    # Gated like every read (require(MONITORING_READ)): with no auth attached and allow_no_auth unset,
    # it is fail-closed 503 "authentication is not configured" (security.py) — never served publicly.
    transport = httpx.ASGITransport(app=create_app(engine))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/config/provenance")).status_code == 503


# --- Web console: the config-page provenance badge ---------------------------


def test_config_page_badge_clean() -> None:
    html = config_page(
        ConfigProvenance(loaded=True, fingerprint="a" * 64, git_head="b" * 40, files=3, drift=False)
    )
    assert "Running config:" in html
    assert "commit bbbbbbb" in html  # 7-char abbreviated commit
    assert ">clean<" in html
    assert "status-running" in html
    assert "DRIFTED" not in html


def test_config_page_badge_drifted() -> None:
    html = config_page(
        ConfigProvenance(loaded=True, fingerprint="a" * 64, git_head="c" * 40, files=3, drift=True)
    )
    assert ">DRIFTED<" in html
    assert "status-error" in html
    assert ">clean<" not in html


def test_config_page_badge_without_git_uses_fingerprint() -> None:
    # No .git on the engine host (common) -> fall back to the content-fingerprint identity.
    html = config_page(
        ConfigProvenance(loaded=True, fingerprint="d" * 64, git_head=None, files=2, drift=False)
    )
    assert "fingerprint dddddddddddd" in html  # 12-char abbreviated fingerprint
    assert "commit" not in html


def test_config_page_no_badge_when_not_loaded() -> None:
    # Backward-compatible: no provenance (older/embedding path) renders the page unchanged.
    assert "Running config:" not in config_page(None)
    assert "Running config:" not in config_page(ConfigProvenance(loaded=False))
    assert "Reload configuration" in config_page(None)  # the page still renders its action
