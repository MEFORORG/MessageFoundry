# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``Engine.last_reload_dir`` moves only when a reload is applied (vault BACKLOG #2598).

Two readers trust that field to name the directory the running graph came from: the drift check
behind ``GET /config/provenance``, and ``Engine.set_connection_flag``, which writes
``connections.toml`` there. A dry run applies nothing and a failed reload applies nothing, so
neither may move it. Each refusal below sits beside a control that does move it, so an unchanged
field is a reading of the rule and never of a reload that did not run.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.engine import ConfigReloadDenied


def _write_valid_config(cfg: Path, inbox: Path, outdir: Path) -> None:
    for d in (cfg, inbox, outdir):
        d.mkdir(parents=True, exist_ok=True)
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


async def _engine(tmp_path: Path) -> tuple[Engine, Path, Path]:
    live = tmp_path / "live"
    staging = tmp_path / "staging"
    _write_valid_config(live, tmp_path / "in", tmp_path / "out")
    _write_valid_config(staging, tmp_path / "in2", tmp_path / "out2")
    eng = await Engine.create(
        tmp_path / "r.db", poll_interval=0.05, config_dir=live, config_reload_roots=[str(staging)]
    )
    return eng, live, staging


async def test_a_failed_dry_run_on_a_missing_dir_leaves_the_field(tmp_path: Path) -> None:
    eng, _live, staging = await _engine(tmp_path)
    try:
        with pytest.raises(FileNotFoundError):
            await eng.reload_detail(str(staging / "absent"), dry_run=True)
        assert eng.last_reload_dir is None
        # Control: an applied reload of the same root does move it.
        await eng.reload_detail(str(staging))
        assert eng.last_reload_dir == staging.resolve()
    finally:
        await eng.stop()


async def test_a_successful_dry_run_leaves_the_field(tmp_path: Path) -> None:
    eng, live, staging = await _engine(tmp_path)
    try:
        await eng.reload_detail(str(live))
        assert eng.last_reload_dir == live.resolve(), "control: the applied reload moved it"
        outcome = await eng.reload_detail(str(staging), dry_run=True)
        assert outcome.applied is False
        assert eng.last_reload_dir == live.resolve()
    finally:
        await eng.stop()


async def test_a_failed_real_reload_leaves_the_field(tmp_path: Path) -> None:
    eng, live, staging = await _engine(tmp_path)
    try:
        await eng.reload_detail(str(live))
        (staging / "cfg.py").write_text("this is not python\n", encoding="utf-8")
        with pytest.raises(WiringError):
            await eng.reload_detail(str(staging))
        assert eng.last_reload_dir == live.resolve()
    finally:
        await eng.stop()


async def test_a_refused_path_leaves_the_field(tmp_path: Path) -> None:
    """The control the review ran: a path outside every root never moved the field."""
    eng, _live, _staging = await _engine(tmp_path)
    outside = tmp_path / "outside"
    _write_valid_config(outside, tmp_path / "in3", tmp_path / "out3")
    try:
        with pytest.raises(ConfigReloadDenied):
            await eng.reload_detail(str(outside), dry_run=True)
        assert eng.last_reload_dir is None
    finally:
        await eng.stop()


async def test_the_dry_run_row_still_names_the_directory_it_checked(tmp_path: Path) -> None:
    """The ``config_reload_check`` row read the field to name its directory. With the field held
    still, the row must take the checked directory from the outcome instead."""
    eng, live, staging = await _engine(tmp_path)
    try:
        await eng.reload_detail(str(live))
        transport = httpx.ASGITransport(app=create_app(eng, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post("/config/reload", json={"config_dir": str(staging), "dry_run": True})
            assert r.status_code == 200, r.text
        rows = await eng.store.list_audit(action="config_reload_check")
        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"])
        assert detail["dir"] == str(staging.resolve())
        assert "fingerprint" in detail
        assert eng.last_reload_dir == live.resolve()
    finally:
        await eng.stop()
