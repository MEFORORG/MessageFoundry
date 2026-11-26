# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[dr]`` misconfigurations refused at load rather than found during a disaster (BACKLOG #5965).

``[dr].activate`` was a startup latch: with ``enabled`` it brought a box up under the DR
run-profile at engine construction, without the seed verification, the takeover hook or the
``dr.activate`` audit row ``POST /dr/activate`` runs. By owner ruling of 2026-11-25 it is a
removed key, refused at load whatever its value, and no engine construction path activates DR.
Item 1 (S09-42): a DR box that names no seed, a blank or padded seed or token path, and a restore
token on a SQLite store where nothing reads it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    DrSettings,
    EgressSettings,
    StoreSettings,
    load_settings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore

_SEED = {"seed_archive": "C:/dr/seed.mfbak"}
_REMOVED = r"\[dr\]\.activate was REMOVED"


def test_enabled_and_activate_in_code_are_refused() -> None:
    """Red on main, where this combination loaded as the startup latch. Every removed key's
    refusal is pinned for the whole table in ``tests/test_open_mode_is_no_service.py``; this is
    the owner-ruled case, and it names the route."""
    with pytest.raises(ValidationError, match=_REMOVED) as caught:
        DrSettings.model_validate({"enabled": True, "activate": True, **_SEED})
    assert "POST /dr/activate" in str(caught.value)


def test_enabled_and_activate_from_a_file_are_refused(tmp_path: Path) -> None:
    """The owner-ruled case through the loader, which names the route and echoes no value."""
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        "[dr]\nenabled = true\nactivate = true\nseed_archive = 'C:/dr/seed.mfbak'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=_REMOVED) as caught:
        load_settings(config_path=cfg, environ={})
    assert "POST /dr/activate" in str(caught.value)
    assert "true" not in str(caught.value)


def test_an_enabled_box_loads_passive() -> None:
    """The control: without the removed key an enabled box loads."""
    dr = DrSettings.model_validate({"enabled": True, **_SEED})
    assert dr.enabled and "activate" not in DrSettings.model_fields


async def test_no_engine_construction_path_activates_dr(tmp_path: Path) -> None:
    """Red on main: settings that skip validation and still carry ``activate = true`` brought the
    engine and the coordinator up under the DR run-profile. Every DR box now starts passive."""
    db = tmp_path / "e.db"
    smuggled = DrSettings.model_construct(
        enabled=True, activate=True, seed_archive=_SEED["seed_archive"]
    )
    engine = Engine(
        await MessageStore.open(db),
        poll_interval=0.05,
        store_settings=StoreSettings(path=str(db)),
        dr_settings=smuggled,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        assert engine.dr_active is False
        assert engine._dr_run_threshold() is None
        assert engine._dr_standby_threshold() is not None  # passive: binds no listener
        assert engine._dr_backup_paused() is True
        coord = engine.dr_coordinator
        assert coord is not None and coord.active is False
    finally:
        await engine.stop()


def test_an_enabled_box_with_no_seed_is_refused() -> None:
    """With neither key, every POST /dr/activate aborts for want of a seed."""
    with pytest.raises(ValidationError, match=r"seed_archive or \[dr\]\.seed_dir"):
        DrSettings(enabled=True)


@pytest.mark.parametrize(
    "seed", [{"seed_archive": "C:/dr/seed.mfbak"}, {"seed_dir": str(Path.cwd().resolve())}]
)
def test_an_enabled_box_with_either_seed_key_loads(seed: dict[str, str]) -> None:
    assert DrSettings.model_validate({"enabled": True, **seed}).enabled


def test_a_disabled_box_needs_no_seed() -> None:
    assert not DrSettings().enabled


@pytest.mark.parametrize("field", ["seed_archive", "seed_dir", "restore_token"])
@pytest.mark.parametrize("blank", [" ", "\t", "  \n"])
def test_a_blank_path_is_refused(field: str, blank: str) -> None:
    """A blank is truthy, so activation would try to open it and abort every time."""
    with pytest.raises(ValidationError, match=rf"\[dr\]\.{field} must be a non-blank path"):
        DrSettings.model_validate({field: blank})


@pytest.mark.parametrize("field", ["seed_archive", "seed_dir", "restore_token"])
def test_a_padded_path_is_refused(field: str) -> None:
    """Activation would open the padded path as written and abort. ``seed_dir`` used to strip the
    padding where the other two refused it; all three refuse now."""
    value = f" {Path.cwd().resolve()} " if field == "seed_dir" else " C:/dr/seed.mfbak "
    with pytest.raises(ValidationError, match=rf"\[dr\]\.{field} must not begin or end"):
        DrSettings.model_validate({field: value})


def _toml(tmp_path: Path, store: str, dr: str) -> Path:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(f"[store]\n{store}\n[dr]\n{dr}\n", encoding="utf-8")
    return cfg


def test_a_restore_token_on_sqlite_is_refused(tmp_path: Path) -> None:
    """No check reads it on SQLite, so an operator expecting provenance protection got none."""
    cfg = _toml(
        tmp_path,
        "path = 'site.db'",
        "enabled = true\nseed_archive = 'C:/dr/seed.mfbak'\nrestore_token = 'C:/dr/token.json'",
    )
    with pytest.raises(ValidationError, match=r"restore_token applies only to a Postgres"):
        load_settings(config_path=cfg, environ={})


def test_a_restore_token_on_a_server_db_loads(tmp_path: Path) -> None:
    """The control: the backend the token is for."""
    cfg = _toml(
        tmp_path,
        "backend = 'postgres'\nserver = 'pg'\ndatabase = 'd'\nusername = 'u'",
        "enabled = true\nseed_archive = 'C:/dr/seed.mfbak'\nrestore_token = 'C:/dr/token.json'",
    )
    assert load_settings(config_path=cfg, environ={}).dr.restore_token == "C:/dr/token.json"
