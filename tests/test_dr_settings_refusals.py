# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[dr]`` misconfigurations refused at load rather than found during a disaster (BACKLOG #5965).

``[dr].activate = true`` without ``[dr].enabled`` was ignored, so it is refused. With ``enabled`` it
loads, as the startup latch it has always been. Item 1 (S09-42): a DR box that names no seed, a
blank or padded seed or token path, and a restore token on a SQLite store where nothing reads it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import DrSettings, load_settings

_SEED = {"seed_archive": "C:/dr/seed.mfbak"}


def test_activate_without_enabled_is_refused() -> None:
    """The engine never read it there, so a box meant to come up active came up as a plain engine."""
    with pytest.raises(ValidationError, match=r"\[dr\]\.activate = true needs \[dr\]\.enabled"):
        DrSettings.model_validate({"activate": True, **_SEED})


@pytest.mark.parametrize("activate", [True, False])
def test_an_enabled_box_loads_either_way(activate: bool) -> None:
    """The control: with enabled, activate = true loads, as the startup latch."""
    dr = DrSettings.model_validate({"enabled": True, "activate": activate, **_SEED})
    assert dr.enabled and dr.activate is activate


def test_activate_true_without_enabled_from_a_file_is_refused(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[dr]\nactivate = true\n", encoding="utf-8")
    with pytest.raises(ValidationError, match=r"\[dr\]\.activate = true needs \[dr\]\.enabled"):
        load_settings(config_path=cfg, environ={})


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
