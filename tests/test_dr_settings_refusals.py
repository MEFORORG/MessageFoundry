# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[dr]`` misconfigurations refused at load rather than found during a disaster (BACKLOG #5965).

A boot-time ``[dr].activate = true`` skipped what ``POST /dr/activate`` runs (the cold-seed verify,
the takeover hook and the ``dr.activate`` audit row), and without ``[dr].enabled`` it was ignored.
Item 1 (S09-42): a DR box that names no seed, a blank seed or token path, and a restore token on a
SQLite store where nothing reads it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import DrSettings, load_settings

_SEED = {"seed_archive": "C:/dr/seed.mfbak"}


@pytest.mark.parametrize("enabled", [True, False])
def test_activate_true_is_refused_with_or_without_enabled(enabled: bool) -> None:
    with pytest.raises(ValidationError, match=r"POST /dr/activate") as info:
        DrSettings.model_validate({"enabled": enabled, "activate": True, **_SEED})
    assert "[dr].activate" in str(info.value)


def test_activate_false_still_loads() -> None:
    """The control: the passive box the endpoint promotes."""
    dr = DrSettings.model_validate({"enabled": True, "activate": False, **_SEED})
    assert dr.enabled and not dr.activate


def test_activate_true_from_a_file_is_refused(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        "[dr]\nenabled = true\nactivate = true\nseed_archive = 'C:/dr/seed.mfbak'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match=r"\[dr\]\.activate = true is not supported"):
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


@pytest.mark.parametrize("field", ["seed_archive", "restore_token"])
@pytest.mark.parametrize("blank", [" ", "\t", "  \n"])
def test_a_blank_path_is_refused(field: str, blank: str) -> None:
    """A blank is truthy, so activation would try to open it and abort every time."""
    with pytest.raises(ValidationError, match=rf"\[dr\]\.{field} must be a non-blank path"):
        DrSettings.model_validate({field: blank})


@pytest.mark.parametrize("field", ["seed_archive", "restore_token"])
def test_a_padded_path_is_refused(field: str) -> None:
    """Activation would open the padded path as written and abort."""
    with pytest.raises(ValidationError, match=rf"\[dr\]\.{field} must not begin or end"):
        DrSettings.model_validate({field: " C:/dr/seed.mfbak "})


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
