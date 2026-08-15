# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0114 flag architecture (§6): three Phase-4 claim-path sub-lever flags on ``[store]``.

All three are DEFAULT OFF (reliability-core), read once at store open, and SQL-Server-only by
construction. This file freezes the flag architecture itself:

- defaults are OFF and env-settable via ``MEFOR_STORE_FIFO_CLAIM_*`` (the settings contract);
- AC-6 sentinel (the ADR 0075 scoping precedent): the SQLite and Postgres backends NEVER reference
  the flags, so on those backends they are provable no-ops. The positive control (SqlServerStore
  actually reading each flag) lives with each sub-lever's own test file, so this sentinel stays
  green at every intermediate build layer.

Per-sub-lever behavior tests: ``test_adr0114_claim_fold.py`` (C), ``test_adr0114_claim_proc.py``
(A), ``test_adr0114_claim_prepared.py`` (B).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.settings import StoreSettings, load_settings

_FLAGS = ("fifo_claim_fold_reset", "fifo_claim_proc", "fifo_claim_prepared")

_REPO = Path(__file__).resolve().parents[1]


def test_flags_exist_and_default_off() -> None:
    s = StoreSettings()
    for flag in _FLAGS:
        assert getattr(s, flag) is False, f"{flag} must default OFF (ADR 0114 §6)"


def test_flags_env_coercion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The documented env spellings (ADR 0114 "to resolve on acceptance"): MEFOR_STORE_FIFO_CLAIM_*.
    monkeypatch.chdir(tmp_path)
    s = load_settings(
        environ={
            "MEFOR_STORE_FIFO_CLAIM_FOLD_RESET": "true",
            "MEFOR_STORE_FIFO_CLAIM_PROC": "true",
            "MEFOR_STORE_FIFO_CLAIM_PREPARED": "true",
        }
    )
    assert s.store.fifo_claim_fold_reset is True
    assert s.store.fifo_claim_proc is True
    assert s.store.fifo_claim_prepared is True
    # And "false" coerces back off (the str -> bool precedent of test_sqlserver_env_coercion).
    s = load_settings(environ={"MEFOR_STORE_FIFO_CLAIM_FOLD_RESET": "false"})
    assert s.store.fifo_claim_fold_reset is False


def test_flags_have_descriptions() -> None:
    # The Field descriptions are the operator-facing contract line (the fifo_claim_batch pattern).
    for flag in _FLAGS:
        field = StoreSettings.model_fields[flag]
        assert field.description, f"{flag} needs a description"
        assert "SQL Server only" in field.description


def test_ac6_sentinel_non_sqlserver_backends_never_reference_the_flags() -> None:
    """AC-6: the flags SHALL be provable no-ops on SQLite and Postgres — neither backend's source
    references any of them (the ADR 0075 backend-gate precedent, applied to settings flags: a
    backend that never reads a flag cannot change behavior under it)."""
    for module in ("store.py", "postgres.py", "base.py"):
        source = (_REPO / "messagefoundry" / "store" / module).read_text(encoding="utf-8")
        for flag in _FLAGS:
            assert flag not in source, (
                f"messagefoundry/store/{module} references {flag} — ADR 0114 scopes the Phase-4"
                " claim-path sub-levers to SqlServerStore ONLY (AC-6)"
            )


def test_flags_documented_in_configuration_md() -> None:
    doc = (_REPO / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    for flag in _FLAGS:
        assert f"`{flag}`" in doc, f"docs/CONFIGURATION.md must document {flag}"
