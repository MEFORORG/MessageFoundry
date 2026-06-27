# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the config content fingerprint (ADR 0041 D1).

Verifies the fingerprint is stable, location-independent, and changes when *any* loaded file
changes — including a ``_``-prefixed helper (the loader skips it as a top-level module but still
executes it, so it must be in the fingerprint) and the data-authored ``connections.toml`` /
``environments`` / ``codesets`` files.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.fingerprint import config_fingerprint, config_fingerprint_detail

_HEXDIGITS = set("0123456789abcdef")


def _bundle(d: Path) -> None:
    """Write a representative config bundle: a module, a helper, and each data-authored artifact."""
    (d / "codesets").mkdir(parents=True, exist_ok=True)
    (d / "environments").mkdir(parents=True, exist_ok=True)
    (d / "cfg.py").write_text("inbound = 1\n", encoding="utf-8")
    (d / "_helper.py").write_text("HELPER = 1\n", encoding="utf-8")
    (d / "connections.toml").write_text("[x]\n", encoding="utf-8")
    (d / "codesets" / "diet.csv").write_text("key,value\na,b\n", encoding="utf-8")
    (d / "environments" / "dev.toml").write_text("host = 'x'\n", encoding="utf-8")


def test_fingerprint_is_stable(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    assert config_fingerprint(d) == config_fingerprint(d)


def test_fingerprint_is_64_hex(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    fp = config_fingerprint(d)
    assert len(fp) == 64
    assert set(fp) <= _HEXDIGITS


def test_fingerprint_is_path_relative_not_absolute(tmp_path: Path) -> None:
    # Two byte-identical bundles at different absolute paths must fingerprint identically — the
    # digest keys on each file's relative path + content, never its absolute location.
    a = tmp_path / "a" / "cfg"
    b = tmp_path / "b" / "cfg"
    _bundle(a)
    _bundle(b)
    assert config_fingerprint(a) == config_fingerprint(b)


def test_fingerprint_changes_on_module_edit(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "cfg.py").write_text("inbound = 2\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_helper_edit(tmp_path: Path) -> None:
    # The insider point: a '_'-prefixed helper is skipped as a top-level module by the loader but is
    # still executed code (a sibling imports it), so editing it MUST change the fingerprint.
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "_helper.py").write_text("HELPER = 999\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_connections_toml_edit(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "connections.toml").write_text("[y]\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_environment_edit(tmp_path: Path) -> None:
    # A redirect via environments/<env>.toml changes effective behaviour with no code edit — it must
    # move the fingerprint, or an env-value redirect would slip past the audit unchanged.
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "environments" / "dev.toml").write_text("host = 'evil'\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_codeset_edit(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "codesets" / "diet.csv").write_text("key,value\na,zzz\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_changes_on_new_file(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "extra.py").write_text("x = 1\n", encoding="utf-8")
    assert config_fingerprint(d) != before


def test_fingerprint_ignores_unrelated_files(tmp_path: Path) -> None:
    # A README or a .pyc next to the config is not loaded code — it must not move the fingerprint.
    d = tmp_path / "cfg"
    _bundle(d)
    before = config_fingerprint(d)
    (d / "README.md").write_text("notes\n", encoding="utf-8")
    (d / "cfg.pyc").write_text("compiled\n", encoding="utf-8")
    assert config_fingerprint(d) == before


def test_detail_has_fingerprint_and_file_count(tmp_path: Path) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    detail = config_fingerprint_detail(d)
    assert detail["fingerprint"] == config_fingerprint(d)
    assert detail["files"] == 5
    # tmp_path is outside any git work tree, so provenance is omitted (not None, absent).
    assert "git_head" not in detail
