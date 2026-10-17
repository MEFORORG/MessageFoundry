# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the config content fingerprint (ADR 0041 D1).

Verifies the fingerprint is stable, location-independent, and changes when *any* loaded file
changes — including a ``_``-prefixed helper (the loader skips it as a top-level module but still
executes it, so it must be in the fingerprint) and the data-authored ``connections.toml`` /
``environments`` / ``codesets`` files.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.fingerprint import (
    UNREADABLE_FILES_KEY,
    ConfigDirMissing,
    config_fingerprint,
    config_fingerprint_detail,
    digest_coverage,
)

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
    # vault BACKLOG #2597: the scheme tag decides whether two digests are comparable at all.
    assert detail["scheme"] == "mefor-cfg-fp:v2"
    # tmp_path is outside any git work tree, so provenance is omitted (not None, absent).
    assert "git_head" not in detail


# --- vault BACKLOG #2596: the strict digest a dual-control approval binds fails closed ----------


def _unreadable(
    monkeypatch: pytest.MonkeyPatch, name: str, *, when: dict[str, bool] | None = None
) -> None:
    """Make ``read_bytes`` of every file called ``name`` fail as an access-denied read does, always,
    or while ``when["on"]``. A real access list cannot be set portably, and a Windows administrator
    reads through one anyway. tests/test_dual_control_reload.py uses it too."""
    real = Path.read_bytes

    def _read(self: Path) -> bytes:
        if (when is None or when["on"]) and self.name == name:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", _read)


@pytest.mark.parametrize("name", ["cfg.py", "dev.toml"])
def test_strict_refuses_a_file_it_cannot_read_where_the_default_skips_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    readable = config_fingerprint(d, strict=True)
    _unreadable(monkeypatch, name)
    with pytest.raises(PermissionError):
        config_fingerprint(d, strict=True)
    # The control, and the observational rule every other caller keeps: the rest is digested.
    assert config_fingerprint(d) != readable
    assert config_fingerprint_detail(d)["files"] == 4


def test_strict_refuses_a_missing_directory_where_the_default_digests_an_empty_bundle(
    tmp_path: Path,
) -> None:
    gone, empty, a_file = tmp_path / "gone", tmp_path / "empty", tmp_path / "a-file"
    empty.mkdir()
    a_file.write_text("x", encoding="utf-8")
    for not_a_dir in (gone, a_file):
        with pytest.raises(FileNotFoundError):
            config_fingerprint(not_a_dir, strict=True)
    # The control: an empty directory is a directory, and the default digests a missing one as it.
    assert config_fingerprint(empty, strict=True) == config_fingerprint(gone)


#: Directory names no directory can have. A 300-character component is past every filesystem's
#: name limit, so Linux answers ENAMETOOLONG and Windows ERROR_INVALID_NAME. Windows also refuses a
#: ``?``, the name the PR 2239 review probed; elsewhere that is an ordinary missing name.
INVALID_DIR_NAMES = [
    pytest.param("a" * 300, id="too-long"),
    pytest.param(
        "sub?",
        id="question-mark",
        marks=pytest.mark.skipif(os.name != "nt", reason="only Windows refuses a ? in a name"),
    ),
]


@pytest.mark.parametrize("name", INVALID_DIR_NAMES)
def test_strict_refuses_a_name_no_directory_can_have_as_missing(tmp_path: Path, name: str) -> None:
    """The OS refuses the name with an error that is not ENOENT, so a strict digest raised that
    error, and a gated reload of the name answered ``digest_unavailable`` or ``unreadable``. No
    directory can have the name, so it is missing (vault BACKLOG #2596)."""
    with pytest.raises(ConfigDirMissing):
        config_fingerprint(tmp_path / name, strict=True)


def test_strict_refuses_a_folder_it_cannot_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``glob`` swallows a listing error, so an unlistable ``codesets`` folder would leave its
    tables out of the digest. A missing one is fine: nothing in it is left out."""
    d = tmp_path / "cfg"
    _bundle(d)
    readable = config_fingerprint(d, strict=True)
    real_scandir = os.scandir

    def _scandir(path: Any) -> Any:
        if Path(path).name == "codesets":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    with pytest.raises(PermissionError):
        config_fingerprint(d, strict=True)
    monkeypatch.undo()
    shutil.rmtree(d / "codesets")
    assert config_fingerprint(d, strict=True) != readable  # the control: absent, not refused


# --- vault BACKLOG #2944: the observational digest says when it left something out --------------


@pytest.mark.parametrize("name", ["cfg.py", "dev.toml"])
def test_the_detail_marks_a_digest_that_left_out_a_file_it_could_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """An antivirus lock at one start and not the next gave two digests for the same bytes, and
    nothing in the detail said the first covered only part of the bundle."""
    d = tmp_path / "cfg"
    _bundle(d)
    assert UNREADABLE_FILES_KEY not in config_fingerprint_detail(d), "control: a whole bundle"
    _unreadable(monkeypatch, name)
    detail = config_fingerprint_detail(d)
    rel = "cfg.py" if name == "cfg.py" else "environments/dev.toml"
    assert detail[UNREADABLE_FILES_KEY] == [rel]
    # Still best-effort: the rest is digested, as config_fingerprint's default does.
    assert detail["files"] == 4 and detail["fingerprint"] == config_fingerprint(d)


def test_the_detail_marks_a_digest_whose_folder_could_not_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = tmp_path / "cfg"
    _bundle(d)
    real_scandir = os.scandir

    def _scandir(path: Any) -> Any:
        if Path(path).name == "codesets":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    assert config_fingerprint_detail(d)[UNREADABLE_FILES_KEY] == ["codesets"]
    monkeypatch.undo()
    shutil.rmtree(d / "codesets")
    # The control: a folder that is absent left nothing out.
    assert UNREADABLE_FILES_KEY not in config_fingerprint_detail(d)


def test_the_detail_of_a_missing_directory_is_an_empty_bundle_and_not_partial(
    tmp_path: Path,
) -> None:
    detail = config_fingerprint_detail(tmp_path / "gone")
    assert detail["files"] == 0 and UNREADABLE_FILES_KEY not in detail


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ({"fingerprint": "f"}, ("f", ())),
        ({"fingerprint": "f", UNREADABLE_FILES_KEY: ["a.py", "b.py"]}, ("f", ("a.py", "b.py"))),
        ({"fingerprint": "f", UNREADABLE_FILES_KEY: 1}, ("f", ("?",))),
        ({"fingerprint": ""}, None),
        ({}, None),
        (None, None),
    ],
    ids=["whole", "partial", "not-a-list", "empty", "no-fingerprint", "none"],
)
def test_digest_coverage(detail: dict[str, object] | None, expected: object) -> None:
    assert digest_coverage(detail) == expected
