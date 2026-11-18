# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5446: in ``--path`` mode the location detector judges where a file really is.

``--path`` keys each file by its path relative to the root the caller NAMED, and the location
detector (``docs/security/``, the vault-only security corpus) used to judge only that relative key.
So naming the directory itself, a file inside it, or its parent (``docs``) dropped the
``docs/security/`` prefix from the key, and the run exited 0 over a private security document. The
detector now also judges ``_location``: the file's real path, relative to the work tree holding it.

The other half of the row, a nonexistent path named beside a real one exiting 0, was fixed under
BACKLOG #5585 (the ``_NO_ROOT`` refusal); the last test pins it.

Every file written here holds benign synthetic text, so only the location rule can fire.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

_SCANNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_REASON = "private security document"


@pytest.fixture
def mod(monkeypatch: pytest.MonkeyPatch):
    """The scanner, with ``main``'s token reload and the inherited require/floor variables
    neutralised, as ``tests/test_scan_forbidden.py``'s ``sf_main`` does: either would make ``main``
    return 2 before it scans, for a reason unrelated to the location rule."""
    spec = importlib.util.spec_from_file_location("scan_forbidden_5446", _SCANNER_PATH)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "reload_tokens", lambda: None)
    monkeypatch.delenv("MEFOR_REQUIRE_TOKENS", raising=False)
    monkeypatch.delenv("MEFOR_MIN_DETECTORS", raising=False)
    return m


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "snap"
    (root / "docs" / "security").mkdir(parents=True)
    (root / "docs" / "other").mkdir(parents=True)
    (root / "docs" / "security" / "notes.md").write_text("plain prose\n", encoding="utf-8")
    (root / "docs" / "other" / "readme.md").write_text("plain prose\n", encoding="utf-8")
    return root


def _run(mod, capsys: pytest.CaptureFixture[str], *paths: str) -> tuple[int, str]:
    code = mod.main(["--path", *paths])
    out = capsys.readouterr()
    return code, out.out + out.err


@pytest.mark.parametrize(
    "named",
    [
        pytest.param(("docs", "security"), id="the-directory-itself"),
        pytest.param(("docs", "security", "notes.md"), id="a-file-inside-it"),
        pytest.param(("docs",), id="its-parent"),
    ],
)
def test_a_named_path_under_docs_security_is_a_location_hit(
    mod, tree: Path, capsys: pytest.CaptureFixture[str], named: tuple[str, ...]
) -> None:
    code, out = _run(mod, capsys, str(tree.joinpath(*named)))
    assert code == 1, out
    assert _REASON in out


def test_a_cwd_relative_root_is_judged_where_it_sits(
    mod, tree: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--path security`` run from inside ``docs`` carries no ``docs/`` in what the caller wrote."""
    monkeypatch.chdir(tree / "docs")
    code, out = _run(mod, capsys, "security")
    assert code == 1, out
    assert _REASON in out


def test_a_root_named_in_another_case_is_judged_in_its_disk_case(
    mod, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """On a case-insensitive filesystem ``DOCS/SECURITY`` opens the same directory."""
    other = tree / "DOCS" / "SECURITY"
    if not other.is_dir():
        pytest.skip("case-sensitive filesystem: the other spelling names no directory")
    code, out = _run(mod, capsys, str(other))
    assert code == 1, out
    assert _REASON in out


def test_a_link_into_docs_security_is_judged_where_it_lands(
    mod, tree: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    link = tmp_path / "elsewhere"
    try:
        os.symlink(tree / "docs" / "security", link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a directory link here ({type(exc).__name__})")
    for named in (link, link / "notes.md"):
        code, out = _run(mod, capsys, str(named))
        assert code == 1, (named, out)
        assert _REASON in out


def test_control_a_sibling_directory_stays_clean(
    mod, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control: the same content one directory over is not a hit, so the rule above is location."""
    code, out = _run(mod, capsys, str(tree / "docs" / "other"))
    assert code == 0, out
    assert _REASON not in out


def test_control_a_parent_dot_dot_out_of_docs_security_is_not_a_hit(
    mod, tree: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: a root reached through ``..`` from inside ``docs/security`` is judged where it lands,
    not by the working directory it was named from."""
    monkeypatch.chdir(tree / "docs" / "security")
    code, out = _run(mod, capsys, str(Path("..") / "other"))
    assert code == 0, out
    assert _REASON not in out


def test_control_a_work_tree_under_a_docs_security_directory_is_not_a_hit(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control: the location is relative to the work tree, so a clone that itself sits under some
    ``docs/security`` directory is not a hit on every file it holds."""
    clone = tmp_path / "docs" / "security" / "clone"
    (clone / "src").mkdir(parents=True)
    (clone / ".git").write_text("gitdir: nowhere\n", encoding="utf-8")
    (clone / "src" / "app.py").write_text("plain prose\n", encoding="utf-8")
    code, out = _run(mod, capsys, str(clone))
    assert code == 0, out
    assert _REASON not in out


def test_a_missing_path_beside_a_real_one_refuses(
    mod, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The row's second half, already fixed under BACKLOG #5585: pinned here, not rebuilt."""
    code, out = _run(mod, capsys, str(tree / "docs" / "other"), str(tree / "missing"))
    assert code == 2, out
    assert "does not exist" in out
