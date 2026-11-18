# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5446: in ``--path`` mode the location detector judges where a file really is.

``--path`` keys each file by its path relative to the root the caller NAMED, and the location
detector (``docs/security/``, the vault-only security corpus) used to judge only that relative key.
So naming the directory itself, a file inside it, or its parent (``docs``) dropped the
``docs/security/`` prefix from the key, and the run exited 0 over a private security document. The
detector now also judges the file's absolute path, the named root joined to the key.

The other half of the row, a nonexistent path named beside a real one exiting 0, was fixed under
BACKLOG #5585 (the ``_NO_ROOT`` refusal); the last test pins it.

Every file written here holds benign synthetic text, so only the location rule can fire.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCANNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_REASON = "private security document"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scan_forbidden_5446", _SCANNER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
    tree: Path, capsys: pytest.CaptureFixture[str], named: tuple[str, ...]
) -> None:
    mod = _load_scanner()
    code, out = _run(mod, capsys, str(tree.joinpath(*named)))
    assert code == 1, out
    assert _REASON in out


def test_a_cwd_relative_root_is_judged_where_it_sits(
    tree: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--path security`` run from inside ``docs`` carries no ``docs/`` in what the caller wrote."""
    mod = _load_scanner()
    monkeypatch.chdir(tree / "docs")
    code, out = _run(mod, capsys, "security")
    assert code == 1, out
    assert _REASON in out


def test_control_a_sibling_directory_stays_clean(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control: the same content one directory over is not a hit, so the rule above is location."""
    mod = _load_scanner()
    code, out = _run(mod, capsys, str(tree / "docs" / "other"))
    assert code == 0, out
    assert _REASON not in out


def test_a_parent_dot_dot_out_of_docs_security_is_not_a_hit(
    tree: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: the absolute form is normalised, so a root reached through ``..`` from inside
    ``docs/security`` is judged where it lands, not by the working directory it was named from."""
    mod = _load_scanner()
    monkeypatch.chdir(tree / "docs" / "security")
    code, out = _run(mod, capsys, str(Path("..") / "other"))
    assert code == 0, out
    assert _REASON not in out


def test_a_missing_path_beside_a_real_one_refuses(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The row's second half, already fixed under BACKLOG #5585: pinned here, not rebuilt."""
    mod = _load_scanner()
    code, out = _run(mod, capsys, str(tree / "docs" / "other"), str(tree / "missing"))
    assert code == 2, out
    assert "does not exist" in out
