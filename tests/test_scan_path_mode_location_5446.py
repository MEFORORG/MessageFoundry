# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5446: in ``--path`` mode the location detector judges where a file really is.

``--path`` keys each file by its path relative to the root the caller NAMED, and the location
detector (``docs/security/``, the vault-only security corpus) used to judge only that relative key.
So naming the directory itself, a file inside it, or its parent (``docs``) dropped the
``docs/security/`` prefix from the key, and the run exited 0 over a private security document. The
detector now also judges ``_locations``: the file's path as named and its real path, each whole and
absolute, and a file is a hit if either falls under docs/security.

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


def test_a_link_inside_a_walked_root_is_judged_where_it_lands(
    mod, tree: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file link inside the named root, pointing into docs/security, is a location hit."""
    snap = tmp_path / "elsewhere"
    snap.mkdir()
    (snap / "plain.md").write_text("plain prose\n", encoding="utf-8")
    try:
        os.symlink(tree / "docs" / "security" / "notes.md", snap / "notes.md")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a file link here ({type(exc).__name__})")
    code, out = _run(mod, capsys, str(snap))
    assert code == 1, out
    assert _REASON in out


def test_a_nested_work_tree_under_docs_security_keeps_the_prefix(
    mod, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A ``.git`` under docs/security (a nested clone) must not strip the prefix the rule keys on."""
    (tree / ".git").write_text("gitdir: nowhere\n", encoding="utf-8")
    (tree / "docs" / "security" / ".git").write_text("gitdir: nowhere\n", encoding="utf-8")
    code, out = _run(mod, capsys, str(tree / "docs" / "security"))
    assert code == 1, out
    assert _REASON in out


def test_a_case_variant_tracked_path_is_a_hit_in_every_mode(mod) -> None:
    """The staged and tracked scans fold case as --path does, so the gates agree."""
    hits, stop = mod._name_hits(Path("Docs/Security/x.md"), "Docs/Security/x.md")
    assert stop and _REASON in hits[0]


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


def test_a_work_tree_under_a_docs_security_directory_fails_closed(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A ``.git`` at or below a docs/security directory is no work-tree boundary, so a clone that
    itself sits under one is a hit on every file it holds. This was a control that read clean; it
    is indistinguishable from a planted ``.git`` below docs/security, so it now fails closed."""
    clone = tmp_path / "docs" / "security" / "clone"
    (clone / "src").mkdir(parents=True)
    (clone / ".git").write_text("gitdir: nowhere\n", encoding="utf-8")
    (clone / "src" / "app.py").write_text("plain prose\n", encoding="utf-8")
    code, out = _run(mod, capsys, str(clone))
    assert code == 1, out
    assert _REASON in out


@pytest.mark.parametrize(
    ("planted", "held"),
    [
        pytest.param(("docs",), ("docs", "security"), id="at-docs"),
        pytest.param(("docs", "security"), ("docs", "security"), id="at-docs-security"),
        pytest.param(("docs", "security", "sub"), ("docs", "security", "sub"), id="below"),
    ],
)
@pytest.mark.parametrize("as_dir", [False, True], ids=["git-file", "git-dir"])
def test_a_planted_git_entry_does_not_strip_the_prefix(
    mod,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    planted: tuple[str, ...],
    held: tuple[str, ...],
    as_dir: bool,
) -> None:
    """A commit snapshot written outside any work tree, carrying a ``.git`` entry at ``docs``, at
    docs/security or below it, must not make that directory the top of a work tree: it would drop
    the prefix the rule keys on, and naming the directory read clean (BACKLOG #5446)."""
    snap = tmp_path / "snap"
    where = snap.joinpath(*held)
    where.mkdir(parents=True)
    (where / "notes.md").write_text("plain prose\n", encoding="utf-8")
    git = snap.joinpath(*planted, ".git")
    if as_dir:
        git.mkdir()
    else:
        git.write_text("gitdir: nowhere\n", encoding="utf-8")
    for named in (where, where / "notes.md", snap / "docs"):
        code, out = _run(mod, capsys, str(named))
        assert code == 1, (named, out)
        assert _REASON in out


def _link(target: Path, link: Path, *, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a link here ({type(exc).__name__})")


def test_a_link_under_docs_security_pointing_out_is_judged_where_it_sits(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file link that sits under docs/security and points outside it is a hit, by the path it
    was walked or named at, though where it lands is clean (BACKLOG #5446)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "plain.md").write_text("plain prose\n", encoding="utf-8")
    sec = tmp_path / "snap" / "docs" / "security"
    sec.mkdir(parents=True)
    _link(outside / "plain.md", sec / "notes.md")
    for named in (sec, sec / "notes.md", sec.parent):
        code, out = _run(mod, capsys, str(named))
        assert code == 1, (named, out)
        assert _REASON in out


def test_a_docs_security_that_is_itself_a_link_out_is_judged_where_it_sits(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Naming a docs/security directory that is a link to a clean directory elsewhere."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "plain.md").write_text("plain prose\n", encoding="utf-8")
    docs = tmp_path / "snap" / "docs"
    docs.mkdir(parents=True)
    _link(outside, docs / "security", is_dir=True)
    for named in (docs / "security", docs / "security" / "plain.md"):
        code, out = _run(mod, capsys, str(named))
        assert code == 1, (named, out)
        assert _REASON in out


def test_control_a_link_out_of_a_clean_directory_stays_clean(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control: the same link one directory over from docs/security is not a hit, so the rule
    above is where the link sits."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "plain.md").write_text("plain prose\n", encoding="utf-8")
    other = tmp_path / "snap" / "docs" / "other"
    other.mkdir(parents=True)
    _link(outside / "plain.md", other / "notes.md")
    code, out = _run(mod, capsys, str(other))
    assert code == 0, out
    assert _REASON not in out


def test_a_missing_path_beside_a_real_one_refuses(
    mod, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The row's second half, already fixed under BACKLOG #5585: pinned here, not rebuilt."""
    code, out = _run(mod, capsys, str(tree / "docs" / "other"), str(tree / "missing"))
    assert code == 2, out
    assert "does not exist" in out


@pytest.mark.parametrize(
    "skipped",
    [
        pytest.param(("scripts", "security", "scan-tokens.local.txt"), id="skip-path"),
        pytest.param((".github", "actions", "act", "dist", "index.js"), id="vendored-bundle"),
    ],
)
def test_a_skipped_name_under_docs_security_is_still_a_location_hit(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str], skipped: tuple[str, ...]
) -> None:
    """The location rule runs before any skip rule: a file whose root-relative path matches
    SKIP_PATHS or the vendored-bundle pattern, walked from a named docs/security, used to be
    dropped by the skip and the run exited 0 over a private document (BACKLOG #5446)."""
    sec = tmp_path / "snap" / "docs" / "security"
    held = sec.joinpath(*skipped)
    held.parent.mkdir(parents=True)
    held.write_text("plain prose\n", encoding="utf-8")
    # A clean root named beside it, so the unfixed run exits 0 rather than refusing an empty scan.
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "readme.md").write_text("plain prose\n", encoding="utf-8")
    code, out = _run(mod, capsys, str(sec), str(clean))
    assert code == 1, out
    assert _REASON in out
    assert held.name in out, out


@pytest.mark.parametrize(
    "skipped",
    [
        pytest.param(("scripts", "security", "scan-tokens.local.txt"), id="skip-path"),
        pytest.param((".github", "actions", "act", "dist", "index.js"), id="vendored-bundle"),
    ],
)
def test_control_a_skipped_name_elsewhere_is_still_skipped(
    mod, tmp_path: Path, capsys: pytest.CaptureFixture[str], skipped: tuple[str, ...]
) -> None:
    """Control: the same file one directory over from docs/security is still skipped, so the hit
    above is the location rule and the skip rules are unchanged elsewhere."""
    other = tmp_path / "snap" / "docs" / "other"
    held = other.joinpath(*skipped)
    held.parent.mkdir(parents=True)
    # Content that would be a hit if it were read, so a skip is told from a clean read.
    held.write_text("connect(" + repr(".".join(("8", "8", "4", "4"))) + ")\n", encoding="utf-8")
    (tmp_path / "snap" / "readme.md").write_text("plain prose\n", encoding="utf-8")
    code, out = _run(mod, capsys, str(other), str(tmp_path / "snap" / "readme.md"))
    assert code == 0, out
    assert _REASON not in out
