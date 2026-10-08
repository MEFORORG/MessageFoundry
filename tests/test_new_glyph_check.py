# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The new-glyph hook refuses an ADDED glyph and stays silent on everything else.

Each case drives the real script as a subprocess against a throwaway git repo with a real staged
diff, the same shape as ``tests/test_claim_check.py``. A detector that cannot be shown firing is
indistinguishable from one that is not running, so every silent case sits beside a firing one.

Glyphs are written as ``\\N{...}`` escapes so this file stays ASCII: a literal glyph here would be
the thing under test, and it would raise UnicodeEncodeError on a stock cp1252 console.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_operator_docs_no_warning_sign import _DATED_RECORDS, _HELD

_ROOT = Path(__file__).resolve().parents[1]
_CHECK = _ROOT / "scripts" / "quality" / "new_glyph_check.py"

_BALLOT_X = "\N{BALLOT X}"  # U+2717, one of the measured additions on main
_NO_ENTRY = "\N{NO ENTRY}"  # U+26D4, another
_ROCKET = "\N{ROCKET}"  # U+1F680, the emoji plane
_VS16 = "\N{VARIATION SELECTOR-16}"
_ARROW = "\N{RIGHTWARDS ARROW}"  # U+2192, deliberately allowed


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, timeout=60
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "T")
    _git(r, "config", "core.autocrlf", "false")
    (r / "notes.md").write_text(f"old line with {_NO_ENTRY} already here\n", encoding="utf-8")
    _git(r, "add", "notes.md")
    _git(r, "commit", "-q", "-m", "seed")
    return r


def _write(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _git(repo, "add", rel)


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # PYTHONIOENCODING=cp1252 reproduces a stock Windows console: if the report ever prints a glyph,
    # the child dies with UnicodeEncodeError instead of passing quietly.
    env = {"PATH": os.environ["PATH"], "PYTHONIOENCODING": "cp1252"}
    for key in ("SYSTEMROOT", "HOME", "USERPROFILE", "TEMP", "TMP"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    return subprocess.run(
        [sys.executable, str(_CHECK), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="cp1252",
        errors="strict",
        env=env,
        timeout=60,
    )


@pytest.mark.parametrize(
    ("glyph", "code"),
    [(_BALLOT_X, "U+2717"), (_NO_ENTRY, "U+26D4"), (_ROCKET, "U+1F680"), (_VS16, "U+FE0F")],
)
def test_an_added_glyph_is_refused_and_named_by_codepoint(
    repo: Path, glyph: str, code: str
) -> None:
    _write(repo, "src/report.py", f'print("{glyph} failed")\n')
    proc = _run(repo)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"src/report.py:1: {code}" in proc.stderr
    assert "write the word" in proc.stderr


def test_a_clean_addition_passes_and_says_what_it_judged(repo: Path) -> None:
    """The negative control, with an arrow, which is outside every banned range on purpose."""
    _write(repo, "src/report.py", f'print("step one {_ARROW} step two")\nx = 1\n')
    proc = _run(repo)
    assert proc.returncode == 0, proc.stderr
    assert "2 added line(s) in 1 file(s), no new glyph" in proc.stdout


def test_a_glyph_already_on_the_branch_is_not_judged(repo: Path) -> None:
    """Editing a different line of a file that already carries a glyph is not adding one."""
    (repo / "notes.md").write_text(
        f"old line with {_NO_ENTRY} already here\nnew plain line\n", encoding="utf-8"
    )
    _git(repo, "add", "notes.md")
    proc = _run(repo)
    assert proc.returncode == 0, proc.stderr


def test_editing_a_line_that_already_carried_the_glyph_passes(repo: Path) -> None:
    """Section 11 says not to sweep old glyphs out of a file edited for another reason."""
    (repo / "notes.md").write_text(f"old line, reworded, with {_NO_ENTRY} kept\n", encoding="utf-8")
    _git(repo, "add", "notes.md")
    assert _run(repo).returncode == 0
    # Positive control: the same edit adding a SECOND mark is a net addition, and it fires.
    (repo / "notes.md").write_text(
        f"reworded {_NO_ENTRY} with {_NO_ENTRY} twice\n", encoding="utf-8"
    )
    _git(repo, "add", "notes.md")
    proc = _run(repo)
    assert proc.returncode == 1
    assert "notes.md:1: U+26D4" in proc.stderr


def test_a_glyph_quoted_in_backticks_is_the_permitted_token_form(repo: Path) -> None:
    _write(repo, "docs/rule.md", f"The banner `{_NO_ENTRY}` meant blocked. Say BLOCKED instead.\n")
    assert _run(repo).returncode == 0
    # The same glyph outside the backticks on the same line still fires.
    _write(repo, "docs/rule.md", f"The banner `{_NO_ENTRY}` meant blocked {_NO_ENTRY}.\n")
    assert _run(repo).returncode == 1


@pytest.mark.parametrize("rel", ["CHANGELOG.md", "docs/benchmarks/RUN-2026-10-07.md"])
def test_an_exempt_path_may_add_a_glyph(repo: Path, rel: str) -> None:
    _write(repo, rel, f"{_BALLOT_X} dated record\n")
    assert _run(repo).returncode == 0
    # Positive control: the same content one directory over is refused.
    _write(repo, "docs/other.md", f"{_BALLOT_X} dated record\n")
    assert _run(repo).returncode == 1


def test_commit_mode_judges_a_commit_that_already_exists(repo: Path) -> None:
    """The dry-run arm: the same rule over a commit's own diff against its parent."""
    _write(repo, "a.txt", f"bad {_ROCKET}\n")
    _git(repo, "commit", "-q", "-m", "adds a glyph")
    bad = _git(repo, "rev-parse", "HEAD").strip()
    _write(repo, "b.txt", "fine\n")
    _git(repo, "commit", "-q", "-m", "clean")
    assert _run(repo, "--commit", bad).returncode == 1
    assert _run(repo, "--commit", "HEAD").returncode == 0


def test_a_merge_does_not_refuse_what_the_other_parent_already_had(repo: Path) -> None:
    """Merging main into a branch must not re-judge every glyph main gained since the fork."""
    _git(repo, "switch", "-q", "-c", "feature")
    _write(repo, "f.txt", "feature work\n")
    _git(repo, "commit", "-q", "-m", "feature")
    _git(repo, "switch", "-q", "main")
    _write(repo, "m.txt", f"main gained {_BALLOT_X}\n")
    _git(repo, "commit", "-q", "-m", "main glyph")
    _git(repo, "switch", "-q", "feature")
    _git(repo, "merge", "-q", "--no-commit", "--no-ff", "main")
    assert _run(repo).returncode == 0
    # Positive control: a glyph added DURING the merge is new against both parents.
    _write(repo, "resolve.txt", f"added while merging {_BALLOT_X}\n")
    proc = _run(repo)
    assert proc.returncode == 1
    assert "resolve.txt:1: U+2717" in proc.stderr
    assert "m.txt" not in proc.stderr


def test_git_failure_fails_closed(tmp_path: Path) -> None:
    proc = _run(tmp_path, "--commit", "definitely-not-a-rev")
    assert proc.returncode == 2
    assert "NOT checked" in proc.stderr


def test_the_exempt_list_mirrors_the_warning_sign_guard() -> None:
    """One list of exemptions, read from the guard that owns it; drift here is a silent widening."""
    sys.path.insert(0, str(_CHECK.parent))
    try:
        import new_glyph_check as hook
    finally:
        sys.path.pop(0)
    assert set(hook.EXEMPT_PATHS) == set(_HELD)
    assert tuple(hook.EXEMPT_PREFIXES) == tuple(_DATED_RECORDS)


def test_the_script_source_is_ascii() -> None:
    """The hook names glyphs by codepoint, so its own source must carry none."""
    _CHECK.read_bytes().decode("ascii")
