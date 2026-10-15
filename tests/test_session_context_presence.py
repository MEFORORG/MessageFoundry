# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SessionStart banner (``scripts/worktree/session-context.ps1``) must degrade, never throw.

Whatever this hook prints to stdout IS the chat's starting context. If it raises, the session opens
with a stack trace instead of its coordination rules -- and the failure is silent, because nobody
reads a hook's exit code. These tests pin the fail-safe contract around the presence roster it now
calls into: a missing, broken, or slow ``presence.ps1`` must cost you the live-session list and
nothing else.

The scripts are copied into a throwaway tree rather than edited in place, so a test run never mutates
the repo -- these same scripts are live in every sibling session while the suite runs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "scripts" / "worktree" / "session-context.ps1"
PRESENCE = ROOT / "scripts" / "coord" / "presence.ps1"
HOOKINPUT = ROOT / "scripts" / "hooks" / "_hookinput.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="session-context.ps1 needs pwsh on Windows",
)

# The first thing the hook prints once it has real context. This fixture's repo has two worktrees, so
# the parallel-session block always runs here and its header is the signal that the hook produced
# context rather than dying early.
#
# It was the unconditional Ultracode preference banner until 2026-09-20, when the owner had that
# preference removed from every session. Nothing is printed unconditionally now, so the marker has to
# come from a block this fixture guarantees.
ALWAYS_PRINTED = "[PARALLEL SESSION"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def staged(tmp_path: Path) -> Path:
    """A git repo with 2+ worktrees (so the parallel-session block runs) holding script copies."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-qm", "init")
    _git(repo, "worktree", "add", "-q", "-b", "second", str(tmp_path / "wt2"))

    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "coord").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    # The shipped layout: the hook dot-sources its input reader from scripts/hooks, and says aloud
    # when it is missing.
    (repo / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy(HOOKINPUT, repo / "scripts" / "hooks" / "_hookinput.ps1")
    return repo


def run_context(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "worktree" / "session-context.ps1"),
        ],
        cwd=str(repo),
        input="",  # the hook reads its input; an inherited stdin would hold the read to its bound
        capture_output=True,
        text=True,
        timeout=180,
        check=False,  # the whole point is that it exits 0 even when presence.ps1 fails
    )


def fake_presence(repo: Path, rows: list[dict[str, object]]) -> None:
    """Stand in for presence.ps1 -Json, emitting exactly the shape the real script emits."""
    payload = json.dumps(rows).replace("'", "''")  # '' escapes a quote in a PS single-quoted string
    (repo / "scripts" / "coord" / "presence.ps1").write_text(
        f"Write-Output '{payload}'\n", encoding="utf-8"
    )


def test_banner_survives_a_missing_presence_script(staged: Path) -> None:
    """presence.ps1 absent (an older checkout, a partial clone) must not cost the banner."""
    assert not (staged / "scripts" / "coord" / "presence.ps1").exists()
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout
    assert "LIVE sessions" not in proc.stdout  # degraded, not crashed


def test_banner_survives_a_presence_script_that_throws(staged: Path) -> None:
    (staged / "scripts" / "coord" / "presence.ps1").write_text(
        "throw 'presence exploded'\n", encoding="utf-8"
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout
    assert "LIVE sessions" not in proc.stdout


def test_banner_survives_presence_emitting_junk(staged: Path) -> None:
    """Malformed JSON on stdout must not take the hook down in ConvertFrom-Json."""
    (staged / "scripts" / "coord" / "presence.ps1").write_text(
        "Write-Output 'not json at all'\n", encoding="utf-8"
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout


def test_live_peers_are_rendered_when_presence_reports_them(staged: Path) -> None:
    """The positive arm: a peer in the shared primary on another surface must be called out.

    Without this the suite would pass with the presence block silently emitting nothing at all --
    every other test here asserts an ABSENCE, which a no-op integration also satisfies.
    """
    # One foreign vscode session sitting in the shared primary -- the worst case the banner exists for.
    fake_presence(
        staged,
        [
            {
                "Short": "deadbeef",
                "Surface": "vscode",
                "Worktree": "primary",
                "Branch": "main",
                "IsSelf": False,
                "IsPrimary": True,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert "LIVE sessions in this repo right now (1 besides you)" in proc.stdout
    assert "deadbeef" in proc.stdout
    assert "vscode" in proc.stdout
    assert "SHARED PRIMARY" in proc.stdout
    assert "cannot be reached by" in proc.stdout  # the non-desktop coordination note


def test_the_session_id_is_labelled_because_the_same_banner_prints_real_shas(
    staged: Path,
) -> None:
    """BACKLOG #1098: an 8-hex session id printed bare reads as an abbreviated commit SHA.

    It reads that way for a measured reason rather than a vague one, and this test measures it: the
    ``git worktree list`` block a few lines up prints ``<path> <abbreviated sha> [branch]``, so the same
    banner already teaches "8 hex before a bracketed branch = commit SHA". The roster then reused the
    shape for a registry session id, which resolves to no git object at all. A session comparing "is that
    worktree ahead of mine" against it gets an error at best, and the wrong tree if the prefix resolves.

    The POSITIVE CONTROL is the first half: assert the real SHA is genuinely in this output, keyed to
    ``rev-parse HEAD`` so it is an object and not a shape. Without it the second assertion would be a
    claim about an ambiguity nobody had shown to exist.
    """
    head = subprocess.run(
        ["git", "-C", str(staged), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    fake_presence(
        staged,
        [
            {
                "Short": "deadbeef",
                "Surface": "desktop",
                "Worktree": "sibling",
                "Branch": "second",
                "IsSelf": False,
                "IsPrimary": False,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0

    sha_rows = [ln for ln in proc.stdout.splitlines() if head[:7] in ln]
    assert sha_rows, (
        f"no row carries HEAD ({head[:7]}), so this banner does not in fact print commit SHAs and the "
        f"ambiguity below is unproven -- fix this control before trusting the assertion after it"
    )
    print(f"real SHA rows in the same banner: {sha_rows}")

    row = next(ln for ln in proc.stdout.splitlines() if "deadbeef" in ln)
    print(f"roster row: {row!r}")
    assert row.strip().startswith("session deadbeef"), (
        f"the registry session id is printed bare, in the same shape the worktree rows use for a real "
        f"abbreviated SHA: {row!r}"
    )


def test_self_is_excluded_from_the_peer_count(staged: Path) -> None:
    fake_presence(
        staged,
        [
            {
                "Short": "aaaaaaaa",
                "Surface": "desktop",
                "Worktree": "w",
                "Branch": "b",
                "IsSelf": True,
                "IsPrimary": False,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert "LIVE sessions" not in proc.stdout  # you alone is not a coordination problem


# --------------------------------------------------------------------------------------------------
# Which worktree the banner describes.
#
# Measured 2026-10-12: the desktop app starts a worktree session's CLI with `--project-config-root
# <primary checkout>`, and a hook then runs in the PRIMARY. Across MessageFoundry worktree transcripts
# this banner printed "This chat's worktree: <primary>" 410 times against 48 for a worktree. Only the
# hook input's `cwd` names the worktree. These tests run the hook IN the primary, as the app does,
# and vary only that field.
# --------------------------------------------------------------------------------------------------


def _top(path: Path) -> str:
    """The toplevel exactly as git prints it, which is how the banner prints it."""
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def primary_and_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """A primary checkout carrying the shipped hook and its helper, plus one linked worktree.

    realpath, because a short 8.3 temp path and its long form are two spellings git will not equate.
    """
    base = Path(os.path.realpath(tmp_path))
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-qm", "init")
    wt = base / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(wt))
    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    shutil.copy(HOOKINPUT, repo / "scripts" / "hooks" / "_hookinput.ps1")
    return repo, wt


def run_in_primary(repo: Path, payload: dict[str, object]) -> str:
    """Run the hook as the desktop app does: in the primary, with the input on stdin as UTF-8."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "worktree" / "session-context.ps1"),
        ],
        cwd=str(repo),
        input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc.stdout.decode("utf-8", "replace")


def test_the_banner_names_the_worktree_the_hook_input_names(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    repo, wt = primary_and_worktree
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(wt)})
    assert f"This chat's worktree: {_top(wt)}  (branch: linked)" in out, out
    assert "SHARED PRIMARY checkout" not in out, out


def test_a_cwd_below_the_worktree_root_names_the_same_worktree(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    repo, wt = primary_and_worktree
    sub = wt / "deep" / "er"
    sub.mkdir(parents=True)
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(sub)})
    assert f"This chat's worktree: {_top(wt)}  (branch: linked)" in out, out


def test_without_a_cwd_the_banner_names_where_the_hook_runs(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    """The control. With no `cwd` the same call describes the primary, so the arms above can fail."""
    repo, _ = primary_and_worktree
    out = run_in_primary(repo, {"hook_event_name": "SessionStart"})
    assert f"This chat's worktree: {_top(repo)}  (branch: main)" in out, out
    assert "SHARED PRIMARY checkout" in out, out
    assert "COULD NOT READ" not in out, "no `cwd` is not a fault and must not be reported as one"


def test_a_cwd_that_does_not_exist_is_said_aloud(
    primary_and_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, _ = primary_and_worktree
    gone = Path(os.path.realpath(tmp_path)) / "deleted-worktree"
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(gone)})
    assert "[session-context] COULD NOT READ THIS SESSION'S WORKTREE" in out, out
    assert "deleted-worktree, which does not exist" in out, out
    assert f"This chat's worktree: {_top(repo)}" in out, (
        "the fallback is the old behaviour, said aloud"
    )


def test_a_missing_input_reader_is_said_aloud(primary_and_worktree: tuple[Path, Path]) -> None:
    """Under SilentlyContinue a dot-source of a missing file does not throw, so a hook that relied
    on the throw would fall back to the primary in silence."""
    repo, wt = primary_and_worktree
    (repo / "scripts" / "hooks" / "_hookinput.ps1").unlink()
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(wt)})
    assert "[session-context] COULD NOT READ THIS SESSION'S WORKTREE" in out, out
    assert "_hookinput.ps1 is missing" in out, out


def test_a_primary_under_a_directory_named_worktrees_is_still_the_primary(
    tmp_path: Path,
) -> None:
    """Read from a subdirectory, git prints the git-dir in full, so a test for 'worktrees' in it
    misreads a primary that sits under a directory of that name. The common dir is the measure."""
    base = Path(os.path.realpath(tmp_path)) / "worktrees"
    base.mkdir()
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(base / "linked"))
    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    shutil.copy(HOOKINPUT, repo / "scripts" / "hooks" / "_hookinput.ps1")
    sub = repo / "sub"
    sub.mkdir()
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(sub)})
    assert "SHARED PRIMARY checkout" in out, out


def test_the_hook_reads_its_input_when_a_shim_runs_it_in_process(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    """The user-level shim runs the hook with `& $s` inside its own pwsh -Command, stdin inherited.
    The read must reach the input from there too, not only under -File."""
    repo, wt = primary_and_worktree
    script = str(repo / "scripts" / "worktree" / "session-context.ps1").replace("'", "''")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", f"& '{script}'"],
        cwd=str(repo),
        input=json.dumps({"hook_event_name": "SessionStart", "cwd": str(wt)}).encode("utf-8"),
        capture_output=True,
        timeout=180,
        check=False,
    )
    out = proc.stdout.decode("utf-8", "replace")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert f"This chat's worktree: {_top(wt)}  (branch: linked)" in out, out
