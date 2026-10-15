# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hooks answer for the worktree their input names, not the one they run in.

Measured 2026-10-12: the desktop app starts a worktree session's CLI with ``--project-config-root
<primary checkout>``. A hook then runs with its working directory, ``CLAUDE_PROJECT_DIR`` and ``git
rev-parse --show-toplevel`` all naming the PRIMARY. Only the ``cwd`` field of the JSON on stdin names
the worktree. ``scripts/hooks/_hookinput.ps1`` reads that field, as UTF-8.

This file holds the helper's own tests and the one changed hook no other test file drives,
``lane-level.ps1``. The hooks that have a test file carry their case there.

Every hook here runs IN the primary, as the app runs it. Each arm that names the worktree has a
control that does not, and the control is what shows the fixture reproduces the fault.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from tests._session_pin import pin_path, seed_pin
from tests._spawn_lock import run_single

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "scripts" / "hooks"
HELPER = HOOKS / "_hookinput.ps1"
LANE = HOOKS / "lane-level.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the hooks are PowerShell run under pwsh on Windows",
)

# Not ASCII on purpose. The console decoder [Console]::In uses turns this into two box-drawing
# characters, which is the half of the defect a plain ASCII path cannot show.
ACCENTED = "caf\u00e9-linked"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _same_dir(a: str, b: Path) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _primary_with(tmp_path: Path, worktree_leaf: str) -> tuple[Path, Path]:
    """A primary checkout and one linked worktree. realpath, so 8.3 and long names cannot differ."""
    base = Path(os.path.realpath(tmp_path))
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    wt = base / worktree_leaf
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(wt))
    return repo, wt


def _run(script: Path, cwd: Path, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc


def _raw(payload: dict[str, Any], *, ascii_escaped: bool = False) -> bytes:
    """The input as the harness writes it: raw UTF-8, never escaped to ASCII."""
    return json.dumps(payload, ensure_ascii=ascii_escaped).encode("utf-8")


# --------------------------------------------------------------------------------------------------
# The helper.
# --------------------------------------------------------------------------------------------------


def _helper(tmp_path: Path, call: str, stdin: bytes) -> dict[str, Any]:
    probe = tmp_path / "probe.ps1"
    probe.write_text(
        # UTF-8 out as well as in, or the probe's own console encoder mangles what the helper read.
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{HELPER}'\n$t = Read-CcxHookInput\n{call} | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = _run(probe, tmp_path, stdin)
    return dict(json.loads(proc.stdout.decode("utf-8")))


def test_the_helper_reads_a_cwd_that_is_not_ascii(tmp_path: Path) -> None:
    _, wt = _primary_with(tmp_path, ACCENTED)
    got = _helper(tmp_path, "Get-CcxHookPayloadCwd -Text $t", _raw({"cwd": str(wt)}))
    assert got["Named"] is True and got["Reason"] == "", got
    assert _same_dir(got["Cwd"], wt), got


def test_the_helper_walks_up_to_the_worktree_root(tmp_path: Path) -> None:
    _, wt = _primary_with(tmp_path, "linked")
    sub = wt / "deep" / "er"
    sub.mkdir(parents=True)
    got = _helper(tmp_path, "@{ Root = Get-CcxWorktreeRoot '" + str(sub) + "' }", _raw({}))
    assert _same_dir(got["Root"], wt), got


def test_the_helper_says_no_cwd_is_not_a_fault(tmp_path: Path) -> None:
    got = _helper(
        tmp_path,
        "Resolve-CcxHookSession -Text $t | Select-Object Named, Dir, Reason",
        _raw({"session_id": "s1"}),
    )
    assert got == {"Named": False, "Dir": None, "Reason": ""}, got


# --------------------------------------------------------------------------------------------------
# Resolve-CcxHookSession: the rules in the helper's header. The Lander's verdicts on korus#223 and
# PR 2328 measured a `cwd` that followed a `cd` into a sibling worktree or another repository, with
# and without a pin, and the hooks answered for wherever it pointed. Every probe here runs IN the
# primary, as the desktop app runs a hook, and each refusal has a control that is not refused.
# --------------------------------------------------------------------------------------------------


def _resolve(
    repo: Path, tmp_path: Path, payload: dict[str, Any], flags: str = "", helper: Path = HELPER
) -> dict[str, Any]:
    probe = tmp_path / "resolve.ps1"
    probe.write_text(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{helper}'\n$t = Read-CcxHookInput\n"
        f"$r = Resolve-CcxHookSession -Text $t {flags}\n"
        "[pscustomobject]@{ Dir = $r.Dir; Reason = $r.Reason; Note = $r.Note; Source = $r.Source;"
        " Pinned = $r.Pinned } | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = _run(probe, repo, _raw(payload))
    return dict(json.loads(proc.stdout.decode("utf-8")))


def _other_repo(tmp_path: Path) -> Path:
    other = Path(os.path.realpath(tmp_path)) / "other-repo"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    return other


def _opted_in(tmp_path: Path, worktree_leaf: str = "linked") -> tuple[Path, Path, Path]:
    """A primary that opted in to pins, its linked worktree, and a sibling worktree.

    The helper under test lives in THIS repository, not the fixture's, so it may write a pin there
    only through ``ccx.config.json`` (the opt-in rule in the helper's header)."""
    repo, wt = _primary_with(tmp_path, worktree_leaf)
    (repo / "ccx.config.json").write_text("{}\n", encoding="utf-8")
    sibling = Path(os.path.realpath(tmp_path)) / "sibling"
    _git(repo, "worktree", "add", "-q", "-b", "sibling", str(sibling))
    return repo, wt, sibling


def _launch(session: str, cwd: Path, source: str = "startup") -> dict[str, Any]:
    return {
        "cwd": str(cwd),
        "session_id": session,
        "hook_event_name": "SessionStart",
        "source": source,
    }


def _stop(session: str, cwd: Path) -> dict[str, Any]:
    return {"cwd": str(cwd), "session_id": session, "hook_event_name": "Stop"}


def test_a_pinned_session_answers_for_its_own_worktree(tmp_path: Path) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    got = _resolve(repo, tmp_path, _stop("s1", wt))
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert got["Reason"] == "" and got["Note"] == "" and got["Source"] == "cwd", got


def test_an_unpinned_cwd_in_a_sibling_is_refused_and_the_hook_stays_put(tmp_path: Path) -> None:
    """THE LANDER'S POINT, ON BOTH PRs: with no pin a sibling's `cwd` was answered for as it stood.

    No pin means the hook cannot tell the session's own worktree from a sibling it moved into, so it
    refuses both and stays in the start checkout, with a Reason to say aloud."""
    repo, _, sibling = _opted_in(tmp_path)
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] is None and got["Source"] == "start", "an unpinned sibling cwd was followed"
    assert "no pin records that this session started in" in got["Reason"], got
    # The control: an unpinned `cwd` inside the start checkout's own worktree is used.
    sub = repo / "sub"
    sub.mkdir()
    here = _resolve(repo, tmp_path, _stop("s1", sub))
    assert here["Dir"] and _same_dir(here["Dir"], sub) and here["Reason"] == "", here


def test_a_cwd_in_another_repository_is_a_fault_without_a_pin(tmp_path: Path) -> None:
    repo, _ = _primary_with(tmp_path, "linked")
    other = _other_repo(tmp_path)
    got = _resolve(repo, tmp_path, {"cwd": str(other), "session_id": "s1"})
    assert got["Dir"] is None, got
    assert "which is in another repository" in got["Reason"], got


def test_a_cwd_under_an_empty_git_file_is_a_fault(tmp_path: Path) -> None:
    """A `.git` that names no git directory is not a checkout. Walking up to it alone accepted it."""
    repo, _ = _primary_with(tmp_path, "linked")
    fake = Path(os.path.realpath(tmp_path)) / "fake"
    fake.mkdir()
    (fake / ".git").write_text("", encoding="utf-8")
    got = _resolve(repo, tmp_path, {"cwd": str(fake), "session_id": "s1"})
    assert got["Dir"] is None and "names no git directory" in got["Reason"], got


def test_after_a_cd_to_a_sibling_the_hook_answers_for_the_pinned_worktree(tmp_path: Path) -> None:
    repo, wt, sibling = _opted_in(tmp_path)
    start = _resolve(repo, tmp_path, _launch("s1", wt))
    assert start["Dir"] and _same_dir(start["Dir"], wt), start
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], wt), "the session showed as its sibling after a cd"
    assert "outside the worktree the session started in" in got["Note"], got
    # The control: another session that STARTED in the sibling is answered for there.
    other = _resolve(repo, tmp_path, _launch("s2", sibling))
    assert other["Dir"] and _same_dir(other["Dir"], sibling), other


def test_after_a_cd_to_another_repository_the_hook_answers_for_the_pinned_worktree(
    tmp_path: Path,
) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    other = _other_repo(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    got = _resolve(repo, tmp_path, _stop("s1", other))
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert "which is in another repository" in got["Note"], got
    assert not (other / ".git" / "ccx-session-root").exists(), (
        "nothing may be written into that repository"
    )


def test_a_compact_after_a_cd_does_not_move_the_pin(tmp_path: Path) -> None:
    """SessionStart also fires on /compact, wherever a `cd` left the cwd. Only a launch (startup,
    resume, or no source) writes the pin."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    _resolve(repo, tmp_path, _launch("s1", sibling, "compact"))
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], wt), (
        "a compaction re-pinned the session to its sibling"
    )
    # The control: a resume does rewrite it.
    _resolve(repo, tmp_path, _launch("s1", sibling, "resume"))
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], sibling), got


@pytest.mark.parametrize("source", ["clear", "compact"])
def test_a_clear_after_a_cd_never_pins_the_sibling(tmp_path: Path, source: str) -> None:
    """THE HIGH FINDING. /clear mints a NEW session id, so its SessionStart finds no pin, and the old
    rule ("a /clear writes a pin where none exists") pinned whatever sibling a `cd` had reached. A
    /clear or /compact now never pins; the new id follows the no-pin rule until a launch."""
    repo, _, sibling = _opted_in(tmp_path)
    first = _resolve(repo, tmp_path, _launch("fresh", sibling, source))
    assert first["Dir"] is None and first["Pinned"] is None, first
    assert "no pin records" in first["Reason"], first
    got = _resolve(repo, tmp_path, _stop("fresh", sibling))
    assert got["Dir"] is None, "a /clear after a cd pinned the sibling"
    assert not any((repo / ".git" / "ccx-session-root").glob("*")), "a pin was written"
    # The control: the same `cwd` at a startup is the session's launch, and it pins.
    _resolve(repo, tmp_path, _launch("fresh", sibling))
    got = _resolve(repo, tmp_path, _stop("fresh", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], sibling), got


def test_a_launch_answers_for_its_cwd_and_pins_only_where_opted_in(tmp_path: Path) -> None:
    """The opt-in gate. A user-scope copy of the helper writes no file in a clone that did not opt
    in, yet still answers the launch itself, whose `cwd` is where the session started."""
    repo, wt = _primary_with(tmp_path, "linked")
    pins = repo / ".git" / "ccx-session-root"
    got = _resolve(repo, tmp_path, _launch("s1", wt))
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert not pins.exists(), "a pin was written in a clone that did not opt in"
    # A helper that LIVES in the clone is the clone's own hook, and that is an opt-in too.
    own = repo / "scripts" / "hooks"
    own.mkdir(parents=True)
    shutil.copy(HELPER, own / "_hookinput.ps1")
    _resolve(repo, tmp_path, _launch("s1", wt), helper=own / "_hookinput.ps1")
    assert len(list(pins.glob("*"))) == 1, "the clone's own helper wrote no pin"
    # -ReadOnly never writes, opted in or not.
    _resolve(repo, tmp_path, _launch("s2", wt), "-ReadOnly", helper=own / "_hookinput.ps1")
    assert len(list(pins.glob("*"))) == 1, "a -ReadOnly launch wrote a pin"


def test_a_launch_that_cannot_replace_the_pin_keeps_no_stale_one(tmp_path: Path) -> None:
    """A swap that failed used to leave the previous run's pin, which then answered for every later
    event. A read-only pin makes the move fail on demand. The helper must still end with the new pin
    or none, never the old one naming the sibling."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", sibling))
    pin = next((repo / ".git" / "ccx-session-root").glob("*"))
    os.chmod(pin, 0o444)
    try:
        _resolve(repo, tmp_path, _launch("s1", wt, "resume"))
        got = _resolve(repo, tmp_path, _stop("s1", sibling))
        assert not (got["Dir"] and _same_dir(got["Dir"], sibling)), "the stale pin answered"
    finally:
        if pin.exists():
            os.chmod(pin, 0o644)


def _pin_file(repo: Path, worktree: Path) -> Path:
    """The one file under the common dir that names ``worktree``, wherever the helper keeps it."""
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    for f in common.rglob("*"):
        if f.is_file() and f.suffix != ".tmp" and f.stat().st_size < 4096:
            try:
                if _same_dir(f.read_text(encoding="utf-8").strip(), worktree):
                    return f
            except (OSError, UnicodeDecodeError, ValueError):
                continue
    raise AssertionError("the launch wrote no pin naming the worktree")


def test_the_pin_is_never_missing_while_it_is_replaced(tmp_path: Path) -> None:
    """THE MEDIUM FINDING: `Move-Item -Force` deletes and then moves, so a reader between the two saw
    no pin and followed the sibling. Measured on pwsh 7.6.6. One thread relaunches the session in
    alternating worktrees while another checks, as tightly as it can, that the pin file exists."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    pin = _pin_file(repo, wt)
    probe = tmp_path / "race.ps1"
    probe.write_text(
        "param($h, $a, $b, $pin)\n"
        "$writer = Start-ThreadJob -ArgumentList $h, $a, $b -ScriptBlock {\n"
        "    param($h, $a, $b)\n"
        "    . $h\n"
        "    foreach ($i in 1..300) {\n"
        "        $cwd = if ($i % 2) { $b } else { $a }\n"
        "        $j = @{ cwd = $cwd; session_id = 's1'; hook_event_name = 'SessionStart';"
        " source = 'resume' } | ConvertTo-Json\n"
        "        $null = Resolve-CcxHookSession -Text $j\n"
        "    }\n"
        "}\n"
        "$misses = 0; $reads = 0\n"
        "while ($writer.State -eq 'Running' -or $writer.State -eq 'NotStarted') {\n"
        "    $reads++\n"
        "    if (-not [System.IO.File]::Exists($pin)) { $misses++ }\n"
        "}\n"
        "$errs = @(Receive-Job $writer -Wait -AutoRemoveJob 2>&1 | ForEach-Object { [string]$_ })\n"
        "$named = Get-Content -LiteralPath $pin -TotalCount 1\n"
        "@{ reads = $reads; misses = $misses; errors = $errs; named = $named }"
        " | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe)]
        + [str(HELPER), str(wt), str(sibling), str(pin)],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT * 3,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert got["errors"] == [], f"the writer failed, so this proves nothing: {got}"
    # One read per write at the least, or the window between a delete and a move was barely sampled.
    assert got["reads"] >= 300, f"the reader barely ran, so this proves nothing: {got}"
    assert _same_dir(got["named"], wt), f"the writer did not finish on its last launch: {got}"
    assert got["misses"] == 0, f"a reader found no pin mid-replace: {got}"


def test_a_pin_write_prunes_stale_temp_files_and_keeps_fresh_ones(tmp_path: Path) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    pins = repo / ".git" / "ccx-session-root"
    pins.mkdir(parents=True)
    stale = pins / "abc.1.dead.tmp"
    fresh = pins / "abc.2.live.tmp"
    stale.write_text("x", encoding="utf-8")
    fresh.write_text("x", encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale, (old, old))
    _resolve(repo, tmp_path, _launch("s1", wt))
    assert not stale.exists(), "a temp file an hour old was left behind"
    assert fresh.exists(), "a temp file a live writer may own was removed"


def test_a_pin_naming_a_removed_worktree_is_ignored(tmp_path: Path) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    _git(repo, "worktree", "remove", "--force", str(wt))
    got = _resolve(repo, tmp_path, _stop("s1", repo))
    assert got["Dir"] and _same_dir(got["Dir"], repo), got
    assert got["Pinned"] is None, got


def test_allow_outside_still_prefers_the_pin(tmp_path: Path) -> None:
    """A pinned session that ran `cd` into a scratch directory keeps its own worktree. Only a
    session with nothing pinned is answered for where it stands."""
    repo, wt, _ = _opted_in(tmp_path)
    scratch = Path(os.path.realpath(tmp_path)) / "scratch"
    scratch.mkdir()
    _resolve(repo, tmp_path, _launch("s1", wt))
    got = _resolve(
        repo, tmp_path, {"cwd": str(scratch), "session_id": "s1"}, "-ReadOnly -AllowOutside"
    )
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    other = _resolve(
        repo, tmp_path, {"cwd": str(scratch), "session_id": "s2"}, "-ReadOnly -AllowOutside"
    )
    assert other["Dir"] and _same_dir(other["Dir"], scratch), other


def test_the_seeded_pin_matches_the_one_a_launch_writes(tmp_path: Path) -> None:
    """tests/_session_pin.py writes pins for the hook tests by hand. Pin it to the real layout."""
    repo, wt, _ = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    written = pin_path(repo, "s1")
    assert written.is_file(), "the launch wrote its pin somewhere the seeder does not look"
    assert _same_dir(written.read_text(encoding="utf-8").strip(), wt)


# --------------------------------------------------------------------------------------------------
# lane-level.ps1. It tells a builder lane by its worktree's name, so from the primary it answered for
# neither lane nor dispatcher and said nothing.
# --------------------------------------------------------------------------------------------------


def _lane(repo: Path, payload: dict[str, Any]) -> str:
    out = _run(LANE, repo, _raw(payload)).stdout.decode("utf-8").strip()
    return str(json.loads(out)["hookSpecificOutput"]["additionalContext"]) if out else ""


@pytest.fixture
def builder_lane(tmp_path: Path) -> tuple[Path, Path]:
    repo, wt = _primary_with(tmp_path, "builder-lane")
    (repo / ".git" / "mefor-coord").mkdir()
    return repo, wt


def test_lane_level_nags_the_builder_worktree_the_input_names(
    builder_lane: tuple[Path, Path],
) -> None:
    repo, wt = builder_lane
    seed_pin(repo, wt, "s1")
    text = _lane(repo, {"hook_event_name": "Stop", "cwd": str(wt), "session_id": "s1"})
    assert "[lane] Your lane level is unstated or stale" in text, text


def test_lane_level_without_a_cwd_reads_where_it_runs(builder_lane: tuple[Path, Path]) -> None:
    """The control. The primary is no builder lane, so the same call says nothing at all."""
    repo, _ = builder_lane
    assert _lane(repo, {"hook_event_name": "Stop"}) == ""


def test_lane_level_says_aloud_when_the_cwd_does_not_exist(
    builder_lane: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, _ = builder_lane
    gone = str(Path(os.path.realpath(tmp_path)) / "deleted-worktree")
    text = _lane(repo, {"hook_event_name": "Stop", "cwd": gone})
    assert "[lane] COULD NOT READ THIS SESSION'S WORKTREE" in text, text
    assert "deleted-worktree, which does not exist" in text, text
