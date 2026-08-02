# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the collision gate (``scripts/hooks/collision_gate.ps1``) and its installer.

The gate refuses to edit a file another LIVE session is already changing. Worktrees stop two sessions
overwriting each other's bytes; they do not stop two sessions editing the same file in parallel and
finding out at merge, when one of them has to throw work away.

Two properties carry the weight, and they pull in opposite directions:

* **It denies on a live session and only on a live session.** A dormant worktree cannot be racing you,
  and a gate that blocks every file an abandoned branch ever touched gets uninstalled.
* **It fails OPEN on every error.** This gate prevents rework; it must never be the reason a session
  cannot work. That is deliberately the opposite of the worktree gate, which protects the shared tree
  and fails closed.

The gate is driven as a real subprocess with a real PreToolUse payload, against a stub overlap script
supplying known rows. Splitting it there is intentional: these tests pin the gate's DECISION, and
``test_coord_overlap.py`` pins how the rows are computed. Neither re-implements the other.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "hooks" / "collision_gate.ps1"
INSTALLER = ROOT / "scripts" / "coord" / "install-coordination.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="collision_gate.ps1 needs pwsh on Windows",
)


def make_overlap_stub(tmp_path: Path, rows: list[dict[str, Any]]) -> Path:
    """A stand-in for overlap.ps1 that emits the rows we want, in the real script's shape."""
    stub = tmp_path / "overlap-stub.ps1"
    payload = json.dumps(rows).replace("'", "''")  # '' escapes a quote in a PS single-quoted string
    stub.write_text(
        "param([string]$File,[switch]$Json,[switch]$Refresh,[int]$CacheSeconds,"
        "[string]$Repo,[string[]]$ConfigRoot,[string]$TasksDir)\n"
        f"Write-Output '{payload}'\n",
        encoding="utf-8",
    )
    return stub


def run_gate(
    overlap: Path | None,
    file_path: str | None = "a.py",
    state_dir: Path | None = None,
    raw_input: str | None = None,
) -> dict[str, Any] | None:
    """Invoke the gate exactly as Claude Code does. Returns the emitted object, or None for silence.

    ``state_dir`` isolates the unresolved-notice throttle. Without it the gate would stamp the REAL
    repository's coordination directory, so one test's notice would silence the next one's -- and the
    suite would pass or fail on the order it happened to run in.
    """
    payload: dict[str, Any] = {"tool_name": "Edit", "tool_input": {}}
    if file_path is not None:
        payload["tool_input"]["file_path"] = file_path
    args = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(GATE)]
    if overlap is not None:
        args += ["-OverlapScript", str(overlap)]
    if state_dir is not None:
        args += ["-StateDir", str(state_dir)]
    proc = subprocess.run(
        args,
        input=json.dumps(payload) if raw_input is None else raw_input,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    # A hook must never crash the tool call: a non-zero exit is ignored by the harness, which would
    # leave the gate looking installed while permitting everything.
    assert proc.returncode == 0, f"gate exited {proc.returncode}: {proc.stderr}"
    out = proc.stdout.strip()
    return json.loads(out) if out else None


LIVE_ROW = {
    "Worktree": "sibling-wt",
    "Branch": "claude/other-work",
    "Live": True,
    "Short": "deadbeef",
    "Surface": "vscode",
    "Files": ["a.py"],
    "Work": ["Rewrite the ingest path", "Add the retry test"],
}
DORMANT_ROW = {**LIVE_ROW, "Live": False, "Short": "", "Surface": "", "Worktree": "old-wt"}

# A live session with the file OPEN AND UNSAVED, versus one that committed it and went clean. The gate
# must separate these: `Files` unions committed-and-unlanded with working-tree, so both look identical
# through it, and a committed file stays until the branch LANDS.
EDITING_ROW = {**LIVE_ROW, "Dirty": ["a.py"], "MatchedDirty": True}
COMMITTED_ROW = {**LIVE_ROW, "Dirty": [], "MatchedDirty": False}


def test_denies_when_a_live_session_is_changing_the_file(tmp_path: Path) -> None:
    got = run_gate(make_overlap_stub(tmp_path, [LIVE_ROW]))
    assert got is not None, "expected a deny, got allow"
    out = got["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"


def test_the_denial_names_the_session_branch_and_what_it_is_building(tmp_path: Path) -> None:
    """A deny that doesn't say WHO or WHAT just looks like a broken tool and gets overridden."""
    got = run_gate(make_overlap_stub(tmp_path, [LIVE_ROW]))
    assert got is not None
    reason = got["hookSpecificOutput"]["permissionDecisionReason"]
    assert "deadbeef" in reason
    assert "claude/other-work" in reason
    assert "Rewrite the ingest path" in reason  # the duplicate-work signal
    assert "vscode" in reason  # surface matters: it cannot be reached by session messaging


def test_allows_when_only_a_dormant_worktree_touches_the_file(tmp_path: Path) -> None:
    """Nobody is typing in it, so it cannot be racing you."""
    assert run_gate(make_overlap_stub(tmp_path, [DORMANT_ROW])) is None


def test_allows_when_nobody_else_touches_the_file(tmp_path: Path) -> None:
    assert run_gate(make_overlap_stub(tmp_path, [])) is None


def test_denies_only_on_an_uncommitted_edit_in_a_live_worktree(tmp_path: Path) -> None:
    got = run_gate(make_overlap_stub(tmp_path, [EDITING_ROW]))
    assert got is not None, "an unsaved edit in a live worktree must still deny"
    assert got["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "UNCOMMITTED" in got["hookSpecificOutput"]["permissionDecisionReason"]


def test_allows_a_file_another_live_session_committed_and_finished_with(tmp_path: Path) -> None:
    """THE OVER-BLOCK. Reported 2026-08-01 with a repro: a session committed a file, went clean, and
    said in writing it was done -- and the peer it handed off to was still refused.

    ``Files`` unions committed-and-unlanded with working-tree, so a committed file keeps blocking until
    the branch LANDS. While PRs cannot merge that is indefinite, so the blocked set only ever grows and
    two sessions that coordinated correctly still cannot hand a file over. This gate's own docstring
    names that failure: a gate that cries wolf gets uninstalled.
    """
    got = run_gate(make_overlap_stub(tmp_path, [COMMITTED_ROW]))
    assert got is not None, "expected context, not silence"
    out = got["hookSpecificOutput"]
    assert "permissionDecision" not in out, f"must not block a committed-and-clean file: {out}"
    ctx = out["additionalContext"]
    assert "deadbeef" in ctx and "claude/other-work" in ctx, "context must still name the peer"


def test_a_row_without_the_dirty_signal_still_denies(tmp_path: Path) -> None:
    """Fail SAFE across the upgrade. A cached overlap row written before MatchedDirty existed carries
    no such property; treating it as clean would silently permit a real collision, so it is treated as
    dirty and the gate degrades to its previous over-blocking behaviour instead.
    """
    got = run_gate(make_overlap_stub(tmp_path, [LIVE_ROW]))  # no Dirty/MatchedDirty at all
    assert got is not None
    assert got["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_an_editing_peer_still_denies_when_another_peer_merely_committed(tmp_path: Path) -> None:
    """One finished peer must not mask a peer who is actively typing in the file."""
    got = run_gate(make_overlap_stub(tmp_path, [COMMITTED_ROW, EDITING_ROW]))
    assert got is not None
    assert got["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_allows_a_payload_with_no_file_path(tmp_path: Path) -> None:
    assert run_gate(make_overlap_stub(tmp_path, [LIVE_ROW]), file_path=None) is None


# ------------------------------------------------------------------- failing open, but not silently
#
# Every one of these paths used to `exit 0` with EMPTY STDOUT -- which is byte-for-byte what "checked,
# nobody else is in this file" looks like. A gate that had consulted nothing was indistinguishable from
# a gate reporting all-clear, so its own failure was reported to the session as reassurance.
#
# The posture does not change: all of them still ALLOW. Only the silence does.


def unresolved(got: dict[str, Any] | None) -> str:
    """Assert the shape of an unresolved notice and return its text."""
    assert got is not None, "an unresolved gate must say so, not exit silently"
    out = got["hookSpecificOutput"]
    # THE FAIL-OPEN POSTURE IS THE POINT. A notice that carried a permissionDecision would turn a
    # broken guard into a blocked session -- strictly worse than the silence it replaces.
    assert "permissionDecision" not in out, f"a diagnostic must never block: {out}"
    assert out["hookEventName"] == "PreToolUse"
    ctx: str = out["additionalContext"]
    # It must be a JSON payload, not a bare line: this hook's stdout is parsed as a DECISION, so a
    # stray line risks a misparse on every Edit and Write. json.loads in run_gate already proved that.
    assert "could NOT check" in ctx
    return ctx


def test_says_so_when_the_overlap_script_is_missing(tmp_path: Path) -> None:
    got = run_gate(tmp_path / "does-not-exist.ps1", state_dir=tmp_path / "state")
    assert "overlap-missing" in unresolved(got)


def test_says_so_when_the_overlap_script_throws(tmp_path: Path) -> None:
    broken = tmp_path / "broken.ps1"
    broken.write_text("param([string]$File,[switch]$Json)\nthrow 'boom'\n", encoding="utf-8")
    ctx = unresolved(run_gate(broken, state_dir=tmp_path / "state"))
    assert "overlap-failed" in ctx or "overlap-threw" in ctx


def test_says_so_when_the_overlap_script_emits_junk(tmp_path: Path) -> None:
    junk = tmp_path / "junk.ps1"
    junk.write_text(
        "param([string]$File,[switch]$Json)\nWrite-Output 'not json'\n", encoding="utf-8"
    )
    assert "overlap-unparseable" in unresolved(run_gate(junk, state_dir=tmp_path / "state"))


def test_says_so_when_the_overlap_script_answers_with_nothing(tmp_path: Path) -> None:
    """THE CONFLATION THIS FIX EXISTS FOR, and the only one with no other symptom.

    Under ``-Json`` a *resolved* "nobody else is in this file" is the two bytes ``[]``. A script that
    exits 0 having printed nothing has produced no verdict at all. The gate treated both as "no rows,
    allow", so a silently-broken overlap script was reported to the session as an all-clear forever.
    """
    mute = tmp_path / "mute.ps1"
    mute.write_text("param([string]$File,[switch]$Json)\nexit 0\n", encoding="utf-8")
    assert "overlap-empty" in unresolved(run_gate(mute, state_dir=tmp_path / "state"))


def test_a_resolved_empty_answer_stays_silent(tmp_path: Path) -> None:
    """The other half of that pair, and the reason it cannot simply always warn.

    ``[]`` IS an answer. This is the hot path on every single Edit and Write, so a gate that spoke up
    here would put a line into the context of every edit in the repo forever.
    """
    assert run_gate(make_overlap_stub(tmp_path, []), state_dir=tmp_path / "state") is None


def test_says_so_when_the_hook_payload_is_unreadable(tmp_path: Path) -> None:
    got = run_gate(
        make_overlap_stub(tmp_path, [LIVE_ROW]), state_dir=tmp_path / "state", raw_input="{not json"
    )
    assert "payload-unreadable" in unresolved(got)


def test_the_notice_is_rate_limited_per_reason(tmp_path: Path) -> None:
    """A persistently broken overlap script must not narrate itself into every edit.

    Same state dir twice: the first call reports, the second is suppressed. This is the difference
    between a diagnostic and a nag, and this gate's own docstring names where nags end up.
    """
    state = tmp_path / "state"
    missing = tmp_path / "does-not-exist.ps1"
    assert run_gate(missing, state_dir=state) is not None, "first occurrence must be reported"
    assert run_gate(missing, state_dir=state) is None, "second occurrence must be suppressed"


def test_a_different_reason_is_not_suppressed_by_the_first(tmp_path: Path) -> None:
    """Per-reason, not global -- otherwise one benign fault masks every later one."""
    state = tmp_path / "state"
    assert run_gate(tmp_path / "does-not-exist.ps1", state_dir=state) is not None
    junk = tmp_path / "junk.ps1"
    junk.write_text(
        "param([string]$File,[switch]$Json)\nWrite-Output 'not json'\n", encoding="utf-8"
    )
    assert "overlap-unparseable" in unresolved(run_gate(junk, state_dir=state))


def test_an_unwritable_throttle_reports_anyway(tmp_path: Path) -> None:
    """The noise-suppressor must fail toward NOISE.

    If it failed toward quiet, a coordination directory that could not be written would restore the
    exact silent-allow this whole change removes -- and it would do it invisibly.
    """
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory", encoding="utf-8")
    unwritable = blocker / "state"  # cannot be created: its parent is a file
    missing = tmp_path / "does-not-exist.ps1"
    assert run_gate(missing, state_dir=unwritable) is not None
    assert run_gate(missing, state_dir=unwritable) is not None, (
        "must not go quiet when it cannot stamp"
    )


# --------------------------------------------------------------------------------- installer


def run_installer(settings: Path, *extra: str) -> str:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-SettingsPath",
            str(settings),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture
def settings(tmp_path: Path) -> Path:
    p = tmp_path / "settings.json"
    p.write_text(
        json.dumps(
            {
                "theme": "dark",
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    return p


def load(settings: Path) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(settings.read_text(encoding="utf-8-sig"))
    return parsed


def test_install_wires_both_hooks(settings: Path) -> None:
    run_installer(settings)
    d = load(settings)
    assert "SessionStart" in d["hooks"]
    matchers = [g.get("matcher") for g in d["hooks"]["PreToolUse"]]
    assert "Edit|Write|MultiEdit|NotebookEdit" in matchers


def test_install_preserves_unrelated_hooks_and_settings(settings: Path) -> None:
    """User settings is shared with other tooling AND edited by sibling sessions. Clobbering it is
    the failure that costs the most, because a bad write disables every setting silently."""
    run_installer(settings)
    d = load(settings)
    assert d["theme"] == "dark"
    cmds = [g["hooks"][0]["command"] for g in d["hooks"]["PreToolUse"]]
    assert any("echo other" in c for c in cmds), "pre-existing hook was dropped"


def test_install_is_idempotent(settings: Path) -> None:
    run_installer(settings)
    first = load(settings)
    run_installer(settings)
    second = load(settings)
    assert first == second, "re-install duplicated or altered entries"


def test_uninstall_removes_only_our_entries(settings: Path) -> None:
    run_installer(settings)
    run_installer(settings, "-Uninstall")
    d = load(settings)
    assert "SessionStart" not in d["hooks"]
    cmds = [g["hooks"][0]["command"] for g in d["hooks"]["PreToolUse"]]
    assert cmds == ["echo other"]
    assert d["theme"] == "dark"


def test_status_reports_installed_state(settings: Path) -> None:
    assert "missing" in run_installer(settings, "-Status")
    run_installer(settings)
    assert "INSTALLED" in run_installer(settings, "-Status")


def shim_for(settings: Path, matcher_prefix: str, tmp_path: Path, name: str) -> Path:
    cmd = next(
        g["hooks"][0]["command"]
        for g in load(settings)["hooks"]["PreToolUse"]
        if g.get("matcher", "").startswith(matcher_prefix)
    )
    p = tmp_path / name
    p.write_text(cmd, encoding="utf-8")
    return p


def test_shim_runs_the_primary_checkouts_script_not_the_worktrees(
    settings: Path, tmp_path: Path
) -> None:
    """A worktree on a branch that predates a coordination change has none of the scripts.

    Measured: a cwd-resolved shim found nothing there and exited silently -- no banner, no gate, and
    no indication either was missing. Coordination is infrastructure and must be uniform, so the shim
    resolves the PRIMARY checkout (which tracks main) rather than whatever branch the caller is on.
    """
    primary = tmp_path / "primary"
    primary.mkdir()
    _git_init(primary)
    # Only the PRIMARY gets a gate script; the worktree deliberately does not have one.
    (primary / "scripts" / "hooks").mkdir(parents=True)
    (primary / "scripts" / "hooks" / "collision_gate.ps1").write_text(
        "Write-Output 'PRIMARY-SCRIPT-RAN'\n", encoding="utf-8"
    )
    wt = tmp_path / "old-branch-wt"
    subprocess.run(
        ["git", "-C", str(primary), "worktree", "add", "-q", "-b", "old", str(wt)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert not (wt / "scripts" / "hooks" / "collision_gate.ps1").exists()

    run_installer(settings)
    shim = shim_for(settings, "Edit", tmp_path, "shim.ps1")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(shim)],
        cwd=str(wt),
        input=json.dumps({"tool_name": "Edit", "tool_input": {"file_path": "x.py"}}),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert "PRIMARY-SCRIPT-RAN" in proc.stdout, (
        f"shim did not reach the primary checkout's script: {proc.stdout!r} {proc.stderr!r}"
    )


def _git_init(repo: Path) -> None:
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    (repo / "f.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "f.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "init"], check=True, capture_output=True
    )


def test_installed_shim_is_inert_outside_a_git_repo(settings: Path, tmp_path: Path) -> None:
    """User settings are global: this hook runs in every unrelated project on the machine and must
    do nothing there rather than erroring on each tool call."""
    run_installer(settings)
    shim_cmd = next(
        g["hooks"][0]["command"]
        for g in load(settings)["hooks"]["PreToolUse"]
        if g.get("matcher", "").startswith("Edit")
    )
    shim = tmp_path / "shim.ps1"
    shim.write_text(shim_cmd, encoding="utf-8")
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(shim)],
        cwd=str(outside),
        input=json.dumps({"tool_name": "Edit", "tool_input": {"file_path": "x.py"}}),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "", "shim produced output outside a repo"
