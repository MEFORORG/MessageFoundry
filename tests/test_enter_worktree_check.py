# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/worktree/enter-check.ps1 and its PreToolUse hook auto-allow only a SAFE worktree (ADR 0212).

Each test builds a fleet repository with its own bare origin, and a temp root laid out the way the
harness lays out a session's scratchpad: ``<temp>/claude/<project>/<session>/scratchpad/``. The
scripts run from a sandbox copy (tests/_fake_gh.py) with a fake gh first on PATH, so the kill
switch is read from a state file and the real repository variable is never touched.

Every UNSAFE case below is one check's own positive control: the layout differs from the SAFE one
in exactly the way that check exists to catch.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests._fake_gh import ROOT, Sandbox, make_sandbox

CHECK = ROOT / "scripts" / "worktree" / "enter-check.ps1"
HOOK = ROOT / "scripts" / "hooks" / "enter-worktree-check.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")

SID = "0b6f3a1e-5c2d-4e8f-9a7b-1c2d3e4f5a6b"
OTHER_SID = "9f8e7d6c-5b4a-4321-8fed-cba987654321"


def _git(*args: str, cwd: Path) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    proc = subprocess.run(
        ["git", "-c", f"core.hooksPath={cwd.anchor}nonexistent-hooks", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, (args, proc.stdout, proc.stderr)
    return proc.stdout.strip()


def _make_repo(base: Path, name: str) -> Path:
    """A primary checkout with a bare origin whose main holds a `.claude/settings.json`."""
    origin = base / f"{name}-origin.git"
    _git("init", "-q", "--bare", "-b", "main", str(origin), cwd=base)
    repo = base / name
    _git("init", "-q", "-b", "main", str(repo), cwd=base)
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "init", cwd=repo)
    _git("remote", "add", "origin", str(origin), cwd=repo)
    _git("push", "-q", "origin", "main", cwd=repo)
    _git("fetch", "-q", "origin", cwd=repo)
    return repo


@dataclass
class Fleet:
    sb: Sandbox
    base: Path
    engine: Path
    temp: Path
    home: Path

    def scratch(self, sid: str = SID, project: str = "proj") -> Path:
        d = self.temp / "claude" / project / sid / "scratchpad"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def add_worktree(self, path: Path, repo: Path | None = None) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        _git("worktree", "add", "-q", "--detach", str(path), "origin/main", cwd=repo or self.engine)
        return path

    def own_wt(self) -> Path:
        """The SAFE layout: a linked worktree in this session's own scratchpad."""
        return self.add_worktree(self.scratch() / "eng-main")

    def git_dir(self, wt: Path) -> Path:
        return Path(_git("rev-parse", "--absolute-git-dir", cwd=wt))

    def check(
        self,
        path: Path | str,
        sid: str = SID,
        cwd: Path | None = None,
        *,
        fleet: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        # One repository: `pwsh -File` binds `a,b` as ONE string, not an array.
        return self.sb.run(
            CHECK,
            "-Path",
            str(path),
            "-SessionId",
            sid,
            "-SessionCwd",
            str(cwd or self.home),
            "-FleetRepos",
            str(fleet or self.engine),
            "-TempRoot",
            str(self.temp),
        )

    def hook(self, payload: object | str) -> subprocess.CompletedProcess[str]:
        stdin = payload if isinstance(payload, str) else json.dumps(payload)
        return self.sb.run(
            HOOK, "-FleetRepos", str(self.engine), "-TempRoot", str(self.temp), stdin=stdin
        )


@pytest.fixture
def fleet(tmp_path: Path) -> Fleet:
    sb = make_sandbox(tmp_path)
    shutil.copytree(ROOT / "scripts" / "worktree", sb.repo / "scripts" / "worktree")
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    base = tmp_path / "fleet"
    base.mkdir()
    engine = _make_repo(base, "engine")
    temp = tmp_path / "temp"
    temp.mkdir()
    f = Fleet(sb=sb, base=base, engine=engine, temp=temp, home=base / "home")
    # The session's own cwd: a linked worktree, never the primary (check d).
    f.add_worktree(f.home)
    return f


def _verdict(proc: subprocess.CompletedProcess[str]) -> str:
    lines = proc.stdout.splitlines()
    return lines[0] if lines else ""


def assert_safe(proc: subprocess.CompletedProcess[str]) -> None:
    assert proc.returncode == 0 and _verdict(proc) == "SAFE", (proc.stdout, proc.stderr)


def _failed(proc: subprocess.CompletedProcess[str]) -> list[str]:
    """The `x.` letters of the checks an UNSAFE run names."""
    return [ln.strip()[:2] for ln in proc.stdout.splitlines()[1:]]


def assert_unsafe(proc: subprocess.CompletedProcess[str], check: str) -> None:
    assert proc.returncode == 1 and _verdict(proc) == "UNSAFE", (proc.stdout, proc.stderr)
    assert f"{check}." in _failed(proc), (check, proc.stdout)


# ---------------------------------------------------------------- the one SAFE layout


def test_own_scratchpad_linked_worktree_is_safe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    assert_safe(fleet.check(wt))


def test_the_repository_s_own_seat_markers_do_not_count_against_f(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    (wt / ".claude" / "seat.local.txt").write_text("builder\n", encoding="utf-8")
    (wt / ".claude" / "ROLE.local.md").write_text("# card\n", encoding="utf-8")
    assert_safe(fleet.check(wt))


# ---------------------------------------------------------------- a. canonical path


@pytest.mark.skipif(sys.platform != "win32", reason="the extended-length prefix is a Windows form")
def test_an_extended_length_path_is_refused(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    assert_unsafe(fleet.check("\\\\?\\" + str(wt)), "a")


def test_a_missing_path_is_unsafe(fleet: Fleet) -> None:
    assert_unsafe(fleet.check(fleet.scratch() / "nothing-here"), "a")


# ---------------------------------------------------------------- b. a linked fleet worktree


def test_the_primary_is_unsafe(fleet: Fleet) -> None:
    assert_unsafe(fleet.check(fleet.engine), "b")


def test_a_non_fleet_repository_s_worktree_is_unsafe(fleet: Fleet) -> None:
    stranger = _make_repo(fleet.base, "stranger")
    wt = fleet.add_worktree(fleet.scratch() / "stranger-wt", repo=stranger)
    assert_unsafe(fleet.check(wt), "b")


def test_a_plain_directory_in_the_scratchpad_is_unsafe(fleet: Fleet) -> None:
    d = fleet.scratch() / "not-a-worktree"
    d.mkdir()
    assert_unsafe(fleet.check(d), "b")


# ---------------------------------------------------------------- c. ownership


def test_another_session_s_scratchpad_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.add_worktree(fleet.scratch(OTHER_SID) / "eng-main")
    assert_unsafe(fleet.check(wt), "c")


def test_an_extra_project_segment_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.add_worktree(fleet.temp / "claude" / "x" / "y" / SID / "scratchpad" / "eng-main")
    assert_unsafe(fleet.check(wt), "c")


def test_the_own_session_id_deeper_in_another_scratchpad_is_unsafe(fleet: Fleet) -> None:
    """The id must sit at its one position; a `-like "*<id>*"` match would take this path."""
    wt = fleet.add_worktree(fleet.scratch(OTHER_SID) / SID / "eng-main")
    assert_unsafe(fleet.check(wt), "c")


def test_a_claude_worktrees_tree_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.add_worktree(fleet.engine / ".claude" / "worktrees" / "agent-x")
    assert_unsafe(fleet.check(wt), "c")


def test_a_link_inside_the_own_scratchpad_to_another_worktree_is_unsafe(fleet: Fleet) -> None:
    elsewhere = fleet.add_worktree(fleet.base / "elsewhere")
    link = fleet.scratch() / "looks-mine"
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(elsewhere)],
            check=True,
            capture_output=True,
            timeout=30,
        )
    else:
        link.symlink_to(elsewhere, target_is_directory=True)
    proc = fleet.check(link)
    assert_unsafe(proc, "c")
    # The link resolved to its target, which IS a fleet worktree: only ownership refused it.
    assert "b." not in _failed(proc), proc.stdout


def test_a_non_uuid_session_id_is_unsafe_even_where_its_directory_exists(fleet: Fleet) -> None:
    """The segment matches here, so only the session-id shape check refuses it."""
    wt = fleet.add_worktree(fleet.scratch("not-a-session") / "eng-main")
    assert_unsafe(fleet.check(wt, sid="not-a-session"), "c")


@pytest.mark.parametrize("sid", ["-", "..", "proj", SID.upper() + "x"])
def test_a_session_id_that_is_not_a_uuid_is_unsafe(fleet: Fleet, sid: str) -> None:
    wt = fleet.own_wt()
    assert_unsafe(fleet.check(wt, sid=sid), "c")


# ---------------------------------------------------------------- d. not in a primary


def test_a_session_in_the_primary_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    assert_unsafe(fleet.check(wt, cwd=fleet.engine), "d")
    (fleet.engine / "docs").mkdir()
    assert_unsafe(fleet.check(wt, cwd=fleet.engine / "docs"), "d")


# ---------------------------------------------------------------- e. locked or mid-operation


def test_a_locked_worktree_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    _git("worktree", "lock", str(wt), cwd=fleet.engine)
    assert_unsafe(fleet.check(wt), "e")


@pytest.mark.parametrize("marker", ["rebase-merge", "MERGE_HEAD", "BISECT_LOG"])
def test_an_operation_in_progress_is_unsafe(fleet: Fleet, marker: str) -> None:
    wt = fleet.own_wt()
    state = fleet.git_dir(wt) / marker
    if marker.startswith("rebase"):
        state.mkdir()
    else:
        state.write_text("0" * 40 + "\n", encoding="utf-8")
    assert_unsafe(fleet.check(wt), "e")


# ---------------------------------------------------------------- f. branch provenance


def test_a_branch_whose_settings_differ_from_origin_main_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    (wt / ".claude" / "settings.json").write_text('{"hooks": {}}\n', encoding="utf-8")
    _git("commit", "-q", "-am", "own hooks", cwd=wt)
    assert_unsafe(fleet.check(wt), "f")


def test_a_branch_that_adds_mcp_json_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    (wt / ".mcp.json").write_text("{}\n", encoding="utf-8")
    _git("add", ".mcp.json", cwd=wt)
    _git("commit", "-q", "-m", "own mcp", cwd=wt)
    assert_unsafe(fleet.check(wt), "f")


def test_an_untracked_settings_local_file_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    (wt / ".claude" / "settings.local.json").write_text("{}\n", encoding="utf-8")
    assert_unsafe(fleet.check(wt), "f")


# ---------------------------------------------------------------- g. kill switch


@pytest.mark.parametrize("state", [{"variables": {"MEFOR_AFK_KILL": "on"}}, {"fail": True}])
def test_the_kill_switch_not_off_is_unsafe(fleet: Fleet, state: dict[str, object]) -> None:
    wt = fleet.own_wt()
    fleet.sb.set_state(**state)
    assert_unsafe(fleet.check(wt), "g")


# ---------------------------------------------------------------- h. local disable file


def test_the_local_off_file_is_unsafe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    off = fleet.engine / ".git" / "mefor-coord" / "enter-check" / "OFF"
    off.parent.mkdir(parents=True)
    off.write_text("", encoding="utf-8")
    assert_unsafe(fleet.check(wt), "h")


# ---------------------------------------------------------------- faults fail closed


def test_an_exception_mid_check_is_unsafe(fleet: Fleet) -> None:
    """A fleet repository that is present but will not list throws inside check b."""
    wt = fleet.own_wt()
    broken = fleet.base / "not-a-repo"
    broken.mkdir()
    proc = fleet.check(wt, fleet=broken)
    assert_unsafe(proc, "b")
    assert "worktree list could not be read" in proc.stdout


def test_no_sanitiser_is_unsafe_with_a_fixed_reason(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    (fleet.sb.repo / "scripts" / "hooks" / "worktree_gate.ps1").unlink()
    proc = fleet.check(wt)
    assert proc.returncode == 1 and _verdict(proc) == "UNSAFE", proc.stdout
    assert "sanitiser could not be loaded" in proc.stdout
    assert str(wt) not in proc.stdout


def test_reasons_are_folded_onto_one_line_each(fleet: Fleet) -> None:
    proc = fleet.check(str(fleet.scratch() / "x") + "\nb. forged")
    assert _verdict(proc) == "UNSAFE"
    assert not any(ln.startswith("b. forged") for ln in proc.stdout.splitlines()), proc.stdout


# ---------------------------------------------------------------- the hook


def _payload(fleet: Fleet, path: Path) -> dict[str, object]:
    return {
        "session_id": SID,
        "cwd": str(fleet.home),
        "hook_event_name": "PreToolUse",
        "tool_name": "EnterWorktree",
        "tool_input": {"path": str(path)},
    }


def _decision(proc: subprocess.CompletedProcess[str]) -> dict[str, object] | None:
    assert proc.returncode == 0, proc.stderr
    assert "deny" not in proc.stdout, proc.stdout
    if not proc.stdout.strip():
        return None
    out = json.loads(proc.stdout)
    spec: dict[str, object] = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    return spec


def test_the_hook_allows_on_safe(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    spec = _decision(fleet.hook(_payload(fleet, wt)))
    assert spec is not None and spec["permissionDecision"] == "allow", spec


def test_the_hook_gives_no_decision_on_unsafe(fleet: Fleet) -> None:
    wt = fleet.add_worktree(fleet.scratch(OTHER_SID) / "eng-main")
    spec = _decision(fleet.hook(_payload(fleet, wt)))
    assert spec is not None and "permissionDecision" not in spec, spec
    assert "did not auto-allow" in str(spec["additionalContext"])
    assert "c." in str(spec["additionalContext"])


def test_the_hook_gives_no_decision_when_the_kill_switch_is_on(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    fleet.sb.set_state(variables={"MEFOR_AFK_KILL": "on"})
    spec = _decision(fleet.hook(_payload(fleet, wt)))
    assert spec is not None and "permissionDecision" not in spec, spec


@pytest.mark.parametrize(
    "stdin",
    [
        "",
        "not json",
        "[]",
        json.dumps({"session_id": SID, "tool_input": {"name": "fresh"}}),
        json.dumps({"session_id": SID, "tool_input": {"path": ""}}),
    ],
)
def test_the_hook_is_silent_without_a_path(fleet: Fleet, stdin: str) -> None:
    assert _decision(fleet.hook(stdin)) is None


def test_the_hook_is_silent_without_a_cwd(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    payload = _payload(fleet, wt)
    del payload["cwd"]
    assert _decision(fleet.hook(payload)) is None


def test_the_hook_gives_no_decision_when_the_check_is_missing(fleet: Fleet) -> None:
    wt = fleet.own_wt()
    (fleet.sb.repo / "scripts" / "worktree" / "enter-check.ps1").unlink()
    assert _decision(fleet.hook(_payload(fleet, wt))) is None


def test_the_hook_is_wired_for_enter_worktree_only() -> None:
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    groups = [
        g
        for g in settings["hooks"]["PreToolUse"]
        if any(
            str(a).endswith("/enter-worktree-check.ps1")
            for h in g["hooks"]
            for a in h.get("args", [])
        )
    ]
    assert [g["matcher"] for g in groups] == ["EnterWorktree"], groups


def test_the_marker_allow_list_names_what_the_hooks_write() -> None:
    """Check f's two exempt files are the ones role-card-inject.ps1 writes, read from its source.

    A rename there would otherwise turn every seated worktree UNSAFE, and the SAFE test above
    writes the same literals itself, so it cannot see the drift.
    """
    writer = (ROOT / "scripts" / "hooks" / "role-card-inject.ps1").read_text(encoding="utf-8")
    written = {
        m.group(2)
        for m in re.finditer(r"^\$(MarkerRelPath|RoleCopyRelPath) = '([^']+)'", writer, re.M)
    }
    check = CHECK.read_text(encoding="utf-8")
    m = re.search(r"^\$localMarkers = @\(([^)]*)\)", check, re.M)
    assert m is not None, "enter-check.ps1 no longer declares $localMarkers"
    assert set(re.findall(r"'([^']+)'", m.group(1))) == written, (m.group(1), written)
