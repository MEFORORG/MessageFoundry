# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Execution tests for ``scripts/worktree/remove.ps1 -Path`` and ``-List`` (vault BACKLOG #1017).

``-Path`` is the CHECKED route the worktree gate's rule 3d names: a session may run it against a
finished worktree it is not standing in, and the script decides. So every refusal here is a
protection the gate used to provide by refusing outright, and each one is driven for real.

Three rules, the first two inherited from ``tests/test_worktree_remove.py``:

* **No test drives the real checkout.** The REAL script runs as a subprocess with ``-RepoRoot``
  pointing at a synthetic repo under ``tmp_path``.
* **A refusal is paired with the run that is supposed to succeed.** A non-zero exit alone cannot
  tell "the guard fired" from "the script is broken", so each refusal asserts its own message and is
  followed by a control on the same tree where one is possible.
* **The session registry is a fixture.** The occupancy fence reads ``USERPROFILE``, so every run
  points it at a throwaway home. No run here reads this machine's real registry.

Windows only, like the suite it sits beside: the registry lookup is keyed on ``USERPROFILE``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
SCRIPT = _REPO / "scripts" / "worktree" / "remove.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="remove.ps1 is a PowerShell script driven through pwsh on Windows",
)

# Every GIT_* variable goes: run from inside a git hook, GIT_DIR or GIT_WORK_TREE would point these
# children at the REAL repository instead of the throwaway one.
_ENV = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}

# What the fixture repository ignores. `__pycache__` is written WITHOUT a trailing slash so it also
# matches a FILE of that name, which is one of the two cases the exception must not swallow.
_GITIGNORE = "\n".join(
    [
        ".venv/",
        "node_modules/",
        # Un-ignored again in one place, so a test can make an UNTRACKED directory of a tolerated name.
        "!vendor/node_modules/",
        "__pycache__",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        "*.log",
        "out/",
        "",
    ]
)


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=_ENV
    )
    return proc.stdout


#: remove.ps1 and the two scripts it dot-sources. A test that runs a COPY of the script needs all
#: three. One list, shared with tests/test_worktree_gate_removal_route.py.
REAL_SCRIPTS = (
    "scripts/worktree/remove.ps1",
    "scripts/coord/occupancy.ps1",
    "scripts/coord/session-registry.ps1",
)


def settle_worktrees(primary: Path) -> None:
    """Date every linked worktree's own git state two days back, as if nothing had touched it since.

    ``-Path`` refuses a tree whose git directory was written to inside its quiet period, and a
    fixture tree is seconds old. This stands in for the passing of time, for every test that is
    about some OTHER check. The quiet period itself is driven by the tests that pass
    ``settle=False``, which leave a tree as fresh as it really is.
    """
    then = time.time() - 2 * 24 * 3600
    admin = primary / ".git" / "worktrees"
    if not admin.is_dir():
        return
    for tree in admin.iterdir():
        for state in [*tree.iterdir(), tree / "logs" / "HEAD"]:
            if state.is_file():
                os.utime(state, (then, then))


def write_registry(root: Path, home: Path, *occupied: Path) -> Path:
    """Make ``home`` a USERPROFILE whose session registry is readable, and return it.

    It always holds one record OUTSIDE every worktree, so the fence has something to examine. Each
    path in ``occupied`` adds a record with no pid. That fences as UNREADABLE, which is a veto, so
    the record reads as a session in that directory.
    """
    sessions = home / ".claude" / "sessions"
    shutil.rmtree(sessions, ignore_errors=True)
    sessions.mkdir(parents=True)
    elsewhere = root / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    (sessions / "1.json").write_text(
        json.dumps({"cwd": str(elsewhere), "pid": 1, "sessionId": "clear", "startedAt": 0}),
        encoding="utf-8",
    )
    for i, cwd in enumerate(occupied, start=2):
        (sessions / f"{i}.json").write_text(
            json.dumps({"cwd": str(cwd), "sessionId": f"in-{i}"}), encoding="utf-8"
        )
    return home


class Rig:
    """A synthetic primary at ``<root>/Repo`` plus a throwaway home holding a session registry."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "Repo"
        self.home = root / "home"

    def scratch(self, name: str) -> Path:
        """The shape a harness scratchpad has, which no ``-Name`` can spell."""
        return self.root / "Temp" / "claude" / "slug" / "0f0e" / "scratchpad" / name

    def add(self, path: Path, *extra: str) -> Path:
        args = extra or ("-b", path.name)
        _git(self.primary, "worktree", "add", "-q", *args, str(path))
        return path

    def is_registered(self, path: Path) -> bool:
        out = _git(self.primary, "worktree", "list", "--porcelain")
        listed = {
            ln[len("worktree ") :].replace("\\", "/").rstrip("/").lower()
            for ln in out.splitlines()
            if ln.startswith("worktree ")
        }
        return str(path).replace("\\", "/").rstrip("/").lower() in listed

    def branch_exists(self, name: str) -> bool:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(self.primary),
                "rev-parse",
                "--verify",
                "--quiet",
                f"refs/heads/{name}",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=_ENV,
        )
        return proc.returncode == 0

    def registry(self, *occupied: Path, home: Path | None = None) -> Path:
        return write_registry(self.root, home or self.home, *occupied)

    def run(
        self,
        *args: str,
        cwd: Path | None = None,
        home: Path | None = None,
        script: Path | None = None,
        repo_root: Path | None = None,
        extra: dict[str, str] | None = None,
        settle: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if settle:
            settle_worktrees(self.primary)
        argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script or SCRIPT)]
        if script is None or repo_root is not None:
            argv += ["-RepoRoot", str(repo_root or self.primary)]
        return subprocess.run(
            [*argv, *args],
            cwd=str(cwd or self.root),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            env={**_ENV, "USERPROFILE": str(home or self.home), **(extra or {})},
        )


def _out(proc: subprocess.CompletedProcess[str]) -> str:
    return proc.stdout + proc.stderr


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    r = Rig(tmp_path)
    r.primary.mkdir()
    _git(r.primary, "init", "-q", "-b", "main")
    _git(r.primary, "config", "user.email", "t@example.invalid")
    _git(r.primary, "config", "user.name", "t")
    _git(r.primary, "config", "commit.gpgsign", "false")
    (r.primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    (r.primary / ".gitignore").write_text(_GITIGNORE, encoding="utf-8")
    _git(r.primary, "add", "seed.txt", ".gitignore")
    _git(r.primary, "commit", "-q", "-m", "seed")
    seed = _git(r.primary, "rev-parse", "HEAD").strip()
    _git(r.primary, "update-ref", "refs/remotes/origin/main", seed)
    r.registry()
    return r


def _common(rig: Rig) -> Path:
    return Path(
        _git(rig.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    )


# --- the one thing it is for ----------------------------------------------------------------------


def _claim(rig: Rig, key: str, holder: Path) -> Path:
    claims = _common(rig) / "mefor-coord" / "claims"
    claims.mkdir(parents=True, exist_ok=True)
    claim = claims / f"{key}.json"
    claim.write_text(
        json.dumps({"key": key, "worktree": str(holder).replace("\\", "/"), "note": "t"}),
        encoding="utf-8",
    )
    return claim


def test_path_removes_a_clean_tree_no_name_can_spell_and_leaves_its_branch(rig: Rig) -> None:
    wt = rig.add(rig.scratch("done"))
    tip = _commit(wt, "finished.txt")
    # A claim held by ANOTHER tree is not this tree's, and must neither block the run nor be touched.
    elsewhere = rig.add(rig.scratch("other-work"))
    theirs = _claim(rig, "9002", elsewhere)

    # No -Name can spell this path: tests/test_worktree_remove.py pins that -Name looks only at the
    # <repo>-<name> sibling. That is the gap this route fills.
    proc = rig.run("-Path", str(wt))

    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()
    assert not rig.is_registered(wt)
    # "Removes the directory, never the branch" is the property the gate text promises.
    assert rig.branch_exists("done")
    assert _git(rig.primary, "rev-parse", "refs/heads/done").strip() == tip
    assert "Branch 'done' was not touched" in proc.stdout
    # The fixture has no remote, so the one commit is on the local branch alone, and the run says so.
    assert "1 commit(s) on 'done' are on no remote-tracking ref" in proc.stdout, proc.stdout
    assert theirs.exists(), "a claim held by a different, living worktree was released"
    assert elsewhere.exists()


# --- in use, by a signal that does not depend on where a session was launched ---------------------


def test_a_tree_that_still_holds_a_claim_is_refused_and_its_claim_is_left_alone(rig: Rig) -> None:
    """A claim crosses the boundary the session fence cannot: it names the WORKTREE that took a key,
    whoever launched the session. So a held claim refuses, -Force included, and is never released
    by this route. Once the claim is gone the same call removes the tree."""
    wt = rig.add(rig.scratch("claimed"))
    claim = _claim(rig, "9001", wt)

    proc = rig.run("-Path", str(wt), "-Force")

    assert proc.returncode != 0
    assert "still holds 1 work claim(s): 9001" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)
    assert claim.exists(), "the refusal released the claim it refused on"

    # A claim file that will not parse might name this tree, so it refuses too.
    claim.write_text("{ half-written", encoding="utf-8")
    proc = rig.run("-Path", str(wt), "-Force")
    assert proc.returncode != 0
    assert "could not be parsed" in _out(proc) and "9001.json" in _out(proc), _out(proc)
    assert wt.exists()

    # A record that parses but names no worktree cannot be ruled out either.
    claim.write_text(json.dumps({"key": "9001", "note": "no holder recorded"}), encoding="utf-8")
    proc = rig.run("-Path", str(wt), "-Force")
    assert proc.returncode != 0
    assert "9001.json" in _out(proc), _out(proc)
    assert wt.exists()

    claim.unlink()
    assert rig.run("-Path", str(wt)).returncode == 0
    assert not wt.exists()


def test_a_tree_git_wrote_to_recently_is_refused_until_it_has_been_quiet(rig: Rig) -> None:
    """A commit rewrites files in the tree's own git directory. Inside the quiet period nothing can
    tell whether whatever made it has finished, so the run refuses, -Force included."""
    wt = rig.add(rig.scratch("warm"))
    _commit(wt, "just-now.txt")

    proc = rig.run("-Path", str(wt), "-Force", settle=False)

    assert proc.returncode != 0
    assert "Target was active recently" in _out(proc), _out(proc)
    assert "quiet period" in _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    # Control: the same tree and the same call, once its git state is two days old.
    proc = rig.run("-Path", str(wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_live_session_recorded_in_a_parent_tree_does_not_clear_a_sibling_it_is_working_in(
    rig: Rig,
) -> None:
    """THE CASE THE SESSION FENCE CANNOT SEE, staged for real. A session is launched in a tree under
    .claude/worktrees and works in a SIBLING tree: a subagent Builder is recorded exactly this way.
    Its record is LIVE, with a real running process, and it names the parent tree, not the sibling.

    The fence therefore finds nobody in the sibling. What refuses is the claim, and with the claim
    gone, the fresh git state. Only when both are absent does the tree go, which is the last step
    here and the proof that the fence alone would have let it go from the start.
    """
    parent = rig.add(rig.primary / ".claude" / "worktrees" / "parent")
    sibling = rig.add(rig.primary.parent / "Repo-b191")
    _commit(sibling, "built.txt")
    claim = _claim(rig, "9191", sibling)

    # THE BASE INTERPRETER, NOT sys.executable. In a Windows virtual environment sys.executable is a
    # launcher stub that starts the real interpreter as a child, and kill() below would end the stub
    # and leave that child sleeping. Its cwd is the fixture root, so nothing here holds a checkout.
    interpreter = getattr(sys, "_base_executable", None) or sys.executable
    session = subprocess.Popen(
        [interpreter, "-c", "import time; time.sleep(300)"], cwd=str(rig.root)
    )
    try:
        sessions = rig.home / ".claude" / "sessions"
        (sessions / f"{session.pid}.json").write_text(
            json.dumps(
                {
                    "cwd": str(parent),
                    "pid": session.pid,
                    "sessionId": "live-in-parent",
                    "startedAt": int(time.time() * 1000),
                }
            ),
            encoding="utf-8",
        )

        # Control for "the record is live and the fence is working": the parent tree itself would
        # be refused as occupied, if this route reached it. It does not, so the fence is asked about
        # a reachable tree by moving the record's cwd into the sibling for one run.
        in_sibling = rig.root / "occupied-home"
        occupied = in_sibling / ".claude" / "sessions"
        occupied.mkdir(parents=True)
        (occupied / f"{session.pid}.json").write_text(
            json.dumps(
                {
                    "cwd": str(sibling),
                    "pid": session.pid,
                    "sessionId": "live-in-sibling",
                    "startedAt": int(time.time() * 1000),
                }
            ),
            encoding="utf-8",
        )
        seen = rig.run("-Path", str(sibling), home=in_sibling, settle=False)
        assert seen.returncode != 0
        assert "Target is occupied" in _out(seen) and "LIVE" in _out(seen), _out(seen)

        # The real shape: recorded in the parent. The fence passes; the claim refuses.
        proc = rig.run("-Path", str(sibling), settle=False)
        assert proc.returncode != 0
        assert "Target is occupied" not in _out(proc), _out(proc)
        assert "still holds 1 work claim(s): 9191" in _out(proc), _out(proc)

        # No claim, as for work that was never claimed: the fresh git state refuses.
        claim.unlink()
        proc = rig.run("-Path", str(sibling), settle=False)
        assert proc.returncode != 0
        assert "Target was active recently" in _out(proc), _out(proc)
        assert sibling.exists() and rig.is_registered(sibling)
        assert (sibling / "built.txt").is_file()

        # Neither signal, and the session still LIVE in the parent: the tree goes. This is what the
        # fence alone decides, and it is why the two signals above exist.
        proc = rig.run("-Path", str(sibling))
        assert proc.returncode == 0, _out(proc)
        assert not sibling.exists()
    finally:
        session.kill()
        session.wait(timeout=30)


# --- what it must never be pointed at -------------------------------------------------------------


def test_path_refuses_anything_that_is_not_a_registered_linked_worktree(rig: Rig) -> None:
    plain = rig.root / "plain"
    plain.mkdir()
    (plain / "keep.txt").write_text("keep\n", encoding="utf-8")
    other = rig.root / "Other"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    _git(other, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q",
         "--allow-empty", "-m", "init")  # fmt: skip
    foreign = rig.root / "Other-x"
    _git(other, "worktree", "add", "-q", "-b", "x", str(foreign))

    for target, needle in (
        (plain, "not a registered linked worktree"),
        (foreign, "not a registered linked worktree"),
        (rig.primary, "is the primary checkout"),
    ):
        proc = rig.run("-Path", str(target), "-Force")
        assert proc.returncode != 0, (target, proc.stdout)
        assert needle in _out(proc), (target, _out(proc))
        assert target.exists(), target
    assert (plain / "keep.txt").is_file()

    # Positive control: a registered linked worktree at the same depth is removed.
    mine = rig.add(rig.root / "mine")
    proc = rig.run("-Path", str(mine))
    assert proc.returncode == 0, _out(proc)
    assert not mine.exists()


def test_the_unsafe_spellings_and_inherited_git_variables_are_refused(rig: Rig) -> None:
    """Five refusals on one tree, then the run that removes it. The control at the end is what makes
    each refusal above mean "this guard fired" and not "nothing can remove this tree"."""
    wt = rig.add(rig.scratch("careful"))

    dotted = rig.run("-Path", f"{wt}.", "-Force")
    assert dotted.returncode != 0
    assert "ends in a dot or a space" in _out(dotted)

    redirected = rig.run("-Path", str(wt), extra={"GIT_DIR": str(rig.primary / ".git")})
    assert redirected.returncode != 0
    assert "GIT_DIR is set" in _out(redirected)

    inside = rig.run("-Path", ".", cwd=wt)
    assert inside.returncode != 0
    assert "standing inside" in _out(inside)

    # -Path does not take -DeleteBranch at all, so the branch cannot go by this route.
    with_branch = rig.run("-Path", str(wt), "-DeleteBranch")
    assert with_branch.returncode != 0
    # The binder's own message is not asserted: its wording follows the host's language. That the
    # run failed and the tree and branch are still there, asserted below, is the property.

    assert wt.exists() and rig.is_registered(wt)
    assert rig.branch_exists("careful")

    proc = rig.run("-Path", str(wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_copy_of_the_script_inside_the_target_refuses_to_remove_it(rig: Rig) -> None:
    wt = rig.add(rig.scratch("selfhost"))
    for rel in REAL_SCRIPTS:
        dest = wt / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_REPO / rel, dest)

    proc = rig.run("-Path", str(wt), "-Force", script=wt / "scripts" / "worktree" / "remove.ps1")

    assert proc.returncode != 0
    assert "lives inside" in _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    # Control: the same target and the same -Force, run from the copy OUTSIDE it.
    assert rig.run("-Path", str(wt), "-Force").returncode == 0
    assert not wt.exists()


def test_a_tree_under_claude_worktrees_is_not_reached_and_name_still_removes_the_overlap(
    rig: Rig,
) -> None:
    """The batch 184 decision, kept: the occupancy fence cannot see a subagent in a harness tree, so
    this route does not reach one. A clean tree and a clearing registry change nothing, and neither
    does -Force.

    The overlap is a sibling new.ps1 made BESIDE a linked worktree, which also sits under
    ``.claude/worktrees``. ``-Path`` refuses it like the rest; the copy of the script in that linked
    worktree still removes it by ``-Name``, which is the control here.
    """
    managed = rig.primary / ".claude" / "worktrees"
    foo = rig.add(managed / "foo")
    sibling = rig.add(managed / "foo-bar", "-b", "bar")

    for target in (foo, sibling):
        proc = rig.run("-Path", str(target), "-Force")
        assert proc.returncode != 0, _out(proc)
        assert "under .claude/worktrees" in _out(proc), _out(proc)
        assert target.exists() and rig.is_registered(target)

    by_name = rig.run("-Name", "bar", repo_root=foo)
    assert by_name.returncode == 0, _out(by_name)
    assert not sibling.exists()
    assert foo.exists()


def test_a_target_holding_another_registered_worktree_is_refused(rig: Rig) -> None:
    outer = rig.add(rig.scratch("outer"))
    inner = rig.add(outer / "inner")

    proc = rig.run("-Path", str(outer), "-Force")

    assert proc.returncode != 0
    assert "contains 1 other registered worktree" in _out(proc), _out(proc)
    assert outer.exists() and inner.exists() and rig.is_registered(inner)

    # Control: with the inner tree gone, the same target goes. The inner one is taken out with git
    # directly, because removing a clean tree by -Path is already pinned by the first test here.
    _git(rig.primary, "worktree", "remove", str(inner))
    assert rig.run("-Path", str(outer)).returncode == 0
    assert not outer.exists()


def test_a_locked_worktree_is_refused_until_it_is_unlocked(rig: Rig) -> None:
    wt = rig.add(rig.scratch("held"))
    _git(rig.primary, "worktree", "lock", "--reason", "in use", str(wt))

    proc = rig.run("-Path", str(wt), "-Force")

    assert proc.returncode != 0
    assert "is locked (in use)" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    _git(rig.primary, "worktree", "unlock", str(wt))
    assert rig.run("-Path", str(wt)).returncode == 0
    assert not wt.exists()


# --- commits the removal would leave in no ref ------------------------------------------------------


def _commit(wt: Path, name: str) -> str:
    (wt / name).write_text("work\n", encoding="utf-8")
    _git(wt, "add", "--", name)
    _git(wt, "commit", "-q", "-m", f"add {name}")
    return _git(wt, "rev-parse", "HEAD").strip()


def test_a_detached_head_holding_commits_no_ref_holds_is_refused_even_with_force(rig: Rig) -> None:
    wt = rig.add(rig.scratch("loose"), "--detach")
    tip = _commit(wt, "loose.txt")

    proc = rig.run("-Path", str(wt), "-Force")

    assert proc.returncode != 0
    assert "held by no ref" in _out(proc) and tip in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    # Control: once a branch holds the commit, the same call goes through and the commit is kept.
    _git(rig.primary, "branch", "keep-loose", tip)
    again = rig.run("-Path", str(wt), "-Force")
    assert again.returncode == 0, _out(again)
    assert not wt.exists()
    assert _git(rig.primary, "rev-parse", "keep-loose").strip() == tip


def test_a_commit_only_the_head_reflog_holds_is_refused_even_with_force(rig: Rig) -> None:
    """HEAD is back on its branch, so the detached-HEAD check reads clean. The commit made while
    detached is held by the worktree's HEAD reflog alone, and the removal deletes that reflog."""
    wt = rig.add(rig.scratch("wandered"))
    _git(wt, "checkout", "-q", "--detach")
    stray = _commit(wt, "stray.txt")
    _git(wt, "checkout", "-q", "wandered")
    assert _git(wt, "status", "--porcelain").strip() == ""
    assert _git(wt, "symbolic-ref", "--short", "HEAD").strip() == "wandered"

    proc = rig.run("-Path", str(wt), "-Force")

    assert proc.returncode != 0
    assert "HEAD reflog" in _out(proc) and stray in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    _git(rig.primary, "branch", "keep-stray", stray)
    again = rig.run("-Path", str(wt))
    assert again.returncode == 0, _out(again)
    assert not wt.exists()
    assert _git(rig.primary, "rev-parse", "keep-stray").strip() == stray


def test_a_commit_only_a_per_worktree_ref_holds_is_refused(rig: Rig) -> None:
    """``refs/worktree/*`` lives in the worktree's own admin directory and goes with it. The commit
    here was never HEAD, so neither the detached check nor the reflog check can see it, and the
    primary's ``--glob=refs/*`` reads the primary's copy of that namespace, not this tree's."""
    wt = rig.add(rig.scratch("pinned"))
    tree = _git(wt, "rev-parse", "HEAD^{tree}").strip()
    aside = _git(wt, "commit-tree", tree, "-p", "HEAD", "-m", "kept aside").strip()
    _git(wt, "update-ref", "refs/worktree/aside", aside)
    assert aside not in _git(wt, "reflog", "show", "--format=%H", "HEAD")

    proc = rig.run("-Path", str(wt), "-Force")

    assert proc.returncode != 0
    assert "per-worktree ref" in _out(proc) and aside in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    _git(rig.primary, "branch", "keep-aside", aside)
    again = rig.run("-Path", str(wt))
    assert again.returncode == 0, _out(again)
    assert not wt.exists()


# --- the occupancy fence -----------------------------------------------------------------------------


def test_an_occupied_target_and_an_unreadable_registry_both_refuse(rig: Rig) -> None:
    wt = rig.add(rig.scratch("busy"))

    occupied = rig.registry(wt / "sub", home=rig.root / "occupied-home")
    proc = rig.run("-Path", str(wt), "-Force", home=occupied)
    assert proc.returncode != 0
    assert "Target is occupied" in _out(proc), _out(proc)

    # UNREADABLE refuses: a record that will not parse, or no registry anywhere under the home.
    garbled = rig.root / "garbled-home"
    (garbled / ".claude" / "sessions").mkdir(parents=True)
    (garbled / ".claude" / "sessions" / "9.json").write_text("{ half-written", encoding="utf-8")
    nowhere = rig.root / "no-registry-home"
    nowhere.mkdir()
    for unreadable in (garbled, nowhere):
        proc = rig.run("-Path", str(wt), "-Force", home=unreadable)
        assert proc.returncode != 0, unreadable
        assert "Occupancy unknown" in _out(proc), (unreadable, _out(proc))
    assert wt.exists() and rig.is_registered(wt)

    # Control: the same target, with a registry that clears it.
    proc = rig.run("-Path", str(wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_readable_registry_with_no_records_clears_the_target(rig: Rig) -> None:
    """Manager decision, batch 184, ported with the route: every session exited cleanly, so the
    registry is readable and empty. Nobody is recorded in the target."""
    wt = rig.add(rig.scratch("idle"))
    empty = rig.root / "empty-home"
    (empty / ".claude" / "sessions").mkdir(parents=True)

    proc = rig.run("-Path", str(wt), home=empty)

    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_the_fence_is_on_path_only_so_name_still_runs_with_no_registry(rig: Rig) -> None:
    """The -Name tests in tests/test_worktree_remove.py set no USERPROFILE. A fence on -Name would
    refuse on every runner with no session registry, so it must stay off that route.

    The name is passed POSITIONALLY on purpose. ``remove.ps1 <name>`` bound before the script had
    parameter sets, and adding them dropped it once: this is the call that would have caught that.
    """
    sibling = rig.add(rig.primary.parent / "Repo-sib", "-b", "sib")
    nowhere = rig.root / "no-registry-home"
    nowhere.mkdir()

    proc = rig.run("sib", home=nowhere)

    assert proc.returncode == 0, _out(proc)
    assert not sibling.exists()


# --- what the removal would delete --------------------------------------------------------------------


def test_tracked_untracked_and_ignored_files_each_refuse_and_force_overrides(rig: Rig) -> None:
    wt = rig.add(rig.scratch("dirty"))

    ignored = wt / "run.log"
    ignored.write_text("ignored, and possibly the only copy\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0
    assert "!! run.log" in _out(proc) and "ignored files outside" in _out(proc), _out(proc)
    ignored.unlink()

    untracked = wt / "new-work.txt"
    untracked.write_text("not committed\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0
    assert "?? new-work.txt" in _out(proc), _out(proc)
    untracked.unlink()

    (wt / "seed.txt").write_text("modified\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0
    assert "seed.txt" in _out(proc) and "uncommitted changes" in _out(proc), _out(proc)
    assert (wt / "seed.txt").read_text(encoding="utf-8") == "modified\n"

    forced = rig.run("-Path", str(wt), "-Force")
    assert forced.returncode == 0, _out(forced)
    assert not wt.exists()


_TOLERATED = (
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
)


def test_only_an_ignored_directory_with_a_tolerated_name_goes_without_force(rig: Rig) -> None:
    """The exception, in both directions. Three lookalikes refuse; the six real cases do not."""
    wt = rig.add(rig.scratch("built"))

    for tracked_dir in ("vendor", "pkg"):
        (wt / tracked_dir).mkdir()
        (wt / tracked_dir / "keep.txt").write_text("tracked\n", encoding="utf-8")
    _git(wt, "add", "vendor/keep.txt", "pkg/keep.txt")
    _git(wt, "commit", "-q", "-m", "two tracked directories")

    # An UNTRACKED directory with a tolerated name. The fixture un-ignores this one path, so git
    # reports it `??` and not `!!`, and the name alone must not clear it.
    lookalike = wt / "vendor" / "node_modules"
    lookalike.mkdir()
    (lookalike / "work.js").write_text("hand-written\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0
    assert "?? vendor/node_modules/" in _out(proc), _out(proc)
    shutil.rmtree(lookalike)

    # An ignored FILE with a tolerated name.
    as_file = wt / "pkg" / "__pycache__"
    as_file.write_text("a file, not a cache directory\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0
    assert "!! pkg/__pycache__" in _out(proc), _out(proc)
    as_file.unlink()

    # An ignored directory with any OTHER name.
    (wt / "out").mkdir()
    (wt / "out" / "report.txt").write_text("generated, maybe\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0
    assert "!! out/" in _out(proc), _out(proc)
    shutil.rmtree(wt / "out")
    assert wt.exists() and rig.is_registered(wt)

    # The six tolerated names, one of them below the root.
    for name in _TOLERATED:
        parent = wt / "pkg" if name == "__pycache__" else wt
        (parent / name).mkdir()
        (parent / name / "artefact.bin").write_text("rebuildable\n", encoding="utf-8")
    listed = _git(wt, "status", "--porcelain", "--ignored")
    assert listed.count("!! ") == len(_TOLERATED), listed

    proc = rig.run("-Path", str(wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_tolerated_name_that_is_a_junction_out_of_the_tree_is_not_tolerated(rig: Rig) -> None:
    """A junction named ``node_modules`` can point anywhere. A recursive delete that follows it takes
    content the worktree never held, so the name alone must not clear it. Whether git reports the
    junction as a directory or as a link, the run must refuse and the outside content must survive."""
    wt = rig.add(rig.scratch("linked"))
    outside = rig.root / "shared-packages"
    outside.mkdir()
    precious = outside / "precious.txt"
    precious.write_text("lives outside every worktree\n", encoding="utf-8")
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(wt / "node_modules"), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"could not create a junction: {made.stderr or made.stdout}")

    proc = rig.run("-Path", str(wt))

    assert proc.returncode != 0, _out(proc)
    assert "node_modules" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)
    assert precious.read_text(encoding="utf-8") == "lives outside every worktree\n"


def test_an_edit_hidden_by_skip_worktree_needs_force(rig: Rig) -> None:
    """git status cannot see an edit to a file flagged skip-worktree, so status alone reads clean."""
    wt = rig.add(rig.scratch("flagged"))
    (wt / "seed.txt").write_text("hidden local edit\n", encoding="utf-8")
    _git(wt, "update-index", "--skip-worktree", "seed.txt")
    assert _git(wt, "status", "--porcelain").strip() == ""

    proc = rig.run("-Path", str(wt))

    assert proc.returncode != 0
    assert "flagged seed.txt" in _out(proc) and "skip-worktree" in _out(proc), _out(proc)
    assert (wt / "seed.txt").read_text(encoding="utf-8") == "hidden local edit\n"

    assert rig.run("-Path", str(wt), "-Force").returncode == 0
    assert not wt.exists()


# --- what removing the directory strands or disturbs ---------------------------------------------------


def test_a_target_owning_an_unlanded_ledger_number_is_refused_and_force_is_not_the_override(
    rig: Rig,
) -> None:
    wt = rig.add(rig.scratch("owner"))
    alloc = _common(rig) / "mefor-coord" / "alloc" / "backlog"
    alloc.mkdir(parents=True)
    (alloc / "9101.json").write_text(
        json.dumps(
            {
                "number": "9101",
                "kind": "backlog",
                "title": "t",
                "branch": "b",
                "worktree": str(wt).replace("\\", "/"),
            }
        ),
        encoding="utf-8",
    )

    forced = rig.run("-Path", str(wt), "-Force")
    assert forced.returncode != 0, "-Force bypassed the allocation guard"
    assert "9101" in _out(forced)
    assert wt.exists() and rig.is_registered(wt)

    allowed = rig.run("-Path", str(wt), "-AllowOrphanedAllocations")
    assert allowed.returncode == 0, _out(allowed)
    assert not wt.exists()


def test_path_runs_no_blanket_prune_so_another_stale_registration_survives(rig: Rig) -> None:
    """`git worktree prune` drops every registration whose directory is missing, with the HEAD reflog
    each one holds. This route removes one worktree and must leave the others exactly as they were."""
    gone = rig.add(rig.scratch("gone"))
    shutil.rmtree(gone)
    assert rig.is_registered(gone), "PRECONDITION: the stale registration must exist"
    wt = rig.add(rig.scratch("mine"))

    proc = rig.run("-Path", str(wt))

    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()
    assert rig.is_registered(gone), (
        "a blanket prune dropped a registration this run was not asked about"
    )


# --- -List ----------------------------------------------------------------------------------------------


def test_list_names_every_worktree_its_class_and_route_and_changes_nothing(rig: Rig) -> None:
    sibling = rig.add(rig.primary.parent / "Repo-sib", "-b", "sib")
    scratch = rig.add(rig.scratch("pad"))
    managed = rig.add(rig.primary / ".claude" / "worktrees" / "cm")
    # A tree BELOW a directory named like a sibling. Its path starts with the sibling prefix and its
    # own leaf is one character, shorter than the prefix: the first version of -List cut the leaf
    # before checking for the extra path level, and died on exactly this row.
    below = rig.add(rig.primary.parent / "Repo-pins" / "x")
    before = _git(rig.primary, "worktree", "list", "--porcelain")

    proc = rig.run("-List")

    assert proc.returncode == 0, _out(proc)

    def row(path: Path) -> str:
        spelled = str(path).replace("\\", "/")
        (line,) = [ln for ln in proc.stdout.splitlines() if ln.rstrip().endswith(spelled)]
        return line

    assert row(sibling).split()[:3] == ["sibling", "-Name,-Path", "sib"], proc.stdout
    assert row(scratch).split()[:3] == ["other", "-Path", "-"], proc.stdout
    assert row(below).split()[:3] == ["other", "-Path", "-"], proc.stdout
    assert row(managed).split()[:3] == ["managed", "none", "-"], proc.stdout
    assert "sibling 1, managed 1, other 2" in proc.stdout, proc.stdout
    assert "-Name reaches 1 of 4 and -Path reaches 3" in proc.stdout, proc.stdout
    assert _git(rig.primary, "worktree", "list", "--porcelain") == before
    assert sibling.exists() and scratch.exists() and managed.exists() and below.exists()
