# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the destructive worktree pruner (``scripts/worktree/prune-merged.ps1``).

This script once removed a worktree another live session was working in: ``git worktree remove
--force`` deleted the ``.git`` pointer and deregistered the tree, then failed to delete the directory,
leaving a folder git no longer recognised. It also printed ``Done. Pruned 5`` when four removals had
succeeded. These tests exist because a tool that deletes other people's checkouts needs proof that it
**refuses**, not just proof that it works.

Every test drives the REAL script as a subprocess against a synthetic repo built under ``tmp_path``,
never against this checkout -- so what is under test is the logic an operator runs.

Two rules govern the assertions, both learned by mutating the script and watching tests survive:

* **Assert the DECISION and the REASON, not survival.** Defence in depth means deleting the primary
  veto still leaves the directory intact (the ``-Apply`` re-check catches it), so a survival-only
  assertion passes on a script that has lost its main fence. This is the rule that applies everywhere,
  and it is the stronger of the two.
* **Carry a positive control in the same invocation where one is possible.** ``repo-clean`` coming back
  ``removed`` proves "nothing was pruned" did not pass because the candidate set was empty or the run
  refused for an unrelated reason. It is *not* possible everywhere -- a refusal test (unavailable
  fence, ``-Name`` miss) refuses the whole run by design, so those assert the decision, the reason and
  the exit code instead. The docstring here used to claim every veto test had one; two did.

The ``-Apply`` re-check -- the layer that closes the window between reading a candidate and deleting it
-- is driven by a **gh shim on PATH**. The merge probe is a real subprocess the script runs mid-pass,
so a shim that performs a side effect (a session arrives, the fence dies, the metadata is touched)
before answering reproduces the race deterministically, with no threads and no sleeps. Fixture ordering
is load-bearing for that: ``git worktree list`` returns candidates as ``ahead, child, clean, dirty,
gone, locked, untracked``, and only a branch with unique commits reaches the gh call, so backdating
``clean`` and ``gone`` puts the side effect strictly between ``clean``'s decision and its removal.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "worktree" / "prune-merged.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="prune-merged.ps1 needs pwsh on Windows (Process.StartTime liveness fence)",
)

# Metadata files the activity signal reads. Backdating these is how a fixture gets past the veto
# without turning it off.
_GITDIR_FILES = ("index", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "COMMIT_EDITMSG", "MERGE_MSG")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return proc.stdout


def _commit(repo: Path, name: str, text: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "--", name)
    _git(repo, "commit", "-qm", f"add {name}")


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").strip()


def _add_worktree(primary: Path, path: Path, branch: str) -> None:
    """``worktree add -b`` only -- never a verb the session harness gate refuses."""
    _git(primary, "worktree", "add", "-q", "-b", branch, str(path))


def _backdate(primary: Path, worktree: Path, hours: float) -> None:
    """Age a worktree's PRIVATE git metadata so the activity veto releases it."""
    gitdir = Path(
        subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--absolute-git-dir"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    when = time.time() - hours * 3600
    for rel in (*_GITDIR_FILES, "logs/HEAD"):
        f = gitdir / rel
        if f.exists():
            os.utime(f, (when, when))


class Fixture:
    """A synthetic repo family: one primary, one nested worktree, and eight siblings."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "wt" / "repo"
        self.cfg = root / "cfg"

    def sibling(self, slug: str) -> Path:
        return self.primary.parent / f"{self.primary.name}-{slug}"

    def write_session(
        self,
        *,
        pid: int,
        cwd: Path | str,
        session_id: str,
        entrypoint: str = "claude-desktop",
        started_at: int | None = None,
    ) -> None:
        rec: dict[str, Any] = {
            "pid": pid,
            "sessionId": session_id,
            "cwd": str(cwd),
            # NOW, not import time. The fence compares the pid's real start time against this, so a
            # module-level constant makes every record look like a recycled pid once the suite has been
            # running for a minute -- and the veto tests then pass for the wrong reason (STALE is not a
            # veto). Measured: five of them failed in a 14-minute full run and passed in isolation.
            "startedAt": int(time.time() * 1000) if started_at is None else started_at,
            "version": "2.1.220",
            "kind": "interactive",
            "entrypoint": entrypoint,
        }
        (self.cfg / "sessions" / f"{pid}.json").write_text(json.dumps(rec), encoding="utf-8")


def _build(root: Path) -> Fixture:
    """Build the fixture family.

    No network and no push: ``origin`` is a real bare repo so ``-Fetch`` would work offline, and the
    remote-tracking refs the merge signals read are written with ``update-ref`` directly.
    """
    fx = Fixture(root)
    origin = root / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True)

    fx.primary.mkdir(parents=True)
    _git(fx.primary, "init", "-q", "-b", "main")
    _git(fx.primary, "config", "user.email", "t@example.invalid")
    _git(fx.primary, "config", "user.name", "t")
    _git(fx.primary, "remote", "add", "origin", str(origin))
    _commit(fx.primary, "seed.txt", "seed")
    main_tip = _head(fx.primary)
    _git(fx.primary, "update-ref", "refs/remotes/origin/main", main_tip)

    # A nested worktree, where EnterWorktree/new.ps1 put them. Must never be a candidate.
    _add_worktree(fx.primary, fx.primary / ".claude" / "worktrees" / "nested", "nested-branch")

    # The positive control: clean, no commits beyond origin/main, nobody in it.
    _add_worktree(fx.primary, fx.sibling("clean"), "clean")

    wt = fx.sibling("dirty")
    _add_worktree(fx.primary, wt, "dirty")
    (wt / "seed.txt").write_text("modified", encoding="utf-8")

    wt = fx.sibling("untracked")
    _add_worktree(fx.primary, wt, "untracked")
    (wt / "brand_new_module.py").write_text("# never committed anywhere\n", encoding="utf-8")

    wt = fx.sibling("ahead")
    _add_worktree(fx.primary, wt, "ahead")
    _commit(wt, "ahead.txt", "unique work")

    wt = fx.sibling("locked")
    _add_worktree(fx.primary, wt, "locked")
    _git(fx.primary, "worktree", "lock", "--reason", "in use by a bench run", str(wt))

    # Squash-merge shape: unique commits, and the branch's OWN upstream deleted.
    wt = fx.sibling("gone")
    _add_worktree(fx.primary, wt, "gone")
    _commit(wt, "gone.txt", "squashed upstream")
    _git(fx.primary, "update-ref", "refs/remotes/origin/gone", _head(wt))
    _git(fx.primary, "branch", "--set-upstream-to=origin/gone", "gone")
    _git(fx.primary, "update-ref", "-d", "refs/remotes/origin/gone")

    # ANOTHER branch's upstream is gone: `new.ps1 -Base origin/<parent>` leaves this shape, and it is
    # not a merge signal for the child.
    _git(fx.primary, "update-ref", "refs/remotes/origin/parent", main_tip)
    wt = fx.sibling("child")
    _add_worktree(fx.primary, wt, "child")
    _git(fx.primary, "branch", "--set-upstream-to=origin/parent", "child")
    _commit(wt, "child.txt", "never pushed")
    _git(fx.primary, "update-ref", "-d", "refs/remotes/origin/parent")

    _git(fx.primary, "worktree", "add", "-q", "--detach", str(fx.sibling("detached")))

    # A SEPARATE repo living beside the primary: shares the name prefix, shares no .git.
    decoy = fx.sibling("decoy")
    decoy.mkdir()
    _git(decoy, "init", "-q")

    (fx.cfg / "sessions").mkdir(parents=True)
    return fx


@pytest.fixture
def sleeper() -> Iterator[int]:
    """A pid that is unambiguously LIVE for the fence.

    NOT ``os.getpid()``: the fence calls a record STALE when its process started more than
    ``StartSkewMinutes`` (15) before the recorded ``startedAt``, so a pytest process older than 15
    minutes silently flips to STALE and the veto tests would pass for the wrong reason.

    FUNCTION-scoped, deliberately. A session-scoped sleeper drifts the other way: it starts once, and
    by the time a late test writes a record with ``startedAt=now`` the process looks like it began
    long before its session, which the fence reads as a recycled pid -- also STALE, also silently
    turning a veto test green for the wrong reason. Spawning per test keeps the two timestamps within
    a second of each other, which is the only configuration that is LIVE for the right reason.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(900)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=30)


@pytest.fixture(scope="session")
def readonly_fx(tmp_path_factory: pytest.TempPathFactory) -> Fixture:
    """Shared by the dry-run tests, which provably mutate nothing."""
    return _build(tmp_path_factory.mktemp("prune-ro"))


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    """Function-scoped, for the -Apply tests.

    Worktree registrations are absolute-path-bound, so a mutated fixture must be rebuilt, not copied.
    """
    return _build(tmp_path)


def _argv(
    fx: Fixture,
    extra: tuple[str, ...],
    *,
    config_root: Path | str | None,
    skip_gh: bool,
    skip_fetch: bool,
    as_json: bool,
) -> list[str]:
    root = fx.cfg if config_root == "" else config_root
    args = [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(SCRIPT),
        "-RepoRoot",
        str(fx.primary),
    ]
    if skip_fetch:
        args.append("-SkipFetch")
    if skip_gh:
        args.append("-SkipGh")
    if as_json:
        args.append("-Json")
    if root is not None:
        args += ["-ConfigRoot", str(root)]
    return args + list(extra)


def _env_with(path_prepend: Path | None) -> dict[str, str] | None:
    if path_prepend is None:
        return None
    env = dict(os.environ)
    env["PATH"] = f"{path_prepend}{os.pathsep}{env.get('PATH', '')}"
    return env


def run(
    fx: Fixture,
    *extra: str,
    config_root: Path | str | None = "",
    skip_gh: bool = True,
    skip_fetch: bool = True,
    path_prepend: Path | None = None,
) -> dict[str, Any]:
    """Invoke the real script with -Json and parse its receipt.

    ``config_root=""`` means the fixture's own root; ``None`` omits the flag entirely.
    ``path_prepend`` puts a shim directory ahead of the real tools, for the gh/git probes.
    """
    proc = subprocess.run(
        _argv(
            fx, extra, config_root=config_root, skip_gh=skip_gh, skip_fetch=skip_fetch, as_json=True
        ),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=_env_with(path_prepend),
    )
    assert proc.stdout.strip(), f"no JSON on stdout (exit {proc.returncode}): {proc.stderr}"
    out: dict[str, Any] = json.loads(proc.stdout)
    out["_exit"] = proc.returncode
    out["_stdout"] = proc.stdout
    return out


def run_text(
    fx: Fixture,
    *extra: str,
    skip_gh: bool = True,
    skip_fetch: bool = True,
    path_prepend: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Same, without -Json: the human summary is a separate surface and can lie on its own."""
    return subprocess.run(
        _argv(fx, extra, config_root=fx.cfg, skip_gh=skip_gh, skip_fetch=skip_fetch, as_json=False),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=_env_with(path_prepend),
    )


_SHIMS = 0


def _shim_dir(tmp_path: Path) -> Path:
    global _SHIMS
    _SHIMS += 1
    d = tmp_path / f"shim{_SHIMS}"
    d.mkdir()
    return d


def gh_shim(
    tmp_path: Path,
    *,
    payload: str = "[]",
    exit_code: int = 0,
    side_effect: str = "",
    stderr: str = "",
) -> Path:
    """A ``gh`` on PATH that answers ``gh pr list`` -- and can change the world before it does.

    The side effect runs on the FIRST invocation only, which (given the fixture ordering documented in
    the module docstring) lands strictly between ``repo-clean``'s decision and its removal. That is the
    real race the ``-Apply`` re-check exists for, reproduced without a thread or a sleep.
    """
    d = _shim_dir(tmp_path)
    helper = d / "gh_helper.py"
    body = "import pathlib, subprocess, sys, time, json, os\n"
    body += f"_mark = pathlib.Path(r'{d}') / 'fired'\n"
    body += "def _side_effect():\n"
    body += textwrap.indent(side_effect or "pass", "    ") + "\n"
    body += (
        "if not _mark.exists():\n    _mark.write_text('1', encoding='utf-8')\n    _side_effect()\n"
    )
    body += f"sys.stderr.write({stderr!r})\n"
    body += f"sys.stdout.write({payload!r})\n"
    body += f"sys.exit({exit_code})\n"
    helper.write_text(body, encoding="utf-8")
    (d / "gh.cmd").write_text(
        f'@echo off\r\n"{sys.executable}" "{helper}" %*\r\nexit /b %errorlevel%\r\n',
        encoding="utf-8",
    )
    return d


def git_shim_that_lies_about_removal(tmp_path: Path) -> Path:
    """A ``git`` that reports success for ``worktree remove`` without removing anything.

    The script must count what it can VERIFY (directory gone AND deregistered), not what git claims.
    Nothing else can drive that branch: a real git that exits 0 really does delete the tree.

    A ``.ps1`` shim, not a ``.cmd`` one, and that is load-bearing. PowerShell reaches a ``.cmd`` through
    ``cmd.exe``, whose parser strips carets, so ``refs/heads/<b>^{commit}`` arrived as
    ``refs/heads/<b>{commit}``, every branch reported "no resolvable tip", and nothing was ever
    prunable -- the shim would have been testing its own breakage. PowerShell resolves a ``.ps1`` on
    PATH itself and passes argv through untouched (measured: the caret survives and the exit code
    propagates).
    """
    d = _shim_dir(tmp_path)
    real = shutil.which("git")
    assert real, "git must be on PATH"
    (d / "git.ps1").write_text(
        "# No param block: `-C <path>` must land in $args, not bind to a parameter.\n"
        "if (($args -contains 'worktree') -and ($args -contains 'remove')) { exit 0 }\n"
        f"& '{real}' @args\n"
        "exit $LASTEXITCODE\n",
        encoding="utf-8",
    )
    return d


def use_github_remote(fx: Fixture) -> None:
    """The PR probe only runs when origin looks like GitHub."""
    _git(fx.primary, "remote", "set-url", "origin", "https://github.com/acme/repo.git")


def by_leaf(res: dict[str, Any], slug: str) -> dict[str, Any]:
    leaf = f"repo-{slug}"
    hits: list[dict[str, Any]] = [c for c in res["candidates"] if c["Leaf"] == leaf]
    assert hits, f"{leaf} was not a candidate; got {[c['Leaf'] for c in res['candidates']]}"
    return hits[0]


def live_record(fx: Fixture, sleeper: int, cwd: Path, sid: str = "aaaaaaaa-1111") -> None:
    fx.write_session(pid=sleeper, cwd=cwd, session_id=sid)


# --------------------------------------------------------------------------------------------------
# Scope: what is and is not a candidate
# --------------------------------------------------------------------------------------------------


def test_candidate_set_excludes_primary_nested_detached_and_foreign_repos(
    readonly_fx: Fixture, sleeper: int
) -> None:
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0001-0000")
    res = run(readonly_fx, "-IdleHours", "0")
    leaves = {c["Leaf"] for c in res["candidates"]}
    assert leaves == {
        "repo-clean",
        "repo-dirty",
        "repo-untracked",
        "repo-ahead",
        "repo-locked",
        "repo-gone",
        "repo-child",
    }
    assert "nested" not in leaves  # nested under the PRIMARY: not a `<primary>-` sibling
    assert "repo-decoy" not in leaves  # a separate repo that merely shares the name prefix
    assert [e["leaf"] for e in res["excluded"]] == ["repo-detached"]


def test_a_worktree_nested_in_a_SIBLING_is_never_a_candidate(fx: Fixture, sleeper: int) -> None:
    """`<primary>-clean/.claude/worktrees/inner` also starts with `<primary>-`.

    The candidate set was a bare prefix match, so a CLAUDE-MANAGED nested worktree -- the exact place
    EnterWorktree relocates a live session into -- was a candidate in its own right, with none of the
    nested protections applied to it. Nesting under the PRIMARY escaped only by the accident that
    `<primary>/` is not `<primary>-`, which is why the case that was tested was the one that worked.
    """
    live_record(fx, sleeper, fx.primary)
    inner = fx.sibling("clean") / ".claude" / "worktrees" / "inner"
    _add_worktree(fx.primary, inner, "inner-branch")

    res = run(fx, "-Apply", "-IdleHours", "0")
    assert "inner" not in {c["Leaf"] for c in res["candidates"]}
    assert any(e["leaf"] == "inner" and "nested inside" in e["reason"] for e in res["excluded"])
    assert inner.exists()
    assert "inner-branch" in _git(fx.primary, "branch", "--list", "inner-branch")
    # Positive control: with `clean` protected by containment, `gone` still proves the run acted.
    assert by_leaf(res, "gone")["Outcome"] == "removed"


def test_name_cannot_reach_a_nested_worktree(fx: Fixture, sleeper: int) -> None:
    """-Name matched leaves, so it reached the nested population the header promised never to touch."""
    live_record(fx, sleeper, fx.primary)
    inner = fx.sibling("clean") / ".claude" / "worktrees" / "inner"
    _add_worktree(fx.primary, inner, "inner-branch")

    res = run(fx, "-Apply", "-IdleHours", "0", "-Name", "inner")
    assert res["counts"]["candidates"] == 0
    assert res["namedMisses"] == ["inner"]
    assert res["_exit"] == 2, "an instruction that could not be carried out is not a success"
    assert inner.exists()


def test_bracketed_parent_directory_still_matches(tmp_path: Path) -> None:
    """Anti-vacuity control: `-like` reads `[br]` as a character class and matches nothing.

    Every "was not pruned" assertion in this file would pass for free against an empty candidate set.
    """
    fx = _build(tmp_path / "[br]")
    res = run(fx, "-IdleHours", "0")
    assert res["counts"]["candidates"] == 7


# --------------------------------------------------------------------------------------------------
# The rule: prune = merged AND clean AND NOT occupied
# --------------------------------------------------------------------------------------------------


def test_clean_merged_unoccupied_is_pruned(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-Apply", "-IdleHours", "0")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "PRUNE"
    assert d["Outcome"] == "removed"
    assert not fx.sibling("clean").exists()
    # Both merge signals fire here: `clean` has nothing beyond origin/main and `gone`'s own upstream
    # was deleted. Only `clean` is CONTAINED in origin/main, so only its branch may be deleted.
    assert res["counts"]["removed"] == 2
    assert res["counts"]["branchesDeleted"] == 1
    assert res["counts"]["branchesKept"] == 1
    assert res["_exit"] == 0


def test_occupied_worktree_is_never_pruned(fx: Fixture, sleeper: int) -> None:
    """The incident. A worktree can be clean AND merged AND occupied at the same time."""
    live_record(fx, sleeper, fx.sibling("gone"), "bbbbbbbb-2222")
    res = run(fx, "-Apply", "-IdleHours", "0")

    d = by_leaf(res, "gone")
    assert d["Decision"] == "SKIP", "occupancy must be decided BEFORE the removal, not caught by it"
    assert d["Reason"].startswith("occupied by 1 session(s)")
    assert d["Occupants"][0]["State"] == "LIVE"
    assert fx.sibling("gone").exists()

    # Positive control in the same invocation: the run was capable of removing something.
    assert by_leaf(res, "clean")["Outcome"] == "removed"


def test_vscode_session_vetoes_exactly_like_a_desktop_one(fx: Fixture, sleeper: int) -> None:
    """The fence is path-based; the launching surface is irrelevant to it."""
    fx.write_session(
        pid=sleeper,
        cwd=fx.sibling("gone"),
        session_id="cccccccc-3333",
        entrypoint="claude-vscode",
    )
    res = run(fx, "-IdleHours", "0")
    d = by_leaf(res, "gone")
    assert d["Decision"] == "SKIP"
    assert d["Occupants"][0]["Surface"] == "claude-vscode"
    # LIVE explicitly: a STALE record would also produce SKIP under some other reason, and this test
    # would then be green while proving nothing about the surface.
    assert d["Occupants"][0]["State"] == "LIVE"


def test_session_in_a_nested_worktree_vetoes_its_ancestor(fx: Fixture, sleeper: int) -> None:
    """`<sibling>/.claude/worktrees/<x>` is gitignored, so the PARENT reads perfectly clean.

    Removing the parent with --force deletes the nested checkout too and leaves it registered with no
    directory -- the exact orphan state the incident produced.
    """
    outer = fx.sibling("clean")
    inner = outer / ".claude" / "worktrees" / "inner"
    _add_worktree(fx.primary, inner, "inner-branch")
    live_record(fx, sleeper, inner, "dddddddd-4444")

    res = run(fx, "-Apply", "-IdleHours", "0")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert "nested inner" in d["Reason"]
    assert outer.exists() and inner.exists()


def test_a_worktree_containing_another_is_refused_even_when_empty(
    fx: Fixture, sleeper: int
) -> None:
    """No session in the nested tree at all -- containment alone must disqualify it."""
    live_record(fx, sleeper, fx.primary)
    outer = fx.sibling("clean")
    _add_worktree(fx.primary, outer / ".claude" / "worktrees" / "inner", "inner-branch")

    res = run(fx, "-Apply", "-IdleHours", "0")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert "nested registered worktree" in d["Reason"]
    assert d["NestedWorktrees"] == ["inner"]
    assert outer.exists()
    # The half this used to miss entirely. `<primary>-clean/.claude/worktrees/inner` also starts with
    # `<primary>-`, so it was a CANDIDATE in its own right and was removed with its branch on this very
    # invocation -- while the assertion above watched the parent being protected.
    assert (outer / ".claude" / "worktrees" / "inner").exists(), (
        "the Claude-managed nested worktree was DESTROYED"
    )
    assert "inner-branch" in _git(fx.primary, "branch", "--list", "inner-branch")


def test_a_claude_worktree_under_a_plain_directory_is_still_excluded(
    fx: Fixture, sleeper: int
) -> None:
    """The second, independent half of the candidate-set rule, with no containment to hide behind.

    `<primary>-scratch/` is an ordinary directory, not a registered worktree, so nothing CONTAINS the
    nested checkout inside it -- but the path shape is Claude-managed by construction, whoever owns the
    directory above it. Without this rule the containment check alone lets it through.
    """
    live_record(fx, sleeper, fx.primary)
    plain = fx.sibling("scratch")
    plain.mkdir()
    inner = plain / ".claude" / "worktrees" / "loose"
    _add_worktree(fx.primary, inner, "loose-branch")

    res = run(fx, "-Apply", "-IdleHours", "0")
    assert "loose" not in {c["Leaf"] for c in res["candidates"]}
    assert any(e["leaf"] == "loose" and "Claude-managed" in e["reason"] for e in res["excluded"])
    assert inner.exists()
    assert by_leaf(res, "clean")["Outcome"] == "removed"  # positive control


def test_a_record_with_no_cwd_is_unplaceable_and_refuses_too(fx: Fixture, sleeper: int) -> None:
    """The same defect as the unparseable record, second shape: it PARSES, so it counted as a record --
    and was then dropped by a bare `continue`. A record with no cwd could name any worktree, so it
    clears none of them, and "skipped" is indistinguishable from "that session is not here"."""
    live_record(fx, sleeper, fx.primary)
    (fx.cfg / "sessions" / "9913.json").write_text(
        json.dumps(
            {"pid": sleeper, "sessionId": "n0cwd000-8888", "startedAt": int(time.time() * 1000)}
        ),
        encoding="utf-8",
    )
    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert res["fence"]["recordsUnplaceable"] == 1
    assert any("no cwd" in f for f in res["fence"]["unplaceableFiles"])
    assert res["counts"]["removed"] == 0
    assert fx.sibling("clean").exists()


def test_dead_record_is_not_a_veto_and_not_a_permission(fx: Fixture, sleeper: int) -> None:
    """Liveness may only VETO. A DEAD verdict must not authorise the removal by itself."""
    dead = _find_free_pid()
    fx.write_session(pid=dead, cwd=fx.sibling("clean"), session_id="eeeeeeee-5555")
    live_record(fx, sleeper, fx.primary)  # keeps the fence available

    res = run(fx)  # default -IdleHours: signal 2 still stands
    d = by_leaf(res, "clean")
    assert d["Occupants"] == []  # not a veto
    assert d["Decision"] == "SKIP"  # and not a green light either
    assert d["Reason"].startswith("recently active")


def test_unreadable_record_vetoes_while_the_fence_stays_available(
    fx: Fixture, sleeper: int
) -> None:
    live_record(fx, sleeper, fx.primary)
    (fx.cfg / "sessions" / "weird.json").write_text(
        json.dumps(
            {
                "pid": "not-a-number",
                "sessionId": "ffffffff-6666",
                "cwd": str(fx.sibling("clean")),
                "startedAt": int(time.time() * 1000),
            }
        ),
        encoding="utf-8",
    )
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["available"] is True
    assert "[UNREADABLE]" in by_leaf(res, "clean")["Reason"]


# --------------------------------------------------------------------------------------------------
# Fence unavailable => refuse, loudly
# --------------------------------------------------------------------------------------------------


def test_empty_registry_refuses_everything(fx: Fixture) -> None:
    """An empty roster is 'I could not look', not 'nobody is here'. Run with -Apply on purpose."""
    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert res["fence"]["recordsExamined"] == 0
    assert res["counts"]["removed"] == 0
    assert all(c["Decision"] == "SKIP" for c in res["candidates"])
    assert all(any("fence unavailable" in r for r in c["Reasons"]) for c in res["candidates"]), (
        "every candidate must name the fence, or a mutant that drops the check still passes"
    )
    assert fx.sibling("clean").exists()


def test_missing_config_root_refuses_everything(fx: Fixture, tmp_path: Path) -> None:
    res = run(fx, "-Apply", "-IdleHours", "0", config_root=tmp_path / "nope")
    assert res["_exit"] == 2
    assert res["fence"]["rootsExamined"] == 0
    assert "no Claude config root" in res["fence"]["detail"]
    assert res["counts"]["removed"] == 0


def test_only_a_malformed_record_is_unavailable_not_empty(fx: Fixture) -> None:
    (fx.cfg / "sessions" / "12345.json").write_text("{not json", encoding="utf-8")
    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["_exit"] == 2
    assert res["fence"]["recordsExamined"] == 0
    assert res["fence"]["recordsUnplaceable"] == 1
    assert res["fence"]["available"] is False


def test_one_unparseable_record_makes_the_whole_fence_unavailable(
    fx: Fixture, sleeper: int
) -> None:
    """A half-written record is what a session that launched a second ago looks like.

    The reader used to drop it silently, so it appeared in no count: an occupied worktree flipped from
    SKIP to PRUNE purely because the record naming it was caught mid-write, and the availability gate
    was satisfied by some OTHER session's record. Its cwd is unknowable, so no candidate can be cleared.
    """
    live_record(fx, sleeper, fx.primary)  # a perfectly good record: the fence is not "empty"
    (fx.cfg / "sessions" / "9911.json").write_text(
        '{"pid": 4242, "cwd": "C:\\\\so', encoding="utf-8"
    )

    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert res["fence"]["recordsExamined"] == 1, "the readable one was still read"
    assert res["fence"]["recordsUnplaceable"] == 1
    assert any("9911.json" in f for f in res["fence"]["unplaceableFiles"])
    assert res["counts"]["removed"] == 0
    assert all(any("fence unavailable" in r for r in c["Reasons"]) for c in res["candidates"])
    assert fx.sibling("clean").exists()


def test_a_record_with_no_pid_vetoes_instead_of_reading_as_dead(fx: Fixture, sleeper: int) -> None:
    """It parsed, so the fence is available -- but it cannot be fenced, so it cannot clear a worktree.

    ``DEAD`` is not in the veto set, so a record whose ``pid`` had not been written yet was a green
    light on the worktree it named.
    """
    live_record(fx, sleeper, fx.primary)
    (fx.cfg / "sessions" / "9912.json").write_text(
        json.dumps(
            {
                "sessionId": "0ddba11a-9999",
                "cwd": str(fx.sibling("clean")),
                "startedAt": int(time.time() * 1000),
            }
        ),
        encoding="utf-8",
    )
    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["fence"]["available"] is True
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert d["Occupants"][0]["State"] == "UNREADABLE"
    assert fx.sibling("clean").exists()
    # Positive control: the run could still remove something.
    assert by_leaf(res, "gone")["Outcome"] == "removed"


def test_negative_idle_hours_is_refused(fx: Fixture, sleeper: int) -> None:
    """A negative cut-off puts the boundary in the FUTURE, disarming signal 2 while looking set."""
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-Apply", "-IdleHours", "-1")
    assert res["_exit"] == 2
    assert "IdleHours" in res["error"]
    assert fx.sibling("clean").exists()


# --------------------------------------------------------------------------------------------------
# Reduced assurance is announced, never silent
# --------------------------------------------------------------------------------------------------


def test_disabled_activity_veto_is_declared(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["activityVeto"] is False
    assert any("activity veto DISABLED" in r for r in res["fence"]["reducedAssurance"])

    text = run_text(fx, "-IdleHours", "0").stdout
    assert "REDUCED ASSURANCE" in text


def test_explicit_config_root_is_declared_as_fixture_scope(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-IdleHours", "0")
    assert any(
        "real session registry was NOT consulted" in r for r in res["fence"]["reducedAssurance"]
    )


def test_fence_contribution_is_reported_not_implied(fx: Fixture, sleeper: int) -> None:
    """The number that matters is how many candidates signal 1 vetoed -- measured 0 of 4 in the wild."""
    live_record(fx, sleeper, fx.primary)  # in the primary: vetoes no candidate
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["liveInRepo"] == 1
    assert res["fence"]["vetoedCandidates"] == 0

    text = run_text(fx, "-IdleHours", "0").stdout
    assert "0 of 7 candidate(s) vetoed by signal 1" in text


# --------------------------------------------------------------------------------------------------
# The other disqualifiers
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("slug", "needle"),
    [
        ("dirty", "dirty: 1 uncommitted tracked change(s)"),
        ("untracked", "--force would delete them unrecoverably"),
        ("locked", "locked by git: in use by a bench run"),
        ("ahead", "not merged (no merge signal)"),
        ("child", "not merged"),
    ],
)
def test_disqualifiers(readonly_fx: Fixture, sleeper: int, slug: str, needle: str) -> None:
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0002-0000")
    res = run(readonly_fx, "-IdleHours", "0")
    d = by_leaf(res, slug)
    assert d["Decision"] == "SKIP"
    assert needle in d["Reason"]


def test_gone_upstream_of_another_branch_is_not_a_merge_signal(
    readonly_fx: Fixture, sleeper: int
) -> None:
    """`new.ps1 -Base origin/<parent>` leaves the child pointing at the PARENT's upstream."""
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0003-0000")
    d = by_leaf(run(readonly_fx, "-IdleHours", "0"), "child")
    assert d["Decision"] == "SKIP"
    assert any("belongs to ANOTHER branch" in n for n in d["Notes"])


def test_never_used_is_reported_separately_from_merged(readonly_fx: Fixture, sleeper: int) -> None:
    """'0 commits beyond origin/main' is true of a merged branch AND of one that never advanced.

    The second is the incident's shape, so it must not be reported as though something was merged.
    """
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0004-0000")
    d = by_leaf(run(readonly_fx, "-IdleHours", "0"), "clean")
    assert d["Decision"] == "PRUNE"
    assert d["NeverUsed"] is True
    assert "never used" in d["Reason"]


def test_merge_is_not_evaluated_for_a_disqualified_candidate(
    readonly_fx: Fixture, sleeper: int
) -> None:
    """`Merged: false` would claim it was checked and found unmerged. It was never asked."""
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0005-0000")
    d = by_leaf(run(readonly_fx, "-IdleHours", "0"), "dirty")
    assert d["Merged"] is None
    assert d["MergeReason"] == "not evaluated (already disqualified)"


def test_activity_veto_fires_then_releases(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    d = by_leaf(run(fx), "clean")
    assert d["Decision"] == "SKIP"
    assert d["Reason"].startswith("recently active")

    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    d = by_leaf(run(fx), "clean")
    assert d["Decision"] == "PRUNE"
    assert d["ActivityAgeHours"] > 36


def test_name_overrides_activity_but_never_occupancy_or_a_lock(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.sibling("gone"), "77777777-8888")
    res = run(fx, "-Name", "clean")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "PRUNE"
    assert any("overridden by -Name" in n for n in d["Notes"])
    assert [c["Leaf"] for c in res["candidates"]] == ["repo-clean"]

    for slug in ("gone", "locked"):
        d = by_leaf(run(fx, "-Name", slug), slug)
        assert d["Decision"] == "SKIP", f"-Name must not override {slug}"


def test_unreadable_git_metadata_fails_closed(fx: Fixture, sleeper: int) -> None:
    """A half-removed worktree exits 128 with no output, which used to read as CLEAN."""
    live_record(fx, sleeper, fx.primary)
    victim = fx.sibling("clean")
    (victim / ".git").unlink()  # the orphan shape: directory present, pointer gone

    d = by_leaf(run(fx), "clean")
    assert d["Decision"] == "SKIP"
    assert any("git status failed" in r for r in d["Reasons"])
    assert any("activity unknown" in r for r in d["Reasons"])


# --------------------------------------------------------------------------------------------------
# Outcomes, not intentions
# --------------------------------------------------------------------------------------------------


def test_counts_report_successes_not_candidates(fx: Fixture, sleeper: int) -> None:
    """The original defect: `Done. Pruned 5` after four removals succeeded.

    A held-open file makes `worktree remove --force` fail for real (msvcrt's share mode omits
    FILE_SHARE_DELETE), reproducing the incident's exact error without mocking anything.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        res = run(fx, "-Apply")
    finally:
        blocker.close()

    assert res["counts"]["prunable"] == 2, "both should have been eligible"
    assert res["counts"]["removed"] == 1
    assert res["counts"]["failed"] == 1
    outcome = by_leaf(res, "gone")["Outcome"]
    assert outcome in {"orphaned", "failed"}
    # 3 is not "worse failure", it is a DIFFERENT outcome: a directory is broken on disk right now.
    assert res["_exit"] == (3 if outcome == "orphaned" else 1)
    assert by_leaf(res, "clean")["Outcome"] == "removed"
    # `orphaned` is a subset of `failed`, and the three outcome buckets partition the candidates.
    assert res["counts"]["orphaned"] + res["counts"]["failedNonOrphan"] == res["counts"]["failed"]
    assert (
        res["counts"]["removed"] + res["counts"]["failed"] + res["counts"]["skipped"]
        == res["counts"]["candidates"]
    )


def test_human_summary_matches_the_counts(fx: Fixture, sleeper: int) -> None:
    """The text surface is what an operator reads, and it can over-report on its own."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        proc = run_text(fx, "-Apply")
    finally:
        blocker.close()

    assert "Done. removed 1, failed 1" in proc.stdout
    assert "Pruned 2" not in proc.stdout
    assert proc.returncode in {1, 3}
    # A branch deliberately kept on the failed removal must be counted as kept, not silently dropped.
    assert "branches: 1 deleted, 1 kept." in proc.stdout


def test_failed_removal_is_diagnosed_and_the_branch_survives(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        res = run(fx, "-Apply", "-Name", "gone")
    finally:
        blocker.close()

    d = by_leaf(res, "gone")
    assert d["Outcome"] in {"orphaned", "failed"}
    assert d["BranchOutcome"] == "kept"
    if d["Outcome"] == "orphaned":
        assert "ORPHANED" in d["OutcomeDetail"]
        assert "registered=" in d["OutcomeDetail"]
    branches = _git(fx.primary, "branch", "--list", "gone")
    assert "gone" in branches, "a failed removal must not take the branch with it"


def test_orphan_state_prints_the_recovery_recipe(fx: Fixture, sleeper: int) -> None:
    """The orphaned directory is what nearly cost a session its work.

    Neither ``worktree repair`` nor ``worktree add`` alone recovers it -- only move-aside then re-add
    -- so a red error without the recipe leaves the operator stuck.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        proc = run_text(fx, "-Apply", "-Name", "gone")
    finally:
        blocker.close()

    if "ORPHANED" not in proc.stdout:
        pytest.skip("git removed the directory despite the open handle on this filesystem")
    assert ".git pointer" in proc.stdout
    assert "registration:" in proc.stdout
    assert "Move-Item" in proc.stdout
    assert "worktree add" in proc.stdout
    assert "'git worktree prune' was NOT run" in proc.stdout
    assert proc.returncode == 3, "an orphan is its own outcome, not a generic failure"


def test_branch_with_unique_commits_is_kept_never_force_deleted(fx: Fixture, sleeper: int) -> None:
    """`gone` is a merge signal for the WORKTREE and never a licence to delete the BRANCH.

    `branch -d` refuses a branch merged only into origin/main whenever local main lags, so `-D` used
    to be the routine path -- overriding git's last protection on a verdict formed seconds earlier.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    tip = _git(fx.primary, "rev-parse", "gone").strip()

    res = run(fx, "-Apply", "-Name", "gone")
    d = by_leaf(res, "gone")
    assert d["Outcome"] == "removed"
    assert d["BranchOutcome"] == "kept"
    assert "not on origin/main" in d["BranchDetail"]
    assert res["counts"]["branchesKept"] == 1
    assert _git(fx.primary, "rev-parse", "gone").strip() == tip


def test_worktree_prune_is_never_run(fx: Fixture, sleeper: int) -> None:
    """`git worktree prune` deregisters ANY worktree whose directory is momentarily missing.

    That includes the `.claude/worktrees` ones this script must never touch, and it would finish off
    a half-removed tree.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    nested = fx.primary / ".claude" / "worktrees" / "nested"
    moved = fx.primary.parent / "nested-moved-aside"
    nested.rename(moved)
    try:
        res = run(fx, "-Apply")
        assert res["counts"]["removed"] == 1  # the control still worked
        registered = _git(fx.primary, "worktree", "list")
        assert "nested" in registered, "the missing nested worktree must still be registered"
    finally:
        moved.rename(nested)


def test_dry_run_mutates_nothing_and_does_not_fetch(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    before = sorted(p.name for p in fx.primary.parent.iterdir())

    res = run(fx, config_root=fx.cfg)
    assert by_leaf(res, "clean")["Decision"] == "PRUNE"
    assert by_leaf(res, "clean")["Outcome"] == "not attempted"
    assert res["fetched"] is False
    assert "skipped (-SkipFetch)" in res["refs"]
    assert sorted(p.name for p in fx.primary.parent.iterdir()) == before


# --------------------------------------------------------------------------------------------------
# Refusals about where it is run
# --------------------------------------------------------------------------------------------------


def test_refuses_from_a_linked_worktree(fx: Fixture) -> None:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(fx.sibling("clean")),
            "-ConfigRoot",
            str(fx.cfg),
            "-SkipFetch",
            "-SkipGh",
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "not the primary checkout"


def test_refuses_outside_a_repository(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(plain),
            "-SkipFetch",
            "-SkipGh",
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "not a git repository"


# --------------------------------------------------------------------------------------------------
# Static guard: the defect class where a probe silently never runs
# --------------------------------------------------------------------------------------------------


def test_gh_json_field_list_is_one_argv_entry() -> None:
    """`--json number, headRefOid` is three argv entries; gh rejects the third and the block dies.

    That is the whole exact-tip merge probe silently never running while the receipt still claimed a
    PR probe was scoped -- a green gate that cannot see the thing it guards.
    """
    src = SCRIPT.read_text(encoding="utf-8")
    assert "--json number,headRefOid" in src
    assert "--json number, " not in src


# --------------------------------------------------------------------------------------------------
# The -Apply re-check: the window between reading a candidate and deleting it
#
# Every test below drives it with the gh shim documented at the top of this file. `clean` and `gone`
# are both backdated, so `clean` is decided first and `gone` -- the only one with unique commits -- is
# what triggers the gh call. The side effect therefore lands after `clean`'s decision and before its
# removal, and `gone` is the positive control that the run really was capable of removing something.
# --------------------------------------------------------------------------------------------------


def _stage_recheck(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    use_github_remote(fx)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)


def test_a_session_arriving_mid_run_is_vetoed_and_counted(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """The race the incident description blames, made deterministic.

    The fence receipt must also OWN the save: a re-check veto used to leave `Occupants: []` on the one
    candidate the fence stopped, so `vetoedCandidates` reported 0 for a run signal 1 had rescued.
    """
    _stage_recheck(fx, sleeper)
    shim = gh_shim(
        tmp_path,
        side_effect=(
            "import json, time\n"
            f"rec = {{'pid': {sleeper}, 'sessionId': 'beef0001-1111',"
            f" 'cwd': r'{fx.sibling('clean')}', 'entrypoint': 'claude-desktop',"
            " 'startedAt': int(time.time() * 1000)}\n"
            f"pathlib.Path(r'{fx.cfg / 'sessions' / 'beef.json'}')"
            ".write_text(json.dumps(rec), encoding='utf-8')\n"
        ),
    )
    res = run(fx, "-Apply", skip_gh=False, path_prepend=shim)

    d = by_leaf(res, "clean")
    assert d["Decision"] == "PRUNE", "the decision pass could not have known"
    assert d["Outcome"] == "skipped"
    assert d["OutcomeDetail"].startswith("re-check: a session arrived")
    assert d["Occupants"] and d["Occupants"][0]["State"] == "LIVE"
    assert fx.sibling("clean").exists()

    assert res["fence"]["vetoedCandidatesAtDecision"] == 0
    assert res["fence"]["vetoedCandidates"] == 1, "the receipt must count the save it made"
    assert by_leaf(res, "gone")["Outcome"] == "removed"


def test_activity_is_rechecked_before_the_removal(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Signal 2 was the ONE signal missing from the re-check -- and the only one with real coverage.

    Signal 1 has been measured vetoing 0 of 4 live siblings, so during the apply window the fence was
    effectively down: a git command by the occupant between the decision and the delete changed nothing.
    """
    _stage_recheck(fx, sleeper)
    gitdir = fx.primary / ".git" / "worktrees" / "repo-clean" / "HEAD"
    shim = gh_shim(tmp_path, side_effect=f"os.utime(r'{gitdir}', None)\n")

    res = run(fx, "-Apply", skip_gh=False, path_prepend=shim)
    d = by_leaf(res, "clean")
    assert d["Decision"] == "PRUNE"
    assert d["Outcome"] == "skipped"
    assert d["OutcomeDetail"].startswith("re-check: git metadata was touched")
    assert fx.sibling("clean").exists()
    assert by_leaf(res, "gone")["Outcome"] == "removed"


def test_a_nested_worktree_appearing_mid_run_is_vetoed(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    _stage_recheck(fx, sleeper)
    late = fx.sibling("clean") / ".claude" / "worktrees" / "late"
    shim = gh_shim(
        tmp_path,
        side_effect=(
            f"subprocess.run(['git', '-C', r'{fx.primary}', 'worktree', 'add', '-q', '-b',"
            f" 'late-branch', r'{late}'], check=True)\n"
        ),
    )
    res = run(fx, "-Apply", skip_gh=False, path_prepend=shim)
    d = by_leaf(res, "clean")
    assert d["Outcome"] == "skipped"
    assert d["OutcomeDetail"].startswith("re-check: a nested worktree appeared")
    assert late.exists()
    assert by_leaf(res, "gone")["Outcome"] == "removed"


def test_the_clean_recheck_keeps_the_specific_reason(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """It used to flatten four different states into "no longer clean".

    A vanished directory, an exit-128 status, a new untracked file and a real edit are not the same
    event, and the operator is reading this precisely because something moved under a destructive run.
    """
    _stage_recheck(fx, sleeper)
    victim = fx.sibling("clean") / "brand_new.py"
    shim = gh_shim(
        tmp_path, side_effect=f"pathlib.Path(r'{victim}').write_text('x', encoding='utf-8')\n"
    )

    res = run(fx, "-Apply", skip_gh=False, path_prepend=shim)
    d = by_leaf(res, "clean")
    assert d["Outcome"] == "skipped"
    assert "untracked file(s) present" in d["OutcomeDetail"]
    assert "no longer clean" not in d["OutcomeDetail"]
    assert victim.exists()


def test_a_fence_that_dies_mid_run_refuses_and_says_so(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Exit 2 used to arrive with a GREEN summary and `fence.available: true` in the same receipt.

    A caller gating on the receipt concluded the fence was fine; a caller gating on the exit code
    concluded a refusal. Both were reading the same run.
    """
    _stage_recheck(fx, sleeper)
    sessions = fx.cfg / "sessions"
    shim = gh_shim(
        tmp_path,
        side_effect=f"[p.unlink() for p in pathlib.Path(r'{sessions}').glob('*.json')]\n",
    )
    res = run(fx, "-Apply", skip_gh=False, path_prepend=shim)

    assert res["_exit"] == 2
    assert res["counts"]["removed"] == 0
    assert res["fence"]["availableAtDecision"] is True
    assert res["fence"]["availableAtApply"] is False
    assert res["fence"]["available"] is False, "the headline field must fail closed"
    assert "readable session record" in res["fence"]["detailAtApply"]
    for slug in ("clean", "gone"):
        assert by_leaf(res, slug)["OutcomeDetail"].startswith("re-check: fence became unavailable")
        assert fx.sibling(slug).exists()

    # The text surface is a second invocation, so the registry the first run emptied has to be put back
    # -- otherwise the fence is unavailable from the START and this would prove the wrong branch.
    live_record(fx, sleeper, fx.primary)
    proc = run_text(
        fx,
        "-Apply",
        skip_gh=False,
        path_prepend=gh_shim(
            tmp_path,
            side_effect=f"[p.unlink() for p in pathlib.Path(r'{sessions}').glob('*.json')]\n",
        ),
    )
    assert "Occupancy fence: 1 config root(s)" in proc.stdout, "available at decision time"
    assert "Exit 2:" in proc.stdout, "the summary must explain the refusal it just exited with"
    assert "gone by the time of the removal" in proc.stdout
    assert "Done. removed 0" in proc.stdout


# --------------------------------------------------------------------------------------------------
# The merged-PR probe: the receipt must report what the probe ANSWERED
# --------------------------------------------------------------------------------------------------


def test_a_merged_pr_at_this_exact_tip_is_a_merge_signal(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    live_record(fx, sleeper, fx.primary)
    use_github_remote(fx)
    _backdate(fx.primary, fx.sibling("ahead"), hours=100)
    tip = _git(fx.primary, "rev-parse", "ahead").strip()
    shim = gh_shim(tmp_path, payload=json.dumps([{"number": 7, "headRefOid": tip}]))

    res = run(fx, skip_gh=False, path_prepend=shim)
    d = by_leaf(res, "ahead")
    assert d["Decision"] == "PRUNE"
    assert d["Reason"] == "PR #7 merged at this exact tip"
    assert res["ghProbes"] == {"attempted": 1, "failed": 0, "firstError": ""}
    assert "1 candidate(s) probed" in res["gh"]


def test_a_pr_merged_at_an_OLDER_tip_is_not_a_merge_signal(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """`--head <branch>` matches by NAME, so a branch continued after its PR merged reads as merged."""
    live_record(fx, sleeper, fx.primary)
    use_github_remote(fx)
    _backdate(fx.primary, fx.sibling("ahead"), hours=100)
    shim = gh_shim(tmp_path, payload=json.dumps([{"number": 9, "headRefOid": "deadbeef" * 5}]))

    res = run(fx, skip_gh=False, path_prepend=shim)
    d = by_leaf(res, "ahead")
    assert d["Decision"] == "SKIP"
    assert any("the branch moved on after that merge" in n for n in d["Notes"])


def test_a_failing_gh_probe_is_reported_not_claimed(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """The receipt used to assert "PR probe scoped to <slug>" on a run where every probe errored.

    That is the same defect class -- a receipt claiming a check that never ran -- as the argv bug that
    silently disabled this whole block.
    """
    live_record(fx, sleeper, fx.primary)
    use_github_remote(fx)
    _backdate(fx.primary, fx.sibling("ahead"), hours=100)
    shim = gh_shim(
        tmp_path, payload="", exit_code=1, stderr="GraphQL: Could not resolve to a Repository"
    )

    res = run(fx, skip_gh=False, path_prepend=shim)
    assert res["ghProbes"]["attempted"] == 1
    assert res["ghProbes"]["failed"] == 1
    assert "FAILED on 1 of 1" in res["gh"]
    assert any("merged-PR probe FAILED" in r for r in res["fence"]["reducedAssurance"])
    assert any("probe FAILED for this branch" in n for n in by_leaf(res, "ahead")["Notes"])


# --------------------------------------------------------------------------------------------------
# Reduced assurance: everything that narrows the fence says so
# --------------------------------------------------------------------------------------------------


def test_a_fractional_idle_window_is_declared_too(fx: Fixture, sleeper: int) -> None:
    """Only the literal 0 used to be declared. `-IdleHours 0.5`, typed for "half an hour", released
    every worktree on the real repo and printed nothing at all."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("clean"), hours=1)

    # Control first: at the default window this worktree is protected.
    assert by_leaf(run(fx), "clean")["Decision"] == "SKIP"

    res = run(fx, "-IdleHours", "0.5")
    assert res["fence"]["activityVeto"] is True, "it is nominally ON, which is the trap"
    assert any("activity window NARROWED" in r for r in res["fence"]["reducedAssurance"])
    assert by_leaf(res, "clean")["Decision"] == "PRUNE", "the same tree is now released"
    assert "REDUCED ASSURANCE" in run_text(fx, "-IdleHours", "0.5").stdout


def test_name_is_declared_as_reduced_assurance(fx: Fixture, sleeper: int) -> None:
    """-Name is `-IdleHours 0` scoped to one tree, and -IdleHours 0 gets a red banner.

    It produced only a grey `note:` -- and the SKIP line it overrides is the tool's own recommendation.
    """
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-Name", "clean")
    assert any("-Name" in r and "repo-clean" in r for r in res["fence"]["reducedAssurance"]), res[
        "fence"
    ]["reducedAssurance"]
    assert "REDUCED ASSURANCE" in run_text(fx, "-Name", "clean").stdout


def test_a_failed_fetch_is_declared_reduced_assurance(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Its own text says merge decisions are resting on stale refs. That IS reduced assurance."""
    live_record(fx, sleeper, fx.primary)
    _git(fx.primary, "remote", "set-url", "origin", str(tmp_path / "no-such-origin.git"))
    res = run(fx, "-Fetch", skip_fetch=False)
    assert "FETCH FAILED" in res["refs"]
    assert res["fetched"] is False
    assert any("FETCH FAILED" in r for r in res["fence"]["reducedAssurance"])


def test_apply_fetches_for_real(fx: Fixture, sleeper: int) -> None:
    """The fetch path itself was never executed by a test: every invocation passed -SkipFetch."""
    live_record(fx, sleeper, fx.primary)
    _git(fx.primary, "push", "-q", "origin", "main")
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    res = run(fx, "-Apply", "-Name", "clean", skip_fetch=False)
    assert res["fetched"] is True
    assert "origin fetched" in res["refs"]
    assert by_leaf(res, "clean")["Outcome"] == "removed"


# --------------------------------------------------------------------------------------------------
# Outcomes: verification, branch bookkeeping, and orphans that outlive the run
# --------------------------------------------------------------------------------------------------


def test_a_removal_is_verified_not_trusted(fx: Fixture, sleeper: int, tmp_path: Path) -> None:
    """Exit 0 is git's CLAIM. The directory being gone and deregistered is the fact."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    res = run(
        fx, "-Apply", "-Name", "clean", path_prepend=git_shim_that_lies_about_removal(tmp_path)
    )

    d = by_leaf(res, "clean")
    assert d["Outcome"] == "failed"
    assert "git reported success" in d["OutcomeDetail"]
    assert res["counts"]["removed"] == 0
    assert res["counts"]["failed"] == 1
    assert res["_exit"] == 1
    assert fx.sibling("clean").exists()
    assert "clean" in _git(fx.primary, "branch", "--list", "clean"), (
        "an unverified removal must not take the branch"
    )
    assert d["BranchOutcome"] == "kept"
    assert res["counts"]["branchesKept"] == 1


def test_a_branch_is_force_deleted_only_after_reverifying_containment(
    fx: Fixture, sleeper: int
) -> None:
    """The permissive half of the branch rule: `-d` refuses, containment holds, so `-D` is lossless.

    This is the arm that actually destroys a ref, and in the base fixture local `main` never lags
    origin/main, so `-d` always succeeded and the force-delete path was unreachable.
    """
    live_record(fx, sleeper, fx.primary)
    wt = fx.sibling("fd")
    _add_worktree(fx.primary, wt, "fd")
    _commit(wt, "fd.txt", "work that IS on origin/main")
    tip = _head(wt)
    _git(fx.primary, "update-ref", "refs/remotes/origin/main", tip)  # local main now lags
    _backdate(fx.primary, wt, hours=100)

    res = run(fx, "-Apply", "-Name", "fd")
    d = by_leaf(res, "fd")
    assert d["Outcome"] == "removed"
    assert d["BranchOutcome"] == "force-deleted"
    assert "0 commits beyond origin/main" in d["BranchDetail"]
    assert res["counts"]["branchesDeleted"] == 1
    assert _git(fx.primary, "rev-parse", "origin/main").strip() == tip, "nothing was lost"


def test_branch_outcome_is_not_a_claim_nobody_made(fx: Fixture, sleeper: int) -> None:
    """`BranchOutcome` defaulted to 'kept', so the JSON reported 7 branches kept on a run whose
    summary said 0 -- the two surfaces of one receipt disagreeing by 7."""
    live_record(fx, sleeper, fx.primary)
    res = run(fx)  # dry run: nothing is attempted at all
    assert {c["BranchOutcome"] for c in res["candidates"]} == {"not attempted"}
    assert res["counts"]["branchesKept"] == 0


def test_an_orphan_is_reported_by_every_later_run(fx: Fixture, sleeper: int) -> None:
    """Git deregisters an orphan, so it leaves the candidate set and the NEXT run printed a green
    all-clear over a directory this script had broken. The recipe lived only in the first run's
    scrollback."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        first = run(fx, "-Apply", "-Name", "gone")
    finally:
        blocker.close()
    if by_leaf(first, "gone")["Outcome"] != "orphaned":
        pytest.skip("git removed the directory despite the open handle on this filesystem")

    later = run(fx)  # a plain dry run: it must not report an all-clear
    assert later["counts"]["orphansFromEarlierRuns"] == 1
    assert [o["leaf"] for o in later["orphansFromEarlierRuns"]] == ["repo-gone"]
    assert later["_exit"] == 3
    assert "repo-gone" not in {c["Leaf"] for c in later["candidates"]}, "git no longer lists it"

    text = run_text(fx).stdout
    assert "ORPHANED director" in text
    assert "Move-Item" in text
    assert "DRY RUN - nothing would be removed" in text


def test_a_repaired_orphan_stops_being_reported(fx: Fixture, sleeper: int) -> None:
    """A ledger that cannot clear itself is a nag, and a nagging destructive tool gets ignored."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        first = run(fx, "-Apply", "-Name", "gone")
    finally:
        blocker.close()
    if by_leaf(first, "gone")["Outcome"] != "orphaned":
        pytest.skip("git removed the directory despite the open handle on this filesystem")

    shutil.rmtree(fx.sibling("gone"), ignore_errors=True)
    if fx.sibling("gone").exists():
        pytest.skip("the orphaned directory could not be cleaned up on this filesystem")
    later = run(fx)
    assert later["counts"]["orphansFromEarlierRuns"] == 0
    assert later["_exit"] == 0


def test_a_name_that_matches_nothing_does_not_exit_green(fx: Fixture, sleeper: int) -> None:
    """The operator asked for a specific destructive action and nothing was even considered."""
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-Apply", "-Name", "no-such-worktree")
    assert res["namedMisses"] == ["no-such-worktree"]
    assert res["counts"]["candidates"] == 0
    assert res["_exit"] == 2
    assert (
        "matched no PRUNABLE sibling" in run_text(fx, "-Apply", "-Name", "no-such-worktree").stdout
    )


def _find_free_pid() -> int:
    proc = subprocess.Popen(
        ["cmd", "/c", "exit"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    proc.wait(timeout=30)
    time.sleep(0.3)
    return proc.pid
