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
from collections.abc import Iterator, Sequence
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

    def write_transcript(
        self,
        *,
        session_id: str,
        cwd: Path | str,
        writes: Sequence[Path | str] = (),
        tool: str = "Edit",
        sidechain: bool = True,
        hours_ago: float = 0.5,
        project: str = "proj",
        path_key: str = "file_path",
        block_type: str = "tool_use",
        extra_input: dict[str, Any] | None = None,
        raw_tail: str = "",
        stem: str = "agent-a1",
    ) -> Path:
        """Write a Claude Code transcript the way the real corpus records one.

        ``json.dumps`` is load-bearing: it escapes every backslash, which is the ONLY spelling a real
        transcript uses for a Windows path. A fixture that hand-wrote forward slashes would pass
        against a scanner whose backslash needle does not exist -- which is precisely the bug the
        needle self-check now catches, and it was found on the real corpus rather than here.

        ``sidechain`` puts the file where subagent transcripts actually live. It defaults to True
        because 100% of the cross-worktree writes measured on this repo came from a sidechain line, so
        a suite that only exercised the parent shape would prove nothing about the case that matters.
        """
        base = self.cfg / "projects" / project
        if sidechain:
            f = base / session_id / "subagents" / "workflows" / "wf_test" / f"{stem}.jsonl"
        else:
            f = base / f"{session_id}.jsonl"
        f.parent.mkdir(parents=True, exist_ok=True)

        when = time.time() - hours_ago * 3600
        stamp = (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(when))
            + f".{int((when % 1) * 1000):03d}Z"
        )
        lines: list[str] = []
        for target in writes:
            payload: dict[str, Any] = {path_key: str(target)}
            payload.update(extra_input or {})
            lines.append(
                json.dumps(
                    {
                        "type": "assistant",
                        "isSidechain": sidechain,
                        "sessionId": session_id,
                        "cwd": str(cwd),
                        "timestamp": stamp,
                        "gitBranch": "whatever",
                        "message": {
                            "role": "assistant",
                            "content": [
                                {
                                    "type": block_type,
                                    "id": "toolu_test",
                                    "name": tool,
                                    "input": payload,
                                }
                            ],
                        },
                    }
                )
            )
        body = "\n".join(lines)
        if lines:
            body += "\n"
        body += raw_tail
        f.write_text(body, encoding="utf-8")
        # The mtime funnel is stage 1 of the scan, so a backdated line needs a backdated file or the
        # transcript is never opened at all.
        os.utime(f, (when, when))
        return f


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
    script: Path | None = None,
) -> list[str]:
    root = fx.cfg if config_root == "" else config_root
    args = [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(script or SCRIPT),
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


def _env_with(
    path_prepend: Path | None, env_extra: dict[str, str] | None = None
) -> dict[str, str] | None:
    if path_prepend is None and not env_extra:
        return None
    env = dict(os.environ)
    if path_prepend is not None:
        env["PATH"] = f"{path_prepend}{os.pathsep}{env.get('PATH', '')}"
    env.update(env_extra or {})
    return env


def run(
    fx: Fixture,
    *extra: str,
    config_root: Path | str | None = "",
    skip_gh: bool = True,
    skip_fetch: bool = True,
    path_prepend: Path | None = None,
    script: Path | None = None,
    env_extra: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Invoke the real script with -Json and parse its receipt.

    ``config_root=""`` means the fixture's own root; ``None`` omits the flag entirely.
    ``path_prepend`` puts a shim directory ahead of the real tools, for the gh/git probes.
    ``script`` points at a MUTATED copy of the script tree, for the anti-vacuity suite.
    ``env_extra`` redirects the environment -- USERPROFILE, for the tests that must exercise config
    root DISCOVERY rather than an explicit ``-ConfigRoot`` (which bypasses it entirely).
    """
    proc = subprocess.run(
        _argv(
            fx,
            extra,
            config_root=config_root,
            skip_gh=skip_gh,
            skip_fetch=skip_fetch,
            as_json=True,
            script=script,
        ),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=_env_with(path_prepend, env_extra),
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
    """The number that matters is how many candidates each source vetoed -- signal 1 measured 0 of 4.

    PER SOURCE, never one merged total: a combined "the fence vetoed N" cannot show that one of its
    signals has gone to zero, and one of them measurably had.
    """
    live_record(fx, sleeper, fx.primary)  # in the primary: vetoes no candidate
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["liveInRepo"] == 1
    assert res["fence"]["vetoedCandidates"] == 0
    assert res["fence"]["vetoedByCwd"] == 0
    assert res["fence"]["vetoedByFootprint"] == 0
    assert res["fence"]["candidatesWithoutFootprint"] == 7

    text = run_text(fx, "-IdleHours", "0").stdout
    assert "Signal 1 (recorded cwd)     placed a session inside 0 of 7 candidate(s)" in text
    assert "Signal 3 (write footprint) placed a session inside 0 of 7 candidate(s)" in text


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


# --------------------------------------------------------------------------------------------------
# Signal 3: the write footprint
#
# The defect these exist for: a session's recorded cwd is where it was LAUNCHED, and nothing ever
# rewrites it, so a workflow that fans subagents into N sibling worktrees is one record carrying one
# cwd. Measured on the real repo 2026-07-30: of the writes landing in a `<primary>-<slug>` sibling --
# the only class this tool destroys -- 88.9% came from a session sitting in a different checkout, and
# signal 1 placed a session inside 0 of the 4 siblings that existed. `test_a_session_writing_in_from_
# another_checkout_is_placed_there` is that case, and it is the one that fails without this signal.
# --------------------------------------------------------------------------------------------------

SID_WRITER = "beefbeef-1111-2222-3333-444444444444"


def _quiesce(fx: Fixture, *slugs: str) -> None:
    """Age signal 2 out of the way so an assertion is about signals 1 and 3, not about mtimes."""
    for s in slugs:
        _backdate(fx.primary, fx.sibling(s), 500)


def test_a_session_writing_in_from_another_checkout_is_placed_there(
    fx: Fixture, sleeper: int
) -> None:
    """THE case. cwd in the PRIMARY, writes into ``repo-clean``; signal 1 can only see the primary.

    Run with ``-Apply`` and with signal 2 aged out of both siblings, so nothing but the footprint
    stands between ``repo-clean`` and ``git worktree remove --force``. ``repo-gone`` is the positive
    control in the SAME invocation: it proves the run was capable of removing something, so the SKIP
    on ``repo-clean`` is a veto and not a refusal for some unrelated reason.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,  # <- the divergence: sitting in the primary
        writes=[fx.sibling("clean") / "scripts" / "thing.py"] * 3,
    )

    res = run(fx, "-Apply")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert d["Outcome"] != "removed"
    assert fx.sibling("clean").exists()
    # The REASON, not just survival: a survival-only assertion passes on a script that lost the signal
    # and was saved by a later layer.
    assert "write footprint" in d["Reason"], d["Reasons"]
    occ = [o for o in d["Occupants"] if o["Source"] == "footprint"]
    assert len(occ) == 1
    assert occ[0]["State"] == "LIVE"
    assert occ[0]["Writes"] == 3
    assert occ[0]["CrossTree"] is True, "the whole point is that its cwd is somewhere else"

    # Per-source receipt: signal 1 saw nothing here and must SAY so rather than being folded into a
    # single count that looks like coverage.
    assert res["fence"]["vetoedByCwd"] == 0
    assert res["fence"]["vetoedByFootprint"] == 1
    assert res["fence"]["footprint"]["crossTreeWrites"] == 3

    assert by_leaf(res, "gone")["Outcome"] == "removed", "positive control"


def test_signal_1_still_sees_nothing_here_which_is_why_signal_3_exists(
    fx: Fixture, sleeper: int
) -> None:
    """The control for the test above: the SAME fixture with the footprint source blind.

    If the transcript is written for a DIFFERENT repo's path, signal 3 has nothing to say and
    ``repo-clean`` is destroyed -- which is exactly what the tool did before this signal existed, and
    the reason a green suite over the old code proved nothing.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.root / "somewhere-else" / "thing.py"],
    )
    res = run(fx, "-Apply")
    assert by_leaf(res, "clean")["Outcome"] == "removed"
    assert res["fence"]["vetoedByFootprint"] == 0
    assert res["fence"]["footprint"]["writesUnplaced"] == 1, (
        "a write that placed nowhere must be COUNTED -- 'another repo' and 'this repo, spelled "
        "differently' are indistinguishable here"
    )


def test_a_footprint_from_a_dead_session_does_not_veto(fx: Fixture, sleeper: int) -> None:
    """Only a POSITIVELY proven-gone verdict releases a footprint, and this is that verdict.

    Carries its own positive control: the identical footprint with a LIVE record DOES veto, so this
    cannot pass because the footprint was never seen.
    """
    _quiesce(fx, "clean", "gone")
    dead = _find_free_pid()
    fx.write_session(pid=dead, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id="0000aaaa-9999")  # fence available
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )

    res = run(fx, "-Apply")
    assert by_leaf(res, "clean")["Outcome"] == "removed", "a dead writer must not veto forever"
    assert res["fence"]["vetoedByFootprint"] == 0

    # Same corpus, live record: the veto comes back. Without this the assertion above would also pass
    # on a build that simply never read the transcript.
    fx2 = _build(fx.root / "again")
    _quiesce(fx2, "clean", "gone")
    fx2.write_session(pid=sleeper, cwd=fx2.primary, session_id=SID_WRITER)
    fx2.write_transcript(
        session_id=SID_WRITER, cwd=fx2.primary, writes=[fx2.sibling("clean") / "x.py"]
    )
    assert run(fx2)["fence"]["vetoedByFootprint"] == 1


def test_a_footprint_older_than_the_window_does_not_veto(fx: Fixture, sleeper: int) -> None:
    """The second bound on 'forever': an unfenceable writer vetoes until it ages out, not for ever.

    The writer here has NO registry record at all, which is the state that vetoes indefinitely if the
    window is not applied -- a clean exit and a session that never registered look identical.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id="0000aaaa-9999")
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
        hours_ago=200,
    )
    res = run(fx, "-Apply")
    assert by_leaf(res, "clean")["Outcome"] == "removed"
    assert res["fence"]["vetoedByFootprint"] == 0

    # Positive control on the SAME corpus: widen the window and the veto reappears, so this did not
    # pass because the transcript was unreadable, mis-shaped, or never enumerated.
    fx2 = _build(fx.root / "wide")
    _quiesce(fx2, "clean", "gone")
    fx2.write_session(pid=sleeper, cwd=fx2.primary, session_id="0000aaaa-9999")
    fx2.write_transcript(
        session_id=SID_WRITER,
        cwd=fx2.primary,
        writes=[fx2.sibling("clean") / "x.py"],
        hours_ago=200,
    )
    wide = run(fx2, "-FootprintHours", "400")
    assert wide["fence"]["vetoedByFootprint"] == 1
    assert by_leaf(wide, "clean")["Occupants"][0]["State"] == "UNREGISTERED"


def test_an_unregistered_writer_vetoes_inside_the_window(fx: Fixture, sleeper: int) -> None:
    """Absence of a record is not evidence of absence, so it vetoes until the window closes."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id="0000aaaa-9999")
    fx.write_transcript(
        session_id="c0ffee00-dead-beef-0000-000000000000",
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
    )
    res = run(fx, "-Apply")
    d = by_leaf(res, "clean")
    assert d["Outcome"] != "removed"
    assert d["Occupants"][0]["State"] == "UNREGISTERED"
    assert fx.sibling("clean").exists()


def test_name_cannot_override_the_write_footprint(fx: Fixture, sleeper: int) -> None:
    """-Name is the loudest thing an operator can do to the fence, and it stops at signal 2.

    It is the flag reached for when the tool refuses, so a signal it CAN turn off is a signal that
    stops protecting anything the moment it starts working.
    """
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )
    res = run(fx, "-Apply", "-Name", "clean")
    d = by_leaf(res, "clean")
    assert d["Confirmed"] is True, "the override was accepted for signal 2"
    assert d["Outcome"] != "removed"
    assert "write footprint" in d["Reason"]
    assert fx.sibling("clean").exists()


# --- Fail-closed: a corpus that cannot be read is not a corpus that is empty ---------------------


def test_a_torn_transcript_line_makes_the_fence_unavailable(fx: Fixture, sleeper: int) -> None:
    """A half-written final line is what a session writing RIGHT NOW looks like.

    Its target is unknowable, so it clears no candidate; the whole run refuses. The fixture writes a
    GOOD line first, so this is 'incomplete', not 'empty'.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    torn = json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use"}]}})
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("gone") / "ok.py"],
        raw_tail='{"type":"assistant","x":"'
        + str(fx.sibling("clean")).replace("\\", "\\\\")
        + "\\",
    )
    assert torn  # documents the shape; the tail above is the same thing, truncated

    res = run(fx, "-Apply")
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert res["fence"]["footprint"]["available"] is False
    assert any("will not parse" in f for f in res["fence"]["footprint"]["faults"])
    assert res["counts"]["removed"] == 0
    assert all(any("fence unavailable" in r for r in c["Reasons"]) for c in res["candidates"])
    assert fx.sibling("clean").exists() and fx.sibling("gone").exists()


def test_an_unreadable_transcript_makes_the_fence_unavailable(fx: Fixture, sleeper: int) -> None:
    """In the window and unopenable: it could name the very worktree about to be destroyed."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    f = fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )
    import msvcrt

    fh = os.open(str(f), os.O_RDWR | os.O_BINARY)
    try:
        try:
            msvcrt.locking(fh, msvcrt.LK_NBLCK, os.path.getsize(str(f)))
        except OSError:  # pragma: no cover - filesystem dependent
            pytest.skip("this filesystem does not enforce a mandatory byte-range lock")
        res = run(fx, "-Apply")
    finally:
        os.close(fh)
    assert res["_exit"] == 2
    assert res["fence"]["footprint"]["available"] is False
    assert any("could not be read" in x for x in res["fence"]["footprint"]["faults"])
    assert res["counts"]["removed"] == 0
    assert fx.sibling("clean").exists()


def test_a_moved_input_schema_makes_the_fence_unavailable(fx: Fixture, sleeper: int) -> None:
    """Stale schema: transcripts mention this repo, and not one tool call carries a known path key.

    Inference over a format nobody promised us goes QUIETLY to zero, which is the same 'confident
    green over nothing' this repo keeps being bitten by. The canary turns it into a refusal.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
        path_key="target_path",  # the vendor renamed it
    )
    res = run(fx, "-Apply")
    assert res["_exit"] == 2
    assert res["fence"]["footprint"]["available"] is False
    assert res["fence"]["footprint"]["transcriptsWithNeedle"] >= 1
    assert res["fence"]["footprint"]["pathBlocksExamined"] == 0
    assert any("format has moved" in x for x in res["fence"]["footprint"]["faults"])
    assert res["counts"]["removed"] == 0


def test_the_canary_fails_when_only_SUBAGENT_extraction_goes_to_zero(
    fx: Fixture, sleeper: int
) -> None:
    """The canary that actually matters, and the one a parent-only canary would miss.

    Every cross-worktree write measured on this repo came from a sidechain line. A canary that only
    proved a PARENT write is extractable stays green while the entire signal disappears -- so here the
    parent transcript extracts perfectly and only the subagent shape has moved.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    # Parent: healthy. A canary keyed on "did we extract anything at all" is satisfied by this line.
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("gone") / "ok.py"],
        sidechain=False,
    )
    # Subagent: the input key moved. Nothing extractable, and it is where the signal lives.
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
        sidechain=True,
        path_key="target_path",
    )
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["pathBlocksExamined"] >= 1, "the parent line still extracted -- that is the point"
    assert fp["sidechainLines"] >= 1
    assert fp["sidechainPathBlocks"] == 0
    assert fp["available"] is False
    assert any("SUBAGENT extraction" in x for x in fp["faults"])
    assert res["_exit"] == 2
    assert res["counts"]["removed"] == 0


def test_no_corpus_is_declared_rather_than_read_as_nobody_is_here(
    fx: Fixture, sleeper: int
) -> None:
    """A machine with no transcripts is legitimate, and a fence that bricks on it gets bypassed.

    So this stays AVAILABLE and contributes nothing -- and has to say so in those words. A bare
    ``vetoedByFootprint: 0`` reads as 'nobody is anywhere' and sends an operator to ``-Name``.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["available"] is True
    assert fp["rootsWithCorpus"] == 0
    assert "contributed nothing" in fp["note"]
    assert any("contributed nothing" in r for r in res["fence"]["reducedAssurance"])
    assert by_leaf(res, "clean")["Outcome"] == "removed", "it must not brick the tool"

    text = run_text(fx, "-IdleHours", "0").stdout
    assert "candidate(s) have NO footprint at all" in text
    assert "not the same as nobody being there" in text


def test_a_negative_footprint_window_is_refused(fx: Fixture, sleeper: int) -> None:
    """A negative window puts the cut-off in the future: signal 3 disarmed while appearing set."""
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    res = run(fx, "-Apply", "-FootprintHours", "-1")
    assert res["_exit"] == 2
    assert "FootprintHours" in res["error"]
    assert fx.sibling("clean").exists()


# --- Placement: git's spelling, not ours ---------------------------------------------------------


def _junction(fx: Fixture) -> Path:
    link = fx.root / "linked"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(fx.primary.parent)],
        capture_output=True,
        text=True,
        check=False,
    )
    if made.returncode != 0 or not link.exists():  # pragma: no cover - policy dependent
        pytest.skip(f"could not create a junction here: {made.stdout}{made.stderr}")
    return link


def test_a_write_through_a_junction_is_placed_by_gitdir(fx: Fixture, sleeper: int) -> None:
    """The literal prefix match is a string compare, so an equivalent spelling places nowhere.

    A junction is the cheap reproduction of the UNC / 8.3 / ``subst`` family. Walking up to ``.git``
    and reading where it points answers in git's own spelling instead of ours.

    THE ``cwd`` HERE IS LOAD-BEARING AND USED TO BE WRONG. It was the primary, and ``write_transcript``
    stamps the cwd onto every line -- so the line carried a worktree path of this repo as a literal
    substring for a reason that had nothing to do with the junction, and survived the needle funnel
    that used to run BEFORE placement. With the cwd moved outside the family the line contains no
    needle at all, which is the configuration the .git fallback exists for: re-running the old test
    with this one-word change failed on its own assertion (``placedByGitdir == 1`` -> ``0 == 1``).
    ``transcriptsWithNeedle == 0`` is asserted below so it can never silently drift back.
    """
    link = _junction(fx)
    outside = fx.root / "outside"
    outside.mkdir(exist_ok=True)

    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=outside, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=outside,  # <- NOT the primary: the line must carry no path of this repo family
        writes=[link / fx.sibling("clean").name / "x.py"],
    )
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["transcriptsWithNeedle"] == 0, (
        "the transcript must mention no worktree of this repo, or the junction is not what placed it"
    )
    assert fp["placedByPrefix"] == 0, "the string compare must genuinely have failed"
    assert fp["placedByGitdir"] == 1
    assert fp["gitdirProbes"] > 0
    d = by_leaf(res, "clean")
    assert d["Outcome"] != "removed"
    assert "write footprint" in d["Reason"]
    assert by_leaf(res, "gone")["Outcome"] == "removed", "positive control"


def test_mutant_restoring_the_needle_funnel_hides_the_junction_write(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """The funnel that made the .git fallback unreachable, put back, on the same fixture.

    The pre-filter tested every LINE for a worktree path as a literal substring before anything was
    placed -- so the only spellings the fallback exists for were dropped before it could run. Measured
    on the real script: a registered LIVE session writing into a candidate through a junction gave
    ``Available=true``, zero faults, ``writesExamined=0`` AND ``writesUnplaced=0`` (invisible to every
    counter), and ``-Apply`` destroyed the directory.
    """
    link = _junction(fx)
    outside = fx.root / "outside"
    outside.mkdir(exist_ok=True)
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=outside, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=outside, writes=[link / fx.sibling("clean").name / "x.py"]
    )
    assert run(fx)["fence"]["vetoedByFootprint"] == 1, "control: the shipped scanner sees it"

    mutated = _mutant(
        tmp_path,
        (
            "coord/footprint.ps1",
            '        $all = $txt.Split("`n")',
            '        if (-not $family) { continue }\n        $all = $txt.Split("`n")',
        ),
    )
    bad = run(fx, "-Apply", script=mutated)
    fp = bad["fence"]["footprint"]
    assert fp["available"] is True and not fp["faults"], (
        "the funnel is SILENT -- that is the defect"
    )
    assert fp["writesExamined"] == 0 and fp["writesUnplaced"] == 0, "invisible to every counter"
    assert bad["fence"]["vetoedByFootprint"] == 0
    assert by_leaf(bad, "clean")["Outcome"] == "removed", (
        "with the funnel back, a live session's worktree is destroyed -- the mutant must KILL"
    )


def test_the_gitdir_fallback_is_actually_reached(fx: Fixture, sleeper: int) -> None:
    """``Split-Path -LiteralPath ... -Parent`` is an invalid PARAMETER SET, so it throws every time.

    With the throw swallowed, the whole fallback was dead code reporting zero probes while looking
    like it ran -- measured on the real corpus as 2090 unplaced writes and not one probe attempted.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.root / "elsewhere" / "x.py"]
    )
    fp = run(fx)["fence"]["footprint"]
    assert fp["writesUnplaced"] == 1
    assert fp["gitdirProbes"] > 0, "an unplaced write must at least have been probed"


# --- Hygiene, disjointness, and the anti-vacuity suite -------------------------------------------


def test_no_transcript_content_reaches_the_receipt(fx: Fixture, sleeper: int) -> None:
    """A transcript carries the full text a Write was given and the full command a Bash call ran.

    Extraction is an allow-list over two keys; everything else must be discarded UNREAD. This asserts
    it over both surfaces, because the human summary can leak on its own.
    """
    secret = "PXQZ-CANARY-PAYLOAD-9931"
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
        extra_input={
            "old_string": secret,
            "new_string": secret,
            "content": secret,
            "command": f"echo {secret}",
        },
    )
    res = run(fx)
    assert res["fence"]["vetoedByFootprint"] == 1, "the line WAS read, so this is not vacuous"
    assert secret not in json.dumps(res)
    assert secret not in run_text(fx).stdout


def test_signal_3_reads_nothing_signal_2_reads(fx: Fixture, sleeper: int) -> None:
    """Two signals that share an input are one signal wearing a disguise.

    Signal 2 is the newest mtime of seven git metadata files; signal 3 reads ``*.jsonl`` under a
    config root's ``projects``. Asserted at source level so the two can never quietly converge.
    """
    footprint = (SCRIPT.parent.parent / "coord" / "footprint.ps1").read_text(encoding="utf-8")
    for name in (*_GITDIR_FILES, "logs/HEAD"):
        assert f"'{name}'" not in footprint, f"signal 3 must not read signal 2's {name}"
    assert "*.jsonl" in footprint
    prune = SCRIPT.read_text(encoding="utf-8")
    activity = prune.split("function Get-WorktreeActivity", 1)[1].split("\n}", 1)[0]
    assert "jsonl" not in activity
    assert "projects" not in activity


def _mutant(tmp_path: Path, *subs: tuple[str, str, str]) -> Path:
    """A copy of the script tree with one guard removed, for proving a guard can FAIL.

    Every substitution is asserted to have matched: a mutant that silently did not apply is a test
    that passes for the same reason the guard it is checking would.
    """
    dst = tmp_path / f"mutant{len(list(tmp_path.glob('mutant*')))}"
    shutil.copytree(SCRIPT.parent.parent, dst / "scripts")
    for rel, old, new in subs:
        f = dst / "scripts" / rel
        text = f.read_text(encoding="utf-8")
        assert old in text, f"mutation target vanished from {rel}: {old!r}"
        f.write_text(text.replace(old, new, 1), encoding="utf-8")
    return dst / "scripts" / "worktree" / "prune-merged.ps1"


def test_mutant_dropping_the_footprint_join_loses_the_veto(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Strip the source out of the fence and the case this whole signal exists for comes back."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )
    assert run(fx)["fence"]["vetoedByFootprint"] == 1

    mutated = _mutant(
        tmp_path, ("coord/occupancy.ps1", "$sessions += @($fp.Footprints)", "# removed")
    )
    assert run(fx, script=mutated)["fence"]["vetoedByFootprint"] == 0, (
        "the veto survived a build with no footprint source, so it was never the thing producing it"
    )


def test_mutant_swallowing_a_parse_fault_stops_failing_closed(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """The 'veto, not vanish' regression, one layer up: drop the fault and a torn line goes quiet."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("gone") / "ok.py"],
        raw_tail='{"type":"assistant","x":"'
        + str(fx.sibling("clean")).replace("\\", "\\\\")
        + "\\",
    )
    assert run(fx)["fence"]["available"] is False

    mutated = _mutant(
        tmp_path,
        (
            "coord/footprint.ps1",
            """                try { $null = $tail | ConvertFrom-Json -EA Stop }
                catch {""",
            """                try { $null = $tail | ConvertFrom-Json -EA Stop }
                catch { }
                if ($false) {""",
        ),
    )
    assert run(fx, script=mutated)["fence"]["available"] is True, (
        "the refusal survived deleting the fault, so it was not the fault producing it"
    )


def test_a_corrupt_line_in_the_MIDDLE_of_a_transcript_also_refuses(
    fx: Fixture, sleeper: int
) -> None:
    """The other unparseable shape, and it is a different code path from the torn tail.

    The tail check exists because a truncated line may be cut before the ``tool_use`` marker the cheap
    pre-filter looks for; this one has the marker and still will not parse, which is what a corrupted
    or format-changed line looks like mid-file.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    esc = str(fx.sibling("clean") / "x.py").replace("\\", "\\\\")
    good = json.dumps({"type": "user", "note": "well formed"})
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("gone") / "ok.py"],
        raw_tail=f'{{"kind":"tool_use","p":"{esc}"\n{good}\n',
    )
    res = run(fx, "-Apply")
    assert res["_exit"] == 2
    assert res["fence"]["footprint"]["available"] is False
    assert any("will not parse" in x for x in res["fence"]["footprint"]["faults"])
    assert res["counts"]["removed"] == 0


def test_mutant_ORing_availability_stops_refusing(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Availability is ANDed across sources. Make it an OR and a blind source stops mattering."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
        path_key="target_path",
    )
    assert run(fx)["_exit"] == 2

    mutated = _mutant(
        tmp_path,
        (
            "coord/occupancy.ps1",
            "if (-not $fp.Available) {\n            $available = $false",
            "if ($false) {\n            $available = $false",
        ),
    )
    assert run(fx, script=mutated)["_exit"] != 2, (
        "the refusal survived disconnecting the footprint source from availability"
    )


def test_mutant_deriving_the_needle_from_gits_spelling_is_caught(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """The needle self-check, proven by reintroducing the bug it was written for.

    ``git worktree list`` reports FORWARD slashes; transcripts record backslashes. Deriving the
    escaped needle by replacing backslashes in git's output is a no-op, so the only spelling that
    matters has no needle. On the real corpus that silently halved the writes examined and left two
    worktrees a live session had written 79 times between them reading as untouched.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )
    good = run(fx)
    assert good["fence"]["vetoedByFootprint"] == 1
    assert good["fence"]["footprint"]["available"] is True

    mutated = _mutant(
        tmp_path,
        (
            "coord/footprint.ps1",
            "return @(($back.Replace('\\', '\\\\') + '\\\\'), ($fwd + '/'))",
            "return @(($b.Replace('\\', '\\\\') + '\\\\'), ($fwd + '/'))",
        ),
    )
    bad = run(fx, script=mutated)
    assert bad["fence"]["footprint"]["available"] is False, (
        "the needle self-check did not fire on a needle set with no backslash spelling"
    )
    assert any("backslash-spelled needle" in x for x in bad["fence"]["footprint"]["faults"])
    assert bad["_exit"] == 2


# --- The recorder that does not exist -------------------------------------------------------------


def test_nothing_on_the_hook_path_touches_the_footprint_scan() -> None:
    """This design records nothing, which is how 'a recorder failure must not break a tool call' is met.

    There is no hook, no settings.json entry and no store, so there is no write-side failure to have.
    The property that has to be defended is that it STAYS that way: the corpus scan must never end up
    behind a PreToolUse/SessionStart hook, where a slow or throwing scan would sit in front of every
    tool call. presence.ps1 is the SessionStart consumer of the same matcher and must not opt in.
    """
    coord = SCRIPT.parent.parent / "coord"
    presence = (coord / "presence.ps1").read_text(encoding="utf-8")
    assert "Get-WorktreeOccupancy" in presence, "still the same matcher, or this proves nothing"
    assert "-IncludeFootprints" not in presence
    for name in ("overlap.ps1", "session-registry.ps1", "presence.ps1"):
        # The dot-source, not a mention: session-registry.ps1 explains in prose WHY the shared
        # normaliser lives there rather than in the scanner, and that is not a dependency.
        assert 'footprint.ps1"' not in (coord / name).read_text(encoding="utf-8"), (
            f"{name} is on a hook path and must not pull the corpus scan in"
        )
    hooks = SCRIPT.parent.parent / "hooks"
    if hooks.is_dir():
        for f in hooks.glob("*.ps1"):
            assert "footprint" not in f.read_text(encoding="utf-8").lower()


# --------------------------------------------------------------------------------------------------
# Signal 4: the operator pin -- the only cover for a writer that is not a Claude tool call
# --------------------------------------------------------------------------------------------------

PIN_CLI = SCRIPT.parent / "worktree-pin.ps1"


def _pin_dir(fx: Fixture) -> Path:
    common = subprocess.run(
        ["git", "-C", str(fx.primary), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    d = Path(common) / "worktree-pins"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_pin(fx: Fixture, slug: str, *, hours: float = 12, reason: str = "hand-editing") -> Path:
    """Write a pin directly, so the reader is under test rather than the CLI."""
    import datetime

    exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=hours)
    f = _pin_dir(fx) / f"{slug}.{os.getpid()}.{abs(hash((slug, hours))) % 10**8:08x}.json"
    f.write_text(
        json.dumps(
            {
                "path": str(fx.sibling(slug)),
                "reason": reason,
                "by": "an-operator",
                "pid": os.getpid(),
                "at": datetime.datetime.now(datetime.UTC).isoformat(),
                "expiresAt": exp.isoformat().replace("+00:00", "Z"),
            }
        ),
        encoding="utf-8",
    )
    return f


def test_a_pin_vetoes_a_worktree_no_other_signal_can_see(fx: Fixture, sleeper: int) -> None:
    """A human editing in an editor leaves no registry record and no transcript. This is the cover.

    ``repo-gone`` is the positive control in the same invocation.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    _write_pin(fx, "clean", reason="hand-editing in VS Code")

    res = run(fx, "-Apply")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert d["Outcome"] != "removed"
    assert "operator pin" in d["Reason"]
    assert res["fence"]["vetoedByPin"] == 1
    assert res["fence"]["vetoedByCwd"] == 0
    assert res["fence"]["vetoedByFootprint"] == 0
    assert res["fence"]["pins"]["examined"] == 1
    assert by_leaf(res, "gone")["Outcome"] == "removed", "positive control"


def test_name_cannot_override_a_pin(fx: Fixture, sleeper: int) -> None:
    """Same rule as signals 1 and 3: the flag reached for when the tool refuses cannot reach it."""
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    _write_pin(fx, "clean")
    res = run(fx, "-Apply", "-Name", "clean")
    assert by_leaf(res, "clean")["Outcome"] != "removed"
    assert fx.sibling("clean").exists()


def test_an_expired_pin_does_not_veto(fx: Fixture, sleeper: int) -> None:
    """Every pin expires, or the first forgotten one becomes a permanent refusal."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    _write_pin(fx, "clean", hours=-1)
    res = run(fx, "-Apply")
    assert res["fence"]["pins"]["expired"] == 1
    assert res["fence"]["vetoedByPin"] == 0
    assert by_leaf(res, "clean")["Outcome"] == "removed"


def test_an_unparseable_pin_makes_the_fence_unavailable(fx: Fixture, sleeper: int) -> None:
    """A half-written pin is what somebody taking one right now looks like; its path is unknowable."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    (_pin_dir(fx) / "half.json").write_text('{"path": "C:\\\\so', encoding="utf-8")
    res = run(fx, "-Apply")
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert res["fence"]["pins"]["available"] is False
    assert res["fence"]["pins"]["unreadable"] == 1
    assert res["counts"]["removed"] == 0
    assert fx.sibling("clean").exists()


def test_a_pin_with_no_expiry_is_a_fault_not_an_eternal_veto(fx: Fixture, sleeper: int) -> None:
    """It cannot be aged out, so honouring it would refuse for ever and dropping it would lose a veto."""
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    (_pin_dir(fx) / "forever.json").write_text(
        json.dumps({"path": str(fx.sibling("clean")), "reason": "no expiry"}), encoding="utf-8"
    )
    res = run(fx, "-Apply")
    assert res["_exit"] == 2
    assert any("never age out" in f for f in res["fence"]["pins"]["faults"])
    assert res["counts"]["removed"] == 0


def test_a_stale_pin_for_a_removed_worktree_heals_instead_of_bricking(
    fx: Fixture, sleeper: int
) -> None:
    """An unexpired pin naming a path that EXISTS and is no worktree is a fault -- it could be this
    repo, spelled a way the matcher does not recognise.

    An EXPIRED one is not, or a pin outliving the worktree it named would refuse every run for ever
    and the only fix would be for somebody to find and delete a file they have never heard of.

    THE FIXTURE USED TO NAME A DIRECTORY THAT DID NOT EXIST for the fault half, and that conflated the
    two cases: an unexpired pin on a path that is not on disk at all is what a BIRTH PIN becomes the
    second its worktree is removed, and treating it as a fault took the whole fence down for hours
    (see ``test_a_pin_whose_worktree_is_GONE_does_not_brick_the_fence``). Nothing can occupy a
    directory that is not there, under any spelling, so only an existing path can hide a veto -- which
    is what this now pins down, both halves in one run.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    import datetime

    d = _pin_dir(fx)
    exists_but_not_a_worktree = fx.root / "long-gone-worktree"
    exists_but_not_a_worktree.mkdir(exist_ok=True)
    stale = {
        "path": str(exists_but_not_a_worktree),
        "reason": "x",
        "expiresAt": (
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
        ).isoformat(),
    }
    (d / "stale.json").write_text(json.dumps(stale), encoding="utf-8")
    ok = run(fx)
    assert ok["fence"]["pins"]["available"] is True
    assert ok["fence"]["pins"]["expired"] == 1
    assert ok["fence"]["pins"]["unplaceable"] == 0

    live = dict(stale)
    live["expiresAt"] = (
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    ).isoformat()
    (d / "live.json").write_text(json.dumps(live), encoding="utf-8")
    bad = run(fx, "-Apply")
    assert bad["_exit"] == 2
    assert bad["fence"]["pins"]["unplaceable"] == 1
    assert bad["fence"]["pins"]["gone"] == 0, (
        "the path exists, so this is not the self-healing case"
    )
    assert bad["counts"]["removed"] == 0


def test_the_pin_cli_takes_lists_and_releases(fx: Fixture) -> None:
    """Drive the real CLI: an operator's only way in, and a separate surface from the reader."""

    def cli(*args: str) -> dict[str, Any]:
        proc = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(PIN_CLI),
                "-Repo",
                str(fx.primary),
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert proc.stdout.strip(), f"exit {proc.returncode}: {proc.stderr}"
        out: dict[str, Any] = json.loads(proc.stdout)
        out["_exit"] = proc.returncode
        return out

    took = cli(
        "-Take", "-Path", str(fx.sibling("clean")), "-Reason", "by hand", "-Hours", "3", "-Json"
    )
    assert Path(took["pin"]).exists()
    listed = cli("-List", "-Json")
    assert listed["available"] is True
    assert [p["worktree"] for p in listed["pins"]] == ["repo-clean"]
    assert listed["pins"][0]["reason"] == "by hand"
    cli("-Release", took["pin"], "-Json")
    assert cli("-List", "-Json")["pins"] == []


def test_the_pin_cli_refuses_to_create_a_live_landmine(fx: Fixture) -> None:
    """A pin on a non-worktree path is a FAULT to the reader: it would refuse every run until it expired."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PIN_CLI),
            "-Repo",
            str(fx.primary),
            "-Take",
            "-Path",
            str(fx.root),
            "-Reason",
            "oops",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode != 0
    assert "not a registered worktree" in proc.stderr + proc.stdout


def test_concurrent_pins_do_not_lose_each_other(fx: Fixture) -> None:
    """One file per pin, never a read-modify-write over a shared list.

    The measured failure of the naive shape was six concurrent writers leaving ONE surviving write
    and six stray temp files -- and subagents share a process, so a pid alone is not a unique key.
    """
    procs = [
        subprocess.Popen(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(PIN_CLI),
                "-Repo",
                str(fx.primary),
                "-Take",
                "-Path",
                str(fx.sibling("clean")),
                "-Reason",
                f"writer {i}",
                "-Json",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for i in range(6)
    ]
    for p in procs:
        assert p.wait(timeout=180) == 0
    d = _pin_dir(fx)
    assert len(list(d.glob("*.json"))) == 6, "a concurrent writer was lost"
    assert list(d.glob("*.tmp")) == [], "temp files were left behind"


def test_new_ps1_takes_a_birth_pin(fx: Fixture) -> None:
    """A brand-new worktree is merged, clean and history-free from the second it exists.

    That is exactly the state that got one destroyed, and no other signal covers it. Asserted at
    source level: driving new.ps1 end to end would provision a venv.
    """
    text = (SCRIPT.parent / "new.ps1").read_text(encoding="utf-8")
    assert "New-WorktreePin" in text
    assert "pin.ps1" in text
    # Best-effort, or worktree creation starts failing for a fence's benefit.
    block = text.split("New-WorktreePin", 1)[0].rsplit("try {", 1)[1]
    assert "catch" not in block
    assert "could not take a birth pin" in text


def test_a_footprint_source_that_throws_refuses_instead_of_crashing(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """However it fails, it must fail as a REFUSAL with a receipt -- never as a stack trace.

    A destructive tool that dies mid-decision leaves the operator with no table and no exit code they
    can act on, and the next thing they reach for is the override.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    mutated = _mutant(
        tmp_path,
        ("coord/footprint.ps1", "$now = Get-Date", "throw 'synthetic scanner failure'"),
    )
    res = run(fx, "-Apply", script=mutated)
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert "threw" in res["fence"]["footprint"]["detail"]
    assert res["counts"]["removed"] == 0
    assert fx.sibling("clean").exists()


# --------------------------------------------------------------------------------------------------
# The adversarial round: four independent reviews drove the scanner and the pruner against the real
# corpus and found holes that every green test above walked straight past. Each test here reproduces
# one, and each carries either a positive control or a mutation that puts the hole back.
# --------------------------------------------------------------------------------------------------


def test_the_occupancy_fence_is_re_read_for_EVERY_removal_not_once_for_the_loop(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """A session that arrives DURING the first removal must still stop the second one.

    The re-read used to sit above the ``foreach``, so signals 1, 3 and 4 were frozen at the moment the
    first removal began and only signal 2 -- the crude 36 h metadata heuristic -- was refreshed per
    candidate. That inverts the branch's own arithmetic: signal 3 is the one with measured coverage,
    and it was the stale one for candidates 2..N. Signal 2 cannot cover this, because writing a
    transcript touches no git metadata.

    The git shim fires on the FIRST ``worktree remove`` and plants the footprint, so the arrival lands
    strictly between ``repo-clean``'s removal and ``repo-gone``'s. The positive control is the same
    footprint present BEFORE the run starts, in a separate invocation.
    """
    late = "cafe0001-1111-2222-3333-444444444444"

    # --- control: the identical footprint, already on disk ---
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=late)
    fx.write_transcript(session_id=late, cwd=fx.primary, writes=[fx.sibling("gone") / "late.py"])
    control = run(fx, "-Apply")
    assert by_leaf(control, "gone")["Outcome"] != "removed", "control: it vetoes when it is there"
    assert control["fence"]["vetoedByFootprint"] == 1

    # --- the race: the same footprint, written mid-run by the removal of the FIRST candidate ---
    fx2 = _build(tmp_path / "race")
    _backdate(fx2.primary, fx2.sibling("clean"), 500)
    _backdate(fx2.primary, fx2.sibling("gone"), 500)
    fx2.write_session(pid=sleeper, cwd=fx2.primary, session_id=late)

    planter = tmp_path / "plant.py"
    planter.write_text(
        "import json, os, pathlib, time\n"
        f"base = pathlib.Path(r{str(fx2.cfg)!r}) / 'projects' / 'proj' / {late!r} / 'subagents'\n"
        "base.mkdir(parents=True, exist_ok=True)\n"
        "f = base / 'agent-late.jsonl'\n"
        "when = time.time() - 60\n"
        "stamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(when)) + '.000Z'\n"
        f"target = str(pathlib.Path(r{str(fx2.sibling('gone'))!r}) / 'late.py')\n"
        "rec = {'type': 'assistant', 'isSidechain': True, 'sessionId': " + repr(late) + ",\n"
        f"       'cwd': r{str(fx2.primary)!r}, 'timestamp': stamp,\n"
        "       'message': {'role': 'assistant', 'content': [\n"
        "           {'type': 'tool_use', 'id': 't1', 'name': 'Write',\n"
        "            'input': {'file_path': target}}]}}\n"
        "f.write_text(json.dumps(rec) + '\\n', encoding='utf-8')\n"
        "os.utime(f, (when, when))\n",
        encoding="utf-8",
    )

    d = _shim_dir(tmp_path)
    real = shutil.which("git")
    assert real, "git must be on PATH"
    mark = d / "fired"
    (d / "git.ps1").write_text(
        f"$mark = '{mark}'\n"
        "if (($args -contains 'worktree') -and ($args -contains 'remove') -and "
        "-not (Test-Path -LiteralPath $mark)) {\n"
        "  Set-Content -LiteralPath $mark -Value '1'\n"
        f"  & '{sys.executable}' '{planter}' | Out-Null\n"
        "}\n"
        f"& '{real}' @args\n"
        "exit $LASTEXITCODE\n",
        encoding="utf-8",
    )

    res = run(fx2, "-Apply", path_prepend=d)
    assert mark.exists(), "the shim never fired -- this test would prove nothing"
    assert by_leaf(res, "clean")["Outcome"] == "removed", "the first removal must happen"
    assert by_leaf(res, "gone")["Outcome"] != "removed", (
        "a live session's write landed in repo-gone during removal #1 and it was destroyed anyway"
    )
    assert "footprint" in json.dumps(by_leaf(res, "gone")["Occupants"])
    assert fx2.sibling("gone").exists()


def test_a_write_tool_RENAME_is_a_fault_not_a_silent_zero(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Canary 4, and the hole every other canary is structurally unable to see.

    Canaries 1-3 are denominated on PATH-BEARING blocks, which stay perfectly healthy through a rename
    of the write TOOL NAMES. Measured on the real repo with ``Write``/``Edit`` renamed in the
    allow-list: ``vetoedByFootprint`` 5 -> 0, ``available`` still true, ``faults`` empty, ``note``
    empty, ``pathBlocksExamined`` UP by three -- and ``MessageFoundry-pins``, with a LIVE session that
    had written into it 61 times from another checkout, went from SKIP to PRUNE.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )
    good = run(fx, "-Apply")
    assert good["fence"]["vetoedByFootprint"] == 1, "control"
    assert good["fence"]["footprint"]["writeToolNamesSeen"] == ["Edit"]

    mutated = _mutant(
        tmp_path,
        (
            "coord/footprint.ps1",
            "$script:FootprintWriteTools = @('Write', 'Edit', 'MultiEdit', 'NotebookEdit')",
            "$script:FootprintWriteTools = @('WriteFile', 'EditFile')",
        ),
    )
    bad = run(fx, "-Apply", script=mutated)
    fp = bad["fence"]["footprint"]
    assert fp["writesExamined"] == 0, "the rename really did take extraction to zero"
    assert fp["pathBlocksExamined"] > 0, "...while the other canaries' denominator stayed healthy"
    assert fp["available"] is False, "canary 4 did not fire on a vocabulary that no longer matches"
    assert any("tool vocabulary has moved" in x for x in fp["faults"])
    assert bad["_exit"] == 2
    assert bad["counts"]["removed"] == 0
    assert fx.sibling("clean").exists()


def test_a_shell_only_window_does_not_brick_the_pruner(fx: Fixture, sleeper: int) -> None:
    """Canary 1 must fire on a MOVED KEY, never on a window that simply ran no path tools.

    Its denominator used to be "transcripts mentioning this repo", so a 36 h window whose only in-repo
    tool calls were shell or search commands -- a monitoring loop, a CI babysit, a git-only session --
    refused every prune, for up to 36 h, with no override flag, and told the operator to go looking for
    a vendor schema change that had not happened. Denominating on tools that carry a path BY
    DEFINITION is the same detection without the false positive.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    # A Bash block naming the repo: it carries `command`, never a path key.
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("clean") / "x.py"],
        tool="Bash",
        path_key="command",
    )
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["transcriptsWithNeedle"] >= 1, "the repo IS named, or this proves nothing"
    assert fp["pathToolBlocks"] == 0, "no tool that must carry a path was called"
    assert fp["pathBlocksExamined"] == 0
    assert fp["available"] is True, "a shell-only window is not a schema change"
    assert fp["faults"] == []
    assert by_leaf(res, "clean")["Outcome"] == "removed", "it must not brick the tool"


def test_an_unrelated_project_subagent_does_not_brick_the_pruner(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """Canary 2's numerator was repo-scoped and its denominator machine-wide.

    ``SidechainFiles`` counted every in-window subagent transcript on the host; ``SidechainLines``
    counted only lines that survived the repo needle funnel. So one subagent run in ANY other project,
    with no MessageFoundry subagent write in the same window, refused every prune for up to 36 h and
    blamed a vendor schema change. Measured on this host: 122 of 475 in-window subagent transcripts
    already belong to other projects.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    outside = fx.root / "another-repo"
    outside.mkdir(exist_ok=True)
    # A subagent in a DIFFERENT project, writing somewhere else entirely.
    fx.write_transcript(
        session_id="deadbeef-0000",
        cwd=outside,
        writes=[outside / "z.py"],
        project="some-other-project",
        sidechain=True,
    )
    # ...and an ordinary parent-session touch of THIS repo in the same window, which is what makes the
    # old numerator/denominator mismatch bite: work another project with subagents, touch this one from
    # the main session only. ``repo-gone`` absorbs it so ``repo-clean`` stays the positive control.
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("gone") / "ok.py"],
        sidechain=False,
    )
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["sidechainFiles"] >= 1
    assert fp["sidechainLines"] >= 1, (
        "its lines must be parsed, or the two sides are not comparable"
    )
    assert fp["available"] is True and fp["faults"] == []
    assert by_leaf(res, "clean")["Outcome"] == "removed", "it must not brick the tool"

    # And the funnel, put back: the same corpus now refuses, blaming a marker that never moved.
    mutated = _mutant(
        tmp_path,
        (
            "coord/footprint.ps1",
            '        $all = $txt.Split("`n")',
            '        if (-not $family) { continue }\n        $all = $txt.Split("`n")',
        ),
    )
    bad = run(fx, "-Apply", script=mutated)
    assert bad["fence"]["footprint"]["available"] is False
    assert any("subagent marker has moved" in x for x in bad["fence"]["footprint"]["faults"])


def test_a_tail_torn_BEFORE_the_path_still_refuses(fx: Fixture, sleeper: int) -> None:
    """A torn tail was a fault only if the tear landed AFTER the path bytes.

    The path sits deep inside the line, so a tear before it is the MORE likely one -- and it produced
    ``available=true, faults=0`` plus a Note positively asserting that nothing in the window mentioned
    this repo. Relevance is now decided per FILE, not per tail.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER,
        cwd=fx.primary,
        writes=[fx.sibling("gone") / "ok.py"],
        # Cut before "tool_use" AND before any path: neither the old marker gate nor the old needle
        # gate would have looked at this line.
        raw_tail='{"type":"assistant","message":{"content":[{"ty',
    )
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["available"] is False, "a half-written final line is a session writing RIGHT NOW"
    assert any("half-written" in x for x in fp["faults"])
    assert res["_exit"] == 2
    assert res["counts"]["removed"] == 0


def test_a_torn_tail_in_an_UNRELATED_transcript_is_counted_not_refused(
    fx: Fixture, sleeper: int
) -> None:
    """The other half of the same rule, and the reason it is scoped rather than absolute.

    The scan is machine-wide, so faulting on any unparseable line anywhere would refuse every run for
    as long as ANY session on the host is mid-append. A fence nobody can use is a fence that gets
    bypassed. ``repo-clean`` coming back removed is the positive control.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    outside = fx.root / "another-repo"
    outside.mkdir(exist_ok=True)
    fx.write_transcript(
        session_id="deadbeef-0000",
        cwd=outside,
        writes=[outside / "z.py"],
        project="some-other-project",
        raw_tail='{"type":"assistant","message":{"content":[{"ty',
    )
    res = run(fx, "-Apply")
    fp = res["fence"]["footprint"]
    assert fp["linesUnparseableElsewhere"] >= 1, "it must be COUNTED, not silently dropped"
    assert fp["available"] is True and fp["faults"] == []
    assert by_leaf(res, "clean")["Outcome"] == "removed", "positive control"


def test_a_corpus_root_without_a_session_registry_is_still_scanned(
    fx: Fixture, sleeper: int, tmp_path: Path
) -> None:
    """The corpus was discovered by a predicate about a directory it does not read.

    ``Get-ClaudeConfigRoots`` admitted a root only if it held ``sessions``; footprint.ps1 reads
    ``projects``. A root with a full corpus and no session registry -- an account swap mid-flight, and
    this machine carries a ``.claude-swap-backup`` -- was dropped BEFORE ``RootsExamined`` counted it,
    so the receipt reported a healthy scan over a corpus that had vanished.
    """
    home = tmp_path / "home"
    (home / ".claude" / "sessions").mkdir(parents=True)
    (home / ".claude" / "sessions" / f"{sleeper}.json").write_text(
        json.dumps(
            {
                "pid": sleeper,
                "sessionId": SID_WRITER,
                "cwd": str(fx.primary),
                "startedAt": int(time.time() * 1000),
                "entrypoint": "claude-desktop",
                "kind": "interactive",
            }
        ),
        encoding="utf-8",
    )
    # The corpus lives in a SECOND root that has no sessions/ at all.
    corpus = Fixture(fx.root)
    corpus.cfg = home / ".claude-corpus"
    (corpus.cfg / "projects").mkdir(parents=True)
    _quiesce(fx, "clean", "gone")
    corpus.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"] * 2
    )

    env = {"USERPROFILE": str(home)}
    res = run(fx, "-Apply", config_root=None, env_extra=env)
    fp = res["fence"]["footprint"]
    assert fp["rootsExamined"] == 2, "the sessions-less root must be COUNTED, not silently dropped"
    assert fp["rootsWithCorpus"] == 1
    assert fp["transcriptsFound"] == 1
    assert res["fence"]["vetoedByFootprint"] == 1
    assert by_leaf(res, "clean")["Outcome"] != "removed"
    assert by_leaf(res, "gone")["Outcome"] == "removed", "positive control"

    mutated = _mutant(
        tmp_path,
        (
            "coord/footprint.ps1",
            "-MustContain @('sessions', 'projects')",
            "-MustContain @('sessions')",
        ),
    )
    bad = run(fx, "-Apply", config_root=None, env_extra=env, script=mutated)
    bfp = bad["fence"]["footprint"]
    assert bfp["rootsExamined"] == 1 and bfp["transcriptsFound"] == 0
    assert bfp["available"] is True and bfp["faults"] == [], (
        "the loss is SILENT -- that is the defect"
    )
    assert by_leaf(bad, "clean")["Outcome"] == "removed", "the mutant must KILL"


def test_a_pin_whose_worktree_is_GONE_does_not_brick_the_fence(fx: Fixture, sleeper: int) -> None:
    """new.ps1 takes a 6 h birth pin and nothing released it.

    So ``new.ps1 -Name x`` / 20 minutes of work / ``remove.ps1 -Name x`` left an UNEXPIRED pin naming
    a directory that no longer existed, which made the ENTIRE fence unavailable for the rest of the
    6 h, for every session, with no override flag and a message naming a path the operator could not
    find. A directory that is not there cannot be occupied under any spelling, so ignoring it cannot
    hide a veto. The positive control is the next test: a path that DOES exist still faults.
    """
    import datetime

    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    ghost = _pin_dir(fx) / "repo-born.999.deadbeef.json"
    ghost.write_text(
        json.dumps(
            {
                "path": str(fx.sibling("never-existed")),
                "reason": "created by new.ps1",
                "by": "new.ps1",
                "pid": 999,
                "at": datetime.datetime.now(datetime.UTC).isoformat(),
                "expiresAt": (
                    datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=6)
                ).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    res = run(fx, "-Apply")
    ps = res["fence"]["pins"]
    assert ps["gone"] == 1, "it must be counted, not merely tolerated"
    assert ps["unplaceable"] == 0
    assert ps["available"] is True and res["fence"]["available"] is True
    assert by_leaf(res, "clean")["Outcome"] == "removed", "it must not brick the tool"


def test_a_pin_on_a_path_that_EXISTS_and_is_no_worktree_still_refuses(
    fx: Fixture, sleeper: int
) -> None:
    """The positive control for the test above, and the case that must stay fail-closed.

    A directory that exists but places nowhere could be this repo's worktree under a spelling the
    matcher does not recognise -- and that is a missed veto, not a stale pin.
    """
    import datetime

    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    real_dir = fx.root / "a-real-directory"
    real_dir.mkdir(exist_ok=True)
    (_pin_dir(fx) / "odd.998.beefdead.json").write_text(
        json.dumps(
            {
                "path": str(real_dir),
                "reason": "hand-editing",
                "by": "someone",
                "pid": 998,
                "at": datetime.datetime.now(datetime.UTC).isoformat(),
                "expiresAt": (
                    datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=6)
                ).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    res = run(fx, "-Apply")
    assert res["fence"]["pins"]["unplaceable"] == 1
    assert res["fence"]["pins"]["gone"] == 0
    assert res["fence"]["available"] is False
    assert res["_exit"] == 2
    assert res["counts"]["removed"] == 0


def test_removing_a_worktree_releases_its_pins(fx: Fixture) -> None:
    """The other half of the birth-pin fix: the store must not only ever grow.

    ``Remove-WorktreePins`` is driven for real here; ``remove.ps1`` resolves its repo from
    ``$PSScriptRoot`` and cannot be pointed at a fixture, so its wiring is asserted at source level --
    with the best-effort contract asserted too, since a pin that will not delete must never fail a
    removal that already happened.
    """
    kept = _write_pin(fx, "gone")
    doomed = _write_pin(fx, "clean")
    out = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{SCRIPT.parent.parent / 'coord' / 'pin.ps1'}'; "
            f"Remove-WorktreePins -Path '{fx.sibling('clean')}' -PinDir '{_pin_dir(fx)}'",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "1"
    assert not doomed.exists()
    assert kept.exists(), "only the named worktree's pins may go"

    text = (SCRIPT.parent / "remove.ps1").read_text(encoding="utf-8")
    assert "Remove-WorktreePins" in text
    assert "pin.ps1" in text
    block = text.split("Remove-WorktreePins", 1)[1]
    assert "catch" in block, "releasing a pin must never fail a removal that already happened"


def test_a_narrowed_footprint_window_is_declared(fx: Fixture, sleeper: int) -> None:
    """``-FootprintHours`` shipped with the exact hole ``-IdleHours`` was already burned by.

    ``-IdleHours 0.5``, typed for "half an hour", released every worktree on this repo and printed no
    warning at all; that is why a 12 h floor and a red banner exist for it. The new knob had neither,
    and the ``-Name`` banner in the same run asserted "signals 1 and 3 still apply" while signal 3 had
    been disarmed by the same command line.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    res = run(fx, "-FootprintHours", "0.5", "-Name", "clean")
    ra = " | ".join(res["fence"]["reducedAssurance"])
    assert "footprint window NARROWED to 0.5 h" in ra
    assert "signal 3 is NARROWED to 0.5 h" in ra, "the -Name banner must not claim signal 3 applies"
    assert "signals 1 and 3 still apply" not in ra

    off = run(fx, "-FootprintHours", "0")
    assert any("signal 3 is OFF" in x for x in off["fence"]["reducedAssurance"])


def test_the_SessionStart_roster_does_not_depend_on_the_corpus_scanner() -> None:
    """The old guard scanned three files for the dot-source and missed the only one that had it.

    ``presence.ps1`` dot-sources ``occupancy.ps1``, which dot-sourced ``footprint.ps1`` and ``pin.ps1``
    UNCONDITIONALLY -- so both sat on the SessionStart hook path. Measured with a parse error planted
    in ``footprint.ps1``: presence.ps1 exited 1 with no JSON, ``session-context.ps1`` caught it into an
    empty peer list, and the banner rendered identically minus the roster. Asserted at RUNTIME, because
    the source-level version of this test passed while the property was false.
    """
    coord = SCRIPT.parent.parent / "coord"
    probe = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{coord / 'presence.ps1'}' -Json 2>&1 | Out-Null; "
            "[pscustomobject]@{ "
            "  fp = [bool](Get-Command Get-WorktreeFootprints -EA SilentlyContinue); "
            "  pin = [bool](Get-Command New-WorktreePin -EA SilentlyContinue); "
            "  occ = [bool](Get-Command Get-WorktreeOccupancy -EA SilentlyContinue) "
            "} | ConvertTo-Json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    got = json.loads(probe.stdout)
    assert got["occ"] is True, "still the same matcher, or this proves nothing"
    assert got["fp"] is False, "the corpus scanner reached the SessionStart hook path"
    assert got["pin"] is False, "the pin store reached the SessionStart hook path"

    # And the file-level rule the runtime check enforces, including the file the old guard skipped.
    for name in ("overlap.ps1", "session-registry.ps1", "presence.ps1", "occupancy.ps1"):
        text = (coord / name).read_text(encoding="utf-8")
        for dep in ('footprint.ps1"', 'pin.ps1"'):
            # A dot-source at column 0 is file scope; one inside a function is not.
            top_level = [ln for ln in text.splitlines() if ln.startswith(". ") and dep in ln]
            assert not top_level, f"{name} loads {dep} at file scope, which is a hook path"


def test_a_broken_roster_does_not_silently_empty_the_coordination_banner(tmp_path: Path) -> None:
    """A failed roster and an empty roster used to render IDENTICALLY: the block just disappeared.

    So a session read "nobody else is here" off a dependency it does not use -- absence of evidence as
    evidence of absence, on the one banner that exists to prevent collisions. Driven for real against
    a copied tree whose ``presence.ps1`` fails, in both shapes: a THROW and a silent non-zero exit.
    The second is the one a try/catch alone does not cover, because nothing propagates through ``&``.
    """
    for label, stub in (
        ("throw", "throw 'synthetic roster failure'\n"),
        ("silent exit", "exit 1\n"),
    ):
        dst = tmp_path / f"tree-{label.replace(' ', '-')}"
        shutil.copytree(SCRIPT.parent.parent, dst / "scripts")
        (dst / "scripts" / "coord" / "presence.ps1").write_text(stub, encoding="utf-8")
        out = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(dst / "scripts" / "worktree" / "session-context.ps1"),
            ],
            capture_output=True,
            text=True,
            cwd=str(SCRIPT.parent.parent.parent),
            check=False,
        )
        assert "PEER ROSTER UNAVAILABLE" in out.stdout, (
            f"a {label} in presence.ps1 emptied the roster silently: {out.stdout[-600:]}"
        )
        assert "Do not read this as 'nobody else is here'" in out.stdout
        assert "This chat's worktree" in out.stdout, "the rest of the banner must still render"

    # And the control: the real presence.ps1 renders no such marker.
    ok = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT.parent / "session-context.ps1"),
        ],
        capture_output=True,
        text=True,
        cwd=str(SCRIPT.parent.parent.parent),
        check=False,
    )
    assert "PEER ROSTER UNAVAILABLE" not in ok.stdout


def test_a_transcript_that_cannot_be_stat_ed_would_be_silently_dropped(
    fx: Fixture, sleeper: int
) -> None:
    """The one guard here I could NOT kill, recorded as such rather than claimed as covered.

    ``File.GetLastWriteTime`` does not throw on a missing file -- it returns the 1601 epoch, which is
    older than any cut, so a transcript that moved or was deleted between the (lazy) enumeration and
    the stat was ``continue``d out of the window with ``Available`` still true and no fault.
    ``sessions.ps1 -Rehome`` MOVES transcripts as normal operation, so the window is real.

    What is asserted here is (a) the primitive that makes the guard REACHABLE on this runtime and
    (b) that the counter is on the receipt, so an operator would see it if it ever fired. What is NOT
    asserted is the guard firing end to end: three constructions were tried and none reproduces it --
    an extended-length name that non-extended APIs cannot resolve (.NET resolves it), a dangling
    symlink (``File.Exists`` returns true and the link's own mtime comes back), and deleting a file
    mid-enumeration (not deterministic at 13,700 files scanned in ~9 s). A guard that cannot be killed
    is a guard that is not really tested, and saying so is the point of this test existing.
    """
    probe = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$p = 'C:\\definitely\\no\\such\\file.jsonl'; "
            "[pscustomobject]@{ year = [System.IO.File]::GetLastWriteTime($p).Year; "
            "exists = [System.IO.File]::Exists($p) } | ConvertTo-Json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    got = json.loads(probe.stdout)
    assert got["year"] < 1800, "the sentinel this guard keys on is gone; re-derive the condition"
    assert got["exists"] is False

    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"]
    )
    fp = run(fx)["fence"]["footprint"]
    assert fp["transcriptsVanished"] == 0
    assert fp["transcriptsFound"] == 1, "and it counted the one that IS there"


def test_the_receipt_names_the_write_vocabulary_it_was_looking_for(
    fx: Fixture, sleeper: int
) -> None:
    """Canary 4 fires only when the intersection is EMPTY, so a PARTIAL rename leaves it green.

    That residual is real and cannot be closed by inference, so the vocabulary is made legible instead:
    the allow-list, what was actually seen against it, and every distinct tool name observed.
    """
    _quiesce(fx, "clean", "gone")
    fx.write_session(pid=sleeper, cwd=fx.primary, session_id=SID_WRITER)
    fx.write_transcript(
        session_id=SID_WRITER, cwd=fx.primary, writes=[fx.sibling("clean") / "x.py"], tool="Write"
    )
    res = run(fx)
    fp = res["fence"]["footprint"]
    assert fp["writeToolsAllowList"] == ["Write", "Edit", "MultiEdit", "NotebookEdit"]
    assert fp["writeToolNamesSeen"] == ["Write"], "seen != allowed, and the gap must be visible"
    assert "Write" in fp["toolNamesSeen"]
    text = run_text(fx).stdout
    assert "write tools recognised: Write of Write/Edit/MultiEdit/NotebookEdit" in text
