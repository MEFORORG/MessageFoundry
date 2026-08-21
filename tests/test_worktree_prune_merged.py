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
import re
import shutil
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests._dead_pid import never_live_pid

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


def _gitdir(worktree: Path) -> Path:
    return Path(
        subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--absolute-git-dir"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )


def _age_reflog(gitdir: Path, when: float) -> None:
    """Rewrite every ``logs/HEAD`` entry's epoch, which is what actually ages a reflog now.

    Signal 2 reads the reflog by CONTENT, not by mtime, because a ``git gc`` rewrites the file in
    place and used to move all of them to one identical mtime. So a fixture that only calls
    ``os.utime`` on ``logs/HEAD`` is no longer aging anything the script looks at -- it would be
    setting a field that is read only as a fallback.
    """
    log = gitdir / "logs" / "HEAD"
    if not log.exists():
        return
    lines = log.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        head, tab, msg = line.partition("\t")
        # "<old> <new> <name> <<email>> <epoch> <tz>" -- replace the epoch, keep the offset.
        head = re.sub(r"\d{9,11}(?=\s+[+-]\d{4}\s*$)", str(int(when)), head)
        out.append(head + tab + msg)
    log.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
    # Put the mtime back where the caller asked for it. Writing the file moved it to NOW -- which is
    # the gc's own signature -- so without this the fixture ages the CONTENT while leaving the
    # timestamp fresh, and `_backdate` silently stops setting the field it appears to set. That is
    # harmless only while the script reads content, and becomes a fixture that lies the moment anyone
    # reads the mtime again. Found by mutating the script: the CONTROL line failed instead of the
    # assertion under test, which is the tell.
    os.utime(log, (when, when))


def _backdate(primary: Path, worktree: Path, hours: float) -> None:
    """Age a worktree's PRIVATE git metadata so the activity veto releases it."""
    gitdir = _gitdir(worktree)
    when = time.time() - hours * 3600
    for rel in (*_GITDIR_FILES, "logs/HEAD"):
        f = gitdir / rel
        if f.exists():
            os.utime(f, (when, when))
    _age_reflog(gitdir, when)


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


def _clone(template: Path, dest: Path) -> Fixture:
    """Copy a prebuilt fixture family and rebind every absolute path git recorded inside it.

    ``_build`` is ~30 git subprocesses and, measured on this checkout, **2.4s of the 3.9s an average
    test in this file costs**. The file runs it 60 times (59 function-scoped ``fx`` + one
    ``readonly_fx``) to produce 60 byte-identical repos. This is the cheap half: copy the tree, then
    fix the two things a copy gets wrong. Serial, same 71 tests passing: 250.7s -> 166.3s.

    Only two kinds of absolute path survive a copy, and both are repairable in one subprocess each:

    * the primary's ``origin`` remote URL, which still names the TEMPLATE's bare repo -- so a
      ``-Fetch`` test would silently reach the wrong origin rather than fail. Not hypothetical:
      ``test_apply_fetches_for_real`` pushes, and without this line the push lands in the template.
    * the worktree registrations, in BOTH directions (each tree's ``.git`` file names its gitdir, and
      each ``.git/worktrees/<name>/gitdir`` names its tree). ``git worktree repair`` exists for exactly
      this and rewrites the whole family in a single call.

    WHICH TREES TO REPAIR IS DERIVED FROM THE FILESYSTEM, NEVER FROM A NAME PATTERN. A linked worktree
    has a ``.git`` FILE; a repository has a ``.git`` DIRECTORY. That one distinction excludes both the
    primary and ``decoy`` (a SEPARATE repo that merely shares the name prefix) by construction, so
    adding a worktree to ``_build`` needs no matching edit here. A ``repo-*`` glob would have gone
    quietly wrong instead: an unmatched tree keeps TEMPLATE-absolute registrations in both directions
    and the test then exercises the wrong tree while passing.

    Note ``git worktree list`` cannot be used for this -- before the repair its registrations still
    name the template, so it reports the paths we are trying to correct.

    Mtimes are preserved (``copytree`` uses ``copy2``), which is load-bearing -- the activity veto
    reads the newest mtime of the private git metadata, and ``_backdate`` moves it. The reflog is
    carried by CONTENT for the same reason: since 2026-08-18 the veto reads ``logs/HEAD``'s last
    ENTRY rather than its mtime, so a copy that preserved only the timestamp would age nothing the
    script actually looks at. The template ages by at most the file's own runtime, minutes against a
    36h window, and no test asserts an exact age.
    """
    shutil.copytree(template, dest, symlinks=True, dirs_exist_ok=True)
    fx = Fixture(dest)
    _git(fx.primary, "remote", "set-url", "origin", str(dest / "origin.git"))
    trees = sorted(p.parent for p in dest.rglob(".git") if p.is_file())
    assert trees, f"no linked worktrees found under {dest} -- the copy is not a fixture family"
    _git(fx.primary, "worktree", "repair", *(str(p) for p in trees))

    # Post-condition, because everything downstream rests on git's repair semantics rather than on any
    # code here: a registration still naming the template means this clone shares state with every
    # other clone, which is silent cross-test contamination rather than a failure. Plain file reads,
    # not another subprocess -- this runs 60 times a session.
    stale = sorted(
        p
        for p in (fx.primary / ".git" / "worktrees").glob("*/gitdir")
        if str(template) in p.read_text(encoding="utf-8")
    )
    assert not stale, f"worktree repair left {len(stale)} registration(s) on the template: {stale}"
    return fx


@pytest.fixture(scope="session")
def _template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The one real ``_build`` per worker. Never handed to a test.

    Kept pristine on purpose: every other fixture in this file is a copy of it, so a test that
    mutated it would poison every LATER test in the worker -- an order-dependent failure, which is
    the expensive kind. Tests get clones; nothing gets this.
    """
    root = tmp_path_factory.mktemp("prune-template")
    _build(root)
    return root


@pytest.fixture(scope="session")
def readonly_fx(_template: Path, tmp_path_factory: pytest.TempPathFactory) -> Fixture:
    """Shared by the dry-run tests, which mutate no GIT state. They do mutate the config tree.

    The precise claim matters, because the loose one ("these tests mutate nothing") was wrong and
    would have made the accumulation below look impossible rather than merely harmless. Every test
    here calls ``live_record``, which writes ``cfg/sessions/<pid>.json``; ``sleeper`` is
    function-scoped, so each writes a DIFFERENT filename and none is ever cleaned up. A test late in
    the file therefore sees every earlier test's record, all but its own belonging to a pid that has
    since been killed.

    Harmless today, and only by luck of what is asserted: those leftovers are well-formed and dead,
    and a dead record is neither a veto nor a permission (``test_dead_record_is_not_a_veto_and_not_a
    _permission``), so decisions are unaffected. It stops being harmless the moment a test here
    asserts on a COUNT -- records examined, unplaceable, or live-in-repo -- because that count then
    depends on how many tests ran first. Add such an assertion and this fixture must gain a cleanup,
    or that test must take function-scoped ``fx`` instead.

    Still its own clone rather than the template itself: the template must stay pristine for every
    other clone in the worker, so sharing it here would turn this accumulation from harmless into
    contamination of the whole file.
    """
    return _clone(_template, tmp_path_factory.mktemp("prune-ro"))


@pytest.fixture
def fx(_template: Path, tmp_path: Path) -> Fixture:
    """Function-scoped, for the -Apply tests.

    Worktree registrations are absolute-path-bound, so a mutated fixture cannot be REUSED -- but it
    can be copied and rebound, which is what ``_clone`` does and why this is no longer a full rebuild.
    """
    return _clone(_template, tmp_path)


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
    dead = never_live_pid()
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


# --------------------------------------------------------------------------------------------------
# Coordination claims stranded by a removal (BACKLOG #345)
#
# A claim lives beside the SHARED object store, so it outlives the worktree that took it. Removing the
# worktree used to leave the claim file behind, and `claim.ps1 -Take` hard-blocks on any claim file that
# exists -- so the key became unclaimable by every future session until a human ran `-Release -Force`.
#
# The dangerous direction here is the FALSE POSITIVE, not the miss: releasing a claim held by a
# different, LIVING worktree hands its key away and invites the duplicate build the registry exists to
# stop. So the negative test below is the load-bearing one, and it carries a positive control in the
# same invocation to prove it did not pass by the run doing nothing at all.
# --------------------------------------------------------------------------------------------------


def _claims_dir(fx: Fixture) -> Path:
    """Where claim.ps1 puts claims: <git-common-dir>/mefor-coord/claims."""
    common = Path(
        subprocess.run(
            [
                "git",
                "-C",
                str(fx.primary),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    d = common / "mefor-coord" / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_claim(fx: Fixture, key: str, worktree: Path | str, *, note: str = "work") -> Path:
    """Write a claim exactly as claim.ps1 does: folded filename, UTF-8 with NO BOM.

    The BOM matters -- claim.ps1 comments that the python-side gate reads these with
    ``encoding="utf-8"`` and a BOM makes ``json.loads`` raise, which would be swallowed into "not
    claimed" and silently disable the gate. A fixture that wrote one would be testing a file shape the
    real tool never produces.
    """
    safe = re.sub(r"[^a-z0-9._-]+", "-", key.strip().lower()).strip("-")
    f = _claims_dir(fx) / f"{safe}.json"
    f.write_bytes(
        json.dumps(
            {
                "key": key,
                "note": note,
                "branch": "some-branch",
                "worktree": str(worktree),
                "claimed": "2026-08-02T00:00:00.0000000+00:00",
            }
        ).encode("utf-8")
    )
    return f


def test_a_claim_held_by_a_pruned_worktree_is_released(fx: Fixture, sleeper: int) -> None:
    """The orphan this exists to remove.

    Written with BACKSLASHES, which is what `str(Path)` gives on Windows, while claim.ps1 records the
    forward-slash form from `git rev-parse --path-format=absolute`. Both must match the same worktree
    or the release silently does nothing -- a miss that would look exactly like success.
    """
    live_record(fx, sleeper, fx.primary)
    claim = write_claim(fx, "clean-work", fx.sibling("clean"), note="the pruned session's work")

    res = run(fx, "-Apply", "-IdleHours", "0")

    d = by_leaf(res, "clean")
    assert d["Outcome"] == "removed"
    assert d["ClaimsReleased"] == ["clean-work"]
    assert d["ClaimsUnreleased"] == []
    assert not claim.exists(), "the claim file outlived its worktree and now blocks the key forever"
    assert res["counts"]["claimsReleased"] == 1
    assert res["counts"]["claimsUnreleased"] == 0
    assert res["_exit"] == 0


def test_a_claim_held_by_a_LIVING_worktree_is_never_released(fx: Fixture, sleeper: int) -> None:
    """The false positive, which is worse than the bug being fixed.

    `dirty` is never pruned (it has modified files), so its claim must survive a run that removes two
    OTHER worktrees. Asserting only "the file still exists" would pass against a script that released
    nothing at all, so this carries `clean`'s release as the positive control in the same invocation.
    """
    live_record(fx, sleeper, fx.primary)
    survivor = write_claim(fx, "dirty-work", fx.sibling("dirty"), note="someone is mid-build")
    control = write_claim(fx, "clean-work", fx.sibling("clean"))

    res = run(fx, "-Apply", "-IdleHours", "0")

    assert by_leaf(res, "dirty")["Decision"] == "SKIP"
    assert survivor.exists(), "a live session's claim was handed to whoever asks for it next"
    assert json.loads(survivor.read_text(encoding="utf-8"))["key"] == "dirty-work"
    # Positive control: the run DID release claims, so the survival above is a decision, not a no-op.
    assert not control.exists()
    assert res["counts"]["claimsReleased"] == 1


def test_a_claim_naming_a_PREFIX_of_the_pruned_path_is_not_released(
    fx: Fixture, sleeper: int
) -> None:
    """Anti-substring control. `<primary>` is a strict prefix of `<primary>-clean`.

    A `StartsWith` or leaf-name match would release the PRIMARY checkout's claim while pruning a
    sibling -- and the primary is where the operator is sitting. Full normalised equality is the only
    match that cannot do this.
    """
    live_record(fx, sleeper, fx.primary)
    primary_claim = write_claim(fx, "primary-work", fx.primary, note="held by the primary checkout")
    control = write_claim(fx, "clean-work", fx.sibling("clean"))

    res = run(fx, "-Apply", "-IdleHours", "0")

    assert primary_claim.exists(), "pruning a sibling released the PRIMARY checkout's claim"
    assert not control.exists()
    assert res["counts"]["claimsReleased"] == 1


def test_a_dry_run_releases_no_claim(fx: Fixture, sleeper: int) -> None:
    """A preview that mutates the shared registry is not a preview.

    The anti-vacuity half matters as much as the assertion: `clean` must come back PRUNE, or this
    passes for free on a run that had no candidates.
    """
    live_record(fx, sleeper, fx.primary)
    claim = write_claim(fx, "clean-work", fx.sibling("clean"))

    res = run(fx, "-IdleHours", "0")  # no -Apply

    assert by_leaf(res, "clean")["Decision"] == "PRUNE", "nothing would have been removed anyway"
    assert claim.exists()
    assert res["counts"]["claimsReleased"] == 0
    assert fx.sibling("clean").exists()


def test_an_unreadable_claim_is_reported_not_silently_swept(fx: Fixture, sleeper: int) -> None:
    """A claim we cannot parse might name this worktree, so we can neither clear it nor ignore it.

    Reporting it is the whole point: a `continue` here would let the receipt describe a clean sweep it
    never made, leaving a permanently-blocked key that nothing mentions again. It must also move the
    exit code -- the condition is exactly the orphan this feature removes.

    It is counted ONCE PER RUN, not once per removal. This run removes two worktrees (`clean` and
    `gone`) and each consults the same claims directory; the first version of this attributed the
    corrupt file to every removal and reported 2 for one blocked key. An unreadable claim belongs to no
    worktree by definition -- not being able to read it is exactly not knowing whose it is.
    """
    live_record(fx, sleeper, fx.primary)
    bad = _claims_dir(fx) / "corrupt.json"
    bad.write_bytes(b"{not json at all")

    res = run(fx, "-Apply", "-IdleHours", "0")

    assert res["counts"]["removed"] == 2, "two removals must both have consulted the registry"
    assert by_leaf(res, "clean")["Outcome"] == "removed", "the run must still have acted"
    assert res["counts"]["claimsUnreadable"] == 1
    assert [u["file"] for u in res["claims"]["unreadable"]] == ["corrupt.json"]
    assert res["claims"]["scanned"] is True
    # Not attributed to a decision: we never learned whose it was.
    assert by_leaf(res, "clean")["ClaimsUnreleased"] == []
    assert by_leaf(res, "gone")["ClaimsUnreleased"] == []
    assert bad.exists(), "an unparseable claim must not be deleted on a guess"
    assert res["_exit"] != 0, "a key left permanently blocked is not a successful prune"


def test_an_unreadable_claim_reds_a_DRY_RUN_too(fx: Fixture, sleeper: int) -> None:
    """The receipt is the surface CI reads, and it exits before the human summary is printed.

    An exit-code decision made after the -Json branch would be reached only on the text path, so the
    receipt would carry exitCode 0 over a key nothing can claim. A dry run finds the same condition
    because the condition belongs to the registry, not to any removal.
    """
    live_record(fx, sleeper, fx.primary)
    (_claims_dir(fx) / "corrupt.json").write_bytes(b"{not json at all")

    res = run(fx, "-IdleHours", "0")  # no -Apply

    assert by_leaf(res, "clean")["Decision"] == "PRUNE", "anti-vacuity: the run had real candidates"
    assert res["counts"]["removed"] == 0
    assert res["counts"]["claimsUnreadable"] == 1
    assert res["_exit"] != 0, "the JSON receipt reported a clean run over an unclaimable key"


def test_the_human_summary_reports_released_claims(fx: Fixture, sleeper: int) -> None:
    """The text surface is separate from the receipt and can lie on its own."""
    live_record(fx, sleeper, fx.primary)
    write_claim(fx, "clean-work", fx.sibling("clean"))

    proc = run_text(fx, "-Apply", "-IdleHours", "0")

    assert "released claim 'clean-work'" in proc.stdout
    assert "claims: 1 released" in proc.stdout


def test_the_summary_stays_silent_when_no_claim_was_involved(fx: Fixture, sleeper: int) -> None:
    """A standing `claims: 0 released` on every run trains the eye to skip the line."""
    live_record(fx, sleeper, fx.primary)
    proc = run_text(fx, "-Apply", "-IdleHours", "0")
    assert "claims:" not in proc.stdout


def test_an_absent_registry_reports_NOT_SCANNED_rather_than_clean(
    fx: Fixture, sleeper: int
) -> None:
    """`unreadable: []` next to `released: 0` reads exactly like a registry checked and found tidy.

    A repo that has never used claim.ps1 has no claims directory at all, so the survey does not run.
    Without `scanned` there is no field distinguishing "read it, nothing wrong" from "never looked" --
    the silent-instrument shape this whole item is about, reintroduced in the receipt.
    """
    live_record(fx, sleeper, fx.primary)
    # Deliberately do NOT call _claims_dir(): it creates the directory as a side effect.
    res = run(fx, "-Apply", "-IdleHours", "0")

    assert res["counts"]["removed"] == 2, "anti-vacuity: the run really did prune"
    assert res["claims"]["scanned"] is False
    assert res["claims"]["unreadable"] == []
    assert res["counts"]["claimsReleased"] == 0
    assert res["_exit"] == 0, "an absent registry is not an error, just an unknown"


def test_an_empty_registry_reports_SCANNED(fx: Fixture, sleeper: int) -> None:
    """The other half of the pair -- without it, `scanned` could be hardcoded false and still pass."""
    live_record(fx, sleeper, fx.primary)
    _claims_dir(fx)  # exists, but holds nothing

    res = run(fx, "-Apply", "-IdleHours", "0")

    assert res["claims"]["scanned"] is True
    assert res["claims"]["unreadable"] == []


# --------------------------------------------------------------------------------------------------
# Signal 2 reads the reflog by CONTENT, not by mtime
#
# MEASURED 2026-08-18 on the real repository: a `git gc` rewrote every reflog in place and left 48 of
# 50 worktree `logs/HEAD` files carrying the IDENTICAL mtime, to the second, while their contents were
# days older. Signal 2 took the newest mtime, so one gc made the entire repository read "recently
# active" for the next 36 hours -- 11 of 14 candidates were vetoed on that basis alone and the tool
# removed nothing.
#
# The pair that matters is the first two tests below. Reading the entry instead of the mtime is only
# correct if it still SEES a real session, so the gc test is worthless without the one directly after
# it, which proves the signal was narrowed rather than deleted.
# --------------------------------------------------------------------------------------------------


def _reflog(worktree: Path) -> Path:
    return _gitdir(worktree) / "logs" / "HEAD"


def _set_mtime(path: Path, when: float) -> None:
    os.utime(path, (when, when))


def test_a_gc_touching_every_reflog_does_not_veto(fx: Fixture, sleeper: int) -> None:
    """The bug, reproduced: a write that appends NOTHING must not read as activity."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    assert by_leaf(run(fx), "clean")["Decision"] == "PRUNE", "control: released before the gc"

    # Exactly what `git gc` does to a reflog it expires: same bytes, new mtime.
    before = _reflog(fx.sibling("clean")).read_bytes()
    _set_mtime(_reflog(fx.sibling("clean")), time.time())
    assert _reflog(fx.sibling("clean")).read_bytes() == before, "the fixture must change no content"

    res = run(fx)
    assert by_leaf(res, "clean")["Decision"] == "PRUNE", by_leaf(res, "clean")["Reason"]
    assert by_leaf(res, "gone")["Decision"] == "PRUNE", "anti-vacuity: the pass still prunes"


def test_a_fresh_reflog_entry_vetoes_even_when_every_mtime_is_old(
    fx: Fixture, sleeper: int
) -> None:
    """The other direction, and the one that stops the fix from being a deletion of signal 2.

    A session that ran a real git command appended an entry stamped now. Here every mtime says the
    worktree is 100 hours idle and ONLY the reflog's content says otherwise -- so a script that had
    simply stopped reading `logs/HEAD` would prune a worktree somebody is working in, and pass the
    gc test above while doing it.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    assert by_leaf(run(fx), "clean")["Decision"] == "PRUNE", "control: released before the entry"

    log = _reflog(fx.sibling("clean"))
    _age_reflog(_gitdir(fx.sibling("clean")), time.time())  # the entry says: used just now
    _set_mtime(log, time.time() - 100 * 3600)  # ...while every timestamp still says old

    res = run(fx)
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert d["Reason"].startswith("recently active")
    assert by_leaf(res, "gone")["Decision"] == "PRUNE", "anti-vacuity: the pass still prunes"


def test_an_unparseable_reflog_falls_back_to_the_mtime_and_keeps_vetoing(
    fx: Fixture, sleeper: int
) -> None:
    """A shape this does not recognise is a reason to keep vetoing, never a reason to stop.

    A parse failure that returned "no signal" would make an unreadable reflog the QUIETEST possible
    state -- the one input that removes a worktree instead of protecting it.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    assert by_leaf(run(fx), "clean")["Decision"] == "PRUNE", "control: released before the damage"

    log = _reflog(fx.sibling("clean"))
    log.write_text("this line is not a reflog entry\n", encoding="utf-8")
    _set_mtime(log, time.time())

    res = run(fx)
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert d["Reason"].startswith("recently active")
    assert by_leaf(res, "gone")["Decision"] == "PRUNE", "anti-vacuity: the pass still prunes"


def test_an_empty_reflog_contributes_nothing_rather_than_its_mtime(
    fx: Fixture, sleeper: int
) -> None:
    """Every entry expired: the reflog holds no evidence either way, and the six mtimes still speak.

    Reading its mtime here would reinstate the bug on the OLDEST worktrees in the repository -- the
    ones whose entries a gc has already expired, which are exactly the ones most likely to be
    prunable.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)

    log = _reflog(fx.sibling("clean"))
    log.write_text("", encoding="utf-8")
    _set_mtime(log, time.time())

    res = run(fx)
    assert by_leaf(res, "clean")["Decision"] == "PRUNE", by_leaf(res, "clean")["Reason"]
    assert by_leaf(res, "gone")["Decision"] == "PRUNE", "anti-vacuity: the pass still prunes"


# --- REPORT-ONLY rows (BACKLOG #1294) -------------------------------------------------------------
# The population this script must never remove was previously invisible to every line of its report:
# not a candidate, not an `excluded` row, absent from the JSON. An operator had to assemble the list
# by hand. These cover the reporting path and, more importantly, that it stays a REPORTING path.


def test_a_nested_claude_worktree_is_reported_but_never_a_candidate(
    readonly_fx: Fixture, sleeper: int
) -> None:
    """`.claude/worktrees/nested` must appear in reportOnly and never in candidates.

    The two halves are separately load-bearing. Appearing in `reportOnly` is the whole feature --
    before it, the tree was indistinguishable from one the script had never seen. Staying out of
    `candidates` is the safety property the exclusion exists for, and a reporting feature that
    quietly widened the candidate set would be the exact regression this file's header warns about.
    """
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0002-0000")
    res = run(readonly_fx, "-IdleHours", "0")

    assert "nested" not in {c["Leaf"] for c in res["candidates"]}
    assert "nested" in {r["leaf"] for r in res["reportOnly"]}


def test_report_only_rows_are_never_removed_by_apply(readonly_fx: Fixture, sleeper: int) -> None:
    """-Apply must not act on a reported row. This is the property the whole section rests on."""
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0003-0000")
    res = run(readonly_fx, "-IdleHours", "0", "-Apply")

    reported = {r["path"] for r in res["reportOnly"]}
    assert reported, "nothing was reported, so this asserts nothing -- fixture regression"
    # Every reported path must still be a registered worktree afterwards.
    for path in reported:
        assert Path(path).exists(), f"-Apply removed a REPORT-ONLY worktree: {path}"


def test_a_detached_tree_held_by_no_other_ref_is_withheld_not_reported(
    fx: Fixture, sleeper: int
) -> None:
    """The one case that must never be suggested, and the reason the content test was rewritten.

    `git worktree remove` does NOT delete a branch, so a tree ON A BRANCH keeps its commits through
    the ref and is safe to suggest whatever its merge state. A DETACHED tree is rung 3 of the
    recoverability ladder: once the tree is gone its commits are reachable from nothing and survive
    only until something collects them. So a detached tip that no other ref contains is withheld --
    and it is precisely the tree that looks most finished, being clean and idle.
    """
    live_record(fx, sleeper, fx.primary)
    lone = fx.primary.parent / "detached-unique"
    _add_worktree(fx.primary, lone, "tmp-unique")
    _commit(lone, "only-here.txt", "exists nowhere else")
    tip = _head(lone)
    # Drop the only ref that holds it, leaving the worktree detached at an unreferenced commit.
    _git(lone, "checkout", "--detach", "HEAD")
    _git(fx.primary, "branch", "-D", "tmp-unique")
    _backdate(fx.primary, lone, 200.0)

    # -IdleHours 0, not 1. The fixture's other worktrees are created seconds ago, so at 1 they are all
    # withheld as recently-active and reportOnly comes back EMPTY -- which made every absence
    # assertion below vacuous. The positive control caught exactly that.
    res = run(fx, "-IdleHours", "0")

    # POSITIVE CONTROL FIRST, and it is not decoration. Every other assertion here is of the form
    # "this tree is ABSENT from reportOnly", which is trivially satisfied when reportOnly is empty --
    # so with the feature fully broken this test passed. Measured: neutering the collection reddened
    # the sibling tests and left this one green. Assert the list is populated before reading anything
    # from its absence.
    assert res["reportOnly"], (
        "reportOnly is empty, so the absence assertions below prove nothing -- "
        "either the fixture stopped producing report-only trees or the feature is broken"
    )

    assert tip not in {r.get("safety", "") for r in res["reportOnly"]}
    assert str(lone) not in {r["path"] for r in res["reportOnly"]}, (
        "a detached worktree whose commits exist in no other ref was suggested for removal"
    )
    assert res["counts"]["reportOnlyHeld"] >= 1


def test_a_worktree_holding_a_coordination_claim_is_never_reported(
    fx: Fixture, sleeper: int
) -> None:
    """The commands the report emits are plain `git worktree remove`, which does NOT release claims.

    This script's own -Apply path releases them (``Remove-ClaimsHeldBy``, BACKLOG #345). The reported
    commands do not, so a reported row whose tree holds a claim hands the operator a command that
    strands it -- and a stranded claim is worse than an orphaned worktree, because ``claim.ps1
    -Release`` is worktree-scoped and nobody can release it once the holder is gone. Measured
    2026-08-19: 19 of 28 live claims were already orphaned exactly that way.
    """
    live_record(fx, sleeper, fx.primary)
    nested = fx.primary / ".claude" / "worktrees" / "nested"

    before = run(fx, "-IdleHours", "0")
    assert "nested" in {r["leaf"] for r in before["reportOnly"]}, (
        "fixture regression: 'nested' must be reported BEFORE the claim, or this proves nothing"
    )

    # Derive the common dir, never type `.git/...`: in a worktree `.git` is a FILE, so the bare form
    # resolves against the wrong place and the claim would be written where nothing reads it -- which
    # looks exactly like the feature working.
    common = Path(
        _git(fx.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    )
    claims = common / "mefor-coord" / "claims"
    claims.mkdir(parents=True, exist_ok=True)
    (claims / "9999.json").write_text(
        json.dumps({"key": "9999", "worktree": str(nested).replace("\\", "/"), "note": "held"}),
        encoding="utf-8",
    )

    after = run(fx, "-IdleHours", "0")
    assert "nested" not in {r["leaf"] for r in after["reportOnly"]}, (
        "a worktree holding a coordination claim was suggested for removal"
    )
    assert after["counts"]["reportOnlyHeld"] > before["counts"]["reportOnlyHeld"]
