# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The opt-in nightly removal of finished ``.claude/worktrees`` trees (owner request, 2026-11-05).

``prune-merged.ps1`` lists the trees under ``.claude/worktrees`` that look finished and removes none of
them, by design. ``run-daily-prune.ps1 -RemoveFinishedClaudeWorktrees`` acts on a FRESH copy of that list
through ``finished-worktree-removal.ps1``, which re-checks every tree immediately before a plain
``git worktree remove``. These tests pin, at least:

* a dry run removes nothing and says what it would remove;
* a clean, idle, unlocked, unoccupied tree is removed, ignored files (a ``.venv``) and all, and its
  branch survives;
* a dirty, untracked-file, locked, recently-active, occupied, no-longer-registered, stranded-detached,
  protected or out-of-scope tree is REFUSED, with the reason, and left on disk;
* no removal command ever carries ``--force``;
* the runner takes its list from a fresh ``prune-merged.ps1 -Json`` run and logs every outcome.

Every test drives the real scripts against a synthetic repo under ``tmp_path``. The liveness fence reads
``$env:USERPROFILE\\.claude*\\sessions``, so each run points ``USERPROFILE`` at a fixture home holding one
DEAD record (an empty registry makes the fence unavailable, which refuses everything for the wrong
reason), and ``MEFOR_COORD_ROOT`` at a fixture coordination root, so no real claim is read.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests._dead_pid import never_live_pid
from tests.test_worktree_prune_merged import _backdate, _git

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "worktree" / "finished-worktree-removal.ps1"
RUNNER = ROOT / "scripts" / "worktree" / "run-daily-prune.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-daily-prune.ps1"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("pwsh") is None or os.name != "nt",
        reason="the liveness fence needs pwsh on Windows (Process.StartTime)",
    ),
    # Two prune-merged.ps1 runs plus the removal pass; the subprocess waits below are 300 s.
    pytest.mark.timeout(360),
]

# Trees the fixture builds under <primary>/.claude/worktrees.
FINISHED = ("clean", "venv")
UNSAFE = (
    "dirty",
    "untracked",
    "locked",
    "active",
    "touched",
    "occupied",
    "stranded",
    "flagged",
    "rewritten",
    "claimed",
    "cloned",
    "deepclone",
    "hiddenclone",
    "allocated",
    "dotenv",
)


class Fx:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "repo"
        self.home = root / "home"
        self.coord = root / "coord"
        self.sessions = self.home / ".claude" / "sessions"

    def tree(self, name: str) -> Path:
        return self.primary / ".claude" / "worktrees" / name

    def env(self, *, claudecode: bool = False) -> dict[str, str]:
        env = dict(os.environ)
        env["USERPROFILE"] = str(self.home)
        env["MEFOR_COORD_ROOT"] = str(self.coord)
        if claudecode:
            env["CLAUDECODE"] = "1"
        else:
            env.pop("CLAUDECODE", None)
        return env

    def registered(self) -> set[str]:
        out = _git(self.primary, "worktree", "list", "--porcelain")
        return {
            os.path.normcase(os.path.normpath(line[len("worktree ") :]))
            for line in out.splitlines()
            if line.startswith("worktree ")
        }

    def is_registered(self, p: Path) -> bool:
        return os.path.normcase(os.path.normpath(p)) in self.registered()


def _session(fx: Fx, pid: int, cwd: Path, sid: str) -> None:
    rec = {
        "pid": pid,
        "sessionId": sid,
        "cwd": str(cwd),
        "startedAt": int(time.time() * 1000),
        "version": "2.1.220",
        "kind": "interactive",
        "entrypoint": "claude-desktop",
    }
    (fx.sessions / f"{pid}.json").write_text(json.dumps(rec), encoding="utf-8")


def _age(primary: Path, tree: Path, hours: float) -> None:
    """Age the git metadata AND the working tree's top level, the two idle readings."""
    _backdate(primary, tree, hours)
    when = time.time() - hours * 3600
    for entry in (tree, *tree.iterdir()):
        os.utime(entry, (when, when))


@pytest.fixture
def fx(tmp_path: Path) -> Fx:
    f = Fx(tmp_path.resolve())
    origin = f.root / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True)
    f.primary.mkdir()
    _git(f.primary, "init", "-q", "-b", "main")
    _git(f.primary, "config", "user.email", "t@example.invalid")
    _git(f.primary, "config", "user.name", "t")
    _git(f.primary, "remote", "add", "origin", str(origin))
    (f.primary / ".gitignore").write_text(
        ".venv/\nnode_modules/\n__pycache__/\n.env\n*.db\n/.claude/\n", encoding="utf-8"
    )
    (f.primary / "seed.txt").write_text("seed", encoding="utf-8")
    # One ADR on origin/main, so an allocation check has a file to match, and to mismatch.
    (f.primary / "docs" / "adr").mkdir(parents=True)
    (f.primary / "docs" / "adr" / "0001-seed.md").write_text("# seed\n", encoding="utf-8")
    _git(f.primary, "add", "--", ".gitignore", "seed.txt", "docs/adr/0001-seed.md")
    _git(f.primary, "commit", "-qm", "seed")
    _git(f.primary, "push", "-q", "origin", "main")
    _git(f.primary, "fetch", "-q", "origin")

    for name in (*FINISHED, *UNSAFE):
        _git(f.primary, "worktree", "add", "-q", "-b", name, str(f.tree(name)))

    venv = f.tree("venv") / ".venv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = nowhere\n", encoding="utf-8")
    # Regenerable caches deeper down: the allowlist covers these at any depth, so they do not refuse.
    (f.tree("venv") / "pkg" / "__pycache__").mkdir(parents=True)
    (f.tree("venv") / "pkg" / "__pycache__" / "m.pyc").write_bytes(b"\0")
    (f.tree("venv") / "ide" / "node_modules" / "left-pad").mkdir(parents=True)
    (f.tree("venv") / "ide" / "node_modules" / "left-pad" / "index.js").write_text("//\n", "utf-8")
    # An ignored file that is not a cache: the removal would delete it, so it refuses.
    (f.tree("dotenv") / ".env").write_text("MEFOR_X=1\n", encoding="utf-8")
    (f.tree("dirty") / "seed.txt").write_text("modified", encoding="utf-8")
    (f.tree("untracked") / "deep" / "er").mkdir(parents=True)
    (f.tree("untracked") / "deep" / "er" / "never_committed.py").write_text("#\n", encoding="utf-8")
    _git(f.primary, "worktree", "lock", "--reason", "in use by a bench run", str(f.tree("locked")))

    # Detached, with a commit no ref holds: removing it would strand that commit.
    stranded = f.tree("stranded")
    _git(stranded, "checkout", "-q", "--detach")
    (stranded / "lone.txt").write_text("only here", encoding="utf-8")
    _git(stranded, "add", "--", "lone.txt")
    _git(stranded, "commit", "-qm", "lone")
    _git(f.primary, "branch", "-q", "-D", "stranded")

    # An edit git status cannot see: the file is flagged skip-worktree first.
    flagged = f.tree("flagged")
    _git(flagged, "update-index", "--skip-worktree", "seed.txt")
    (flagged / "seed.txt").write_text("edited under a flag", encoding="utf-8")

    # Back on its branch, with a commit made while detached that only the tree's own HEAD reflog holds.
    rewritten = f.tree("rewritten")
    _git(rewritten, "checkout", "-q", "--detach")
    (rewritten / "gone.txt").write_text("detached work", encoding="utf-8")
    _git(rewritten, "add", "--", "gone.txt")
    _git(rewritten, "commit", "-qm", "detached work")
    _git(rewritten, "checkout", "-q", "rewritten")

    # An amend on the branch: the old commit is held by the branch's own reflog, which survives the
    # removal, so it must NOT refuse. Built in a FINISHED tree so the positive control carries it.
    clean = f.tree("clean")
    (clean / "amended.txt").write_text("v1", encoding="utf-8")
    _git(clean, "add", "--", "amended.txt")
    _git(clean, "commit", "-qm", "v1")
    _git(clean, "commit", "-q", "--amend", "-m", "v1 amended")

    # A git clone inside an ignored .venv/src, where pip puts an editable install.
    clone = f.tree("cloned") / ".venv" / "src" / "pkg"
    clone.mkdir(parents=True)
    _git(clone, "init", "-q")
    # Deeper than the old one-level look reached: a clone two levels inside a nested node_modules.
    deep = f.tree("deepclone") / "ide" / "node_modules" / "pkg" / "vendor" / "lib"
    deep.mkdir(parents=True)
    _git(deep, "init", "-q")
    # A checkout under an ignored .claude/, where git status lists nothing at all.
    hidden = f.tree("hiddenclone") / ".claude" / "worktrees" / "inner"
    hidden.mkdir(parents=True)
    _git(hidden, "init", "-q")

    for name in (*FINISHED, *UNSAFE):
        if name == "touched":
            # Git metadata idle, but the working tree written just now.
            _backdate(f.primary, f.tree(name), 200)
        elif name != "active":
            _age(f.primary, f.tree(name), 200)

    f.sessions.mkdir(parents=True)
    (f.coord / "claims").mkdir(parents=True)
    claim = {"key": "row-1", "worktree": str(f.tree("claimed"))}
    (f.coord / "claims" / "row-1.json").write_text(json.dumps(claim), encoding="utf-8")
    # An ADR number allocated in the tree, whose file is not on origin/main.
    (f.coord / "alloc" / "adr").mkdir(parents=True)
    alloc = {"number": "9999", "kind": "adr", "title": "t", "worktree": str(f.tree("allocated"))}
    (f.coord / "alloc" / "adr" / "9999.json").write_text(json.dumps(alloc), encoding="utf-8")
    # One readable DEAD record outside the repo, so the fence is available and vetoes nothing.
    _session(f, never_live_pid(), f.root, "dead0000-0000")
    return f


@pytest.fixture
def sleeper() -> Iterator[int]:
    """A pid that is LIVE for the fence. Function-scoped so its start time matches ``startedAt``."""
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


def remove(
    fx: Fx,
    paths: list[Path],
    *,
    apply: bool,
    idle_hours: str = "72",
    protect: list[Path] | None = None,
    prelude: str = "",
    env_extra: dict[str, str | None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Call Invoke-FinishedWorktreeRemoval directly, keyed by tree name.

    Inputs travel as environment JSON, never spliced into the command text, so no path needs quoting.
    ``prelude`` runs after the helper is dot-sourced, so a test can stand a function in for git.
    ``env_extra`` sets a variable, or removes it where the value is None.
    """
    env = fx.env()
    for key, value in (env_extra or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    env["T_PRIMARY"] = str(fx.primary)
    env["T_PATHS"] = json.dumps([str(p) for p in paths])
    env["T_PROTECT"] = json.dumps([str(p) for p in protect or []])
    command = (
        f". '{HELPER}'; {prelude}; "
        "$r = Invoke-FinishedWorktreeRemoval -Primary $env:T_PRIMARY "
        "-Paths @($env:T_PATHS | ConvertFrom-Json) -Protect @($env:T_PROTECT | ConvertFrom-Json) "
        f"-IdleHours {idle_hours} -Apply:${'true' if apply else 'false'}; "
        "ConvertTo-Json -InputObject @($r) -Depth 4"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    rows: list[dict[str, Any]] = json.loads(proc.stdout)
    assert len(rows) == len(paths), f"one row per path expected: {rows}"
    return {Path(r["Path"]).name: r for r in rows}


def test_dry_run_removes_nothing_and_reports_what_it_would(fx: Fx) -> None:
    rows = remove(fx, [fx.tree(n) for n in FINISHED], apply=False)
    for name in FINISHED:
        assert rows[name]["Outcome"] == "WOULD-REMOVE", rows[name]
        assert fx.tree(name).is_dir()
        assert fx.is_registered(fx.tree(name))


def test_apply_removes_a_finished_tree_and_keeps_its_branch(fx: Fx) -> None:
    rows = remove(fx, [fx.tree(n) for n in FINISHED], apply=True)
    for name in FINISHED:
        assert rows[name]["Outcome"] == "REMOVED", rows[name]
        assert not fx.tree(name).exists()
        assert not fx.is_registered(fx.tree(name))
        # `git worktree remove` deletes no branch, so the commits stay reachable.
        _git(fx.primary, "rev-parse", "--verify", "-q", f"refs/heads/{name}")


def test_apply_refuses_every_unsafe_tree_and_leaves_it(fx: Fx, sleeper: int) -> None:
    _session(fx, sleeper, fx.tree("occupied"), "live0000-0000")
    gone = fx.tree("gone")
    _git(fx.primary, "worktree", "add", "-q", "-b", "gone", str(gone))
    _git(fx.primary, "worktree", "remove", str(gone))
    outside = fx.root / "repo-sibling"
    _git(fx.primary, "worktree", "add", "-q", "-b", "sibling", str(outside))
    _backdate(fx.primary, outside, 200)

    trees = [fx.tree(n) for n in UNSAFE] + [gone, outside, fx.tree("clean")]
    rows = remove(fx, trees, apply=True, protect=[fx.tree("clean")])

    expected = {
        "dirty": r"dirty: 1 uncommitted tracked change",
        "untracked": r"1 untracked file\(s\) present",
        "locked": r"locked: in use by a bench run",
        "active": r"recently active: git metadata",
        "touched": r"recently active: the working tree was written",
        "flagged": r"1 file\(s\) flagged skip-worktree",
        "rewritten": r"1 commit\(s\) held only by its HEAD reflog",
        "claimed": r"a coordination claim names it",
        "occupied": r"occupied: live0000 LIVE",
        "stranded": r"1 commit\(s\) held only by its HEAD reflog",
        "cloned": r"a nested git checkout at \.venv/src/pkg/\.git",
        "deepclone": r"a nested git checkout at ide/node_modules/pkg/vendor/lib/\.git",
        # The ignored-entry check runs first and lists .claude/ itself; the nested walk would also refuse.
        "hiddenclone": r"ignored entr\(ies\) that are not a regenerable cache.*!! \.claude/",
        "dotenv": r"1 ignored entr\(ies\) that are not a regenerable cache.*!! \.env",
        "allocated": r"owns allocation\(s\) not provably on origin/main \(adr #9999\)",
        "gone": r"no longer a registered worktree",
        "repo-sibling": r"outside \.claude/worktrees",
        "clean": r"executing from",
    }
    for name, pattern in expected.items():
        assert rows[name]["Outcome"] == "REFUSED", rows[name]
        assert re.search(pattern, rows[name]["Reason"]), rows[name]
    for p in trees:
        if p != gone:
            assert p.is_dir(), f"a refused tree was touched: {p}"
            assert fx.is_registered(p)


@pytest.mark.parametrize("idle", ["6", "0", "([double]::NaN)", "([double]::PositiveInfinity)"])
def test_a_window_under_the_floor_or_not_a_number_refuses_everything(fx: Fx, idle: str) -> None:
    """NaN compares false both ways, so a `-lt` guard alone would wave it through."""
    rows = remove(fx, [fx.tree("clean")], apply=True, idle_hours=idle)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "floor" in rows["clean"]["Reason"]
    assert fx.tree("clean").is_dir()


def test_no_removal_command_carries_force(fx: Fx) -> None:
    # The command is built before any re-check, so a floor refusal (no git reads) still carries it.
    rows = remove(fx, [fx.tree(n) for n in (*FINISHED, *UNSAFE)], apply=False, idle_hours="6")
    for r in rows.values():
        assert "worktree remove" in r["Command"]
        assert not re.search(r"\s(--force|-f)\b", r["Command"]), r
    # And in the source: no `worktree remove` invocation in any of the three scripts names a force flag.
    # Comments are stripped first, block and line, because the headers say "never --force" in prose.
    for script in (HELPER, RUNNER, INSTALLER):
        source = re.sub(r"<#.*?#>", "", script.read_text(encoding="utf-8"), flags=re.DOTALL)
        hits = 0
        for line in source.splitlines():
            code = line.split("#", 1)[0]
            if "worktree remove" in code:
                hits += 1
                assert not re.search(r"(--force|\s-f\b)", code), f"{script.name}: {line}"
        if script == HELPER:
            assert hits >= 1, (
                "the instrument found no removal call in the helper -- it is reading nothing"
            )


def run_runner(
    fx: Fx,
    log_dir: Path,
    *args: str,
    claudecode: bool = False,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(RUNNER),
            "-RepoRoot",
            str(fx.primary),
            "-LogDir",
            str(log_dir),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env={**fx.env(claudecode=claudecode), **(env_extra or {})},
        check=False,
    )


def run_logged(fx: Fx, log_dir: Path, *args: str, claudecode: bool = False) -> tuple[int, str]:
    proc = run_runner(fx, log_dir, *args, claudecode=claudecode)
    logs = sorted(log_dir.glob("prune-*.log"))
    assert logs, f"no log written (exit {proc.returncode}): {proc.stderr}"
    return proc.returncode, logs[-1].read_text(encoding="utf-8")


def _outcome(log: str, outcome: str, tree: Path) -> bool:
    norm = str(tree).replace("\\", "/").lower()
    return any(
        line.strip().startswith(outcome) and norm in line.replace("\\", "/").lower()
        for line in log.splitlines()
    )


def test_runner_without_the_switch_does_not_touch_claude_worktrees(fx: Fx, tmp_path: Path) -> None:
    _, log = run_logged(fx, tmp_path / "logs-off", "-Apply")
    assert "finished .claude/worktrees" not in log
    for name in FINISHED:
        assert fx.tree(name).is_dir()


def test_runner_dry_run_lists_from_a_fresh_prune_merged_run_and_removes_nothing(
    fx: Fx, tmp_path: Path, sleeper: int
) -> None:
    _session(fx, sleeper, fx.tree("occupied"), "live0000-0000")
    # Under CLAUDECODE on purpose: the dry run must stay usable in-session; only -Apply is refused.
    code, log = run_logged(
        fx, tmp_path / "logs-dry", "-RemoveFinishedClaudeWorktrees", claudecode=True
    )
    assert "--- finished .claude/worktrees: mode=DRYRUN ---" in log
    for name in FINISHED:
        assert _outcome(log, "WOULD-REMOVE", fx.tree(name)), log
        assert fx.tree(name).is_dir()
    # prune-merged.ps1's list does not read the lock; the re-check does.
    assert _outcome(log, "REFUSED", fx.tree("locked")), log
    assert re.search(r"mode=DRYRUN listed=\d+ removed=0 wouldRemove=2 ", log), log
    assert re.search(r"GB free on ", log), log
    assert code in (0, 2), log


def test_runner_apply_removes_the_finished_trees_and_logs_each(
    fx: Fx, tmp_path: Path, sleeper: int
) -> None:
    _session(fx, sleeper, fx.tree("occupied"), "live0000-0000")
    _, log = run_logged(fx, tmp_path / "logs-apply", "-Apply", "-RemoveFinishedClaudeWorktrees")
    for name in FINISHED:
        assert _outcome(log, "REMOVED", fx.tree(name)), log
        assert not fx.tree(name).exists()
    for name in UNSAFE:
        assert fx.tree(name).is_dir(), f"{name} was removed: {log}"
    assert re.search(r"mode=APPLY listed=\d+ removed=2 wouldRemove=0 ", log), log


def test_runner_refuses_apply_with_the_step_inside_claude_code(fx: Fx, tmp_path: Path) -> None:
    """The other arm of the dry-run test above: same switch, -Apply added, CLAUDECODE set."""
    proc = run_runner(
        fx, tmp_path / "logs-cc", "-Apply", "-RemoveFinishedClaudeWorktrees", claudecode=True
    )
    assert proc.returncode != 0
    assert "Refusing -Apply -RemoveFinishedClaudeWorktrees inside Claude Code" in (
        proc.stderr + proc.stdout
    )
    for name in FINISHED:
        assert fx.tree(name).is_dir()


def test_an_unreadable_claim_refuses_every_tree(fx: Fx) -> None:
    """Cannot-tell is not absent: a claim file of the wrong shape might name any tree."""
    (fx.coord / "claims" / "bad.json").write_text("[1, 2]", encoding="utf-8")
    rows = remove(fx, [fx.tree("clean")], apply=True)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "claim file or directory could not be read" in rows["clean"]["Reason"]
    assert fx.tree("clean").is_dir()


def _helper_apply(fx: Fx, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """The helper called directly with -Apply on the clean tree, for a refusal that throws."""
    env = {**env, "T_PRIMARY": str(fx.primary), "T_PATH": str(fx.tree("clean"))}
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{HELPER}'; Invoke-FinishedWorktreeRemoval -Primary $env:T_PRIMARY "
            "-Paths @($env:T_PATH) -IdleHours 72 -Apply",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        check=False,
    )


def test_the_helper_refuses_apply_inside_claude_code(fx: Fx) -> None:
    """Dot-sourcing the helper must not be a way around the runner's refusal."""
    proc = _helper_apply(fx, fx.env(claudecode=True))
    assert proc.returncode != 0
    assert "Refusing Invoke-FinishedWorktreeRemoval -Apply inside Claude Code" in (
        proc.stderr + proc.stdout
    )
    assert fx.tree("clean").is_dir()


@pytest.mark.parametrize(
    "marker",
    [
        "rebase-merge",
        "rebase-apply",
        "CHERRY_PICK_HEAD",
        "MERGE_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "BISECT_START",
        "sequencer",
    ],
)
def test_an_operation_in_progress_refuses(fx: Fx, marker: str) -> None:
    """Its state lives in the tree's own git dir, which the removal deletes."""
    gitdir = Path(_git(fx.tree("clean"), "rev-parse", "--absolute-git-dir").strip())
    if marker.startswith("rebase-") or marker == "sequencer":
        (gitdir / marker).mkdir()
    else:
        (gitdir / marker).write_text("0" * 40 + "\n", encoding="utf-8")
    rows = remove(fx, [fx.tree("clean")], apply=True)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert f"operation is in progress in its git dir ({marker})" in rows["clean"]["Reason"]
    assert fx.tree("clean").is_dir()


def _allocate(fx: Fx, number: str, tree: Path) -> None:
    rec = {"number": number, "kind": "adr", "title": "t", "worktree": str(tree)}
    (fx.coord / "alloc" / "adr" / f"x{len(number)}.json").write_text(json.dumps(rec), "utf-8")


def test_an_allocation_number_is_never_read_as_a_pattern(fx: Fx) -> None:
    """Red before the fix: ".*" padded to "00.*" matched docs/adr/0001-seed.md, so it read as landed."""
    _allocate(fx, ".*", fx.tree("clean"))
    rows = remove(fx, [fx.tree("clean")], apply=True)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "(adr #.*)" in rows["clean"]["Reason"]
    assert fx.tree("clean").is_dir()


def test_an_allocation_whose_adr_is_on_origin_main_does_not_refuse(fx: Fx) -> None:
    """The positive control for the test above: the same check, on a number that has landed."""
    _allocate(fx, "1", fx.tree("clean"))
    rows = remove(fx, [fx.tree("clean")], apply=False)
    assert rows["clean"]["Outcome"] == "WOULD-REMOVE", rows["clean"]


@pytest.mark.parametrize("registry", ["claims", "alloc"])
def test_a_registry_that_cannot_be_listed_refuses(fx: Fx, registry: str) -> None:
    """Red before the fix: Test-Path saw the entry and Get-ChildItem listed a FILE standing where the
    directory should be as no records, so claims or allocations read as none."""
    shutil.rmtree(fx.coord / registry)
    (fx.coord / registry).write_text("not a directory", encoding="utf-8")
    rows = remove(fx, [fx.tree("clean")], apply=True)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "could not be read" in rows["clean"]["Reason"], rows["clean"]
    assert fx.tree("clean").is_dir()


#: A function named git takes precedence over git.exe, so it intercepts only the removal call, which
#: the helper runs as `git -C <primary> worktree remove <path>`, and passes every other call through.
_GIT_SHIM = (
    "function global:git {{ "
    "if ($args.Count -ge 5 -and $args[2] -eq 'worktree' -and $args[3] -eq 'remove') {{ {body} }} "
    "else {{ & git.exe @args }} }}"
)


def test_git_declining_a_tree_every_check_passed_is_declined_not_refused(fx: Fx) -> None:
    """A race: the tree is locked between the last re-check and the removal, and git refuses."""
    shim = _GIT_SHIM.format(
        body="& git.exe -C $args[1] worktree lock --reason race $args[4]; & git.exe @args"
    )
    rows = remove(fx, [fx.tree("clean")], apply=True, prelude=shim)
    assert rows["clean"]["Outcome"] == "DECLINED", rows["clean"]
    assert "git declined" in rows["clean"]["Reason"]
    assert fx.tree("clean").is_dir()
    assert fx.is_registered(fx.tree("clean"))


#: The real removal, then the directory put back: deregistered, still on disk.
_ORPHAN_SHIM = _GIT_SHIM.format(
    body="& git.exe @args; $c = $LASTEXITCODE; "
    "$null = New-Item -ItemType Directory -Path $args[4]; $global:LASTEXITCODE = $c"
)


def test_a_tree_left_on_disk_after_deregistering_is_orphaned_and_ledgered(fx: Fx) -> None:
    rows = remove(fx, [fx.tree("clean")], apply=True, prelude=_ORPHAN_SHIM)
    assert rows["clean"]["Outcome"] == "ORPHANED", rows["clean"]
    assert not fx.is_registered(fx.tree("clean"))
    common = Path(
        _git(fx.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    )
    ledger = json.loads((common / "prune-merged-orphans.json").read_text(encoding="utf-8"))
    assert any(Path(e["path"]).name == "clean" for e in ledger), ledger


def test_an_error_after_the_orphaned_verdict_keeps_it(fx: Fx) -> None:
    """Red before the fix: the throw relabelled the row REFUSED, and the runner's exit 3 was lost."""
    prelude = _ORPHAN_SHIM + "; function Add-OrphanLedgerEntry { throw 'ledger boom' }"
    rows = remove(fx, [fx.tree("clean")], apply=True, prelude=prelude)
    assert rows["clean"]["Outcome"] == "ORPHANED", rows["clean"]
    assert "ledger boom" in rows["clean"]["Reason"]


def _junction(link: Path, target: Path) -> None:
    subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "New-Item -ItemType Junction -Path $env:T_LINK -Target $env:T_TARGET | Out-Null",
        ],
        check=True,
        capture_output=True,
        timeout=60,
        env={**os.environ, "T_LINK": str(link), "T_TARGET": str(target)},
    )


def test_a_link_inside_a_tolerated_cache_refuses(fx: Fx) -> None:
    """git does not delete through a link, so the removal would end ORPHANED (npm link makes these)."""
    elsewhere = fx.root / "elsewhere"
    elsewhere.mkdir()
    modules = fx.tree("clean") / "ide" / "node_modules"
    modules.mkdir(parents=True)
    _junction(modules / "linked", elsewhere)
    _age(fx.primary, fx.tree("clean"), 200)
    rows = remove(fx, [fx.tree("clean")], apply=True)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "a link at ide/node_modules/linked" in rows["clean"]["Reason"]
    assert fx.tree("clean").is_dir()


@pytest.mark.parametrize("name", [".env", "store.db", "store.db-wal", ".env.local", "x.sqlite3"])
def test_a_data_file_inside_a_tolerated_cache_refuses(fx: Fx, name: str) -> None:
    """git lists the cache folder as one ignored line and never reads into it."""
    modules = fx.tree("clean") / "ide" / "node_modules"
    modules.mkdir(parents=True)
    (modules / name).write_text("x\n", encoding="utf-8")
    _age(fx.primary, fx.tree("clean"), 200)
    rows = remove(fx, [fx.tree("clean")], apply=True)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert (
        f"a data file inside a cache directory at ide/node_modules/{name}"
        in rows["clean"]["Reason"]
    )
    assert fx.tree("clean").is_dir()


def test_a_registry_whose_holding_folder_is_gone_reads_as_unreadable(fx: Fx) -> None:
    """Red before the fix: an unreachable share raises the same ItemNotFoundException as a missing
    folder, so a root that dropped after the run's one probe read as "no claims, no allocations"."""
    env = fx.env()
    env["T_GONE"] = str(fx.root / "gone-root")
    env["T_HERE"] = str(fx.coord)
    command = (
        f". '{HELPER}'; "
        "$a = (Get-ClaimedWorktreeIndex @(Join-Path $env:T_GONE 'claims') -RequireParent).Unreadable; "
        "$b = (Get-ClaimedWorktreeIndex @(Join-Path $env:T_HERE 'no-claims-yet') -RequireParent).Unreadable; "
        "$c = Get-AllocationRefusal -Primary . -Norms @('x') -AllocDir (Join-Path $env:T_GONE 'alloc'); "
        "ConvertTo-Json -InputObject @{ gone = $a; here = $b; alloc = $c }"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["gone"] is True, out
    # The control: a registry not made yet, under a folder that is there, holds no claim.
    assert out["here"] is False, out
    assert "allocation registry could not be read" in out["alloc"], out


# --- The five fail-open findings left on PR 2802. Each test below was red on that PR's code. ---

#: Writes into the tree from inside the fence, the LAST gate of the first pass, which is the window
#: the re-check just before the removal exists for. ``{write}`` runs once, in the tree ``T_TREE``.
_LATE_WRITE = (
    "$global:fence = ${{function:Get-WorktreeOccupancy}}; "
    "function global:Get-WorktreeOccupancy {{ param($Repo) "
    "if (-not $global:wrote) {{ $global:wrote = $true; {write} }}; & $global:fence -Repo $Repo }}"
)

#: Puts every top-level mtime of the tree back 30 days, so the idle reading does not refuse first and
#: the gate under test is the one that has to see the write.
_BACKDATE = (
    "; $old = (Get-Date).AddDays(-30); "
    "foreach ($p in @($env:T_TREE) + @(Get-ChildItem -LiteralPath $env:T_TREE -Force | "
    "ForEach-Object FullName)) { (Get-Item -LiteralPath $p -Force).LastWriteTime = $old }"
)

_WRITE_ENV = "Set-Content -LiteralPath (Join-Path $env:T_TREE '.env') -Value 'MEFOR_X=1'"
_WRITE_CLONE = "$null = & git.exe init -q (Join-Path $env:T_TREE 'ide/node_modules/pkg')"
#: A commit no shared ref holds, kept by a per-worktree ref: it moves none of the idle readings.
_WRITE_REF = (
    "$c = & git.exe -C $env:T_TREE commit-tree 'HEAD^{tree}' -p HEAD -m keep; "
    "& git.exe -C $env:T_TREE update-ref refs/worktree/keep $c"
)
#: A claim taken in the window, which nothing inside the tree records.
_WRITE_CLAIM = (
    "@{ key = 'late'; worktree = $env:T_TREE } | ConvertTo-Json | "
    "Set-Content -LiteralPath $env:T_CLAIM"
)


@pytest.mark.parametrize(
    ("write", "made", "pattern"),
    [
        (_WRITE_ENV + _BACKDATE, ".env", r"ignored entr\(ies\).*!! \.env"),
        (_WRITE_CLONE + _BACKDATE, "ide/node_modules/pkg/.git", r"nested git checkout at ide/"),
        (_WRITE_ENV, ".env", r"recently active: the working tree was written"),
        (_WRITE_REF, "seed.txt", r"1 commit\(s\) held only by its HEAD reflog or its own refs"),
        (_WRITE_CLAIM, "seed.txt", r"a coordination claim names it"),
    ],
    ids=["ignored-file", "nested-clone", "recent-write", "worktree-ref", "late-claim"],
)
def test_a_write_after_the_first_pass_refuses_at_the_last_recheck(
    fx: Fx, write: str, made: str, pattern: str
) -> None:
    """Red on PR 2802: the content gates ran once, before the claim, allocation and fence reads, so a
    write in that window went with the tree (a plain worktree remove deletes an ignored .env)."""
    tree = fx.tree("clean")
    rows = remove(
        fx,
        [tree],
        apply=True,
        prelude=_LATE_WRITE.format(write=write),
        env_extra={"T_TREE": str(tree), "T_CLAIM": str(fx.coord / "claims" / "late.json")},
    )
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "just before the removal" in rows["clean"]["Reason"], rows["clean"]
    assert re.search(pattern, rows["clean"]["Reason"]), rows["clean"]
    assert (tree / made).exists()
    assert fx.is_registered(tree)


_REDIRECT_NAMES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")


def _redirect_value(fx: Fx, var: str) -> str:
    other = fx.root / "other"
    if not other.exists():
        other.mkdir()
        _git(other, "init", "-q")
    return {
        "GIT_DIR": str(other / ".git"),
        "GIT_WORK_TREE": str(other),
        "GIT_COMMON_DIR": str(other / ".git"),
        "GIT_INDEX_FILE": str(fx.root / "stray.index"),
    }[var]


@pytest.mark.parametrize("var", _REDIRECT_NAMES)
def test_a_git_redirect_in_the_environment_refuses_the_whole_run(fx: Fx, var: str) -> None:
    """Red on PR 2802: each makes `git -C <tree>` answer for another checkout, and nothing refused."""
    proc = _helper_apply(fx, {**fx.env(), var: _redirect_value(fx, var)})
    assert proc.returncode != 0, proc.stdout
    assert f"{var} is set" in proc.stderr + proc.stdout
    assert fx.tree("clean").is_dir()
    assert fx.is_registered(fx.tree("clean"))


def test_the_runner_refuses_a_git_redirect_before_it_prunes(fx: Fx, tmp_path: Path) -> None:
    log_dir = tmp_path / "logs-redirect"
    proc = run_runner(
        fx,
        log_dir,
        "-RemoveFinishedClaudeWorktrees",
        env_extra={"GIT_DIR": _redirect_value(fx, "GIT_DIR")},
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "GIT_DIR is set" in proc.stderr + proc.stdout
    # Up front, and into the log: a scheduled run leaves the reason, and no prune or step ran.
    (log,) = log_dir.glob("prune-*.log")
    text = log.read_text(encoding="utf-8")
    assert "REFUSED before the prune; nothing was attempted" in text, text
    assert "GIT_DIR is set" in text
    assert "=== exit 2 " in text
    assert "finished .claude/worktrees" not in text


def test_the_runner_refuses_a_git_redirect_before_resolving_the_primary(
    fx: Fx, tmp_path: Path
) -> None:
    """The scheduled task passes no -RepoRoot, so the runner resolves the primary itself, through git.
    Under a GIT_DIR naming no repository that read used to throw before the log existed."""
    log_dir = tmp_path / "logs-noroot"
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(RUNNER),
            "-LogDir",
            str(log_dir),
            "-RemoveFinishedClaudeWorktrees",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env={**fx.env(), "GIT_DIR": str(fx.root / "not-a-repo")},
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    (log,) = log_dir.glob("prune-*.log")
    text = log.read_text(encoding="utf-8")
    assert "REFUSED before the prune; nothing was attempted" in text, text
    assert "GIT_DIR is set" in text


def test_the_redirect_list_mirrors_remove_ps1() -> None:
    """The nightly removal refuses exactly the base names remove.ps1 refuses on -Path and -List."""
    names = re.compile(r"'([A-Z_]+)'")
    remove_src = (ROOT / "scripts" / "worktree" / "remove.ps1").read_text(encoding="utf-8")
    gates_src = (ROOT / "scripts" / "worktree" / "worktree-gates.ps1").read_text(encoding="utf-8")
    theirs = re.search(r"\$redirectNames = @\(([^)]*)\)", remove_src)
    ours = re.search(r"\$GIT_REDIRECT_NAMES = @\(([^)]*)\)", gates_src)
    assert theirs and ours, "the instrument found no list to compare"
    assert names.findall(theirs.group(1)) == list(_REDIRECT_NAMES)
    assert names.findall(ours.group(1)) == list(_REDIRECT_NAMES)


#: The real removal, then a flag the read stubs below wait on, so every gate before it reads truly.
_AFTER_REMOVAL = _GIT_SHIM.format(
    body="& git.exe @args; $c = $LASTEXITCODE; PUTBACK$global:T_REMOVED = $true; "
    "$global:LASTEXITCODE = $c"
)
#: Test-Path answers False for the tree, as it does for a path it may not read.
_TEST_PATH_FALSE = (
    "function global:Test-Path { if ($global:T_REMOVED -and $args -contains $env:T_HIDE) "
    "{ return $false }; Microsoft.PowerShell.Management\\Test-Path @args }"
)
#: Get-Item cannot read the tree: access denied, which is neither present nor absent.
_GET_ITEM_DENIED = (
    "function global:Get-Item { if ($global:T_REMOVED -and $args -contains $env:T_HIDE) "
    "{ throw [System.UnauthorizedAccessException]::new('stub: access to the path is denied') }; "
    "Microsoft.PowerShell.Management\\Get-Item @args }"
)


@pytest.mark.parametrize(
    ("putback", "stub"),
    [
        ("$null = New-Item -ItemType Directory -Path $args[4]; ", _TEST_PATH_FALSE),
        ("", _GET_ITEM_DENIED),
    ],
    ids=["test-path-false", "unreadable"],
)
def test_an_end_state_that_cannot_be_confirmed_absent_is_never_removed(
    fx: Fx, putback: str, stub: str
) -> None:
    """Red on PR 2802: the end state was read with Test-Path, so a leftover it could not read was
    REMOVED. Only a confirmed absence, under a folder that is there, reads as gone."""
    tree = fx.tree("clean")
    prelude = _AFTER_REMOVAL.replace("PUTBACK", putback) + "; " + stub
    rows = remove(fx, [tree], apply=True, prelude=prelude, env_extra={"T_HIDE": str(tree)})
    assert rows["clean"]["Outcome"] == "ORPHANED", rows["clean"]
    # The readers' "Nothing was removed." is false once git has run, so it must not reach the row.
    assert "Nothing was removed" not in rows["clean"]["Reason"], rows["clean"]
    assert not fx.is_registered(tree)


def _coord_not_plain(fx: Fx, case: str) -> dict[str, str | None]:
    if case == "local-root-is-a-file":
        common = Path(
            _git(fx.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
        )
        (common / "mefor-coord").write_text("not a directory", encoding="utf-8")
        return {"MEFOR_COORD_ROOT": None}
    if case == "shared-root-is-a-junction":
        # The registries under it are plain; only the folder holding them is a link.
        link = fx.root / "coord-link"
        _junction(link, fx.coord)
        return {"MEFOR_COORD_ROOT": str(link)}
    sub = {"alloc-kind-is-a-junction": "alloc/adr"}.get(case, case.split("-", 1)[0])
    shutil.rmtree(fx.coord / sub)
    empty = fx.root / f"empty-{sub.replace('/', '-')}"
    empty.mkdir()
    _junction(fx.coord / sub, empty)
    return {}


@pytest.mark.parametrize(
    "case",
    [
        "local-root-is-a-file",
        "shared-root-is-a-junction",
        "claims-is-a-junction",
        "alloc-is-a-junction",
        "alloc-kind-is-a-junction",
    ],
)
def test_a_coordination_folder_that_is_not_a_plain_directory_refuses(fx: Fx, case: str) -> None:
    """Red on PR 2802: a file standing where mefor-coord should be read as a present parent, so its
    claims and allocations read as none; a junction was listed through, wherever it pointed."""
    env_extra = _coord_not_plain(fx, case)
    rows = remove(fx, [fx.tree("clean")], apply=False, env_extra=env_extra)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "could not be read" in rows["clean"]["Reason"], rows["clean"]


def test_a_tree_root_that_is_a_junction_refuses_before_any_other_gate(fx: Fx) -> None:
    """Red on PR 2802: the root was never checked, so every gate and the removal read through it."""
    tree = fx.tree("clean")
    real = fx.root / "clean-real"
    tree.rename(real)
    _junction(tree, real)
    # The junction's own mtime is new and the link itself cannot be aged from here, so the working-tree
    # reading is held idle; without that, PR 2802's code refused it as recently active instead.
    prelude = "function Get-WorkingTreeActivity { (Get-Date).AddDays(-30) }"
    rows = remove(fx, [tree], apply=False, prelude=prelude)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "its root is a junction or link" in rows["clean"]["Reason"], rows["clean"]
    assert (real / "seed.txt").is_file()


def test_a_junction_above_the_tree_inside_its_claude_segment_refuses(fx: Fx) -> None:
    """The tree root is plain, but .claude/worktrees is a link, so the tree lives elsewhere and the
    path-shape gate would accept it."""
    worktrees = fx.primary / ".claude" / "worktrees"
    real = fx.root / "worktrees-real"
    worktrees.rename(real)
    _junction(worktrees, real)
    rows = remove(fx, [fx.tree("clean")], apply=False)
    assert rows["clean"]["Outcome"] == "REFUSED", rows["clean"]
    assert "a folder above it" in rows["clean"]["Reason"], rows["clean"]
    assert (real / "clean" / "seed.txt").is_file()
