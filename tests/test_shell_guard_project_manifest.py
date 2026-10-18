# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The worktree gate and a repo's own shell guards, run by ONE dispatcher process.

Given ``-ProjectGuards``, ``shell-guard-dispatch.ps1`` runs the guards named on its command line --
for an account-level handler, the installed worktree gate -- and then the guards
``$env:CLAUDE_PROJECT_DIR`` lists in ``scripts/hooks/shell-guards.txt``. The dispatcher's header says
why and how the list is read.

Three things must hold, and each has its section below:

* the decision is the one the gate and the guards reach standalone, first deny winning, with the gate
  first -- the gate's decisions are unchanged by running in-process;
* the manifest is untrusted, so a line that could run anything outside the repo's ``scripts/hooks/``
  is refused, visibly, and the other guards still run;
* a guard's exit code is the one its own process would have exited with, which the gate's git calls
  made a live question: they leave ``$LASTEXITCODE`` non-zero when the gate falls off its end.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from tests.test_claude_settings_contract import _ROOT
from tests.test_worktree_gate import assert_denied

DISPATCHER = _ROOT / "scripts" / "hooks" / "shell-guard-dispatch.ps1"
GATE = _ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
MANIFEST = _ROOT / "scripts" / "hooks" / "shell-guards.txt"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

_DENY = (
    "[Console]::Out.Write((@{hookSpecificOutput=@{hookEventName='PreToolUse';"
    "permissionDecision='deny';permissionDecisionReason='%s'}} | ConvertTo-Json -Compress))"
)


def _payload(command: str, cwd: Path | str, tool: str = "Bash") -> str:
    return json.dumps(
        {
            "session_id": "s-1",
            "cwd": str(cwd),
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {"command": command},
        }
    )


def _env(home: Path | None, project: Path | None) -> dict[str, str]:
    """The child's environment. ``home`` holds the gate's allowlist, which the gate reads from its
    parameter default -- the dispatcher runs it with no arguments, exactly as installed."""
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
    if home is not None:
        env["USERPROFILE"] = str(home)
        env["HOME"] = str(home)
    if project is not None:
        env["CLAUDE_PROJECT_DIR"] = str(project)
    return env


def _proc(argv: list[str], raw: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, input=raw, capture_output=True, text=True, timeout=120, env=env, encoding="utf-8"
    )


def _dispatch(
    raw: str, *, home: Path | None, project: Path | None, named: list[Path] | None = None
) -> subprocess.CompletedProcess[str]:
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(DISPATCHER), "-ProjectGuards"]
    return _proc(argv + [str(p) for p in named or []], raw, _env(home, project))


def _standalone(guard: Path, raw: str, home: Path) -> str:
    proc = _proc(["pwsh", "-NoProfile", "-File", str(guard)], raw, _env(home, None))
    assert proc.returncode == 0, f"{guard.name} exited {proc.returncode}: {proc.stderr}"
    return proc.stdout


def _decision(stdout: str) -> dict[str, Any] | None:
    """The parsed decision. Parsed, never compared as text: the gate builds its JSON from a plain
    hashtable, and its key order differs from one pwsh process to the next (measured 2026-10-17:
    four runs of one payload, three orders), so byte equality would compare hash seeds."""
    return json.loads(stdout) if stdout.strip() else None


@pytest.fixture
def gate_home(tmp_path: Path) -> tuple[Path, Path]:
    """A home whose allowlist governs a fixture primary, and that primary."""
    primary = tmp_path / "Primary"
    primary.mkdir()
    hooks = tmp_path / "home" / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "worktree-gate.repos.txt").write_text(f"{primary}\n", encoding="utf-8")
    return tmp_path / "home", primary


def _manifest_guards() -> list[Path]:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    return [_ROOT / e for e in entries]


# ================================================================== the wiring


def test_the_manifest_lists_the_three_guards_with_the_bounded_one_first() -> None:
    names = [g.name for g in _manifest_guards()]
    assert sorted(names) == sorted(
        ["block-api-burn.ps1", "block-unbounded-fs-scan.ps1", "block-blanket-git-stage.ps1"]
    ), names
    # It refuses an over-long payload unread, so a huge one never reaches the parsers after it.
    assert names[0] == "block-blanket-git-stage.ps1", names
    for guard in _manifest_guards():
        assert guard.is_file(), guard
    # The gate is named by the installed handler; listing the repo's copy too would run it twice.
    assert "worktree_gate.ps1" not in names and DISPATCHER.name not in names


# ================================================================== equivalence


def _corpus(primary: Path) -> list[str]:
    elsewhere = primary.parent / "Elsewhere"
    return [
        _payload("git status --short", elsewhere),
        _payload("git reset --hard", primary),  # the gate's deny
        _payload("git add -A", elsewhere),
        _payload("gh run watch 123", elsewhere, tool="PowerShell"),
        _payload("find /proc -name x", elsewhere),
        _payload("git reset --hard && git add -A", primary),  # gate and a guard: the gate wins
        _payload('echo "git add -A; gh run watch 1"', elsewhere),
        "not json at all",
    ]


def test_the_dispatcher_decides_what_the_gate_then_the_guards_decide_standalone(
    gate_home: tuple[Path, Path],
) -> None:
    home, primary = gate_home
    order = [GATE, *_manifest_guards()]
    corpus = _corpus(primary)
    with ThreadPoolExecutor(max_workers=6) as pool:
        alone = {(raw, g): pool.submit(_standalone, g, raw, home) for raw in corpus for g in order}
        both = {
            raw: pool.submit(_dispatch, raw, home=home, project=_ROOT, named=[GATE])
            for raw in corpus
        }
        mismatches = []
        for raw in corpus:
            expected = next(
                (d for g in order if (d := _decision(alone[(raw, g)].result())) is not None), None
            )
            proc = both[raw].result()
            assert proc.returncode == 0 and not proc.stderr.strip(), (raw, proc.stderr)
            if _decision(proc.stdout) != expected:
                mismatches.append((raw[:100], expected, proc.stdout[:200]))
    assert not mismatches, mismatches


def test_the_corpus_reaches_a_deny_from_the_gate_and_every_guard(
    gate_home: tuple[Path, Path],
) -> None:
    """The control for the test above: a corpus nothing denies would make it vacuous."""
    home, primary = gate_home
    corpus = _corpus(primary)
    for guard, raw in zip([GATE, *_manifest_guards()], corpus[1:5], strict=True):
        assert_denied(_decision(_standalone(guard, raw, home)))
    # And the double deny really is one the gate decides, so the order is under test.
    gate_reason = assert_denied(_decision(_standalone(GATE, corpus[5], home)))
    both = assert_denied(
        _decision(_dispatch(corpus[5], home=home, project=_ROOT, named=[GATE]).stdout)
    )
    assert both == gate_reason


def test_a_repo_with_no_manifest_gets_the_gate_alone(
    gate_home: tuple[Path, Path], tmp_path: Path
) -> None:
    home, primary = gate_home
    bare = tmp_path / "BareRepo"
    bare.mkdir()
    allow = _dispatch(_payload("git add -A", bare), home=home, project=bare, named=[GATE])
    assert (allow.returncode, allow.stdout, allow.stderr.strip()) == (0, "", "")
    deny = _dispatch(_payload("git reset --hard", primary), home=home, project=bare, named=[GATE])
    assert_denied(_decision(deny.stdout))


def test_no_project_dir_means_the_named_guards_alone(gate_home: tuple[Path, Path]) -> None:
    home, _primary = gate_home
    proc = _dispatch(_payload("git add -A", "C:/repo"), home=home, project=None, named=[GATE])
    assert (proc.returncode, proc.stdout, proc.stderr.strip()) == (0, "", "")


# ================================================================== the manifest is untrusted


def _repo_with(tmp_path: Path, manifest: str, *, probe: bool = True) -> Path:
    """A fixture repo whose scripts/hooks/ holds a probe guard that denies everything."""
    root = tmp_path / "Repo"
    hooks = root / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    if probe:
        (hooks / "probe.ps1").write_text(
            "$null = [Console]::In.ReadToEnd()\n" + _DENY % "probe" + "\n", encoding="utf-8"
        )
    (hooks / "shell-guards.txt").write_text(manifest, encoding="utf-8")
    return root


def _escapee(tmp_path: Path) -> Path:
    """A guard OUTSIDE the repo that would deny if it ever ran."""
    out = tmp_path / "outside"
    out.mkdir(exist_ok=True)
    guard = out / "evil.ps1"
    guard.write_text(
        "$null = [Console]::In.ReadToEnd()\n" + _DENY % "escaped" + "\n", encoding="utf-8"
    )
    return guard


@pytest.mark.parametrize(
    "line",
    [
        "{abs}",
        "scripts/hooks/../../outside/evil.ps1",
        "scripts/hooks/../../../outside/evil.ps1",
        r"scripts\hooks\probe.ps1",
        "Scripts/Hooks/probe.ps1",
        "./scripts/hooks/probe.ps1",
        "scripts/hooks/sub/probe.ps1",
        "scripts/hooks/probe.txt",
        "scripts/other/probe.ps1",
        "scripts/hooks/.probe.ps1",
        "scripts/hooks/probe.ps1:stream",
        "scripts/hooks/probe.ps1 ; evil",
    ],
)
def test_a_line_that_is_not_a_repo_hook_is_refused_and_reported(tmp_path: Path, line: str) -> None:
    evil = _escapee(tmp_path)
    root = _repo_with(tmp_path, "# a comment\n\n" + line.format(abs=evil) + "\n")
    proc = _dispatch(_payload("git status", root), home=None, project=root)
    assert "escaped" not in proc.stdout and "probe" not in proc.stdout, proc.stdout
    assert proc.returncode == 1, (proc.returncode, proc.stderr)
    assert "failed open" in proc.stderr and "manifest line 3" in proc.stderr, proc.stderr


def test_a_refused_line_does_not_stop_the_good_ones(tmp_path: Path) -> None:
    evil = _escapee(tmp_path)
    root = _repo_with(tmp_path, f"{evil}\nscripts/hooks/probe.ps1\n")
    proc = _dispatch(_payload("git status", root), home=None, project=root)
    assert assert_denied(_decision(proc.stdout)) == "probe"
    assert "manifest line 1" in proc.stderr


def test_a_good_line_runs_and_a_duplicate_runs_once(tmp_path: Path) -> None:
    root = _repo_with(tmp_path, "", probe=False)
    counter = tmp_path / "runs.txt"
    (root / "scripts" / "hooks" / "count.ps1").write_text(
        f"$null = [Console]::In.ReadToEnd(); Add-Content -LiteralPath '{counter}' -Value x\n",
        encoding="utf-8",
    )
    (root / "scripts" / "hooks" / "shell-guards.txt").write_text(
        "scripts/hooks/count.ps1\nscripts/hooks/count.ps1\n", encoding="utf-8"
    )
    proc = _dispatch(_payload("git status", root), home=None, project=root)
    assert (proc.returncode, proc.stdout, proc.stderr.strip()) == (0, "", "")
    assert counter.read_text(encoding="utf-8").split() == ["x"]


def test_a_listed_guard_that_is_missing_is_reported(tmp_path: Path) -> None:
    root = _repo_with(tmp_path, "scripts/hooks/not-there.ps1\nscripts/hooks/probe.ps1\n")
    proc = _dispatch(_payload("git status", root), home=None, project=root)
    assert assert_denied(_decision(proc.stdout)) == "probe"
    assert "not-there.ps1" in proc.stderr and "no such file" in proc.stderr


def test_an_oversized_manifest_is_refused_whole(tmp_path: Path) -> None:
    root = _repo_with(tmp_path, "scripts/hooks/probe.ps1\n" + "#" * 20000 + "\n")
    proc = _dispatch(_payload("git status", root), home=None, project=root)
    assert proc.stdout == "" and proc.returncode == 1
    assert "16384-byte cap" in proc.stderr


@pytest.mark.skipif(os.name != "nt", reason="a directory junction is a Windows construct")
def test_a_hooks_directory_that_is_a_junction_out_of_the_repo_is_refused(tmp_path: Path) -> None:
    """The line is well-formed and its path lexically inside the repo; the JUNCTION leads out."""
    evil = _escapee(tmp_path)
    (evil.parent / "probe.ps1").write_text(evil.read_text(encoding="utf-8"), encoding="utf-8")
    root = tmp_path / "Repo"
    (root / "scripts").mkdir(parents=True)
    link = root / "scripts" / "hooks"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(evil.parent)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert made.returncode == 0, made.stderr or made.stdout
    (evil.parent / "shell-guards.txt").write_text("scripts/hooks/probe.ps1\n", encoding="utf-8")
    proc = _dispatch(_payload("git status", root), home=None, project=root)
    assert "escaped" not in proc.stdout, proc.stdout
    assert "link or junction" in proc.stderr, proc.stderr


def test_a_relative_project_dir_is_reported(tmp_path: Path) -> None:
    proc = _dispatch(_payload("git status", "C:/repo"), home=None, project=Path("relative/dir"))
    assert proc.returncode == 1 and "not a full path" in proc.stderr, proc.stderr


# ================================================================== a guard's exit code


def _guard(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("native_exit", [2, 128])
def test_a_native_exit_code_left_behind_is_not_the_guard_s_exit(
    tmp_path: Path, native_exit: int
) -> None:
    """Run alone, a guard that runs a native command and then falls off its end exits 0. In-process
    the native's code is still in $LASTEXITCODE, and reading it alone made a 2 a false block and a
    128 -- what git returns outside a repository, which the gate runs -- a reported failure."""
    native = _guard(
        tmp_path,
        "native.ps1",
        f"$null = [Console]::In.ReadToEnd(); $null = & pwsh -NoProfile -Command 'exit {native_exit}'",
    )
    probe = _guard(tmp_path, "probe.ps1", "$null = [Console]::In.ReadToEnd()\n" + _DENY % "probe")
    raw = _payload("git status", "C:/repo")
    alone = _proc(["pwsh", "-NoProfile", "-File", str(native)], raw, _env(None, None))
    assert alone.returncode == 0, alone.returncode
    lone = _dispatch(raw, home=None, project=None, named=[native])
    assert (lone.returncode, lone.stdout, lone.stderr.strip()) == (0, "", "")
    then = _dispatch(raw, home=None, project=None, named=[native, probe])
    assert assert_denied(_decision(then.stdout)) == "probe"


@pytest.mark.parametrize(("code", "expected"), [(2, 2), (1, 1), (128, 1)])
def test_an_explicit_exit_is_still_the_guard_s_exit(
    tmp_path: Path, code: int, expected: int
) -> None:
    """The other half: `exit N` keeps meaning N. 2 blocks; any other non-zero is a reported failure."""
    guard = _guard(tmp_path, "exits.ps1", f"$null = [Console]::In.ReadToEnd(); exit {code}")
    proc = _dispatch(_payload("git status", "C:/repo"), home=None, project=None, named=[guard])
    assert proc.returncode == expected, (proc.returncode, proc.stderr)
    if code != 2:
        assert f"exit code {code}" in proc.stderr
