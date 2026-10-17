# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the PreToolUse shell-guard dispatcher.

The dispatcher (``scripts/hooks/shell-guard-dispatch.ps1``) runs the shell-call guards that
``.claude/settings.json`` names, in order, inside ONE pwsh process, so a Bash or PowerShell tool
call pays pwsh startup once instead of once per guard. Why, with the measurement, is in its header.

WHAT MUST HOLD IS EQUIVALENCE, NOT A NEW POLICY. Each guard keeps its own tests, which drive the
guard file standalone. This module asserts the other half: that the dispatcher's decision on a
payload is exactly what the guards decide standalone, taken in the settings file's order with the
first deny winning, and that one guard's scope, failure or absence cannot change another's verdict.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from tests.test_blanket_stage_guard import bash
from tests.test_claude_settings_contract import (
    _PLACEHOLDER,
    _ROOT,
    _hook_handlers,
    _load,
    matcher_selects,
)
from tests.test_worktree_gate import assert_denied

DISPATCHER = _ROOT / "scripts" / "hooks" / "shell-guard-dispatch.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def _shell_handlers() -> list[tuple[str, dict[str, Any]]]:
    """(matcher, handler) for every PreToolUse handler whose matcher selects a shell tool."""
    return [
        (group.get("matcher", ""), handler)
        for group in _load().get("hooks", {}).get("PreToolUse", [])
        for handler in group.get("hooks", [])
        if any(matcher_selects(group.get("matcher", ""), t) for t in ("Bash", "PowerShell"))
    ]


def _wired_argv() -> list[str]:
    handlers = _shell_handlers()
    assert len(handlers) == 1, f"expected one shell PreToolUse handler, found {len(handlers)}"
    handler = handlers[0][1]
    return [
        str(a).replace(_PLACEHOLDER, _ROOT.as_posix())
        for a in [handler["command"], *handler.get("args", [])]
    ]


def _wired_guards() -> list[Path]:
    """The guard paths the settings file hands the dispatcher, in its order."""
    argv = _wired_argv()
    after = argv[argv.index(next(a for a in argv if a.endswith(DISPATCHER.name))) + 1 :]
    return [Path(a) for a in after]


def _proc(argv: list[str], raw: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=raw, capture_output=True, text=True, timeout=120)


def _run(argv: list[str], raw: str) -> str:
    proc = _proc(argv, raw)
    # Fail-open is the contract: a non-zero exit is a hook error, which lets the command run.
    assert proc.returncode == 0, f"{argv[-1]} exited {proc.returncode}: {proc.stderr}"
    return proc.stdout


def _standalone(guard: Path, raw: str) -> str:
    return _run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(guard)], raw)


def _dispatch_argv(guards: list[Path]) -> list[str]:
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(DISPATCHER)]
    return argv + [str(g) for g in guards]


def _dispatch(guards: list[Path], raw: str) -> str:
    return _run(_dispatch_argv(guards), raw)


def _decision(stdout: str) -> dict[str, Any] | None:
    return json.loads(stdout) if stdout.strip() else None


# ================================================================== the wiring


def test_one_handler_runs_every_shell_guard_through_the_dispatcher() -> None:
    """The point of the change: one process per shell tool call, not one per guard."""
    argv = _wired_argv()
    assert argv[:4] == ["pwsh", "-NoProfile", "-NonInteractive", "-File"], argv
    assert Path(argv[4]).name == DISPATCHER.name, argv
    names = [g.name for g in _wired_guards()]
    assert sorted(names) == sorted(
        ["block-api-burn.ps1", "block-unbounded-fs-scan.ps1", "block-blanket-git-stage.ps1"]
    ), names
    # The bounded guard first: it refuses an over-long payload unread, so a huge payload never
    # reaches the guards that parse whatever they are given. The dispatcher's header says why.
    assert names[0] == "block-blanket-git-stage.ps1", names
    for guard in _wired_guards():
        assert guard.is_file(), guard


def test_the_dispatcher_runs_for_both_shell_tools() -> None:
    matcher = _shell_handlers()[0][0]
    for tool in ("Bash", "PowerShell"):
        assert matcher_selects(matcher, tool), (matcher, tool)


def test_no_other_handler_still_launches_a_guard_on_its_own() -> None:
    """A guard left wired beside the dispatcher would run twice and pay its startup again."""
    for _event, handler in _hook_handlers(_load()):
        args = [str(a) for a in handler.get("args", [])]
        if any(a.endswith(DISPATCHER.name) for a in args):
            continue
        for guard in _wired_guards():
            assert not any(a.endswith(guard.name) for a in args), (guard.name, handler)


# ================================================================== equivalence

# Every guard's deny control, each one's allow control, a command two guards both refuse, a
# quoted mention of each forbidden form, payloads no guard can read, a non-ASCII operand that a
# deny message echoes back, and a command past the blanket guard's length cap.
_CORPUS: list[str] = [
    json.dumps(bash(c, tool=t))
    for t in ("Bash", "PowerShell")
    for c in (
        "git status --short",
        "git add -A",
        "git commit -am wip",
        "gh run watch 123",
        "gh pr checks 5 --watch",
        "find /proc -name x",
        "grep -r pattern /proc",
        "find ./src -maxdepth 2 -name '*.py'",
        "git add -A && gh run watch 1",
        'echo "git add -A; gh run watch 1; find /proc"',
        "find /proc/été -name x",
    )
] + [
    "",
    "not json at all",
    '{"tool_input": {"command": "git add -A"}}',
    json.dumps(bash("echo " + "x" * 70000)),
]


def test_the_dispatcher_decides_exactly_what_the_guards_decide_standalone() -> None:
    """Byte-for-byte: the dispatcher's stdout is the first non-empty stdout of the guards run
    standalone, in the settings file's order -- or nothing, when every guard allows."""
    guards = _wired_guards()
    with ThreadPoolExecutor(max_workers=6) as pool:
        standalone = {(raw, g): pool.submit(_standalone, g, raw) for raw in _CORPUS for g in guards}
        dispatched = {raw: pool.submit(_dispatch, guards, raw) for raw in _CORPUS}
        mismatches = []
        for raw in _CORPUS:
            expected = next(
                (out for g in guards if (out := standalone[(raw, g)].result()).strip()), ""
            )
            got = dispatched[raw].result()
            if got != expected:
                mismatches.append((raw[:120], expected[:200], got[:200]))
    assert not mismatches, mismatches


def test_the_equivalence_corpus_reaches_a_deny_from_every_guard() -> None:
    """The control for the test above: a corpus every guard allows would make it vacuous."""
    for guard, command in (
        ("block-blanket-git-stage.ps1", "git add -A"),
        ("block-api-burn.ps1", "gh run watch 123"),
        ("block-unbounded-fs-scan.ps1", "find /proc -name x"),
    ):
        path = next(g for g in _wired_guards() if g.name == guard)
        assert json.dumps(bash(command)) in _CORPUS
        assert_denied(_decision(_standalone(path, json.dumps(bash(command)))))


def test_the_first_deny_in_settings_order_wins() -> None:
    raw = json.dumps(bash("git add -A && gh run watch 1"))
    reason = assert_denied(_decision(_dispatch(_wired_guards(), raw)))
    assert "blanket git staging" in reason
    reversed_reason = assert_denied(_decision(_dispatch(_wired_guards()[::-1], raw)))
    assert "gh run watch" in reversed_reason


# ================================================================== isolation and fail-open

_DENY = (
    "[Console]::Out.Write((@{hookSpecificOutput=@{hookEventName='PreToolUse';"
    "permissionDecision='deny';permissionDecisionReason='%s'}} | ConvertTo-Json -Compress))"
)


def _guard(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body + "\n", encoding="utf-8")
    return path


def _probe(tmp_path: Path) -> Path:
    """Denies only when it runs WITHOUT strict mode or a Stop preference leaking into it, and
    with the payload on stdin. Reading an unset variable is an error under strict mode Latest,
    and a non-terminating Write-Error becomes a throw under a Stop preference; either one throws
    before the deny, and the dispatcher reads a throw as an allow."""
    return _guard(
        tmp_path,
        "probe.ps1",
        "$raw = [Console]::In.ReadToEnd()\n"
        "Write-Error 'probe: a non-terminating error, harmless unless Stop leaked in'\n"
        "if ($null -eq $neverAssignedAnywhere -and $raw -match 'git') { " + _DENY % "probe" + " }",
    )


def test_a_guard_s_strict_mode_and_error_preference_do_not_leak_into_the_next(
    tmp_path: Path,
) -> None:
    strict = _guard(
        tmp_path,
        "strict.ps1",
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        "$null = [Console]::In.ReadToEnd()",
    )
    raw = json.dumps(bash("git status"))
    assert assert_denied(_decision(_dispatch([strict, _probe(tmp_path)], raw))) == "probe"


def test_a_guard_that_throws_or_is_missing_does_not_stop_the_next(tmp_path: Path) -> None:
    throws = _guard(tmp_path, "throws.ps1", "throw 'broken guard'")
    missing = tmp_path / "not-there.ps1"
    raw = json.dumps(bash("git status"))
    out = _dispatch([throws, missing, _probe(tmp_path)], raw)
    assert assert_denied(_decision(out)) == "probe"


@pytest.mark.parametrize(
    "body",
    ["throw 'broken guard'", "$null = [Console]::In.ReadToEnd(); exit 1", None],
    ids=["throws", "exits-1", "missing"],
)
def test_a_failed_guard_is_reported_not_silently_off(tmp_path: Path, body: str | None) -> None:
    """Run as its own process, a crashed guard was a visible non-blocking hook error (a non-zero
    exit that is not 2). It must stay visible here when nothing else decided."""
    guard = tmp_path / "missing.ps1" if body is None else _guard(tmp_path, "failed.ps1", body)
    proc = _proc(_dispatch_argv([guard]), json.dumps(bash("git status")))
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    assert proc.stdout == ""
    assert "failed open" in proc.stderr and guard.name in proc.stderr


def test_a_blocking_exit_is_passed_on_and_ends_the_run(tmp_path: Path) -> None:
    """Exit 2 is Claude Code's blocking exit, with the reason on stderr."""
    blocks = _guard(
        tmp_path,
        "blocks.ps1",
        "$null = [Console]::In.ReadToEnd(); [Console]::Error.WriteLine('blocked by exit 2'); exit 2",
    )
    proc = _proc(_dispatch_argv([blocks, _probe(tmp_path)]), json.dumps(bash("git status")))
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "blocked by exit 2" in proc.stderr
    assert proc.stdout == ""


def test_stray_console_text_does_not_end_the_run(tmp_path: Path) -> None:
    """Text on stdout that is not a decision decided nothing for a guard run alone, so it must
    not stop the guards after it from denying."""
    stray = _guard(
        tmp_path, "stray.ps1", "$null = [Console]::In.ReadToEnd(); [Console]::Out.Write('debug')"
    )
    raw = json.dumps(bash("git status"))
    assert assert_denied(_decision(_dispatch([stray, _probe(tmp_path)], raw))) == "probe"
    assert _dispatch([stray], raw) == ""


def test_a_non_deny_decision_is_kept_and_a_later_deny_still_wins(tmp_path: Path) -> None:
    ask = _guard(
        tmp_path,
        "ask.ps1",
        "$null = [Console]::In.ReadToEnd()\n" + _DENY.replace("'deny'", "'ask'") % "asked",
    )
    raw = json.dumps(bash("git status"))
    kept = _decision(_dispatch([ask], raw))
    assert kept is not None and kept["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert assert_denied(_decision(_dispatch([ask, _probe(tmp_path)], raw))) == "probe"


def test_a_guard_that_exits_returns_control_to_the_dispatcher(tmp_path: Path) -> None:
    exits = _guard(tmp_path, "exits.ps1", "$null = [Console]::In.ReadToEnd(); exit 0")
    raw = json.dumps(bash("git status"))
    assert assert_denied(_decision(_dispatch([exits, _probe(tmp_path)], raw))) == "probe"


def test_pipeline_output_from_a_guard_is_not_a_decision(tmp_path: Path) -> None:
    chatty = _guard(tmp_path, "chatty.ps1", "'some pipeline output'")
    assert _dispatch([chatty], json.dumps(bash("git status"))) == ""


def test_every_guard_allowing_is_an_allow(tmp_path: Path) -> None:
    raw = json.dumps(bash("git status --short"))
    assert _dispatch(_wired_guards(), raw) == ""
    assert _dispatch([], raw) == ""
