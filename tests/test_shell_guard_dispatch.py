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
import os
import shutil
import subprocess
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from tests._bash_resolver import require_bash
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
INSTALLER = _ROOT / "scripts" / "worktree" / "install-gate.ps1"
USER_GATE = "--user-hook=worktree_gate"

# HERMETIC BY DEFAULT. The dispatcher reads the running account's settings.json to decide whether
# to run the installed worktree gate, so a test that inherited this session's CLAUDE_CONFIG_DIR
# would run the real gate. No account directory means nothing delegates.
_NO_ACCOUNT = _ROOT / "no-such-claude-config-dir"
_HERMETIC = {"CLAUDE_CONFIG_DIR": str(_NO_ACCOUNT), "CLAUDE_PROJECT_DIR": str(_NO_ACCOUNT)}

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
    return [Path(a) for a in after if not a.startswith("--")]


def _proc(
    argv: list[str], raw: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    full = {**os.environ, **_HERMETIC, **(env or {})}
    return subprocess.run(argv, input=raw, capture_output=True, text=True, timeout=120, env=full)


def _run(argv: list[str], raw: str, env: dict[str, str] | None = None) -> str:
    proc = _proc(argv, raw, env)
    # Fail-open is the contract: a non-zero exit is a hook error, which lets the command run.
    assert proc.returncode == 0, f"{argv[-1]} exited {proc.returncode}: {proc.stderr}"
    return proc.stdout


def _standalone(guard: Path, raw: str) -> str:
    return _run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(guard)], raw)


def _dispatch_argv(guards: Sequence[Path | str]) -> list[str]:
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(DISPATCHER)]
    return argv + [str(g) for g in guards]


def _dispatch(guards: Sequence[Path | str], raw: str, env: dict[str, str] | None = None) -> str:
    return _run(_dispatch_argv(guards), raw, env)


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
    # The installed worktree gate runs before every repository guard (the dispatcher says why).
    assert argv[5] == USER_GATE, argv
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


def test_a_failed_native_command_inside_a_guard_is_not_a_failed_guard(tmp_path: Path) -> None:
    """worktree_gate.ps1 runs git, and a git call that fails leaves $LASTEXITCODE non-zero while
    the script goes on to finish normally. Run alone that was exit 0, so it must be here too."""
    native = _guard(
        tmp_path,
        "native.ps1",
        "$null = [Console]::In.ReadToEnd(); $null = git rev-parse --verify no-such-ref 2>$null",
    )
    proc = _proc(_dispatch_argv([native]), json.dumps(bash("git status")))
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    assert proc.stdout == ""


# ================================================================== the account's worktree gate

_SID = "0f1e2d3c-aaaa-bbbb-cccc-123456789abc"


def _account(tmp_path: Path, *, delegates: bool, gate: str | None) -> dict[str, str]:
    """A fake home with an installed gate, and an account whose settings may delegate it."""
    home = tmp_path / "home"
    hooks = home / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    if gate is not None:
        (hooks / "worktree_gate.ps1").write_text(gate + "\n", encoding="utf-8")
    account = tmp_path / "account"
    account.mkdir()
    command = f"# delegates {USER_GATE}" if delegates else "pwsh -File worktree_gate.ps1"
    body = {
        "hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell", "hooks": [{"command": command}]}]}
    }
    (account / "settings.json").write_text(json.dumps(body), encoding="utf-8")
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    return {
        "USERPROFILE": str(home),
        "HOME": str(home),
        "CLAUDE_CONFIG_DIR": str(account),
        "CLAUDE_PROJECT_DIR": str(project),
    }


def _payload(command: str = "git status") -> str:
    return json.dumps({**bash(command), "session_id": _SID})


_GATE_DENIES = "$null = [Console]::In.ReadToEnd(); " + _DENY % "installed gate"


def test_a_delegated_gate_runs_in_process_and_records_the_session(tmp_path: Path) -> None:
    env = _account(tmp_path, delegates=True, gate=_GATE_DENIES)
    out = _dispatch([USER_GATE], _payload(), env)
    assert assert_denied(_decision(out)) == "installed gate"
    marker = Path(env["CLAUDE_PROJECT_DIR"]) / ".git" / "shell-guard-dispatch" / _SID
    assert marker.is_file(), "the account's own entry needs the marker to stand down"


def test_an_account_that_does_not_delegate_is_not_run_twice(tmp_path: Path) -> None:
    """The account still runs the gate itself, so running it here too would be a second launch."""
    env = _account(tmp_path, delegates=False, gate=_GATE_DENIES)
    assert _dispatch([USER_GATE], _payload(), env) == ""
    assert not (Path(env["CLAUDE_PROJECT_DIR"]) / ".git" / "shell-guard-dispatch").exists()


def test_a_session_marker_keeps_the_gate_when_the_account_file_reads_nothing(
    tmp_path: Path,
) -> None:
    """The account's entry has stood down for a marked session, so a failed or changed read of the
    account file must not leave the call with no gate at all."""
    env = _account(tmp_path, delegates=False, gate=_GATE_DENIES)
    markers = Path(env["CLAUDE_PROJECT_DIR"]) / ".git" / "shell-guard-dispatch"
    markers.mkdir()
    (markers / _SID).touch()
    assert assert_denied(_decision(_dispatch([USER_GATE], _payload(), env))) == "installed gate"


def test_a_delegated_gate_that_is_missing_is_reported(tmp_path: Path) -> None:
    env = _account(tmp_path, delegates=True, gate=None)
    proc = _proc(_dispatch_argv([USER_GATE]), _payload(), env)
    assert proc.returncode == 1, (proc.returncode, proc.stderr)
    assert "worktree_gate.ps1" in proc.stderr


def test_an_unknown_option_is_reported_not_run(tmp_path: Path) -> None:
    proc = _proc(_dispatch_argv(["--user-hook=../escape"]), _payload())
    assert proc.returncode == 1 and "unknown option" in proc.stderr


# ================================================================== the account's stand-down entry


def _installed_shell_entry(tmp_path: Path, gate_dst: Path) -> dict[str, Any]:
    """Build the installer's real Bash|PowerShell entry for a given gate path, without installing:
    the region from the stand-down text through the entry list, run as the installer runs it."""
    text = INSTALLER.read_text(encoding="utf-8")
    region = text[text.index("$gateForBash = ") : text.index("# Wire (idempotently)")]
    # The matcher list sits inside this region and reads two switches; neither is set here.
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$Marker = 'worktree_gate.ps1'",
            f"$GateDst = '{gate_dst}'",
            f"$command = 'pwsh -NoProfile -File \"{gate_dst}\"'",
            "$matchers = @('Write|Edit|MultiEdit|NotebookEdit', 'Bash|PowerShell')",
            region,
            "$entries | Where-Object { $_.matcher -ceq 'Bash|PowerShell' } |"
            " ConvertTo-Json -Depth 6 -Compress",
        ]
    )
    runner = tmp_path / "entry.ps1"
    runner.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    entry: dict[str, Any] = json.loads(proc.stdout)["hooks"][0]
    return entry


def test_the_installed_shell_entry_stands_down_only_for_a_recorded_session(
    tmp_path: Path,
) -> None:
    gate = tmp_path / "hooks" / "worktree_gate.ps1"
    gate.parent.mkdir()
    # A stub gate that proves it ran and that the payload reached it on stdin.
    gate.write_text(
        "$in = [Console]::In.ReadToEnd()\n"
        "$saw = if ($in -match '\"session_id\"') { 'saw the payload' } else { 'saw nothing' }\n"
        + _DENY.replace("'%s'", "$saw")
        + "\n",
        encoding="utf-8",
    )
    entry = _installed_shell_entry(tmp_path, gate)
    assert entry["shell"] == "bash"
    assert "worktree_gate.ps1" in entry["command"], "the installer's marker finds its own entry"
    assert USER_GATE in entry["command"], "the dispatcher's delegation check reads this text"

    shell = require_bash(tmp_path)
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / ".claude").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.write_text(json.dumps({"args": [USER_GATE]}), encoding="utf-8")

    def run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [shell, "-c", entry["command"]],
            input=_payload(),
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "CLAUDE_PROJECT_DIR": str(project)},
        )

    # No marker: the account runs the gate, and the gate sees the payload.
    first = run()
    assert first.returncode == 0, first.stderr
    assert assert_denied(_decision(first.stdout)) == "saw the payload"

    # Marker recorded by a dispatcher that ran the gate for this session: stand down.
    markers = project / ".git" / "shell-guard-dispatch"
    markers.mkdir()
    (markers / _SID).touch()
    second = run()
    assert second.returncode == 0, second.stderr
    assert second.stdout == ""

    # A marker in a project whose dispatcher does not run the gate is not a reason to stand down:
    # it may be stale, or forged with one touch.
    settings.write_text(json.dumps({"args": []}), encoding="utf-8")
    assert assert_denied(_decision(run().stdout)) == "saw the payload"
    settings.write_text(json.dumps({"args": [USER_GATE]}), encoding="utf-8")

    # Another session's marker is not this session's.
    (markers / _SID).unlink()
    (markers / "some-other-session").touch()
    third = run()
    assert assert_denied(_decision(third.stdout)) == "saw the payload"
