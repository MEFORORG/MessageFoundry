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
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from tests._bash_resolver import require_bash
from tests._spawn_lock import run_single, single_spawn, spawn_burst
from tests.test_blanket_stage_guard import bash
from tests.test_claude_settings_contract import (
    _PLACEHOLDER,
    _ROOT,
    _hook_handlers,
    _load,
    matcher_selects,
)
from tests.test_install_gate_upstream_provenance import _psq
from tests.test_worktree_gate import assert_denied

DISPATCHER = _ROOT / "scripts" / "hooks" / "shell-guard-dispatch.ps1"
INSTALLER = _ROOT / "scripts" / "worktree" / "install-gate.ps1"
USER_GATE = "--user-hook=worktree_gate"

# HERMETIC BY DEFAULT. The dispatcher reads the running account's settings.json to decide whether
# to run the installed worktree gate, and writes proofs into that account. A test that inherited
# this session's CLAUDE_CONFIG_DIR would run the real gate and write into the real account.
_NO_ACCOUNT = Path(tempfile.gettempdir()) / "mefor-test-no-claude-account"
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
    argv: list[str], raw: str, *, burst: bool = False, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    # A single launch takes the shared side of the pwsh spawn lock (BACKLOG #1304). Inside a
    # burst, which already holds the exclusive side, it must not wait on its own burst.
    launch = subprocess.run if burst else run_single
    full = {**os.environ, **_HERMETIC, **(env or {})}
    return launch(argv, input=raw, capture_output=True, text=True, timeout=120, env=full)


def _run(
    argv: list[str], raw: str, *, burst: bool = False, env: dict[str, str] | None = None
) -> str:
    proc = _proc(argv, raw, burst=burst, env=env)
    # Fail-open is the contract: a non-zero exit is a hook error, which lets the command run.
    assert proc.returncode == 0, f"{argv[-1]} exited {proc.returncode}: {proc.stderr}"
    return proc.stdout


def _standalone(guard: Path, raw: str, *, burst: bool = False) -> str:
    return _run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(guard)], raw, burst=burst)


def _dispatch_argv(guards: Sequence[Path | str]) -> list[str]:
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(DISPATCHER)]
    return argv + [str(g) for g in guards]


def _dispatch(guards: list[Path], raw: str, *, burst: bool = False) -> str:
    return _run(_dispatch_argv(guards), raw, burst=burst)


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
    # The installed worktree gate runs before every repository guard: the account's entry waits
    # on its proof (the dispatcher says why).
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
    # Six concurrent pwsh launches are a storm, so each chunk holds the exclusive side of the spawn
    # lock (BACKLOG #1304). The test flaked once in a parallel suite run, with its detail lost; the
    # storm is the likely cause, not a measured one. A few chunks rather than one burst: a single
    # hold over about 100 launches would make every other worker's locked launch wait it out, and
    # each burst can first wait up to 15 s for in-flight launches, so the chunks stay few.
    mismatches = []
    with ThreadPoolExecutor(6) as pool:
        for start in range(0, len(_CORPUS), 9):
            chunk = _CORPUS[start : start + 9]
            with spawn_burst("test_shell_guard_dispatch equivalence"):
                standalone = {
                    (raw, g): pool.submit(_standalone, g, raw, burst=True)
                    for raw in chunk
                    for g in guards
                }
                dispatched = {raw: pool.submit(_dispatch, guards, raw, burst=True) for raw in chunk}
                for raw in chunk:
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


def test_an_unknown_option_is_reported_not_run() -> None:
    proc = _proc(_dispatch_argv(["--user-hook=../escape"]), json.dumps(bash("git status")))
    assert proc.returncode == 1 and "unknown option" in proc.stderr


# ================================================================== the account's worktree gate

_SID = "0f1e2d3c-aaaa-bbbb-cccc-123456789abc"
_CALL = "toolu_01TestCallAbc"


class _World:
    """A fake home with an installed gate stub, an account that may delegate it, and a project
    whose settings pass the gate to the dispatcher. The stub logs every run to `log`."""

    def __init__(self, tmp_path: Path, *, delegates: bool = True, gate: str | None = "") -> None:
        self.log = tmp_path / "gate-runs.log"
        home = tmp_path / "home"
        hooks = home / ".claude" / "hooks"
        hooks.mkdir(parents=True)
        self.gate = hooks / "worktree_gate.ps1"
        if gate is not None:
            _guard(
                hooks,
                self.gate.name,
                "$in = [Console]::In.ReadToEnd()\n"
                f"Add-Content -LiteralPath {_psq(str(self.log))} -Value 'ran'\n" + gate,
            )
        self.account = tmp_path / "account"
        self.account.mkdir()
        command = "bash entry: shell-guard-proof" if delegates else "pwsh -File worktree_gate.ps1"
        entry = {"matcher": "Bash|PowerShell", "hooks": [{"command": command}]}
        (self.account / "settings.json").write_text(
            json.dumps({"hooks": {"PreToolUse": [entry]}}), encoding="utf-8"
        )
        self.proofs = self.account / "shell-guard-proof"
        self.project = tmp_path / "project"
        (self.project / ".claude").mkdir(parents=True)
        self.project_settings(USER_GATE)
        self.env = {
            "USERPROFILE": str(home),
            "HOME": str(home),
            "CLAUDE_CONFIG_DIR": str(self.account),
            "CLAUDE_PROJECT_DIR": str(self.project),
        }

    def project_settings(self, arg: str) -> None:
        (self.project / ".claude" / "settings.json").write_text(
            json.dumps({"args": [arg]}), encoding="utf-8"
        )

    def runs(self) -> int:
        return len(self.log.read_text(encoding="utf-8").split()) if self.log.exists() else 0

    def proof(self, kind: str, call: str = _CALL) -> Path:
        return self.proofs / f"{call}.{kind}"

    def hint(self) -> Path:
        return self.proofs / f"{_SID}.session"


def _payload(command: str = "git status", call: str | None = _CALL) -> str:
    body = {**bash(command), "session_id": _SID}
    if call is not None:
        body["tool_use_id"] = call
    return json.dumps(body)


_GATE_DENIES = _DENY % "installed gate"


def test_a_delegated_gate_that_allows_leaves_this_call_its_proof(tmp_path: Path) -> None:
    world = _World(tmp_path)
    proc = _proc(_dispatch_argv([USER_GATE]), _payload(), env=world.env)
    assert proc.returncode == 0 and proc.stdout == "", (proc.returncode, proc.stderr)
    assert world.runs() == 1
    assert world.proof("ok").read_text(encoding="utf-8") == _SID + "\n"
    assert not world.proof("run").exists()
    assert world.hint().is_file(), "the account's entry waits only for a hinted session"


def test_a_delegated_gate_that_denies_leaves_no_proof(tmp_path: Path) -> None:
    world = _World(tmp_path, gate=_GATE_DENIES)
    out = _run(_dispatch_argv([USER_GATE]), _payload(), env=world.env)
    assert assert_denied(_decision(out)) == "installed gate"
    assert not world.proof("ok").exists()
    assert world.proof("run").is_file(), "the entry is told to run the gate now, not wait"


@pytest.mark.parametrize(
    ("gate", "code"),
    [
        ("[Console]::Error.WriteLine('gate blocks'); exit 2", 2),
        ("exit 1", 1),
        ("throw 'broken gate'", 1),
        (None, 1),
        (_DENY.replace("'deny'", "'ask'") % "asked", 0),
        ("[Console]::Out.Write('stray text')", 0),
    ],
    ids=["exit-2", "exit-1", "throws", "missing", "asks", "stray-stdout"],
)
def test_anything_but_a_silent_allow_leaves_no_proof(
    tmp_path: Path, gate: str | None, code: int
) -> None:
    """Only a gate that finished normally and printed nothing stands the account's entry down."""
    world = _World(tmp_path, gate=gate)
    proc = _proc(_dispatch_argv([USER_GATE]), _payload(), env=world.env)
    assert proc.returncode == code, (proc.returncode, proc.stdout, proc.stderr)
    assert not world.proof("ok").exists()
    assert world.proof("run").is_file()


def test_a_payload_without_a_call_id_gets_the_gate_but_no_proof(tmp_path: Path) -> None:
    world = _World(tmp_path)
    proc = _proc(_dispatch_argv([USER_GATE]), _payload(call=None), env=world.env)
    assert proc.returncode == 0, proc.stderr
    assert world.runs() == 1
    assert not list(world.proofs.glob("*.ok")) and not list(world.proofs.glob("*.run"))


def test_an_account_that_does_not_delegate_is_not_run_twice(tmp_path: Path) -> None:
    """That account still runs the gate itself, so running it here too would be a second run."""
    world = _World(tmp_path, delegates=False, gate=_GATE_DENIES)
    assert _run(_dispatch_argv([USER_GATE]), _payload(), env=world.env) == ""
    assert world.runs() == 0
    assert not world.proofs.exists()


def test_an_account_that_stopped_delegating_releases_a_waiting_entry(tmp_path: Path) -> None:
    world = _World(tmp_path, delegates=False)
    world.proofs.mkdir()
    world.hint().touch()
    assert _run(_dispatch_argv([USER_GATE]), _payload(), env=world.env) == ""
    assert world.proof("run").is_file() and not world.proof("ok").exists()
    assert not world.hint().exists()


def test_old_proofs_are_pruned(tmp_path: Path) -> None:
    world = _World(tmp_path)
    world.proofs.mkdir()
    old = time.time() - 3600
    stale = world.proof("ok", "toolu_old")
    stale.write_text(_SID + "\n", encoding="utf-8")
    os.utime(stale, (old, old))
    other = world.proofs / "another-session.session"
    other.touch()
    os.utime(other, (old, old))
    assert _run(_dispatch_argv([USER_GATE]), _payload(), env=world.env) == ""
    assert not stale.exists(), "a proof older than 10 minutes is pruned"
    assert other.exists(), "a session hint is kept for 30 days"
    assert world.proof("ok").exists()


# ================================================================== the account's shell entry


def _installed_shell_entry(tmp_path: Path, gate_dst: Path) -> dict[str, Any]:
    """Build the installer's real Bash|PowerShell entry for a given gate path, without installing:
    the region from the entry text through the entry list, run as the installer runs it."""
    text = INSTALLER.read_text(encoding="utf-8")
    # From the installer's own $command line, so the test cannot carry a drifted copy of it.
    start = text.index('$command = "pwsh -NoProfile -File')
    region = text[start : text.index("# Wire (idempotently)")]
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$GateDst = {_psq(str(gate_dst))}",
            region,
            "$entries | Where-Object { $_.matcher -ceq 'Bash|PowerShell' } |"
            " ConvertTo-Json -Depth 6 -Compress",
        ]
    )
    runner = tmp_path / "entry.ps1"
    runner.write_text(script, encoding="utf-8")
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    entry: dict[str, Any] = json.loads(proc.stdout)["hooks"][0]
    return entry


class _Entry:
    """The installed entry, run through bash -c the way a shell-form hook runs."""

    def __init__(self, tmp_path: Path, world: _World) -> None:
        self.world = world
        self.hook = _installed_shell_entry(tmp_path, world.gate)
        self.shell = require_bash(tmp_path)

    def start(self) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [self.shell, "-c", self.hook["command"]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, **self.world.env},
        )
        assert proc.stdin is not None
        proc.stdin.write(_payload())
        proc.stdin.close()
        return proc

    def run(self) -> tuple[subprocess.CompletedProcess[str], float]:
        began = time.monotonic()
        with single_spawn():
            proc = self.start()
            out, err = proc.communicate(timeout=120)
        return subprocess.CompletedProcess(proc.args, proc.returncode, out, err), (
            time.monotonic() - began
        )


def _hinted(world: _World) -> None:
    world.proofs.mkdir(exist_ok=True)
    world.hint().touch()


def test_the_installed_shell_entry_is_bash_and_blocks_on_its_own_failure(tmp_path: Path) -> None:
    hook = _installed_shell_entry(tmp_path, tmp_path / "worktree_gate.ps1")
    assert hook["shell"] == "bash"
    assert hook["onFailure"] == "block", (
        "an entry that cannot start must not leave the call ungated"
    )
    # The wait (20 s) leaves the gate 40 s, more than its old 15 s, before the entry is refused.
    assert hook["timeout"] == 60
    assert "worktree_gate.ps1" in hook["command"], "the installer's marker finds its own entry"
    assert "shell-guard-proof" in hook["command"], "the dispatcher's delegation check reads this"
    assert USER_GATE in hook["command"], "the entry waits only where the project wires the gate"
    assert "\r" not in hook["command"]
    # Measured 2026-10-17: a bash started without Git's /usr/bin on PATH ran Windows' timeout.exe
    # for a bare `timeout`, which exits 1 without running the gate. The hook's timeout bounds it.
    assert "timeout " not in hook["command"]


def test_an_unhinted_session_runs_the_gate_at_once(tmp_path: Path) -> None:
    world = _World(tmp_path, gate=_GATE_DENIES)
    done, took = _Entry(tmp_path, world).run()
    assert done.returncode == 0, done.stderr
    assert assert_denied(_decision(done.stdout)) == "installed gate"
    assert world.runs() == 1
    assert took < 15, took


def test_the_entry_stands_down_on_this_call_s_proof_and_the_gate_runs_once(
    tmp_path: Path,
) -> None:
    """The whole design, end to end: the entry and the real dispatcher start together, as Claude
    Code starts them, and the gate runs once -- in the dispatcher -- for an allowed call."""
    world = _World(tmp_path)
    entry = _Entry(tmp_path, world)
    _hinted(world)
    with spawn_burst("test_shell_guard_dispatch entry and dispatcher"):
        waiting = entry.start()
        dispatched = _proc(_dispatch_argv([USER_GATE]), _payload(), burst=True, env=world.env)
        out, err = waiting.communicate(timeout=120)
    assert dispatched.returncode == 0, dispatched.stderr
    assert waiting.returncode == 0 and out == "", (waiting.returncode, out, err)
    assert world.runs() == 1


def test_a_deny_in_the_dispatcher_is_repeated_by_the_entry_without_a_wait(tmp_path: Path) -> None:
    world = _World(tmp_path, gate=_GATE_DENIES)
    entry = _Entry(tmp_path, world)
    _hinted(world)
    with spawn_burst("test_shell_guard_dispatch entry and dispatcher, deny"):
        waiting = entry.start()
        dispatched = _proc(_dispatch_argv([USER_GATE]), _payload(), burst=True, env=world.env)
        settled = time.monotonic()
        out, err = waiting.communicate(timeout=120)
    assert assert_denied(_decision(dispatched.stdout)) == "installed gate"
    assert assert_denied(_decision(out)) == "installed gate", err
    assert world.runs() == 2
    assert time.monotonic() - settled < 15, "the .run proof ends the wait"


def test_a_proof_older_than_the_wait_is_not_this_call_s(tmp_path: Path) -> None:
    """A proof already on disk when the call began -- stale, or planted for an id read early from
    the transcript -- does not stand the gate down."""
    world = _World(tmp_path, gate=_GATE_DENIES)
    _hinted(world)
    world.proof("ok").write_text(_SID + "\n", encoding="utf-8")
    old = time.time() - 5
    os.utime(world.proof("ok"), (old, old))
    done, took = _Entry(tmp_path, world).run()
    assert assert_denied(_decision(done.stdout)) == "installed gate"
    assert world.runs() == 1
    assert took < 15, took


def test_a_proof_for_another_session_is_not_this_call_s(tmp_path: Path) -> None:
    world = _World(tmp_path, gate=_GATE_DENIES)
    entry = _Entry(tmp_path, world)
    _hinted(world)
    with single_spawn():
        waiting = entry.start()
        deadline = time.monotonic() + 30
        while not world.proof("wait").exists():
            assert time.monotonic() < deadline, "the entry never began waiting"
            time.sleep(0.02)
        time.sleep(0.05)
        world.proof("ok").write_text("some-other-session\n", encoding="utf-8")
        out, err = waiting.communicate(timeout=120)
    assert assert_denied(_decision(out)) == "installed gate", err
    assert world.runs() == 1


def test_a_project_that_does_not_wire_the_gate_costs_no_wait(tmp_path: Path) -> None:
    """A hint alone never makes the entry wait where the project's dispatcher cannot answer."""
    world = _World(tmp_path, gate=_GATE_DENIES)
    _hinted(world)
    world.project_settings("--something-else")
    done, took = _Entry(tmp_path, world).run()
    assert assert_denied(_decision(done.stdout)) == "installed gate"
    assert took < 15, took
    assert not world.proof("wait").exists()


def test_with_no_answer_the_wait_ends_and_the_gate_runs(tmp_path: Path) -> None:
    """A hinted session whose dispatcher never answers: a missing, broken or slow replacement."""
    world = _World(tmp_path, gate=_GATE_DENIES)
    _hinted(world)
    done, took = _Entry(tmp_path, world).run()
    assert assert_denied(_decision(done.stdout)) == "installed gate", done.stderr
    assert world.runs() == 1
    assert 19 < took < 55, took


@pytest.mark.parametrize(
    ("gate", "code", "message"),
    [
        ("[Console]::Error.WriteLine('gate blocks'); exit 2", 2, None),
        ("exit 1", 0, "exited 1"),
        ("throw 'broken gate'", 0, "exited 1"),
    ],
    ids=["exit-2", "exit-1", "throws"],
)
def test_the_gate_s_own_exit_keeps_its_old_meaning(
    tmp_path: Path, gate: str, code: int, message: str | None
) -> None:
    """onFailure=block covers the entry, not the gate: a gate that crashes still fails open, now
    with a message, and its blocking exit still blocks."""
    world = _World(tmp_path, gate=gate)
    done, _ = _Entry(tmp_path, world).run()
    assert done.returncode == code, (done.returncode, done.stdout, done.stderr)
    if message is None:
        assert "gate blocks" in done.stderr
    else:
        assert message in json.loads(done.stdout)["systemMessage"]
