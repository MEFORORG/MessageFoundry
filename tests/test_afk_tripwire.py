# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/hooks/afk-tripwire.ps1: a Class C act in a shell command is recorded, not blocked
(ADR 0211; docs/AUTONOMY-PLAN.md section 4.4).

THE TWO ARMS ARE DISJOINT AND BOTH ARE REQUIRED. The hit arm alone passes for a hook that trips on
everything, and the pass arm alone for one that trips on nothing; the pass arm carries the quoted
mentions a commit message or a heredoc holds, because a tripwire that fires on prose is noise.

Every test drives the real hook as a subprocess with a real PreToolUse payload, from a sandbox git
repository (tests/_fake_gh.py), so a record lands in the sandbox's spool and a gh call would show.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import ROOT, Sandbox, make_sandbox

HOOK = ROOT / "scripts" / "hooks" / "afk-tripwire.ps1"
DISPATCHER = ROOT / "scripts" / "hooks" / "shell-guard-dispatch.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    return make_sandbox(tmp_path)


def _payload(command: str, tool: str = "Bash") -> str:
    return json.dumps(
        {"tool_name": tool, "tool_input": {"command": command}, "session_id": "sess-trip-0001"}
    )


def _context(stdout: str) -> str | None:
    if not stdout.strip():
        return None
    out: dict[str, Any] = json.loads(stdout)
    assert "permissionDecision" not in out["hookSpecificOutput"], "the tripwire must not decide"
    context: str = out["hookSpecificOutput"]["additionalContext"]
    return context


def _run(sb: Sandbox, command: str, *, cloud: bool = True, tool: str = "Bash") -> str | None:
    extra = {"CLAUDE_CODE_REMOTE": "true"} if cloud else {}
    proc = sb.run(HOOK, stdin=_payload(command, tool), **extra)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    return _context(proc.stdout)


MUST_HIT = [
    pytest.param("git push --force origin b", "git push --force", id="push-force"),
    pytest.param("git push -f origin b", "git push --force", id="push-f"),
    pytest.param("git -C D:/x push -uf origin b", "git push --force", id="push-cluster"),
    pytest.param("git --super-prefix x/ push --force", "git push --force", id="super-prefix"),
    pytest.param(
        "cat <<'EOF' | git commit --no-verify -F -\nmsg\nEOF",
        "--no-verify",
        id="command-after-heredoc-opener",
    ),
    pytest.param(
        "cat <<EOF > f\nEOF\ngit push --force origin b", "git push --force", id="empty-heredoc"
    ),
    pytest.param(
        "git push origin $(git branch --show-current) --force",
        "git push --force",
        id="subexpression-argument",
    ),
    pytest.param("git push origin ${BR} --force", "git push --force", id="braced-variable"),
    pytest.param("git push \\\r\n--force origin b", "git push --force", id="crlf-continuation"),
    pytest.param("if ($a) { git push --force }", "git push --force", id="powershell-block"),
    pytest.param(
        "git -c core.hooksPath=/dev/null commit -m x", "core.hooksPath", id="hooks-path-override"
    ),
    pytest.param("SKIP=ruff,mypy git commit -m x", "SKIP=", id="pre-commit-skip"),
    pytest.param("$null = git push --force origin b", "git push --force", id="ps-assignment"),
    pytest.param("$r = git reset --hard", "git reset --hard", id="ps-assignment-reset"),
    pytest.param('git push "--force" origin b', "git push --force", id="quoted-flag"),
    pytest.param("git push --forc origin b", "git push --force", id="abbreviated-long"),
    pytest.param("git reset --ha", "git reset --hard", id="abbreviated-hard"),
    pytest.param(
        "gh variable set MEFOR_AFK_KILL --repo MEFORORG/MessageFoundry --body off",
        "kill switch",
        id="kill-switch-set",
    ),
    pytest.param(
        "gh api -X PATCH repos/MEFORORG/MessageFoundry/actions/variables/MEFOR_AFK_KILL"
        " -f value=off",
        "kill switch",
        id="kill-switch-patch",
    ),
    pytest.param("git push --force-with-lease origin b", "git push --force", id="lease"),
    pytest.param("git push origin +main:main", "git push --force", id="plus-refspec"),
    pytest.param("git push origin :old-branch", "git push ref deletion", id="colon-refspec"),
    pytest.param("git push origin --delete old", "git push ref deletion", id="delete"),
    pytest.param("git push -d origin old", "git push ref deletion", id="delete-short"),
    pytest.param("git commit --no-verify -m wip", "git commit --no-verify", id="no-verify"),
    pytest.param("git commit -nm wip", "git commit -n", id="commit-n-cluster"),
    pytest.param("git push --no-verify", "git push --no-verify", id="push-no-verify"),
    pytest.param("git reset --hard origin/main", "git reset --hard", id="reset-hard"),
    pytest.param("cd x && git reset --hard", "git reset --hard", id="after-separator"),
    pytest.param('bash -c "git reset --hard HEAD"', "git reset --hard", id="behind-bash-c"),
    pytest.param("pwsh -Command 'git push -f'", "git push --force", id="behind-pwsh-command"),
    pytest.param(
        r"pwsh -NoProfile -File scripts\worktree\remove.ps1 -Path x -Force",
        "remove.ps1 -Force",
        id="remove-force",
    ),
    pytest.param(r"& 'D:\a b\claim.ps1' -Release 5 -force", "claim.ps1 -Force", id="claim-force"),
    pytest.param(
        r"pwsh -File scripts\coord\alloc.ps1 -Kind adr -AllowOrphanedAllocations",
        "-AllowOrphanedAllocations",
        id="allow-orphaned",
    ),
]

MUST_PASS = [
    pytest.param("git status", id="status"),
    pytest.param("git push origin b", id="plain-push"),
    pytest.param("git push -u origin b", id="push-u"),
    pytest.param("git commit -am wip", id="commit-am"),
    pytest.param("git commit -m 'never use --no-verify or reset --hard'", id="quoted-message"),
    pytest.param('echo "git push --force"', id="echo-mention"),
    pytest.param("cat <<'EOF' > notes.txt\ngit push --force\nEOF\necho done", id="heredoc-body"),
    pytest.param(
        'git commit -F - <<"END-OF-MSG"\ngit reset --hard is never run here\nEND-OF-MSG',
        id="heredoc-dashed-delimiter",
    ),
    pytest.param("cat <<\\EOF\ngit push -f\nEOF", id="heredoc-escaped-delimiter"),
    pytest.param("git reset --soft HEAD~1", id="reset-soft"),
    pytest.param(r"pwsh -File scripts\worktree\remove.ps1 -Path x", id="remove-no-force"),
    pytest.param("Remove-Item -Force x.txt", id="remove-item-force"),
    pytest.param("git log --format=%H -n 3", id="log-n"),
    pytest.param("git push --progress origin b", id="push-progress"),
    pytest.param("git commit -uno -m x", id="commit-untracked-mode"),
    pytest.param("git push origin b # never --force", id="flag-in-comment"),
    pytest.param("git commit -m '--no-verify'", id="quoted-flag-as-message"),
    pytest.param(
        "gh api repos/MEFORORG/MessageFoundry/actions/variables/MEFOR_AFK_KILL",
        id="kill-switch-read",
    ),
    pytest.param("gh api repos/MEFORORG/MessageFoundry/pulls/1 -X PATCH -f x=y", id="other-gh"),
]


@pytest.mark.parametrize(("command", "act"), MUST_HIT)
def test_each_class_c_act_trips(sb: Sandbox, command: str, act: str) -> None:
    context = _run(sb, command)
    assert context is not None, f"{command!r} did not trip"
    assert act in context and "Class C" in context


@pytest.mark.parametrize("command", MUST_PASS)
def test_ordinary_commands_and_mentions_do_not_trip(sb: Sandbox, command: str) -> None:
    assert _run(sb, command) is None


def test_powershell_tool_commands_trip_too(sb: Sandbox) -> None:
    assert _run(sb, "git reset --hard", tool="PowerShell") is not None


def test_a_hit_is_spooled_as_a_tripwire_record_with_no_network(sb: Sandbox) -> None:
    command = "git push --force https://user:SECRET-TOKEN@example.invalid/r.git b"
    context = _run(sb, command, cloud=False)
    assert context is not None and "Recorded as tripwire d" in context
    assert sb.calls == [], "the tripwire hook reached gh"
    (spooled,) = sb.spool()
    rec = json.loads(spooled.read_text(encoding="utf-8"))
    assert rec["kind"] == "tripwire" and rec["class"] == "C" and rec["outcome"] == "detected"
    assert rec["session"] == "sess-trip-0001"
    assert "git push --force" in rec["note"]
    assert "SECRET-TOKEN" not in spooled.read_text(encoding="utf-8"), "the command text was logged"


def test_a_hit_never_probes_an_unreachable_shared_root(sb: Sandbox) -> None:
    """The header says no network. A configured root that does not answer must not be probed:
    the probe would write coord-root-down.json, and a dead SMB read can hang for a minute."""
    proc = sb.run(HOOK, stdin=_payload("git reset --hard"), MEFOR_COORD_ROOT=r"\\192.0.2.1\coord")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    context = _context(proc.stdout)
    assert context is not None and "Recorded as tripwire d" in context
    assert not (sb.coord / "coord-root-down.json").exists(), "the hook probed the shared root"
    assert len(sb.spool()) == 1
    assert "seat registry" not in proc.stderr, "decision.ps1's note escaped the hook's 2>$null"


def test_a_miss_writes_nothing(sb: Sandbox) -> None:
    assert _run(sb, "git status", cloud=False) is None
    assert sb.spool() == []


def test_a_cloud_session_is_told_but_writes_no_record(sb: Sandbox) -> None:
    context = _run(sb, "git reset --hard", cloud=True)
    assert context is not None and "your Manager logs it" in context
    assert not sb.coord.exists()


@pytest.mark.parametrize("raw", ["", "not json", '{"tool_input": {}}'])
def test_unreadable_payloads_fail_open_silently(sb: Sandbox, raw: str) -> None:
    proc = sb.run(HOOK, stdin=raw, CLAUDE_CODE_REMOTE="true")
    assert proc.returncode == 0 and proc.stdout == "", (proc.stdout, proc.stderr)


# ------------------------------------------------------------------ through the dispatcher


def _asker(tmp_path: Path) -> Path:
    guard = tmp_path / "ask-guard.ps1"
    guard.write_text(
        "$null = [Console]::In.ReadToEnd()\n"
        '[Console]::Out.Write(\'{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
        '"permissionDecision":"ask","permissionDecisionReason":"because"}}' + "')\n",
        encoding="utf-8",
    )
    return guard


def _dispatch(sb: Sandbox, guards: list[Path], command: str) -> dict[str, Any]:
    local = [sb.repo / g.relative_to(ROOT) if g.is_relative_to(ROOT) else g for g in guards]
    proc = sb.run(DISPATCHER, *map(str, local), stdin=_payload(command), CLAUDE_CODE_REMOTE="true")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    out: dict[str, Any] = json.loads(proc.stdout)
    return out


def test_the_dispatcher_passes_a_context_only_answer_through(sb: Sandbox) -> None:
    out = _dispatch(sb, [HOOK], "git reset --hard")
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "AFK TRIPWIRE" in out["hookSpecificOutput"]["additionalContext"]


def test_the_dispatcher_joins_the_context_onto_a_kept_decision(sb: Sandbox, tmp_path: Path) -> None:
    out = _dispatch(sb, [_asker(tmp_path), HOOK], "git reset --hard")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "because"
    assert "AFK TRIPWIRE" in out["hookSpecificOutput"]["additionalContext"]


def test_a_failed_guard_is_named_in_the_context_it_would_hide_behind(
    sb: Sandbox, tmp_path: Path
) -> None:
    """Writing a context exits 0, so a guard that failed open on the same call must be said."""
    out = _dispatch(sb, [tmp_path / "missing-guard.ps1", HOOK], "git reset --hard")
    assert "FAILED OPEN" in out["hookSpecificOutput"]["additionalContext"]
