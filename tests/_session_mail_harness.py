# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared fixture and helpers for the session-mail suite (``test_session_mail*.py``).

Extracted so the suite can live in more than one FILE. Under ``pytest -n N --dist loadfile`` a file
is pinned to one worker, so the whole run cannot finish faster than its largest file -- and this
suite was the second-largest in the repo at 204.8s. The tests are subprocess-bound (each drives the
real pwsh scripts against a throwaway repo), so the cost is the work itself and there is nothing to
memoise; the only lever is letting the halves run on different workers.

Nothing here is a test. The split is along the suite's own section-8 banner, so each half is a
contiguous slice of what was one file:

* ``test_session_mail.py``      -- delivery, exclusion under contention, path and injection safety,
  the caps, the silence-and-failure modes, and the ASCII guard.
* ``test_session_mail_held.py`` -- section 8, "showing is not consuming": the phantom SessionStart,
  the marker lifecycle, and what the operator is told about held mail.

``requires_pwsh_on_windows`` is published rather than applied: ``pytestmark`` is inert in a module
pytest does not collect, so each test module applies it and there is still only one definition of
the condition.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
HOOKS = ROOT / "scripts" / "hooks"
DRAIN = HOOKS / "mail-drain.ps1"
MAIL = COORD / "mail.ps1"
MAIL_KEY = COORD / "mail-key.ps1"
MAIL_CLAIM = COORD / "mail-claim.ps1"

# Below pyproject.toml's --timeout=60 (and CI's 120) so a hung script fails THIS test by name via
# TimeoutExpired instead of taking the leg down through --timeout-method=thread with no attribution.
TIMEOUT = 45

# Both clauses, not just pwsh. The mail path resolves <git-common-dir> and normalises Windows-cased
# paths (mail-key.ps1 lowercases and rewrites '/' to '\'), so a Linux leg would exercise something
# other than what ships.
requires_pwsh_on_windows = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the session-mail scripts need pwsh on Windows",
)

SELF_ID = "11111111-2222-3333-4444-555555555555"

# Leak-gate safe: no real worktree slug (no trailing 6-hex token on a branch) and no home path.
# scripts/security/scan_forbidden.py's _WORKTREE_SLUG and _HOME_PATH detectors are STRUCTURAL and fire
# with no token secret loaded, so a real path in a fixture would red the required forbidden-content
# context.
PEER_CWD = "D:\\t\\peer-wt"
PEER_BRANCH = "claude/other-work"


def _const(name: str) -> int:
    """Read a cap out of the drain rather than restating it.

    The drain's constants are THE control (mail.ps1's copies are advisory). A hardcoded number here
    would be a third copy, and the copy that drifts is the one nobody is testing.
    """
    m = re.search(rf"^\${name}\s*=\s*(\d+)", DRAIN.read_text(encoding="ascii"), re.M)
    assert m, f"${name} not found in {DRAIN}"
    return int(m.group(1))


MAX_MESSAGES = _const("MAX_MESSAGES")
MAX_BODY_BYTES = _const("MAX_BODY_BYTES")
MAX_TOTAL_BYTES = _const("MAX_TOTAL_BYTES")
# The per-message hook-authored frame, charged by the selection pass alongside the body. Read from the
# script rather than hard-coded here for the same reason as the others: a test carrying its own copy of
# a constant stops testing the shipped value the moment somebody tunes it.
FRAME_OVERHEAD_BYTES = _const("FRAME_OVERHEAD_BYTES")
MAX_LINE_CHARS = _const("MAX_LINE_CHARS")
# Held messages consumed per drain. It bounds WORK, not delivery: the remainder keeps its marker and is
# consumed at the next turn boundary, exactly as a message over MAX_MESSAGES is shown at the next drain.


# --------------------------------------------------------------------------------------------------
# Fixture repo and helpers.
# --------------------------------------------------------------------------------------------------


def _git_init(repo: Path) -> None:
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    (repo / "f.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "f.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "init"], check=True, capture_output=True
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout. A real commit, not a bare ``init``: an empty repo has no HEAD."""
    r = tmp_path / "repo"
    r.mkdir()
    _git_init(r)
    return r


def mail_root(repo: Path) -> Path:
    """Mirror of what the drain computes at mail-drain.ps1:275-277. Never a parameter -- the drain
    takes no root override, so a test that got this wrong would silently test nothing."""
    return repo / ".git" / "mefor-coord" / "mail"


SEEDER = r"""
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Cwd,
    [Parameter(Mandatory)][string]$KeyLib,
    [Parameter(Mandatory)][string]$ClaimLib
)
$ErrorActionPreference = 'Stop'
. $KeyLib
. $ClaimLib
$specs = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$key = ConvertTo-BoxKey -Path $Cwd
$inbox = Join-Path $Root "box/$key/inbox"
[System.IO.Directory]::CreateDirectory($inbox) | Out-Null
$rows = @()
foreach ($s in $specs) {
    $stem = if ($s.stem) { [string]$s.stem } else { New-MessageId }
    $tok = if ($s.token) { [string]$s.token } else { New-ClaimToken }
    $name = if ($s.name) { [string]$s.name } else { "$stem--$tok.json" }
    if ($null -ne $s.raw) {
        $text = [string]$s.raw
    }
    else {
        $now = [DateTime]::UtcNow
        $o = [ordered]@{
            v          = 1
            id         = if ($null -ne $s.jsonId) { [string]$s.jsonId } else { $stem }
            kind       = if ($s.kind) { [string]$s.kind } else { 'note' }
            createdUtc = $now.ToString('o')
            expiresUtc = if ($s.expiresUtc) { [string]$s.expiresUtc } else { $now.AddMinutes(720).ToString('o') }
            from       = [ordered]@{
                sessionId = '00000000-0000-0000-0000-000000000000'
                cwd       = if ($null -ne $s.fromCwd) { [string]$s.fromCwd } else { 'D:\t\peer-wt' }
                branch    = if ($null -ne $s.fromBranch) { [string]$s.fromBranch } else { 'claude/other-work' }
                host      = 'TESTBOX'
            }
            to         = [ordered]@{ cwd = $Cwd; sessionId = [string]$s.toSessionId }
            body       = [string]$s.body
        }
        $text = $o | ConvertTo-Json -Depth 8
    }
    # UTF-8 without a BOM, NOT -Encoding ascii: a hostile-unicode fixture has to survive the write so
    # the drain's own scrub is what the test is measuring.
    [System.IO.File]::WriteAllText((Join-Path $inbox $name), $text, (New-Object System.Text.UTF8Encoding($false)))
    $rows += [pscustomobject]@{ name = $name; stem = $stem; token = $tok }
}
([pscustomobject]@{ key = $key; inbox = $inbox; rows = @($rows) } | ConvertTo-Json -Depth 6) | Write-Output
"""


def _seeder(tmp_path: Path) -> Path:
    p = tmp_path / "seed.ps1"
    if not p.exists():
        p.write_text(SEEDER, encoding="ascii")
    return p


def seed(repo: Path, tmp_path: Path, specs: list[dict[str, Any]]) -> dict[str, Any]:
    """Write messages straight into the inbox, the way anything running as this user can.

    Deliberately NOT via ``mail.ps1 -Send`` for most tests: the send-side body cap is advisory and is
    bypassed by exactly this route, so the caps arm has to use it. It mints ids and claim tokens by
    dot-sourcing the REAL mail-key.ps1 / mail-claim.ps1 -- a second copy of either shape in the test
    would be the drift this channel's single-definition rule exists to prevent.
    """
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_seeder(tmp_path)),
            "-Root",
            str(mail_root(repo)),
            "-Cwd",
            str(repo),
            "-KeyLib",
            str(MAIL_KEY),
            "-ClaimLib",
            str(MAIL_CLAIM),
        ],
        input=json.dumps(specs),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"seeder failed: {proc.stderr}"
    return dict(json.loads(proc.stdout))


def run_drain(
    repo: Path,
    *,
    event: str = "Stop",
    session_id: str | None = SELF_ID,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Drive the hook exactly as Claude Code does.

    The payload MUST carry ``cwd``: mail-drain.ps1:272 falls back to ``(Get-Location).Path``, so a
    payload without it would point the drain at the LIVE checkout's mail root, which is both a false
    test result and a mutation of state sibling sessions depend on.

    THE DEFAULT EVENT IS ``Stop`` BECAUSE ``Stop`` IS WHAT IS WIRED, and because it is the only event
    that CONSUMES. Section 8 records why showing and consuming are separate; the consequence here is
    that ``SessionStart`` no longer moves anything, so a test that asserts a message reached ``seen/``
    has to name the event that puts it there. Defaulting to the non-consuming event would leave every
    delivery assertion in this module silently testing the unwired half.
    """
    payload: dict[str, Any] = {"hook_event_name": event, "cwd": str(cwd or repo)}
    if session_id is not None:
        payload["session_id"] = session_id
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(DRAIN)],
        cwd=str(cwd or repo),
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    # FAIL OPEN, asserted in the helper and not per-test. A Stop hook that fails can end a turn badly
    # and a SessionStart hook that fails replaces the whole starting context; asserting it per-test
    # would leave every path nobody wrote a test for unchecked.
    assert proc.returncode == 0, f"drain exited {proc.returncode}: {proc.stderr}"
    assert not proc.stderr.strip(), f"drain wrote to stderr: {proc.stderr}"
    return proc


def injection(proc: subprocess.CompletedProcess[str]) -> str:
    """The additionalContext the hook emitted, or '' when it emitted nothing at all."""
    out = proc.stdout.strip()
    if not out:
        return ""
    obj = json.loads(out)
    return str(obj["hookSpecificOutput"]["additionalContext"])


def frames(text: str) -> list[tuple[str, list[str]]]:
    """(id, lines) for each message frame, split on the delimiters the HOOK writes at column 0."""
    out: list[tuple[str, list[str]]] = []
    cur_id: str | None = None
    cur: list[str] = []
    for ln in text.splitlines():
        if ln.startswith("--- message id="):
            cur_id = ln.removeprefix("--- message id=").split()[0]
            cur = []
        elif ln.startswith("--- end message id="):
            if cur_id is not None:
                out.append((cur_id, cur))
            cur_id = None
        elif cur_id is not None:
            cur.append(ln)
    return out


def delimiter_lines(text: str, delim: str) -> int:
    """Lines that BEGIN with ``delim`` at column 0 -- i.e. lines the hook itself wrote.

    A substring count is the wrong instrument for a frame-forgery test: a hostile body quoting the
    delimiter is exactly the input, and the containment rule promises the quote lands at column 6
    behind ``    | ``, not that the bytes never appear.
    """
    return sum(1 for ln in text.splitlines() if ln.startswith(delim))


def body_lines(frame: list[str]) -> list[str]:
    """Frame lines that carry message content, prefix stripped, hook-written markers dropped."""
    out: list[str] = []
    for ln in frame:
        if not (ln.startswith("    | ") or ln == "    |"):
            continue
        stripped = ln.removeprefix("    | ") if ln.startswith("    | ") else ""
        if stripped.startswith(("[mefor-mail:", " The whole message is on disk")):
            break
        out.append(stripped)
    return out


_SHELL_STARTS = (
    "pwsh",
    "powershell",
    "cmd ",
    "cmd.exe",
    "git ",
    "bash ",
    "sh ",
    "iex",
    "invoke-expression",
    "& ",
    '&"',
    "start-process",
)


def runnable_command_lines(text: str) -> list[str]:
    """Lines a reader could paste into a shell and have run.

    Deliberately anchored on the line's FIRST token rather than on a substring: a hostile from.cwd or
    a hostile body can put the word ``pwsh`` into the injection, and it is contained there by the
    ``claimed-from:`` label or the ``    | `` prefix. Substring absence would be a control that a
    hostile fixture can turn red without anything being wrong.
    """
    out: list[str] = []
    for ln in text.splitlines():
        low = ln.strip().lower()
        if low.startswith(_SHELL_STARTS) or (
            "mail.ps1" in low and (" -send" in low or " -body" in low)
        ):
            out.append(ln)
    return out


def receipts(repo: Path) -> list[str]:
    d = mail_root(repo) / "receipts"
    return sorted(p.name for p in d.glob("*.json")) if d.is_dir() else []


def box_files(repo: Path, key: str, sub: str) -> list[str]:
    d = mail_root(repo) / "box" / key / sub
    return sorted(p.name for p in d.glob("*.json")) if d.is_dir() else []


def tree(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}
