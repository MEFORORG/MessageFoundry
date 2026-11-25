# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every path inside one worktree addresses one mail box.

BACKLOG #7581 (Argon S33-75) claims a different spelling of a worktree path addresses a box nobody
drains. Case, slash direction, a trailing separator and a ``..`` segment already shared one key,
through ConvertTo-BoxKeyPath and Resolve-Path, and the first arms pin that.

The subdirectory half was real: the drain and the watcher keyed on the session's cwd, seat.ps1 on the
toplevel, and the sender on whatever path it was given. Resolve-BoxPath in mail-key.ps1 is now the one
keyer all four call, and the later arms pin that a root and a subdirectory reach each other, that mail
queued under a subdirectory's old key is still read, and three edge cases: a path in no checkout, a
removed worktree's leftover directory under the primary, and the primary itself.

Each arm drives the real scripts against a throwaway repo and its own fixture mail root.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from _session_mail_harness import (
    COORD,
    HOOKS,
    MAIL,
    MAIL_KEY,
    TIMEOUT,
    box_files,
    injection,
    mail_root,
    repo,
    requires_pwsh_on_windows,
    run_drain,
)

__all__ = ["repo"]  # re-exported so pytest resolves the fixture in this module

pytestmark = requires_pwsh_on_windows

SESSION = "11111111-2222-3333-4444-555555555555"


def _send_key(repo: Path, to: str, body: str = "spelled") -> str:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(MAIL),
         "-MailRoot", str(mail_root(repo)), "-Send", "-Json", "-To", to, "-Body", body],
        cwd=str(repo), capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    return str(json.loads(proc.stdout)[0]["Key"])


@pytest.mark.parametrize("spell", ["upper", "slash", "trailing", "dotdot"])
def test_every_spelling_of_the_worktree_root_addresses_one_box(repo: Path, spell: str) -> None:
    (repo / "x").mkdir()
    spelled = {
        "upper": str(repo).upper(),
        "slash": str(repo).replace("\\", "/"),
        "trailing": str(repo) + "\\",
        "dotdot": str(repo / "x" / ".."),
    }[spell]
    assert _send_key(repo, spelled) == _send_key(repo, str(repo))


# ------------------------------------------------------------------------------ subdirectories


def _ps_expr(expr: str, path: Path | str) -> str:
    """Evaluate ``expr`` against the real mail-key.ps1, with $env:BK_PATH set to ``path``."""
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", f". '{MAIL_KEY}'; {expr}"],
        capture_output=True, text=True, timeout=TIMEOUT, check=True,
        env=dict(os.environ, BK_PATH=str(path)),
    )  # fmt: skip
    return proc.stdout.strip()


def _resolve(path: Path | str) -> str:
    return _ps_expr("Resolve-BoxPath -Path $env:BK_PATH", path)


def _key(path: Path | str) -> str:
    return _ps_expr("ConvertTo-BoxKey -Path $env:BK_PATH", path)


def _same(a: Path | str, b: Path | str) -> bool:
    return str(a).rstrip("\\/").lower() == str(b).rstrip("\\/").lower()


def _sub(repo: Path) -> Path:
    sub = repo / "pkg" / "inner"
    sub.mkdir(parents=True)
    return sub


def test_a_root_send_is_read_by_a_subdirectory_session(repo: Path) -> None:
    sub = _sub(repo)
    _send_key(repo, str(repo), body="to the published root")
    assert "to the published root" in injection(run_drain(repo, event="SessionStart", cwd=sub))


def test_a_subdirectory_send_is_read_by_a_root_session(repo: Path) -> None:
    sub = _sub(repo)
    assert _send_key(repo, str(sub), body="to a subdirectory") == _key(repo)
    assert "to a subdirectory" in injection(run_drain(repo, event="SessionStart"))


def test_the_seat_record_names_the_box_a_subdirectory_send_addresses(repo: Path) -> None:
    sub = _sub(repo)
    env = dict(os.environ, CLAUDE_CODE_SESSION_ID="sess-a")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(COORD / "seat.ps1"),
         "-Declare", "-Seat", "builder", "-Done", "d"],
        cwd=str(sub), capture_output=True, text=True, timeout=TIMEOUT, check=False, env=env,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    seats = repo / ".git" / "mefor-coord" / "seats"
    boxes = sorted(p.parent.name for p in seats.glob("*/sess-a.json"))
    assert boxes == [_send_key(repo, str(sub))]


def _queue_under_the_subdirectory_key(repo: Path, sub: Path, body: str) -> Path:
    """Mail as a sender older than the keyer queued it: in the subdirectory's own box."""
    _send_key(repo, str(repo), body=body)
    box = mail_root(repo) / "box"
    old_inbox = box / _key(sub) / "inbox"
    old_inbox.mkdir(parents=True)
    for f in (box / _key(repo) / "inbox").glob("*.json"):
        f.rename(old_inbox / f.name)
    assert len(list(old_inbox.glob("*.json"))) == 1
    return old_inbox


def test_mail_queued_under_a_subdirectory_key_is_still_read(repo: Path) -> None:
    sub = _sub(repo)
    old_inbox = _queue_under_the_subdirectory_key(repo, sub, "queued before the keyer")
    assert "queued before the keyer" in injection(run_drain(repo, event="SessionStart", cwd=sub))
    assert not list(old_inbox.glob("*.json")), "moved into the worktree's box"
    assert box_files(repo, _key(repo), "inbox")


def test_status_still_counts_a_claim_left_under_a_subdirectory_key(repo: Path) -> None:
    sub = _sub(repo)
    old_inbox = _queue_under_the_subdirectory_key(repo, sub, "claimed before the keyer")
    claiming = old_inbox.parent / "claiming"
    claiming.mkdir()
    for f in old_inbox.glob("*.json"):
        f.rename(claiming / f.name)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(MAIL),
         "-MailRoot", str(mail_root(repo)), "-Status", "-Json"],
        cwd=str(sub), capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    status = json.loads(proc.stdout)
    assert status["Key"] == _key(repo)
    assert status["LegacyClaiming"] == 1


def test_the_watcher_wakes_on_mail_under_a_subdirectory_key(repo: Path) -> None:
    sub = _sub(repo)
    _queue_under_the_subdirectory_key(repo, sub, "wake me")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOKS / "mail-watch.ps1"),
         "-MaxWaitSeconds", "15", "-PollSeconds", "1"],
        cwd=str(sub), input=json.dumps({"cwd": str(sub), "session_id": SESSION}),
        capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )  # fmt: skip
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "wake me" in proc.stderr


# ------------------------------------------------------------------------------ edge cases


def test_the_primary_checkout_keys_on_itself_and_raises_its_subdirectory(repo: Path) -> None:
    assert _resolve(repo) == str(repo), "a root is returned unchanged, so its key never moved"
    assert _same(_resolve(_sub(repo)), repo)


def test_an_untracked_subdirectory_is_raised_under_a_crlf_gitignore(repo: Path) -> None:
    # A CRLF blank line is a lone `\r` pattern, which check-ignore matched against a trailing-slash
    # probe of any untracked directory (measured in a Windows checkout with core.autocrlf).
    (repo / ".gitignore").write_bytes(b"/.claude/worktrees/\r\n\r\n*.log\r\n")
    sub = _sub(repo)
    assert not list(sub.iterdir()), "no tracked file under it"
    assert _same(_resolve(sub), repo)
    assert not _same(_resolve(repo / ".claude" / "worktrees" / "gone"), repo)


def test_a_path_in_no_checkout_is_keyed_as_given(tmp_path: Path) -> None:
    outside = tmp_path / "loose" / "dir"
    outside.mkdir(parents=True)
    assert _resolve(outside) == str(outside)


def test_a_removed_worktrees_leftover_does_not_resolve_to_the_primary(repo: Path) -> None:
    (repo / ".gitignore").write_text("/.claude/worktrees/\n", encoding="utf-8")
    leftover = repo / ".claude" / "worktrees" / "gone"
    (leftover / "sub").mkdir(parents=True)
    # Control: an unignored folder beside it IS raised, so the walk does reach the primary.
    kept = repo / ".claude" / "kept"
    kept.mkdir()
    assert _same(_resolve(kept), repo)
    assert _resolve(leftover) == str(leftover)
    assert _resolve(leftover / "sub") == str(leftover / "sub")
    assert _send_key(repo, str(leftover)) != _key(repo)


def test_a_stale_dot_git_file_stops_the_walk(repo: Path, tmp_path: Path) -> None:
    stale = repo / "pruned-wt"
    (stale / "sub").mkdir(parents=True)
    (stale / ".git").write_text(f"gitdir: {tmp_path / 'no-such-gitdir'}\n", encoding="utf-8")
    assert _resolve(stale / "sub") == str(stale / "sub")
    # Control: with the stale file gone, the same folder is raised to the primary.
    (stale / ".git").unlink()
    assert _same(_resolve(stale / "sub"), repo)
