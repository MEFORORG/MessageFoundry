# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""mail.ps1 refuses a -To path inside a worktree that is not the worktree's root.

BACKLOG #7581 (Argon S33-75). ``-Send -To <path>`` hashes the path as given. A session's drain keys
its box on the cwd it runs in, normally its worktree root, and seat.ps1 publishes the root's key, so a
box keyed on a subdirectory is one no drain is likely to read -- and the sender was told ``Queued``.
The send is refused instead, naming the root. Each arm drives the real scripts against a throwaway
repo and its own fixture mail root, never a live queue.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from _session_mail_harness import (
    COORD,
    MAIL,
    TIMEOUT,
    injection,
    mail_root,
    repo,
    requires_pwsh_on_windows,
    run_drain,
)

__all__ = ["repo"]  # re-exported so pytest resolves the fixture in this module

pytestmark = requires_pwsh_on_windows


def _mail(cwd: Path, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(MAIL),
            "-MailRoot",
            str(root),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def _boxes(root: Path) -> list[str]:
    d = root / "box"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def _worktree_root(path: Path) -> str:
    """The decision mail.ps1 makes, read with the same function rather than with git."""
    lib = COORD.parent / "hooks" / "_hookinput.ps1"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
         f". '{lib}'; [string](Get-CcxWorktreeRoot '{path}')"],
        capture_output=True, text=True, timeout=TIMEOUT, check=True,
    )  # fmt: skip
    return proc.stdout.strip()


def test_a_send_to_a_path_below_the_worktree_root_is_refused_and_writes_nothing(
    repo: Path,
) -> None:
    sub = repo / "deep" / "er"
    sub.mkdir(parents=True)
    root = mail_root(repo)
    send = _mail(repo, root, "-Send", "-To", str(sub), "-Body", "sent to a subdirectory")
    assert send.returncode != 0, send.stdout
    assert "is not its root" in send.stderr, send.stderr
    assert str(repo) in send.stderr, "the refusal must name the root to send to instead"
    assert _boxes(root) == [], "a shadow box was minted for the subdirectory"
    # The control: the root itself sends, and the worktree's drain shows it.
    ok = _mail(repo, root, "-Send", "-To", str(repo), "-Body", "sent to the root")
    assert ok.returncode == 0, ok.stderr
    assert "    | sent to the root" in injection(run_drain(repo))


@pytest.mark.parametrize("spell", ["upper", "slash", "trailing", "dotdot"])
def test_every_spelling_of_the_worktree_root_addresses_one_box(repo: Path, spell: str) -> None:
    """A pin: these already shared a key through ConvertTo-BoxKeyPath and Resolve-Path. The new
    below-the-root refusal must not take any of them for a subdirectory."""
    (repo / "x").mkdir()
    spelled = {
        "upper": str(repo).upper(),
        "slash": str(repo).replace("\\", "/"),
        "trailing": str(repo) + "\\",
        "dotdot": str(repo / "x" / ".."),
    }[spell]
    root = mail_root(repo)
    plain = _mail(repo, root, "-Send", "-Json", "-To", str(repo), "-Body", "plain")
    send = _mail(repo, root, "-Send", "-Json", "-To", spelled, "-Body", "spelled")
    assert plain.returncode == 0, plain.stderr
    assert send.returncode == 0, send.stderr
    assert json.loads(send.stdout)[0]["Key"] == json.loads(plain.stdout)[0]["Key"]


def test_a_path_in_no_worktree_still_sends_for_an_anchored_session(
    repo: Path, tmp_path: Path
) -> None:
    """The must-not-trip arm. An -AnchorRepo drain keys its box on a cwd in no worktree, so that
    path stays addressable; the refusal is only for a path below a worktree root."""
    container = tmp_path / "container"
    container.mkdir()
    assert _worktree_root(container) == "", (
        f"{container} sits in a worktree; this arm proves nothing"
    )
    send = _mail(repo, mail_root(repo), "-Send", "-To", str(container), "-Body", "anchored")
    assert send.returncode == 0, send.stderr
