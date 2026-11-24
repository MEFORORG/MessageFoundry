# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""mail.ps1 addresses a box by the worktree TOPLEVEL, the way the drain and seat.ps1 key it.

BACKLOG #7581 (Argon S33-75). A box is keyed on the recipient's worktree root: seat.ps1 publishes the
key of ``git rev-parse --show-toplevel``, and a session's drain reads the box of the worktree it runs
in. ``-Send -To <path>`` used to hash the resolved path as given, so a path INSIDE a worktree minted
a box beside the real one that nobody drains, and the sender was told ``Queued``. ``-Status`` run
from a subdirectory reported that same shadow box. Each arm below drives the real scripts against a
throwaway repo and the repo's own fixture mail root, never a live queue.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from _session_mail_harness import (
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


def _status(cwd: Path, root: Path) -> Any:
    proc = _mail(cwd, root, "-Status", "-Json")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _boxes(root: Path) -> list[str]:
    d = root / "box"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def test_a_send_to_a_path_inside_the_worktree_reaches_the_worktrees_drain(repo: Path) -> None:
    sub = repo / "deep" / "er"
    sub.mkdir(parents=True)
    root = mail_root(repo)
    send = _mail(repo, root, "-Send", "-Json", "-To", str(sub), "-Body", "sent to a subdirectory")
    assert send.returncode == 0, send.stderr
    rows = json.loads(send.stdout)
    assert rows[0]["Key"] == _status(repo, root)["Key"], rows
    # The box the drain reads, and the only box: no shadow box was minted for the subdirectory.
    assert _boxes(root) == [rows[0]["Key"]]
    assert "    | sent to a subdirectory" in injection(run_drain(repo))


@pytest.mark.parametrize("spell", ["upper", "slash", "trailing", "dotdot"])
def test_every_spelling_of_the_worktree_addresses_one_box(repo: Path, spell: str) -> None:
    (repo / "x").mkdir()
    spelled = {
        "upper": str(repo).upper(),
        "slash": str(repo).replace("\\", "/"),
        "trailing": str(repo) + "\\",
        "dotdot": str(repo / "x" / ".."),
    }[spell]
    root = mail_root(repo)
    send = _mail(repo, root, "-Send", "-Json", "-To", spelled, "-Body", "spelled")
    assert send.returncode == 0, send.stderr
    assert json.loads(send.stdout)[0]["Key"] == _status(repo, root)["Key"]


def test_a_send_to_a_directory_in_no_worktree_is_refused_and_writes_nothing(
    repo: Path, tmp_path: Path
) -> None:
    loose = tmp_path / "not-a-checkout"
    loose.mkdir()
    probe = subprocess.run(
        ["git", "-C", str(loose), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode != 0, f"{loose} is inside a checkout, so this arm proves nothing"
    root = mail_root(repo)
    send = _mail(repo, root, "-Send", "-To", str(loose), "-Body", "into the void")
    assert send.returncode != 0, send.stdout
    assert "in no git worktree" in send.stderr, send.stderr
    assert _boxes(root) == []
    # The control: the same call to the worktree itself sends, so the refusal is not a broken send.
    ok = _mail(repo, root, "-Send", "-To", str(repo), "-Body", "into the box")
    assert ok.returncode == 0, ok.stderr


def test_status_from_a_subdirectory_reports_the_worktrees_own_box(repo: Path) -> None:
    sub = repo / "nested"
    sub.mkdir()
    root = mail_root(repo)
    at_top = _status(repo, root)
    below = _status(sub, root)
    assert below["Key"] == at_top["Key"], (below, at_top)
    assert Path(below["Worktree"]) == Path(at_top["Worktree"])
