# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every spelling of one worktree path addresses one mail box.

BACKLOG #7581 (Argon S33-75) claims a different spelling of a worktree path addresses a box nobody
drains. Measured: case, slash direction, a trailing separator and a ``..`` segment already share one
key, through ConvertTo-BoxKeyPath and Resolve-Path, and these arms pin that. The subdirectory half of
the finding is real, but it is a split between the keyers (the drain keys on the session cwd, seat.ps1
on the toplevel), and a sender-only change was measured to make it worse, so it is not changed here.
Each arm drives the real mail.ps1 against a throwaway repo and its own fixture mail root.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from _session_mail_harness import MAIL, TIMEOUT, mail_root, repo, requires_pwsh_on_windows

__all__ = ["repo"]  # re-exported so pytest resolves the fixture in this module

pytestmark = requires_pwsh_on_windows


def _send_key(repo: Path, to: str) -> str:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(MAIL),
         "-MailRoot", str(mail_root(repo)), "-Send", "-Json", "-To", to, "-Body", "spelled"],
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
