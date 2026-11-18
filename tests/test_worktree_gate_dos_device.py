# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does the DOS-device spelling of a governed root compare equal to the root?

BACKLOG #5454. ``Get-ComparablePath`` in ``scripts/hooks/worktree_gate.ps1`` folded the extended-length
prefixes (backslash backslash question-mark backslash, and its UNC form) onto the plain drive-letter
spelling, but not the DOS-device prefixes (backslash backslash dot backslash, and its UNC form).
``GetFullPath`` returns a DOS-device path unchanged, so ``\\\\.\\C:\\<governed>`` matched no governed root
in any rule that compares through ``Get-ComparablePath``.

MEASURED 2026-11-18 on Windows: ``git -C '\\\\.\\D:\\<worktree>' rev-parse --git-common-dir`` exits 0 and
names the real common dir, so the spelling reaches the repository with no setup at all, the same as the
extended-length prefix the gate already folds.

The comparison helper is the one in ``tests/test_worktree_gate_path_aliases.py``, restated here so this
row's PR edits no shared test file; it runs the SHIPPED functions, never a copy of their logic.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_SOURCE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
B = chr(92)

# Same two gates, for the same reasons, as tests/test_worktree_gate_path_aliases.py: GetFullPath applies
# HOST path rules, so on POSIX every row here is a relative path and nothing would be folded.
pytestmark = [
    pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"),
    pytest.mark.skipif(
        os.name != "nt",
        reason="[System.IO.Path]::GetFullPath applies HOST path rules; DOS-device paths are Windows-only",
    ),
]


def _brace_block(src: str, name: str) -> str:
    start = src.index("function " + name)
    depth = 0
    i = src.index("{", start)
    while True:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1


def comparable(paths: list[str]) -> list[str]:
    """Run the SHIPPED ``Get-ComparablePath`` (and the host list it reads) over each path."""
    src = GATE_SOURCE.read_text(encoding="utf-8")
    marker = "$script:LocalHostSpellings"
    var_start = src.index(marker)
    var = src[var_start : src.index("function Get-ComparablePath", var_start)]
    block = var + "\n".join(_brace_block(src, n) for n in ("Get-FullPathRaw", "Get-ComparablePath"))
    body = "\n".join(f"Get-ComparablePath '{p}'" for p in paths)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", block + "\n" + body],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip().splitlines()


def test_the_dos_device_spellings_of_a_local_path_compare_equal() -> None:
    """The defect: each of these names the same local file as ``C:\\Repo``."""
    got = comparable(
        [
            B + B + "." + B + "C:" + B + "Repo",
            "//./C:/Repo",
            B + B + "." + B + "UNC" + B + "localhost" + B + "C$" + B + "Repo",
            B + B + "." + B + "C:" + B + "Other" + B + ".." + B + "Repo",
        ]
    )
    assert got == ["c:/repo"] * 4, got


def test_a_dos_device_path_to_a_REMOTE_admin_share_is_NOT_folded_onto_the_local_drive() -> None:
    """Control: a share on another box is another machine's drive, so it must not fold onto ``c:``.

    Passes on the gate with and without the fold, so a failure here is the fold over-reaching.
    """
    (got,) = comparable([B + B + "." + B + "UNC" + B + "otherbox" + B + "C$" + B + "Repo"])
    assert not got.startswith("c:"), got


def test_a_dos_device_path_to_a_non_drive_device_stays_distinct() -> None:
    """Control: a device that is not a drive letter must not fold onto a drive path."""
    (got,) = comparable([B + B + "." + B + "PhysicalDrive0"])
    assert not got.startswith("c:"), got
