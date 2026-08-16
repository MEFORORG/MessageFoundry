# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A control byte is invisible in every view a human uses, so a gate is the only way to see it.

An escape written into a string can collapse into the byte it names: a backslash-b becomes 0x08, a
backslash-a becomes 0x07. The file then reads correctly in an editor, in ``git diff`` and in review,
while the program sees something the author never wrote.

Measured three times in this repository inside one week:

  * ``scripts/security/scan_forbidden.py:662`` on ``main`` -- a comment about word boundaries whose
    word boundary had become a backspace. Harmless where it sat, in a comment, and it would have
    been inherited by the next person to copy that reasoning into a pattern.
  * a regex in ``scripts/coord/claim-reconcile.ps1`` while it was being written, where the byte sat
    INSIDE the pattern and it matched nothing at all, silently.
  * the pre-commit comment introduced alongside this very check, which arrived carrying three of
    them. The gate caught its own commit.

The tests below pin the two halves that matter: it must find a planted byte, and it must not fire on
ordinary text. A gate that cannot be shown failing is indistinguishable from a gate that is not
running -- and this one had a real repository hit on the day it was written rather than a synthetic
one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "quality" / "control_char_check.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECK), *args], capture_output=True, text=True, timeout=45
    )


def test_a_planted_backspace_is_found_and_named(tmp_path: Path) -> None:
    """The 0x08 case specifically, because it is the one a word-boundary escape collapses into."""
    f = tmp_path / "sample.py"
    f.write_bytes(b'PATTERN = "\x08[0-9a-f]{7,40}"\n')
    proc = run(str(f))
    assert proc.returncode == 1
    assert "BACKSPACE" in proc.stderr
    assert "sample.py:1:" in proc.stderr


def test_ordinary_text_passes_and_the_count_is_reported(tmp_path: Path) -> None:
    """The negative control, and coverage on the clean path: 'no violations' over an unstated scope
    is the silence this check exists to remove."""
    f = tmp_path / "fine.py"
    f.write_text('X = "plain"\n\tindented = 1\r\n', encoding="utf-8")
    proc = run(str(f))
    assert proc.returncode == 0, proc.stderr
    assert "1 file(s) checked" in proc.stdout


def test_tab_lf_and_cr_are_allowed(tmp_path: Path) -> None:
    f = tmp_path / "ws.md"
    f.write_bytes(b"a\tb\r\nc\n")
    assert run(str(f)).returncode == 0


def test_nul_bell_and_escape_are_all_refused(tmp_path: Path) -> None:
    for byte, name in ((b"\x00", "NUL"), (b"\x07", "BEL"), (b"\x1b", "ESC"), (b"\x7f", "DEL")):
        f = tmp_path / f"b{byte.hex()}.py"
        f.write_bytes(b"x = 1" + byte + b"\n")
        proc = run(str(f))
        assert proc.returncode == 1, f"{name} was not refused"
        assert name in proc.stderr


def test_out_of_scope_files_are_ignored(tmp_path: Path) -> None:
    """A control byte in a binary blob is content, not a mistake."""
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00\x01\x02")
    assert run(str(f)).returncode == 0


def test_the_line_and_column_locate_the_byte(tmp_path: Path) -> None:
    f = tmp_path / "where.py"
    f.write_bytes(b"first\nsecond\nthi\x08rd\n")
    proc = run(str(f))
    assert "where.py:3:4:" in proc.stderr, proc.stderr


def test_list_reports_scope_and_exits_zero() -> None:
    """Scope is auditable on demand, the same contract licence_header_check.py offers."""
    proc = run("--list")
    assert proc.returncode == 0
    # A file that is already TRACKED. Asserting on this check's own path fails before its first
    # commit, because --list reads git ls-files -- a test that only passes after `git add` is a test
    # that pins the wrong thing.
    assert "scripts/quality/licence_header_check.py" in proc.stdout
    assert "README.md" in proc.stdout


def test_this_repository_has_no_control_bytes_outside_the_ide_extension() -> None:
    """The live check. `ide/src/*.ts` carries DELIBERATE raw NUL key separators, which are their
    owner's call to convert; everything else must stay clean, and did not before today."""
    proc = run()
    offending = {
        line.split(":")[1].strip()
        for line in proc.stderr.splitlines()
        if line.startswith("control-char: ") and ":" in line[14:]
    }
    unexpected = {p for p in offending if not p.startswith("ide/src/")}
    assert not unexpected, f"control bytes outside ide/src/: {sorted(unexpected)}"
