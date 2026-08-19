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


def test_this_repository_passes_the_gate_outright() -> None:
    """The live check, and now a PASS rather than a filtered one.

    This test used to run the scan and then discard `ide/src/` hits from the OUTPUT, which meant the
    gate exited 1 on `main` while this test went green -- so no CI step could be added, and the hook
    blocked every commit touching those two files over content already there. The allowance belongs
    in the script, where both callers read it; the test's job is to assert the repository is clean by
    the gate's own verdict, not by a second opinion the gate does not share.
    """
    proc = run()
    assert proc.returncode == 0, proc.stderr
    # The exception is DECLARED in the output, not merely applied -- this is what would fail if
    # someone widened NUL_IS_CONTENT_UNDER into a blanket directory skip.
    assert "deliberate NUL(s) allowed under ide/src/" in proc.stdout


def test_a_nul_under_the_allowed_prefix_is_permitted_and_counted(tmp_path: Path) -> None:
    d = tmp_path / "ide" / "src"
    d.mkdir(parents=True)
    f = d / "keys.ts"
    f.write_bytes(b'const k = "a\x00b";\n')
    proc = run(str(f))
    assert proc.returncode == 0, proc.stderr
    assert "1 deliberate NUL(s) allowed" in proc.stdout


def test_the_allowance_is_per_byte_not_per_directory(tmp_path: Path) -> None:
    """A collapsed word-boundary escape under ide/src/ is STILL refused.

    TypeScript is the likeliest place for this defect -- the escape and the byte are equally valid in
    a string literal -- so a blanket directory skip would have blinded the gate exactly where it is
    most needed. This is the test that keeps the allowance narrow.
    """
    d = tmp_path / "ide" / "src"
    d.mkdir(parents=True)
    f = d / "pattern.ts"
    f.write_bytes(b'const p = "\x08[0-9]";\n')
    proc = run(str(f))
    assert proc.returncode == 1, proc.stdout
    assert "BACKSPACE" in proc.stderr


def test_the_prefix_match_is_boundary_aware(tmp_path: Path) -> None:
    """`vendor/not-ide/src/` is not `ide/src/`, and a bare substring test would have said it was."""
    d = tmp_path / "vendor" / "not-ide" / "src"
    d.mkdir(parents=True)
    f = d / "x.ts"
    f.write_bytes(b'const q = "a\x00b";\n')
    proc = run(str(f))
    assert proc.returncode == 1, proc.stdout
    assert "NUL" in proc.stderr
