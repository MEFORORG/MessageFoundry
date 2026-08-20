# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""An invalid escape sequence is the quietest way to lose a whole test module.

It becomes a ``SyntaxError`` on a future Python, and a ``SyntaxError`` fails at COLLECTION -- so
the module does not report one failing test, it reports FEWER TESTS. BACKLOG #1271 found three
such lines in ``tests/test_remotefile_transport.py``; this pins the class rather than those
three lines, because a point fix for something invisible regresses invisibly.

The arms below are chosen to be the ones a careless implementation gets wrong, each measured on
that item rather than imagined:

  * a line carrying THREE invalid escapes must report THREE. The compiler warns once per LINE,
    so a gate that forwards the warning count invites a per-warning patch that leaves two
    behind and still dies on the upgrade.
  * a BYTES literal must be told to use ``rb"..."`` and a ``str`` ``r"..."``. They are not
    interchangeable, and a uniform patch is wrong in one direction.
  * a CRLF line continuation must NOT fire. A backslash before a carriage return is valid, and
    an early version of this scan reported 25 of them as defects across three files -- caught
    only because the compiler disagreed.

A gate that cannot be shown failing is indistinguishable from a gate that is not running, so
every positive arm here plants a real defect and reads the real exit code.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "quality" / "escape_sequence_check.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECK), *args],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(ROOT),
    )


def test_a_planted_invalid_escape_in_a_str_is_found_and_located(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_bytes(b'NAME = "..\\..\\etc\\passwd.hl7"\n')
    proc = run(str(sample))
    assert proc.returncode == 1, proc.stdout
    assert "sample.py:1:" in proc.stderr
    assert "str literal" in proc.stderr


def test_the_escape_COUNT_is_reported_not_the_warning_count(tmp_path: Path) -> None:
    """The lesson of #1271: one line, three escapes, and the compiler warns exactly once."""
    sample = tmp_path / "three.py"
    sample.write_bytes(b'NAME = "..\\..\\etc\\passwd.hl7"\n')  # \. \e \p on ONE line
    proc = run(str(sample))
    assert proc.returncode == 1
    assert "3 invalid escape(s)" in proc.stderr
    # and the summary must agree with the per-line report rather than counting lines
    assert "3 invalid escape(s) across 1 line(s)" in proc.stderr


def test_a_bytes_literal_is_told_to_use_rb_not_r(tmp_path: Path) -> None:
    """``r`` and ``rb`` are different fixes; recommending the wrong one does not compile the same."""
    sample = tmp_path / "bytesy.py"
    sample.write_bytes(b'BODY = b"MSH|^~\\&|A"\n')
    proc = run(str(sample))
    assert proc.returncode == 1
    assert "bytes literal" in proc.stderr
    assert "rb'...'" in proc.stderr


def test_a_crlf_line_continuation_does_not_fire(tmp_path: Path) -> None:
    """The measured false-positive class: a backslash before CR is a continuation, not a defect."""
    sample = tmp_path / "crlf.py"
    sample.write_bytes(b'TEXT = """\\\r\nfirst\r\nsecond\r\n"""\r\n')
    proc = run(str(sample))
    assert proc.returncode == 0, proc.stderr


def test_raw_literals_and_ordinary_text_pass(tmp_path: Path) -> None:
    """The negative control. A gate that fires on valid code gets switched off."""
    sample = tmp_path / "fine.py"
    sample.write_bytes(
        b'PATH = r"..\\..\\etc\\passwd.hl7"\n'
        b'BODY = rb"MSH|^~\\&|A"\n'
        b'ESCAPED = "a\\nb\\tc\\\\d\\x00e"\n'
        b'HL7 = "MSH|^~\\\\&|A"\n'
    )
    proc = run(str(sample))
    assert proc.returncode == 0, proc.stderr
    assert "clean" in proc.stdout


def test_list_reports_scope_and_exits_clean() -> None:
    """Scope must be auditable: a gate whose file set nobody can print is a gate nobody can check."""
    proc = run("--list")
    assert proc.returncode == 0, proc.stderr
    listed = [line for line in proc.stdout.splitlines() if line.strip()]
    assert listed, "the scope list is empty, which would make every other arm vacuous"
    assert all(p.endswith(".py") for p in listed)
    # A long-TRACKED file, deliberately: the scope comes from `git ls-files`, so naming this
    # test's own path would assert that the test has been committed rather than that the scope
    # is real -- and would fail for the author and pass for everyone after them.
    assert "tests/test_remotefile_transport.py" in listed


def test_the_tracked_tree_is_clean() -> None:
    """The actual #1271 regression guard, over the whole repository rather than the one file.

    Run with no arguments, which is the CI invocation: every tracked ``.py``. This is the arm
    that fails if the class comes back anywhere, including in a file that does not exist yet.
    """
    proc = run()
    assert proc.returncode == 0, proc.stderr
