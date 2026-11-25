# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The commit-msg hook reads an optional `Verified-by:` trailer, in OBSERVE MODE only.

A missing or unrecognised trailer prints one advisory line to stderr; a valid one prints nothing.
No case may refuse the commit. Each case runs the real hook as a subprocess on a message file, the
way git invokes it. These messages cite no ledger number, so the hook exits before any git read
and no repository is needed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "claim_check.py"


def _run(tmp_path: Path, message: str) -> subprocess.CompletedProcess[str]:
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_bytes(message.encode("utf-8"))
    return subprocess.run(
        [sys.executable, str(_CHECK), str(msg)],
        cwd=tmp_path,
        capture_output=True,
        encoding="utf-8",
        errors="backslashreplace",
        timeout=60,
    )


@pytest.mark.parametrize(
    "trailer",
    [
        "Verified-by: code-review xhigh",
        "Verified-by: verify",
        "Verified-by: tests",
        "Verified-by: none",
        "verified-by:   Code-Review   XHIGH",
        "Verified-by: tests\r",
    ],
)
def test_a_valid_trailer_is_silent(tmp_path: Path, trailer: str) -> None:
    proc = _run(tmp_path, f"docs: a plain subject\n\nSome body.\n\n{trailer}\n")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_an_absent_trailer_prints_one_advisory_line_and_passes(tmp_path: Path) -> None:
    proc = _run(tmp_path, "docs: a plain subject\n\nSome body.\n")
    assert proc.returncode == 0, proc.stderr
    lines = proc.stderr.splitlines()
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith("advisory: no 'Verified-by:' trailer")
    assert "not refused" in lines[0]


@pytest.mark.parametrize(
    "trailer",
    [
        "Verified-by: code-review high",
        "Verified-by: ",
        "Verified-by: looked at it",
        "Verified-by: tests and a review",
    ],
)
def test_a_malformed_trailer_prints_one_advisory_line_and_passes(
    tmp_path: Path, trailer: str
) -> None:
    proc = _run(tmp_path, f"docs: a plain subject\n\nSome body.\n\n{trailer}\n")
    assert proc.returncode == 0, proc.stderr
    lines = proc.stderr.splitlines()
    assert len(lines) == 1, proc.stderr
    assert "is not one of" in lines[0]
    assert "not refused" in lines[0]


def test_an_indented_or_quoted_trailer_does_not_count(tmp_path: Path) -> None:
    proc = _run(tmp_path, "docs: a plain subject\n\nQuote:\n    Verified-by: tests\n")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.startswith("advisory: no 'Verified-by:' trailer")


@pytest.mark.parametrize("trailer", ["", "\nVerified-by: tests\n"])
def test_the_advisory_never_masks_a_later_refusal(tmp_path: Path, trailer: str) -> None:
    """The bare-citation refusal runs AFTER the advisory, and still refuses, trailer or not.

    Its subject needs no git read, so no repository is needed for the real ordering.
    """
    proc = _run(tmp_path, f"fix: x (#1, #2)\n\nBody.\n{trailer}")
    assert proc.returncode == 1, proc.stderr
    assert ("advisory:" in proc.stderr) == (trailer == "")
