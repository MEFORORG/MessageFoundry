# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The commit-msg hook refuses the attribution trailers CLAUDE.md section 5 says to omit.

The rule lives in ``scripts/hooks/claim_check.py`` because that is the payload the existing
commit-msg shim execs; ``scripts/coord/install-git-hooks.ps1`` needs no new install path. Each case
runs the real script as a subprocess on a message file, the way git invokes it. The trailer rule
runs before any git read, so no repository is needed. Every silent case has a firing twin, because
a detector that cannot be shown firing proves nothing by staying quiet.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "claim_check.py"

# Built from parts so this file's own commit message, which may quote this module, never matters,
# and so a grep for the literal trailer in the tree finds the hook rather than its test.
_COAUTHOR = "Co-Authored-By" + ": Claude Opus <noreply@anthropic.com>"
_SESSION = "Claude-Session" + ": https://claude.ai/code/session_x"


def _run(tmp_path: Path, message: str) -> subprocess.CompletedProcess[str]:
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text(message, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(_CHECK), str(msg)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize(
    "trailer",
    [
        _COAUTHOR,
        _COAUTHOR.lower(),
        _COAUTHOR.upper(),
        _SESSION,
        "co-authored-by:Claude",
        "Co-Authored-By" + " : Claude <noreply@anthropic.com>",
        "Claude-Session" + " : x",
    ],
)
def test_the_trailer_is_refused_and_the_line_is_named(tmp_path: Path, trailer: str) -> None:
    proc = _run(tmp_path, f"docs: a plain subject\n\nSome body.\n\n{trailer}\n")
    assert proc.returncode == 1, proc.stderr
    assert "attribution-trailer check" in proc.stderr
    assert "line 5:" in proc.stderr
    assert "Delete those lines" in proc.stderr


def test_a_clean_message_passes(tmp_path: Path) -> None:
    """The negative control: an ordinary message, including another person's trailer."""
    proc = _run(
        tmp_path,
        "docs: a plain subject\n\nSome body.\n\nCo-Authored-By: A Person <a@example.invalid>\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


@pytest.mark.parametrize("quoted", [f"    {_COAUTHOR}", f"`{_COAUTHOR}`", f"> {_SESSION}"])
def test_a_quoted_trailer_in_the_body_passes(tmp_path: Path, quoted: str) -> None:
    proc = _run(tmp_path, f"docs: a plain subject\n\nThe hook refuses this:\n{quoted}\n")
    assert proc.returncode == 0, proc.stderr


def test_the_diff_below_the_scissors_line_is_not_message_text(tmp_path: Path) -> None:
    """`git commit -v` appends the diff below the scissors; a trailer there is content, not a trailer."""
    scissors = "# ------------------------ >8 ------------------------"
    proc = _run(tmp_path, f"docs: subject\n\nbody\n{scissors}\n{_COAUTHOR}\n")
    assert proc.returncode == 0, proc.stderr
    # Positive control: the same trailer above the scissors fires.
    proc = _run(tmp_path, f"docs: subject\n\n{_COAUTHOR}\n{scissors}\n")
    assert proc.returncode == 1


def test_the_trailer_rule_fires_before_the_citation_rule(tmp_path: Path) -> None:
    """It needs no git and no claim, so a message the claim gate would also refuse names it first."""
    subject = "fix: a thing (#1318, #1320)"
    # Control: this subject alone is refused by the citation rule, so the assertion below can fail.
    alone = _run(tmp_path, f"{subject}\n")
    assert alone.returncode == 1
    assert "claim gate" in alone.stderr.lower()
    proc = _run(tmp_path, f"{subject}\n\n{_SESSION}\n")
    assert proc.returncode == 1
    assert "attribution-trailer check" in proc.stderr
    assert "claim gate" not in proc.stderr.lower()
