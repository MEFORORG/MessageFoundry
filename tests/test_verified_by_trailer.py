# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The commit-msg hook reads an optional `Verified-by:` trailer, in OBSERVE MODE only.

A missing, unrecognised or contradictory trailer prints one advisory line to stderr; a valid one
prints nothing, and a merge or a git-generated squash or revert message prints nothing either. No
case may refuse the commit. Each case runs the real hook as a subprocess on a message file, the way
git invokes it. These messages cite no ledger number, so the hook exits before any git read and no
repository is needed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "claim_check.py"
_NOT_REFUSED = "this advisory does not refuse the commit"


def _run(
    tmp_path: Path, message: str, state: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    # The message file's directory stands in for the per-worktree git dir, as it does under git.
    for name in state:
        (tmp_path / name).write_text("0" * 40 + "\n", encoding="utf-8")
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


def _one_advisory(proc: subprocess.CompletedProcess[str]) -> str:
    assert proc.returncode == 0, proc.stderr
    lines = proc.stderr.splitlines()
    assert len(lines) == 1, proc.stderr
    assert lines[0].startswith("advisory: ")
    assert lines[0].endswith(_NOT_REFUSED)
    return lines[0]


@pytest.mark.parametrize(
    "trailer",
    [
        "Verified-by: code-review low",
        "Verified-by: code-review medium",
        "Verified-by: code-review high",
        "Verified-by: code-review xhigh",
        "Verified-by: code-review max",
        "Verified-by: verify",
        "Verified-by: tests",
        "Verified-by: none",
        "verified-by:   Code-Review   XHIGH",
        "Verified-by: tests\r",
        "Verified-by: tests\nVerified-by: Tests",
        "Signed-off-by: A Person <a@example.invalid>\n  continued\nVerified-by: tests",
    ],
)
def test_a_valid_trailer_is_silent(tmp_path: Path, trailer: str) -> None:
    proc = _run(tmp_path, f"docs: a plain subject\n\nSome body.\n\n{trailer}\n")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_an_absent_trailer_prints_one_advisory_line_and_passes(tmp_path: Path) -> None:
    line = _one_advisory(_run(tmp_path, "docs: a plain subject\n\nSome body.\n"))
    assert line.startswith("advisory: no 'Verified-by:' trailer")


@pytest.mark.parametrize(
    "trailer",
    [
        "Verified-by: code-review",
        "Verified-by: code-review ultra",
        "Verified-by: ",
        "Verified-by: looked at it",
        "Verified-by: tests and a review",
    ],
)
def test_a_malformed_trailer_prints_one_advisory_line_and_passes(
    tmp_path: Path, trailer: str
) -> None:
    line = _one_advisory(_run(tmp_path, f"docs: a plain subject\n\nSome body.\n\n{trailer}\n"))
    assert "is not one of" in line


@pytest.mark.parametrize(
    "trailers",
    [
        "Verified-by: tests\nVerified-by: code-review xhigh",
        "Verified-by: tests\nVerified-by: looked at it",
    ],
)
def test_contradictory_trailers_print_one_advisory_line(tmp_path: Path, trailers: str) -> None:
    """Two values that differ say nothing about what ran, even when each is valid on its own."""
    line = _one_advisory(_run(tmp_path, f"docs: a plain subject\n\nSome body.\n\n{trailers}\n"))
    assert "disagree" in line


@pytest.mark.parametrize(
    "message",
    [
        # Indented: a quote, not a trailer.
        "docs: a plain subject\n\nQuote:\n    Verified-by: tests\n",
        # In the body, followed by another paragraph: not in the trailer block.
        "docs: a plain subject\n\nVerified-by: tests\n\nA closing paragraph of prose.\n",
        # In a last paragraph that is prose, so git reads no trailer block at all.
        "docs: a plain subject\n\nThe old form was\nVerified-by: tests\nand it moved.\n",
        # The subject paragraph is never a trailer block.
        "Verified-by: tests\n",
        # Below the scissors line `git commit -v` writes, which git drops.
        "docs: a plain subject\n\nBody.\n# ------------------------ >8 ------------------------\n"
        "\nVerified-by: tests\n",
    ],
)
def test_a_trailer_outside_the_trailer_block_does_not_count(tmp_path: Path, message: str) -> None:
    line = _one_advisory(_run(tmp_path, message))
    assert line.startswith("advisory: no 'Verified-by:' trailer")


@pytest.mark.parametrize(
    ("message", "state"),
    [
        ("Merge branch 'main' into topic\n", ()),
        ("Merge remote-tracking branch 'origin/main'\n", ()),
        ("Resolve the conflict by hand\n", ("MERGE_HEAD",)),
        ("Squashed commit of the following:\n\ncommit 0123456789abcdef\n", ()),
        ("Fold the topic in\n", ("SQUASH_MSG",)),
        ('Revert "docs: a plain subject"\n\nThis reverts commit 0123456789abcdef.\n', ()),
        ("Back the change out\n", ("REVERT_HEAD",)),
    ],
)
def test_a_merge_or_git_generated_message_is_skipped(
    tmp_path: Path, message: str, state: tuple[str, ...]
) -> None:
    proc = _run(tmp_path, message, state)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_a_merge_shaped_word_in_an_ordinary_subject_still_advises(tmp_path: Path) -> None:
    """Negative control for the skip: only git's own merge subjects are skipped."""
    line = _one_advisory(_run(tmp_path, "Merge the two readers into one helper\n\nBody.\n"))
    assert line.startswith("advisory: no 'Verified-by:' trailer")


@pytest.mark.parametrize("trailer", ["", "\nVerified-by: tests\n"])
def test_the_advisory_never_masks_a_later_refusal(tmp_path: Path, trailer: str) -> None:
    """The bare-citation refusal runs AFTER the advisory, and still refuses, trailer or not.

    Its subject needs no git read, so no repository is needed for the real ordering.
    """
    proc = _run(tmp_path, f"fix: x (#1, #2)\n\nBody.\n{trailer}")
    assert proc.returncode == 1, proc.stderr
    assert "MessageFoundry claim gate" in proc.stderr
    assert "no 'BACKLOG #' token governs them" in proc.stderr
    assert ("advisory:" in proc.stderr) == (trailer == "")
