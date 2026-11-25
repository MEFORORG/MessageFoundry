# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The commit-msg hook reads an optional `Verified-by:` trailer, in OBSERVE MODE only.

A missing, unrecognised or contradictory trailer prints one advisory line to stderr; a valid one
prints nothing, and a merge or a git-generated squash or revert message prints nothing either. No
case may refuse the commit. Each case runs the real hook as a subprocess on a message file, the way
git invokes it. These messages cite no ledger number, so the hook's only git call is
`git interpret-trailers --parse`, which runs outside a repository, and no repository is needed.
"""

from __future__ import annotations

import os
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
        # Above a `---` rule with prose below it: git reads no trailer block for the commit.
        "docs: a plain subject\n\nBody.\n\nVerified-by: tests\n---\nnotes after the rule\n",
    ],
)
def test_a_trailer_outside_the_trailer_block_does_not_count(tmp_path: Path, message: str) -> None:
    line = _one_advisory(_run(tmp_path, message))
    assert line.startswith("advisory: no 'Verified-by:' trailer")


@pytest.mark.parametrize(
    "message",
    [
        # A wrapped value: git folds the continuation line into the trailer.
        "docs: a plain subject\n\nBody.\n\nVerified-by: code-review\n  xhigh\n",
        # The comment block an editor commit leaves below the message.
        "docs: a plain subject\n\nBody.\n\nVerified-by: tests\n# Please enter the message.\n#\n",
        # A `---` rule in the body is body text in a commit message, not a patch divider.
        "docs: a plain subject\n\nBody.\n\n---\n\nMore body.\n\nVerified-by: tests\n",
    ],
)
def test_a_trailer_git_reads_is_counted(tmp_path: Path, message: str) -> None:
    proc = _run(tmp_path, message)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


@pytest.mark.parametrize("body", ["", "Body.\n\n"])
def test_a_hash_digit_subject_does_not_hide_the_trailer(tmp_path: Path, body: str) -> None:
    """A `#1134:` subject, which a -m or -F commit keeps, leaves the trailer block readable.

    The bare-citation check refuses this subject; the advisory must not add a false line above it.
    """
    proc = _run(tmp_path, f"#1134: retire the old reader\n\n{body}Verified-by: tests\n")
    assert proc.returncode == 1, proc.stderr
    assert "MessageFoundry claim gate" in proc.stderr
    assert "advisory:" not in proc.stderr


def test_git_that_cannot_answer_prints_one_advisory_line(tmp_path: Path) -> None:
    """No git on PATH: the advisory says the trailer went unchecked, and still refuses nothing."""
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_bytes(b"docs: a plain subject\n\nBody.\n\nVerified-by: tests\n")
    proc = subprocess.run(
        [sys.executable, str(_CHECK), str(msg)],
        cwd=tmp_path,
        capture_output=True,
        encoding="utf-8",
        errors="backslashreplace",
        timeout=60,
        env={**os.environ, "PATH": str(tmp_path)},
    )
    line = _one_advisory(proc)
    assert "git could not read the trailers" in line


@pytest.mark.parametrize(
    ("message", "state"),
    [
        ("Merge branch 'main' into topic\n", ("MERGE_HEAD",)),
        ("Resolve the conflict by hand\n", ("MERGE_HEAD",)),
        ("Squashed commit of the following:\n\ncommit 0123456789abcdef\n", ()),
        ('Revert "docs: a plain subject"\n\nThis reverts commit 0123456789abcdef.\n', ()),
        ('Reapply "docs: a plain subject"\n\nThis reverts commit 0123456789abcdef.\n', ()),
        ("fixup! docs: a plain subject\n", ()),
        ("squash! docs: a plain subject\n", ()),
        ("amend! docs: a plain subject\n\ndocs: a better subject\n", ()),
    ],
)
def test_a_merge_or_git_generated_message_is_skipped(
    tmp_path: Path, message: str, state: tuple[str, ...]
) -> None:
    proc = _run(tmp_path, message, state)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


@pytest.mark.parametrize(
    ("message", "state"),
    [
        ("Merge the two readers into one helper\n\nBody.\n", ()),
        # A human subject in git's merge shape, with no merge in progress.
        ("Merge branch handling into the router\n\nBody.\n", ()),
        # The author's own message while a squash or revert state file lingers.
        ("Fold the topic in\n\nBody.\n", ("SQUASH_MSG",)),
        ("Back the change out\n\nBody.\n", ("REVERT_HEAD",)),
        # The revert sentence in an ordinary commit's body.
        ("Reland the router\n\nThis reverts commit 0123456789abcdef, which broke X.\n", ()),
        # The revert sentence only in the diff `git commit -v` appends below the scissors.
        (
            'Revert "docs: a plain subject"\n\nBody.\n'
            "# ------------------------ >8 ------------------------\n"
            "+This reverts commit 0123456789abcdef.\n"
            "This reverts commit 0123456789abcdef.\n",
            (),
        ),
    ],
)
def test_only_git_shapes_are_skipped(tmp_path: Path, message: str, state: tuple[str, ...]) -> None:
    """Negative controls for the skip: a look-alike still gets the advisory."""
    line = _one_advisory(_run(tmp_path, message, state))
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
