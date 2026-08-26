# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Untracked is an INDEX fact; lost is a CONTENT fact (BACKLOG #1298).

The archive dialog warns that untracked files "will be permanently discarded". It reasons from "not
in THIS WORKTREE'S index" straight to "will be lost", and skips the only question that decides it:
is the content somewhere else.

The two come apart for an ordinary and constant reason. A worktree branched behind ``main`` does not
have the files that landed since, so a copy of one of them sitting in that tree is untracked THERE
while tracked on ``main`` -- fully recoverable, and the warning is wrong about it.

**Every test below pairs the reassuring answer with the alarming one over the SAME command.** A
helper that always said RECOVERABLE would pass a suite that only ever fed it recoverable files, and
that is the failure mode that matters here: a false RECOVERABLE costs the file, while a false
AT-RISK costs a look. The three arms -- absent, modified, identical -- are asserted to produce three
different verdicts, so the cases cannot funnel to one assertion.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "coord" / "recoverable.ps1"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="recoverable.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    return proc.stdout


def run_helper(worktree: Path, ref: str = "origin/main") -> tuple[int, dict[str, object]]:
    """Drive the REAL script as a subprocess, as -Json, and return (exit code, payload)."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-Worktree",
            str(worktree),
            "-Ref",
            ref,
            "-NoFetch",
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.stdout.strip(), f"helper produced no stdout:\n{proc.stderr}"
    return proc.returncode, dict(json.loads(proc.stdout))


def by_path(payload: dict[str, object], field: str) -> dict[str, str]:
    """Map path -> one field of its row. One unpacker, so the isinstance dance is written once."""
    rows = payload["Rows"]
    assert isinstance(rows, list)
    out: dict[str, str] = {}
    for r in rows:
        out[str(r["Path"])] = str(r[field])
    return out


def verdicts(payload: dict[str, object]) -> dict[str, str]:
    return by_path(payload, "Verdict")


def reasons(payload: dict[str, object]) -> dict[str, str]:
    return by_path(payload, "Reason")


@pytest.fixture
def upstream_and_behind(tmp_path: Path) -> tuple[Path, Path]:
    """An 'origin' whose main carries a file, and a clone parked one commit BEHIND it.

    This is the shape the item is about, built rather than described: the behind-tree genuinely does
    not have the later file in its index, which is what makes git call a copy of it untracked.
    """
    up = tmp_path / "up"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    git(up, "config", "user.email", "t@example.invalid")
    git(up, "config", "user.name", "t")
    (up / "base.txt").write_text("base\n", encoding="utf-8")
    git(up, "add", "base.txt")
    git(up, "commit", "-qm", "base")

    (up / "landed.txt").write_text("landed content\n", encoding="utf-8")
    git(up, "add", "landed.txt")
    git(up, "commit", "-qm", "land a file")

    behind = tmp_path / "behind"
    git(tmp_path, "clone", "-q", str(up), str(behind))
    git(behind, "config", "user.email", "t@example.invalid")
    git(behind, "config", "user.name", "t")
    # Park one commit behind: this tree's index has no landed.txt.
    first = git(behind, "rev-list", "--max-parents=0", "HEAD").strip()
    git(behind, "checkout", "-q", "--detach", first)
    assert not (behind / "landed.txt").exists()
    return up, behind


def test_a_landed_file_in_a_behind_worktree_is_recoverable_not_lost(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """The reassuring arm, and the one the dialog gets wrong."""
    _, behind = upstream_and_behind
    (behind / "landed.txt").write_text("landed content\n", encoding="utf-8")

    assert "?? landed.txt" in git(behind, "status", "--porcelain"), (
        "precondition: git must call this untracked, or the test is not about the reported case"
    )

    code, payload = run_helper(behind)
    print(json.dumps(payload, indent=2))
    assert verdicts(payload)["landed.txt"] == "RECOVERABLE"
    assert payload["AtRisk"] == 0
    assert code == 0, "nothing at risk must exit 0, so this is usable as a check"


def test_a_file_absent_from_the_ref_is_at_risk(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """The alarming arm. Same command, same tree, opposite answer."""
    _, behind = upstream_and_behind
    (behind / "genuinely_new.txt").write_text("nobody else has this\n", encoding="utf-8")

    code, payload = run_helper(behind)
    print(json.dumps(payload, indent=2))
    assert verdicts(payload)["genuinely_new.txt"] == "AT-RISK"
    assert payload["AtRisk"] == 1
    assert code == 1, "anything at risk must exit non-zero"


def test_a_file_on_the_ref_but_locally_modified_is_at_risk(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """The arm a name-only or existence-only check would miss.

    The path IS on the ref, so 'is it on main' answers yes and a helper that stopped there would
    call it recoverable. The local edit is the thing that would actually be lost.
    """
    _, behind = upstream_and_behind
    (behind / "landed.txt").write_text("landed content\nplus a local edit\n", encoding="utf-8")

    code, payload = run_helper(behind)
    print(json.dumps(payload, indent=2))
    assert verdicts(payload)["landed.txt"] == "AT-RISK"
    # The reason must be `modified`, NOT `absent`. Both are AT-RISK, so Verdict alone cannot tell
    # this test from the one above it -- and an existence-only check would have said RECOVERABLE.
    got_reasons = reasons(payload)
    assert got_reasons["landed.txt"] == "modified", (
        f"expected the on-ref-but-edited reason, got {got_reasons}; if this says 'absent' the ref "
        "lookup is failing and every file would be reported at risk for the wrong reason"
    )
    assert code == 1


def test_the_three_arms_do_not_collapse_to_one_answer(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """All three at once: a suite whose cases all produce the same string proves nothing.

    This is the test that would catch a helper hard-coded to one verdict, which every single-arm
    test above would pass individually.
    """
    _, behind = upstream_and_behind
    (behind / "landed.txt").write_text("landed content\n", encoding="utf-8")
    (behind / "genuinely_new.txt").write_text("nobody else has this\n", encoding="utf-8")
    (behind / "base.txt").write_text("base\nlocally edited\n", encoding="utf-8")

    code, payload = run_helper(behind)
    got = verdicts(payload)
    print(json.dumps(payload, indent=2))

    assert got["landed.txt"] == "RECOVERABLE"
    assert got["genuinely_new.txt"] == "AT-RISK"

    # AND THE REASONS MUST DIFFER, not just the verdicts. Verdict is deliberately BINARY -- three of
    # its four causes are AT-RISK -- so a suite that only asserts Verdict cannot tell "absent from
    # the ref" from "on the ref but modified", which is the distinction the docs call the whole
    # point. Without this block a consumer would have to parse English with the ref interpolated
    # into it, and nothing here would notice if Reason collapsed to one value.
    got_reasons = reasons(payload)
    assert got_reasons["landed.txt"] == "identical"
    assert got_reasons["genuinely_new.txt"] == "absent"
    assert len(set(got_reasons.values())) == 2, f"the reasons collapsed to one value: {got_reasons}"

    # base.txt is TRACKED and modified, so it is not untracked and not this script's subject.
    assert "base.txt" not in got, (
        "a tracked-but-modified file is not what the archive warning is about; including it would "
        "widen the report past the population the item names"
    )
    assert payload["AtRisk"] == 1
    assert payload["Recoverable"] == 1
    assert code == 1


def test_an_untracked_directory_is_expanded_rather_than_reported_as_one_entry(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """git's default porcelain collapses an untracked DIRECTORY to a single entry.

    Every file beneath it would then go unexamined while the run still printed a verdict, which is
    the silent-undercount shape. --untracked-files=all is what prevents it, and this pins that.
    """
    _, behind = upstream_and_behind
    nested = behind / "newdir" / "deeper"
    nested.mkdir(parents=True)
    (nested / "a.txt").write_text("a\n", encoding="utf-8")
    (nested / "b.txt").write_text("b\n", encoding="utf-8")

    code, payload = run_helper(behind)
    got = verdicts(payload)
    print(json.dumps(payload, indent=2))

    assert "newdir/deeper/a.txt" in got, f"the directory was not expanded: {sorted(got)}"
    assert "newdir/deeper/b.txt" in got, f"the directory was not expanded: {sorted(got)}"
    assert payload["Untracked"] == 2
    assert code == 1


def test_the_ref_it_compared_against_is_reported(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """A verdict without the ref it was computed against cannot be re-checked by its reader."""
    _, behind = upstream_and_behind
    (behind / "landed.txt").write_text("landed content\n", encoding="utf-8")

    _, payload = run_helper(behind)
    assert payload["Ref"] == "origin/main"
    sha = str(payload["RefSha"])
    assert len(sha) == 40, f"expected a full sha, got {sha!r}"
    assert sha == git(behind, "rev-parse", "origin/main").strip()


def test_an_unresolvable_ref_refuses_rather_than_reporting_everything_clean(
    upstream_and_behind: tuple[Path, Path],
) -> None:
    """The direction that matters: cannot-compare must never render as nothing-to-worry-about.

    If the ref does not resolve, every file is 'absent from the ref' by construction -- which would
    be the correct AT-RISK answer for the wrong reason, and would look identical to a real one. The
    script refuses the run instead.
    """
    _, behind = upstream_and_behind
    (behind / "landed.txt").write_text("landed content\n", encoding="utf-8")

    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-Worktree",
            str(behind),
            "-Ref",
            "origin/no-such-branch-zzq",
            "-NoFetch",
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode != 0, "an unresolvable ref must not exit 0"
    combined = proc.stdout + proc.stderr
    assert "refusing" in combined.lower(), f"expected an explicit refusal, got:\n{combined}"
