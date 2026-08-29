# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Does the born-wrong detector actually separate the two populations it claims to?

BACKLOG #1344. The tool exists to split anchors a current-tree check renders identically: one whose
line was right when written and has since drifted, and one that was NEVER right at the commit the cell
stamps. A detector that cannot tell those apart would report the whole population as born-wrong and
look like a finding.

**THE FIXTURE IS A REAL GIT HISTORY, not a stub, and that is the point.** The distinction under test is
between two TREES, so a fake that hands the classifier a string proves only that the classifier reads
strings. Every row below is built by moving a token between two real commits.

**EVERY OUTCOME IS ASSERTED, INCLUDING THE ONES THAT ARE NOT FINDINGS.** A suite that only pinned
``born_wrong`` would pass against a detector that returns it unconditionally.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "asvs"))

from anchor_provenance import (  # noqa: E402
    ABSENT,
    AMBIGUOUS,
    AT_LINE,
    BORN_WRONG,
    NEVER_VERIFIED,
    NO_COMMIT,
    PATH_GONE,
    UNREADABLE,
    audit,
    classify,
    main,
    summarise,
)
from scorecard import Anchor, Cell  # noqa: E402


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def history(tmp_path: Path) -> tuple[Path, str, str]:
    """Two commits. The token sits at line 2 in the first and line 4 in the second.

    That single move is the whole discriminator: an anchor recording line 2 is CORRECT at the first
    commit and BORN-WRONG at the second, with no other difference between the runs.
    """
    repo = tmp_path / "engine"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)
    src = repo / "mod.py"

    src.write_text("first\nNEEDLE\nthird\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-m", "one", cwd=repo)
    early = git("rev-parse", "HEAD", cwd=repo)

    src.write_text("first\nsecond\nthird\nNEEDLE\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-m", "two", cwd=repo)
    later = git("rev-parse", "HEAD", cwd=repo)
    return repo, early, later


def cell_at(ref: str, line: int, path: str = "mod.py", expect: str = "NEEDLE") -> Cell:
    return Cell(
        id="X.1.1",
        level=1,
        verdict="pass",
        verified_at=ref,
        evidence=(Anchor(path=path, line=line, expect=expect),),
    )


# ------------------------------------------------------------------ the classifier, in isolation


@pytest.mark.parametrize(
    ("text", "expect", "line", "want_verdict", "want_line"),
    [
        ("a\nNEEDLE\nc\n", "NEEDLE", 2, AT_LINE, 2),
        ("a\nNEEDLE\nc\n", "NEEDLE", 9, BORN_WRONG, 2),
        ("a\nb\n", "NEEDLE", 2, ABSENT, None),
        ("x\nDUP\ny\nDUP\n", "DUP", 2, AMBIGUOUS, None),
        # A token spanning a newline. 42 of the live anchors do, and a per-line scan finds none of them
        # -- the line must be derived from the character offset, as check_anchors derives it.
        ("a\nb\nX\nY\n", "X\nY", 3, AT_LINE, 3),
    ],
)
def test_classify_discriminates_every_outcome(
    text: str, expect: str, line: int, want_verdict: str, want_line: int | None
) -> None:
    verdict, actual = classify(text, expect, line)
    assert verdict == want_verdict
    assert actual == want_line


def test_ambiguous_is_not_reported_as_born_wrong(history: tuple[Path, str, str]) -> None:
    """Uniqueness is the locator, so a token occurring twice cannot be born-wrong -- it has no location.

    Folding ambiguity into born-wrong would inflate the population with anchors whose line number was
    never load-bearing in the first place, which is the opposite of the item's claim.
    """
    repo, _early, _later = history
    (repo / "dup.py").write_text("DUP\nx\nDUP\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-m", "dup", cwd=repo)
    ref = git("rev-parse", "HEAD", cwd=repo)

    verdicts = audit([cell_at(ref, 1, path="dup.py", expect="DUP")], repo)
    assert [v.verdict for v in verdicts] == [AMBIGUOUS]
    assert AMBIGUOUS not in NEVER_VERIFIED


# ------------------------------------------------------------------ the two populations, against git


def test_an_anchor_correct_at_its_own_commit_is_NOT_born_wrong(
    history: tuple[Path, str, str],
) -> None:
    """The control that stops the detector being a rubber stamp.

    This anchor records line 2 and the token really is at line 2 in the commit the cell stamps. It has
    since MOVED, so a current-tree check would flag it -- and it is exactly the population this tool
    must leave alone.
    """
    repo, early, _later = history
    verdicts = audit([cell_at(early, 2)], repo)
    assert [v.verdict for v in verdicts] == [AT_LINE]


def test_an_anchor_wrong_at_its_own_commit_IS_born_wrong(history: tuple[Path, str, str]) -> None:
    """The same anchor, the same recorded line, judged against a DIFFERENT stamped commit.

    Nothing about the anchor changed between this row and the one above. Only the commit the cell
    claims to have verified at did, which is precisely the variable the item is about.
    """
    repo, _early, later = history
    verdicts = audit([cell_at(later, 2)], repo)
    assert [v.verdict for v in verdicts] == [BORN_WRONG]
    assert verdicts[0].actual_line == 4
    assert BORN_WRONG in NEVER_VERIFIED


def test_the_override_ref_answers_the_later_tree_hypothesis(
    history: tuple[Path, str, str],
) -> None:
    """``--at`` is the falsifiable form of the item's own explanation, so it gets a row.

    The item hypothesises that the numbers were read from a LATER tree than the commit stamped. Its
    test is whether some single ref resolves the population. Here the EARLY ref does exactly that for a
    cell stamped LATE, which is the shape a confirmation would take.
    """
    repo, early, later = history
    born_wrong = audit([cell_at(later, 2)], repo)
    assert born_wrong[0].verdict == BORN_WRONG

    resolved = audit([cell_at(later, 2)], repo, override_ref=early)
    assert resolved[0].verdict == AT_LINE
    assert resolved[0].ref == early


# ------------------------------------------------------------------ the answers that are not verdicts


def test_a_path_absent_at_the_stamped_commit_is_distinguished(
    history: tuple[Path, str, str],
) -> None:
    """A file that did not exist yet is not the same event as a token that moved, and merging them
    would attribute a record-keeping failure to the anchor's author."""
    repo, early, _later = history
    verdicts = audit([cell_at(early, 1, path="never_existed.py")], repo)
    assert [v.verdict for v in verdicts] == [PATH_GONE]


def test_an_unresolvable_stamp_is_distinguished_from_a_missing_file(
    history: tuple[Path, str, str],
) -> None:
    """A stamp git cannot resolve says the RECORD is broken, not the anchor. Reported as its own
    verdict so it cannot be counted into the born-wrong population."""
    repo, _early, _later = history
    verdicts = audit([cell_at("0" * 40, 2)], repo)
    assert [v.verdict for v in verdicts] == [UNREADABLE]


def test_a_cell_with_no_recorded_commit_is_not_silently_skipped(
    history: tuple[Path, str, str],
) -> None:
    """An un-stamped cell cannot be judged, and dropping it would shrink the denominator invisibly --
    which is how a coverage number quietly stops meaning what it says."""
    repo, _early, _later = history
    verdicts = audit([cell_at("", 2)], repo)
    assert [v.verdict for v in verdicts] == [NO_COMMIT]


# ------------------------------------------------------------------ reporting and refusals


def test_the_summary_reports_direction_because_direction_is_the_evidence(
    history: tuple[Path, str, str],
) -> None:
    """The item's argument that this is ONE defect rests on the drift being systematic rather than
    scattered. The summary must therefore print the split rather than assert the conclusion."""
    repo, _early, later = history
    text = summarise(audit([cell_at(later, 2)], repo))
    assert "born-wrong direction" in text
    assert "recorded HIGHER than actual 0, LOWER 1" in text


def test_it_refuses_a_root_that_contains_the_scorecard(tmp_path: Path, history) -> None:
    """Resolving anchors against the repository that STORES the record is self-consistent and wrong.

    ``scorecard.py`` refuses the same pairing in verify mode, and the vault carries its own copy of the
    engine sources for exactly that trap to fall into.
    """
    repo, early, _later = history
    card = repo / "card.toml"
    card.write_text("", encoding="utf-8")
    assert main(["--scorecard", str(card), "--root", str(repo)]) == 2


def test_detail_is_written_only_when_asked(tmp_path: Path, history) -> None:
    """Cell identifiers paired with file paths are the enumeration CLAUDE.md section 12 keeps vaulted,
    so the per-cell record must never be a side effect of running the tool."""
    repo, _early, later = history
    card = tmp_path / "card.toml"
    card.write_text(
        f'[[cell]]\nid = "X.1.1"\nlevel = 1\nverdict = "pass"\nverified_at = "{later}"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n',
        encoding="utf-8",
    )
    detail = tmp_path / "detail.json"
    assert main(["--scorecard", str(card), "--root", str(repo)]) == 0
    assert not detail.exists()

    assert main(["--scorecard", str(card), "--root", str(repo), "--detail", str(detail)]) == 0
    rows = json.loads(detail.read_text(encoding="utf-8"))
    assert rows and rows[0]["verdict"] == BORN_WRONG


def test_a_root_whose_HEAD_cannot_be_resolved_is_refused_not_stamped_HEAD(
    tmp_path: Path, capsys
) -> None:
    """The comment above this tool's own header says NO NUMBER HERE IS A FACT WITHOUT THE PAIR IT
    WAS MEASURED AGAINST -- and the pair is exactly what degrades silently.

    ``git rev-parse HEAD`` on a commitless repo exits 128 and echoes the literal ``HEAD`` on stdout,
    so the header stamps ``engine=HEAD``. Measured on that arm: rc=0, every anchor unreadable, and a
    closing line reading ``NOT verifiable at the cell's own recorded commit: 0``. A reassuring zero
    over a run where nothing was verifiable at all.
    """
    repo = tmp_path / "commitless"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nid = "X.1.1"\nlevel = 1\nverdict = "pass"\nverified_at = "deadbeef"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n',
        encoding="utf-8",
    )
    assert main(["--scorecard", str(card), "--root", str(repo)]) == 3
    captured = capsys.readouterr()
    # NOT a bare ``"HEAD" in err``. That assertion passed with this guard REMOVED, because pytest
    # names ``tmp_path`` after the test and this test's name contains HEAD -- so the directory path
    # echoed in a DIFFERENT refusal satisfied it. Caught by mutation, not by re-reading. The phrase
    # below is emitted by the rev-parse guard and by nothing else in either tool.
    assert "cannot resolve HEAD" in captured.err
    assert "engine=HEAD" not in captured.out
