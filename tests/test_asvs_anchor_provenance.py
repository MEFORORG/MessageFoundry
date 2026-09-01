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

#: The refusal code for a run that started and will not publish a number. This tool splits its two
#: refusals: 2 says the INVOCATION is unusable and is decidable from the arguments alone, 3 says the
#: arguments were good and the measurement came out void. Spelled here rather than as a bare literal
#: at each site, because an arm that pins the wrong family passes for the wrong reason.
REFUSED = 3

#: Planted in every record the CLI arms drive, and searched for in every captured stream. A real
#: requirement id collides with ordinary numbers in this tool's own output -- it prints line numbers,
#: counts and percentages -- so an absence assertion against one proves nothing. This cannot occur by
#: accident, so a hit is PROOF of disclosure rather than a coincidence.
SENTINEL_ID = "ZZ.SENTINEL.9"
SECOND_SENTINEL_ID = "ZZ.SENTINEL.8"

#: Assessment CONTENT, as against the public vocabulary (anchor, scorecard, verifier, stale, born
#: wrong). Stated ONCE and scanned by EVERY arm that captures a stream, which is the whole reason it
#: is a module constant: the sibling tool put its equivalent list inside the one happy-path arm that
#: used it, so the refusal path was never scanned and shipped a leak. A list only one caller reads is
#: a list that only covers one caller.
BANNED_CONTENT = ("verdict", "coverage", "partial", " pass ", "unverified")


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True
    ).stdout.strip()


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    """Run the CLI and return its code plus BOTH streams joined, so a leak cannot hide on stderr.

    Every refusal in this tool writes to stderr and every summary to stdout, so an arm reading one
    stream is blind to half the output it is asserting about -- and blind in the direction that
    passes.
    """
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def _assert_no_assessment_content(stream: str) -> None:
    """Nothing a reader could paste from this stream may name a graded row or a grading word.

    The module docstring calls the summary "safe to paste anywhere", and that is a claim about the
    TOOL rather than about one code path. Asserting it in a single arm would make it hold exactly
    where it was already obvious.
    """
    for sentinel in (SENTINEL_ID, SECOND_SENTINEL_ID):
        assert sentinel not in stream, f"the output disclosed a graded row's identifier:\n{stream}"
    for banned in BANNED_CONTENT:
        assert banned not in stream.lower(), (
            f"the output leaked assessment content ({banned!r}):\n{stream}"
        )


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


def test_detail_is_written_only_when_asked(tmp_path: Path, history, capsys) -> None:
    """Cell identifiers paired with file paths are the enumeration CLAUDE.md section 12 keeps vaulted,
    so the per-cell record must never be a side effect of running the tool.

    THE SPLIT IS ASSERTED IN BOTH DIRECTIONS HERE, which is what makes it a property rather than a
    habit: the identifier reaches the file ``--detail`` names, and it reaches nothing else. An arm
    that only checked the file was absent would pass just as well against a tool that printed the
    identifier to stdout as well.
    """
    repo, _early, later = history
    card = tmp_path / "card.toml"
    card.write_text(
        f'[[cell]]\nid = "{SENTINEL_ID}"\nlevel = 1\nverdict = "pass"\nverified_at = "{later}"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n',
        encoding="utf-8",
    )
    detail = tmp_path / "detail.json"
    code, out = _run(["--scorecard", str(card), "--root", str(repo)], capsys)
    assert code == 0
    assert not detail.exists()
    _assert_no_assessment_content(out)

    code, out = _run(
        ["--scorecard", str(card), "--root", str(repo), "--detail", str(detail)], capsys
    )
    assert code == 0
    _assert_no_assessment_content(out)
    rows = json.loads(detail.read_text(encoding="utf-8"))
    assert rows and rows[0]["verdict"] == BORN_WRONG
    assert rows[0]["cell"] == SENTINEL_ID


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
        f'[[cell]]\nid = "{SENTINEL_ID}"\nlevel = 1\nverdict = "pass"\nverified_at = "deadbeef"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n',
        encoding="utf-8",
    )
    assert main(["--scorecard", str(card), "--root", str(repo)]) == REFUSED
    captured = capsys.readouterr()
    _assert_no_assessment_content(captured.out + captured.err)
    # NOT a bare ``"HEAD" in err``. That assertion passed with this guard REMOVED, because pytest
    # names ``tmp_path`` after the test and this test's name contains HEAD -- so the directory path
    # echoed in a DIFFERENT refusal satisfied it. Caught by mutation, not by re-reading. The phrase
    # below is emitted by the rev-parse guard and by nothing else in either tool.
    assert "cannot resolve HEAD" in captured.err
    assert "engine=HEAD" not in captured.out


def test_a_run_where_NOTHING_could_be_read_is_refused_not_closed_with_a_zero(
    history: tuple[Path, str, str], tmp_path: Path, capsys
) -> None:
    """The reassuring zero this tool's own test docstring names as the harm, still shipping.

    NEVER_VERIFIED is frozenset({BORN_WRONG, ABSENT, PATH_GONE}). UNREADABLE and NO_COMMIT are not in
    it -- correctly, because an unresolvable stamp is a different fact from a born-wrong anchor. But
    the closing line sums only that set, so a run where every anchor was unreadable closes with
    "anchors that were NOT verifiable at the cell's own recorded commit: 0" and exits 0, WITH A REAL
    SHA IN THE HEADER. Round one's rev-parse guard closed only the commitless doorway to this.

    Reachable by a shallow clone, a fresh clone of a rewritten history, or simply the wrong sibling
    checkout -- and the header cannot separate the good run from the bad one, because the engine ref
    is identical in both.
    """
    repo, _early, _later = history
    card = tmp_path / "card.toml"
    card.write_text(
        f'[[cell]]\nid = "{SENTINEL_ID}"\nlevel = 1\nverdict = "pass"\n'
        'verified_at = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n',
        encoding="utf-8",
    )
    rc = main(["--scorecard", str(card), "--root", str(repo)])
    assert rc == REFUSED
    captured = capsys.readouterr()
    assert "REFUSING" in captured.err
    assert "could not be read" in captured.err
    _assert_no_assessment_content(captured.out + captured.err)


def test_the_closing_line_never_stands_alone_when_some_anchor_could_not_be_read(
    history: tuple[Path, str, str], tmp_path: Path, capsys
) -> None:
    """A PARTIALLY unreadable run still answers, but the takeaway number may not be printed naked.

    One anchor resolves and one does not. The "NOT verifiable" line is legitimate, and on its own it
    invites the reader to carry a number that did not examine half the population. So the count of
    anchors that could not be read is printed beside it, always, including when it is zero -- a stated
    zero is checkable and an absent line is not.
    """
    repo, _early, later = history
    card = tmp_path / "card.toml"
    card.write_text(
        f'[[cell]]\nid = "{SENTINEL_ID}"\nlevel = 1\nverdict = "pass"\nverified_at = "{later}"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n'
        f'[[cell]]\nid = "{SECOND_SENTINEL_ID}"\nlevel = 1\nverdict = "pass"\n'
        'verified_at = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\nexpect = "NEEDLE"\n',
        encoding="utf-8",
    )
    code, out = _run(["--scorecard", str(card), "--root", str(repo)], capsys)
    assert code == 0
    assert "could not be read" in out
    _assert_no_assessment_content(out)


#: Records that reach ``load_scorecard`` and do not come back as cells, one per fault it fails
#: differently, paired with the exception CLASS each produces. Every identifier here is invented --
#: ``ZZ.SENTINEL.9`` and ``bogus`` cannot collide with a real requirement -- so a hit in a captured
#: stream is proof of disclosure rather than a coincidence.
#:
#: THE THREE ``KeyError`` ROWS ARE THE SECOND HALF OF THE DEFECT. ``load_scorecard`` subscripts the
#: record directly in a dozen places, so these reached no refusal at all: they escaped as a traceback
#: and exit 1, a code this tool's own contract never defines and no ``return`` in it produces.
_UNREADABLE: dict[str, tuple[str, str]] = {
    "unknown_state": ('[[cell]]\nid = "{id}"\nlevel = 1\nverdict = "bogus"\n', "ScorecardError"),
    "na_without_rationale": (
        '[[cell]]\nid = "{id}"\nlevel = 1\nverdict = "na"\n',
        "ScorecardError",
    ),
    "closed_without_a_pin": (
        '[[cell]]\nid = "{id}"\nlevel = 1\nverdict = "pass"\ndecision_closed = true\n',
        "ScorecardError",
    ),
    "row_without_id": ('[[cell]]\nlevel = 1\nverdict = "pass"\n', "KeyError"),
    "row_without_level": ('[[cell]]\nid = "{id}"\nverdict = "pass"\n', "KeyError"),
    "citation_without_a_token": (
        '[[cell]]\nid = "{id}"\nlevel = 1\nverdict = "pass"\n'
        '[[cell.evidence]]\npath = "mod.py"\nline = 2\n',
        "KeyError",
    ),
    "not_toml_at_all": ('[[cell]\nid = "{id}"\n', "TOMLDecodeError"),
}


@pytest.mark.parametrize("fault", sorted(_UNREADABLE))
def test_a_record_that_will_not_load_is_refused_without_naming_the_row(
    history: tuple[Path, str, str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fault: str,
) -> None:
    """THE LOAD BOUNDARY, which no arm above reaches in either direction.

    ``load_scorecard`` refuses in ten places and nine of them open by naming the graded row they
    rejected; one lists the whole grading vocabulary. So an unguarded call would print a graded row's
    identifier to stderr the first time a record went malformed -- as a traceback, which is also
    exit 1, outside the 0/2/3 this tool returns anywhere else.

    Both halves are asserted here because they arrive together and are fixed together. The exit code
    is the one a poller reads; the stream is the one a person pastes.

    THIS FUNCTION'S NAME, ITS PARAMETER NAMES AND EVERY KEY IN ``_UNREADABLE`` ARE PART OF THE
    FIXTURE: pytest builds ``tmp_path`` from the first two, the parametrize id lands in it as well,
    and the refusal prints the path it was handed. All of them must stay clear of
    :data:`BANNED_CONTENT`, or the arm fails against its own name.
    """
    repo, _early, _later = history
    body, exc_name = _UNREADABLE[fault]
    record = tmp_path / f"{fault}.toml"
    record.write_text(body.format(id=SENTINEL_ID), encoding="utf-8")

    code, out = _run(["--scorecard", str(record), "--root", str(repo)], capsys)

    # Reaching this line at all is half the arm. An unguarded call raises out of ``main`` instead of
    # returning, so before the guard existed every row here died in ``_run`` with the traceback
    # itself as the failure -- which is exactly the output the tool would have printed.
    assert code == REFUSED, (
        f"{fault!r} exited {code}, not {REFUSED}. Exit 1 is what an escaping exception produces and "
        f"this tool defines no meaning for it, so a caller cannot tell it from a crash:\n{out}"
    )
    assert "REFUSING" in out, out
    # Exit 3 is shared with the unresolvable-HEAD and nothing-readable refusals, so the code alone
    # cannot pin THIS guard. A bare "REFUSING" cannot either. This phrase is emitted here and
    # nowhere else in the tool.
    assert "would not load" in out, f"{fault!r} was refused by some other guard:\n{out}"
    _assert_no_assessment_content(out)
    # A refusal read nothing, so it prints no total: "nothing was found" and "nothing was looked at"
    # must never render identically, which is the property this whole tool exists to hold.
    assert "anchors examined" not in out, f"{fault!r} printed a total off an unread record:\n{out}"
    # WITHHOLDING THE DIAGNOSTIC MUST NOT WITHHOLD THE TRIAGE. The class carries nothing from the
    # record and is the one part that crosses.
    assert exc_name in out, f"{fault!r} gave the reader no failure class to act on:\n{out}"


def test_the_class_name_alone_separates_a_bad_file_from_a_bad_row(
    history: tuple[Path, str, str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The argument for withholding the reader's message, written as a test rather than a comment.

    Two records fail, and a reader acts on them differently. One never became a record at all, so the
    repair is to the file's syntax. The other parsed and carries a row the reader rejected, so the
    repair is to that row, found by running the verifier where the record lives.

    That split is the entire triage cost of suppressing the message, and the exception CLASS pays it
    in full. Asserting each name is present is not enough on its own -- a guard that printed both, or
    a constant string containing both, would satisfy it -- so each is also asserted ABSENT from the
    other run.
    """
    repo, _early, _later = history
    bad_file = tmp_path / "not_a_document.toml"
    bad_file.write_text(f'[[cell]\nid = "{SENTINEL_ID}"\n', encoding="utf-8")
    bad_row = tmp_path / "a_rejected_row.toml"
    bad_row.write_text(
        f'[[cell]]\nid = "{SENTINEL_ID}"\nlevel = 1\nverdict = "bogus"\n', encoding="utf-8"
    )

    file_code, file_out = _run(["--scorecard", str(bad_file), "--root", str(repo)], capsys)
    row_code, row_out = _run(["--scorecard", str(bad_row), "--root", str(repo)], capsys)

    assert file_code == REFUSED and row_code == REFUSED
    assert "TOMLDecodeError" in file_out and "TOMLDecodeError" not in row_out
    assert "ScorecardError" in row_out and "ScorecardError" not in file_out
    _assert_no_assessment_content(file_out)
    _assert_no_assessment_content(row_out)
