# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Can the anchor report actually detect a stale anchor, and does it refuse what it must refuse?

BACKLOG #1405. The reporter's whole value is a negative claim -- "these citations no longer reach the
code they name" -- and a negative claim is the easiest thing in the world to make vacuously. So each
constraint the tool was built under gets an arm here that goes RED if the constraint is lost:

* **positive control** -- delete the quoted line, exactly the way a real fix does, and the report must
  count it. A test that cannot fail is worse than no test, and every arm below rests on this one;
* **negative control** -- an intact tree must report ZERO unresolved, or the detector is firing on
  everything and the positive control proves nothing;
* **it reports, it does not rewrite** -- nothing in the tool proposes a replacement anchor, and the
  scorecard file is byte-identical after a run;
* **the scorecard path is an argument** -- it is required, and a root CONTAINING the record is refused;
* **no requirement identifiers** -- a sentinel row id planted in the fixture must appear nowhere in
  the output, in the failing case as well as the clean one, AND NOWHERE IN A REFUSAL: the reader's
  own diagnostics name the row they rejected, and an error path is where output stops being reviewed;
* **unknown is not zero** -- a missing, unparseable or empty record exits non-zero and never prints a
  reassuring total, and it exits 2 rather than 1 so "I could not measure" never renders as a finding;
* **one locator, not two** -- the report, the gate and the provenance tool must agree by construction.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "asvs"))

from anchor_provenance import ABSENT, AMBIGUOUS, AT_LINE, classify  # noqa: E402
from anchor_report import (  # noqa: E402
    EXIT_FINDINGS,
    EXIT_INSTRUMENT,
    EXIT_OK,
    PATH_MISSING,
    UNRESOLVED,
    audit,
    changed_paths,
    main,
)
from scorecard import (  # noqa: E402
    ANCHOR_AMBIGUOUS,
    ANCHOR_GONE,
    ANCHOR_LOCATED,
    Findings,
    check_anchors,
    load_scorecard,
    locate_anchor,
)

#: Planted in the fixture record and searched for in every captured stream. A real requirement id
#: (``2.1.1``) would collide with ordinary numbers in the output; this cannot occur by accident, so a
#: hit is proof of disclosure rather than a coincidence.
SENTINEL_ID = "ZZ.SENTINEL.9"

#: The line a "fix" deletes. Written to read like the real case the item describes -- the code got
#: better and the improvement removed the statement the citation quoted.
QUOTED = 'ssl_context.minimum_version = "TLSv1.2"'

#: Assessment CONTENT, as against the public vocabulary (anchor, scorecard, verifier, stale). Stated
#: ONCE and scanned by every arm that captures output. It used to be spelled out in the one happy-path
#: arm, which is precisely why the leak on the refusal path reached review: a list only one caller
#: reads is a list that only covers one caller.
BANNED_CONTENT = ("verdict", "coverage", "partial", " pass ", "unverified")

SOURCE = f"""\
def connect() -> None:
    {QUOTED}
    return None
"""


def _scorecard(
    path: Path, *, cell_id: str = SENTINEL_ID, expect: str = QUOTED, line: int = 2
) -> Path:
    """A minimal but LOADABLE record: `load_scorecard` is the reporter's real reader, not a stub."""
    path.write_text(
        "[scorecard]\n"
        'anchor_commit = "0000000"\n\n'
        "[[cell]]\n"
        f'id = "{cell_id}"\n'
        "level = 1\n"
        'verdict = "pass"\n'
        'last_verified = "2026-08-31"\n\n'
        "[[cell.evidence]]\n"
        'path = "engine_module.py"\n'
        f"line = {line}\n"
        f"expect = {expect!r}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, Path]:
    """An engine tree with the quoted line present, and a record citing it. Returns (root, record).

    The record is deliberately written OUTSIDE the root: that is the real topology (the scorecard
    lives in a different repository) and it is what the containment refusal exists to protect.
    """
    root = tmp_path / "engine"
    root.mkdir()
    (root / "engine_module.py").write_text(SOURCE, encoding="utf-8")
    return root, _scorecard(tmp_path / "record.toml")


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    """Run the CLI and return its code plus BOTH streams joined, so a leak cannot hide on stderr."""
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


# --------------------------------------------------------------------------------------------
# The positive control, and the negative control that makes it mean something.
# --------------------------------------------------------------------------------------------


def test_a_deleted_quoted_line_is_reported(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """THE POSITIVE CONTROL. Remove the quoted statement the way a real improvement would."""
    root, record = tree
    (root / "engine_module.py").write_text("def connect() -> None:\n    return None\n", "utf-8")

    code, out = _run(["--scorecard", str(record), "--root", str(root), "--strict"], capsys)

    assert code == EXIT_FINDINGS, f"a gone anchor did not fail under --strict:\n{out}"
    assert "NOT RESOLVING      : 1" in out, out
    assert "token gone       : 1" in out, out
    # The affected FILE is named -- the item's fix is only actionable if a human can find it.
    assert "engine_module.py" in out, out


def test_an_intact_tree_reports_zero(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """THE NEGATIVE CONTROL. Without this, a detector that flags everything passes the arm above."""
    root, record = tree
    code, out = _run(["--scorecard", str(record), "--root", str(root), "--strict"], capsys)

    assert code == EXIT_OK, f"an intact tree was reported as broken:\n{out}"
    assert "NOT RESOLVING      : 0" in out, out
    assert "resolving          : 1" in out, out


def test_a_missing_cited_file_is_separated_from_a_gone_token(tmp_path: Path) -> None:
    """A deleted FILE and a rewritten LINE have different first questions, so they count apart."""
    root = tmp_path / "engine"
    root.mkdir()  # the cited module is never created
    cells = load_scorecard(_scorecard(tmp_path / "record.toml"))
    assert [o.status for o in audit(cells, root)] == [PATH_MISSING]


def test_an_ambiguous_token_counts_as_unresolved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A token occurring twice locates nothing, so it is a failure to resolve, not mere drift."""
    root = tmp_path / "engine"
    root.mkdir()
    (root / "engine_module.py").write_text(SOURCE + SOURCE, encoding="utf-8")
    record = _scorecard(tmp_path / "record.toml")

    code, out = _run(["--scorecard", str(record), "--root", str(root), "--strict"], capsys)

    assert code == EXIT_FINDINGS, out
    assert "ambiguous        : 1" in out, out


# --------------------------------------------------------------------------------------------
# Constraint: it reports, it does not rewrite.
# --------------------------------------------------------------------------------------------


def test_the_record_is_not_written(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """An anchor that MOVED and one that was WRONG need different human responses, so neither is
    silently re-pointed. Asserted on the bytes rather than on the absence of a --fix flag: a future
    edit adds behaviour long before it adds a flag."""
    root, record = tree
    (root / "engine_module.py").write_text(f"# moved\n\n\n    {QUOTED}\n", encoding="utf-8")
    before = record.read_bytes()

    _run(["--scorecard", str(record), "--root", str(root)], capsys)

    assert record.read_bytes() == before, "the reporter modified the record"


def test_no_output_proposes_a_replacement_line(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """The output must not offer a re-anchor. A tool cannot tell a moved token from a retired control,
    and the single affordance of suggesting one is what manufactures silent corruption."""
    root, record = tree
    (root / "engine_module.py").write_text(f"# moved\n\n\n    {QUOTED}\n", encoding="utf-8")

    _, out = _run(["--scorecard", str(record), "--root", str(root)], capsys)

    lowered = out.lower()
    for banned in ("re-anchor to", "should be line", "update line", "now at line", "suggest"):
        assert banned not in lowered, f"the report proposes a repair ({banned!r}):\n{out}"


# --------------------------------------------------------------------------------------------
# Constraint: the scorecard path is an argument, and the root must not contain the record.
# --------------------------------------------------------------------------------------------


def test_the_scorecard_argument_is_required(tree: tuple[Path, Path]) -> None:
    """No default may exist. A defaulted path names a file in THIS repository, where the record is
    not tracked -- so it would measure the wrong tree, or nothing, and still print a full report."""
    root, _ = tree
    with pytest.raises(SystemExit) as exc:
        main(["--root", str(root)])
    assert exc.value.code == 2, "argparse must refuse a run with no --scorecard"


def test_a_root_containing_the_record_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Anchors resolved against the repository that STORES the record are self-consistent and wrong.

    The vault carries its own tracked copy of the engine sources, so this is a live trap rather than a
    hypothetical one; `scorecard.verify` refuses the same pairing.
    """
    root = tmp_path / "vault"
    root.mkdir()
    (root / "engine_module.py").write_text(SOURCE, encoding="utf-8")
    record = _scorecard(root / "record.toml")

    code, out = _run(["--scorecard", str(record), "--root", str(root)], capsys)

    assert code == EXIT_INSTRUMENT, out
    assert "CONTAINS the scorecard" in out, out


# --------------------------------------------------------------------------------------------
# Constraint: no requirement identifiers, coverage or gaps in the output.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("break_it", [True, False])
def test_the_row_identifier_never_reaches_the_output(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str], break_it: bool
) -> None:
    """BOTH cases, because suppression that only holds on a clean run is not suppression.

    A path-to-requirement map enumerates what IS covered over a closed domain, which hands out what is
    NOT by subtraction. This repository's run logs are public.
    """
    root, record = tree
    if break_it:
        (root / "engine_module.py").write_text("def connect() -> None:\n    pass\n", "utf-8")

    _, out = _run(["--scorecard", str(record), "--root", str(root)], capsys)

    assert SENTINEL_ID not in out, f"the report disclosed a requirement identifier:\n{out}"


def test_the_outcome_type_carries_no_identifier_field(tree: tuple[Path, Path]) -> None:
    """Structural, not a filter on the way out: a field that EXISTS is a field a later edit prints."""
    root, record = tree
    outcome = audit(load_scorecard(record), root)[0]
    fields = set(vars(outcome))
    assert fields == {"path", "status"}, f"AnchorOutcome grew a field: {sorted(fields)}"


def test_assessment_content_is_absent_from_the_report(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Counts of anchors are safe; a grade distribution or a coverage figure is the content.

    THIS FUNCTION'S OWN NAME IS PART OF THE FIXTURE and must stay clear of the banned words: pytest
    builds `tmp_path` from it, the report prints the paths it was given, and the first draft failed
    on its own name. Kept as a comment rather than fixed by excluding the path rows -- excluding them
    would also stop the scan seeing a real leak that happened to land on one.
    """
    root, record = tree
    _, out = _run(["--scorecard", str(record), "--root", str(root)], capsys)
    for banned in BANNED_CONTENT:
        assert banned not in out.lower(), (
            f"the report leaked assessment content ({banned!r}):\n{out}"
        )


# --------------------------------------------------------------------------------------------
# Constraint: an empty result from a source it could not read is UNKNOWN, not zero.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("absent", None),
        ("unparseable", "this is not = = toml\n["),
        ("no cells", '[scorecard]\nanchor_commit = "0000000"\n'),
        ("cell with no anchors", '[[cell]]\nid = "ZZ.SENTINEL.9"\nlevel = 1\nverdict = "pass"\n'),
    ],
)
def test_a_record_it_could_not_read_is_never_a_clean_zero(
    tree: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    name: str,
    body: str | None,
) -> None:
    """Four ways to read nothing, one required answer. Every one of them printed a plausible report at
    some point in some tool in this repository, which is why all four are pinned rather than one."""
    root, _ = tree
    record = tmp_path / f"{name.replace(' ', '_')}.toml"
    if body is not None:
        record.write_text(body, encoding="utf-8")

    code, out = _run(["--scorecard", str(record), "--root", str(root)], capsys)

    assert code == EXIT_INSTRUMENT, f"{name!r} did not fail closed:\n{out}"
    assert "NOT RESOLVING      : 0" not in out, f"{name!r} printed a clean total:\n{out}"
    assert "REFUSING" in out, out


#: Records that PARSE as TOML and are then REJECTED by the reader, one per fault it raises
#: differently, paired with the exception class each fault produces. Every identifier here is
#: invented -- ``ZZ.SENTINEL.9`` and ``bogus`` cannot collide with a real requirement -- so a hit in
#: captured output is proof of disclosure rather than a coincidence.
#:
#: THE THREE ``KeyError`` ROWS ARE THE SECOND DEFECT. ``load_scorecard`` subscripts the record
#: directly in a dozen places, so these never reached the reporter's refusal at all: they escaped as a
#: traceback and exit 1, which is :data:`EXIT_FINDINGS` -- "I could not measure this" rendered as "I
#: measured it, and citations are broken".
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
        '[[cell]]\nid = "{id}"\nlevel = 1\nverdict = "pass"\n\n'
        '[[cell.evidence]]\npath = "engine_module.py"\nline = 2\n',
        "KeyError",
    ),
}


@pytest.mark.parametrize("fault", sorted(_UNREADABLE))
def test_a_refusal_names_no_row_and_no_grading_words(
    tree: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    fault: str,
) -> None:
    """THE REFUSAL PATH ITSELF, which the happy-path scan above cannot reach.

    Nine of the ten refusals in `load_scorecard` open by naming the graded row they rejected, and
    several quote the grading words in full. So interpolating that exception into this tool's own
    refusal disclosed a requirement identifier the first time a record went malformed -- onto stderr,
    which the workflow shipped beside the tool sends to a public run log. The suppression held only
    while every record loaded, which is not a control.

    THIS FUNCTION'S NAME AND EVERY PARAMETER NAME ARE PART OF THE FIXTURE: pytest builds `tmp_path`
    from them and the refusal prints the path it was given, so both must stay clear of
    :data:`BANNED_CONTENT` -- the same trap the clean-run arm above records.
    """
    root, _ = tree
    body, exc_name = _UNREADABLE[fault]
    record = tmp_path / f"{fault}.toml"
    record.write_text(
        '[scorecard]\nanchor_commit = "0000000"\n\n' + body.format(id=SENTINEL_ID),
        encoding="utf-8",
    )

    code, out = _run(["--scorecard", str(record), "--root", str(root)], capsys)

    assert code == EXIT_INSTRUMENT, (
        f"{fault!r} exited {code}, not {EXIT_INSTRUMENT}. Exit {EXIT_FINDINGS} would render "
        f"'I could not measure this' as 'I measured it, and citations are broken':\n{out}"
    )
    assert "REFUSING" in out, out
    assert SENTINEL_ID not in out, f"the refusal disclosed a requirement identifier:\n{out}"
    for banned in BANNED_CONTENT:
        assert banned not in out.lower(), (
            f"the refusal leaked assessment content ({banned!r}):\n{out}"
        )
    # A refusal read nothing, so it prints no total: "nothing was found" and "nothing was looked at"
    # must never render identically, and that is the property this whole tool exists to hold.
    assert "anchors examined" not in out, f"{fault!r} printed a total off an unread record:\n{out}"
    assert "NOT RESOLVING" not in out, out
    # Withholding the diagnostic must not withhold the TRIAGE. The exception CLASS carries nothing
    # from the record and is the whole difference between "the file is unreadable" and "the file
    # parsed and a row is malformed", so it is the one part that crosses.
    assert exc_name in out, f"{fault!r} gave the reader no failure class to act on:\n{out}"


def test_a_git_range_that_will_not_resolve_is_unknown_not_empty(tree: tuple[Path, Path]) -> None:
    """None and the empty set are different answers. Merging them turns a failed `git diff` into
    "this change broke nothing", which is the same clean-looking zero with a different source."""
    root, _ = tree  # not a git repository at all
    assert changed_paths(root, "no-such-ref") is None


def test_an_unresolvable_range_says_so_in_the_report(
    tree: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    root, record = tree
    code, out = _run(
        ["--scorecard", str(record), "--root", str(root), "--changed-since", "no-such-ref"], capsys
    )
    # The anchor population WAS read, so the main answer stands and the run is not an instrument
    # failure. Only the narrowing is unavailable, and it must say so rather than print a zero.
    assert code == EXIT_OK, out
    assert "GIT WOULD NOT ANSWER" in out, out


# --------------------------------------------------------------------------------------------
# Constraint: one locator, not two.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expect", "status", "provenance"),
    [
        (SOURCE, QUOTED, ANCHOR_LOCATED, AT_LINE),
        ("def connect() -> None:\n    pass\n", QUOTED, ANCHOR_GONE, ABSENT),
        (SOURCE + SOURCE, QUOTED, ANCHOR_AMBIGUOUS, AMBIGUOUS),
    ],
)
def test_every_tool_asks_the_locator_the_same_question(
    text: str, expect: str, status: str, provenance: str
) -> None:
    """The report, the gate and the provenance tool share ONE definition of "does this resolve".

    Two matchers would make any disagreement between them a fact about the matchers rather than about
    the record -- the failure the provenance module's own docstring warns about, which it used to
    guard against by hand-copying the code.
    """
    assert locate_anchor(text, expect).status == status
    assert classify(text, expect, 2)[0] == provenance


def test_the_gate_and_the_report_agree_on_the_same_tree(tree: tuple[Path, Path]) -> None:
    """Executable proof of the sharing above: a broken anchor is fatal to `check_anchors` and
    unresolved to `audit`, over the identical inputs."""
    root, record = tree
    (root / "engine_module.py").write_text("def connect() -> None:\n    pass\n", "utf-8")
    cells = load_scorecard(record)

    findings = Findings()
    check_anchors(cells, root, findings)

    assert len(findings.problems) == 1, findings.problems
    assert [o.status in UNRESOLVED for o in audit(cells, root)] == [True]


def test_the_multiline_token_case_survives_the_shared_locator(tmp_path: Path) -> None:
    """Tokens spanning a newline are real -- 42 of the record's roughly 2,000 do. A per-line scan
    finds none of them, so the offset-derived line is a property worth pinning here too."""
    root = tmp_path / "engine"
    root.mkdir()
    (root / "engine_module.py").write_text("a\nb\nfirst\nsecond\nc\n", encoding="utf-8")
    found = locate_anchor((root / "engine_module.py").read_text(encoding="utf-8"), "first\nsecond")
    assert (found.status, found.line) == (ANCHOR_LOCATED, 3)


# --------------------------------------------------------------------------------------------
# The tool runs where it is expected to run.
# --------------------------------------------------------------------------------------------


def test_it_runs_on_a_bare_interpreter_from_an_unrelated_directory(tmp_path: Path) -> None:
    """`-I -S` drops site-packages, PYTHONPATH and the user site dir, standing in for the bare
    `setup-python` a workflow gives it. The record lives in another repository, so the realistic
    host for this tool is a checkout with nothing installed -- the same contract
    tests/test_asvs_verifier_vault_contract.py holds `scorecard.py` to."""
    script = ROOT / "scripts" / "asvs" / "anchor_report.py"
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(script), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"rc={proc.returncode}\n--- stderr ---\n{proc.stderr}"
    assert "--scorecard" in proc.stdout, proc.stdout[:400]
