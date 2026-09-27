# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every ADR file in docs/adr/ is reachable from docs/adr/README.md (BACKLOG #1516).

A file is reachable when its number's index row links it, or names it as a DECLARED COMPANION (one
number, one row, two files -- ADR 0013 is the live instance). The ledger gate already asks the
companion question for files a commit ADDS. Nothing asked it of the files that already exist, so a
tool that keys on the ADR number got one file per number and dropped the other with no error. Two
audits of every ADR each graded 0013's main file and never opened its companion.

The companion rule is defined once, in scripts/hooks/ledger_check.py, and imported here rather than
restated, so the commit-time gate and this corpus check cannot drift apart.

THE POSITIVE CONTROLS ARE THE POINT. "Nothing unrepresented" is also what a broken enumeration
prints, which is the false green that produced the row. So the real-corpus test also asserts that the
known companion is found and classified, and the tmp_path tests show an unlisted file is reported.
No test pins a file or row count: ADRs land weekly and a pinned count is red for the wrong reason.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADR_DIR = ROOT / "docs" / "adr"
KNOWN_PRIMARY = "0013-query-response-orchestration.md"
KNOWN_COMPANION = "0013-increment-2-reingress-design.md"
README_HEAD = "# Architecture Decision Records\n\n| ADR | Decision | Status |\n|---|---|---|\n"


@pytest.fixture(scope="module")
def ledger_check() -> ModuleType:
    # The hook is a stdlib script, not a package, so load it by path.
    path = ROOT / "scripts" / "hooks" / "ledger_check.py"
    spec = importlib.util.spec_from_file_location("ledger_check", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _corpus(tmp_path: Path, rows: list[str], files: list[str]) -> Path:
    adr = tmp_path / "adr"
    adr.mkdir()
    (adr / "README.md").write_text(README_HEAD + "".join(r + "\n" for r in rows), encoding="utf-8")
    for name in files:
        (adr / name).write_text(f"# {name}\n", encoding="utf-8")
    return adr


def test_every_adr_file_in_the_tree_is_represented_in_the_index(ledger_check: ModuleType) -> None:
    coverage = ledger_check.adr_index_coverage(ADR_DIR)

    # Positive controls first. Without them an empty or deduplicated enumeration passes the last
    # assertion exactly as a clean corpus does.
    assert len(coverage.files) > 150, (
        f"the enumeration found only {len(coverage.files)} ADR files in {ADR_DIR}; it is broken"
    )
    # Both of 0013's files: a number-keyed dedupe drops one of them, and which one depends on sort order.
    assert KNOWN_COMPANION in coverage.files, "the enumeration dropped ADR 0013's companion file"
    assert KNOWN_PRIMARY in coverage.files, "the enumeration dropped ADR 0013's main file"
    assert KNOWN_COMPANION in coverage.companions, (
        f"{KNOWN_COMPANION} is not classified as a declared companion: {coverage.companions}"
    )
    # A classifier that calls every file a companion would pass the line above.
    assert KNOWN_PRIMARY not in coverage.companions, f"{KNOWN_PRIMARY} is classified as a companion"

    assert coverage.unrepresented == [], (
        f"ADR file(s) reachable from no row in docs/adr/README.md: {coverage.unrepresented}. "
        "Add the file's own row, or name it inside its number's row if it is a declared companion."
    )


def test_an_unlisted_file_in_the_corpus_is_reported(
    tmp_path: Path, ledger_check: ModuleType
) -> None:
    adr = _corpus(
        tmp_path,
        rows=["| [0001](0001-first.md) | First | Accepted |"],
        files=["0001-first.md", "0002-orphan.md"],
    )

    coverage = ledger_check.adr_index_coverage(adr)

    assert coverage.files == ["0001-first.md", "0002-orphan.md"]
    assert coverage.unrepresented == ["0002-orphan.md"]


def test_a_second_file_under_one_number_is_enumerated_and_reported_when_undeclared(
    tmp_path: Path, ledger_check: ModuleType
) -> None:
    # The exact loss the audits hit: keying on the number collapses these two files into one.
    adr = _corpus(
        tmp_path,
        rows=["| [0013](0013-main.md) | Main decision | Accepted |"],
        files=["0013-main.md", "0013-stray.md"],
    )

    coverage = ledger_check.adr_index_coverage(adr)

    assert coverage.files == ["0013-main.md", "0013-stray.md"]
    assert coverage.companions == []
    assert coverage.unrepresented == ["0013-stray.md"]


def test_a_companion_named_inside_its_row_is_represented(
    tmp_path: Path, ledger_check: ModuleType
) -> None:
    adr = _corpus(
        tmp_path,
        rows=[
            "| [0013](0013-main.md) | Main. Design companion: "
            "[0013-design](0013-design.md) | Accepted |"
        ],
        files=["0013-main.md", "0013-design.md"],
    )

    coverage = ledger_check.adr_index_coverage(adr)

    assert coverage.companions == ["0013-design.md"]
    assert coverage.unrepresented == []


def test_a_row_written_without_the_space_after_the_pipe_is_seen(
    tmp_path: Path, ledger_check: ModuleType
) -> None:
    # BACKLOG #2003. The gate's row count already accepted `|[0002]`, while index_row needed
    # `| [0002]`, so this file read as unrepresented here and as indexed at commit time.
    row = "|[0002](0002-tight.md) | Tight row | Accepted |"
    adr = _corpus(tmp_path, rows=[row], files=["0002-tight.md"])

    coverage = ledger_check.adr_index_coverage(adr)

    assert coverage.unrepresented == []
    # The row's own link, not a companion: the classifier anchors on the same pattern.
    assert coverage.companions == []
    assert ledger_check.index_row(README_HEAD + row + "\n", "0002") == row
    assert ledger_check.INDEX_ROW.findall(README_HEAD + row + "\n") == ["0002"]
    # A no-break space after the pipe is still a row, as `\s*` counted it before the fix.
    nbsp = "|\xa0[0002](0002-tight.md) | Tight row | Accepted |"
    assert ledger_check.index_rows(README_HEAD + nbsp + "\n") == [("0002", nbsp)]


def test_the_shared_companion_predicate(ledger_check: ModuleType) -> None:
    # Pins the predicate only. The gate's own use of it is covered by test_ledger_check.py's
    # declared-companion and reused-number tests.
    row = "| [0013](0013-main.md) | Main. Companion: [0013-design](0013-design.md) | Accepted |"
    assert ledger_check.row_names_file(row, "0013-main.md")
    assert ledger_check.row_names_file(row, "0013-design.md")
    assert not ledger_check.row_names_file(row, "0013-stray.md")
    assert ledger_check.index_row(README_HEAD + row + "\n", "0013") == row
    assert ledger_check.index_row(README_HEAD + row + "\n", "0014") == ""


@pytest.mark.parametrize(
    "stray",
    [
        "0013-mai.md",  # a prefix of the row's own link
        "0013-design-v2.md",  # the companion's name plus a suffix: a prefix match the other way
        "0013-desig.md",
        "0013-main.m.md",
    ],
)
def test_a_near_miss_filename_is_not_named_by_the_row(ledger_check: ModuleType, stray: str) -> None:
    # BACKLOG #2001. The predicate was `basename.removesuffix(".md") in row`, a substring test, so
    # `0013-mai` matched inside `0013-main.md` and the stray file read as a declared companion.
    row = "| [0013](0013-main.md) | Main. Companion: [0013-design](0013-design.md) | Accepted |"
    assert not ledger_check.row_names_file(row, stray)


@pytest.mark.parametrize("target", ["0013-design.md", "./0013-design.md", "0013-design.md#a"])
def test_every_accepted_link_form_names_the_file(ledger_check: ModuleType, target: str) -> None:
    row = f"| [0013](0013-main.md) | Main. Companion: [design]({target}) | Accepted |"
    assert ledger_check.row_names_file(row, "0013-design.md")


@pytest.mark.parametrize(
    "link",
    [
        "[design](docs/adr/0013-design.md)",  # resolves to docs/adr/docs/adr/: a dead link
        "[design](<0013-design.md>)",
        '[design](0013-design.md "title")',
        "[design](0013-design%2Emd)",
        "`[design](0013-design.md)`",  # inline code renders no link
        "<!-- [design](0013-design.md) -->",
        "\\[design](0013-design.md)",  # an escaped bracket renders no link
        "design](0013-design.md)",  # no opening bracket, so no link
    ],
)
def test_a_link_form_outside_the_one_accepted_form_names_nothing(
    ledger_check: ModuleType, link: str
) -> None:
    # BACKLOG #2001. Narrow on purpose: each extra form is a place where the gate's regex and the
    # renderer disagree, and every real row uses the sibling form. Refusing fails closed.
    row = f"| [0013](0013-main.md) | Main. Companion: {link} | Accepted |"
    assert not ledger_check.row_names_file(row, "0013-design.md")


@pytest.mark.parametrize("target", ["0190-with space.md", "<0190-with space.md>"])
def test_a_name_with_a_space_cannot_be_linked_so_it_is_refused(
    ledger_check: ModuleType, target: str
) -> None:
    # ADR_FILE admits a space (BACKLOG #1871), but the one accepted link form does not. The gate
    # refuses such a file rather than read a form the renderer may not agree with. Fail closed.
    row = f"| [0190]({target}) | Spaced | Accepted |"
    assert not ledger_check.row_names_file(row, "0190-with space.md")


def test_a_filename_in_PLAIN_TEXT_does_not_name_the_file(ledger_check: ModuleType) -> None:
    # The substring test accepted this. A reader of the rendered index finds no link to follow.
    row = "| [0013](0013-main.md) | Main. See also 0013-design.md | Accepted |"
    assert not ledger_check.row_names_file(row, "0013-design.md")


@pytest.mark.parametrize("own", ["(./0190-x.md)", "(0190-x.md#top)"])
def test_the_rows_own_link_in_any_accepted_form_is_not_a_companion(
    tmp_path: Path, ledger_check: ModuleType, own: str
) -> None:
    # "Is this the row's own file" and "does the row name this file" read links with one parser, so
    # a form one accepts cannot make the other call the primary file a companion.
    adr = _corpus(tmp_path, rows=[f"| [0190]{own} | X | Accepted |"], files=["0190-x.md"])

    coverage = ledger_check.adr_index_coverage(adr)

    assert coverage.unrepresented == []
    assert coverage.companions == []


def test_a_row_hidden_after_a_unicode_line_separator_is_seen_by_nothing(
    ledger_check: ModuleType,
) -> None:
    # BACKLOG #2003. str.splitlines() breaks on U+2028, INDEX_ROW's `^` does not. A row finder that
    # split lines itself returned this hidden "row" while the row count never saw it, so a colliding
    # 0001-evil.md read as a declared companion. index_rows is now the one enumeration.
    readme = (
        README_HEAD
        + "prose\u2028| [0001](0001-first.md) | x [c](0001-evil.md) |\n"
        + "| [0001](0001-first.md) | First | Accepted |\n"
    )
    assert ledger_check.index_rows(readme) == [
        ("0001", "| [0001](0001-first.md) | First | Accepted |")
    ]
    assert not ledger_check.row_names_file(ledger_check.index_row(readme, "0001"), "0001-evil.md")


def test_a_near_miss_file_in_the_corpus_is_reported(
    tmp_path: Path, ledger_check: ModuleType
) -> None:
    # The ledger item's own example, through the corpus check that shares the predicate.
    adr = _corpus(
        tmp_path,
        rows=["| [0001](0001-first.md) | First | Accepted |"],
        files=["0001-first.md", "0001-fir.md"],
    )

    coverage = ledger_check.adr_index_coverage(adr)

    assert coverage.unrepresented == ["0001-fir.md"]
    assert coverage.companions == []
