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


def test_the_shared_companion_predicate(ledger_check: ModuleType) -> None:
    # Pins the predicate only. The gate's own use of it is covered by test_ledger_check.py's
    # declared-companion and reused-number tests.
    row = "| [0013](0013-main.md) | Main. Companion: [0013-design](0013-design.md) | Accepted |"
    assert ledger_check.row_names_file(row, "0013-main.md")
    assert ledger_check.row_names_file(row, "0013-design.md")
    assert not ledger_check.row_names_file(row, "0013-stray.md")
    assert ledger_check.index_row(README_HEAD + row + "\n", "0013") == row
    assert ledger_check.index_row(README_HEAD + row + "\n", "0014") == ""
