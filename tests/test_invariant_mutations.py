# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The mutation list stays applicable, and its runner scores by exit code (BACKLOG #1746, 4 and 5).

``scripts/ci/invariant_mutations.py`` runs the checked-in breaks in
``scripts/ci/invariant_mutations.toml``; each break must turn its named tests red. Running every
break costs minutes, so it is not done here. What IS done here, on every engine leg, is the half that
rots silently: a refactor that moves a row's ``find`` text leaves the row breaking nothing, and the
runner would then report ERROR on its next run rather than on the PR that caused it. These tests
fail on that PR instead.

The runner's scoring rules are pinned too, because they are the whole of limb 4: only pytest exit 1
with a ``FAILED`` line naming a listed test is a kill, and exit 0 is a survivor, and every other code
means the tests never judged the break.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "ci" / "invariant_mutations.py"

#: Rows at landing: eight, one per offline-reachable instance of the thirteen. A floor, so deleting
#: rows to make a stale list pass is a visible change to this number.
_MIN_ROWS = 8


def _load() -> Any:
    """Import the script by path -- ``scripts/`` is not a package."""
    spec = importlib.util.spec_from_file_location("invariant_mutations", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["invariant_mutations"] = module
    spec.loader.exec_module(module)
    return module


_MOD = _load()
_ROWS = _MOD.load()


def test_the_list_is_populated_and_every_row_is_distinct() -> None:
    assert len(_ROWS) >= _MIN_ROWS, [m.id for m in _ROWS]
    assert len({m.id for m in _ROWS}) == len(_ROWS)
    assert all(m.find != m.replace for m in _ROWS), "a row whose break changes nothing"


@pytest.mark.parametrize("row", _ROWS, ids=lambda m: m.id)
def test_every_row_breaks_text_that_exists_exactly_once(row: Any) -> None:
    count = _MOD.anchor_count(row)
    assert count == 1, (
        f"{row.id}: `find` occurs {count} time(s) in {row.file}. The code moved; re-anchor the row on "
        f"the new text and re-run `python scripts/ci/invariant_mutations.py --only {row.id}`"
    )


def test_the_anchor_count_sees_text_that_is_not_there(tmp_path: Path) -> None:
    """Paired control: the count is 0 for absent text, and CRLF files still match."""
    (tmp_path / "f.py").write_bytes(b"a = 1\r\nb = 2\r\n")
    row = _MOD.Mutation(
        id="x", item=1, file="f.py", find="a = 1\nb = 2\n", replace="", tests=("t",)
    )
    assert _MOD.anchor_count(row, root=tmp_path) == 1
    absent = _MOD.Mutation(id="y", item=1, file="f.py", find="c = 3\n", replace="", tests=("t",))
    assert _MOD.anchor_count(absent, root=tmp_path) == 0


def _defined_tests(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test")
    }


@pytest.mark.parametrize("row", _ROWS, ids=lambda m: m.id)
def test_every_named_test_exists(row: Any) -> None:
    assert len(row.tests) >= 1
    for node in row.tests:
        rel, _, name = node.partition("::")
        path = _REPO / rel
        assert path.is_file(), f"{row.id}: {rel} does not exist"
        assert name in _defined_tests(path), f"{row.id}: {rel} defines no {name}"


@pytest.mark.parametrize(
    ("returncode", "output", "verdict"),
    [
        (1, "FAILED tests/t.py::test_a - AssertionError\n", "KILLED"),
        (1, "FAILED tests/t.py::test_a[p1] - AssertionError\n", "KILLED"),
        (0, "1 passed\n", "SURVIVED"),
        # A red that is not one of the row's tests did not judge the break.
        (1, "FAILED tests/other.py::test_z - boom\n", "ERROR"),
        # Exit 1 with no FAILED line: something failed, but not a listed test.
        (1, "1 failed\n", "ERROR"),
        (2, "ERROR collecting tests/t.py\n", "ERROR"),
        (4, "ERROR: not found: tests/t.py::test_a\n", "ERROR"),
        (5, "no tests ran\n", "ERROR"),
    ],
)
def test_a_break_is_scored_by_exit_code_and_failed_lines(
    returncode: int, output: str, verdict: str
) -> None:
    assert _MOD.score(returncode, output, ("tests/t.py::test_a",)) == verdict


def test_the_summary_line_is_never_what_decides() -> None:
    """Exit 0 is a survivor even when the text claims a failure; the words do not score it."""
    assert _MOD.score(0, "1 failed\nFAILED tests/t.py::test_a\n", ("tests/t.py::test_a",)) == (
        "SURVIVED"
    )


def test_children_run_with_a_safe_path() -> None:
    assert _MOD.child_env()["PYTHONSAFEPATH"] == "1"


def test_zero_selected_rows_is_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_MOD, "load", lambda: [])
    assert _MOD.main([]) == 2


def test_an_unknown_id_is_refused() -> None:
    assert _MOD.main(["--only", "no-such-mutation"]) == 2
