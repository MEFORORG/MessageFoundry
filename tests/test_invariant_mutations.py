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

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from tests._negative_controls import _test_names

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


def _row(find: str, replace: str = "") -> Any:
    return _MOD.Mutation(id="x", item=1, file="f.py", find=find, replace=replace, tests=("t",))


def test_the_anchor_count_sees_text_that_is_not_there(tmp_path: Path) -> None:
    """Paired control: the count is 0 for absent text, and CRLF files still match."""
    (tmp_path / "f.py").write_bytes(b"a = 1\r\nb = 2\r\n")
    assert _MOD.anchor_count(_row("a = 1\nb = 2\n"), root=tmp_path) == 1
    assert _MOD.anchor_count(_row("c = 3\n"), root=tmp_path) == 0


def test_the_anchor_must_start_a_line(tmp_path: Path) -> None:
    """A shallow anchor must not match inside a deeper-indented line elsewhere."""
    (tmp_path / "f.py").write_bytes(
        b"def f():\n    if x:\n        if total == 0:\n            pass\n"
    )
    assert _MOD.anchor_count(_row("    if total == 0:\n"), root=tmp_path) == 0
    assert _MOD.anchor_count(_row("        if total == 0:\n"), root=tmp_path) == 1


@pytest.mark.parametrize("row", [r for r in _ROWS if r.file.endswith(".py")], ids=lambda m: m.id)
def test_every_break_still_compiles(row: Any) -> None:
    """A break that is a SyntaxError reddens its tests on the import, not on the property."""
    compile(_MOD.mutated_bytes(row), row.file, "exec")


def test_an_empty_replace_is_a_deletion_not_a_missing_field(tmp_path: Path) -> None:
    listed = tmp_path / "list.toml"
    listed.write_text(
        '[[mutation]]\nid = "d"\nitem = 1\nfile = "f.py"\nfind = "x\\n"\nreplace = ""\n'
        'tests = ["tests/t.py::test_a"]\n',
        encoding="utf-8",
    )
    assert [m.replace for m in _MOD.load(listed)] == [""]
    listed.write_text(
        listed.read_text(encoding="utf-8").replace('tests = ["tests/t.py::test_a"]', "")
    )
    with pytest.raises(ValueError, match="missing"):
        _MOD.load(listed)


@pytest.mark.parametrize("row", _ROWS, ids=lambda m: m.id)
def test_every_named_test_exists(row: Any) -> None:
    assert len(row.tests) >= 1
    for node in row.tests:
        rel, _, name = node.partition("::")
        path = _REPO / rel
        assert path.is_file(), f"{row.id}: {rel} does not exist"
        assert name in _test_names(path), f"{row.id}: {rel} defines no {name}"


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


def test_children_run_with_a_safe_path_and_no_inherited_pytest_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTEST_ADDOPTS", "-rN")
    monkeypatch.setenv("PY_COLORS", "1")
    env = _MOD.child_env()
    assert env["PYTHONSAFEPATH"] == "1"
    assert "PYTEST_ADDOPTS" not in env and "PY_COLORS" not in env


def test_a_skipped_listed_test_is_seen() -> None:
    out = "1 skipped\nSKIPPED [1] tests/t.py:3: needs a server\n"
    assert _MOD.skipped_lines(out) == ["SKIPPED [1] tests/t.py:3: needs a server"]


def test_a_crash_is_could_not_judge_not_survived(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> list[object]:
        raise FileNotFoundError("the list moved")

    monkeypatch.setattr(_MOD, "load", boom)
    assert _MOD.main([]) == 2


def test_zero_selected_rows_is_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_MOD, "load", lambda: [])
    assert _MOD.main([]) == 2


def test_an_unknown_id_is_refused() -> None:
    assert _MOD.main(["--only", "no-such-mutation"]) == 2


# --- the verdict-deciding behaviours, pinned so a later edit cannot quietly undo them ------------


def _completed(returncode: int, stdout: str = "") -> Any:
    return _MOD.subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=""
    )


def _one_row_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    (tmp_path / "f.py").write_bytes(b"guard = True\n")
    monkeypatch.setattr(_MOD, "REPO", tmp_path)
    return _MOD.Mutation(
        id="r", item=1, file="f.py", find="guard = True\n", replace="guard = False\n", tests=("t",)
    )


def test_a_skipped_listed_test_is_an_error_not_a_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _one_row_repo(tmp_path, monkeypatch)
    monkeypatch.setattr(_MOD, "_pytest", lambda tests: _completed(0, "SKIPPED [1] t: no server\n"))
    verdict, reason = _MOD.run_one(row)
    assert (verdict, "skipped" in reason) == ("ERROR", True)
    assert (tmp_path / "f.py").read_bytes() == b"guard = True\n"


def test_a_row_that_stays_green_under_its_break_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _one_row_repo(tmp_path, monkeypatch)
    seen: list[bytes] = []

    def fake(tests: tuple[str, ...]) -> Any:
        seen.append((tmp_path / "f.py").read_bytes())
        return _completed(0)

    monkeypatch.setattr(_MOD, "_pytest", fake)
    assert _MOD.run_one(row)[0] == "SURVIVED"
    # Green before, broken during, green again after the revert: three runs, the middle one mutated.
    assert seen == [b"guard = True\n", b"guard = False\n", b"guard = True\n"]
    assert not (tmp_path / "f.py.invariant-mutation-backup").exists()


def test_a_survivor_outranks_an_error_in_the_exit_code() -> None:
    assert _MOD.exit_code({"KILLED": 3, "SURVIVED": 1, "ERROR": 2}) == 1
    assert _MOD.exit_code({"KILLED": 3, "SURVIVED": 0, "ERROR": 1}) == 2
    assert _MOD.exit_code({"KILLED": 3, "SURVIVED": 0, "ERROR": 0}) == 0


def test_one_rows_crash_does_not_stop_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    other = _MOD.Mutation(id="z", item=1, file="g.py", find="b\n", replace="", tests=("t",))

    def run_one(m: Any) -> tuple[str, str]:
        if m.id == "x":
            raise TimeoutError("hung")
        return "SURVIVED", "green under the break"

    monkeypatch.setattr(_MOD, "run_one", run_one)
    assert _MOD.judge([_row("a\n"), other]) == {"KILLED": 0, "SURVIVED": 1, "ERROR": 1}


def test_a_leftover_backup_is_restored_only_over_its_own_break(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _one_row_repo(tmp_path, monkeypatch)
    target, backup = tmp_path / "f.py", tmp_path / "f.py.invariant-mutation-backup"
    backup.write_bytes(b"guard = True\n")
    target.write_bytes(b"guard = False\n")  # a hard kill left the break in place
    assert _MOD.restore_leftovers([row]) == ["f.py"]
    assert (target.read_bytes(), backup.exists()) == (b"guard = True\n", False)

    # The file moved on since the kill: writing the old bytes back would destroy that work.
    backup.write_bytes(b"guard = True\n")
    target.write_bytes(b"guard = True\nnew_work = 1\n")
    with pytest.raises(_MOD.LeftoverBackup):
        _MOD.restore_leftovers([row])
    assert target.read_bytes() == b"guard = True\nnew_work = 1\n"
