# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/quality/shard_tests.py splits the suite for quality-advisory.yml's `coverage-shard` matrix.

The property that matters is that the shards PARTITION pytest's file set: every file in exactly one
shard. A file in no shard is a file whose coverage silently stops counting, and nothing downstream
would report it, because the combined coverage.xml still lists every source file.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "quality" / "shard_tests.py"


@pytest.fixture(scope="module")
def mod() -> ModuleType:
    spec = importlib.util.spec_from_file_location("shard_tests", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def files(mod: ModuleType) -> list[str]:
    return mod.collected_files()


def test_the_file_set_reaches_both_testpaths(files: list[str]) -> None:
    # Positive controls: this file, and the web console tier the coverage job deliberately keeps.
    assert len(files) >= 1000
    assert "tests/test_quality_shard_tests.py" in files
    assert any(f.startswith("packaging/messagefoundry-webconsole/tests/") for f in files)
    assert all(Path(f).name.startswith("test_") or f.endswith("_test.py") for f in files)


def test_the_file_set_skips_what_pytest_does_not_recurse_into(
    mod: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n', encoding="utf-8"
    )
    for rel in (
        "tests/test_a.py",
        "tests/sub/b_test.py",
        "tests/helper.py",
        "tests/.hidden/test_c.py",
        "tests/node_modules/test_d.py",
        "tests/build/test_e.py",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("", encoding="utf-8")
    assert mod.collected_files(tmp_path) == ["tests/sub/b_test.py", "tests/test_a.py"]


@pytest.mark.parametrize("shards", [2, 4, 7])
def test_the_shards_partition_the_file_set(mod: ModuleType, files: list[str], shards: int) -> None:
    assigned = [mod.shard_of(f, shards) for f in files]
    assert len(assigned) == len(files) >= 1000
    assert set(assigned) == set(range(1, shards + 1)), "every shard must hold at least one file"


def test_the_assignment_is_a_pure_function_of_the_path(mod: ModuleType) -> None:
    # Every shard job computes the partition on its own, so the value is pinned: a host-dependent
    # hash, such as Python's salted hash(), would give each runner a different split.
    assert mod.shard_of("tests/test_x.py", 4) == mod.shard_of("tests/test_x.py", 4)
    assert mod.shard_of("tests/test_quality_shard_tests.py", 4) == 2


def test_main_prints_one_shard_and_refuses_an_out_of_range_index(
    mod: ModuleType, files: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    printed: list[str] = []
    for shard in (1, 2, 3, 4):
        assert mod.main(["--shard", str(shard), "--of", "4"]) == 0
        printed += capsys.readouterr().out.splitlines()
    tooling = mod.tooling_files()
    assert len(tooling) >= 100 and tooling <= set(files), "the manifest names files pytest collects"
    assert sorted(printed) == [f for f in files if f not in tooling]
    with pytest.raises(SystemExit):
        mod.main(["--shard", "5", "--of", "4"])


# --- the engine suite (BACKLOG #5247) -------------------------------------------------------------


@pytest.fixture(scope="module")
def engine(mod: ModuleType) -> dict[int, list[str]]:
    return mod.partition(2, "engine")


def test_the_engine_shards_partition_the_engine_step_s_file_set(
    mod: ModuleType, files: list[str], engine: dict[int, list[str]]
) -> None:
    """Every file the engine step runs, in exactly one of the two shards: testpaths, less the
    tooling tier and the web console package. This half reads this file's own walk of testpaths;
    ci.yml's guard step compares the same split with pytest's real collection."""
    tooling = mod.tooling_files()
    expected = sorted(
        f
        for f in files
        if f not in tooling and not f.startswith("packaging/messagefoundry-webconsole/")
    )
    listed = engine[1] + engine[2]
    print(f"[shards] engine: shard 1 {len(engine[1])}, shard 2 {len(engine[2])} files")
    assert sorted(listed) == expected
    assert len(set(listed)) == len(listed), "a file is in both engine shards"
    assert engine[1] and engine[2], "an engine shard is empty"


def test_the_engine_suite_leaves_the_console_package_out_and_the_coverage_suite_keeps_it(
    mod: ModuleType, engine: dict[int, list[str]]
) -> None:
    console = "packaging/messagefoundry-webconsole/tests/"
    assert not any(f.startswith(console) for files in engine.values() for f in files)
    coverage = mod.partition(4, "coverage")
    assert any(f.startswith(console) for files in coverage.values() for f in files)
    # Engine files whose names merely mention the console stay in: the glob is the package's name.
    assert any("webconsole" in f for files in engine.values() for f in files)


def test_the_connscale_smoke_is_held_in_shard_one(mod: ModuleType) -> None:
    """scripts/connscale_harvest.py joins its readings to the `test (...)` jobs, and only that job
    sets MEFOR_CONNSCALE_LEG. Its hash puts it in shard 2, so the hold is doing real work.

    Falsified by emptying ENGINE_SHARD_ONE: RED on the first assertion. Restored."""
    smoke = "tests/test_connscale_smoke.py"
    assert (_ROOT / smoke).is_file()
    assert mod.assign(smoke, 2, "engine") == 1
    assert mod.shard_of(smoke, 2) == 2, "the hold is no longer load-bearing; re-read why it exists"
    assert mod.assign(smoke, 2, "coverage") == 2, "the hold must not move the coverage split"


def test_the_collection_reader_takes_node_ids_and_nothing_else(mod: ModuleType) -> None:
    output = "\n".join(
        [
            "tests/test_a.py::test_one",
            "tests/test_a.py::TestX::test_two[param-1]",
            "tests\\test_b.py::test_three",
            "",
            "============================== warnings summary ===============",
            "tests\\test_c.py:22",
            "  D:\\checkout\\tests\\test_c.py:22: DeprecationWarning: something::else",
            "50512/58494 tests collected (7982 deselected) in 80.83s (0:01:20)",
        ]
    )
    assert mod.collected_by_pytest(output) == {"tests/test_a.py", "tests/test_b.py"}


def test_the_partition_faults_name_a_missing_file_a_doubled_file_and_an_empty_collection(
    mod: ModuleType,
) -> None:
    split = {1: ["tests/test_a.py", "tests/test_b.py"], 2: ["tests/test_b.py", "tests/test_q.py"]}
    faults = mod.partition_faults(split, {"tests/test_a.py", "tests/test_b.py", "tests/test_c.py"})
    assert faults == [
        "tests/test_b.py is in shards [1, 2]",
        "tests/test_c.py is collected by pytest and in no shard",
    ]
    # A listed file that collects nothing (every test in it deselected) is not a fault.
    assert (
        mod.partition_faults({1: ["tests/test_a.py", "tests/test_q.py"]}, {"tests/test_a.py"}) == []
    )
    # An empty collection is a fault, never a vacuous pass.
    assert mod.partition_faults({1: ["tests/test_a.py"]}, set())


def test_check_collection_exits_by_what_pytest_collected(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, engine: dict[int, list[str]]
) -> None:
    """The real collection is a ci.yml step, too slow for a unit test; this drives its verdicts on
    a stubbed one. Falsified by returning 0 on a fault: RED on the second call. Restored."""

    def collect(stdout: str, returncode: int = 0) -> None:
        done = subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")
        monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: done)

    every = engine[1] + engine[2]
    collect("".join(f"{path}::test_x\n" for path in every))
    assert mod.main(["--suite", "engine", "--of", "2", "--check-collection", "--", "-m", "x"]) == 0
    collect("".join(f"{path}::test_x\n" for path in [*every, "tests/test_nowhere.py"]))
    assert mod.main(["--suite", "engine", "--of", "2", "--check-collection"]) == 1
    collect("", returncode=4)
    assert mod.main(["--suite", "engine", "--of", "2", "--check-collection"]) == 2
    with pytest.raises(SystemExit):
        mod.main(["--suite", "engine", "--shard", "1", "--of", "2", "--check-collection"])
    with pytest.raises(SystemExit):
        mod.main(["--shard", "1", "--of", "2", "-m", "x"])
