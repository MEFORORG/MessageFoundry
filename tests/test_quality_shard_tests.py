# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/quality/shard_tests.py splits the suite for quality-advisory.yml's `coverage-shard` matrix.

The property that matters is that the shards PARTITION pytest's file set: every file in exactly one
shard. A file in no shard is a file whose coverage silently stops counting, and nothing downstream
would report it, because the combined coverage.xml still lists every source file.
"""

from __future__ import annotations

import importlib.util
import re
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


def _engine_shards() -> int:
    """ci.yml's engine suite shard count, read from its shard jobs' run lines, so this file grades
    the split those jobs run. tests/test_ci_engine_suite_shards.py holds each `--of` there to its
    own count of shard jobs."""
    text = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    counts = set(
        re.findall(r'shard_tests\.py --suite engine --shard "\$TEST_SHARD" --of (\d+)', text)
    )
    assert len(counts) == 1, f"ci.yml's engine shard jobs disagree on --of: {sorted(counts)}"
    return int(counts.pop())


_ENGINE_SHARDS = _engine_shards()


@pytest.fixture(scope="module")
def engine(mod: ModuleType) -> dict[int, list[str]]:
    return mod.partition(_ENGINE_SHARDS, "engine")


def test_the_test_shards_partition_the_engine_step_s_file_set(
    mod: ModuleType, files: list[str], engine: dict[int, list[str]]
) -> None:
    """Every file the engine step runs, in exactly one of the shards: testpaths, less the
    tooling tier and the web console package. This half reads this file's own walk of testpaths;
    ci.yml's guard step compares the same split with pytest's real collection."""
    tooling = mod.tooling_files()
    expected = sorted(
        f
        for f in files
        if f not in tooling and not f.startswith("packaging/messagefoundry-webconsole/")
    )
    assert sorted(engine) == list(range(1, _ENGINE_SHARDS + 1))
    listed = [f for shard in sorted(engine) for f in engine[shard]]
    sizes = ", ".join(f"shard {n} {len(engine[n])}" for n in sorted(engine))
    print(f"[shards] engine: {sizes} files")
    assert sorted(listed) == expected
    assert len(set(listed)) == len(listed), "a file is in two test shards"
    assert all(engine.values()), "a test shard is empty"


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
    sets MEFOR_CONNSCALE_LEG. Its hash puts it in shard 3 of 3, so the hold is doing real work.

    Falsified by emptying ENGINE_SUITE_SHARD_ONE: RED on the first assertion. Restored."""
    smoke = "tests/test_connscale_smoke.py"
    assert (_ROOT / smoke).is_file()
    assert mod.assign(smoke, _ENGINE_SHARDS, "engine") == 1
    by_hash = mod.shard_of(smoke, _ENGINE_SHARDS)
    assert by_hash != 1, "the hold is no longer load-bearing; re-read why it exists"
    assert mod.assign(smoke, _ENGINE_SHARDS, "coverage") == by_hash, (
        "the hold must not move the coverage split"
    )


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
    mod: ModuleType, engine: dict[int, list[str]]
) -> None:
    """The real collection is a ci.yml step, too slow for a unit test; this drives its verdicts on
    a stubbed one. Falsified by returning 0 on a fault: RED on the second call. Restored."""

    def check(*answers: tuple[list[str], int]) -> int:
        """Each call of the stub answers with the next (files, exit code) pair."""
        queue = list(answers)

        def run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            files, code = queue.pop(0)
            out = "".join(f"{path}::test_x\n" for path in files)
            return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr="")

        result: int = mod.check_collection(_ENGINE_SHARDS, "engine", ["-m", "x"], run=run)
        assert not queue, "the stub was asked fewer times than expected"
        return result

    every = [f for shard in sorted(engine) for f in engine[shard]]
    quiet, rest = every[0], every[1:]
    assert check((every, 0)) == 0
    assert check(([*every, "tests/test_nowhere.py"], 0)) == 1
    assert check(([], 4)) == 2
    # A listed file the suite collected nothing from: allowed when it is quiet named too (exit 5),
    # a fault when naming it collects tests (a collection-time ignore a shard would bypass).
    assert check((rest, 0), ([], 5)) == 0
    assert check((rest, 0), ([quiet], 0)) == 1
    assert check((rest, 0), ([], 3)) == 2
    for bad in ("0", "-1"):
        with pytest.raises(SystemExit):
            mod.main(["--suite", "engine", "--of", bad, "--check-collection"])
    with pytest.raises(SystemExit):
        mod.main(["--suite", "engine", "--shard", "1", "--of", "2", "--check-collection"])
    with pytest.raises(SystemExit):
        mod.main(["--shard", "1", "--of", "2", "--", "-m", "x"])


# --- the tooling suite (owner ruling 2026-11-24) --------------------------------------------------


@pytest.fixture(scope="module")
def tooling_shards() -> int:
    """ci.yml's tooling shard count, read from its partition guard, which
    tests/test_ci_tooling_gate.py holds to the windows-2025 legs' `of`. A fixture, so a drifted
    guard line fails these tests rather than this module's collection."""
    text = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    counts = set(re.findall(r"shard_tests\.py --suite tooling --of (\d+) --check-collection", text))
    assert len(counts) == 1, f"ci.yml's tooling guard reads {sorted(counts)}"
    return int(counts.pop())


@pytest.fixture(scope="module")
def tooling(mod: ModuleType, tooling_shards: int) -> dict[int, list[str]]:
    return mod.partition(tooling_shards, "tooling")


def test_the_tooling_shards_partition_exactly_the_manifest(
    mod: ModuleType,
    files: list[str],
    tooling: dict[int, list[str]],
    engine: dict[int, list[str]],
    tooling_shards: int,
) -> None:
    """Every manifest file in exactly one tooling shard, no other file in any, and the tooling and
    engine suites disjoint, so no file runs on both tiers or on neither."""
    manifest = mod.tooling_files()
    listed = [f for shard in sorted(tooling) for f in tooling[shard]]
    sizes = ", ".join(f"shard {n} {len(tooling[n])}" for n in sorted(tooling))
    print(f"[shards] tooling: {sizes} files")
    assert sorted(tooling) == list(range(1, tooling_shards + 1))
    assert len(set(listed)) == len(listed), "a file is in two tooling shards"
    assert set(listed) == manifest & set(files) == manifest
    assert all(tooling.values()), "a tooling shard is empty"
    engine_files = {f for shard in engine.values() for f in shard}
    assert not engine_files & manifest


def test_the_tooling_split_is_salted_and_the_salt_moves_it(mod: ModuleType) -> None:
    """The salt is what balanced the split on the measured junit (TOOLING_SALT holds the numbers).
    Pinned, as the coverage split's value is, so a dropped or changed salt reds here rather than as
    a slow shard. The file is one of the tier's largest and one the salt moves: shard 2 unsalted.
    Falsified by returning `shard_of(path, shards)` for the tooling suite: RED on the first
    assertion. Restored."""
    path = "tests/test_worktree_prune_merged.py"
    assert mod.assign(path, 3, "tooling") == 3
    assert mod.shard_of(path, 3) == 2
    manifest = sorted(mod.tooling_files())
    moved = [p for p in manifest if mod.assign(p, 3, "tooling") != mod.shard_of(p, 3)]
    assert moved, "the salted split equals the unsalted one, so the salt does nothing"


def test_main_prints_a_tooling_shard(
    mod: ModuleType,
    tooling: dict[int, list[str]],
    tooling_shards: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert mod.main(["--suite", "tooling", "--shard", "1", "--of", str(tooling_shards)]) == 0
    assert capsys.readouterr().out.splitlines() == tooling[1]
    assert mod.main(["--suite", "tooling", "--shard", "1", "--of", "1"]) == 0
    assert sorted(capsys.readouterr().out.splitlines()) == sorted(mod.tooling_files())


def test_check_collection_judges_the_tooling_suite(
    mod: ModuleType, tooling: dict[int, list[str]], tooling_shards: int
) -> None:
    """The guard's verdicts on the tooling split, on a stubbed collection: a collected file outside
    the manifest is a fault. That is a file carrying the `tooling` mark itself, the shape
    tests/test_scan_forbidden_site_prefix_width.py had until the guard found it."""

    def check(files: list[str]) -> int:
        def run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            out = "".join(f"{path}::test_x\n" for path in files)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=out, stderr="")

        result: int = mod.check_collection(tooling_shards, "tooling", ["-m", "tooling"], run=run)
        return result

    every = [f for shard in sorted(tooling) for f in tooling[shard]]
    assert check(every) == 0
    assert check([*every, "tests/test_quality_shard_tests_not_in_the_manifest.py"]) == 1
