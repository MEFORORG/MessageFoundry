# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/quality/shard_tests.py splits the suite for quality-advisory.yml's `coverage-shard` matrix.

The property that matters is that the shards PARTITION pytest's file set: every file in exactly one
shard. A file in no shard is a file whose coverage silently stops counting, and nothing downstream
would report it, because the combined coverage.xml still lists every source file.
"""

from __future__ import annotations

import importlib.util
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
