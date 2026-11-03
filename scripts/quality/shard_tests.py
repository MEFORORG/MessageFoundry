# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Print the test files one test shard runs, one path per line.

quality-advisory.yml's `coverage-shard` matrix runs the suite in N jobs and the `coverage` job
combines their data. Each shard calls this with its own `--shard`, so the split must be a pure
function of the tree: every shard computes the same partition without talking to the others.

A FILE GOES TO SHARD `crc32(path) mod N`. The whole file, never part of one, so `--dist loadfile`
inside a shard keeps its meaning: a module's tests and its module-scoped fixtures stay together.
A new file lands on a shard without anyone editing a list, and no file moves when another is
added. The balance this buys is measured, not assumed; the workflow's `coverage-shard` header has
the numbers.

The file set is pytest's own: `testpaths` from pyproject.toml, its default `test_*.py` and
`*_test.py` patterns, and its default `norecursedirs`. tests/test_quality_shard_tests.py holds
the partition to that set, so a file pytest collects can never fall between two shards.

TOOLING FILES ARE LEFT OUT. The coverage step deselects them with `-m 'not tooling'`, so a shard
that held one would import and collect it for nothing, and the balance would count files that do
not run. The list is tests/tooling_manifest.txt, read through its own parser.

`--suite engine` IS ci.yml's ENGINE `Tests (pytest)` STEP, split across the `test` job and the
`test-shard2` job (BACKLOG #5247). It differs from the coverage split in two ways, both constants
below. It leaves out the web console package, which that step subtracts with `--ignore-glob`
because the `webconsole` job runs it (BACKLOG #1027), so a shard naming one of its files would run
it twice. And it holds the connscale smoke in shard 1, because scripts/connscale_harvest.py joins
the smoke's readings to the `test (...)` jobs, and the herd floor is armed only there.

`--check-collection` IS THE PARTITION GUARD, and it reads pytest's own collection rather than this
file's re-implementation of it. The arguments after `--` are the step's selection. It runs
`pytest --collect-only -q` with them, and fails if a file pytest collects is in no shard or a file
is in two. A listed file that collects nothing under the selection is printed and allowed, which is
right for marker deselection (pytest deselects it inside its shard too) and for a module-level skip.
It is NOT right for a collection-time ignore (`collect_ignore`, an ignore hook, `--ignore-glob`):
pytest skips those for a path named on the command line, so a shard would run a file the plain suite
ignores. No conftest here declares one; read the printed lines if one is ever added.
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import re
import subprocess
import sys
import tomllib
import zlib
from collections.abc import Callable
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# pytest's defaults, as of pytest 9. pyproject.toml sets neither key, so these are what it collects.
_PYTHON_FILES = ("test_*.py", "*_test.py")
_NORECURSE = ("*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}")

#: The engine step's `--ignore-glob`, matched against the same relative path.
ENGINE_EXCLUDE_GLOB = "*messagefoundry-webconsole*"
#: Held in shard 1 of the engine suite whatever their hash. The module docstring says why.
ENGINE_SHARD_ONE = frozenset({"tests/test_connscale_smoke.py"})

#: A node id's file, as `pytest --collect-only -q` prints it. A warnings-summary line is either
#: indented or reads `path:line`, so neither matches.
_NODE_FILE = re.compile(r"^([^\s:][^:]*\.py)::")


def collected_files(root: Path = _ROOT) -> list[str]:
    """Every file pytest would collect under `testpaths`, as sorted POSIX paths relative to root."""
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    testpaths = config["tool"]["pytest"]["ini_options"]["testpaths"]
    found: set[str] = set()
    for testpath in testpaths:
        base = root / testpath
        for path in base.rglob("*.py"):
            rel_dirs = path.relative_to(base).parts[:-1]
            if any(fnmatch.fnmatch(part, pat) for part in rel_dirs for pat in _NORECURSE):
                continue
            if any(fnmatch.fnmatch(path.name, pat) for pat in _PYTHON_FILES):
                found.add(path.relative_to(root).as_posix())
    return sorted(found)


def tooling_files(root: Path = _ROOT) -> set[str]:
    """The tooling-tier entries, as tests/_tooling_manifest.py parses them."""
    spec = importlib.util.spec_from_file_location(
        "_tooling_manifest", root / "tests" / "_tooling_manifest.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return set(module.entries())


def shard_of(path: str, shards: int) -> int:
    """The 1-based shard a test file belongs to.

    CRC-32, not Python's `hash()`, which is salted per process and would give every runner a
    different split. Not a cryptographic hash either: nothing here is secret or adversarial, and the
    crypto-inventory gate rightly asks for an entry for every one."""
    return zlib.crc32(path.encode("utf-8")) % shards + 1


def assign(path: str, shards: int, suite: str) -> int | None:
    """The shard `suite` puts `path` in, or `None` when that suite does not run the file."""
    if suite == "engine":
        if fnmatch.fnmatch(path, ENGINE_EXCLUDE_GLOB):
            return None
        if path in ENGINE_SHARD_ONE:
            return 1
    return shard_of(path, shards)


def partition(shards: int, suite: str, root: Path = _ROOT) -> dict[int, list[str]]:
    """Every shard's files, keyed 1..shards, with the tooling files left out."""
    tooling = tooling_files(root)
    split: dict[int, list[str]] = {n: [] for n in range(1, shards + 1)}
    for path in collected_files(root):
        shard = None if path in tooling else assign(path, shards, suite)
        if shard is not None:
            split[shard].append(path)
    return split


def collected_by_pytest(output: str) -> set[str]:
    """The files `pytest --collect-only -q` printed at least one node id for."""
    found: set[str] = set()
    for line in output.splitlines():
        match = _NODE_FILE.match(line)
        if match:
            found.add(match.group(1).replace("\\", "/"))
    return found


def partition_faults(split: dict[int, list[str]], collected: set[str]) -> list[str]:
    """What is wrong with `split` against the files pytest itself `collected`. Empty means it holds."""
    if not collected:
        return ["pytest collected no test files, so there is nothing to compare the shards with"]
    owners: dict[str, list[int]] = {}
    for shard, files in split.items():
        for path in files:
            owners.setdefault(path, []).append(shard)
    faults = [
        f"{path} is in shards {nums}" for path, nums in sorted(owners.items()) if len(nums) > 1
    ]
    faults += [
        f"{path} is collected by pytest and in no shard" for path in sorted(collected - set(owners))
    ]
    return faults


def check_collection(
    shards: int,
    suite: str,
    pytest_args: list[str],
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    """Exit 0 when the shards partition pytest's collection, 1 when they do not, 2 when unmeasured.

    `run` is the seam a test replaces, so a stub never reaches the process-wide `subprocess.run`."""
    split = partition(shards, suite)
    # The argv is this interpreter's pytest plus the workflow's own selection, with no shell.
    done = run(  # noqa: S603  # nosec B603
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            *pytest_args,
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if done.returncode != 0:
        sys.stdout.write(done.stdout[-4000:])
        sys.stderr.write(done.stderr[-4000:])
        print(
            f"pytest --collect-only exited {done.returncode}; nothing was compared", file=sys.stderr
        )
        return 2
    collected = collected_by_pytest(done.stdout)
    listed = {path for files in split.values() for path in files}
    sizes = ", ".join(f"shard {n} {len(files)}" for n, files in split.items())
    print(
        f"pytest collected tests from {len(collected)} files; the shards list {len(listed)} ({sizes})"
    )
    for path in sorted(listed - collected):
        print(f"listed, but collects nothing under this selection: {path}")
    faults = partition_faults(split, collected)
    for fault in faults:
        print(f"PARTITION BROKEN: {fault}", file=sys.stderr)
    return 1 if faults else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shard", type=int, help="1-based shard index")
    parser.add_argument("--of", type=int, required=True, dest="shards", help="shard count")
    parser.add_argument("--suite", choices=("coverage", "engine"), default="coverage")
    parser.add_argument(
        "--check-collection",
        action="store_true",
        help="compare every shard with pytest's own collection; pass the selection after --",
    )
    parser.add_argument("pytest_args", nargs="*", help="with --check-collection, the selection")
    args = parser.parse_args(argv)
    if args.shards < 1:
        parser.error(f"--of must be at least 1, got {args.shards}")
    if args.check_collection:
        if args.shard is not None:
            parser.error("--check-collection checks every shard, so it takes no --shard")
        return check_collection(args.shards, args.suite, args.pytest_args)
    if args.pytest_args:
        parser.error("only --check-collection reads pytest arguments")
    if args.shard is None or not 1 <= args.shard <= args.shards:
        parser.error(f"--shard must be between 1 and --of ({args.shards}), got {args.shard}")
    files = partition(args.shards, args.suite)[args.shard]
    if not files:
        # An empty shard would run pytest with no paths, which collects ALL of testpaths.
        print(f"shard {args.shard} of {args.shards} holds no test files", file=sys.stderr)
        return 1
    sys.stdout.write("".join(f"{path}\n" for path in files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
