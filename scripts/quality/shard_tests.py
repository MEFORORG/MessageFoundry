# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Print the test files one diff-coverage shard runs, one path per line.

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
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import sys
import tomllib
import zlib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# pytest's defaults, as of pytest 9. pyproject.toml sets neither key, so these are what it collects.
_PYTHON_FILES = ("test_*.py", "*_test.py")
_NORECURSE = ("*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}")


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shard", type=int, required=True, help="1-based shard index")
    parser.add_argument("--of", type=int, required=True, dest="shards", help="shard count")
    args = parser.parse_args(argv)
    if not 1 <= args.shard <= args.shards:
        parser.error(f"--shard must be between 1 and --of ({args.shards}), got {args.shard}")
    tooling = tooling_files()
    files = [
        path
        for path in collected_files()
        if path not in tooling and shard_of(path, args.shards) == args.shard
    ]
    if not files:
        # An empty shard would run pytest with no paths, which collects ALL of testpaths.
        print(f"shard {args.shard} of {args.shards} holds no test files", file=sys.stderr)
        return 1
    sys.stdout.write("".join(f"{path}\n" for path in files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
