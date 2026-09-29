# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fail when a module on the tests mypy ratchet is already clean (BACKLOG #1799).

The ratchet is the ``ignore_errors = true`` override in pyproject.toml. It exempts test modules that
carried type errors when tests/ entered the mypy gate. ``ignore_errors`` hides every error in a
listed module, so the normal gate cannot tell a listed module that still has errors from one that has
been fixed. A fixed module left on the list is a dead entry: new code written into it goes unchecked,
and the ceiling in tests/test_mypy_tests_scope.py stays higher than the real debt.

HOW IT MEASURES. It copies pyproject.toml with that one override flipped to ``ignore_errors =
false``, then runs mypy over the listed files with the copy, once per platform. A listed module with
no error on ANY platform is dead. The list is the union of the linux and win32 passes (pyproject's
comment says so), so a module clean on linux but not on win32 stays listed.

WHY IT CANNOT PASS BY MEASURING NOTHING. If the flip did not take effect, mypy would report no error
anywhere, every listed module would read as clean, and the check would FAIL naming all of them. A
mypy crash (exit 2) fails on its own. So both broken-instrument shapes fail loud; neither reads green.
tests/test_mypy_tests_scope.py plants a clean module and a dirty one against the parsing and
verdict logic.

Run it from the repository root: ``python scripts/ci/mypy_ratchet_check.py``.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Iterable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"

#: The one line the flip rewrites. The ratchet is the only override that may carry it.
_IGNORE_TRUE = "ignore_errors = true"

#: ``tests/test_x.py:12: error: ...`` or with a column, and either path separator.
_ERROR_LINE = re.compile(r"^(?P<path>[^:\s][^:]*?\.py):\d+(?::\d+)?: error: ")


def ratchet_modules(pyproject_text: str) -> list[str]:
    """The modules the ``ignore_errors = true`` override lists (empty when there is none)."""
    overrides = tomllib.loads(pyproject_text)["tool"]["mypy"].get("overrides", [])
    lists = [o["module"] for o in overrides if o.get("ignore_errors") is True]
    if len(lists) > 1:
        raise SystemExit("expected at most ONE ignore_errors override (the #1799 ratchet)")
    if not lists:
        return []
    module = lists[0]
    return [module] if isinstance(module, str) else list(module)


def flipped_config(pyproject_text: str) -> str:
    """pyproject text with the ratchet's ``ignore_errors = true`` turned to ``false``.

    Only lines inside a ``[[tool.mypy.overrides]]`` table count, so another tool's key of the same
    spelling (coverage.py has one) is left alone. Refuses anything but exactly one such line there,
    so the flip cannot land on the wrong override.
    """
    lines = pyproject_text.splitlines(keepends=True)
    hits = []
    table = ""
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            table = stripped
        elif stripped == _IGNORE_TRUE and table == "[[tool.mypy.overrides]]":
            hits.append(i)
    if len(hits) != 1:
        raise SystemExit(
            f"expected exactly one `{_IGNORE_TRUE}` line in a mypy override, found {len(hits)}"
        )
    lines[hits[0]] = lines[hits[0]].replace("true", "false")
    flipped = "".join(lines)
    # The flip must leave NO ignore_errors override, or the run below still hides errors.
    if ratchet_modules(flipped):
        raise SystemExit("the flipped config still carries an ignore_errors override")
    return flipped


def module_of(path: str) -> str:
    """``tests\\test_x.py`` -> ``tests.test_x``."""
    return path.replace("\\", "/").removeprefix("./").removesuffix(".py").replace("/", ".")


def modules_with_errors(mypy_output: str) -> set[str]:
    """Every module mypy reported at least one ERROR in (notes do not count)."""
    found = set()
    for line in mypy_output.splitlines():
        match = _ERROR_LINE.match(line)
        if match:
            found.add(module_of(match["path"]))
    return found


def dead_entries(listed: Sequence[str], dirty_per_platform: Iterable[set[str]]) -> list[str]:
    """Listed modules no platform reported an error in."""
    dirty = set().union(*dirty_per_platform)
    return [m for m in listed if m not in dirty]


def run_mypy(config: Path, files: Sequence[str], platform: str) -> str:
    cmd = [
        sys.executable,
        "-m",
        "mypy",
        "--explicit-package-bases",
        "--config-file",
        str(config),
        "--platform",
        platform,
        "--no-error-summary",
        "--no-color-output",
        *files,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)  # nosec B603 - fixed argv, no shell
    # 0 = clean, 1 = errors found (expected: the listed modules carry them). 2 is a crash or a usage
    # error, which would otherwise read as "no errors anywhere".
    if proc.returncode not in (0, 1):
        raise SystemExit(
            f"mypy --platform {platform} failed (exit {proc.returncode}):\n{proc.stdout}{proc.stderr}"
        )
    return proc.stdout


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--platform", action="append", dest="platforms", help="repeatable; default linux and win32"
    )
    args = parser.parse_args(argv)
    platforms: list[str] = args.platforms or ["linux", "win32"]

    text = PYPROJECT.read_text(encoding="utf-8")
    listed = ratchet_modules(text)
    if not listed:
        print("mypy ratchet: no ignore_errors override, nothing to check")
        return 0
    files = [m.replace(".", "/") + ".py" for m in listed]

    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "pyproject.toml"
        config.write_text(flipped_config(text), encoding="utf-8")
        dirty = [modules_with_errors(run_mypy(config, files, p)) for p in platforms]

    dead = dead_entries(listed, dirty)
    platform_names = " and ".join(platforms)
    if dead:
        print(
            f"mypy ratchet: {len(dead)} of {len(listed)} listed modules report no error on {platform_names}. "
            "Remove them from the ignore_errors list in pyproject.toml and lower _RATCHET_CEILING in "
            "tests/test_mypy_tests_scope.py:"
        )
        for module in dead:
            print(f"  {module}")
        return 1
    print(f"mypy ratchet: all {len(listed)} listed modules still report errors on {platform_names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
