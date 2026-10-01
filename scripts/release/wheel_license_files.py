# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a wheel whose own dist-info does not carry its license files (BACKLOG #1192).

A wheel declares its license files with PEP 639 ``license-files``, and the build backend copies
them to ``<name>-<version>.dist-info/licenses/``. Two shapes fail silently, and this script refuses
both:

* A file missing from the wheel's OWN dist-info. The check names the exact member, anchored on the
  dist-info the wheel filename declares, so a nested ``*.dist-info/licenses/LICENSE`` under a
  force-included tree cannot stand in for it.
* Any member with a ``..`` path component. Hatchling writes a parent-path ``license-files`` entry
  into the wheel verbatim, as ``dist-info/licenses/../../LICENSE`` (measured 2026-09-30), and an
  installer may then write outside the dist-info. A correct copy beside it does not excuse it.

Usage: ``python scripts/release/wheel_license_files.py 'toolkit-dist/*.whl'``. It requires
``LICENSE`` and ``NOTICE`` unless ``--require`` names others. A pattern that matches no file is a
failure, never a pass.
"""

from __future__ import annotations

import argparse
import glob
import sys
import zipfile
from collections.abc import Sequence
from pathlib import Path

DEFAULT_REQUIRED: tuple[str, ...] = ("LICENSE", "NOTICE")


def problems(wheel: Path, required: Sequence[str] = DEFAULT_REQUIRED) -> list[str]:
    """Every reason ``wheel`` fails, or an empty list. Raises ``zipfile.BadZipFile`` on a bad zip."""
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    # The wheel filename is `<name>-<version>-<tags>.whl`, and its dist-info is `<name>-<version>`.
    name, version = wheel.name.split("-")[:2]
    dist_info = f"{name}-{version}.dist-info"
    found: list[str] = []
    for member in names:
        if ".." in member.replace("\\", "/").split("/"):
            found.append(
                f"{member} has a '..' component, so it would install outside its directory"
            )
    present = set(names)
    for license_file in required:
        if f"{dist_info}/licenses/{license_file}" not in present:
            found.append(f"{dist_info}/licenses/{license_file} is missing")
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("patterns", nargs="+", help="wheel paths or glob patterns")
    parser.add_argument(
        "--require",
        action="append",
        help="a license file the wheel must carry (repeatable; default LICENSE and NOTICE)",
    )
    args = parser.parse_args(argv)
    required = tuple(args.require or DEFAULT_REQUIRED)

    failures = 0
    checked = 0
    for pattern in args.patterns:
        matches = sorted(glob.glob(pattern))
        if not matches:
            print(f"::error::{pattern} matched no wheel, so nothing was checked")
            failures += 1
            continue
        for match in matches:
            wheel = Path(match)
            try:
                found = problems(wheel, required)
            except (OSError, zipfile.BadZipFile) as exc:
                found = [f"could not read it: {exc}"]
            checked += 1
            for problem in found:
                print(f"::error::{wheel.name}: {problem}")
            failures += bool(found)
    if failures:
        return 1
    print(f"license files present in {checked} wheel(s): {', '.join(required)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
