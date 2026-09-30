# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Prove the harness wheel REFUSES an engine it does not ship with, at install time (BACKLOG #1585).

The lockstep checks in ``tests/test_packaging.py`` and in release.yml's harness wheel smoke read
the ``Requires-Dist`` a wheel declares. That is the specifier, not what a resolver DOES with it.
The filed acceptance for #1585 asked for the install legs too, and they were judged unreachable
offline because they seemed to need an index carrying an older engine.

They do not. This script builds tiny STUB ``messagefoundry`` wheels in a temporary directory, one
per arm, each holding only metadata, and asks pip to resolve the harness wheel against each with
``--no-index --find-links`` and ``--dry-run``. No network, nothing installed:

* an OLDER engine must be refused -- the defect the row names, an engine lacking
  ``messagefoundry.apiclient``;
* a NEWER engine must be refused too, since the harness is lockstep and not a floor;
* the engine at the harness's OWN version must resolve, extra and all, or the refusals prove
  nothing. Aiming at the harness version rather than at the pin is what catches a pin that
  drifted from the version it ships at.

``--ignore-installed`` is load-bearing. Without it pip answers from whatever engine the running
interpreter already has, and an installed engine at the pinned version satisfies every arm.

WHAT THIS DOES NOT ESTABLISH: that the real engine's dependency tree (PySide6 and the rest)
resolves. The stub declares the ``harness`` extra with no requirements of its own, so this checks
the harness-to-engine edge only.

Usage: ``python scripts/release/harness_resolution_check.py <harness wheel>``. Exit 0 when all
three arms behave; exit 1, naming the arm, when any does not.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path

from packaging.version import Version

ENGINE = "messagefoundry"


def _metadata(wheel: Path) -> str:
    """The ``Version`` the wheel's own METADATA declares."""
    with zipfile.ZipFile(wheel) as zf:
        names = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise SystemExit(f"::error::{wheel.name} carries {len(names)} METADATA files, not one")
        msg = Parser().parsestr(zf.read(names[0]).decode("utf-8"))
    return str(msg["Version"])


def _stub_wheel(directory: Path, version: str) -> Path:
    """A metadata-only ``messagefoundry`` wheel that declares the ``harness`` extra."""
    dist_info = f"{ENGINE}-{version}.dist-info"
    path = directory / f"{ENGINE}-{version}-py3-none-any.whl"
    files = {
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {ENGINE}\nVersion: {version}\nProvides-Extra: harness\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: harness_resolution_check\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    record = "".join(f"{name},,\n" for name in [*files, f"{dist_info}/RECORD"])
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
        zf.writestr(f"{dist_info}/RECORD", record)
    return path


def _resolves(harness: Path, engine_version: str, workdir: Path) -> tuple[bool, str]:
    """Does pip resolve ``harness`` when the only engine it can see is ``engine_version``?"""
    index = workdir / f"index-{engine_version}"
    index.mkdir()
    _stub_wheel(index, engine_version)
    argv = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--no-index",
        "--find-links",
        str(index),
        str(harness),
    ]
    env = {**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1"}
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, local paths only
        argv, capture_output=True, text=True, env=env, timeout=300, check=False
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def check(harness: Path) -> list[str]:
    """Every arm that misbehaved, as a message; empty when all three behave."""
    # The arms aim at the harness's OWN version, not at whatever its pin says: lockstep means the
    # engine at that version and no other. Aiming at the pin would let a pin that drifted from the
    # version it ships at pass every arm while pointing at the wrong engine.
    shipped = Version(_metadata(harness))
    major, minor, micro = (list(shipped.release) + [0, 0])[:3]
    arms = [
        ("older", "0.0.1", False),
        ("newer", f"{major}.{minor}.{micro + 1}", False),
        ("matched", str(shipped), True),
    ]
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="harness-resolution-") as tmp:
        for arm, engine_version, want in arms:
            got, out = _resolves(harness, engine_version, Path(tmp))
            print(
                f"{arm}: engine {engine_version} -> {'resolves' if got else 'refused'}",
                file=sys.stderr,
            )
            if got != want:
                failures.append(
                    f"the {arm} arm: pip {'resolved' if got else 'refused'} {harness.name} against "
                    f"{ENGINE} {engine_version}, expected it to be "
                    f"{'resolved' if want else 'refused'} (BACKLOG #1585)\n{out}"
                )
    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: harness_resolution_check.py <harness wheel>", file=sys.stderr)
        return 2
    failures = check(Path(argv[0]))
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
