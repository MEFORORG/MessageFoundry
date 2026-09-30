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

* an OLDER engine (``0.0.1``) must be refused -- the defect the row names, an engine lacking
  ``messagefoundry.apiclient``. At a harness version of ``0.0.1``, ``0.0.0`` stands in; at
  ``0.0.0`` no older release exists, so that arm is SKIPPED and says so;
* the NEXT MICRO engine must be refused too, since the harness is lockstep and not a floor;
* the engine at the harness's OWN version must resolve, extra and all, or the refusals prove
  nothing. Aiming at the harness version rather than at the pin is what catches a pin that
  drifted from the version it ships at.

Two probes do not prove a pin EXACT: a range such as ``>0.3,<0.4.1`` passes all three arms. That
half is the specifier checks' job (``_engine_pin`` and the PYSMOKE lockstep check), which refuse
anything but a single ``==``. This script adds what they cannot see: that pip refuses.

``--ignore-installed`` and ``--isolated`` are load-bearing. Without the first, pip answers from
whatever engine the running interpreter already has. Without the second, ``PIP_FIND_LINKS``, any
other ``PIP_*`` variable, or a user or global ``pip.conf`` adds sources to every arm, and a
wheelhouse carrying the engine flips the result either way.

WHAT THIS DOES NOT ESTABLISH: that the real engine's dependency tree (PySide6 and the rest)
resolves. The stub declares the ``harness`` extra with no requirements of its own, so this checks
the harness-to-engine edge only. A harness that declares any OTHER base dependency is refused with
its own message, because ``--no-index`` could not resolve it and every arm would then read as
refused, blaming a correct pin.

NOT STDLIB-ONLY, on purpose. It imports ``packaging`` for PEP 440 and PEP 503 normalisation, and
both places that run it already carry ``packaging``: the test suite's interpreter, and release.yml's
``/tmp/harnesssmoke`` venv, which installs it pinned from the lock before this runs.

Usage: ``python scripts/release/harness_resolution_check.py <harness wheel>``. Exit 0 when every
arm that runs behaves; exit 1, naming the arm, when any does not.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Collection, Iterable
from email.parser import Parser
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ENGINE = "messagefoundry"
ARMS = ("older", "newer", "matched")

#: The platforms a base requirement's marker is evaluated on. The harness installs on all three, so
#: a requirement true on ANY of them is a base dependency, whatever platform runs this check.
_PLATFORMS = (
    {"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix"},
    {"sys_platform": "win32", "platform_system": "Windows", "os_name": "nt"},
    {"sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix"},
)


def _metadata(wheel: Path) -> tuple[Version, list[str]]:
    """``(Version, Requires-Dist lines)`` read out of the wheel's own METADATA.

    A missing or unparseable ``Version:`` exits with an ``::error::`` naming the wheel, not a bare
    traceback: the arms aim at that version, so without it there is nothing to probe.
    """
    with zipfile.ZipFile(wheel) as zf:
        names = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise SystemExit(f"::error::{wheel.name} carries {len(names)} METADATA files, not one")
        msg = Parser().parsestr(zf.read(names[0]).decode("utf-8"))
    raw = msg["Version"]
    if raw is None:
        raise SystemExit(
            f"::error::{wheel.name} METADATA carries no Version: field (BACKLOG #1585)"
        )
    try:
        version = Version(str(raw))
    except InvalidVersion:
        raise SystemExit(
            f"::error::{wheel.name} METADATA Version {raw!r} is not a PEP 440 version "
            f"(BACKLOG #1585)"
        ) from None
    return version, msg.get_all("Requires-Dist") or []


def _other_base_requirements(requires: Iterable[str]) -> list[str]:
    """Base (non-extra) requirements on anything other than the engine.

    A marker is evaluated on EACH platform in ``_PLATFORMS``, not only the one running this check,
    so a Windows-only dependency is still counted on the ubuntu runner. Other marker variables,
    such as ``python_version`` and ``platform_machine``, take the running interpreter's values.
    """
    others = []
    for raw in requires:
        req = Requirement(raw)
        if canonicalize_name(req.name) == ENGINE:
            continue
        marker = req.marker
        if marker is not None and not any(
            marker.evaluate({**platform, "extra": ""}) for platform in _PLATFORMS
        ):
            continue
        others.append(str(req))
    return others


def stub_wheel(
    directory: Path,
    name: str,
    version: str,
    *,
    requires: Iterable[str] = (),
    provides_extra: Iterable[str] = (),
) -> Path:
    """A metadata-only wheel. Also used by tests/test_packaging.py for its synthetic harness wheel.

    The name and version are NORMALISED the way a wheel filename requires: the name per PEP 503
    with ``-`` escaped to ``_``, the version per PEP 440, so ``0.3.0-rc1`` becomes ``0.3.0rc1``. A
    raw hyphen in either splits the filename at the wrong field, and pip then refuses the wheel as
    invalid rather than resolving it, so every arm would read as refused.
    """
    dist = canonicalize_name(name).replace("-", "_")
    normal = str(Version(version))
    dist_info = f"{dist}-{normal}.dist-info"
    path = directory / f"{dist}-{normal}-py3-none-any.whl"
    files = {
        f"{dist_info}/METADATA": "".join(
            [
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {normal}\n",
                *(f"Provides-Extra: {extra}\n" for extra in provides_extra),
                *(f"Requires-Dist: {req}\n" for req in requires),
            ]
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: harness_resolution_check\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    record = "".join(f"{member},,\n" for member in [*files, f"{dist_info}/RECORD"])
    with zipfile.ZipFile(path, "w") as zf:
        for member, text in files.items():
            zf.writestr(member, text)
        zf.writestr(f"{dist_info}/RECORD", record)
    return path


def _resolves(harness: Path, engine_version: str, index: Path) -> tuple[bool, str]:
    """Does pip resolve ``harness`` when the only engine it can see is ``engine_version``?"""
    index.mkdir()
    stub_wheel(index, ENGINE, engine_version, provides_extra=["harness"])
    argv = [
        sys.executable,
        "-I",
        "-m",
        "pip",
        "install",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "--dry-run",
        "--ignore-installed",
        "--no-index",
        "--find-links",
        str(index),
        str(harness),
    ]
    # --isolated ignores PIP_* variables and config files; dropping them here as well means a
    # future pip that narrows --isolated cannot quietly bring them back.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_")}
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, local paths only
        argv, capture_output=True, text=True, env=env, timeout=300, check=False
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def probes(shipped: Version) -> dict[str, tuple[str, bool]]:
    """``{arm: (engine version, should resolve)}`` for every arm that can run at ``shipped``.

    An arm is dropped rather than run on a version it does not describe. The older arm needs a
    release below ``shipped``, and none exists below ``0.0.0``. Every arm left aims at its own
    version: older is below ``shipped``, newer is above it, and matched is ``shipped`` itself.
    """
    major, minor, micro = (list(shipped.release) + [0, 0])[:3]
    # The epoch leads PEP 440 ordering, so the newer arm keeps it: `1!0.3.3`, not `0.3.3`, which
    # sorts BELOW `1!0.3.2` and would let a floor pin pass the arm meant to refuse it.
    epoch = f"{shipped.epoch}!" if shipped.epoch else ""
    arms = {
        "newer": (f"{epoch}{major}.{minor}.{micro + 1}", False),
        "matched": (str(shipped), True),
    }
    older = next((v for v in ("0.0.1", "0.0.0") if Version(v) < shipped), None)
    if older is not None:
        arms["older"] = (older, False)
    return arms


def check(harness: Path, arms: Collection[str] = ARMS) -> list[str]:
    """Every arm in ``arms`` that misbehaved, as a message; empty when they all behave.

    An arm name outside ``ARMS`` raises ``ValueError``. A typo would otherwise run no probe and
    pass.
    """
    unknown = sorted(set(arms) - set(ARMS))
    if unknown:
        raise ValueError(f"unknown arm(s) {unknown}; the arms are {list(ARMS)}")
    shipped, requires = _metadata(harness)
    others = _other_base_requirements(requires)
    if others:
        return [
            f"{harness.name} declares base dependencies besides {ENGINE}: {others}. This check "
            f"stubs only the engine and runs with --no-index, so every arm would read as refused. "
            f"Extend scripts/release/harness_resolution_check.py to stub them (BACKLOG #1585)."
        ]
    # The arms aim at the harness's OWN version, not at whatever its pin says: lockstep means the
    # engine at that version and no other. Aiming at the pin would let a pin that drifted from the
    # version it ships at pass every arm while pointing at the wrong engine.
    runnable = probes(shipped)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="harness-resolution-") as tmp:
        for arm in ARMS:
            if arm not in arms:
                continue
            if arm not in runnable:
                print(
                    f"{arm}: skipped, no engine release exists below {shipped} to probe",
                    file=sys.stderr,
                )
                continue
            engine_version, want = runnable[arm]
            got, out = _resolves(harness, engine_version, Path(tmp) / f"index-{arm}")
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
