# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Which optional extras are absent from this interpreter (BACKLOG #1230, loud-omission half).

WHY THIS IS A SIBLING MODULE AND NOT PART OF ``conftest.py``, which is where it started and where it
does not belong. The tests reached it with a bare ``import conftest``. That passes when only
``tests/`` is collected and FAILS IN A FULL RUN, because ``pyproject.toml`` has two testpaths and
``packaging/messagefoundry-webconsole/tests/conftest.py`` claims the same top-level module name:

    AttributeError: <module 'conftest' from '...webconsole/tests/conftest.py'>
                    has no attribute '_OPTIONAL_EXTRAS'

Seven tests passed alone and failed together, which is the worst way for a test to be wrong -- the
name resolved to the neighbouring module and nothing said so. Importing ``conftest`` BY PATH instead
would re-execute it, and its module body claims a per-process test slot and registers an ``atexit``
unlink, so a second execution burns a slot for nothing.

So the probe lives here: no module-level side effects, imported package-qualified as
``tests._extras_probe`` (the same idiom as ``tests._workflow_contexts``), and ``conftest`` keeps only
the thin pytest hooks that render what these functions compute.
"""

from __future__ import annotations

import importlib.util
from typing import Protocol

#: extra name -> the import sentinels its tests need. Mirrors pyproject.toml's
#: [project.optional-dependencies]; every distribution an extra pulls in is listed, so a
#: half-installed extra reads as absent rather than present.
OPTIONAL_EXTRAS: dict[str, tuple[str, ...]] = {
    "fhir": ("fhir.resources", "fhirpathpy"),
    "dicom": ("pydicom", "pynetdicom"),
    "x12": ("pyx12",),
    "xml": ("lxml", "xmlschema", "signxml"),
    "webauthn": ("webauthn",),
}


class SummaryWriter(Protocol):
    """The two ``TerminalReporter`` methods the summary uses, and nothing else."""

    def write_line(self, line: str) -> None: ...

    def write_sep(self, sep: str, title: str = "", **kwargs: object) -> None: ...


def extra_is_installed(sentinels: tuple[str, ...]) -> bool:
    """True only when EVERY sentinel resolves.

    ``find_spec`` rather than an import: it answers the question without paying the import cost and
    without leaving a partially-imported module behind on failure. A sentinel whose PARENT package is
    absent (``fhir.resources`` with no ``fhir``) RAISES instead of returning ``None`` -- measured, not
    assumed -- so both arms have to mean "absent" or the fhir extra would read as present.
    """
    for name in sentinels:
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True


def missing_extras() -> list[str]:
    """Extras whose tests cannot be collected in this interpreter, in declaration order."""
    return [name for name, probes in OPTIONAL_EXTRAS.items() if not extra_is_installed(probes)]


def report_header_lines() -> list[str]:
    """State the omission up front -- a summary line is easy to scroll past on a long run."""
    missing = missing_extras()
    if not missing:
        return []
    return [f"INCOMPLETE RUN: optional extras absent -- {', '.join(missing)}"]


def write_incomplete_run_summary(reporter: SummaryWriter) -> None:
    """Print the omission where the verdict is rendered, so green cannot be read as complete."""
    missing = missing_extras()
    if not missing:
        return
    write = reporter.write_line
    reporter.write_sep("=", "INCOMPLETE RUN -- coverage was NOT collected", red=True, bold=True)
    write(f"Optional extras absent from this interpreter: {', '.join(missing)}")
    write("Every test module gated on them removed itself at COLLECTION time, so its tests are not")
    write("in the counts above -- passed, failed and skipped alike. This result does NOT establish")
    write("that the full suite is green, and must not be reported as if it did.")
    write("")
    write("To collect them, install what CI installs (.github/workflows/ci.yml):")
    write(f'    pip install --constraint constraints.lock -e ".[dev,harness,{",".join(missing)}]"')
