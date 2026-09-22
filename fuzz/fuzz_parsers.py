# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Atheris entrypoint for the tolerant-parser fuzz targets (ADR 0191).

Run it as a module from the repository root, so the root is on ``sys.path`` and ``fuzz.targets``
imports::

    MEFOR_FUZZ_TARGET=hl7_peek python -m fuzz.fuzz_parsers -max_total_time=60

Every argument after the module name goes straight to libFuzzer. ``fuzz/README.md`` has the local
recipes; the advisory CI job is ``.github/workflows/fuzz.yml``.

**This is the only file in the tree that imports Atheris.** Atheris publishes Linux x86-64 wheels
only, so importing it anywhere the rest of the suite reaches would break the Windows legs outright.
Everything testable therefore lives in :mod:`fuzz.targets`, which is Atheris-free on purpose, and
this file is the thin glue that cannot be imported off Linux.

**Why the import sits inside ``instrument_imports``.** Coverage-guided fuzzing needs the code under
test compiled with coverage callbacks; Atheris adds them at import time to whatever is imported
inside that context manager. Importing ``fuzz.targets`` there pulls ``messagefoundry.parsing`` and,
underneath it, ``hl7`` -- which ``parsing/peek.py`` imports at module top -- so the HL7 mutator is
guided by branches inside the real tolerant parser rather than only by the engine's own wrapper.

**``pydicom`` does NOT come along for the ride, and this docstring used to say it did.** Measured
2026-09-22: ``messagefoundry/parsing/dicom/_deps.py`` imports pydicom *inside* ``load_dcmread`` and
``parse_error_types``, never at module top, deliberately, to keep the engine importable without the
``[dicom]`` extra. Those functions first run inside ``DicomPeek.parse`` -- long after this context
manager has closed -- so on the previous arrangement pydicom was loaded uninstrumented and the
``dicom_peek`` mutator saw coverage only from the thin engine wrapper, blind to the entire DICOM
parse surface it was supposed to be exploring. The explicit import below is what fixes that.

**That fix was reasoned rather than measured. It is measured now, on Linux, in CI.** This paragraph
used to say "Recorded as unverified rather than asserted", and the sentence it replaces is quoted in
ADR 0191's option 1 alongside the figures. GitHub Actions run **35761703252** (workflow ``fuzz``,
head ``cdeb0fa9393bcfc39ccd3bd571f621de84d867ef``, atheris 3.1.0, pydicom 3.0.2) logs Atheris
instrumenting **58 pydicom names** -- the package plus 57 submodules, ``filereader`` and ``encaps``
and ``valuerep`` among them -- and the ``dicom_peek`` mutator then climbs from ``cov: 136`` to
``cov: 341``, stepping +74 at exec #4495 straight after a ``pydicom/filereader.py`` warning. The
target went on to produce a real finding through the DICOM file-meta reader at execution unit 8,326.

**One arm of the original recipe is still missing, and saying which matters.** That recipe was a
comparison against a build with this import removed, and only the with-import arm has ever run, so
the coverage *delta* is not attributable in a controlled sense -- do not quote it as though a
control existed. The instrumentation claim does not need it: ``INFO: Instrumenting pydicom.*``
observes the thing directly, where the ``cov:`` delta was only ever a proxy for it. To run the
missing arm, delete the import below, fuzz ``dicom_peek`` on Linux, and compare ``cov:`` from
``-print_final_stats=1`` against a run with it restored.
"""

from __future__ import annotations

import contextlib
import os
import sys
from typing import Never

# Atheris ships no py.typed marker and there is no `types-atheris`, so the import is untyped
# however it was installed. CI's mypy invocations name `messagefoundry`/`messagefoundry_webconsole`
# and do not reach this directory, but a local `mypy fuzz` should still come back clean.
import atheris  # type: ignore[import-untyped]

with atheris.instrument_imports():
    with contextlib.suppress(ImportError):
        # Imported for its SIDE EFFECT: loading pydicom here is what gets it instrumented. The
        # engine's own import is function-scoped (see the module docstring), so without this line
        # pydicom loads later and uninstrumented. Tolerating absence keeps a `[fuzz]`-only install
        # able to run the HL7 and X12 targets; `dicom_peek` refuses on its own in that case, via
        # `FuzzTarget.available`, so nothing is silently skipped.
        import pydicom  # noqa: F401

    from fuzz.targets import (
        REFUSAL_EXIT,
        TARGETS_BY_NAME,
        FuzzTarget,
        HarnessRefusal,
        libfuzzer_argv,
        work_paths,
        write_seed_corpus,
    )

#: Environment variable naming the target to run. An env var rather than a flag because libFuzzer
#: owns ``sys.argv`` and rejects options it does not recognise, so a custom ``--target=`` would have
#: to be stripped before ``atheris.Setup`` and would collide with libFuzzer's own parsing.
TARGET_ENV = "MEFOR_FUZZ_TARGET"


def _refuse(message: str) -> Never:
    """Exit with :data:`REFUSAL_EXIT` after printing ``message`` to stderr.

    **A refusal is not a finding, and exit code 1 could not tell them apart.** Every refusal here
    predates any fuzzing: no target selected, an unknown name, a missing extra, or a work directory
    that the PHI fence rejected or that cannot be written. ``.github/workflows/fuzz.yml`` reads the
    process status, and on 1 it publishes "this parser broke its exception contract" -- so a failed
    ``[dicom]`` install or a renamed target announced a parser defect that did not exist. The
    distinct code lets the workflow separate "the harness could not run" from "the harness ran and
    found something", which are opposite instructions to whoever reads the log.

    **It separates the refusals this module raises, and nothing else.** A crash the process does not
    choose the status for -- an OOM kill at 137, a signal, an Atheris-internal abort -- still exits
    non-zero without reaching here, and the workflow still buckets it as a finding. Narrowing that
    would mean enumerating status codes the harness does not control, which trades one wrong bucket
    for a more confident wrong bucket.
    """
    print(message, file=sys.stderr)
    raise SystemExit(REFUSAL_EXIT)


def _selected_target() -> FuzzTarget:
    """The target named by :data:`TARGET_ENV`, or refuse naming the valid choices."""
    known = ", ".join(sorted(TARGETS_BY_NAME))
    name = os.environ.get(TARGET_ENV)
    if not name:
        _refuse(f"set {TARGET_ENV} to one of: {known}")
    target = TARGETS_BY_NAME.get(name)
    if target is None:
        _refuse(f"unknown fuzz target {name!r}; valid names: {known}")
    return target


def main() -> None:
    target = _selected_target()
    if not target.available():
        # Refuse rather than pass over it. A target that quietly does nothing is the exact failure
        # this harness exists to avoid: a clean run and a run that never executed look identical.
        _refuse(
            f"fuzz target {target.name!r} needs the {target.requires_module!r} module, which is "
            f"not importable; install the matching extra or choose another target"
        )
    # EVERY work-directory step is inside the guard, not just the path computation. Resolving the
    # path, creating the artifacts directory and materialising the seeds are one operation from the
    # caller's point of view -- "prepare somewhere to work" -- and all three happen before any input
    # is fuzzed. Guarding only the first left an unwritable or full work directory raising OSError,
    # exiting 1, and being published as a parser finding: the misreport this exit code exists to end.
    try:
        corpus, artifacts = work_paths(target)
        artifacts.mkdir(parents=True, exist_ok=True)
        written = write_seed_corpus(target, corpus)
    except HarnessRefusal as exc:
        # The PHI fence in `work_root`. Refusing is the control; see that function's docstring.
        _refuse(str(exc))
    except OSError as exc:
        _refuse(f"cannot prepare the fuzz work directory for {target.name!r}: {exc}")
    print(f"fuzzing {target.name}: {target.summary} ({written} seeds in {corpus})")
    atheris.Setup(libfuzzer_argv(sys.argv, corpus, artifacts), target.run)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
