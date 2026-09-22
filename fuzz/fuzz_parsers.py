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
inside that context manager. Importing ``fuzz.targets`` there pulls ``messagefoundry.parsing`` and
the parser libraries underneath it (``hl7``, and ``pydicom`` for the DICOM target), so the mutator is
guided by branches inside the real parsers rather than only by the engine's own wrappers. Nothing
else is imported there, so instrumentation stays bounded to the parsing surface.
"""

from __future__ import annotations

import os
import sys

# Atheris ships no py.typed marker and there is no `types-atheris`, so the import is untyped
# however it was installed. CI's mypy invocations name `messagefoundry`/`messagefoundry_webconsole`
# and do not reach this directory, but a local `mypy fuzz` should still come back clean.
import atheris  # type: ignore[import-untyped]

with atheris.instrument_imports():
    from fuzz.targets import (
        TARGETS_BY_NAME,
        FuzzTarget,
        libfuzzer_argv,
        work_paths,
        write_seed_corpus,
    )

#: Environment variable naming the target to run. An env var rather than a flag because libFuzzer
#: owns ``sys.argv`` and rejects options it does not recognise, so a custom ``--target=`` would have
#: to be stripped before ``atheris.Setup`` and would collide with libFuzzer's own parsing.
TARGET_ENV = "MEFOR_FUZZ_TARGET"


def _selected_target() -> FuzzTarget:
    """The target named by :data:`TARGET_ENV`, or exit naming the valid choices."""
    known = ", ".join(sorted(TARGETS_BY_NAME))
    name = os.environ.get(TARGET_ENV)
    if not name:
        raise SystemExit(f"set {TARGET_ENV} to one of: {known}")
    target = TARGETS_BY_NAME.get(name)
    if target is None:
        raise SystemExit(f"unknown fuzz target {name!r}; valid names: {known}")
    return target


def main() -> None:
    target = _selected_target()
    if not target.available():
        # Refuse rather than pass over it. A target that quietly does nothing is the exact failure
        # this harness exists to avoid: a clean run and a run that never executed look identical.
        raise SystemExit(
            f"fuzz target {target.name!r} needs the {target.requires_module!r} module, which is "
            f"not importable; install the matching extra or choose another target"
        )
    corpus, artifacts = work_paths(target)
    artifacts.mkdir(parents=True, exist_ok=True)
    written = write_seed_corpus(target, corpus)
    print(f"fuzzing {target.name}: {target.summary} ({written} seeds in {corpus})")
    atheris.Setup(libfuzzer_argv(sys.argv, corpus, artifacts), target.run)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
