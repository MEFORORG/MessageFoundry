# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness entry module must import with nothing but the standard library installed.

The release job's harness smoke installs the built wheel with ``--no-deps`` and imports
``harness.__main__`` out of it. ``--no-deps`` keeps the engine and PySide6 off the publishing
runner, so a top-level ``from messagefoundry...`` in the entry module fails that import. Two such
lines did exactly that on tag v0.5.0 (release run 36877774902): the engine and toolkit published,
and the harness did not.

Nothing else in CI imports the entry module without the engine, so this test does it here. It
runs a fresh, isolated interpreter whose import system refuses every top-level module outside the
standard library, except ``harness`` itself, and imports the entry module from this checkout.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import harness.__main__ as harness_entry

_ENTRY = Path(harness_entry.__file__).resolve()
_ROOT = _ENTRY.parents[1]

#: Run under ``python -I``. Installs a finder AHEAD of every other one (the editable-install finder
#: included) that refuses any top-level name outside the standard library, then imports ``target``.
#: Prints OK on success; exits non-zero with the ImportError on failure.
_PROBE = textwrap.dedent(
    """
    import importlib
    import importlib.abc
    import sys

    root, target = sys.argv[1], sys.argv[2]
    ALLOWED = set(sys.stdlib_module_names) | {"harness"}
    # Whatever site and .pth files loaded at startup (an editable-install finder, say) is not the
    # target's doing, so only modules loaded AFTER this point are checked below.
    BEFORE = set(sys.modules)

    class StdlibOnly(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.partition(".")[0] not in ALLOWED:
                raise ModuleNotFoundError(f"No module named {name!r}", name=name)
            return None

    sys.meta_path.insert(0, StdlibOnly())
    sys.path.insert(0, root)

    # ARMED: the blocker must refuse the engine, which IS installed in the test venv. If this
    # import succeeds, the probe below proves nothing.
    try:
        import messagefoundry  # noqa: F401
    except ModuleNotFoundError:
        pass
    else:
        raise SystemExit("PROBE NOT ARMED: messagefoundry imported through the blocker")

    try:
        module = importlib.import_module(target)
    except ImportError as exc:
        raise SystemExit(f"IMPORT FAILED: {exc}")
    leaked = sorted(
        m for m in set(sys.modules) - BEFORE if m.partition(".")[0] not in ALLOWED
    )
    if leaked:
        raise SystemExit(f"NON-STDLIB MODULES LOADED: {leaked}")
    if not callable(getattr(module, "main", None)):
        raise SystemExit("NO CALLABLE main()")
    print("OK", module.__file__)
    """
)


def _probe(target: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", _PROBE, str(_ROOT), target],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_the_harness_entry_module_imports_without_the_engine() -> None:
    proc = _probe("harness.__main__")
    assert proc.returncode == 0, (
        "harness/__main__.py cannot be imported with only the standard library installed, so the "
        "release job's --no-deps harness smoke will fail. Move the engine (or other third-party) "
        f"import into the function that uses it.\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    # The module the probe loaded is this checkout's, not some other copy on sys.path.
    assert proc.stdout.startswith("OK "), proc.stdout
    assert Path(proc.stdout[3:].strip()).resolve() == _ENTRY


def test_the_probe_refuses_a_module_that_imports_the_engine() -> None:
    """Positive control: the same probe must fail on a harness module with a top-level engine
    import. Without this, a blocker that refuses nothing would pass the test above forever."""
    control = "harness.scenarios"
    source = (_ROOT / "harness" / "scenarios.py").read_text(encoding="utf-8")
    assert "\nfrom messagefoundry" in source, f"{control} no longer imports the engine at top level"
    proc = _probe(control)
    assert proc.returncode != 0, proc.stdout
    assert "No module named 'messagefoundry" in proc.stderr, proc.stderr
