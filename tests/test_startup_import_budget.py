# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Startup import budget for the CLI and the tray (BACKLOG #2514, PEP 810).

Four modules carry a `__lazy_modules__` list: `__main__.py`, `config/__init__.py`, `tray/__main__.py`
and `tray/config.py`. On Python 3.15 the imports they name bind lazily and load on first use. On
3.14, the project's floor, the list is an ordinary variable and nothing changes, so the budget is
ADVISORY there: it skips. The `lazy` keyword is not used because it is a SyntaxError on 3.14.

The budget is a set of modules, never a wall-clock time, so it cannot flake on a loaded runner.
On 3.15.0b3 the lists take the CLI from 273 modules to about 186 and the tray's first process from
204 to 120, counting the interpreter's own modules.

Each probe runs in a FRESH interpreter, because the pytest process has already imported most of
the engine. The CLI probe runs the package through runpy, as `python -m messagefoundry` does, so
`messagefoundry.__main__` is never in `sys.modules`, and it keeps the CLI's exit code, so a refused
argument fails the probe. The tray probe imports the entry module and `tray.branding`, which is
what the first process loads before `main()` re-execs as the branded child.

The control arm runs the same probe with every import forced eager: natively on 3.14, and through
`sys.set_lazy_imports_filter` on 3.15. It asserts the deferred modules DO load there, so a
misspelled name cannot pass the budget by never loading at all. If the control fails because a
module no longer loads even eagerly, its lazy entry is dead: remove it from both places.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

_LAZY_ARM_SKIP = "advisory until the floor is 3.15: __lazy_modules__ has no effect on 3.14 (#2478)"


class _Probe(NamedTuple):
    kind: str
    args: tuple[str, ...]
    #: Must NOT load on 3.15, and must load when forced eager.
    deferred: frozenset[str]
    #: The exact engine modules it may load on 3.15, measured on 3.15.0b3. Exact rather than a
    #: ceiling, so one new eager engine import on the startup path fails here instead of being
    #: absorbed by headroom. If you add one on purpose, add it here and say why in the commit.
    engine: frozenset[str]


#: The CLI reaches `config.tls_policy` through `logging_setup`. Before #2514, loading that leaf ran
#: `config/__init__.py`, which loaded pydantic and every model.
_CLI_DEFERRED = frozenset({"pydantic", "messagefoundry.config.models", "sqlite3", "tomllib"})
_CLI_ENGINE = frozenset(
    {
        "messagefoundry",
        "messagefoundry.cli_common",
        "messagefoundry.cli_surface",
        "messagefoundry.config",
        "messagefoundry.config.tls_policy",
        "messagefoundry.console_streams",
        "messagefoundry.controlchars",
        "messagefoundry.keywrap",
        "messagefoundry.last_resort",
        "messagefoundry.log_spool",
        "messagefoundry.logging_guard",
        "messagefoundry.logging_setup",
        "messagefoundry.odbc_env",
        "messagefoundry.redaction",
        # Eager on purpose (vault BACKLOG #2700): `serve` and `supervise` call it as their first
        # statement, ahead of their own lazy imports. Stdlib and `controlchars` only.
        "messagefoundry.remotedebug",
        "messagefoundry.secretscrub",
    }
)

#: `--help` stops once the parser is built. `_build_parser` builds every subparser, so `check`,
#: `verify` and `serve --help` load the same set today; one stands for all three. Add the others
#: back if parser building ever becomes per-subcommand.
_PROBES = {
    "cli-version": _Probe("cli", ("--version",), _CLI_DEFERRED, _CLI_ENGINE),
    "cli-check-help": _Probe("cli", ("check", "--help"), _CLI_DEFERRED, _CLI_ENGINE),
    "tray-first-process": _Probe(
        "tray",
        (),
        frozenset(
            {"messagefoundry.service_status", "messagefoundry.tray.instance", "asyncio", "tomllib"}
        ),
        frozenset(
            {
                "messagefoundry",
                "messagefoundry.api_tls_source",
                "messagefoundry.controlchars",
                "messagefoundry.redaction",
                "messagefoundry.secretscrub",
                "messagefoundry.tray",
                "messagefoundry.tray.__main__",
                "messagefoundry.tray.branding",
                "messagefoundry.tray.config",
                "messagefoundry.tray.logscrub",
            }
        ),
    ),
}

_PROBE_CODE = """
import json, sys
out, mode, kind, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
if mode == "eager" and hasattr(sys, "set_lazy_imports_filter"):
    sys.set_lazy_imports_filter(lambda *_: False)
try:
    if kind == "cli":
        import runpy
        sys.argv = ["messagefoundry", *args]
        runpy.run_module("messagefoundry", run_name="__main__")
    else:
        import messagefoundry.tray.__main__
        import messagefoundry.tray.branding  # main() imports it before the re-exec
    code = 0
except SystemExit as exc:
    code = exc.code
finally:
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(sorted(sys.modules), fh)
sys.exit(code)
"""


def _loaded(tmp_path: Path, probe: _Probe, *, mode: str) -> set[str]:
    out = tmp_path / "modules.json"
    # PYTHON_LAZY_IMPORTS would override the lists in both arms, so the probe never inherits it.
    env = {k: v for k, v in os.environ.items() if k != "PYTHON_LAZY_IMPORTS"}
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE_CODE, str(out), mode, probe.kind, *probe.args],
        capture_output=True,
        text=True,
        env=env,
        # Under the suite's 60 s pytest-timeout, so a hung probe still reports its stderr.
        timeout=50,
    )
    assert proc.returncode == 0 and out.exists(), proc.stderr[-2000:]
    return set(json.loads(out.read_text(encoding="utf-8")))


@pytest.mark.parametrize("name", list(_PROBES))
def test_control_arm_loads_every_deferred_module_when_eager(tmp_path: Path, name: str) -> None:
    probe = _PROBES[name]
    missing = probe.deferred - _loaded(tmp_path, probe, mode="eager")
    assert not missing, f"never loaded even eagerly, so the lazy entry is dead: {sorted(missing)}"


@pytest.mark.skipif(sys.version_info < (3, 15), reason=_LAZY_ARM_SKIP)
@pytest.mark.parametrize("name", list(_PROBES))
def test_startup_stays_within_budget(tmp_path: Path, name: str) -> None:
    probe = _PROBES[name]
    loaded = _loaded(tmp_path, probe, mode="lazy")
    early = probe.deferred & loaded
    assert not early, f"deferred module loaded at startup: {sorted(early)}"
    engine = {m for m in loaded if m.partition(".")[0] == "messagefoundry"}
    assert engine == probe.engine, (
        f"added: {sorted(engine - probe.engine)}, removed: {sorted(probe.engine - engine)}"
    )
