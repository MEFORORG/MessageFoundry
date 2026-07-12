# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Live host/environment probes — the rows nothing else in the suite can assert.

Each probe is a zero-arg callable returning a :class:`ProbeResult`. Probes must never raise: a broken
check returns ``Status.ERROR`` with the reason. Optional third-party imports (pyodbc, asyncpg,
PySide6) are guarded — absence is ``Status.SKIP`` (can't verify here), not a crash, so the same probe
set runs on the dev PC and the target server, degrading honestly.

Probes deliberately do **not** claim PASS for things only a human on the box can confirm (firewall
rules admitting external traffic, service-account ACLs, a real interactive desktop): those return
``Status.MANUAL`` carrying whatever evidence the probe *could* gather (e.g. local port bindability).
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from harness.acceptance.matrix import Status

#: Repo root (…/harness/acceptance/probes.py → parents[2]).
_REPO_ROOT = Path(__file__).resolve().parents[2]

#: Default listener ports referenced by section A5 (informational bindability check).
_DEFAULT_PORTS: dict[str, int] = {"MLLP": 2575, "DICOM": 11112, "API": 8765}


@dataclass
class ProbeResult:
    """Outcome of one probe: a status, a one-line human detail, and optional evidence."""

    status: Status
    detail: str
    evidence: str = ""


def _in_virtualenv() -> bool:
    # PEP 405 venv / virtualenv both diverge sys.prefix from the base interpreter prefix.
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def _can_import(module: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def probe_python_runtime() -> ProbeResult:
    """A1 — Python 3.14+, a project virtualenv, and the hash-locked requirements present."""
    ver = sys.version_info
    if ver < (3, 14):
        return ProbeResult(
            Status.FAIL, f"Python {ver.major}.{ver.minor} < 3.14 (project targets 3.14+)"
        )
    lock = _REPO_ROOT / "requirements.lock"
    bits = [f"Python {ver.major}.{ver.minor}.{ver.micro}"]
    bits.append("venv" if _in_virtualenv() else "NOT in a venv")
    bits.append("requirements.lock present" if lock.is_file() else "requirements.lock MISSING")
    ok = lock.is_file()  # venv is advisory; the lockfile is the hard signal we can see at runtime
    return ProbeResult(Status.PASS if ok else Status.FAIL, "; ".join(bits))


def probe_optional_extras() -> ProbeResult:
    """A2 — the server-relevant optional extras import (postgres, sqlserver, dicom)."""
    groups: dict[str, tuple[str, ...]] = {
        "postgres": ("asyncpg",),  # the [postgres] extra (pure-Python driver — no libpq)
        "sqlserver": ("aioodbc",),  # the [sqlserver] extra (drags pyodbc)
        "dicom": ("pydicom", "pynetdicom"),
    }
    present: list[str] = []
    missing: list[str] = []
    for extra, mods in groups.items():
        if all(_can_import(m) for m in mods):
            present.append(extra)
        else:
            missing.append(extra)
    detail = f"present: {', '.join(present) or 'none'}"
    if missing:
        # On the dev PC some extras are legitimately absent — SKIP (can't verify), don't fail the box.
        return ProbeResult(Status.SKIP, f"{detail}; missing: {', '.join(missing)}")
    return ProbeResult(Status.PASS, detail)


def probe_sqlserver_odbc_driver() -> ProbeResult:
    """A3 — Microsoft ODBC Driver 18 for SQL Server is installed and discoverable via pyodbc."""
    import importlib

    if not _can_import("pyodbc"):
        return ProbeResult(Status.SKIP, "pyodbc not importable (install the [sqlserver] extra)")
    try:
        # Dynamic import: pyodbc ships no type stubs, so this keeps mypy --strict clean.
        pyodbc = importlib.import_module("pyodbc")
        drivers = list(pyodbc.drivers())
    except Exception as exc:  # pyodbc surfaces driver-manager errors as bare Exception
        return ProbeResult(Status.ERROR, f"pyodbc.drivers() failed: {exc}")
    target = "ODBC Driver 18 for SQL Server"
    if target in drivers:
        return ProbeResult(Status.PASS, f"{target} present", evidence=", ".join(drivers))
    sql_drivers = [d for d in drivers if "SQL Server" in d]
    return ProbeResult(
        Status.FAIL,
        f"{target!r} not found; SQL Server drivers seen: {sql_drivers or 'none'}",
        evidence=", ".join(drivers),
    )


def probe_postgres_client() -> ProbeResult:
    """A4 — asyncpg (the [postgres] driver) is importable and reports a version.

    The engine's PostgreSQL store uses **asyncpg**, which speaks the wire protocol directly and needs
    no libpq/psycopg on the box — so this probes asyncpg, not psycopg (the [postgres] extra installs
    asyncpg). Absent ⇒ SKIP; present ⇒ PASS with the version.
    """
    try:
        import asyncpg
    except ImportError:
        return ProbeResult(Status.SKIP, "asyncpg not importable (install the [postgres] extra)")
    return ProbeResult(Status.PASS, f"asyncpg {getattr(asyncpg, '__version__', '?')}")


def _bindable(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def probe_firewall_ports() -> ProbeResult:
    """A5 — MANUAL: external firewall rules can't be introspected; report local bindability."""
    parts = [
        f"{name} {port}: {'free' if _bindable(port) else 'in use'}"
        for name, port in _DEFAULT_PORTS.items()
    ]
    return ProbeResult(
        Status.MANUAL,
        "confirm inbound firewall rules admit these ports from partner hosts",
        evidence="; ".join(parts),
    )


def probe_writable_dirs() -> ProbeResult:
    """A6 — current process can write the working dir; service-account ACLs remain a manual check."""
    cwd = Path.cwd()
    try:
        with tempfile.NamedTemporaryFile(dir=cwd, prefix="._mefor_probe_", delete=True):
            pass
    except OSError as exc:
        return ProbeResult(Status.FAIL, f"cannot write working dir {cwd}: {exc}")
    return ProbeResult(
        Status.MANUAL,
        "working dir writable by this user; confirm the NSSM service account's ACLs on store/config/log",
        evidence=str(cwd),
    )


def probe_console_gui() -> ProbeResult:
    """A7 — PySide6 imports (console process can start); interactive desktop is a manual confirm."""
    if not _can_import("PySide6"):
        return ProbeResult(Status.SKIP, "PySide6 not importable (install the [console] extra)")
    platform = os.environ.get("QT_QPA_PLATFORM", "(default)")
    return ProbeResult(
        Status.MANUAL,
        "PySide6 present; confirm a real desktop session (not Server Core / offscreen)",
        evidence=f"QT_QPA_PLATFORM={platform}",
    )


def probe_console_no_window() -> ProbeResult:
    """F7 — the console's service-control subprocess path passes CREATE_NO_WINDOW (no flash)."""
    src = _REPO_ROOT / "messagefoundry" / "service.py"
    if not src.is_file():
        return ProbeResult(Status.ERROR, f"expected source not found: {src}")
    text = src.read_text(encoding="utf-8")
    if "CREATE_NO_WINDOW" in text:
        return ProbeResult(
            Status.MANUAL,
            "CREATE_NO_WINDOW set in service-control path; visually confirm no console flashes on Status poll",
            evidence=str(src.relative_to(_REPO_ROOT)),
        )
    return ProbeResult(
        Status.FAIL, f"CREATE_NO_WINDOW missing from {src.name} — console-flash guard regressed"
    )


#: Probe registry — keys match the ``refs[0]`` of every ``Coverage.PROBE`` row in the matrix.
PROBES: dict[str, Callable[[], ProbeResult]] = {
    "python_runtime": probe_python_runtime,
    "optional_extras": probe_optional_extras,
    "sqlserver_odbc_driver": probe_sqlserver_odbc_driver,
    "postgres_client": probe_postgres_client,
    "firewall_ports": probe_firewall_ports,
    "writable_dirs": probe_writable_dirs,
    "console_gui": probe_console_gui,
    "console_no_window": probe_console_no_window,
}


def run_probe(key: str) -> ProbeResult:
    """Run the probe registered under ``key``, turning any unexpected raise into ``Status.ERROR``."""
    probe = PROBES.get(key)
    if probe is None:
        return ProbeResult(Status.ERROR, f"no probe registered for {key!r}")
    try:
        return probe()
    except Exception as exc:  # a probe must never take the runner down
        return ProbeResult(Status.ERROR, f"probe {key!r} raised: {exc!r}")
