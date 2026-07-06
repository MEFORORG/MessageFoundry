# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Host / environment checks — wheel-only, no source tree or test suite required.

Each check returns a :class:`CheckResult` and **never raises**: a broken check returns ``ERROR`` with
the reason. Optional third-party imports (pyodbc, asyncpg, PySide6) are guarded — absence is ``SKIP``
(can't verify here), so the same set runs on a minimal install and a fully-extra'd box, degrading
honestly. Engine files are located via ``importlib`` (works from site-packages), never by assuming a
repo layout.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import socket
import sys
import tempfile
from pathlib import Path

from messagefoundry import __version__
from messagefoundry.verify.model import CheckResult, Status


def _can_import(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def check_python_runtime() -> CheckResult:
    """Python 3.14+ and the engine package importable at a known version."""
    ver = sys.version_info
    if ver < (3, 14):
        return CheckResult(
            "host.python",
            "Python 3.14+",
            Status.FAIL,
            f"Python {ver.major}.{ver.minor} < 3.14 (engine requires 3.14+)",
        )
    return CheckResult(
        "host.python",
        "Python 3.14+ and engine import",
        Status.PASS,
        f"Python {ver.major}.{ver.minor}.{ver.micro}, messagefoundry {__version__}",
    )


def check_optional_drivers() -> CheckResult:
    """Report which optional driver extras are importable (postgres / sqlserver / dicom)."""
    groups = {
        "postgres": ("asyncpg",),
        "sqlserver": ("aioodbc",),
        "dicom": ("pydicom", "pynetdicom"),
    }
    present = [extra for extra, mods in groups.items() if all(_can_import(m) for m in mods)]
    missing = [extra for extra in groups if extra not in present]
    detail = f"present: {', '.join(present) or 'none'}"
    if missing:
        return CheckResult(
            "host.extras",
            "Optional driver extras",
            Status.SKIP,
            f"{detail}; not installed: {', '.join(missing)}",
        )
    return CheckResult("host.extras", "Optional driver extras", Status.PASS, detail)


def check_sqlserver_odbc_driver() -> CheckResult:
    """Microsoft ODBC Driver 18 for SQL Server installed and discoverable via pyodbc."""
    if not _can_import("pyodbc"):
        return CheckResult(
            "host.odbc",
            "SQL Server ODBC Driver 18",
            Status.SKIP,
            "pyodbc not importable (install the [sqlserver] extra)",
        )
    try:
        # Dynamic import keeps mypy --strict clean (pyodbc ships no type stubs).
        pyodbc = importlib.import_module("pyodbc")
        drivers = list(pyodbc.drivers())
    except Exception as exc:  # pyodbc surfaces driver-manager errors as bare Exception
        return CheckResult(
            "host.odbc",
            "SQL Server ODBC Driver 18",
            Status.ERROR,
            f"pyodbc.drivers() failed: {exc}",
        )
    target = "ODBC Driver 18 for SQL Server"
    if target in drivers:
        return CheckResult(
            "host.odbc",
            "SQL Server ODBC Driver 18",
            Status.PASS,
            f"{target} present",
            evidence=", ".join(drivers),
        )
    seen = [d for d in drivers if "SQL Server" in d]
    return CheckResult(
        "host.odbc",
        "SQL Server ODBC Driver 18",
        Status.FAIL,
        f"{target!r} not found; SQL Server drivers seen: {seen or 'none'}",
        evidence=", ".join(drivers),
    )


def check_postgres_driver() -> CheckResult:
    """asyncpg (the [postgres] driver) importable and reporting a version."""
    if not _can_import("asyncpg"):
        return CheckResult(
            "host.asyncpg",
            "PostgreSQL driver (asyncpg)",
            Status.SKIP,
            "asyncpg not importable (install the [postgres] extra)",
        )
    try:
        ver = importlib.metadata.version("asyncpg")
    except importlib.metadata.PackageNotFoundError:
        ver = "?"
    return CheckResult(
        "host.asyncpg",
        "PostgreSQL driver (asyncpg)",
        Status.PASS,
        f"asyncpg {ver} (pure-Python; no libpq needed)",
    )


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


def check_listener_ports(ports: dict[str, int]) -> CheckResult:
    """MANUAL: external firewall rules can't be introspected; report local bindability as evidence."""
    parts = [
        f"{name} {port}: {'free' if _bindable(port) else 'in use/bound'}"
        for name, port in ports.items()
    ]
    return CheckResult(
        "host.ports",
        "Listener ports / firewall",
        Status.MANUAL,
        "confirm inbound firewall rules admit these ports from partner hosts",
        evidence="; ".join(parts),
    )


def check_writable_dir(path: Path) -> CheckResult:
    """The given dir (store/working dir) is writable by this process; ACLs for the service account are manual."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix="._mefor_verify_", delete=True):
            pass
    except OSError as exc:
        return CheckResult(
            "host.writable",
            "Writable store/working dir",
            Status.FAIL,
            f"cannot write {path}: {exc}",
        )
    return CheckResult(
        "host.writable",
        "Writable store/working dir",
        Status.MANUAL,
        f"{path} writable by this user; confirm the NSSM service account's ACLs on store/config/log",
        evidence=str(path),
    )


def check_console_importable() -> CheckResult:
    """The console package imports (PySide6 present); an interactive desktop session is a manual confirm."""
    if not _can_import("PySide6"):
        return CheckResult(
            "host.console",
            "Console importable",
            Status.SKIP,
            "PySide6 not importable (install the [console] extra)",
        )
    return CheckResult(
        "host.console",
        "Console importable",
        Status.MANUAL,
        "PySide6 present; confirm a real desktop session (not Server Core)",
    )


def check_console_no_window() -> CheckResult:
    """The console's service-control path passes CREATE_NO_WINDOW (no console flash on Status poll)."""
    try:
        # find_spec on a SUBMODULE imports the parent package; if console/__init__ ever drags a
        # missing [console]-extra dep (e.g. httpx) this raises ModuleNotFoundError. Degrade to SKIP
        # like every sibling check instead of crashing the whole `verify` run on a non-[console] box.
        spec = importlib.util.find_spec("messagefoundry.console.service_control")
    except (ImportError, ValueError):
        spec = None
    if spec is None or not spec.origin:
        return CheckResult(
            "host.noflash",
            "Console no-window flag",
            Status.SKIP,
            "console.service_control not installed (no [console] extra)",
        )
    try:
        text = Path(spec.origin).read_text(encoding="utf-8")
    except OSError as exc:
        return CheckResult(
            "host.noflash",
            "Console no-window flag",
            Status.ERROR,
            f"could not read service_control source: {exc}",
        )
    if "CREATE_NO_WINDOW" in text:
        return CheckResult(
            "host.noflash",
            "Console no-window flag",
            Status.MANUAL,
            "CREATE_NO_WINDOW set; visually confirm no console flashes during the Status-page poll",
        )
    return CheckResult(
        "host.noflash",
        "Console no-window flag",
        Status.FAIL,
        "CREATE_NO_WINDOW missing from service_control — console-flash guard regressed",
    )


def run_host_checks(*, ports: dict[str, int], writable_dir: Path) -> list[CheckResult]:
    """Run every host/environment check and return their results (order is stable)."""
    return [
        check_python_runtime(),
        check_optional_drivers(),
        check_sqlserver_odbc_driver(),
        check_postgres_driver(),
        check_listener_ports(ports),
        check_writable_dir(writable_dir),
        check_console_importable(),
        check_console_no_window(),
    ]
