# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Host / environment checks — wheel-only, no source tree or test suite required.

Each check returns a :class:`CheckResult` and **never raises**: a broken check returns ``ERROR`` with
the reason. Optional third-party imports (pyodbc, asyncpg) are guarded — absence is ``SKIP`` (can't
verify here), so the same set runs on a minimal install and a fully-extra'd box, degrading honestly.
Engine files are located via ``importlib`` (works from site-packages), never by assuming a repo
layout.

**No check here creates what it checks** (BACKLOG #1708). A check that makes the thing it reports on
cannot fail for the reason its title names, and on a first deployment an operator running ``verify``
elevated would leave administrator-owned directories at the configured path before the service
starts under another identity — which is the identity gap ``host.writable``'s own text warns about,
manufactured by the check.
"""

from __future__ import annotations

import ast
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
    """The given dir (store/working dir) exists and is writable by this process; ACLs are manual.

    Does **not** create the directory (BACKLOG #1708). It used to ``mkdir(parents=True)`` first, so a
    mistyped ``[store].path`` reported writable against a tree the check had just made — and this row
    runs *before* ``store.connect``, so the directory it created was the one the store then filled.
    An absent directory is now a FAIL naming the path.
    """
    rid, title = "host.writable", "Writable store/working dir"
    try:
        exists = path.is_dir()
    except OSError as exc:  # e.g. a permission error stat-ing an ancestor
        return CheckResult(rid, title, Status.FAIL, f"cannot stat {path}: {exc}")
    if not exists:
        return CheckResult(
            rid,
            title,
            Status.FAIL,
            f"no directory at {path} — create it and grant the service account on it, "
            "or check [store].path (verify does not create it for you)",
            evidence=str(path),
        )
    try:
        with tempfile.NamedTemporaryFile(dir=path, prefix="._mefor_verify_", delete=True):
            pass
    except OSError as exc:
        return CheckResult(rid, title, Status.FAIL, f"cannot write {path}: {exc}")
    return CheckResult(
        rid,
        title,
        Status.MANUAL,
        f"{path} writable by this user; confirm the NSSM service account's ACLs on store/config/log",
        evidence=str(path),
    )


#: Modules that spawn ``sc.exe`` from a possibly-windowless host and must suppress its console.
#: ``service_status`` carries its own ``_NO_WINDOW`` (it is the stdlib-only neutral leaf and does not
#: import its elevated sibling), so checking one module would leave the other's regression invisible.
_NO_WINDOW_MODULES: tuple[str, ...] = ("messagefoundry.service", "messagefoundry.service_status")


def _spawns_without_creationflags(source: str) -> list[str]:
    """Names of ``subprocess`` spawns in ``source`` that pass no ``creationflags=`` keyword.

    An AST walk rather than a substring search (BACKLOG #1713). The old check passed on the literal
    text ``CREATE_NO_WINDOW`` appearing anywhere in the file, which the module's own explanatory
    comment satisfies on its own — so the check stayed MANUAL through exactly the regression its FAIL
    text claims to catch, a call site losing ``creationflags=``. A comment cannot satisfy this.
    """
    spawns = {"run", "Popen", "call", "check_call", "check_output"}
    missing: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in spawns:
            continue
        if not (isinstance(func.value, ast.Name) and func.value.id == "subprocess"):
            continue
        if not any(kw.arg == "creationflags" for kw in node.keywords):
            missing.append(f"subprocess.{func.attr} at line {node.lineno}")
    return missing


def check_console_no_window() -> CheckResult:
    """Every ``sc.exe`` spawn suppresses its console window (no flash on the Status-page poll).

    Two conditions, because either alone is satisfiable by a regression (BACKLOG #1713):

    1. the module's ``_NO_WINDOW`` resolves to a non-zero flag, and
    2. every ``subprocess`` spawn in it passes ``creationflags=``.

    Windows-only. ``_NO_WINDOW`` is legitimately ``0`` elsewhere (``CREATE_NO_WINDOW`` does not
    exist off Windows and the constant is a ``getattr`` default), so this SKIPs rather than failing —
    and :mod:`messagefoundry.service` imports ``ctypes.wintypes``, which is not importable off
    Windows at all.
    """
    rid, title = "host.noflash", "Console no-window flag"
    if sys.platform != "win32":
        return CheckResult(
            rid,
            title,
            Status.SKIP,
            f"no console-window flash off Windows (CREATE_NO_WINDOW does not exist on {sys.platform})",
        )
    checked: list[str] = []
    for name in _NO_WINDOW_MODULES:
        try:
            module = importlib.import_module(name)
        except ImportError as exc:
            return CheckResult(rid, title, Status.SKIP, f"{name} not importable: {exc}")
        flag = getattr(module, "_NO_WINDOW", None)
        if not isinstance(flag, int) or flag == 0:
            return CheckResult(
                rid,
                title,
                Status.FAIL,
                f"{name}._NO_WINDOW is {flag!r} on Windows — console-flash guard regressed",
            )
        origin = getattr(module, "__file__", None)
        if not origin:
            return CheckResult(rid, title, Status.SKIP, f"{name} has no source file to inspect")
        try:
            missing = _spawns_without_creationflags(Path(origin).read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError) as exc:
            return CheckResult(rid, title, Status.ERROR, f"could not inspect {name}: {exc}")
        if missing:
            return CheckResult(
                rid,
                title,
                Status.FAIL,
                f"{name} spawns a subprocess without creationflags= ({', '.join(missing)}) — "
                "console-flash guard regressed",
            )
        checked.append(f"{name} (_NO_WINDOW={flag:#x})")
    return CheckResult(
        rid,
        title,
        Status.MANUAL,
        "every sc.exe spawn passes CREATE_NO_WINDOW; visually confirm no console flashes "
        "during the Status-page poll",
        evidence="; ".join(checked),
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
        check_console_no_window(),
    ]
