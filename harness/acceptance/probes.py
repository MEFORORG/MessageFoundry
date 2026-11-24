# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import contextlib
import logging
import os
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from harness.acceptance.matrix import Status

#: Repo root (…/harness/acceptance/probes.py → parents[2]).
_REPO_ROOT = Path(__file__).resolve().parents[2]

_log = logging.getLogger(__name__)

#: Fixed reference ports for section A5 (informational bindability check), one entry per listener
#: the A5 row names (BACKLOG #5849). Each is a stock default, not what a given deployment binds,
#: which depends on its config and --env. TCP is the default of ``IB_Harness_TCP``, the raw-TCP
#: inbound in ``harness/config/tcp_x12.py`` (endpoint ``tcp_in``); a test pins the two together.
_DEFAULT_PORTS: dict[str, int] = {"MLLP": 2575, "DICOM": 11112, "TCP": 2580, "API": 8765}


class _ChainCut(Exception):
    """Current at :func:`scrubbed_exc`'s log call in place of any exception its caller is handling.
    Its ``__context__`` is cleared there, so no chain through it reaches the caller's exception."""


def scrubbed_exc(exc: BaseException, *, before: str = "", typed: bool = False) -> str:
    """``exc`` for a report row, through the verifier's detail scrub (BACKLOG #5395): ``before`` and
    the text as :func:`messagefoundry.verify_leaf.safe_exc_text`, or, with ``typed``, ``before``,
    the type name and the text, all three through one ``safe_detail_text`` pass, so ``before`` is
    scanned with the raw text on this path too. A ``UnicodeError`` gives ``safe_exc_detail``'s
    rendering in place of its text, which quotes no character of the message. A report row leaves
    the box, and driver or OS text can quote a DSN, a credential or a path, and so can ``before``.

    The scrub is imported here, at call time, and a failure to load or run it withholds both
    ``before`` and the text rather than printing either raw, and names the failure's type instead.
    That row then names no probe key or path the caller put in ``before``. The failure is logged at
    WARNING with the two exceptions' type names and no text, after the ``except`` block has ended,
    and with :class:`_ChainCut` current, its ``__context__`` cleared. A handler whose ``emit``
    fails and calls ``logging``'s ``handleError`` prints the current chain to stderr; this way
    that chain reaches neither the scrub failure nor an exception the caller is handling, either
    of which could quote the text. An ``Exception`` raised by the log call itself, such as one from
    a log filter or a record factory, is dropped, so this still returns the withheld row, and one
    line naming only the three exceptions' types, each through ``ascii``, is written to stderr,
    best effort: where stderr is missing or broken, nothing records the drop. A handler that ran
    before the raise may already have emitted the warning. The log call is the last resort, and
    letting its failure propagate would carry frames holding the raw ``exc`` and ``before`` out of here and
    break the contract that a probe never raises. A ``BaseException`` such as ``KeyboardInterrupt``
    is not caught, so it still propagates with those frames. A1 exists to report an interpreter the
    engine cannot run on, and there the engine's modules may not even parse, so a scrub that fails
    to load must not take the runner down either."""
    # Bound on every path, though only the except below reaches the code that reads it.
    failure_name = "unknown"
    try:
        from messagefoundry.redaction import codec_safe_str
        from messagefoundry.verify_leaf import (
            DRIVER_DETAIL_LIMIT,
            safe_detail_text,
            safe_exc_detail,
            safe_exc_text,
        )

        if typed:
            # One pass, not safe_exc_detail then a second scrub: a second pass would read text the
            # first had already hidden, and its length bound would drop the first's notes.
            if isinstance(exc, UnicodeError):
                line = safe_exc_detail(exc)
            else:
                text = codec_safe_str(exc)
                line = f"{type(exc).__name__}: {text}" if text else type(exc).__name__
            return safe_detail_text(before + line, limit=DRIVER_DETAIL_LIMIT)
        return safe_exc_text(exc, before=before)
    except Exception as scrub_failure:  # SyntaxError or ImportError on such an interpreter
        # Type names only, kept as plain strings: the failure's own text could quote the detail it
        # failed to scrub, and the exception objects must not outlive this block.
        failure_name = type(scrub_failure).__name__
    exc_name = type(exc).__name__
    # Logged outside the except block, so the scrub failure is not current at the log call. A
    # caller that passes the exception it is handling still has that one current, and a handler
    # whose emit fails would print it to stderr as the emit failure's __context__. So _ChainCut is
    # made current instead, with its own __context__ cleared: from None alone only hides the
    # context from the default printer, and a chain walker would still reach the caller's text.
    try:
        raise _ChainCut from None
    except _ChainCut as cut:
        cut.__context__ = None
        try:
            _log.warning(
                "the detail scrub failed with %s; a row's %s detail is withheld",
                failure_name,
                exc_name,
            )
        except Exception as log_failure:  # Exception only, never BaseException
            # The log call is the last resort: logging has no channel left to report its own
            # failure, and propagating would leak frames holding the raw exc and before and break
            # the probe contract that run_probe and run_matrix rely on. So the failure is dropped,
            # and one line of type names goes to stderr, under its own guard, so the drop is not
            # silent where stderr works. The failure's text is not printed: a filter or factory
            # can quote anything it saw. ascii() keeps a crafted type name to one printable line.
            with contextlib.suppress(Exception):
                sys.stderr.write(
                    f"{_log.name}: the scrub-failure warning's log call raised "
                    f"{ascii(type(log_failure).__name__)}; the scrub failed with "
                    f"{ascii(failure_name)}, and the row's {ascii(exc_name)} detail is withheld\n"
                )
    return f"{exc_name} (detail withheld: the detail scrub failed with {failure_name})"


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
        # Driver-manager text can quote a DSN or a credential, as the verifier's copy found.
        return ProbeResult(Status.ERROR, scrubbed_exc(exc, before="pyodbc.drivers() failed: "))
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


def probe_firewall_ports() -> ProbeResult:
    """A5 — MANUAL: external firewall rules can't be introspected; report local bindability.

    Each port's state is the verifier's own ``host.ports`` probe, so the two read a port the same
    way. The copy this replaced bound 127.0.0.1 with ``SO_REUSEADDR`` and so would have read a held
    port as free on Windows (BACKLOG #5389). It comes from the client-importable leaf
    :mod:`messagefoundry.verify_leaf`, whose module docstring says what it imports, never from
    :mod:`messagefoundry.verify`, whose runner loads the engine's transports and config."""
    from messagefoundry.verify_leaf import port_state

    parts = [f"{name} {port}: {port_state(port)}" for name, port in _DEFAULT_PORTS.items()]
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
        return ProbeResult(
            Status.FAIL, scrubbed_exc(exc, before=f"cannot write working dir {cwd}: ")
        )
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
        return ProbeResult(
            Status.ERROR, scrubbed_exc(exc, before=f"probe {key!r} raised ", typed=True)
        )
