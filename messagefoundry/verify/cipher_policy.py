# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The host cipher policy the ODBC Driver 18 hops take: DEPLOY-SERVER-DB.md section 5.4, run.

The native driver terminates TLS, so the host's TLS policy decides the suites and versions on every
ODBC hop (ADR 0180). Section 5.4 asks the operator to set that policy and gives manual commands to
check it. This module runs the same checks for ``messagefoundry verify`` and reports what it read
(ASVS 11.3.5). It is operator-run only: nothing here is wired into ``serve``, so it never refuses or
delays an engine start. Owner ruling R3 declined a startup check of this policy, not an operator one.

Every reading carries its control. A suite list that reads empty, or an instrument that is missing
or fails, is never a PASS, because a zero non-AEAD count over an empty list proves nothing.

Windows reads two things. The enabled SChannel suites come from ``Get-TlsCipherSuite``, which has no
registry or API equivalent in the standard library, so it runs through Windows PowerShell with a
fixed argument list and no host data in it. The TLS 1.0 and 1.1 client switches come from the
registry through stdlib ``winreg``, which needs no subprocess. Linux runs the ``openssl`` command
rather than Python's ``ssl`` module: section 5.4 measured that the CLI offers what the driver
offers, and Python sets its own default cipher string over the host's ``CipherString``.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.childenv import hook_environment
from messagefoundry.verify.model import CheckResult, Status

RID = "host.ciphers"
TITLE = "Host cipher policy (ODBC hops)"

#: Windows PowerShell can take several seconds to start cold, so the budget is generous.
_PROBE_TIMEOUT_S = 30.0
#: CREATE_NO_WINDOW off Windows is 0, and the probe there is openssl, which opens no console anyway.
_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_SCHANNEL_PROTOCOLS = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
_LEGACY_VERSIONS: tuple[str, ...] = ("TLS 1.0", "TLS 1.1")
#: Section 5.4's check 1 pattern for an AEAD suite name in SChannel's naming.
_SCHANNEL_AEAD = re.compile("GCM|CCM|CHACHA20_POLY1305")

_OPENSSL_CNF = Path("/etc/ssl/openssl.cnf")
_POLICY_LINE = re.compile(r"^\s*(CipherString|Ciphersuites|MinProtocol)\s*=\s*([^#]*)")
_TLS12_OR_HIGHER = frozenset({"TLSv1.2", "TLSv1.3"})

_SEE_DOC = "see DEPLOY-SERVER-DB.md section 5.4"


class ProbeUnavailable(Exception):
    """The instrument is not on this host, so a person has to run section 5.4 by hand."""


class ProbeFailed(Exception):
    """The instrument ran and gave no usable reading."""


@dataclass(frozen=True)
class _Reading:
    status: Status  # PASS, FAIL, ERROR or MANUAL
    text: str
    evidence: str = ""


#: Worst first: a confirmed finding outranks a reading that broke, which outranks one not taken.
_PRECEDENCE: tuple[Status, ...] = (Status.FAIL, Status.ERROR, Status.MANUAL, Status.PASS)


def _run_lines(argv: list[str]) -> list[str]:
    """The non-blank stdout lines of ``argv``; a missing command or a failed run raises.

    The child gets everything outside the engine's own namespace and its secrets. OpenSSL reads
    ``OPENSSL_CONF`` and its siblings from the environment, and section 5.4 asks for the check to
    run with the engine's environment, so a start-up-names-only environment would read a different
    policy from the one the driver takes."""
    try:
        proc = subprocess.run(  # nosec B603 B607 - argv list (no shell), fixed arguments
            argv,
            env=hook_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_PROBE_TIMEOUT_S,
            check=False,
            creationflags=_NO_WINDOW,
        )
    except FileNotFoundError as exc:
        raise ProbeUnavailable(f"{argv[0]} not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProbeFailed(f"{argv[0]} did not finish in {_PROBE_TIMEOUT_S:.0f}s") from exc
    except OSError as exc:
        raise ProbeFailed(f"{argv[0]} could not run: {exc}") from exc
    if proc.returncode != 0:
        first = next((ln.strip() for ln in proc.stderr.splitlines() if ln.strip()), "")
        raise ProbeFailed(
            f"{argv[0]} exited {proc.returncode}" + (f": {first[:200]}" if first else "")
        )
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _windows_enabled_suites() -> list[str]:
    """The enabled SChannel suite names, as section 5.4's check 1 reads them.

    ``(Get-TlsCipherSuite).Name`` and not a pipe into ``Where-Object Name``: section 5.4 measured
    that pipe passing the whole list through unfiltered. The filtering happens here, in Python."""
    # The absolute path, not a PATH lookup: Windows PowerShell ships with the OS, and a PATH entry
    # ahead of System32 must not choose which program reads the policy.
    exe = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / (
        r"System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    return _run_lines(
        [str(exe), "-NoProfile", "-NonInteractive", "-Command", "(Get-TlsCipherSuite).Name"]
    )


def _schannel_client_enabled(version: str) -> int | None:
    """The DWORD ``Enabled`` under ``<version>\\Client``, or ``None`` when the key or value is unset."""
    if sys.platform != "win32":
        raise ProbeUnavailable("the Windows registry is not available on this platform")
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, rf"{_SCHANNEL_PROTOCOLS}\{version}\Client"
        ) as key:
            value, kind = winreg.QueryValueEx(key, "Enabled")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProbeFailed(f"{version} client key could not be read: {exc}") from exc
    if kind != winreg.REG_DWORD or not isinstance(value, int):
        raise ProbeFailed(f"{version} client Enabled holds registry type {kind}, not a DWORD")
    return value


def _openssl_suites() -> list[str]:
    """``openssl ciphers -s -v``: one line per suite this host's OpenSSL configuration allows."""
    return _run_lines(["openssl", "ciphers", "-s", "-v"])


def _openssl_policy_lines() -> tuple[Path, list[tuple[str, str]]]:
    """The ``CipherString``, ``Ciphersuites`` and ``MinProtocol`` settings in the OpenSSL file.

    Reads the file ``OPENSSL_CONF`` names when this environment sets it, so the file read is the one
    the ``openssl`` probe above loaded. Like section 5.4's ``grep``, it reads every section of the
    file, not only ``[system_default_sect]``."""
    named = os.environ.get("OPENSSL_CONF")
    path = Path(named) if named else _OPENSSL_CNF
    text = path.read_text(encoding="utf-8", errors="replace")
    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = _POLICY_LINE.match(line)
        if match:
            found.append((match.group(1), match.group(2).strip()))
    return path, found


def _suite_reading(probe: Callable[[], list[str]], is_aead: Callable[[str], bool]) -> _Reading:
    try:
        lines = probe()
    except ProbeUnavailable as exc:
        return _Reading(Status.MANUAL, f"suites not read ({exc}); run the commands by hand")
    except ProbeFailed as exc:
        return _Reading(Status.ERROR, f"suites not read: {exc}")
    if not lines:
        return _Reading(
            Status.ERROR,
            "the enabled-suite list read empty, so its control is 0 and a count of non-AEAD "
            "suites over it proves nothing",
        )
    weak = [line.split()[0] for line in lines if not is_aead(line)]
    if weak:
        return _Reading(
            Status.FAIL,
            f"{len(weak)} of {len(lines)} enabled suites are not AEAD",
            evidence="not AEAD: " + ", ".join(weak),
        )
    return _Reading(Status.PASS, f"all {len(lines)} enabled suites are AEAD")


def _windows_protocol_reading() -> _Reading:
    problems: list[str] = []
    for version in _LEGACY_VERSIONS:
        try:
            value = _schannel_client_enabled(version)
        except (ProbeUnavailable, ProbeFailed) as exc:
            return _Reading(Status.ERROR, f"protocol switches not read: {exc}")
        if value is None:
            problems.append(f"{version} client Enabled is not set")
        elif value != 0:
            problems.append(f"{version} client Enabled={value}")
    if problems:
        return _Reading(Status.FAIL, "; ".join(problems) + " (section 5.4 asks for Enabled=0)")
    return _Reading(Status.PASS, "TLS 1.0 and TLS 1.1 client Enabled=0")


def _linux_policy_reading() -> _Reading:
    try:
        path, settings = _openssl_policy_lines()
    except FileNotFoundError as exc:
        return _Reading(
            Status.MANUAL, f"no OpenSSL file at {exc.filename}; confirm MinProtocol by hand"
        )
    except OSError as exc:
        return _Reading(Status.ERROR, f"OpenSSL file not read: {exc}")
    cipher_strings = [value for key, value in settings if key == "CipherString"]
    min_protocols = [value for key, value in settings if key == "MinProtocol"]
    evidence = f"{path}: " + (
        ", ".join(f"{key} = {value}" for key, value in settings) or "no policy lines"
    )
    problems: list[str] = []
    if len(cipher_strings) != 1:
        problems.append(f"{len(cipher_strings)} CipherString lines, not 1")
    if not min_protocols:
        problems.append("no MinProtocol line")
    elif min_protocols[-1] not in _TLS12_OR_HIGHER:  # OpenSSL takes the last one
        problems.append(f"MinProtocol = {min_protocols[-1]}, not TLSv1.2 or higher")
    if problems:
        return _Reading(Status.FAIL, f"{path}: " + "; ".join(problems), evidence=evidence)
    return _Reading(
        Status.PASS,
        f"{path}: one CipherString line, MinProtocol = {min_protocols[-1]}",
        evidence=evidence,
    )


def _combine(readings: Iterable[_Reading]) -> CheckResult:
    taken = list(readings)
    status = next(s for s in _PRECEDENCE if any(r.status is s for r in taken))
    detail = "; ".join(r.text for r in taken)
    if status is not Status.PASS:
        detail += f" -- {_SEE_DOC}"
    evidence = "; ".join(r.evidence for r in taken if r.evidence)
    return CheckResult(RID, TITLE, status, detail, evidence=evidence)


def read_host_cipher_policy(platform: str = sys.platform) -> CheckResult:
    """Run section 5.4's checks for this platform. Never raises; never refuses a start."""
    if platform == "win32":
        return _combine(
            [
                _suite_reading(
                    _windows_enabled_suites, lambda name: bool(_SCHANNEL_AEAD.search(name))
                ),
                _windows_protocol_reading(),
            ]
        )
    if platform.startswith("linux"):
        # Section 5.4's check is `grep -v AEAD` over each `openssl ciphers -v` line.
        return _combine(
            [_suite_reading(_openssl_suites, lambda line: "AEAD" in line), _linux_policy_reading()]
        )
    return CheckResult(
        RID, TITLE, Status.SKIP, f"section 5.4 covers Windows and Linux hosts, not {platform}"
    )
