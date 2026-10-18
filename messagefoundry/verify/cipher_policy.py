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

Windows reads three things. The enabled SChannel suites come from ``Get-TlsCipherSuite``, which has
no registry or API equivalent in the standard library, so it runs through Windows PowerShell with a
fixed argument list and no host data in it. The suite order Group Policy sets, where it sets one,
and the TLS 1.0 and 1.1 client switches come from the registry through stdlib ``winreg``, which
needs no subprocess. Linux runs the ``openssl`` command
rather than Python's ``ssl`` module: section 5.4 measured that the CLI offers what the driver
offers, and Python sets its own default cipher string over the host's ``CipherString``. It reads
the policy lines from the section OpenSSL applies as the system default, found the way OpenSSL
finds it (:func:`_system_default_section`).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.childenv import system_tool_environment, worker_environment
from messagefoundry.redaction import codec_safe_str
from messagefoundry.service_status import _NO_WINDOW, _system_exe
from messagefoundry.verify.model import CheckResult, Status

RID = "host.ciphers"
TITLE = "Host cipher policy (ODBC hops)"

#: Windows PowerShell can take several seconds to start cold, so the budget is generous.
_PROBE_TIMEOUT_S = 30.0

#: Registry value types, as ``winreg`` numbers them; named here so no import of ``winreg`` is
#: needed off Windows.
_REG_SZ, _REG_EXPAND_SZ, _REG_DWORD, _REG_MULTI_SZ = 1, 2, 4, 7
_SCHANNEL_PROTOCOLS = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
#: Where Group Policy's "SSL Cipher Suite Order" setting writes its list.
_POLICY_ORDER_KEY = r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
_LEGACY_VERSIONS: tuple[str, ...] = ("TLS 1.0", "TLS 1.1")
#: Section 5.4's check 1 pattern for an AEAD suite name in SChannel's naming.
_SCHANNEL_AEAD = re.compile("GCM|CCM|CHACHA20_POLY1305")

#: Exit status of the Windows probe on a host without the system TLS module or its
#: ``Get-TlsCipherSuite`` cmdlet. Without the guard, PowerShell exits 1 there, which it also does
#: for a cmdlet that ran and failed.
_NO_CMDLET_EXIT = 64
#: Exit status of the Windows probe when the module it imported, or the command it is about to
#: run, is not the TLS module under ``$PSHOME``. Any non-zero exit but the one above is an ERROR.
_WRONG_MODULE_EXIT = 65
#: The warning and verbose streams are silenced first: Windows PowerShell 5.1 writes their lines to
#: a redirected stdout, where they would fail the suite-name check and make the reading an ERROR.
#:
#: NO COMMAND IN THIS TEXT IS LOOKED UP BY A BARE NAME. The probe's environment carries ``PATH``
#: and no ``PSModulePath``, so a cmdlet whose module is not yet loaded loses to a ``Join-Path.cmd``
#: or ``Test-Path.cmd`` on ``PATH``: measured, the Lander's hold on PR 2406, where such files
#: pointed the import at a planted module and the probe read PASS on a fake suite. So the path is
#: built and tested with .NET calls, which no command shadows; the one cmdlet left, ``Import-Module``,
#: is named by its module, ``Microsoft.PowerShell.Core``, which is loaded in every session before
#: any lookup; and ``Get-TlsCipherSuite`` is run as the imported module's exported command object.
#: Before it runs, the module and the command must both come from the TLS folder under
#: ``$PSHOME``, or the probe exits with the wrong-module status, an ERROR. ``$PSHOME`` is the
#: folder of the pinned ``powershell.exe``; this does not guard against a change to that system
#: folder, which takes an administrator. Only a missing module folder or a module without the
#: cmdlet exits with the "not on this host" status; a module that is there and fails to import
#: stops the command, which exits 1, an ERROR. Output is UTF-8, so a localized error line reaches
#: the ERROR detail readable. ``tests/test_verify_cipher_policy.py`` parses this text with
#: PowerShell's own parser and refuses a bare command name.
_SUITES_COMMAND = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "$WarningPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; "
    "$p = [IO.Path]::Combine($PSHOME, 'Modules', 'TLS'); "
    f"if (-not [IO.Directory]::Exists($p)) {{ exit {_NO_CMDLET_EXIT} }}; "
    "$m = @(Microsoft.PowerShell.Core\\Import-Module -Name $p -PassThru -ErrorAction Stop)[0]; "
    f"if (-not $m.ExportedCommands.ContainsKey('Get-TlsCipherSuite')) {{ exit {_NO_CMDLET_EXIT} }}; "
    "$c = $m.ExportedCommands['Get-TlsCipherSuite']; "
    "if ($m.ModuleBase -ne $p -or $c.Module.ModuleBase -ne $p) { "
    "[Console]::Error.WriteLine('Get-TlsCipherSuite did not come from the TLS module under "
    f"$PSHOME'); exit {_WRONG_MODULE_EXIT} }}; "
    "(& $c).Name"
)
#: The shape of an SChannel suite name. ``SSL_`` is there so an older host's SSL 2 suite is
#: counted, and fails. Any other line is not a reading this check understands, so it is an ERROR
#: rather than being dropped: a dropped line could be a suite.
_SCHANNEL_SUITE_NAME = re.compile(r"(?:TLS|SSL)_[A-Za-z0-9_]+")

#: The shape of an ``openssl ciphers -s -v`` line: name, version, then the Kx, Au, Enc and Mac
#: fields. Any other line is an ERROR, as on Windows.
_OPENSSL_SUITE_LINE = re.compile(r"\S+\s+\S+\s+Kx=\S+\s+Au=\S+\s+Enc=\S+\s+Mac=\S+")

_OPENSSL_CNF = Path("/etc/ssl/openssl.cnf")
#: The variables OpenSSL reads to find its configuration. They cross to the probe on top of what
#: ``worker_environment`` passes to any child, which is the platform's start-up names and the
#: Python interpreter's own variables; ``openssl`` is not Python, so it reads none of the latter.
_OPENSSL_ENV = ("OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES", "OPENSSL_ENGINES")
_POLICY_KEYS = {key.lower(): key for key in ("CipherString", "Ciphersuites", "MinProtocol")}
#: The policy lines the verdict rests on. ``Ciphersuites`` is read for the evidence only.
_JUDGED_KEYS = frozenset({"CipherString", "MinProtocol"})
_SECTION_HEADER = re.compile(r"^\s*\[\s*([^\]]*?)\s*\]")
_ASSIGNMENT = re.compile(r"^\s*([^\s=#]+)\s*=(.*)$")
#: ``.include path``, ``.include = path`` and the ``.pragma`` forms.
_DIRECTIVE = re.compile(r"^\s*(\.include|\.pragma)(?![\w.])")
#: The names OpenSSL follows from the default section to the system-default policy section.
_SYSTEM_DEFAULT_CHAIN = ("openssl_conf", "ssl_conf", "system_default")
#: The one link that names a configuration MODULE rather than a fixed name. OpenSSL reads a module
#: line's name up to its last ``.``, so ``ssl_conf.1`` names this module too, and then matches that
#: stem as a prefix of each module it knows, so a stem such as ``ssl`` can name it as well.
_SSL_MODULE = "ssl_conf"
_TLS12_OR_HIGHER = frozenset({"TLSv1.2", "TLSv1.3"})

_SEE_DOC = "see DEPLOY-SERVER-DB.md section 5.4"


class ProbeUnavailable(Exception):
    """The reading cannot be taken here, because the instrument is not on this host or the
    configuration uses something this check does not follow, so a person runs section 5.4 by hand."""


class ProbeFailed(Exception):
    """The instrument ran and gave no usable reading."""


@dataclass(frozen=True)
class _Reading:
    status: Status  # PASS, FAIL, ERROR or MANUAL
    text: str
    evidence: str = ""


#: Worst first: a confirmed finding outranks a reading that broke, which outranks one not taken.
_PRECEDENCE: tuple[Status, ...] = (Status.FAIL, Status.ERROR, Status.MANUAL, Status.PASS)


@contextmanager
def _probe_errors(program: str) -> Iterator[None]:
    """Turn a start that could not happen into the two probe exceptions."""
    try:
        yield
    except FileNotFoundError as exc:
        raise ProbeUnavailable(f"{program} not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProbeFailed(f"{program} did not finish in {_PROBE_TIMEOUT_S:.0f}s") from exc
    except OSError as exc:
        raise ProbeFailed(f"{program} could not run: {codec_safe_str(exc)}") from exc


def _stdout_lines(program: str, proc: subprocess.CompletedProcess[str]) -> list[str]:
    """The non-blank stdout lines of a finished probe; a non-zero exit raises :class:`ProbeFailed`."""
    if proc.returncode != 0:
        first = next((ln.strip() for ln in proc.stderr.splitlines() if ln.strip()), "")
        raise ProbeFailed(
            f"{program} exited {proc.returncode}" + (f": {first[:200]}" if first else "")
        )
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _every_entry_shaped(
    source: str, entries: list[str], shape: re.Pattern[str], what: str
) -> list[str]:
    """``entries``, when each has ``shape``; otherwise :class:`ProbeFailed` naming the first that
    does not. An entry this check does not understand is neither counted nor dropped, because a
    dropped entry could be a suite."""
    for entry in entries:
        if not shape.fullmatch(entry):
            raise ProbeFailed(f"{source}: {entry[:80]!r} is not {what}")
    return entries


# Each probe makes its own subprocess.run call rather than sharing one helper that takes an
# environment: tests/test_child_process_environment.py trusts env= only as a builder call at the
# start itself, and the two probes need different builders.


def _windows_enabled_suites() -> list[str]:
    """The enabled SChannel suite names, as section 5.4's check 1 reads them.

    ``(Get-TlsCipherSuite).Name`` and not a pipe into ``Where-Object Name``: section 5.4 measured
    that pipe passing the whole list through unfiltered. The filtering happens here, in Python.
    PowerShell is a fixed system tool run by its pinned path, so it takes the start-up names only
    (vault BACKLOG #2716); it finds the TLS module without the operator's ``PSModulePath``. A host
    without the cmdlet is :class:`ProbeUnavailable`, as a host without PowerShell is. A line not
    shaped like a suite name, such as a stream line the command did not silence, is
    :class:`ProbeFailed`: it is neither counted as a suite nor dropped."""
    with _probe_errors("powershell.exe"):
        proc = subprocess.run(  # nosec B603 - pinned tool, argv list (no shell), fixed arguments
            [
                _system_exe("WindowsPowerShell", "v1.0", "powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _SUITES_COMMAND,
            ],
            env=system_tool_environment(),  # the platform's start-up names only (#2716)
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_PROBE_TIMEOUT_S,
            check=False,
            creationflags=_NO_WINDOW,
        )
    if proc.returncode == _NO_CMDLET_EXIT:
        raise ProbeUnavailable("Get-TlsCipherSuite not found in the system TLS module")
    lines = _stdout_lines("powershell.exe", proc)
    return _every_entry_shaped("powershell.exe", lines, _SCHANNEL_SUITE_NAME, "a suite name")


def _hklm_value(subkey: str, name: str) -> tuple[object, int] | None:
    """``(value, registry type)`` of an HKLM value, or ``None`` when the key or value is unset."""
    if sys.platform != "win32":
        raise ProbeUnavailable("the Windows registry is not available on this platform")
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
            value, kind = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProbeFailed(f"{subkey}\\{name} could not be read: {codec_safe_str(exc)}") from exc
    return value, kind


def _schannel_client_enabled(version: str) -> int | None:
    """The DWORD ``Enabled`` under ``<version>\\Client``, or ``None`` when the key or value is unset."""
    found = _hklm_value(rf"{_SCHANNEL_PROTOCOLS}\{version}\Client", "Enabled")
    if found is None:
        return None
    value, kind = found
    if kind != _REG_DWORD or not isinstance(value, int):
        raise ProbeFailed(f"{version} client Enabled holds registry type {kind}, not a DWORD")
    return value


def _schannel_policy_order() -> list[str] | None:
    """The suite list Group Policy's "SSL Cipher Suite Order" sets, or ``None`` when it sets none.

    Split on commas in any of the three string forms, and every entry must be a suite name, so an
    entry that joins a CBC and a GCM suite some other way is an ERROR, never one AEAD suite. An
    expandable string is read as it is, unexpanded: a suite name holds no ``%``, so a value that
    would expand fails the name check rather than being judged on text SChannel may not see."""
    found = _hklm_value(_POLICY_ORDER_KEY, "Functions")
    if found is None:
        return None
    value, kind = found
    if kind in (_REG_SZ, _REG_EXPAND_SZ) and isinstance(value, str):
        items = [value]
    elif kind == _REG_MULTI_SZ and isinstance(value, list):
        items = [str(item) for item in value]
    else:
        raise ProbeFailed(f"the policy suite order holds registry type {kind}, not strings")
    names = [name.strip() for item in items for name in item.split(",") if name.strip()]
    return _every_entry_shaped(
        "the policy suite order", names, _SCHANNEL_SUITE_NAME, "a suite name"
    )


def _openssl_suites() -> list[str]:
    """``openssl ciphers -s -v``: one line per suite this host's OpenSSL configuration allows.

    Found on ``PATH`` by bare name, as section 5.4's own command is. It gets what
    ``worker_environment`` gives any child, the start-up names and the interpreter's variables, and
    the variables OpenSSL reads to find its configuration: section 5.4 asks for the check to run
    with the engine's environment, and without ``OPENSSL_CONF`` it would read a different policy
    from the one the driver takes."""
    with _probe_errors("openssl"):
        proc = subprocess.run(  # nosec B603 B607 - argv list (no shell), fixed arguments
            ["openssl", "ciphers", "-s", "-v"],
            env=worker_environment(extra_names=_OPENSSL_ENV),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_PROBE_TIMEOUT_S,
            check=False,
            creationflags=_NO_WINDOW,
        )
    lines = _stdout_lines("openssl", proc)
    return _every_entry_shaped("openssl", lines, _OPENSSL_SUITE_LINE, "a suite line")


def _config_value(raw: str) -> str:
    """An OpenSSL configuration value as the library reads it.

    A quote, single or double, is removed, and a ``#`` or a space inside one is kept. A backslash
    keeps the next character as it is. A ``#`` outside quotes starts a comment. Unquoted space at
    the end is dropped. ``$name`` expansion is not done; :func:`_expanded_nowhere` refuses it."""
    out: list[str] = []
    kept = 0  # out[:kept] ends with a quoted or escaped character, which no trim may drop
    quote = ""
    chars = iter(raw.strip())
    for char in chars:
        if char == "\\":
            out.append(next(chars, ""))
            kept = len(out)
        elif quote:
            if char == quote:
                quote = ""
            else:
                out.append(char)
                kept = len(out)
        elif char in "\"'":
            quote = char
        elif char == "#":
            break
        else:
            out.append(char)
    return "".join(out[:kept]) + "".join(out[kept:]).rstrip()


def _not_followed(construct: str) -> ProbeUnavailable:
    return ProbeUnavailable(f"uses {construct}, which this check does not follow")


def _expanded_nowhere(value: str) -> str:
    """``value``, unless OpenSSL would expand a ``$`` variable in it."""
    if "$" in value:
        raise _not_followed("$ variable expansion in a value it reads")
    return value


def _config_sections(text: str) -> dict[str, list[tuple[str, str]]]:
    """Each section's ``name = value`` lines, in file order. Lines above the first header are in
    ``default``, which is where OpenSSL files them.

    An ``.include``, a ``.pragma``, a line continued with a backslash or a ``section::name``
    assignment raises :class:`ProbeUnavailable`, wherever it is in the file: each can add to, or
    change how OpenSSL reads, the section this check reads, so a reading taken without it could
    PASS on lines OpenSSL does not apply. These are the constructs known here, not all of them."""
    sections: dict[str, list[tuple[str, str]]] = {"default": []}
    current = sections["default"]
    # OpenSSL ends a line only at a newline; splitlines() would also break at a form feed and
    # other separators, showing this reader a line OpenSSL never sees.
    for line in text.split("\n"):
        if directive := _DIRECTIVE.match(line):
            raise _not_followed(directive[1])
        if line.rstrip().endswith("\\"):
            raise _not_followed("a line continued with a backslash")
        if header := _SECTION_HEADER.match(line):
            current = sections.setdefault(header[1], [])
        elif assignment := _ASSIGNMENT.match(line):
            if "::" in assignment[1]:
                raise _not_followed("a section::name assignment")
            current.append((assignment[1], _config_value(assignment[2])))
    return sections


def _system_default_section(sections: dict[str, list[tuple[str, str]]]) -> str | None:
    """The section OpenSSL applies as the system-default TLS policy, or ``None`` when none is set.

    ``openssl_conf`` in the default section names a section, that section's ``ssl_conf`` names
    another, and its ``system_default`` names the one applied: ``[system_default_sect]`` on the
    stock Ubuntu file section 5.4 measured. A name set twice takes its last value, as in OpenSSL.
    The module link is matched as :func:`_names_the_ssl_module` says."""
    name = "default"
    for key in _SYSTEM_DEFAULT_CHAIN:
        lines = sections.get(name, [])
        if key == _SSL_MODULE:
            values = [value for line_name, value in lines if _names_the_ssl_module(line_name)]
            found = values[-1] if values else None
        else:
            found = dict(lines).get(key)  # dict() keeps a repeated name's last value
        if found is None:
            return None
        name = _expanded_nowhere(found)
    return name


def _names_the_ssl_module(name: str) -> bool:
    """Whether a line of the ``openssl_conf`` section names the SSL module.

    ``ssl_conf`` and ``ssl_conf.<anything>`` do: OpenSSL drops the last ``.`` and what follows. A
    stem that is a shorter prefix of ``ssl_conf``, such as ``ssl``, may name it or an earlier
    module, depending on which modules that OpenSSL build registers first, so it raises
    :class:`ProbeUnavailable` rather than being guessed either way."""
    stem = name.rsplit(".", 1)[0]
    if stem == _SSL_MODULE:
        return True
    if _SSL_MODULE.startswith(stem):  # an empty stem matches the first module registered
        raise _not_followed(f"the module name {name!r}, which OpenSSL may read as {_SSL_MODULE}")
    return False


def _openssl_policy_lines() -> tuple[Path, str | None, list[tuple[str, str]]]:
    """The ``CipherString``, ``Ciphersuites`` and ``MinProtocol`` settings OpenSSL applies.

    Reads the file ``OPENSSL_CONF`` names when this environment sets it, so the file read is the one
    the ``openssl`` probe above loaded. Returns the file, the system-default section, and that
    section's policy lines; no section means the file sets no system-default policy. OpenSSL
    matches a file-form command name without case, so this does too. A file using what this
    check does not follow raises :class:`ProbeUnavailable` naming the file, and so does an
    ``OPENSSL_CONF`` that is set but empty, because which file ``openssl`` read is then not known.
    A leading byte-order mark is dropped, as OpenSSL drops it."""
    named = os.environ.get("OPENSSL_CONF")
    if named == "":
        raise ProbeUnavailable("OPENSSL_CONF is set but empty, so the file openssl read is unknown")
    path = Path(named) if named else _OPENSSL_CNF
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        sections = _config_sections(text)
        section = _system_default_section(sections)
        if section is None:
            return path, None, []
        settings: list[tuple[str, str]] = []
        for name, value in sections.get(section, []):
            if key := _POLICY_KEYS.get(name.lower()):
                settings.append((key, _expanded_nowhere(value) if key in _JUDGED_KEYS else value))
    except ProbeUnavailable as exc:
        raise ProbeUnavailable(f"{path} {exc}") from exc
    return path, section, settings


def _suite_reading(
    what: str, probe: Callable[[], list[str]], is_aead: Callable[[str], bool]
) -> _Reading:
    try:
        lines = probe()
    except ProbeUnavailable as exc:
        return _Reading(Status.MANUAL, f"{what} not read ({exc}); run the commands by hand")
    except ProbeFailed as exc:
        return _Reading(Status.ERROR, f"{what} not read: {exc}")
    if not lines:
        return _Reading(
            Status.ERROR,
            f"the {what} read empty, so its control is 0 and a count of non-AEAD suites over it "
            "proves nothing",
        )
    weak = [line.split()[0] for line in lines if not is_aead(line)]
    if weak:
        return _Reading(
            Status.FAIL,
            f"{len(weak)} of {len(lines)} {what} are not AEAD",
            evidence=f"not AEAD in the {what}: " + ", ".join(weak),
        )
    return _Reading(Status.PASS, f"all {len(lines)} {what} are AEAD")


def _is_schannel_aead(name: str) -> bool:
    return bool(_SCHANNEL_AEAD.search(name))


def _windows_policy_order_readings() -> list[_Reading]:
    """Group Policy's suite order, checked as well where it is set.

    Which list SChannel takes when the policy and the local table disagree was not measured, so a
    suite that is not AEAD in either is a FAIL. That keeps a trimmed local table from reading as a
    PASS beneath a policy that still lists CBC suites."""
    try:
        order = _schannel_policy_order()
    except ProbeUnavailable as exc:
        return [_Reading(Status.MANUAL, f"Group Policy suite order not read ({exc})")]
    except ProbeFailed as exc:
        return [_Reading(Status.ERROR, f"Group Policy suite order not read: {exc}")]
    if order is None:
        return []
    return [_suite_reading("Group Policy suite-order suites", lambda: order, _is_schannel_aead)]


def _windows_protocol_readings() -> list[_Reading]:
    """One reading per legacy version, so a broken read never hides a finding on the other."""
    readings: list[_Reading] = []
    for version in _LEGACY_VERSIONS:
        try:
            value = _schannel_client_enabled(version)
        except ProbeUnavailable as exc:
            readings.append(_Reading(Status.MANUAL, f"{version} client Enabled not read ({exc})"))
            continue
        except ProbeFailed as exc:
            readings.append(_Reading(Status.ERROR, f"{version} client Enabled not read: {exc}"))
            continue
        if value is None:
            readings.append(
                _Reading(
                    Status.FAIL, f"{version} client Enabled is not set (section 5.4 asks for 0)"
                )
            )
        elif value != 0:
            readings.append(
                _Reading(Status.FAIL, f"{version} client Enabled={value} (section 5.4 asks for 0)")
            )
        else:
            readings.append(_Reading(Status.PASS, f"{version} client Enabled=0"))
    return readings


def _linux_policy_reading() -> _Reading:
    try:
        path, section, settings = _openssl_policy_lines()
    except FileNotFoundError as exc:
        return _Reading(
            Status.MANUAL, f"no OpenSSL file at {exc.filename}; confirm MinProtocol by hand"
        )
    except ProbeUnavailable as exc:
        return _Reading(Status.MANUAL, f"{exc}; run the manual commands")
    except OSError as exc:
        return _Reading(Status.ERROR, f"OpenSSL file not read: {codec_safe_str(exc)}")
    if section is None:
        return _Reading(
            Status.FAIL,
            f"{path}: openssl_conf, ssl_conf and system_default lead to no system-default "
            "section, so the file sets no policy",
        )
    where = f"{path} [{section}]"
    cipher_strings = [value for key, value in settings if key == "CipherString"]
    min_protocols = [value for key, value in settings if key == "MinProtocol"]
    evidence = f"{where}: " + (
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
        return _Reading(Status.FAIL, f"{where}: " + "; ".join(problems), evidence=evidence)
    return _Reading(
        Status.PASS,
        f"{where}: one CipherString line, MinProtocol = {min_protocols[-1]}",
        evidence=evidence,
    )


def _combine(*taken: _Reading) -> CheckResult:
    status = next(s for s in _PRECEDENCE if any(r.status is s for r in taken))
    detail = "; ".join(r.text for r in taken)
    if status is not Status.PASS:
        detail += f" -- {_SEE_DOC}"
    evidence = "; ".join(r.evidence for r in taken if r.evidence)
    return CheckResult(RID, TITLE, status, detail, evidence=evidence)


def read_host_cipher_policy(platform: str | None = None) -> CheckResult:
    """Run section 5.4's checks for ``platform`` (default: this one, read at call time).

    Never raises; never refuses a start."""
    platform = platform or sys.platform
    if platform == "win32":
        return _combine(
            _suite_reading("enabled suites", _windows_enabled_suites, _is_schannel_aead),
            *_windows_policy_order_readings(),
            *_windows_protocol_readings(),
        )
    if platform.startswith("linux"):
        # Section 5.4's check is `grep -v AEAD` over each `openssl ciphers -v` line.
        return _combine(
            _suite_reading("enabled suites", _openssl_suites, lambda line: "AEAD" in line),
            _linux_policy_reading(),
        )
    return CheckResult(
        RID, TITLE, Status.SKIP, f"section 5.4 covers Windows and Linux hosts, not {platform}"
    )
