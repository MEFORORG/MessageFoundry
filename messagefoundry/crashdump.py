# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Process-level Windows crash-dump suppression for the engine (ADR 0152, Phase 0).

**Why this exists.** A Windows Error Reporting (WER) crash dump of a running engine is a *full PHI
disclosure written to disk*: every HL7 message body in flight, the decrypted plaintext the store
cipher just produced, and the unwrapped DEK all live in CPython heap while the process runs, and a
minidump copies that heap into a file that is NOT the store, NOT encrypted, and NOT covered by the
store's ACLs or its retention sweep. Nothing prevented one before this module.

**What this does NOT do.** It does not move ASVS 11.7.1 (full memory encryption in use) by one inch.
Dump suppression is memory *hygiene*, and OWASP settled the distinction when it deleted 4.0.3's
V8.3.6 (memory zeroing) as "NOT PRACTICAL" and kept 11.7.1 — see
``docs/adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md``.
This is worth doing on its own merits (it closes a real plaintext-PHI-to-disk path) and on no others.

**Scope, honestly stated.** Everything here is *process-local*: it changes only this process's error
mode and its WER fault-reporting flags, persists nothing, and needs no privilege. That is deliberate —
a serve invocation must not silently rewrite machine or user registry state. The consequence is that
it cannot cover every dump producer on Windows:

* ``HKLM\\...\\Windows Error Reporting\\LocalDumps`` is evaluated **independently** of everything a
  process can set — Microsoft documents local dump collection as configured and controlled separately
  from the rest of the WER infrastructure, and it fires even when WER reporting is disabled or the
  image is on the WER exclusion list. Only machine policy can turn it off for an image.
* A postmortem debugger registered under ``AeDebug`` is likewise outside process control.

Both of those are machine policy, so they are handled at install time —
``scripts/service/install-service.ps1 -SuppressCrashDumps`` — and the residual is named in
:attr:`CrashDumpSuppression.residual` so an operator reading the result is not misled into thinking
this call is the whole fix.

Stdlib only (``ctypes``), no engine state, no I/O. A **no-op on every non-Windows platform**: it
returns an unsupported report and touches nothing.
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass

__all__ = [
    "CrashDumpSuppression",
    "suppress_crash_dumps",
]

# --- Win32 constants (winbase.h / werapi.h) ----------------------------------------------------

#: ``SetErrorMode``: the system does not display the critical-error-handler message box, and does not
#: display the WER "program stopped working" dialog for an unhandled exception. Under a service there
#: is no interactive desktop to show either, but a service that is also run interactively for
#: diagnosis should behave the same way.
_SEM_FAILCRITICALERRORS = 0x0001
_SEM_NOGPFAULTERRORBOX = 0x0002

#: ``WerSetFlags``: do not collect additional heap data in a fault report. This is the PHI-relevant
#: flag — the heap is where every HL7 message body and every decrypted plaintext lives.
_WER_FAULT_REPORTING_FLAG_NOHEAP = 0x0001
#: ``WerSetFlags``: never show fault-reporting UI for this process.
_WER_FAULT_REPORTING_NO_UI = 0x0020
#: ``WerSetFlags``: do not take a process *snapshot* (a copy-on-write clone of the address space,
#: i.e. of all resident PHI) when this process crashes / hangs. Deliberately NOT paired with
#: ``WER_FAULT_REPORTING_FLAG_QUEUE`` (0x2): queueing would move reports to the on-disk WER
#: ReportQueue instead of suppressing them, which is the opposite of what this module is for.
_WER_FAULT_REPORTING_FLAG_DISABLE_SNAPSHOT_CRASH = 0x0040
_WER_FAULT_REPORTING_FLAG_DISABLE_SNAPSHOT_HANG = 0x0080

_WER_FLAGS = (
    _WER_FAULT_REPORTING_FLAG_NOHEAP
    | _WER_FAULT_REPORTING_NO_UI
    | _WER_FAULT_REPORTING_FLAG_DISABLE_SNAPSHOT_CRASH
    | _WER_FAULT_REPORTING_FLAG_DISABLE_SNAPSHOT_HANG
)

#: The residual this call cannot reach, stated in the terms an operator needs to act on it. Kept as a
#: constant so the serve-time log line, the tests, and the docs all quote the same sentence.
RESIDUAL_MACHINE_POLICY = (
    "process-local only: HKLM WER LocalDumps and an AeDebug postmortem debugger are machine policy "
    "and are evaluated independently of any flag a process can set — apply "
    "scripts/service/install-service.ps1 -SuppressCrashDumps to cover them"
)


@dataclass(frozen=True, slots=True)
class CrashDumpSuppression:
    """What :func:`suppress_crash_dumps` actually achieved — a *report*, not a guarantee.

    ``supported`` is False on every non-Windows platform (nothing was attempted and nothing needed to
    be). ``error_mode_set`` / ``wer_flags_set`` record whether each Win32 call succeeded; either may
    be False on an unusual build without the export, which is degraded but not fatal. ``residual``
    always names what process-local suppression cannot reach, so a caller cannot read a fully-True
    report as "no dump of this process can ever be written".
    """

    supported: bool
    error_mode_set: bool = False
    wer_flags_set: bool = False
    residual: str | None = None


def suppress_crash_dumps() -> CrashDumpSuppression:
    """Best-effort, process-local suppression of Windows crash-dump collection for THIS process.

    Two calls, both process-scoped and both persisting nothing:

    1. ``SetErrorMode`` — OR (never replace) ``SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX`` into
       the inherited mode. ORing matters: the mode is inherited from the parent (NSSM, a shell), and
       replacing it could *clear* a protection an operator deliberately set upstream.
    2. ``WerSetFlags`` — ``NOHEAP | NO_UI | DISABLE_SNAPSHOT_CRASH | DISABLE_SNAPSHOT_HANG``, so a
       fault report collects no heap data and no address-space snapshot.

    Never raises: a missing export or a failing call is recorded in the returned report and the
    process continues. Suppressing a dump is hardening, not a correctness requirement, and refusing
    to start an interface engine because a WER flag would not set would be a worse outcome than the
    dump it was meant to prevent.

    Returns ``CrashDumpSuppression(supported=False)`` unchanged on non-Windows platforms.
    """
    if sys.platform != "win32":
        return CrashDumpSuppression(supported=False)

    error_mode_set = False
    wer_flags_set = False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return CrashDumpSuppression(supported=True, residual=RESIDUAL_MACHINE_POLICY)

    get_error_mode = getattr(kernel32, "GetErrorMode", None)
    set_error_mode = getattr(kernel32, "SetErrorMode", None)
    if set_error_mode is not None:
        try:
            current = int(get_error_mode()) if get_error_mode is not None else 0
            set_error_mode(
                ctypes.c_uint(current | _SEM_FAILCRITICALERRORS | _SEM_NOGPFAULTERRORBOX)
            )
            error_mode_set = True
        except (OSError, ValueError, TypeError):  # pragma: no cover - defensive
            error_mode_set = False

    # WerSetFlags is documented in kernel32 but forwards through kernelbase on current Windows
    # builds, and has moved between them across releases — resolve it from either rather than
    # hard-coding one DLL and silently losing the flag on a build that relocated it.
    wer_set_flags = getattr(kernel32, "WerSetFlags", None)
    if wer_set_flags is None:
        try:
            wer_set_flags = getattr(ctypes.WinDLL("kernelbase"), "WerSetFlags", None)
        except OSError:  # pragma: no cover - kernelbase is always present on win32
            wer_set_flags = None
    if wer_set_flags is not None:
        try:
            wer_set_flags.argtypes = [ctypes.c_ulong]
            wer_set_flags.restype = ctypes.c_long
            # HRESULT: S_OK (0) is success; anything else leaves the flag unset.
            wer_flags_set = int(wer_set_flags(ctypes.c_ulong(_WER_FLAGS))) == 0
        except (OSError, ValueError, TypeError):  # pragma: no cover - defensive
            wer_flags_set = False

    return CrashDumpSuppression(
        supported=True,
        error_mode_set=error_mode_set,
        wer_flags_set=wer_flags_set,
        residual=RESIDUAL_MACHINE_POLICY,
    )
