# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0152 Phase 0 — process-local Windows crash-dump suppression + the mlock residency probe.

A Windows Error Reporting dump of the engine is a full plaintext-PHI disclosure written to disk,
outside the store's encryption, ACLs and retention sweep. These cover the process-local half (the
machine-policy half lives in ``scripts/service/install-service.ps1 -SuppressCrashDumps``).

Neither control moves ASVS 11.7.1 — memory hygiene is not memory encryption — so a test here asserts
the module makes no such claim.
"""

from __future__ import annotations

import sys

import pytest

from messagefoundry.crashdump import (
    RESIDUAL_MACHINE_POLICY,
    CrashDumpSuppression,
    suppress_crash_dumps,
)
from messagefoundry.store.crypto import memory_locking_available


def test_suppression_never_raises_and_reports_platform_support() -> None:
    """The call is hardening, not a correctness requirement: it must always return a report."""
    report = suppress_crash_dumps()
    assert isinstance(report, CrashDumpSuppression)
    assert report.supported is (sys.platform == "win32")


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows no-op behaviour")
def test_no_op_off_windows() -> None:
    """A pure no-op off Windows: nothing attempted, nothing claimed, no residual to explain."""
    report = suppress_crash_dumps()
    assert report == CrashDumpSuppression(supported=False)
    assert report.error_mode_set is False
    assert report.wer_flags_set is False
    assert report.residual is None


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 SetErrorMode/WerSetFlags")
def test_windows_sets_error_mode_and_wer_flags() -> None:
    import ctypes

    report = suppress_crash_dumps()
    assert report.supported is True
    assert report.error_mode_set is True
    assert report.wer_flags_set is True

    # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX are now in force for this process.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    assert int(kernel32.GetErrorMode()) & 0x0003 == 0x0003


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 SetErrorMode")
def test_windows_error_mode_is_ored_not_replaced() -> None:
    """The mode is inherited from the parent (NSSM, a shell); replacing it could CLEAR a protection an
    operator deliberately set upstream, so the implementation ORs."""
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    before = int(kernel32.GetErrorMode())
    sentinel = 0x8000  # SEM_NOOPENFILEERRORBOX — nothing this module sets
    kernel32.SetErrorMode(ctypes.c_uint(before | sentinel))
    try:
        suppress_crash_dumps()
        assert int(kernel32.GetErrorMode()) & sentinel == sentinel
    finally:
        kernel32.SetErrorMode(ctypes.c_uint(before))


def test_residual_names_the_machine_policy_it_cannot_reach() -> None:
    """A fully-successful report must still say what it does NOT cover, or an operator reads it as
    'no dump of this process can ever be written' — which is false while HKLM LocalDumps exists."""
    report = suppress_crash_dumps()
    if not report.supported:
        pytest.skip("residual is a Windows concept")
    assert report.residual == RESIDUAL_MACHINE_POLICY
    assert "LocalDumps" in RESIDUAL_MACHINE_POLICY
    assert "AeDebug" in RESIDUAL_MACHINE_POLICY
    assert "-SuppressCrashDumps" in RESIDUAL_MACHINE_POLICY


def test_dump_suppression_claims_nothing_about_asvs_11_7_1() -> None:
    """Memory HYGIENE is not memory ENCRYPTION (OWASP deleted 4.0.3 V8.3.6 and kept 11.7.1). Nothing
    in this module may expose a field that could be cited as satisfying the requirement."""
    fields = set(CrashDumpSuppression.__dataclass_fields__)
    assert fields == {"supported", "error_mode_set", "wer_flags_set", "residual"}
    assert not any("memory_encryption" in name for name in fields)
    doc = suppress_crash_dumps.__doc__ or ""
    assert "compliant" not in doc.lower()


# --- the mlock/VirtualLock residency probe -----------------------------------------------------


def test_memory_locking_probe_returns_a_bool_and_never_raises() -> None:
    """``_lock_memory`` swallows failures BY DESIGN, which is right for the hot path and is also how a
    silently degraded deployment stays invisible. The probe is the one place that observes it."""
    assert isinstance(memory_locking_available(), bool)


def test_memory_locking_probe_is_honest_about_a_zero_length_buffer() -> None:
    """A zero-length lock is not a lock. ``_lock_memory`` returns False for it, so the probe must not
    report residency it did not obtain."""
    assert memory_locking_available(0) is False


@pytest.mark.skipif(sys.platform != "win32", reason="VirtualLock working-set quota is a Win32 rule")
def test_dek_sized_lock_holds_on_windows() -> None:
    """The DEK-sized lock is the one whose failure would be unconditional. On Windows ``VirtualLock``
    is bounded by the process MINIMUM WORKING-SET quota rather than by a privilege, so a 32-byte pin
    succeeds under any account — including the least-privilege service account the installer defaults
    to. (A large plaintext buffer is a different question: that quota is a few hundred KB by default
    and is shared across every concurrent lock, so big bodies under load will silently fail to pin.
    Documented in ``memory_locking_available``; hygiene only, no bearing on 11.7.1.)"""
    assert memory_locking_available(32) is True
