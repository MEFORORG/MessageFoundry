"""Tray SCM read path (ADR 0113 §3). The mapping is pure; the ctypes read is Windows-only."""

from __future__ import annotations

import sys

import pytest

from messagefoundry.tray.state import ScmState
from messagefoundry.tray.winsvc import (
    _SERVICE_PAUSED,
    _SERVICE_RUNNING,
    _SERVICE_START_PENDING,
    _SERVICE_STOP_PENDING,
    _SERVICE_STOPPED,
    _map_current_state,
    query_scm_state,
)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (_SERVICE_STOPPED, ScmState.STOPPED),
        (_SERVICE_START_PENDING, ScmState.START_PENDING),
        (_SERVICE_STOP_PENDING, ScmState.STOP_PENDING),
        (_SERVICE_RUNNING, ScmState.RUNNING),
        (_SERVICE_PAUSED, ScmState.STOPPED),
        (0xDEAD, ScmState.UNAVAILABLE),  # unknown code
    ],
)
def test_map_current_state(code: int, expected: ScmState) -> None:
    assert _map_current_state(code) is expected


def test_query_off_windows_is_unavailable() -> None:
    if sys.platform == "win32":
        pytest.skip("covered by the Windows-only read tests")
    assert query_scm_state("EventLog").state is ScmState.UNAVAILABLE


@pytest.mark.skipif(sys.platform != "win32", reason="ctypes SCM read is Windows-only")
def test_query_nonexistent_service_is_not_installed() -> None:
    # A random, definitely-absent service name → NOT_INSTALLED (OpenService → 1060), unelevated.
    reading = query_scm_state("MefTrayDefinitelyNotAService_zzq")
    assert reading.state is ScmState.NOT_INSTALLED


@pytest.mark.skipif(sys.platform != "win32", reason="ctypes SCM read is Windows-only")
def test_query_known_service_returns_a_real_state() -> None:
    # The Windows Event Log service is always present; the unelevated read must yield a concrete
    # state (not UNAVAILABLE / NOT_INSTALLED) with a sane checkpoint/wait-hint.
    reading = query_scm_state("EventLog")
    assert reading.state in {
        ScmState.RUNNING,
        ScmState.STOPPED,
        ScmState.START_PENDING,
        ScmState.STOP_PENDING,
    }
    assert reading.checkpoint >= 0
    assert reading.wait_hint_s is None or reading.wait_hint_s >= 0
