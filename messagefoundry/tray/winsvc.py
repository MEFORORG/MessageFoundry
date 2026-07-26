"""Unelevated Windows SCM status read for the engine service (ADR 0113 §3).

Direct ctypes ``QueryServiceStatusEx`` — the only status source that yields ``dwCheckPoint`` /
``dwWaitHint`` (true stuck-pending detection) and works locally, unelevated, even when the engine
is down. An interactively-logged-on standard user holds ``SERVICE_QUERY_STATUS`` via the
Interactive SID with no setup; the tray targets an interactive desktop.

Everything ctypes is guarded behind ``sys.platform == "win32"``; off Windows (or on any query
failure) the reader returns :data:`~messagefoundry.tray.state.ScmState.UNAVAILABLE`. The state-code mapping
:func:`_map_current_state` is pure and unit-tested. This module never *controls* the service —
that is the elevated ``control`` path (ADR 0113 §4).
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass

from messagefoundry.tray.state import ScmState

# Win32 service current-state codes (winsvc.h SERVICE_*).
_SERVICE_STOPPED = 0x00000001
_SERVICE_START_PENDING = 0x00000002
_SERVICE_STOP_PENDING = 0x00000003
_SERVICE_RUNNING = 0x00000004
_SERVICE_CONTINUE_PENDING = 0x00000005
_SERVICE_PAUSE_PENDING = 0x00000006
_SERVICE_PAUSED = 0x00000007

# Access rights + info level.
_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_SC_STATUS_PROCESS_INFO = 0

_ERROR_SERVICE_DOES_NOT_EXIST = 1060

_STATE_MAP = {
    _SERVICE_STOPPED: ScmState.STOPPED,
    _SERVICE_START_PENDING: ScmState.START_PENDING,
    _SERVICE_STOP_PENDING: ScmState.STOP_PENDING,
    _SERVICE_RUNNING: ScmState.RUNNING,
    _SERVICE_CONTINUE_PENDING: ScmState.START_PENDING,  # resuming → treat like starting
    _SERVICE_PAUSE_PENDING: ScmState.STOP_PENDING,  # pausing → treat like stopping
    _SERVICE_PAUSED: ScmState.STOPPED,  # paused → not serving
}


def _map_current_state(dw_current_state: int) -> ScmState:
    """Map a Win32 ``dwCurrentState`` code to a :class:`~messagefoundry.tray.state.ScmState`. Pure."""
    return _STATE_MAP.get(dw_current_state, ScmState.UNAVAILABLE)


@dataclass(frozen=True)
class ScmReading:
    """A single SCM status read: the mapped state plus the pending-progress fields."""

    state: ScmState
    checkpoint: int = 0
    wait_hint_s: float | None = None


_UNAVAILABLE = ScmReading(state=ScmState.UNAVAILABLE)


class _ServiceStatusProcess(ctypes.Structure):
    """``SERVICE_STATUS_PROCESS`` (winsvc.h) — the ``SC_STATUS_PROCESS_INFO`` payload."""

    _fields_ = (
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    )


def query_scm_state(service_name: str) -> ScmReading:
    """Read the engine service's SCM status, unelevated. Never raises.

    Returns :data:`ScmState.NOT_INSTALLED` if the service does not exist, ``UNAVAILABLE`` off
    Windows or on any SCM failure, else the mapped running/pending/stopped state with its
    checkpoint + wait-hint.
    """
    if sys.platform != "win32":
        return _UNAVAILABLE

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.restype = wintypes.SC_HANDLE
    advapi32.OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    advapi32.OpenServiceW.restype = wintypes.SC_HANDLE
    advapi32.OpenServiceW.argtypes = (wintypes.SC_HANDLE, wintypes.LPCWSTR, wintypes.DWORD)
    advapi32.CloseServiceHandle.argtypes = (wintypes.SC_HANDLE,)
    advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
    advapi32.QueryServiceStatusEx.argtypes = (
        wintypes.SC_HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.LPDWORD,
    )

    scm = advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not scm:
        return _UNAVAILABLE
    try:
        svc = advapi32.OpenServiceW(scm, service_name, _SERVICE_QUERY_STATUS)
        if not svc:
            err = ctypes.get_last_error()
            if err == _ERROR_SERVICE_DOES_NOT_EXIST:
                return ScmReading(state=ScmState.NOT_INSTALLED)
            return _UNAVAILABLE
        try:
            status = _ServiceStatusProcess()
            needed = wintypes.DWORD()
            ok = advapi32.QueryServiceStatusEx(
                svc,
                _SC_STATUS_PROCESS_INFO,
                ctypes.byref(status),
                ctypes.sizeof(status),
                ctypes.byref(needed),
            )
            if not ok:
                return _UNAVAILABLE
            return ScmReading(
                state=_map_current_state(status.dwCurrentState),
                checkpoint=int(status.dwCheckPoint),
                wait_hint_s=int(status.dwWaitHint) / 1000.0,
            )
        finally:
            advapi32.CloseServiceHandle(svc)
    finally:
        advapi32.CloseServiceHandle(scm)
