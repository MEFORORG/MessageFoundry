# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Start a child process under a restricted copy of this process's own token (Windows only).

A stand-in for the token the Service Control Manager builds for a service whose SID type is
``restricted``: a write-restricted token whose restricting list holds the service SID, the logon
SID, Everyone and WRITE RESTRICTED, with every privilege but one stripped. Any process may make such
a copy of its own token and start a child under it, so this needs no elevation and installs
nothing.

IT IS A STAND-IN AND NOT THE REAL THING. The user here is the test's own account, the session is
interactive and the restricting list is built by this file. What it can show is how code behaves
under a write-restricted, privilege-stripped token. What the Service Control Manager really builds
is read by the ``windows-service-smoke`` leg, on a real service.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from ctypes import wintypes
from typing import Any

#: CreateRestrictedToken flags (winnt.h).
DISABLE_MAX_PRIVILEGE = 0x1
WRITE_RESTRICTED = 0x8

EVERYONE = "S-1-1-0"
WRITE_RESTRICTED_SID = "S-1-5-33"
USERS = "S-1-5-32-545"

_TOKEN_ALL_ACCESS = 0xF01FF
_CREATE_NO_WINDOW = 0x08000000
_INFINITE = 0xFFFFFFFF


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class RestrictedChild:
    """A running child. ``wait`` returns its exit code; ``kill`` ends it. Both close the handles."""

    def __init__(self, kernel32: Any, process: Any, pid: int) -> None:
        self._kernel32 = kernel32
        self._process = process
        self.pid = pid

    def wait(self, timeout_s: float = 120.0) -> int:
        try:
            self._kernel32.WaitForSingleObject(self._process, int(timeout_s * 1000))
            code = wintypes.DWORD()
            self._kernel32.GetExitCodeProcess(self._process, ctypes.byref(code))
            return int(code.value)
        finally:
            self.kill()

    def kill(self) -> None:
        if self._process:
            self._kernel32.TerminateProcess(self._process, 1)
            self._kernel32.CloseHandle(self._process)
            self._process = None


def spawn_restricted(
    argv: list[str],
    *,
    restricting_sids: list[str],
    flags: int = WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE,
    cwd: str | None = None,
) -> RestrictedChild:
    """Start ``argv`` under a restricted copy of this process's token.

    ``restricting_sids`` is the restricting list, as SID strings. ``flags`` defaults to the pair the
    hardened service gets: write-restricted, and every privilege but SeChangeNotifyPrivilege removed.
    """
    if sys.platform != "win32":  # also what narrows the ctypes names below for mypy
        raise RuntimeError("a restricted token is a Windows object; this host is not Windows")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.ConvertStringSidToSidW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
    advapi32.CreateRestrictedToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.CreateProcessAsUserW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    )

    def fail(what: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{what} failed (win32 error {code})")

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_ALL_ACCESS, ctypes.byref(token)
    ):
        raise fail("OpenProcessToken")
    sid_pointers: list[ctypes.c_void_p] = []
    restricted = wintypes.HANDLE()
    try:
        for text in restricting_sids:
            sid = ctypes.c_void_p()
            if not advapi32.ConvertStringSidToSidW(text, ctypes.byref(sid)):
                raise fail(f"ConvertStringSidToSidW({text})")
            sid_pointers.append(sid)
        entries = (_SID_AND_ATTRIBUTES * len(sid_pointers))(
            *[_SID_AND_ATTRIBUTES(p, 0) for p in sid_pointers]
        )
        if not advapi32.CreateRestrictedToken(
            token,
            flags,
            0,
            None,
            0,
            None,
            len(sid_pointers),
            entries if sid_pointers else None,
            ctypes.byref(restricted),
        ):
            raise fail("CreateRestrictedToken")
        startup = _STARTUPINFOW()
        startup.cb = ctypes.sizeof(_STARTUPINFOW)
        info = _PROCESS_INFORMATION()
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        if not advapi32.CreateProcessAsUserW(
            restricted,
            None,
            command,
            None,
            None,
            False,
            _CREATE_NO_WINDOW,
            None,
            cwd,
            ctypes.byref(startup),
            ctypes.byref(info),
        ):
            raise fail("CreateProcessAsUserW")
        kernel32.CloseHandle(info.hThread)
        return RestrictedChild(kernel32, info.hProcess, int(info.dwProcessId))
    finally:
        for pointer in sid_pointers:
            kernel32.LocalFree(pointer)
        if restricted:
            kernel32.CloseHandle(restricted)
        kernel32.CloseHandle(token)
