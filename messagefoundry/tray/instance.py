# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Single-instance guard via a per-session named mutex (ADR 0113 §9).

``CreateMutexW`` in the ``Local\\`` (per-session) namespace: a second launch sees
``ERROR_ALREADY_EXISTS`` and bows out. Per-session (not ``Global\\``) so fast-user-switching
sessions each get their own tray, and to avoid the cross-session ``CreateMutex`` access-denied trap.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

_MUTEX_NAME = "Local\\MessageFoundryTray"
_ERROR_ALREADY_EXISTS = 183


class SingleInstance:
    """Holds the mutex for the process lifetime; ``already_running`` is set by :meth:`acquire`."""

    def __init__(self, name: str = _MUTEX_NAME) -> None:
        self._name = name
        self._handle: int | None = None
        self.already_running = False

    def acquire(self) -> bool:
        """Try to become the sole instance. Returns True if we are first (or off Windows)."""
        if sys.platform != "win32":
            return True
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
        self._handle = kernel32.CreateMutexW(None, False, self._name)
        self.already_running = ctypes.get_last_error() == _ERROR_ALREADY_EXISTS
        return not self.already_running

    def release(self) -> None:
        if self._handle and sys.platform == "win32":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle(self._handle)
            self._handle = None
