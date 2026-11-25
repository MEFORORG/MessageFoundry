# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Win32 SID calls that more than one Windows reader of owners and access lists uses
(BACKLOG #6281).

:func:`~messagefoundry.auth.anchor_path.windows_host_readers` and ``_win32_config_source_probes``
in ``config/wiring.py`` take them from here. They open an object differently and report a failed
read differently, so each keeps its own reader. Each also keeps its own read of the local
Administrators group, because the two answer a partial read differently. What they share is here: the prototypes of the SID, entry, account and token
calls, the text of a binary SID, and the SID of the account this process runs as. Other readers
still declare their own, at least ``restricted_file.py``'s.

ctypes stays behind the platform guard in each function, so mypy and lint pass on the Linux CI leg.
"""

from __future__ import annotations

import sys
from typing import Any


def sid_libraries() -> tuple[Any, Any]:
    """A new ``advapi32`` and ``kernel32``, with the shared prototypes declared.

    Each call loads its own pair, so the prototypes a caller declares beside these do not reach
    another caller. Declaring them keeps a 64-bit pointer from being cut to a default ``c_int``."""
    if sys.platform != "win32":
        raise OSError("the Windows SID readers run only on Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pvoid_p = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, pvoid_p]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, pvoid_p]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,  # lpSystemName (NULL = this machine)
        ctypes.c_void_p,  # Sid
        wintypes.LPWSTR,  # Name
        ctypes.POINTER(wintypes.DWORD),  # cchName
        wintypes.LPWSTR,  # ReferencedDomainName
        ctypes.POINTER(wintypes.DWORD),  # cchReferencedDomainName
        ctypes.POINTER(ctypes.c_int),  # peUse (SID_NAME_USE)
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,  # TOKEN_INFORMATION_CLASS
        ctypes.c_void_p,  # TokenInformation (buffer)
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return advapi32, kernel32


def sid_text(advapi32: Any, kernel32: Any, sid_ptr: int | None) -> str | None:
    """The binary SID at ``sid_ptr`` as text, such as ``S-1-5-18``, or ``None`` for a null pointer
    or a SID ``ConvertSidToStringSidW`` could not render. ``advapi32`` and ``kernel32`` are a pair
    from :func:`sid_libraries`."""
    if sys.platform != "win32":
        raise OSError("the Windows SID readers run only on Windows")
    import ctypes
    from ctypes import wintypes

    if not sid_ptr:
        return None
    out = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
        return None
    try:
        return out.value
    finally:
        # ConvertSidToStringSidW allocates the string with LocalAlloc; free its address.
        if out:
            kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))


def process_user_sid(advapi32: Any, kernel32: Any) -> str | None:
    """The SID of the account this process runs as, from its token's ``TokenUser``, or ``None``
    when the token could not be read. ``advapi32`` and ``kernel32`` are a pair from
    :func:`sid_libraries`."""
    if sys.platform != "win32":
        raise OSError("the Windows SID readers run only on Windows")
    import ctypes
    from ctypes import wintypes

    token = wintypes.HANDLE()
    token_query = 0x0008
    token_user = 1
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)
    ):
        return None
    try:
        size = wintypes.DWORD(0)
        # The sizing call fails by design and fills ``size``.
        advapi32.GetTokenInformation(token, token_user, None, 0, ctypes.byref(size))
        if size.value == 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, token_user, buf, size.value, ctypes.byref(size)):
            return None
        # TOKEN_USER is SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }; the SID pointer is first.
        return sid_text(advapi32, kernel32, ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0])
    finally:
        kernel32.CloseHandle(token)
