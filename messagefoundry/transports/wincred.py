# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-endpoint alternate Windows / network-share credential for the File connector (ADR 0132, #111).

A File (UNC/SMB) endpoint may authenticate to a share under a Windows identity **distinct from the
engine service account**. This module establishes that alternate credential and runs the connector's
blocking filesystem I/O under it.

**win32 ctypes, no pywin32, no impersonation privilege.** Following the ctypes-not-pywin32 precedent
already in the tree — :mod:`messagefoundry.tray.winsvc` (``ctypes.WinDLL('advapi32', use_last_error=True)``
+ ``ctypes.wintypes``) and :mod:`messagefoundry.service` (``ctypes.windll.shell32`` at
``service.py:124``/``service.py:270``), both gated on [ADR 0113](../../docs/adr/0113-windows-tray-service-manager-stdlib-ctypes-tokenless.md)
— this calls ``advapi32.LogonUserW`` with **``LOGON32_LOGON_NEW_CREDENTIALS``** (logon type 9) +
``LOGON32_PROVIDER_WINNT50``, then ``ImpersonateLoggedOnUser`` / ``RevertToSelf``. That logon type
authenticates **outbound network access only** (the SMB hop) and needs **no** privilege — not
``SeTcbPrivilege`` (interactive/batch logon) and not ``SeImpersonatePrivilege`` (LOGON32_LOGON_NEW_CREDENTIALS
tokens are impersonatable by their creator without it). So a plain service account can use it.

**Why not ``WNetAddConnection2W``.** A ``WNET`` share mapping is **process-wide**: two File connections
that map the *same* host under *different* credentials collide. ``LogonUser`` + impersonation is
**per-thread**, so each connection gets an isolated identity with no cross-connection collision — at the
cost that the blocking I/O **must run on a thread we own and impersonate**, never on the shared asyncio
loop thread and never on the shared :func:`asyncio.to_thread` pool (impersonation would leak to unrelated
tasks). :class:`CredentialContext` therefore owns a **dedicated single-worker thread** and brackets every
call ``LogonUser -> Impersonate -> fn() -> RevertToSelf -> CloseHandle`` — the token is created and
destroyed **inside one call on that thread**, so nothing persists to leak across a reload/reconfigure.

**Win32-only.** Off Windows this raises :class:`CredentialUnsupportedError` at construction — a clear
error, never a silent no-op — so a config that asks for an alternate credential on a non-Windows host
fails loud. CI cannot exercise a real alt-credential UNC share, so the live path is a Windows-CI / manual
gate; the non-Windows error path is fully unit-tested.

**PHI / secret handling.** The password lives only in memory for the connector's lifetime and is **never
logged**; error messages carry the Win32 error *code* only (never the username, domain, or password).
The password itself must be supplied via ``env()`` (see :class:`~messagefoundry.config.models.WindowsCredential`).
"""

from __future__ import annotations

import asyncio
import ctypes
import functools
import logging
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

__all__ = [
    "CredentialContext",
    "CredentialError",
    "CredentialUnsupportedError",
    "CredentialLogonError",
    "is_supported",
    "ensure_supported",
]

_T = TypeVar("_T")

# advapi32.LogonUserW constants (winbase.h). LOGON32_LOGON_NEW_CREDENTIALS (9) authenticates outbound
# network hops only and requires NO privilege; WINNT50 is its mandated provider.
_LOGON32_LOGON_NEW_CREDENTIALS = 9
_LOGON32_PROVIDER_WINNT50 = 3

_UNSUPPORTED_MSG = (
    "alternate Windows/network-share credentials for a File endpoint require Windows (win32); "
    "this host is {platform!r}. Remove the credential_* settings (the engine then uses its own "
    "service-account identity), or run the engine on Windows to authenticate to the UNC/SMB share "
    "under a distinct identity."
)


class CredentialError(Exception):
    """Base class for alternate-Windows-credential failures."""


class CredentialUnsupportedError(CredentialError, ValueError):
    """The host is not Windows, so an alternate Windows credential cannot be established. A
    :class:`ValueError` so a connector's construction-time settings validation reports it as the
    configuration error it is (an alt credential was configured on a platform that can't honor it),
    rather than a silent no-op."""


class CredentialLogonError(CredentialError, OSError):
    """``LogonUser``/``ImpersonateLoggedOnUser`` failed at runtime (a bad credential, a locked-out
    account, a rejected logon). An :class:`OSError` so it rides the File connectors' existing
    ``except OSError`` paths (a destination maps it to :class:`DeliveryError`, a source's
    ``validate_startup`` to :class:`SourceStartupError`, and a poll scan logs-and-retries) — never a
    connection crash. The message carries the **Win32 error code only**, never any credential material."""


def is_supported() -> bool:
    """True iff this host can establish an alternate Windows credential (i.e. it is Windows)."""
    return sys.platform == "win32"


def ensure_supported() -> None:
    """Raise :class:`CredentialUnsupportedError` off Windows — the clear, loud POSIX error (never a
    silent no-op) a File connection with ``credential_*`` settings gets at construction on a non-Windows
    host."""
    if not is_supported():
        raise CredentialUnsupportedError(_UNSUPPORTED_MSG.format(platform=sys.platform))


class CredentialContext:
    """Runs blocking filesystem callables under an alternate Windows credential.

    Owns a **dedicated single-worker thread**; each :meth:`run` brackets its callable with a fresh
    ``LogonUser`` -> ``ImpersonateLoggedOnUser`` -> ``fn()`` -> ``RevertToSelf`` -> ``CloseHandle`` on
    that thread. Because the token is created and closed **inside the call**, there is nothing to leak
    across a reload; :meth:`close` only has to shut the worker thread down.

    Constructing off Windows raises :class:`CredentialUnsupportedError` (see :func:`ensure_supported`).
    """

    def __init__(self, *, username: str, password: str, domain: str | None = None) -> None:
        ensure_supported()  # loud, at construction — never a silent no-op off Windows
        self._username = username
        self._password = password
        self._domain = domain
        self._lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None
        self._closed = False

    async def run(self, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
        """Run ``fn(*args, **kwargs)`` on the dedicated impersonated thread and return its result.

        The blocking work runs **off the event loop** (like :func:`asyncio.to_thread`), but on a thread
        this context owns and impersonates — never the shared pool. Raises :class:`CredentialLogonError`
        (an :class:`OSError`) if the alt-credential logon/impersonation fails; any exception ``fn`` raises
        propagates unchanged (the credential is always reverted first)."""
        executor = self._ensure_executor()
        loop = asyncio.get_running_loop()
        call = functools.partial(self._impersonated_call, fn, args, kwargs)
        return await loop.run_in_executor(executor, call)

    def _ensure_executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._closed:
                raise CredentialError("alternate-credential context is closed")
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="mefor-filecred"
                )
            return self._executor

    def _impersonated_call(
        self, fn: Callable[..., _T], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> _T:
        """On the dedicated thread: log the alt credential on, impersonate, run ``fn``, then revert and
        close the token — all bracketed so the thread never lingers impersonated and the token never
        outlives the call."""
        token = _logon(self._username, self._domain, self._password)
        try:
            _impersonate(token)
            try:
                return fn(*args, **kwargs)
            finally:
                _revert()
        finally:
            _close_handle(token)

    async def close(self) -> None:
        """Release the context: shut the dedicated worker thread down (its impersonation, if any, dies
        with it). Idempotent. Run on stop/reload so no thread or identity leaks across a reconfigure."""
        with self._lock:
            executor, self._executor = self._executor, None
            self._closed = True
        if executor is None:
            return
        # Shut down OFF the event loop — join the worker without blocking the loop.
        await asyncio.get_running_loop().run_in_executor(None, executor.shutdown, True)


# --- ctypes primitives (win32-only; each guards sys.platform first so mypy narrows) --------------


def _logon(username: str, domain: str | None, password: str) -> wintypes.HANDLE:
    """``LogonUserW`` with ``LOGON32_LOGON_NEW_CREDENTIALS`` (no privilege required). Returns the logon
    token handle; raises :class:`CredentialLogonError` (Win32 code only) on failure."""
    if sys.platform != "win32":  # unreachable in practice (ensure_supported gates) — narrows mypy
        raise CredentialUnsupportedError(_UNSUPPORTED_MSG.format(platform=sys.platform))
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.LogonUserW.argtypes = (
        wintypes.LPCWSTR,  # lpszUsername
        wintypes.LPCWSTR,  # lpszDomain (NULL => local SAM / a UPN carried in username)
        wintypes.LPCWSTR,  # lpszPassword
        wintypes.DWORD,  # dwLogonType
        wintypes.DWORD,  # dwLogonProvider
        ctypes.POINTER(wintypes.HANDLE),  # phToken (out)
    )
    advapi32.LogonUserW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    ok = advapi32.LogonUserW(
        username,
        domain,
        password,
        _LOGON32_LOGON_NEW_CREDENTIALS,
        _LOGON32_PROVIDER_WINNT50,
        ctypes.byref(token),
    )
    if not ok:
        raise CredentialLogonError(
            f"alternate Windows credential logon failed (LogonUser win32 error "
            f"{ctypes.get_last_error()})"
        )
    return token


def _impersonate(token: wintypes.HANDLE) -> None:
    """``ImpersonateLoggedOnUser`` — apply ``token`` to the current thread. Raises
    :class:`CredentialLogonError` (Win32 code only) on failure."""
    if sys.platform != "win32":  # unreachable — narrows mypy
        raise CredentialUnsupportedError(_UNSUPPORTED_MSG.format(platform=sys.platform))
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ImpersonateLoggedOnUser.argtypes = (wintypes.HANDLE,)
    advapi32.ImpersonateLoggedOnUser.restype = wintypes.BOOL
    if not advapi32.ImpersonateLoggedOnUser(token):
        raise CredentialLogonError(
            f"alternate Windows credential impersonation failed (ImpersonateLoggedOnUser win32 error "
            f"{ctypes.get_last_error()})"
        )


def _revert() -> None:
    """``RevertToSelf`` — drop any impersonation on the current thread, restoring the process identity.
    Best-effort (it effectively never fails; the worker thread is torn down on close regardless), but a
    failure is logged at DEBUG so a stuck impersonation is not silently ignored."""
    if sys.platform != "win32":  # unreachable — narrows mypy
        return
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RevertToSelf.argtypes = ()
    advapi32.RevertToSelf.restype = wintypes.BOOL
    if not advapi32.RevertToSelf():
        logger.debug(
            "RevertToSelf failed on the file-credential thread (win32 error %s)",
            ctypes.get_last_error(),
        )


def _close_handle(token: wintypes.HANDLE) -> None:
    """``CloseHandle`` on a logon token. Best-effort (a leaked handle is process-local and bounded — at
    most one per in-flight call)."""
    if sys.platform != "win32":  # unreachable — narrows mypy
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(token)
