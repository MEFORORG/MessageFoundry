# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Files that hold key material: restricted in the call that creates them, and checked before use.

Two entry points, and both fail closed (vault BACKLOG #2601):

* :func:`write_restricted_file` creates a file that is restricted from its first moment and refuses
  to replace one that exists. Its access list is read back before a single byte is written. A file
  that could not be created that way is never left behind, and there is no fallback to writing the
  file first and tightening it afterwards.
* :func:`broad_read_problem` answers, before a key file is used, whether an account outside the
  intended set can read it.

``store._secure_file`` is the other mechanism, and it is for files that hold no key: it tightens a
file that already exists and only logs when it cannot. A file that holds a key must never have that
as its only protection.

**Windows.** The access list is attached in the ``CreateFileW`` call itself, as a protected list
(no inheritance from the directory) naming SYSTEM, Administrators, the creating account, and each
account granted read. That is the set ``scripts/service/install-service.ps1`` leaves on the data
directory. SYSTEM and Administrators already reach every file on the host, so naming them adds no
one. ``CREATE_NEW`` with ``FILE_FLAG_OPEN_REPARSE_POINT`` refuses a name that is already taken,
whether by a file or by a link.

**POSIX.** ``O_CREAT | O_EXCL`` with mode ``0o600``, which also refuses an existing name or link.

All ``ctypes`` work sits behind ``sys.platform`` guards, so the module imports on every platform and
type-checks on the Linux CI leg (mirrors :mod:`messagefoundry.secrets_dpapi`).
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from messagefoundry.auth.anchor_path import (
    ACCESS_ALLOWED_ACE_TYPE,
    ADMINISTRATORS_SID,
    SYSTEM_SID,
    describe_sid,
)

if TYPE_CHECKING:
    from messagefoundry.config.wiring import _WinPathSecurity

__all__ = ["RestrictedFileError", "broad_read_problem", "write_restricted_file"]


class RestrictedFileError(OSError):
    """A file could not be created restricted, or what was created did not read back as asked.

    An ``OSError`` so a caller that already treats a failed write as fatal treats this the same way.
    The message never carries the bytes that were to be written."""


# --- the access list a new file carries (Windows) -------------------------------------------------

#: FILE_ALL_ACCESS and FILE_GENERIC_READ, as the SDDL rights ``FA`` and ``FR`` store them in an ACE.
_FULL_ACCESS = 0x001F01FF
_READ_ACCESS = 0x00120089
_SDDL_RIGHT: Mapping[int, str] = {_FULL_ACCESS: "FA", _READ_ACCESS: "FR"}


def _expected_access(creator_sid: str, read_sids: Sequence[str]) -> dict[str, int]:
    """The whole access list of a new file, as SID to access mask, in the order it is written.

    Full control for SYSTEM, Administrators and the creating account; read for each account in
    ``read_sids``. An account already holding full control keeps it and gets no second entry."""
    access = {SYSTEM_SID: _FULL_ACCESS, ADMINISTRATORS_SID: _FULL_ACCESS}
    access.setdefault(creator_sid, _FULL_ACCESS)
    for sid in read_sids:
        access.setdefault(sid, _READ_ACCESS)
    return access


def _protected_sddl(access: Mapping[str, int]) -> str:
    """The access list as SDDL: protected (``P``), one explicit allow entry per account."""
    return "D:P" + "".join(f"(A;;{_SDDL_RIGHT[mask]};;;{sid})" for sid, mask in access.items())


def _created_mismatch(
    security: _WinPathSecurity, protected: bool | None, expected: Mapping[str, int]
) -> str | None:
    """Why a just-created file does NOT carry exactly ``expected``, or ``None`` when it does.

    ``protected`` is whether the list blocks inheritance, or ``None`` when that could not be read.
    Kept free of ctypes so the decision is testable on every platform."""
    if security.status != 0:
        return f"its access list could not be read back (Win32 error {security.status})"
    if not security.dacl_present or security.aces is None:
        return "its access list could not be read back"
    if protected is not True:
        return "its access list does not block inheritance from the directory"
    found = sorted(security.aces)
    wanted = sorted((ACCESS_ALLOWED_ACE_TYPE, mask, sid) for sid, mask in expected.items())
    if found != wanted:
        return "its access list is not the one that was asked for"
    return None


# --- the read check, before a key file is used ----------------------------------------------------

#: Rights that let their holder read the file, or give itself the right to: FILE_READ_DATA,
#: WRITE_DAC, WRITE_OWNER, GENERIC_ALL and GENERIC_READ.
_READ_REACH_MASK = 0x00000001 | 0x00040000 | 0x00080000 | 0x10000000 | 0x80000000


def _windows_read_problem(security: _WinPathSecurity) -> str | None:
    """Why a broad account can read the file this access list belongs to, or ``None``.

    A list that could not be read is a problem too: a check that did not finish has not shown the
    file restricted. Kept free of ctypes so the decision is testable on every platform."""
    from messagefoundry.auth.trust_anchors import _is_broad_sid

    if security.status != 0:
        detail = f": {security.status_text}" if security.status_text else ""
        return f"its access list could not be read (Win32 error {security.status}{detail})"
    if not security.dacl_present:
        return "it has no access list at all, so every account on the host can read it"
    if security.aces is None:
        return "its access list could not be read in full"
    for ace_type, mask, sid in security.aces:
        if ace_type != ACCESS_ALLOWED_ACE_TYPE or not mask & _READ_REACH_MASK:
            continue
        if _is_broad_sid(sid.lower()):
            return f"{describe_sid(sid)} can read it"
    return None


def _posix_read_problem(mode: int) -> str | None:
    """Why an account other than the owner can read a file of this mode, or ``None``."""
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        return f"its mode is {stat.S_IMODE(mode):04o}, so accounts other than its owner can read it"
    return None


def broad_read_problem(path: Path) -> str | None:
    """Why ``path`` is readable beyond the accounts a key file is for, or ``None`` when it is not.

    Windows: an allow entry that lets Everyone, Authenticated Users, the local Users group or
    another broad group read the file, or take it over. POSIX: a group or other read bit. A file
    whose access cannot be read is reported as a problem, and so is, on Windows, a path that is
    itself a link, because a link carries its own access list and the file behind it was not read.

    The answer names accounts and modes only, never the path or the file's contents."""
    try:
        # lstat on Windows, so a link is seen as itself; stat on POSIX, so the file behind it is.
        status = os.lstat(path) if sys.platform == "win32" else os.stat(path)
    except OSError as exc:
        return f"it could not be examined ({exc.strerror or type(exc).__name__})"
    if sys.platform == "win32":
        from messagefoundry.config.wiring import _win32_config_source_probes

        if status.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            return "it is a link, so the access list of the file behind it was not read"
        return _windows_read_problem(_win32_config_source_probes().read_path(path))
    return _posix_read_problem(status.st_mode)


# --- creating the file ----------------------------------------------------------------------------


def write_restricted_file(path: Path, data: bytes, *, read_grants: Sequence[str] = ()) -> None:
    """Create ``path`` restricted, confirm its access, then write ``data`` to it.

    ``read_grants`` (Windows only) names further accounts to grant read: an account name such as
    ``NT SERVICE\\MessageFoundry``, or a SID, with or without a leading ``*``.

    Raises ``FileExistsError`` when ``path`` already exists, as a file or as a link, and leaves
    what is there untouched. Raises :class:`RestrictedFileError` when the file cannot be created
    restricted or does not read back as asked, and ``OSError`` when the write itself fails. After
    any failure but ``FileExistsError`` there is no file at ``path``."""
    # The exclusive create sits OUTSIDE the cleanup guard on purpose: a name that is taken raises
    # FileExistsError HERE, and that file belongs to someone. Unlinking it would be the overwrite
    # the exclusive create exists to prevent.
    fd = _create_restricted(path, read_grants)
    try:
        try:
            handle = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)  # nothing owns the descriptor yet, and Windows cannot unlink an open file
            raise
        with handle:
            handle.write(data)
    except BaseException:
        # A write that dies partway (a full volume) would otherwise leave a TRUNCATED file that
        # nothing removes, and the exclusive create then refuses it on every retry. Nothing is
        # relabelled: the error is re-raised as it came. This runs after the `with` closed the
        # handle, which Windows requires before an unlink.
        path.unlink(missing_ok=True)
        raise


def _create_restricted(path: Path, read_grants: Sequence[str]) -> int:
    """Exclusively create ``path`` restricted and return a write-only descriptor for it.

    The access is confirmed here, while the file is still empty, so no byte is ever written to a
    file whose access was not what was asked for. A file that fails that check is removed."""
    if sys.platform == "win32":
        return _create_restricted_windows(path, read_grants)
    if read_grants:
        raise RestrictedFileError("a read grant for another account is supported on Windows only")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        status = os.fstat(fd)
        if stat.S_IMODE(status.st_mode) & 0o077 or status.st_uid != os.geteuid():
            raise RestrictedFileError(
                f"{path} could not be created readable by its owner alone: it reads back as mode "
                f"{stat.S_IMODE(status.st_mode):04o}, owner {status.st_uid}"
            )
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    return fd


def _create_restricted_windows(path: Path, read_grants: Sequence[str]) -> int:
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise RestrictedFileError("the Windows create runs only on Windows")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    from messagefoundry.config.wiring import _win32_config_source_probes
    from messagefoundry.store.store import _parse_sddl_dacl, _read_dacl_sddl

    probes = _win32_config_source_probes()
    if probes.self_sid is None:
        raise RestrictedFileError(
            f"{path} was not created: this process's own account could not be read, so the file "
            "could not be restricted to it"
        )
    expected = _expected_access(probes.self_sid, [_resolve_sid(name) for name in read_grants])

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        )

    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    convert.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,  # lpFileName
        wintypes.DWORD,  # dwDesiredAccess
        wintypes.DWORD,  # dwShareMode
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,  # dwCreationDisposition
        wintypes.DWORD,  # dwFlagsAndAttributes
        wintypes.HANDLE,  # hTemplateFile
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    generic_write = 0x40000000
    create_new = 1
    # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT. With the second, a name that is a link
    # is opened as itself, so CREATE_NEW refuses it as it refuses a file, and nothing is created
    # at whatever the link points to.
    flags_and_attributes = 0x00000080 | 0x00200000
    invalid_handle = wintypes.HANDLE(-1).value

    descriptor = ctypes.c_void_p()
    if not convert(_protected_sddl(expected), 1, ctypes.byref(descriptor), None):
        raise RestrictedFileError(
            f"{path} was not created: its access list could not be built (Win32 error "
            f"{ctypes.get_last_error()})"
        )
    try:
        attributes = _SECURITY_ATTRIBUTES(
            ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor.value, False
        )
        # Share mode 0: until this handle closes, nothing else can open the file for data.
        handle = kernel32.CreateFileW(
            str(path),
            generic_write,
            0,
            ctypes.byref(attributes),
            create_new,
            flags_and_attributes,
            None,
        )
        if handle is None or handle == invalid_handle:
            # ERROR_FILE_EXISTS and ERROR_ALREADY_EXISTS both arrive as FileExistsError.
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(descriptor)

    try:
        sddl = _read_dacl_sddl(path)
        parsed = _parse_sddl_dacl(sddl) if sddl is not None else None
        mismatch = _created_mismatch(
            probes.read_path(path), None if parsed is None else parsed.protected, expected
        )
        if mismatch is not None:
            raise RestrictedFileError(f"{path} could not be created restricted: {mismatch}")
        return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    except BaseException:
        kernel32.CloseHandle(handle)
        path.unlink(missing_ok=True)
        raise


def _resolve_sid(principal: str) -> str:
    """The string SID of ``principal``: an account name, or a SID with or without a leading ``*``.

    Every answer comes back from ``ConvertSidToStringSidW``, so what reaches the access list is a
    SID Windows itself rendered and never the caller's text. A name that does not resolve raises
    :class:`RestrictedFileError`: an entry that cannot be written is a failure, not a file created
    without it."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise RestrictedFileError("an account name resolves to a SID on Windows only")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.LookupAccountNameW.argtypes = [
        wintypes.LPCWSTR,  # lpSystemName (NULL = this machine)
        wintypes.LPCWSTR,  # lpAccountName
        ctypes.c_void_p,  # Sid
        ctypes.POINTER(wintypes.DWORD),  # cbSid
        wintypes.LPWSTR,  # ReferencedDomainName
        ctypes.POINTER(wintypes.DWORD),  # cchReferencedDomainName
        ctypes.POINTER(ctypes.c_int),  # peUse
    ]
    advapi32.LookupAccountNameW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    def render(sid_pointer: ctypes.c_void_p | ctypes.Array[ctypes.c_char]) -> str | None:
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    refusal = RestrictedFileError(f"the account {principal!r} could not be resolved")
    literal = principal.removeprefix("*")
    if literal.upper().startswith("S-1-"):
        sid_pointer = ctypes.c_void_p()
        if not advapi32.ConvertStringSidToSidW(literal, ctypes.byref(sid_pointer)):
            raise refusal
        try:
            rendered = render(sid_pointer)
        finally:
            kernel32.LocalFree(sid_pointer)
    else:
        sid_size = wintypes.DWORD(0)
        domain_size = wintypes.DWORD(0)
        use = ctypes.c_int(0)
        # Sizing probe: fails by design and fills the two lengths.
        advapi32.LookupAccountNameW(
            None,
            principal,
            None,
            ctypes.byref(sid_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
        if sid_size.value == 0:
            raise refusal
        sid_buffer = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(max(domain_size.value, 1))
        if not advapi32.LookupAccountNameW(
            None,
            principal,
            sid_buffer,
            ctypes.byref(sid_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        ):
            raise refusal
        rendered = render(sid_buffer)
    if rendered is None:
        raise refusal
    return rendered
