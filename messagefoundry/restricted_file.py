# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Files that hold key material: restricted in the call that creates them, and checked before use.

Two entry points, and both fail closed (vault BACKLOG #2601):

* :func:`write_restricted_file` creates a file that is restricted from its first moment and refuses
  to replace one that exists. Its access list is read back before a single byte is written. A file
  that could not be created that way is never left behind, and there is no fallback to writing the
  file first and tightening it afterwards.
* :func:`broad_access_problem` answers, before a key file is used, whether a known broad group or
  an application package can read it or change it.

:func:`key_file_handle_problem` is the stricter Windows read check the key custody reads use: the
owner and the exact list, read through the open handle.

Beside them, :func:`unlink_generated` removes a key or certificate file the engine wrote, riding out
the brief Windows hold another process puts on such a file (:func:`ride_out_a_held_file`). It sits
here so the `cert` commands, which write through this module, need not import the API TLS module.
:func:`replace_generated` is its twin for a replace. The config editors use both on files that hold
no key, because a hold looks the same there.

``store._secure_file`` is the other mechanism, and it is for files that hold no key: it tightens a
file that already exists and only logs when it cannot. A file that holds a key must never have that
as its only protection.

**Windows.** The access list is attached in the ``CreateFileW`` call itself, as a protected list
(no inheritance from the directory) naming SYSTEM, Administrators, the creating account unless the
caller turns that off, and each account granted read. That is the set ``scripts/service/install-service.ps1`` leaves on the data
directory. SYSTEM and Administrators already reach every file on the host, so naming them adds no
one. ``CREATE_NEW`` with ``FILE_FLAG_OPEN_REPARSE_POINT`` refuses a name that is already taken,
whether by a file or by a link.

**POSIX.** ``O_CREAT | O_EXCL`` with mode ``0o600``, which also refuses an existing name or link.
On Linux, a POSIX access control list the new file inherits from a default list on its directory is
removed before a byte is written, and its absence read back, so the file's mode is its whole access
(:func:`posix_access_acl`).

All ``ctypes`` work sits behind ``sys.platform`` guards, so the module imports on every platform and
type-checks on the Linux CI leg (mirrors :mod:`messagefoundry.secrets_dpapi`).
"""

from __future__ import annotations

import errno
import os
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from messagefoundry.auth.anchor_path import (
    _GRANTING_ACE_TYPES,
    _SHARED_SERVICE_SIDS,
    ACCESS_ALLOWED_ACE_TYPE,
    ADMINISTRATORS_SID,
    SYSTEM_SID,
    describe_sid,
)

if TYPE_CHECKING:
    from messagefoundry.config.wiring import _WinPathSecurity

__all__ = [
    "LINUX_CREDENTIAL_FILE_SYSTEMS",
    "LINUX_HOST_FILE_SYSTEMS",
    "WINERROR_ACCESS_DENIED",
    "WINERROR_SHARING_VIOLATION",
    "RestrictedFileError",
    "broad_access_problem",
    "custody_account_problem",
    "delete_through_handle",
    "key_file_handle_problem",
    "custody_engine_problem",
    "linux_file_system_problem",
    "linux_file_system_refusal",
    "linux_file_system_type",
    "posix_access_acl",
    "replace_generated",
    "ride_out_a_held_file",
    "unlink_generated",
    "write_restricted_file",
]


class RestrictedFileError(OSError):
    """A file could not be created restricted, or what was created did not read back as asked.

    An ``OSError`` so a caller that already treats a failed write as fatal treats this the same way.
    The message never carries the bytes that were to be written."""


# --- the access list a new file carries (Windows) -------------------------------------------------

#: FILE_ALL_ACCESS and FILE_GENERIC_READ, as the SDDL rights ``FA`` and ``FR`` store them in an ACE,
#: and FILE_GENERIC_READ with DELETE (``FRSD``): the handoff's grant, so the service that reads it
#: can delete it through the handle it read it with (the key custody draft, rule 3 step 2).
_FULL_ACCESS = 0x001F01FF
_READ_ACCESS = 0x00120089
_DELETE = 0x00010000
_READ_DELETE_ACCESS = _READ_ACCESS | _DELETE
_SDDL_RIGHT: Mapping[int, str] = {
    _FULL_ACCESS: "FA",
    _READ_ACCESS: "FR",
    _READ_DELETE_ACCESS: "FRSD",
}


def _expected_access(
    creator_sid: str,
    read_sids: Sequence[str],
    *,
    creator_access: bool = True,
    read_delete: bool = False,
) -> dict[str, int]:
    """The whole access list of a new file, as SID to access mask, in the order it is written.

    Full control for SYSTEM, Administrators and the creating account (not the creating account when
    ``creator_access`` is off); read for each account in ``read_sids``, and with ``read_delete``
    read and delete. An account already holding full control keeps it and gets no second entry."""
    access = {SYSTEM_SID: _FULL_ACCESS, ADMINISTRATORS_SID: _FULL_ACCESS}
    if creator_access:
        access.setdefault(creator_sid, _FULL_ACCESS)
    for sid in read_sids:
        access.setdefault(sid, _READ_DELETE_ACCESS if read_delete else _READ_ACCESS)
    return access


def _protected_sddl(access: Mapping[str, int]) -> str:
    """The access list as SDDL: protected (``P``), one explicit allow entry per account."""
    return "D:P" + "".join(f"(A;;{_SDDL_RIGHT[mask]};;;{sid})" for sid, mask in access.items())


#: Accounts a key custody file is never kept for: SYSTEM, LOCAL SERVICE and NETWORK SERVICE. Every
#: service that runs as LOCAL SERVICE or NETWORK SERVICE holds that account, and SYSTEM is the
#: operating system's own, so a key bound to one is open to all of them. SYSTEM also already holds
#: full control in every custody list, so a grant to it would collapse into that entry and the
#: list would name no engine account at all. Refused unconditionally: as the handoff's grantee and
#: as the account the engine runs as, for the handoff and the host file alike.
_CUSTODY_REFUSED_SIDS = frozenset({SYSTEM_SID, *_SHARED_SERVICE_SIDS})


def custody_account_problem(sid: str | None) -> str | None:
    """Why a key custody file must not be kept for the account ``sid``, or ``None``.

    ``None`` for ``sid`` (an account that could not be read) is a problem too. Kept free of ctypes so
    the decision is testable on every platform."""
    if sid is None:
        return (
            "the account could not be read, so it cannot be shown to be one the engine alone "
            "runs as"
        )
    if sid in _CUSTODY_REFUSED_SIDS:
        return (
            f"{describe_sid(sid)} is an account many services share or the operating system's "
            "own, and a key custody file is kept for an account the engine alone runs as (a "
            "virtual service account, S-1-5-80-...)"
        )
    return None


def custody_engine_problem(engine_sid: str | None) -> str | None:
    """Why the engine, running as ``engine_sid``, may keep no key custody file, or ``None``: the
    one refusal both the custody writers and :func:`key_file_handle_problem` give."""
    problem = custody_account_problem(engine_sid)
    return None if problem is None else f"the engine's own account is refused: {problem}"


# --- the read check, before a key file is used ----------------------------------------------------

#: Rights that let their holder read the file, change it, or give itself the right to. Reading
#: discloses the key. Changing it matters as much: a machine-scope DPAPI blob can be built by any
#: account on the host, so an account that can replace the file can substitute a key it knows.
_REACH_MASK = (
    0x00000001  # FILE_READ_DATA
    | 0x00000002  # FILE_WRITE_DATA
    | 0x00000004  # FILE_APPEND_DATA
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
    | 0x80000000  # GENERIC_READ
)

#: The same, for a DIRECTORY that holds key or secret files: also FILE_DELETE_CHILD, which lets its
#: holder delete any file in the directory whatever that file's own access list says. Deleting a
#: secret file can send its setting back to a less protected source (vault BACKLOG #2595).
_DIRECTORY_REACH_MASK = _REACH_MASK | 0x00000040  # FILE_DELETE_CHILD

#: Groups and logon classes that many accounts hold, beyond the ones the trust-anchor check already
#: names (``auth.trust_anchors._is_broad_sid``: Everyone, Authenticated Users, Users, Guests, the
#: INTERACTIVE, NETWORK, BATCH and SERVICE logon classes, Domain Users and Domain Guests). **At
#: least these, and never a complete list**: this is a list of known broad groups, so a file that
#: passes has not been shown readable by the intended accounts alone.
_MORE_BROAD_GROUP_SIDS: frozenset[str] = frozenset(
    {
        "S-1-2-0",  # LOCAL
        "S-1-2-1",  # CONSOLE LOGON
        "S-1-5-1",  # DIALUP
        "S-1-5-12",  # RESTRICTED
        "S-1-5-13",  # TERMINAL SERVER USER
        "S-1-5-14",  # REMOTE INTERACTIVE LOGON
        "S-1-5-15",  # THIS ORGANIZATION
        "S-1-5-17",  # IUSR
        "S-1-5-64-10",  # NTLM Authentication
        "S-1-5-64-14",  # SChannel Authentication
        "S-1-5-64-21",  # Digest Authentication
        "S-1-5-32-568",  # BUILTIN\IIS_IUSRS
        "S-1-5-32-547",  # BUILTIN\Power Users
        "S-1-5-32-555",  # BUILTIN\Remote Desktop Users
        "S-1-5-80-0",  # NT SERVICE\ALL SERVICES
        "S-1-15-2-1",  # ALL APPLICATION PACKAGES
        "S-1-15-2-2",  # ALL RESTRICTED APPLICATION PACKAGES
        "S-1-18-1",  # Authentication authority asserted identity
        "S-1-18-2",  # Service asserted identity
    }
)
#: The relative id of Domain Computers, in any domain: every machine account holds it.
_DOMAIN_COMPUTERS_RID = "515"


def _is_broad_group(sid: str) -> bool:
    """Whether ``sid`` is a group or logon class that many accounts hold. At least the known ones.

    One predicate for both sides, so the create never writes a grant the check would report. LOCAL
    SERVICE and NETWORK SERVICE are accounts, not groups, and are not counted here: an engine may
    run as one, and an operator who grants one has named an account."""
    from messagefoundry.auth.trust_anchors import _is_broad_sid

    if _is_broad_sid(sid.lower()) or sid in _MORE_BROAD_GROUP_SIDS:
        return True
    return sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] == _DOMAIN_COMPUTERS_RID


#: APPLICATION PACKAGE AUTHORITY: every AppContainer package SID and capability SID starts here.
_PACKAGE_SID_PREFIX = "S-1-15-"


def _is_package_sid(sid: str) -> bool:
    """Whether ``sid`` names an AppContainer package or capability. A package runs under the
    account that starts it, so a read grant to one would let a confined worker read a key file
    (vault BACKLOG #3411; the key custody ADR draft, rule 3). Refused as a grant when a file is
    created, and reported by the check before a key file is used, like a broad group."""
    return sid.upper().startswith(_PACKAGE_SID_PREFIX)


def _windows_access_problem(security: _WinPathSecurity, mask: int = _REACH_MASK) -> str | None:
    """Why a broad group or an application package can read or change the file this access list
    belongs to, or ``None``.

    A list that could not be read is a problem too, and so is an entry of a kind this check cannot
    interpret: a check that did not finish has not shown the file restricted. Kept free of ctypes
    so the decision is testable on every platform."""
    if security.status != 0:
        detail = f": {security.status_text}" if security.status_text else ""
        return f"its access list could not be read (Win32 error {security.status}{detail})"
    if not security.dacl_present:
        return "it has no access list at all, so every account on the host can read or change it"
    if security.aces is None:
        return "its access list could not be read in full"
    for ace_type, ace_mask, sid in security.aces:
        if ace_type not in _GRANTING_ACE_TYPES:
            continue  # a deny or audit entry grants nothing
        if ace_type != ACCESS_ALLOWED_ACE_TYPE:
            # A conditional or object allow entry. The reader records neither its rights nor its
            # account, so who it lets in is unknown.
            return "its access list holds a conditional entry this check cannot interpret"
        if ace_mask & mask and _is_broad_group(sid):
            return f"{describe_sid(sid)} can read or change it"
        if ace_mask & mask and _is_package_sid(sid):
            return f"the application package {sid} can read or change it"
    return None


def _posix_access_problem(mode: int) -> str | None:
    """Why an account other than the owner can read or change a file of this mode, or ``None``."""
    if mode & 0o066:  # group or other, read or write
        return (
            f"its mode is {stat.S_IMODE(mode):04o}, so accounts other than its owner can read or "
            "change it"
        )
    return None


#: The extended attribute that holds a Linux file's POSIX access control list.
POSIX_ACL_XATTR = "system.posix_acl_access"


def posix_access_acl(fd: int) -> bytes | None:
    """The raw POSIX access control list of the open file ``fd``, or ``None`` when it has none.

    Linux only, where the list is an extended attribute; raises :class:`RestrictedFileError`
    elsewhere. No such attribute (``ENODATA``) and a file system that keeps no POSIX list
    (``ENOTSUP``) both mean no list. Every other error propagates as the ``OSError`` it is, because a
    list that could not be read is not a list shown absent. **A file system with its own access
    model, such as an NFSv4 or CIFS mount, also answers ``ENOTSUP``**, so its access list, if it has
    one, is not read here."""
    if sys.platform != "linux":
        raise RestrictedFileError("a POSIX access control list is read on Linux only")
    try:
        return os.getxattr(fd, POSIX_ACL_XATTR)
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return None
        raise


#: Linux file systems a key custody HOST file may be kept on, by their ``statfs`` magic
#: (``linux/magic.h``; ZFS's from OpenZFS): local disk file systems whose access this host's own
#: kernel keeps, through the mode and, where one is set, the POSIX list. **An allowlist, so it fails
#: closed:** a file system not named here is refused whatever it is, so a network, cluster, FUSE or
#: overlay file system, or one stacked over such a file system, is refused without being named.
#: ecryptfs is left out on purpose: it is local, but it may be stacked over NFS, and its own magic
#: does not say what lies beneath it. ext2, ext3 and ext4 share one magic.
LINUX_HOST_FILE_SYSTEMS: Mapping[int, str] = MappingProxyType(
    {
        0xEF53: "ext2/3/4",
        0x58465342: "xfs",
        0x9123683E: "btrfs",
        0x2FC12FC1: "zfs",
        0xF2F52010: "f2fs",
        0xCA451A4E: "bcachefs",
    }
)

#: Linux file systems a systemd credential may be read from: the in-memory file systems systemd
#: mounts a unit's credentials directory on. An allowlist, as :data:`LINUX_HOST_FILE_SYSTEMS` is.
LINUX_CREDENTIAL_FILE_SYSTEMS: Mapping[int, str] = MappingProxyType(
    {0x858458F6: "ramfs", 0x01021994: "tmpfs"}
)


def linux_file_system_problem(magic: int, allowed: Mapping[int, str], what: str) -> str | None:
    """Why a ``what`` must not be kept on a file system of ``statfs`` magic ``magic``, or ``None``
    when ``allowed`` names it. The refusal names the magic in hex. Kept free of I/O so the decision
    is testable on every platform."""
    if magic in allowed:
        return None
    names = list(allowed.values())
    listed = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} or {names[-1]}"
    return f"it is on a file system of type {magic:#010x}, and a {what} is kept on {listed} only"


def linux_file_system_refusal(fd: int, allowed: Mapping[int, str], what: str) -> str | None:
    """Why the open file ``fd`` must not be used as a ``what``: its file system could not be read,
    or ``allowed`` does not name it (:func:`linux_file_system_problem`). ``None`` when it may. Read
    through the descriptor. Linux only, as :func:`linux_file_system_type` is."""
    try:
        magic = linux_file_system_type(fd)
    except OSError as exc:
        return f"its file system could not be read ({exc.strerror or type(exc).__name__})"
    return linux_file_system_problem(magic, allowed, what)


def linux_file_system_type(fd: int) -> int:
    """The ``statfs`` magic of the file system that holds the open file ``fd`` (``fstatfs``).

    Read through the descriptor, so it is the file system of the file that was opened, not of
    whatever a name points to now. Linux only; raises :class:`RestrictedFileError` elsewhere, and
    ``OSError`` when the call fails or the C library offers no ``fstatfs``, chained from the error
    that said so."""
    if sys.platform != "linux":
        raise RestrictedFileError("a file system type is read on Linux only")
    try:
        import ctypes

        # The process's own symbols, which hold the C library's; no library search, so no
        # subprocess. fstatfs64 first: on a 32-bit C library plain fstatfs refuses a large file
        # system with EOVERFLOW. Both structs open with f_type.
        libc = ctypes.CDLL(None, use_errno=True)
        fstatfs = getattr(libc, "fstatfs64", None) or libc.fstatfs
    except (ImportError, AttributeError) as exc:  # no ctypes, or a C library with no fstatfs
        raise OSError(errno.ENOSYS, "this process's C library offers no fstatfs") from exc
    fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
    fstatfs.restype = ctypes.c_int
    # struct statfs opens with f_type: an unsigned int on s390x, and a native long (__fsword_t) on
    # the other Linux ABIs. The rest of the struct is under 128 bytes everywhere; the buffer is
    # larger.
    buffer = ctypes.create_string_buffer(256)
    if fstatfs(fd, buffer) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    field = ctypes.c_uint if os.uname().machine == "s390x" else ctypes.c_ulong
    return field.from_buffer(buffer).value & 0xFFFFFFFF


def broad_access_problem(path: Path, *, directory: bool = False) -> str | None:
    """Why ``path`` is open beyond the accounts a key file is for, or ``None`` when it is not.

    With ``directory``, ``path`` is a directory that holds such files, and on Windows a broad
    group's right to delete a file inside it (FILE_DELETE_CHILD) is a problem too. On POSIX the
    group and other write bits, which the check already refuses, are that right.

    Windows: an allow entry that lets a known broad group read the file, change it, or take it
    over. The groups are at least Everyone, Authenticated Users and the local Users group; the
    whole list is :func:`_is_broad_group`, and it is a list of known groups, not a proof that only
    the intended accounts can reach the file. An application package or capability SID
    (:func:`_is_package_sid`) is reported the same way. POSIX: a group or other read or write bit.
    A file whose access cannot be read is reported as a problem, and so is, on Windows, a path that is
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
        return _windows_access_problem(
            _win32_config_source_probes().read_path(path),
            _DIRECTORY_REACH_MASK if directory else _REACH_MASK,
        )
    return _posix_access_problem(status.st_mode)


# --- the exact check, through an open handle (Windows) --------------------------------------------

_SE_DACL_PROTECTED = 0x1000


@dataclass(frozen=True, slots=True)
class _HandleSecurity:
    """The owner and access list ``GetSecurityInfo`` read from one open handle, before any policy.

    ``aces`` holds ``(type, flags, mask, sid)`` per entry, with ``sid`` empty for an entry type
    whose account the reader does not parse. ``error`` is set when the read did not finish."""

    error: str | None = None
    owner_sid: str | None = None
    dacl_present: bool = True
    protected: bool = False
    aces: tuple[tuple[int, int, int, str], ...] = ()


def _who(sid: str) -> str:
    return f"the application package {sid}" if _is_package_sid(sid) else describe_sid(sid)


def _exact_descriptor_problem(
    security: _HandleSecurity, expected: Mapping[str, int], *, engine_sid: str
) -> str | None:
    """Why the file ``security`` was read from is not owned and listed exactly as a key file is,
    or ``None`` when it is.

    Exactly means: owned by SYSTEM, Administrators (the owner of a file an elevated administrator
    creates) or ``engine_sid``, because an owner keeps READ_CONTROL and WRITE_DAC whatever the list
    says; a protected list; and ``expected`` (an :func:`_expected_access` result) entry for entry:
    no extra entry of any kind, a deny included, no missing one and no inheritance flag. Kept free
    of ctypes so the decision is testable on every platform."""
    if security.error is not None:
        return f"its owner and access list could not be read ({security.error})"
    owner = security.owner_sid
    if owner is None:
        return "its owner could not be read"
    if owner not in {SYSTEM_SID, ADMINISTRATORS_SID, engine_sid}:
        return (
            f"it is owned by {_who(owner)}, not by SYSTEM, Administrators or the account the "
            "engine runs as"
        )
    if not security.dacl_present:
        return "it has no access list at all, so every account on the host can read or change it"
    if not security.protected:
        return "its access list does not block inheritance from the directory"
    wanted = sorted((ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid) for sid, mask in expected.items())
    if sorted(security.aces) == wanted:
        return None
    for ace_type, flags, mask, sid in security.aces:
        if (ace_type, flags, mask, sid) in wanted:
            continue
        if ace_type != ACCESS_ALLOWED_ACE_TYPE or flags:
            return (
                f"its access list holds an entry of type {ace_type:#04x} with flags {flags:#04x}, "
                "beyond the key file's own"
            )
        return f"its access list grants {_who(sid)} access {mask:#010x}, beyond the key file's own"
    return "its access list lacks or repeats an entry the key file's own list names"


def _read_handle_security(handle: int) -> _HandleSecurity:
    """Read the owner and access list of the object open as ``handle`` with ``GetSecurityInfo``, so
    what is read belongs to the open file and not to whatever its name reaches now. The handle needs
    READ_CONTROL, which a read handle holds. Windows only."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise RestrictedFileError("a handle's access list is read on Windows only")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pvoid_p = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        pvoid_p,
        pvoid_p,
        pvoid_p,
        pvoid_p,
        pvoid_p,
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, pvoid_p]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    def sid_text(address: int | None) -> str | None:
        if not address:
            return None
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(address, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetSecurityInfo(
        handle,
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000004,  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        return _HandleSecurity(error=f"Win32 error {status}: {ctypes.FormatError(status).strip()}")
    try:
        # The owner and list pointers point INTO the descriptor, so all is copied out before it is
        # freed.
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            return _HandleSecurity(error=f"Win32 error {ctypes.get_last_error()}")
        owner_sid = sid_text(owner.value)
        if not dacl.value:
            return _HandleSecurity(owner_sid=owner_sid, dacl_present=False)
        # ACL header: revision, sbz1 (bytes), size, count, sbz2 (words). The count is at offset 4.
        count = ctypes.cast(dacl.value + 4, ctypes.POINTER(wintypes.WORD))[0]
        aces: list[tuple[int, int, int, str]] = []
        for index in range(count):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl.value, index, ctypes.byref(ace)) or not ace.value:
                return _HandleSecurity(error=f"entry {index} of its access list could not be read")
            base = ace.value
            ace_type = ctypes.cast(base, ctypes.POINTER(ctypes.c_ubyte))[0]
            ace_flags = ctypes.cast(base + 1, ctypes.POINTER(ctypes.c_ubyte))[0]
            ace_mask = ctypes.cast(base + 4, ctypes.POINTER(wintypes.DWORD))[0]
            sid = ""
            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                # The account's SID follows the 4-byte header and the mask. Any other type is
                # refused on its type alone, so its account is not read.
                parsed = sid_text(base + 8)
                if parsed is None:
                    return _HandleSecurity(error=f"the account in entry {index} could not be read")
                sid = parsed
            aces.append((int(ace_type), int(ace_flags), int(ace_mask), sid))
        return _HandleSecurity(
            owner_sid=owner_sid,
            protected=bool(control.value & _SE_DACL_PROTECTED),
            aces=tuple(aces),
        )
    finally:
        kernel32.LocalFree(descriptor)


#: Volumes whose owner and access list this host's own kernel keeps. On any other, a remote server
#: or a user-mode file system reports them, and can report any owner and any list.
_LOCAL_ACCESS_MODEL_VOLUMES = frozenset({"NTFS", "REFS"})
_FILE_REMOTE_DEVICE = 0x00000010
#: FILE_DEVICE_DISK, what a file on a local disk volume answers (measured on Windows 11, NTFS and
#: ReFS). Every other device type, a network or DFS redirector's included, is refused.
_FILE_DEVICE_DISK = 0x07


@dataclass(frozen=True, slots=True)
class _HandleVolume:
    """What was read about the volume that holds one open handle, before any policy."""

    error: str | None = None
    file_system: str = ""
    device_type: int = 0
    characteristics: int = 0


def _volume_problem(volume: _HandleVolume) -> str | None:
    """Why the owner and access list of a file on ``volume`` cannot be taken as this host's, or
    ``None``. A remote volume, and a file system other than NTFS or ReFS, report a descriptor this
    host's kernel did not keep. A user-mode file system that calls itself NTFS on a local device is
    not caught here. Kept free of ctypes so the decision is testable on every platform."""
    if volume.error is not None:
        return f"its volume could not be read ({volume.error})"
    if volume.characteristics & _FILE_REMOTE_DEVICE:
        return "it is on a network volume, whose owner and access list this host does not keep"
    if volume.device_type != _FILE_DEVICE_DISK:
        return (
            f"it is on a volume of device type {volume.device_type:#04x}, not a local disk, so "
            "this host may not keep its owner and access list"
        )
    if volume.file_system.upper() not in _LOCAL_ACCESS_MODEL_VOLUMES:
        return (
            f"it is on a {volume.file_system or 'nameless'} volume, and a key file is read on "
            "NTFS or ReFS only, whose owner and access list this host keeps"
        )
    return None


def _read_handle_volume(handle: int) -> _HandleVolume:
    """Read the file system name and the device type and characteristics of the volume that holds
    the object open as ``handle``, through the handle. Windows only."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise RestrictedFileError("a handle's volume is read on Windows only")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel32.GetVolumeInformationByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumeInformationByHandleW.restype = wintypes.BOOL

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = (("status", ctypes.c_void_p), ("information", ctypes.c_void_p))

    class _FsDeviceInformation(ctypes.Structure):
        _fields_ = (("device_type", wintypes.ULONG), ("characteristics", wintypes.ULONG))

    ntdll.NtQueryVolumeInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    ntdll.NtQueryVolumeInformationFile.restype = wintypes.LONG

    name = ctypes.create_unicode_buffer(64)
    if not kernel32.GetVolumeInformationByHandleW(handle, None, 0, None, None, None, name, 64):
        return _HandleVolume(error=f"Win32 error {ctypes.get_last_error()}")
    status_block = _IoStatusBlock()
    device = _FsDeviceInformation()
    status = ntdll.NtQueryVolumeInformationFile(
        handle,
        ctypes.byref(status_block),
        ctypes.byref(device),
        ctypes.sizeof(device),
        4,  # FileFsDeviceInformation
    )
    if status != 0:
        return _HandleVolume(error=f"NTSTATUS {status & 0xFFFFFFFF:#010x}")
    return _HandleVolume(
        file_system=name.value,
        device_type=int(device.device_type),
        characteristics=int(device.characteristics),
    )


def key_file_handle_problem(handle: int, *, engine_read_only: bool) -> str | None:
    """Windows: why the key file open as ``handle`` is not owned and listed exactly as one, or
    ``None`` when it is.

    The volume, owner and access list are read through the handle, never by name, so a link in a
    parent directory re-pointed after the open does not change what is judged. The file must be on
    a local NTFS or ReFS volume (:func:`_volume_problem`), owned by SYSTEM, Administrators or the
    account this process runs as, and its protected list must be exactly SYSTEM and Administrators
    with full control and that account with read and delete (``engine_read_only``, the handoff's
    list: what :func:`write_restricted_file` writes with ``creator_access`` off, ``read_delete`` on
    and a read grant to that account) or with full control (the host file's list: what it writes
    for its own creator, with no read grant). Any other entry, a deny entry included, is refused.
    An engine that runs as SYSTEM, LOCAL SERVICE or NETWORK SERVICE is refused for either list
    (:func:`custody_account_problem`). An account that holds a privilege to set any owner, such as
    the restore privilege Administrators and Backup Operators hold, can still make a file that
    passes. Raises :class:`RestrictedFileError` off Windows, and ``OSError`` or a ctypes error when
    a call cannot be made at all."""
    if sys.platform != "win32":
        raise RestrictedFileError("a key file's handle is checked on Windows only")
    from messagefoundry.config.wiring import _win32_config_source_probes

    volume = _volume_problem(_read_handle_volume(handle))
    if volume is not None:
        return volume
    engine_sid = _win32_config_source_probes().self_sid
    refused = custody_engine_problem(engine_sid)
    if refused is not None or engine_sid is None:
        return refused
    # The two lists write_restricted_file makes: the handoff's and the host file's.
    if engine_read_only:
        expected = _expected_access(
            engine_sid, [engine_sid], creator_access=False, read_delete=True
        )
    else:
        expected = _expected_access(engine_sid, ())
    return _exact_descriptor_problem(_read_handle_security(handle), expected, engine_sid=engine_sid)


#: FILE_INFO_BY_HANDLE_CLASS FileDispositionInfo.
_FILE_DISPOSITION_INFO = 4


def delete_through_handle(handle: int) -> None:
    """Windows: delete the file open as ``handle``, through that handle, so what is deleted is the
    file the handle reached and never whatever its name reaches now.

    ``SetFileInformationByHandle`` with ``FileDispositionInfo``: the name goes when the last handle
    to the file closes, so a caller that holds the only handle closes it next. The handle must hold
    DELETE. Raises ``OSError`` when Windows refuses, and :class:`RestrictedFileError` off Windows."""
    if sys.platform != "win32":
        raise RestrictedFileError("a file is deleted through its handle on Windows only")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    delete = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile
    if not kernel32.SetFileInformationByHandle(
        handle, _FILE_DISPOSITION_INFO, ctypes.byref(delete), ctypes.sizeof(delete)
    ):
        raise ctypes.WinError(ctypes.get_last_error())


# --- removing a file the engine wrote -------------------------------------------------------------

#: Windows ERROR_SHARING_VIOLATION: another process holds the file open without delete sharing.
WINERROR_SHARING_VIOLATION = 32
#: Windows ERROR_ACCESS_DENIED: what a REPLACE onto a file held open elsewhere returns, measured on
#: Windows 11 with a reader holding the destination (a delete returns the sharing violation).
WINERROR_ACCESS_DENIED = 5
_HELD_RETRY_S = 2.0
_HELD_POLL_S = 0.05


def ride_out_a_held_file(action: Callable[[], None], held: frozenset[int]) -> None:
    """Run ``action``, retrying for :data:`_HELD_RETRY_S` while Windows refuses it with one of the
    ``held`` codes.

    On Windows a file another process holds open cannot be deleted or replaced, and a certificate or
    key is exactly the file other processes open: the tray pins it, and backup or antivirus may scan
    it. That hold is momentary, so the refusal is retried before it propagates. Any other error, and
    every error off Windows, propagates at once.
    """
    deadline = time.monotonic() + _HELD_RETRY_S
    while True:
        try:
            action()
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in held or time.monotonic() >= deadline:
                raise
        time.sleep(_HELD_POLL_S)


def unlink_generated(path: Path) -> None:
    """Delete one file, riding out a brief Windows sharing violation. Shared by the API's minted
    pair and the `cert` commands' cleanup, so neither imports the other, and the code-set editor."""
    ride_out_a_held_file(path.unlink, frozenset({WINERROR_SHARING_VIOLATION}))


def replace_generated(staged: Path, live: Path) -> None:
    """Move ``staged`` over ``live``, riding out a brief Windows hold on either file.

    Both codes count: a hold on ``staged`` answers the sharing violation and a hold on ``live``
    answers access denied, the same code a true denial answers, so a true denial waits out the
    short retry before it propagates. Shared by the API's minted pair and the config editors."""
    ride_out_a_held_file(
        lambda: os.replace(staged, live),
        frozenset({WINERROR_SHARING_VIOLATION, WINERROR_ACCESS_DENIED}),
    )


# --- creating the file ----------------------------------------------------------------------------


class _OwnerRefused(RestrictedFileError):
    """The file could not be created owned by the account asked for, so nothing was written to it."""


#: ERROR_INVALID_OWNER: the creating token may not make the SID asked for a new object's owner.
_WINERROR_INVALID_OWNER = 1307
_READ_CONTROL = 0x00020000


def _administrators_enabled() -> bool:
    """Whether this process's token holds Administrators as an enabled group: at least an elevated
    administrator's and SYSTEM's do, and a filtered token's (an administrator not elevated, where
    the group is deny-only) does not.

    A pre-check only, for a clear refusal before anything is made. Windows decides who may make a
    SID a new file's owner by the group's owner attribute or an enabled restore privilege, not by
    this answer, so the create's own refusal (ERROR_INVALID_OWNER) and the read-back of the owner
    stay the binding checks. Windows only."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise RestrictedFileError("a token's groups are read on Windows only")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.CheckTokenMembership.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.CheckTokenMembership.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(ADMINISTRATORS_SID, ctypes.byref(sid)):
        raise RestrictedFileError(
            f"the group to check could not be built (Win32 error {ctypes.get_last_error()})"
        )
    try:
        member = wintypes.BOOL()
        # A null token: the thread's impersonation token, else a copy of the process's own.
        if not advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)):
            raise RestrictedFileError(
                f"this process's groups could not be read (Win32 error {ctypes.get_last_error()})"
            )
        return bool(member.value)
    finally:
        kernel32.LocalFree(sid)


def write_restricted_file(
    path: Path,
    data: bytes,
    *,
    read_grants: Sequence[str] = (),
    creator_access: bool = True,
    owner: str | None = None,
    read_delete: bool = False,
    local_volume_only: bool = False,
) -> None:
    """Create ``path`` restricted, confirm its access, then write ``data`` to it.

    ``read_grants`` (Windows only) names further accounts to grant read: an account name such as
    ``NT SERVICE\\MessageFoundry``, or a SID, with or without a leading ``*``.

    ``owner`` (Windows only) is the account the file is created owned by, in the call that creates
    it, named as ``read_grants`` are, and read back through the creating handle before a byte is
    written. A token that may not make that account an owner, or a file that reads back owned by
    anyone else, raises :class:`RestrictedFileError`. Left out, the owner is the creating token's
    default.

    ``creator_access`` (Windows only to turn off) gives the creating account full control. With it
    off the list is SYSTEM and Administrators with full control and each read grant with read, and
    nothing for the creating account: the key custody draft's descriptor (rule 5) when the one read
    grant is the service. The creator still writes the file through the handle that creates it, and
    reads the list back as its owner, or through Administrators' entry when ``owner`` names
    Administrators. Removing the file after a failure then takes the right
    to delete it from the directory, or Administrators' full control, so an elevated administrator
    is the caller this is for.

    ``read_delete`` (Windows only) gives each read grant DELETE beside read (SDDL ``FRSD``), so the
    account it names can delete the file through the handle it reads it with: the key custody
    handoff, which the service deletes once it has converted it (draft rule 3 step 2).

    ``local_volume_only`` refuses, while the new file is still empty, a file on a volume whose
    access this host does not keep: on Windows anything but a local NTFS or ReFS disk
    (:func:`_volume_problem`, read through the creating handle), and on Linux a file system
    :data:`LINUX_HOST_FILE_SYSTEMS` does not name (``fstatfs`` on the creating descriptor). The
    empty file is then removed, so no byte reaches a network, cluster or user-mode file system. Any
    other POSIX host refuses it before a file is made. The key custody writers pass it; it is off
    by default, so the other key files are written as before.

    On Windows the new file's owner and access list are read back through the creating handle and
    judged by the same exact check a key custody read makes (:func:`_exact_descriptor_problem`):
    owned by SYSTEM, Administrators or the creating account (or by ``owner``, when given), a
    protected list, and exactly the entries asked for, with no inheritance flag.

    Raises ``FileExistsError`` when ``path`` already exists, as a file or as a link, and leaves
    what is there untouched. Raises :class:`RestrictedFileError` when the file cannot be created
    restricted or does not read back as asked, and ``OSError`` when the write itself fails. After
    any failure but ``FileExistsError`` there is no file at ``path``, or, where it could not be
    removed, the :class:`RestrictedFileError` raised says so."""
    # The exclusive create sits OUTSIDE the cleanup guard on purpose: a name that is taken raises
    # FileExistsError HERE, and that file belongs to someone. Unlinking it would be the overwrite
    # the exclusive create exists to prevent.
    fd = _create_restricted(
        path,
        read_grants,
        creator_access=creator_access,
        owner=owner,
        read_delete=read_delete,
        local_volume_only=local_volume_only,
    )
    try:
        try:
            handle = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)  # nothing owns the descriptor yet, and Windows cannot unlink an open file
            raise
        with handle:
            handle.write(data)
    except BaseException as failure:
        # A write that dies partway (a full volume) would otherwise leave a TRUNCATED file that
        # nothing removes, and the exclusive create then refuses it on every retry. The error is
        # re-raised as it came unless the file cannot be removed (_remove_failed). This runs after
        # the `with` closed the handle, which Windows requires before an unlink.
        _remove_failed(path, failure)
        raise


def _remove_failed(path: Path, failure: BaseException) -> None:
    """Remove the file ``failure`` left at ``path``, riding out a brief Windows hold on it.

    Called while ``failure`` is handled, and the caller re-raises it. Where the file cannot be
    removed (a creator with no entry of its own, ``creator_access`` off, and no right to delete in
    the directory, or a hold that outlasts the retry), an ``Exception`` is replaced by a
    :class:`RestrictedFileError` that names both, chained from it; any other ``BaseException`` keeps
    its own type and gains a note. Neither message carries the bytes that were to be written."""
    reason: str | None = None
    try:
        unlink_generated(path)
    except FileNotFoundError:
        pass  # nothing was left
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
    if reason is None:
        return
    left = f"{path} was left behind and could not be removed ({reason}); remove it by hand"
    if not isinstance(failure, Exception):
        failure.add_note(left)
        return
    raise RestrictedFileError(f"{left}. It was left by this failure: {failure}") from failure


def _create_restricted(
    path: Path,
    read_grants: Sequence[str],
    *,
    creator_access: bool,
    owner: str | None,
    read_delete: bool = False,
    local_volume_only: bool = False,
) -> int:
    """Exclusively create ``path`` restricted and return a write-only descriptor for it.

    The access, and with ``local_volume_only`` the volume, are confirmed here, while the file is
    still empty, so no byte is ever written to a file whose access was not what was asked for. A
    file that fails either check is removed."""
    if sys.platform == "win32":
        return _create_restricted_windows(
            path,
            read_grants,
            creator_access=creator_access,
            owner=owner,
            read_delete=read_delete,
            local_volume_only=local_volume_only,
        )
    if read_grants or read_delete:
        raise RestrictedFileError("a read grant for another account is supported on Windows only")
    if not creator_access:
        raise RestrictedFileError("a file without its creator's access is made on Windows only")
    if owner is not None:
        raise RestrictedFileError("a file owned by another account is made on Windows only")
    if local_volume_only and sys.platform != "linux":
        raise RestrictedFileError(
            "a file system is checked before a key file is written on Linux and Windows only"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        if local_volume_only:
            # Before the inherited list is asked for, so a refused file system is not asked.
            refused = linux_file_system_refusal(
                fd, LINUX_HOST_FILE_SYSTEMS, "key custody host file"
            )
            if refused is not None:
                raise RestrictedFileError(f"{path} was not written: {refused}")
        if sys.platform == "linux":
            _drop_inherited_acl(path, fd)
        # A default list or a umask can leave the owner without read; set the mode exactly, so a
        # reader that opens the file as its owner can read what was written. A file system that
        # keeps no modes (vfat, exFAT) refuses the chmod; that is a create that did not restrict.
        status: os.stat_result | None = None
        reason = ""
        try:
            os.fchmod(fd, 0o600)
            status = os.fstat(fd)
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
        if status is None:
            raise RestrictedFileError(
                f"{path} could not be created readable by its owner alone: its mode could not be "
                f"set or read back ({reason})"
            )
        if stat.S_IMODE(status.st_mode) & 0o077 or status.st_uid != os.geteuid():
            raise RestrictedFileError(
                f"{path} could not be created readable by its owner alone: it reads back as mode "
                f"{stat.S_IMODE(status.st_mode):04o}, owner {status.st_uid}"
            )
    except BaseException as failure:
        os.close(fd)
        _remove_failed(path, failure)
        raise
    return fd


def _drop_inherited_acl(path: Path, fd: int) -> None:
    """Remove the access list a new, still empty file inherited from a default list on its
    directory, and read back that it is gone, so the file's mode is its whole access.

    The ``0o600`` create masks the inherited named entries to nothing, but they stay in the list,
    where a later ``chmod`` would widen them again and a reader that judges the entries themselves
    (the key custody reads) refuses them."""
    if sys.platform != "linux":  # pragma: no cover - guard for the type checker off Linux
        raise RestrictedFileError("a POSIX access control list is removed on Linux only")
    reason: str | None = None
    try:
        if posix_access_acl(fd) is not None:
            os.removexattr(fd, POSIX_ACL_XATTR)
            if posix_access_acl(fd) is not None:
                reason = "it still carries one after it was removed"
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
    if reason is not None:
        raise RestrictedFileError(
            f"{path} could not be created without an inherited POSIX access control list: {reason}"
        )


def _create_restricted_windows(
    path: Path,
    read_grants: Sequence[str],
    *,
    creator_access: bool,
    owner: str | None,
    read_delete: bool,
    local_volume_only: bool,
) -> int:
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise RestrictedFileError("the Windows create runs only on Windows")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    from messagefoundry.config.wiring import _win32_config_source_probes

    probes = _win32_config_source_probes()
    if probes.self_sid is None:
        raise RestrictedFileError(
            f"{path} was not created: this process's own account could not be read, so the file "
            "could not be restricted to it"
        )
    read_sids = [_resolve_sid(name) for name in read_grants]
    # Resolved as a grant is, so only a SID Windows itself rendered reaches the descriptor, and the
    # read-back compares like with like.
    owner_sid = None if owner is None else _resolve_sid(owner)
    for name, sid in zip(read_grants, read_sids, strict=True):
        if _is_package_sid(sid):
            raise RestrictedFileError(
                f"{path} was not created: {name!r} is an application package, and a key file is "
                "granted to the account the engine runs as, never to a package"
            )
        if _is_broad_group(sid):
            # A grant that would make the file broadly readable is not a restricted create.
            raise RestrictedFileError(
                f"{path} was not created: {name!r} is {describe_sid(sid)}, a group many accounts "
                "hold, and a key file cannot be granted to it. Name the one account the engine "
                "runs as"
            )
    expected = _expected_access(
        probes.self_sid, read_sids, creator_access=creator_access, read_delete=read_delete
    )

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

    # READ_CONTROL too, so the new file's owner and list are read back through this handle.
    desired_access = generic_write | _READ_CONTROL
    sddl_text = ("" if owner_sid is None else f"O:{owner_sid}") + _protected_sddl(expected)
    descriptor = ctypes.c_void_p()
    if not convert(sddl_text, 1, ctypes.byref(descriptor), None):
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
            desired_access,
            0,
            ctypes.byref(attributes),
            create_new,
            flags_and_attributes,
            None,
        )
        if handle is None or handle == invalid_handle:
            error = ctypes.get_last_error()
            if owner_sid is not None and error == _WINERROR_INVALID_OWNER:
                raise _OwnerRefused(
                    f"{path} was not created: this process may not make {describe_sid(owner_sid)} "
                    "the owner of a new file"
                )
            # ERROR_FILE_EXISTS and ERROR_ALREADY_EXISTS both arrive as FileExistsError.
            raise ctypes.WinError(error)
    finally:
        kernel32.LocalFree(descriptor)

    try:
        if local_volume_only:
            volume = _volume_problem(_read_handle_volume(handle))
            if volume is not None:
                raise RestrictedFileError(f"{path} was not written: {volume}")
        # Read through the creating handle, never by name, and judged by the check a key custody
        # read makes, so the create and the read hold one standard.
        security = _read_handle_security(handle)
        if owner_sid is not None:
            if security.error is not None or security.owner_sid is None:
                raise _OwnerRefused(
                    f"{path} could not be created owned by {describe_sid(owner_sid)}: its owner "
                    f"could not be read back ({security.error or 'none was returned'})"
                )
            if security.owner_sid != owner_sid:
                raise _OwnerRefused(
                    f"{path} could not be created owned by {describe_sid(owner_sid)}: it reads back "
                    f"owned by {_who(security.owner_sid)}"
                )
        mismatch = _exact_descriptor_problem(
            security, expected, engine_sid=owner_sid or probes.self_sid
        )
        if mismatch is not None:
            raise RestrictedFileError(f"{path} could not be created restricted: {mismatch}")
        return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    except BaseException as failure:
        kernel32.CloseHandle(handle)
        _remove_failed(path, failure)
        raise


def _resolve_sid(principal: str) -> str:
    """The string SID of ``principal``: an account name, or a SID with or without a leading ``*``.

    A NAME must resolve to one account: a group, an alias or a domain is refused. A SID literal is
    taken as given.

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
        # SID_NAME_USE: 1 is a user account and 5 a well-known account, which is how SYSTEM and a
        # service's virtual account resolve. A group, an alias or a bare domain name is not ONE
        # account, and a bare domain SID is one no token carries, so the grant would reach nobody.
        if use.value not in (1, 5):
            raise RestrictedFileError(
                f"{principal!r} names a group or a domain, not one account, so a key file cannot "
                "be granted to it. Name the one account the engine runs as"
            )
        rendered = render(sid_buffer)
    if rendered is None:
        raise refusal
    return rendered
