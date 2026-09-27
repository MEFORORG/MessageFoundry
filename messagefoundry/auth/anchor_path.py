# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Can another principal replace a trust anchor through its path? (ASVS 6.7.1, BACKLOG #1142).

The file arm in :mod:`messagefoundry.auth.trust_anchors` reads the anchor's own DACL. That misses the
cheaper attack: delete the anchor through a right on its DIRECTORY, then plant a new file at the same
name. Measured on Windows 11: a user with delete-child on the directory deleted an anchor whose own
DACL gave it no DELETE, planted a substitute, and the file arm then read the substitute owner-only.

This module checks the **resolution chain**: every object the kernel passes through to reach the
anchor, from the volume root down, with each link spliced in and each link object checked too.

On a directory it counts only the rights that remove or rename an entry. Adding files is not one of
them. That distinction is what lets ``C:\\`` and ``C:\\ProgramData`` pass as Windows ships them,
while a directory granting delete-child to an untrusted principal refuses.

The verdict is tri-state, like the file arm's:

* ``True`` -- every object in the chain was read, and only trusted principals can replace anything.
* ``False`` -- some object lets an untrusted principal remove, rename or rewrite part of the chain.
* ``None`` -- nothing was found insecure, but something could not be read or described.

A definite ``False`` anywhere beats ``None``: the walk evaluates every object it reached, even
after a failure.

The policies are pure functions over recorded data, so the Linux CI leg runs the logic of both
arms. Only :func:`anchor_path_verdict` touches the file system, and only its Windows half uses
ctypes.
"""

from __future__ import annotations

import logging
import ntpath
import os
import posixpath
import stat
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

#: The kernel's own limit is 40 on Linux (``MAXSYMLINKS``); Windows allows 63 reparse hops. The walk
#: stops at 40 on both and answers indeterminate, which also ends a link cycle.
MAX_LINK_HOPS = 40

# Object kinds in a chain.
DIRECTORY = "directory"
FILE = "file"
LINK = "link"
PATH = "path"  # a finding about the path as a whole, not one object in it


@dataclass(frozen=True)
class ChainFinding:
    """One object in the chain that is insecure, or that could not be judged.

    ``insecure`` is ``True`` for a definite finding and ``False`` for an indeterminate one. ``sids``
    names the Windows principals the finding is about, so the fix text can remove them. ``owner``
    marks a finding about who owns the object rather than about a grant. ``writable`` marks a POSIX
    finding about group or other write bits, so its fix is the chmod alone and never a chown."""

    path: str
    kind: str
    insecure: bool
    reason: str
    sids: tuple[str, ...] = ()
    owner: bool = False
    writable: bool = False


@dataclass(frozen=True)
class PathVerdict:
    """The result of checking an anchor's resolution chain. ``platform`` picks the fix text.

    ``engine`` names the account the check trusted as the engine's own, for the message: the
    verdict depends on it, so a check run by another account can answer differently."""

    ok: bool | None
    findings: tuple[ChainFinding, ...] = ()
    platform: str = "posix"
    engine: str | None = field(default=None, compare=False)


def _combine(findings: Iterable[ChainFinding]) -> bool | None:
    """False if any finding is definite, None if any is indeterminate, else True."""
    found = list(findings)
    if any(f.insecure for f in found):
        return False
    return None if found else True


def _dedupe(findings: Iterable[ChainFinding], *, fold_case: bool) -> tuple[ChainFinding, ...]:
    """Drop repeats, keeping the first, so a directory reached twice is reported once. Paths are
    compared without case only on Windows: on POSIX, ``Certs`` and ``certs`` are two folders."""
    seen: set[tuple[str, str, bool, str]] = set()
    out: list[ChainFinding] = []
    for f in findings:
        key = (f.path.lower() if fold_case else f.path, f.kind, f.insecure, f.reason)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return tuple(out)


# =================================================================================================
# Windows: the policy for one object (pure)
# =================================================================================================

#: ACE flag: the entry is a template for children and grants nothing on the object that holds it.
INHERIT_ONLY_ACE = 0x08

#: Rights that let a principal rewrite or replace a FILE or a link object. Equal to
#: ``_WIN_WRITE_MASK`` in ``messagefoundry/config/wiring.py``; a test pins the two together.
WIN_FILE_MASK = (
    0x00000002  # FILE_WRITE_DATA
    | 0x00000004  # FILE_APPEND_DATA
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)

#: Rights on a DIRECTORY that let a principal remove or rename an entry, or rename the directory, or
#: grant itself either. Add-file (0x2) and add-subdirectory (0x4) are deliberately absent: they add
#: new names and can never reuse an existing one. GENERIC_WRITE maps to exactly those add rights plus
#: write EA and write attributes, so it is absent too.
WIN_DIR_MASK = (
    0x00000040  # FILE_DELETE_CHILD
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
)

#: ACE types that can GRANT a right in a DACL. Type 0 is the only one the reader parses in full. A
#: callback or object allow entry grants conditionally, so the reader cannot say whether it applies.
ACCESS_ALLOWED_ACE_TYPE = 0x00
_GRANTING_ACE_TYPES = frozenset({0x00, 0x04, 0x05, 0x09, 0x0B})

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

#: Trusted as owner and as grantee: they can change any file anyway, and TrustedInstaller owns
#: ``C:\\`` and ``C:\\Program Files`` as Windows ships them.
_ALWAYS_TRUSTED = frozenset({SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID})

#: Trusted as a grantee on an entry that is not inherit-only. CREATOR OWNER grants nobody; OWNER
#: RIGHTS grants the owner, who is checked in its own right.
_OWNER_PLACEHOLDERS = frozenset({"S-1-3-0", "S-1-3-4"})

#: LocalService and NetworkService run many services, so the engine running as one of them does not
#: make that SID the engine's alone. Self-trust skips them.
_SHARED_SERVICE_SIDS = frozenset({"S-1-5-19", "S-1-5-20"})

#: Broad groups, never trusted, whatever the Administrators membership read says. The config guard
#: refuses the same kind of SID outright (``_WIN_REJECTED_SIDS`` in ``config/wiring.py``). Skipping
#: the lookup for them also means an unfinished membership read cannot soften a grant to Everyone
#: into "could not tell". None of them is ever a process token's user, so a grant to one still
#: refuses when the engine's own SID cannot be read.
_BROAD_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-2",  # NETWORK
        "S-1-5-3",  # BATCH
        "S-1-5-4",  # INTERACTIVE
        "S-1-5-6",  # SERVICE
        "S-1-5-7",  # ANONYMOUS LOGON
        "S-1-5-11",  # Authenticated Users
        "S-1-5-113",  # Local account
        "S-1-5-32-545",  # BUILTIN\Users
        "S-1-5-32-546",  # BUILTIN\Guests
    }
)

#: Names for the reader of a refusal. The verdict never depends on these.
_WELL_KNOWN_NAMES = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-4": "OWNER RIGHTS",
    "S-1-5-2": "NT AUTHORITY\\NETWORK",
    "S-1-5-3": "NT AUTHORITY\\BATCH",
    "S-1-5-4": "NT AUTHORITY\\INTERACTIVE",
    "S-1-5-6": "NT AUTHORITY\\SERVICE",
    "S-1-5-7": "NT AUTHORITY\\ANONYMOUS LOGON",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-113": "NT AUTHORITY\\Local account",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
}


#: The SID shapes a process token's user can take: a machine or domain account, a service's
#: virtual account, an IIS app pool, or an Entra ID account. When the engine's own SID cannot be
#: read, only a SID of one of these shapes might be the engine. LocalService and NetworkService are
#: left out on purpose, as self-trust never applies to them.
_ACCOUNT_SID_PREFIXES = ("S-1-5-21-", "S-1-5-80-", "S-1-5-82-", "S-1-12-1-")


def describe_sid(sid: str) -> str:
    """``NAME (SID)`` for a well-known SID, else the SID alone. No lookup, so nothing can block."""
    name = _WELL_KNOWN_NAMES.get(sid)
    return f"{name} ({sid})" if name else sid


@dataclass(frozen=True)
class WinSecurity:
    """One object's owner and DACL, as the reader recorded them.

    ``aces`` holds ``(type, flags, mask, sid)`` per entry, with ``sid`` empty for an entry type the
    reader does not parse. ``aces is None`` is a NULL DACL. ``error`` is set when the read failed."""

    owner: str | None
    aces: tuple[tuple[int, int, int, str], ...] | None
    error: str | None = None


@dataclass(frozen=True)
class WinTrust:
    """Who the Windows rule trusts.

    ``admin_member`` answers whether a SID is a direct member of local Administrators: ``True``,
    ``False``, or ``None`` when the enumeration could not finish."""

    engine_sid: str | None
    admin_member: Callable[[str], bool | None]

    def _engine(self, sid: str) -> bool:
        return (
            self.engine_sid is not None
            and sid == self.engine_sid
            and (sid not in _SHARED_SERVICE_SIDS)
        )

    def _rest(self, sid: str) -> bool | None:
        if sid in _BROAD_SIDS:
            return False
        member = self.admin_member(sid)
        if member is True:
            return True
        if self.engine_sid is None and sid.startswith(_ACCOUNT_SID_PREFIXES):
            return None  # it might be the engine's own account, which could not be read
        return member

    def grantee(self, sid: str) -> bool | None:
        """Whether an allow entry for ``sid`` is harmless on this object."""
        if sid in _ALWAYS_TRUSTED or sid in _OWNER_PLACEHOLDERS or self._engine(sid):
            return True
        return self._rest(sid)

    def owner(self, sid: str) -> bool | None:
        """Whether ``sid`` may own an object in the chain. An owner holds WRITE_DAC implicitly.

        A well-known admin RID in any domain is trusted here, and only here. That is
        ``_is_well_known_admin_sid`` in ``config/wiring.py``, whose limit ADR 0036 Amendment A
        accepted for owners. For a grantee the membership lookup decides."""
        if sid in _ALWAYS_TRUSTED or self._engine(sid) or _is_well_known_admin_sid(sid):
            return True
        return self._rest(sid)


def _is_well_known_admin_sid(sid: str) -> bool:
    # Imported at call time: config.wiring is a large module, and the auth package must not pay for it
    # at import. By the time an anchor is checked, the engine has loaded its config through it.
    from messagefoundry.config.wiring import _is_well_known_admin_sid as _impl

    return _impl(sid)


def _rights_in_words(bits: int, kind: str) -> str:
    """The masked rights of one entry, in words, for the refusal message."""
    if bits & 0x10000000:
        return "has full control of it"
    words: list[str] = []
    if kind == DIRECTORY:
        if bits & 0x40:
            words.append("can delete or rename entries in it")
        if bits & 0x10000:
            words.append("can rename or delete it")
    else:
        if bits & (0x2 | 0x4 | 0x10 | 0x100 | 0x40000000):
            words.append("can write to it")
        if bits & 0x10000:
            words.append("can delete or rename it")
    if bits & 0x40000:
        words.append("can change its permissions")
    if bits & 0x80000:
        words.append("can take ownership of it")
    return ", ".join(words)


def evaluate_windows_object(
    path: str, kind: str, sec: WinSecurity, trust: WinTrust
) -> list[ChainFinding]:
    """Every finding for one object in the chain. An empty list means the object is sound.

    The entries are scanned before the owner, and past any entry the reader cannot judge, so a
    definite insecure entry is never hidden behind an indeterminate one. Deny entries are ignored:
    that can only make the rule refuse more, never less."""
    if sec.error is not None:
        return [ChainFinding(path, kind, False, f"its permissions could not be read: {sec.error}")]
    if sec.aces is None:
        return [ChainFinding(path, kind, True, "it has a NULL DACL, so everyone has full control")]
    mask = WIN_DIR_MASK if kind == DIRECTORY else WIN_FILE_MASK
    insecure: list[ChainFinding] = []
    unsure: list[ChainFinding] = []
    for ace_type, flags, access, sid in sec.aces:
        if ace_type not in _GRANTING_ACE_TYPES or flags & INHERIT_ONLY_ACE:
            continue
        bits = access & mask
        if not bits:
            continue
        rights = _rights_in_words(bits, kind)
        if ace_type != ACCESS_ALLOWED_ACE_TYPE:
            unsure.append(
                ChainFinding(
                    path,
                    kind,
                    False,
                    f"a conditional or object access entry (type 0x{ace_type:02x}) {rights}, "
                    "and this check cannot tell whom it applies to",
                )
            )
            continue
        verdict = trust.grantee(sid)
        if verdict is True:
            continue
        if verdict is False:
            insecure.append(ChainFinding(path, kind, True, f"{describe_sid(sid)} {rights}", (sid,)))
        else:
            unsure.append(
                ChainFinding(
                    path,
                    kind,
                    False,
                    f"{describe_sid(sid)} {rights}, and whether it is an administrator could not "
                    "be settled",
                    (sid,),
                )
            )
    if sec.owner is None:
        unsure.append(ChainFinding(path, kind, False, "its owner could not be read"))
    else:
        owned = trust.owner(sec.owner)
        if owned is False:
            insecure.append(
                ChainFinding(
                    path,
                    kind,
                    True,
                    f"it is owned by {describe_sid(sec.owner)}, which can change its permissions",
                    (sec.owner,),
                    owner=True,
                )
            )
        elif owned is None:
            unsure.append(
                ChainFinding(
                    path,
                    kind,
                    False,
                    f"it is owned by {describe_sid(sec.owner)}, and whether that is an "
                    "administrator could not be settled",
                    (sec.owner,),
                    owner=True,
                )
            )
    return insecure + unsure


# =================================================================================================
# Windows: the chain (pure over an injected probe)
# =================================================================================================


def _strip_win_prefix(path: str) -> str | None:
    """A path with any ``\\\\?\\`` or ``\\\\.\\`` prefix turned into the form the walk reads.

    ``\\\\?\\C:\\x`` becomes ``C:\\x`` and ``\\\\?\\UNC\\s\\x`` becomes ``\\\\s\\x``. A volume GUID
    path keeps its prefix, since it has no other spelling. Any other device path answers ``None``."""
    for prefix in ("\\\\?\\", "\\\\.\\", "\\??\\"):
        if path.startswith(prefix):
            rest = path[len(prefix) :]
            if rest[:4].upper() == "UNC\\":
                return "\\\\" + rest[4:]
            if len(rest) >= 2 and rest[1] == ":" and rest[0].isascii() and rest[0].isalpha():
                return rest
            if rest[:7].lower() == "volume{":
                return "\\\\?\\" + rest
            return None
    return path


#: A probe answers ``(kind, link target or None)`` for one path, without following a final link.
WinProbe = Callable[[str], tuple[str, str | None]]


def _no_volume_cause(_root: str) -> str | None:
    return None


def _no_drive_target(_drive: str) -> str | None:
    return None


def windows_chain(
    path: str,
    cwd: str | Callable[[], str],
    probe: WinProbe,
    *,
    volume_cause: Callable[[str], str | None] = _no_volume_cause,
    drive_target: Callable[[str], str | None] = _no_drive_target,
) -> tuple[list[tuple[str, str]], str | None]:
    """The chain of ``(object path, kind)`` from the volume root to the anchor, and a cause when the
    walk could not finish.

    Win32 collapses ``.`` and ``..`` in the text before any link is followed, so each pass
    normalizes first. A link's target is spliced in: a relative one against the directory holding
    the link, an absolute one from its own root. Every pass then restarts from the root of the new
    path, which re-reads a shared prefix but keeps the walk simple. The hop limit ends a cycle.

    ``drive_target`` answers the folder a ``subst`` drive letter stands for, or ``None`` for a real
    volume. Such a letter is spliced in like a link, because its ``X:\\`` is not a volume root:
    the folders above the substituted one can still be renamed. ``volume_cause`` answers why a
    volume cannot be judged, and is asked before anything on that volume is read. So a mapped
    network drive costs no round trip per folder, and a FAT volume's missing DACL is never read as
    everyone-full-control. ``cwd`` is called only for a relative path."""
    full = _strip_win_prefix(path)
    if full is None:
        return [], "the path is a device path this check does not read"
    if not ntpath.isabs(full) and not full.startswith("\\\\"):
        full = ntpath.join(cwd() if callable(cwd) else cwd, full)
    chain: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(obj: str, kind: str) -> None:
        if obj.lower() not in seen:
            seen.add(obj.lower())
            chain.append((obj, kind))

    hops = 0
    pending = full
    while True:
        norm = ntpath.normpath(pending)
        if norm.startswith("\\\\") and not norm.startswith("\\\\?\\"):
            return chain, "the path is on a network share, whose permissions this host cannot read"
        drive, rest = ntpath.splitdrive(norm)
        if not drive:
            return chain, "the path has no drive or volume"
        substituted = drive_target(drive) if len(drive) == 2 else None
        if substituted is not None:
            hops += 1
            if hops > MAX_LINK_HOPS:
                return chain, f"the path passes through more than {MAX_LINK_HOPS} links"
            target = _strip_win_prefix(substituted)
            if not target:
                return chain, f"the drive {drive} stands for a path this check does not read"
            pending = target + rest
            continue
        root = drive + "\\"
        why = volume_cause(root)
        if why is not None:
            return chain, f"'{root}': {why}"
        add(root, DIRECTORY)
        parts = [c for c in rest.split("\\") if c]
        cur = root
        spliced = False
        for i, name in enumerate(parts):
            if ":" in name:
                return chain, "the path names an alternate data stream"
            child = ntpath.join(cur, name)
            try:
                kind, target = probe(child)
            except OSError as exc:
                return chain, f"'{child}' could not be read: {exc.strerror or exc}"
            if kind == LINK:
                add(child, LINK)
                hops += 1
                if hops > MAX_LINK_HOPS:
                    return chain, f"the path passes through more than {MAX_LINK_HOPS} links"
                spliced_target = _strip_win_prefix(target or "")
                if not spliced_target:
                    return chain, f"the link '{child}' points at a path this check does not read"
                if spliced_target.startswith("\\") and not spliced_target.startswith("\\\\"):
                    spliced_target = drive + spliced_target  # rooted, no drive: the link's drive
                if not (ntpath.isabs(spliced_target) or spliced_target.startswith("\\\\")):
                    spliced_target = ntpath.join(cur, spliced_target)
                remaining = parts[i + 1 :]
                pending = ntpath.join(spliced_target, *remaining) if remaining else spliced_target
                spliced = True
                break
            add(child, kind)
            if kind != DIRECTORY and i != len(parts) - 1:
                return chain, f"'{child}' is not a directory"
            cur = child
        if not spliced:
            return chain, None


def windows_path_verdict(
    path: str,
    *,
    cwd: str | Callable[[], str],
    probe: WinProbe,
    read_security: Callable[[str, str], WinSecurity],
    volume_cause: Callable[[str], str | None],
    trust: WinTrust,
    drive_target: Callable[[str], str | None] = _no_drive_target,
) -> PathVerdict:
    """Evaluate the whole Windows chain. Pure: every input that touches the host is injected.
    :func:`windows_chain` says what ``volume_cause`` and ``drive_target`` answer. Every object the
    walk reached is evaluated, even when the walk stopped early."""
    chain, cause = windows_chain(
        path, cwd, probe, volume_cause=volume_cause, drive_target=drive_target
    )
    findings: list[ChainFinding] = []
    if cause is not None:
        findings.append(ChainFinding(path, PATH, False, cause))
    for obj, kind in chain:
        findings.extend(evaluate_windows_object(obj, kind, read_security(obj, kind), trust))
    found = _dedupe(findings, fold_case=True)
    return PathVerdict(_combine(found), found, "windows", trust.engine_sid)


# =================================================================================================
# POSIX (pure over injected lstat / readlink / fstype)
# =================================================================================================


@dataclass(frozen=True)
class PosixStat:
    """The two ``lstat`` fields the POSIX rule reads."""

    uid: int
    mode: int


#: File systems whose owner and mode bits are real. CIFS, NFS, FUSE and 9p can show a clean ``755``
#: chain while the server lets others replace the file, so they answer indeterminate.
POSIX_TRUSTED_FS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "overlay"})


def posix_path_verdict(
    path: str,
    *,
    cwd: str | Callable[[], str],
    euid: int,
    lstat_fn: Callable[[str], PosixStat],
    readlink_fn: Callable[[str], str],
    fstype_fn: Callable[[str], tuple[str, str] | None],
) -> PathVerdict:
    """Evaluate the POSIX chain. Pure: every input that touches the host is injected.

    ``fstype_fn`` answers ``(mount point, type)`` for a link-free path, or ``None`` when the type
    cannot be read.

    Each object must be owned by root or by the engine; when the engine runs as root, only root.
    A directory must carry no group or other write bit, unless it is sticky and the entry below it
    in the chain is owned by a trusted uid. The anchor must be a regular file with no group or other
    write bit. A link's own mode means nothing, and its owner counts only through the sticky rule.

    ``..`` is the parent of the directory already reached, which holds no link, as the kernel does.
    POSIX ACLs need no extra read: with an ACL present, the group bits show the ACL mask. ``cwd``
    is called only for a relative path."""
    trusted = {0} if euid == 0 else {0, euid}
    engine = f"uid {euid}"
    if not path.startswith("/"):
        path = posixpath.join(cwd() if callable(cwd) else cwd, path)
    findings: list[ChainFinding] = []
    fs_seen: set[str] = set()

    def visit(obj: str, st: PosixStat, kind: str) -> None:
        if st.uid not in trusted:
            findings.append(
                ChainFinding(
                    obj,
                    kind,
                    True,
                    f"it is owned by uid {st.uid}, not root or the engine",
                    owner=True,
                )
            )
        mounted = fstype_fn(obj)
        if mounted is None:
            if "?" not in fs_seen:
                fs_seen.add("?")
                findings.append(
                    ChainFinding(
                        obj, kind, False, "the type of the file system under it is unknown"
                    )
                )
        elif mounted[1] not in POSIX_TRUSTED_FS and mounted[0] not in fs_seen:
            fs_seen.add(mounted[0])
            findings.append(
                ChainFinding(
                    mounted[0],
                    DIRECTORY,
                    False,
                    f"it is a {mounted[1]} mount, whose owners and mode bits this check cannot vouch "
                    "for",
                )
            )

    todo = [c for c in path.split("/") if c]
    cur = "/"
    hops = 0
    try:
        cur_st = lstat_fn(cur)
    except OSError as exc:
        unread = ChainFinding("/", DIRECTORY, False, f"it could not be read: {exc}")
        return PathVerdict(None, (unread,), "posix", engine)
    visit(cur, cur_st, DIRECTORY)
    while todo:
        name = todo.pop(0)
        if name == ".":
            continue
        if name == "..":
            cur = posixpath.dirname(cur)
            try:
                cur_st = lstat_fn(cur)
            except OSError as exc:
                findings.append(ChainFinding(cur, PATH, False, f"it could not be read: {exc}"))
                break
            continue
        child = posixpath.join(cur, name)
        child_st: PosixStat | None = None
        missing: OSError | None = None
        try:
            child_st = lstat_fn(child)
        except OSError as exc:
            missing = exc
        sticky = bool(cur_st.mode & stat.S_ISVTX)
        if cur_st.mode & 0o022 and not sticky:
            findings.append(
                ChainFinding(cur, DIRECTORY, True, "group or others can write to it", writable=True)
            )
        elif (
            cur_st.mode & 0o022
            and child_st is not None
            and child_st.uid not in trusted
            and stat.S_ISLNK(child_st.mode)
        ):
            # In a sticky folder the entry's owner decides who can replace it, so the finding
            # names the entry, never the shared folder: the fix belongs on the entry. A folder or
            # file entry gets the same finding from its own owner test when it is visited.
            findings.append(
                ChainFinding(
                    child,
                    LINK,
                    True,
                    f"it is owned by uid {child_st.uid}, not root or the engine, and sits in "
                    f"'{cur}', which others can write to",
                    owner=True,
                )
            )
        if child_st is None:
            # Checked after the directory, so a writable directory is still reported.
            findings.append(ChainFinding(child, PATH, False, f"it could not be read: {missing}"))
            break
        if stat.S_ISLNK(child_st.mode):
            hops += 1
            if hops > MAX_LINK_HOPS:
                findings.append(
                    ChainFinding(
                        child, LINK, False, f"more than {MAX_LINK_HOPS} links were followed"
                    )
                )
                break
            try:
                target = readlink_fn(child)
                if target.startswith("/"):
                    cur, cur_st = "/", lstat_fn("/")
            except OSError as exc:
                findings.append(
                    ChainFinding(child, LINK, False, f"the link could not be read: {exc}")
                )
                break
            todo = [c for c in target.split("/") if c] + todo
            continue
        if stat.S_ISDIR(child_st.mode):
            visit(child, child_st, DIRECTORY)
            cur, cur_st = child, child_st
            continue
        visit(child, child_st, FILE)
        if any(c != "." for c in todo):
            findings.append(ChainFinding(child, FILE, False, "the path continues past a file"))
        elif not stat.S_ISREG(child_st.mode):
            findings.append(ChainFinding(child, FILE, True, "it is not a regular file"))
        elif child_st.mode & 0o022:
            findings.append(
                ChainFinding(child, FILE, True, "group or others can write to it", writable=True)
            )
        break
    else:
        # The components ran out on a directory: the anchor is not a file.
        findings.append(
            ChainFinding(cur, DIRECTORY, True, "the path names a directory, not a file")
        )
    found = _dedupe(findings, fold_case=False)
    return PathVerdict(_combine(found), found, "posix", engine)


# =================================================================================================
# The host readers
# =================================================================================================


def _parse_mountinfo(text: str) -> list[tuple[str, str]]:
    """``(mount point, type)`` per line of ``/proc/self/mountinfo``, octal escapes decoded."""
    mounts: list[tuple[str, str]] = []
    for line in text.splitlines():
        head, sep, tail = line.partition(" - ")
        fields = head.split()
        rest = tail.split()
        if not sep or len(fields) < 5 or not rest:
            continue
        point = fields[4]
        for code in ("\\040", "\\011", "\\012", "\\134"):
            point = point.replace(code, chr(int(code[1:], 8)))
        mounts.append((point, rest[0]))
    return mounts


def mount_of(path: str, mounts: list[tuple[str, str]]) -> tuple[str, str] | None:
    """The mount holding a link-free absolute path: the longest mount point that prefixes it. The
    last mount at a point wins, as the kernel stacks them."""
    best: tuple[str, str] | None = None
    for point, fstype in mounts:
        inside = point == "/" or path == point or path.startswith(point.rstrip("/") + "/")
        if inside and (best is None or len(point) >= len(best[0])):
            best = (point, fstype)
    return best


def _posix_host_verdict(path: str) -> PathVerdict:
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
            mounts: list[tuple[str, str]] | None = _parse_mountinfo(fh.read())
    except OSError:
        mounts = None  # not Linux, or no /proc: every object answers indeterminate for its type

    def lstat_fn(p: str) -> PosixStat:
        st = os.lstat(p)
        return PosixStat(st.st_uid, st.st_mode)

    def fstype_fn(p: str) -> tuple[str, str] | None:
        return mount_of(p, mounts) if mounts else None

    geteuid = getattr(os, "geteuid", None)
    return posix_path_verdict(
        path,
        cwd=os.getcwd,
        euid=geteuid() if geteuid is not None else -1,
        lstat_fn=lstat_fn,
        readlink_fn=os.readlink,
        fstype_fn=fstype_fn,
    )


_IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003  # a junction or a volume mount point
_IO_REPARSE_TAG_SYMLINK = 0xA000000C
_NAME_SURROGATE_BIT = 0x20000000  # IsReparseTagNameSurrogate: the tag stands for another name


def _win_probe(path: str) -> tuple[str, str | None]:
    """Kind of one path, without following it.

    Python's ``lstat`` does not follow a name-surrogate reparse point, and follows every other kind,
    as the file system does. Junctions and symbolic links are read and spliced in. Any other name
    surrogate, such as a container layer link, raises, and the walk answers indeterminate: it stands
    for another path this check cannot read, so the folders around that path would go unchecked."""
    st = os.lstat(path)
    tag = getattr(st, "st_reparse_tag", 0)
    if tag in (_IO_REPARSE_TAG_MOUNT_POINT, _IO_REPARSE_TAG_SYMLINK):
        return LINK, os.readlink(path)
    if tag & _NAME_SURROGATE_BIT:
        raise OSError(f"it is a reparse point (tag 0x{tag:08x}) this check does not follow")
    return (DIRECTORY if stat.S_ISDIR(st.st_mode) else FILE), None


@dataclass(frozen=True)
class WinHost:
    """The Windows readers for this host, as :func:`windows_path_verdict` takes them."""

    read_security: Callable[[str, str], WinSecurity]
    volume_cause: Callable[[str], str | None]
    engine_sid: str | None
    admin_member: Callable[[str], bool | None]
    drive_target: Callable[[str], str | None]


def windows_host_readers() -> WinHost:
    """Build the in-process Windows readers. Every object, links included, is opened with
    ``FILE_FLAG_OPEN_REPARSE_POINT`` and read with ``GetSecurityInfo``, so a link's own owner and
    DACL are what get read, not its target's. The handle asks for READ_CONTROL and nothing else.

    ctypes stays behind the platform guard so mypy and lint pass on the Linux CI leg, as
    ``_assert_safe_config_source_windows`` in ``config/wiring.py`` does."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the Windows reader runs only on Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pvoid_p = ctypes.POINTER(ctypes.c_void_p)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetDriveTypeW.restype = wintypes.UINT
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
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
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, pvoid_p]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, pvoid_p]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_int),
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
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]

    invalid_handle = wintypes.HANDLE(-1).value

    def sid_text(sid_ptr: int | None) -> str | None:
        if not sid_ptr:
            return None
        out = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
            return None
        try:
            return out.value
        finally:
            if out:
                kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))

    def win_error(code: int) -> str:
        return f"Win32 error {code} ({ctypes.FormatError(code).strip()})"

    def read_security(obj: str, _kind: str) -> WinSecurity:
        handle = kernel32.CreateFileW(
            obj,
            0x00020000,  # READ_CONTROL
            0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            None,
            3,  # OPEN_EXISTING
            0x02000000 | 0x00200000,  # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
            None,
        )
        if handle is None or handle == invalid_handle:
            return WinSecurity(None, (), win_error(ctypes.get_last_error()))
        owner_ptr = ctypes.c_void_p()
        dacl_ptr = ctypes.c_void_p()
        sd_ptr = ctypes.c_void_p()
        try:
            rc = advapi32.GetSecurityInfo(
                handle,
                1,  # SE_FILE_OBJECT
                0x00000001 | 0x00000004,  # OWNER | DACL
                ctypes.byref(owner_ptr),
                None,
                ctypes.byref(dacl_ptr),
                None,
                ctypes.byref(sd_ptr),
            )
        finally:
            kernel32.CloseHandle(handle)
        if rc != 0:
            return WinSecurity(None, (), win_error(rc))
        try:
            owner = sid_text(owner_ptr.value)
            if not dacl_ptr.value:
                return WinSecurity(owner, None)
            # ACL header: revision, sbz1 (bytes), size, count, sbz2 (words). Count is at offset 4.
            count = ctypes.cast(dacl_ptr.value + 4, ctypes.POINTER(wintypes.WORD))[0]
            aces: list[tuple[int, int, int, str]] = []
            for index in range(count):
                ace_ptr = ctypes.c_void_p()
                if not advapi32.GetAce(dacl_ptr.value, index, ctypes.byref(ace_ptr)):
                    return WinSecurity(owner, (), f"entry {index} of its DACL could not be read")
                base = ace_ptr.value or 0
                ace_type = ctypes.cast(base, ctypes.POINTER(ctypes.c_ubyte))[0]
                ace_flags = ctypes.cast(base + 1, ctypes.POINTER(ctypes.c_ubyte))[0]
                # Every granting entry type carries its access mask right after the 4-byte header.
                ace_mask = ctypes.cast(base + 4, ctypes.POINTER(wintypes.DWORD))[0]
                sid = ""
                if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                    parsed = sid_text(base + 8)
                    if parsed is None:
                        return WinSecurity(owner, (), f"the SID in entry {index} could not be read")
                    sid = parsed
                aces.append((int(ace_type), int(ace_flags), int(ace_mask), sid))
            return WinSecurity(owner, tuple(aces))
        finally:
            if sd_ptr.value:
                kernel32.LocalFree(sd_ptr)

    def volume_cause(root: str) -> str | None:
        drive_type = kernel32.GetDriveTypeW(root)
        if drive_type == 4:  # DRIVE_REMOTE
            return "it is a network drive, whose permissions this host cannot read"
        if drive_type in (0, 1):  # DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR
            return f"the type of this volume could not be read (drive type {drive_type})"
        fs_name = ctypes.create_unicode_buffer(64)
        if not kernel32.GetVolumeInformationW(root, None, 0, None, None, None, fs_name, 64):
            return f"its file system could not be read: {win_error(ctypes.get_last_error())}"
        if fs_name.value.upper() not in ("NTFS", "REFS"):
            return f"it is a {fs_name.value} volume, which keeps no permissions this check can read"
        return None

    def engine_sid() -> str | None:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,
            ctypes.byref(token),  # TOKEN_QUERY
        ):
            return None
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if size.value == 0:
                return None
            buf = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, 1, buf, size.value, ctypes.byref(size)):
                return None
            # TOKEN_USER is SID_AND_ATTRIBUTES; the SID pointer comes first.
            return sid_text(ctypes.cast(buf, pvoid_p)[0])
        finally:
            kernel32.CloseHandle(token)

    def administrators_name() -> str | None:
        # NetLocalGroupGetMembers takes a NAME, and the group's name is localized.
        sid_ptr = ctypes.c_void_p()
        if not advapi32.ConvertStringSidToSidW(ADMINISTRATORS_SID, ctypes.byref(sid_ptr)):
            return None
        try:
            name_len = wintypes.DWORD(0)
            domain_len = wintypes.DWORD(0)
            use = ctypes.c_int(0)
            advapi32.LookupAccountSidW(
                None,
                sid_ptr,
                None,
                ctypes.byref(name_len),
                None,
                ctypes.byref(domain_len),
                ctypes.byref(use),
            )
            if name_len.value == 0:
                return None
            name = ctypes.create_unicode_buffer(name_len.value)
            domain = ctypes.create_unicode_buffer(max(domain_len.value, 1))
            if not advapi32.LookupAccountSidW(
                None,
                sid_ptr,
                name,
                ctypes.byref(name_len),
                domain,
                ctypes.byref(domain_len),
                ctypes.byref(use),
            ):
                return None
            return name.value
        finally:
            if sid_ptr:
                kernel32.LocalFree(sid_ptr)

    def unresolved(members: set[str], why: str) -> tuple[frozenset[str], bool]:
        # Every early exit comes through here, so the operator sees WHY a grantee or owner came
        # out "could not be settled". The SIDs already read still answer yes: membership is
        # monotone, so only a no is withheld.
        log.warning(
            "the trust-anchor path check could not read the local Administrators members (%s); a "
            "principal it cannot place is reported as indeterminate",
            why,
        )
        return frozenset(members), False

    def administrators_members() -> tuple[frozenset[str], bool]:
        """Direct member SIDs of local Administrators, and whether the read was complete. Level 0
        returns SIDs only, so the lookup stays on the local SAM and never waits on a domain
        controller. A nested domain group is therefore not seen, as in the config guard."""
        try:
            netapi32 = ctypes.WinDLL("netapi32", use_last_error=True)
        except OSError as exc:
            return unresolved(set(), f"netapi32 could not be loaded: {exc}")
        netapi32.NetLocalGroupGetMembers.restype = wintypes.DWORD
        netapi32.NetLocalGroupGetMembers.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            pvoid_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            pvoid_p,
        ]
        netapi32.NetApiBufferFree.restype = wintypes.DWORD
        netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
        group = administrators_name()
        if group is None:
            return unresolved(set(), "BUILTIN\\Administrators could not be resolved to its name")
        members: set[str] = set()
        resume = ctypes.c_void_p(0)
        for _page in range(64):  # a termination guard, not a size limit
            buf = ctypes.c_void_p()
            read = wintypes.DWORD(0)
            total = wintypes.DWORD(0)
            rc = netapi32.NetLocalGroupGetMembers(
                None,
                group,
                0,
                ctypes.byref(buf),
                0xFFFFFFFF,  # MAX_PREFERRED_LENGTH
                ctypes.byref(read),
                ctypes.byref(total),
                ctypes.byref(resume),
            )
            if rc not in (0, 234):  # NERR_Success, ERROR_MORE_DATA
                return unresolved(members, f"NetLocalGroupGetMembers returned status {rc}")
            try:
                entries = ctypes.cast(buf, pvoid_p)
                for i in range(read.value):
                    member = sid_text(entries[i])
                    if member is None:
                        return unresolved(members, "a member SID could not be read")
                    members.add(member)
            finally:
                if buf:
                    netapi32.NetApiBufferFree(buf)
            if rc == 234:
                if read.value == 0:
                    return unresolved(members, "NetLocalGroupGetMembers made no progress")
                continue
            return frozenset(members), read.value >= total.value
        return unresolved(members, "the enumeration did not finish in 64 pages")

    def drive_target(drive: str) -> str | None:
        """The folder a ``subst`` drive stands for, or ``None``. QueryDosDeviceW answers
        ``\\??\\C:\\...`` for a substituted drive and ``\\Device\\...`` for a real volume or a
        network redirector."""
        buf = ctypes.create_unicode_buffer(1024)
        if not kernel32.QueryDosDeviceW(drive, buf, len(buf)):
            return None
        return buf.value[4:] if buf.value.startswith("\\??\\") else None

    cache: list[tuple[frozenset[str], bool]] = []

    def admin_member(sid: str) -> bool | None:
        if not cache:
            cache.append(administrators_members())
        members, complete = cache[0]
        if sid in members:
            return True  # a SID found in a partial read is still a member
        return False if complete else None

    return WinHost(read_security, volume_cause, engine_sid(), admin_member, drive_target)


def _windows_host_verdict(path: str) -> PathVerdict:
    host = windows_host_readers()
    return windows_path_verdict(
        path,
        cwd=os.getcwd,
        probe=_win_probe,
        read_security=host.read_security,
        volume_cause=host.volume_cause,
        trust=WinTrust(host.engine_sid, host.admin_member),
        drive_target=host.drive_target,
    )


def anchor_path_verdict(path: str | os.PathLike[str]) -> PathVerdict:
    """Check the resolution chain of the anchor at ``path`` on this host. READ-ONLY: it opens each
    object for READ_CONTROL on Windows and calls ``lstat`` on POSIX, and changes nothing."""
    text = os.fspath(path)
    try:
        if sys.platform == "win32":
            return _windows_host_verdict(text)
        return _posix_host_verdict(text)
    except OSError as exc:
        # Per-object read failures are findings already. What reaches here stopped the check as a
        # whole: a working directory that was deleted, for a relative anchor, or a system DLL that
        # would not load. That is "could not tell", which warns and audits; it must not crash a
        # startup or a reload the file arm would have let through.
        platform = "windows" if sys.platform == "win32" else "posix"
        unrun = ChainFinding(text, PATH, False, f"the path check could not run: {exc}")
        return PathVerdict(None, (unrun,), platform)
