# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Content fingerprint of a loaded config bundle — bind "reviewed in git" to "what loaded".

ADR 0041 (D1). ``load_config()`` executes **every** ``*.py`` in the config dir as the engine
service account, but the ``config_reload`` audit row records only *counts* — so two reloads of the
same directory with **different on-disk code** are indistinguishable, and an operator's reload can't
be tied to a reviewed commit (the attribution-laundering gap: a benign-looking handler diff that a
later innocent reload/restart detonates). :func:`config_fingerprint` returns a stable digest over the
**content** of every file the loader consumes, so the audit (and a startup row) can prove *which
bytes* a given reload activated, diffable against a signed source-of-truth.

By default this is **observational**: a fingerprint records, it does not gate — it never drops a
message or changes a disposition. At least the digest a dual-control release checks does gate
(:func:`snapshot_fingerprint`): it refuses a reload, and still touches no message.
It complements (does not replace) ADR 0036's load-time write-access refusal,
which stops an *unauthorized* principal from writing the config dir; the fingerprint attributes an
*authorized* change to a reviewed source.

Pure + offline: it hashes file *bytes* only — it never imports a config module, runs a subprocess, or
touches the network. The git-HEAD read is best-effort provenance (advisory), and the **content**
digest is the integrity anchor. Run it off the event loop (``asyncio.to_thread``) at the call site,
exactly like ``load_config`` itself.
"""

from __future__ import annotations

import hashlib
import json
import logging
import ntpath
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import NamedTuple, TypeGuard

from messagefoundry.config.snapshot import (
    ConfigDirMissing,
    ConfigSnapshot,
    is_missing_directory,
    is_value_file_entry,
    read_config_snapshot,
    value_file_rel,
)
from messagefoundry.credential import constant_time_equal
from messagefoundry.redaction import json_loads_or_refusal, refuse_repeated_keys

__all__ = [
    "FINGERPRINT_SCHEME",
    "UNREADABLE_FILES_KEY",
    "ConfigDirMissing",
    "DigestCoverage",
    "config_fingerprint",
    "config_fingerprint_detail",
    "describe_left_out",
    "fingerprint_matches",
    "digest_coverage",
    "is_config_digest",
    "is_missing_directory",
    "left_out_of",
    "same_digest",
    "shared_digest_of",
    "shared_digest_text",
    "snapshot_fingerprint",
    "value_file_material",
]

_log = logging.getLogger(__name__)

# Version the scheme so a future change to *what* is hashed (or *how*) is itself detectable in the
# trail — a fingerprint produced by v1 can never collide with one produced by a later revision.
# v2: a dot-named ``*.py`` is no longer hashed, because the loader no longer runs one (vault BACKLOG
# #2781).
# v3: the digest folds the one snapshot a load runs (:mod:`messagefoundry.config.snapshot`, vault
# BACKLOG #2596). A code-set table is matched by its suffix in lower case, as the loader matches it,
# so ``codesets/x.CSV`` is hashed on POSIX too; and a path that resolves to a file another path
# already names is hashed under both names, so a link added beside a module changes the digest.
_SCHEME = b"mefor-cfg-fp:v3\n"

#: The scheme tag :func:`config_fingerprint_detail` records beside each digest. Two digests are
#: comparable only under one scheme: a start compares its own digest with the store's last recorded
#: one only when the tags match, so a change to what is hashed reads as "not comparable" rather than
#: as a changed config (vault BACKLOG #2597).
FINGERPRINT_SCHEME = _SCHEME.decode("ascii").strip()

#: The :func:`config_fingerprint_detail` key that marks a partial digest: the sorted relative paths of
#: the covered files, and of the folders a snapshot lists, that could not be read and were left out
#: (vault BACKLOG #2944). Absent when the digest covers the whole bundle. Paths, not a count, so two
#: partial digests can be compared like for like, and an operator can tell which file to fix. The
#: entry ``.`` is the config directory itself, which could not be listed. Not ``degraded``: an audit
#: row merges this detail into its own, and there ``degraded`` already names failed reload steps.
UNREADABLE_FILES_KEY = "unreadable_files"

# What is hashed is what :func:`~messagefoundry.config.snapshot.read_config_snapshot` reads: every
# config module (by ``config.snapshot._covered_name``, which gives the list a load digests and runs;
# of the reads a load makes, only ADR 0036's trust check lists by ``config_py_files``, which applies
# the same rule; ``_``-prefixed helpers included and a dot-named ``.IB_OLD.py`` or AppleDouble
# ``._X.py`` skipped), ``connections.toml``, each ``codesets/`` table, and each
# ``environments/*.toml`` under the config directory. The last is never loaded as config. The value
# file a serve start reads sits
# under ``[environments].base_dir``; where that is this folder, a reload parses the very bytes
# hashed here (``ConfigSnapshot.environment_file``), so dropping them from the fold would let a
# released reload apply values its digest does not cover. Elsewhere, the default layout, a reload's
# snapshot holds it as ``@value-file/<name>`` and parses those bytes, but no digest here folds it:
# it can hold credentials, and these digests are published unkeyed. A dual-control hold binds it
# with a keyed MAC instead (:func:`value_file_material`; vault BACKLOG #2596). ``__pycache__`` is
# never read: the loader compiles the source itself.


def _entries(snapshot: ConfigSnapshot) -> list[tuple[str, bytes]]:
    """``(posix-relpath, sha256(content))`` for every file in ``snapshot``, sorted.

    Sorting by relpath makes the fold order-independent (filesystem enumeration order can vary);
    keying on the *relative* path (not absolute) makes the digest location-independent, so two
    byte-identical bundles at different paths fingerprint identically. The value file a reload's
    snapshot holds from outside the config directory is left out (:func:`value_file_material`)."""
    return sorted(
        (rel, hashlib.sha256(data).digest())
        for rel, data in snapshot.files.items()
        if not is_value_file_entry(rel)
    )


def _fold(entries: list[tuple[str, bytes]]) -> str:
    h = hashlib.sha256()
    h.update(_SCHEME)
    for rel, digest in entries:
        # NUL-delimit both fields so no (relpath, content) pair can be confused with another by
        # concatenation (e.g. "a" + "bc" vs "ab" + "c").
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(digest)
        h.update(b"\0")
    return h.hexdigest()


#: The shape :func:`_fold` returns: a SHA-256 hex digest, 64 lowercase hex characters.
_DIGEST_SHAPE = re.compile(r"[0-9a-f]{64}")


def is_config_digest(value: object) -> TypeGuard[str]:
    """Whether ``value`` has the shape of a digest this module returns, the one a dual-control
    release compares a held reload's against. A value of any other shape matches no config, so the
    approvals gate refuses a hold that carries one before its claim (vault BACKLOG #3192)."""
    return isinstance(value, str) and _DIGEST_SHAPE.fullmatch(value) is not None


def snapshot_fingerprint(snapshot: ConfigSnapshot) -> str:
    """The content digest of ``snapshot``: the bytes one load read, and so the bytes it ran.

    A digest that gates a load, such as the one a dual-control release checks, is taken from the
    snapshot that load then runs, so nothing can change between the check and the run (vault
    BACKLOG #2596). Its files left out as unreadable, if any, are not covered: a caller that gates
    on it checks :attr:`~messagefoundry.config.snapshot.ConfigSnapshot.unreadable` first, or reads
    the snapshot strictly."""
    return _fold(_entries(snapshot))


#: Leads :func:`value_file_material`, so its bytes are never those of another construction.
_VALUE_FILE_SCHEME = b"mefor-cfg-value-file:v1\n"


def value_file_material(snapshot: ConfigSnapshot) -> bytes | None:
    """What a dual-control hold binds of the value file ``snapshot`` read from outside the config
    directory (:func:`~messagefoundry.config.snapshot.with_value_file`), or ``None`` when it read
    none (vault BACKLOG #2596): its name, whether it was there, and its bytes, so creating,
    removing or editing it each change the material.

    No digest above folds that file, since it can hold credentials and they are published unkeyed.
    The engine MACs this material under a key derived from the store key
    (:func:`~messagefoundry.store.crypto.config_value_file_mac`) and never publishes it bare. A
    value file the snapshot could not read raises ``ValueError``, since the material would then
    claim it was not there, and so does one held under any name but its own, whose bytes no reload
    would serve under that name."""
    held = snapshot.value_file
    if held is None:
        return None
    if any(is_value_file_entry(rel) for rel in snapshot.unreadable):
        raise ValueError("the config snapshot could not read the environment value file")
    rel = value_file_rel(held.name)
    if any(is_value_file_entry(other) and other != rel for other in snapshot.files):
        raise ValueError("the config snapshot holds a value file under another name")
    data = snapshot.files.get(rel)
    material = _VALUE_FILE_SCHEME + held.name.encode("utf-8", "surrogatepass") + b"\0"
    return material + (b"\0" if data is None else b"\1" + data)


def config_fingerprint(directory: str | Path, *, strict: bool = False) -> str:
    """Return a stable SHA-256 hex digest over the content of a config bundle's loaded files.

    By default it is observational, as the module docstring says: a file it cannot read is left out,
    and a missing directory digests as an empty bundle. ``strict`` is for a digest that GATES, the
    one a dual-control approval binds (vault BACKLOG #2596). There a skipped file would leave bytes
    the approval never covered, so ``strict`` raises instead.
    :func:`~messagefoundry.config.snapshot.read_config_snapshot` says at which faults, and which
    gone directory it does not refuse."""
    return snapshot_fingerprint(read_config_snapshot(directory, strict=strict))


def config_fingerprint_detail(
    directory: str | Path, *, snapshot: ConfigSnapshot | None = None
) -> dict[str, object]:
    """Return the fingerprint plus the file count and a best-effort git HEAD, for an audit detail.

    ``git_head`` is included only when ``directory`` resolves inside a git work tree whose commit can
    be read purely from files; it is advisory provenance, not the integrity anchor (the content
    ``fingerprint`` is). Keys: ``fingerprint`` (str), ``scheme`` (str, :data:`FINGERPRINT_SCHEME`),
    ``files`` (int), and optionally ``git_head``.

    With ``snapshot``, the digest is of that snapshot, the bytes a load read and ran, and the
    directory is read for the git HEAD alone (vault BACKLOG #2596). Without it, the directory is
    read now.

    It stays best-effort: a file it cannot read is left out of the digest. But it says so, under
    :data:`UNREADABLE_FILES_KEY` (the files and folders left out), present only when one was. Two
    digests describe the same files only when they left out the same ones: a file held by an
    antivirus lock at one start and not at the next gives two digests for the same bytes. A reader
    that compares digests uses :func:`digest_coverage` (vault BACKLOG #2944). The strict digest a
    dual-control approval binds is :func:`config_fingerprint` with ``strict``, which raises instead.
    """
    base = Path(directory)
    if snapshot is None:
        snapshot = read_config_snapshot(base, strict=False)
    entries = _entries(snapshot)
    detail: dict[str, object] = {
        "fingerprint": _fold(entries),
        "scheme": FINGERPRINT_SCHEME,
        "files": len(entries),
    }
    left_out = [rel for rel in snapshot.unreadable if not is_value_file_entry(rel)]
    if left_out:
        detail[UNREADABLE_FILES_KEY] = left_out
    head = _git_head(base)
    if head is not None:
        detail["git_head"] = head
    return detail


class DigestCoverage(NamedTuple):
    """A digest's fold, with the files and folders it left out (:data:`UNREADABLE_FILES_KEY`)."""

    fold: str
    left_out: tuple[str, ...]


def digest_coverage(detail: Mapping[str, object] | None) -> DigestCoverage | None:
    """The ``fingerprint`` of a :func:`config_fingerprint_detail` with what it left out, or ``None``
    when it has no fingerprint (vault BACKLOG #2944).

    Two digests are comparable only when their second elements are equal: then they cover the same
    files, and differ only when one of those files did. An ``unreadable_files`` value that is not a
    list of strings reads as ``("?",)``, which equals no list a digest records. :func:`same_digest`
    compares two of these."""
    if detail is None:
        return None
    fingerprint = detail.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    left_out = detail.get(UNREADABLE_FILES_KEY)
    if left_out is None:
        return DigestCoverage(fingerprint, ())
    if isinstance(left_out, list) and all(isinstance(rel, str) for rel in left_out):
        return DigestCoverage(fingerprint, tuple(left_out))
    return DigestCoverage(fingerprint, ("?",))


def same_digest(one: DigestCoverage, other: DigestCoverage) -> bool:
    """Whether two :func:`digest_coverage` results name the same bytes of the same files. The fold
    does not hash what a digest left out, so a partial digest can fold to a whole one's value over
    other files: the lists are compared too (vault BACKLOG #3765)."""
    return one.left_out == other.left_out and fingerprint_matches(one.fold, other.fold)


def left_out_of(*digests: DigestCoverage | None) -> list[str]:
    """Sorted, what any of ``digests`` left out: what a comparison of them says nothing about. A
    digest that was not taken is skipped."""
    return sorted({rel for digest in digests if digest is not None for rel in digest.left_out})


def describe_left_out(left_out: Iterable[str]) -> str:
    """``left_out`` for a log line, with ``.`` in words. Paths only, never content; a caller still
    scrubs it, since a file name is whatever the directory holds."""
    return ", ".join("the config directory" if rel == "." else rel for rel in left_out)


#: The keys of a digest another node can compare its own with: the fold, the scheme it was taken
#: under, and what it left out (:func:`same_digest` and the scheme check). ``files`` and ``git_head``
#: are left out, as describing the initiator's checkout rather than the bytes (vault BACKLOG #3109).
_SHARED_DIGEST_KEYS: frozenset[str] = frozenset({"fingerprint", "scheme", UNREADABLE_FILES_KEY})


#: The longest text a bump stores or a follower reads back (vault BACKLOG #3109). Another node wrote
#: it, and each follower parses it on the event loop and copies it into its audit row, so a larger
#: value reads as no digest. The writer applies the same bound, so it never stores what the reader
#: refuses; a digest that leaves out enough files to pass it is stored as unknown.
_SHARED_DIGEST_MAX_CHARS = 65_536

#: A fold as :func:`_fold` writes it: a SHA-256 in lower-case hex.
_FOLD_CHARS = frozenset("0123456789abcdef")


def shared_digest_text(detail: Mapping[str, object] | None) -> str | None:
    """The text a cluster config-version bump stores beside the version it writes: the JSON of the
    initiating node's digest, cut to :data:`_SHARED_DIGEST_KEYS` (vault BACKLOG #3109). ``None``
    when ``detail`` holds no digest :func:`shared_digest_of` would read back; the bump then stores
    the digest as unknown."""
    if detail is None:
        return None
    shared = {key: value for key, value in detail.items() if key in _SHARED_DIGEST_KEYS}
    if not _is_comparable_digest(shared):
        return None
    text = json.dumps(shared, sort_keys=True, separators=(",", ":"))
    return text if len(text) <= _SHARED_DIGEST_MAX_CHARS else None


def _is_comparable_digest(detail: Mapping[str, object]) -> bool:
    """Whether ``detail`` is a digest another node can compare with, in the shape
    :func:`config_fingerprint_detail` writes one: a 64-character lower-case hex fold, a non-empty
    scheme, and an ``unreadable_files`` that is absent or a non-empty list of strings. The writer
    and the reader apply this one rule, so the writer never stores what the reader refuses."""
    fold = detail.get("fingerprint")
    scheme = detail.get("scheme")
    if not (isinstance(fold, str) and len(fold) == 64 and set(fold) <= _FOLD_CHARS):
        return False
    if not (isinstance(scheme, str) and scheme):
        return False
    if UNREADABLE_FILES_KEY not in detail:
        return True
    left_out = detail[UNREADABLE_FILES_KEY]
    return (
        isinstance(left_out, list) and bool(left_out) and all(isinstance(r, str) for r in left_out)
    )


def shared_digest_of(text: object) -> dict[str, object] | None:
    """The digest :func:`shared_digest_text` wrote, or ``None`` when ``text`` is not one: not a
    string, longer than :data:`_SHARED_DIGEST_MAX_CHARS`, not JSON, a repeated key, not an object,
    a key outside :data:`_SHARED_DIGEST_KEYS`, or a value :func:`_is_comparable_digest` refuses.
    Another node wrote it, so it is read as data and checked rather than trusted."""
    if not isinstance(text, str) or len(text) > _SHARED_DIGEST_MAX_CHARS:
        return None
    value, refusal = json_loads_or_refusal(text, object_pairs_hook=refuse_repeated_keys)
    if refusal is not None or not isinstance(value, dict) or not set(value) <= _SHARED_DIGEST_KEYS:
        return None
    return value if _is_comparable_digest(value) else None


def fingerprint_matches(current: object, loaded: str) -> bool:
    """Whether a recomputed fingerprint equals the loaded one, compared in constant time.

    ASVS 11.2.4 (BACKLOG #1167): never ``==``, which stops at the first differing character. Both
    digests are public, so this closes a bare compare rather than a leak. Total: a ``current`` that
    is not a string (a missing key) never matches.
    """
    return isinstance(current, str) and constant_time_equal(current, loaded)


#: A git object id as git writes one: SHA-1 (40) or SHA-256 (64) lower-case hex. ``git_head`` is
#: recorded only in this shape, so the audit field never carries other text a crafted ref file holds
#: (vault BACKLOG #5325).
_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")

#: Characters git's ``check-ref-format`` refuses in a ref name. Two of them matter to the read as
#: well as to git: a backslash is a separator on Windows, and a colon names an NTFS alternate data
#: stream (``refs/heads/main:x``).
_REF_FORBIDDEN = frozenset(" ~^:?*[\\\x7f")

#: The refs a linked worktree keeps in its own gitdir; every other ref lives in the commondir, and
#: git reads it only there (git's ``is_per_worktree_ref``).
_PER_WORKTREE_REFS = ("refs/bisect/", "refs/rewritten/", "refs/worktree/")

#: The longest HEAD, loose ref, ``.git`` pointer or ``commondir`` read: each holds one line, an
#: object id or a path. A longer file is not one git wrote, and reads as unknown rather than load.
_GIT_FILE_LIMIT = 4096

#: The longest ``packed-refs`` read. It lists every packed ref, so it can be large in a big
#: repository, but not without bound.
_PACKED_REFS_LIMIT = 64 * 1024 * 1024


def _object_id(text: str) -> str | None:
    """``text`` stripped, if it is a git object id (:data:`_OBJECT_ID`), else ``None``."""
    text = text.strip()
    return text if _OBJECT_ID.fullmatch(text) else None


#: The HEAD every reftable repository writes, which no file under ``refs/`` resolves: its refs are
#: in a binary table this reader does not parse.
_REFTABLE_STUB = "refs/heads/.invalid"


def _confined_ref(ref: str) -> bool:
    """Whether a symbolic ref names, lexically, a path under ``refs/`` of the root it is joined
    onto: relative, ``refs/`` first, no ``..``, no empty, dot-led or ``.lock`` part, not ending in a
    dot, none of the characters git refuses in a ref name, and, on Windows, no part Windows reserves
    (a device such as ``CON`` or ``COM1``, or a trailing dot or space, which Windows strips;
    :func:`ntpath.isreserved`) (vault BACKLOG #5325). The ref is joined onto the git dir or the
    commondir, so ``ref: ../../x`` or an absolute path would otherwise read a file outside it, and
    a device name would open the device. That root is where the checkout's ``.git`` and
    ``commondir`` point, which is the operator's layout and is not confined, and a link under
    ``refs/`` is followed; what keeps file text out of ``git_head`` is :func:`_object_id`."""
    parts = ref.split("/")
    if len(parts) < 2 or parts[0] != "refs" or ".." in ref or ref.endswith("."):
        return False
    if any(ch in _REF_FORBIDDEN or ord(ch) < 0x20 for ch in ref):
        return False
    return all(
        part
        and not part.startswith(".")
        and not part.endswith(".lock")
        and not (os.name == "nt" and ntpath.isreserved(part))
        for part in parts
    )


def _read_capped(path: Path, limit: int) -> bytes | None:
    """The bytes of the git metadata file ``path``, or ``None`` when it is not a regular file or is
    longer than ``limit``. Read by :func:`~messagefoundry.auth.trust_anchors.read_if_regular`, so a
    pipe in place, even one swapped in after the stat, is never waited on, and a small file is read
    without a ``limit``-sized buffer. Raises its ``OSError`` or ``ValueError``."""
    # Lazy: trust_anchors is heavy, and it imports from config.
    from messagefoundry.auth.trust_anchors import read_if_regular

    data = read_if_regular(str(path), limit + 1)
    if data is None:
        _log.debug("git metadata path is not a regular file; git_head left out")
        return None
    if len(data) > limit:
        _log.debug("git metadata file is longer than %d bytes; git_head left out", limit)
        return None
    return data


def _read_git_bytes(path: Path, limit: int = _GIT_FILE_LIMIT) -> bytes | None:
    """:func:`_read_capped`, with ``None`` also for a file it cannot read. ``ValueError`` covers a
    path holding a NUL. Each reads as unknown provenance (vault BACKLOG #5325)."""
    try:
        return _read_capped(path, limit)
    except (OSError, ValueError) as exc:
        _log.debug("git metadata file not read (%s); git_head left out", type(exc).__name__)
        return None


def _read_git_text(path: Path) -> str | None:
    """:func:`_read_git_bytes` as UTF-8 text, stripped, or ``None`` when that is ``None`` or the
    bytes are not UTF-8."""
    data = _read_git_bytes(path)
    if data is None:
        return None
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        _log.debug("git metadata file is not UTF-8; git_head left out")
        return None


def _git_head(start: Path) -> str | None:
    """Best-effort current commit of the git work tree containing ``start`` — no subprocess.

    Returns the commit's object id (40 hex, or 64 in a SHA-256 repository), or ``None`` when
    ``start`` is not in a work tree or the ref can't be resolved purely from on-disk files (e.g. an
    exotic ref layout). Handles a detached HEAD, a symbolic ``ref:`` HEAD (resolved against loose
    refs then ``packed-refs``), and a linked worktree (``.git`` is a file pointing at a ``gitdir``,
    whose shared refs live in the ``commondir``).

    It returns only a value in the shape of an object id, and only one git would report: a file it
    cannot read or decode, a symbolic ref outside ``refs/`` (:func:`_confined_ref`), a loose ref
    that is there but cannot be read or holds no object id, or a value that is not an object id
    each read as ``None`` (vault BACKLOG #5325).
    """
    try:
        base = start.resolve()
    except (OSError, ValueError):
        return None
    git_dir: Path | None = None
    for parent in (base, *base.parents):
        candidate = parent / ".git"
        if candidate.is_dir():
            git_dir = candidate
            break
        if candidate.is_file():
            line = _read_git_text(candidate)
            if line is None:
                return None
            if line.startswith("gitdir:"):
                try:
                    pointed = (parent / line[len("gitdir:") :].strip()).resolve()
                except (OSError, ValueError):
                    return None
                git_dir = pointed if pointed.exists() else None
            break
    if git_dir is None:
        return None

    # A linked worktree's commondir holds its shared refs; git reads them there and nowhere else.
    common_root = git_dir
    common_file = git_dir / "commondir"
    if os.path.lexists(common_file):
        common_text = _read_git_text(common_file)
        if common_text is None:
            return None
        try:
            common_root = (git_dir / common_text).resolve()
        except (OSError, ValueError):
            return None

    head = _read_git_text(git_dir / "HEAD")
    if head is None:
        return None
    if not head.startswith("ref:"):
        return _object_id(head)  # detached HEAD: the commit id directly
    ref = head[len("ref:") :].strip()
    if ref == _REFTABLE_STUB:
        _log.debug("reftable repository; git_head left out")
        return None
    if not _confined_ref(ref):
        _log.warning("git HEAD names a symbolic ref this reader refuses; git_head left out")
        return None
    root = git_dir if ref.startswith(_PER_WORKTREE_REFS) else common_root
    loose = root / ref
    absent = False
    try:
        data = _read_capped(loose, _GIT_FILE_LIMIT)
    except (FileNotFoundError, NotADirectoryError):
        data, absent = (
            None,
            True,
        )  # no loose ref, or packed and removed since: git reads packed-refs
    except (OSError, ValueError) as exc:
        _log.debug("loose ref not read (%s); git_head left out", type(exc).__name__)
        return None
    if data is None and (absent or loose.is_dir()):
        return _scan_packed_refs(root / "packed-refs", ref)
    # A loose ref that is there but is not a regular file, or holds no object id (another symbolic
    # ref, a crafted file), reads as unknown: packed-refs could report a value git would not.
    return None if data is None else _object_id(data.decode("ascii", "replace"))


def _scan_packed_refs(packed: Path, ref: str) -> str | None:
    """The object id ``packed`` records for ``ref``, or ``None`` when it records none, cannot be
    read, or records one that is not an object id (vault BACKLOG #5325). Lines are matched as
    bytes, so a ref name elsewhere in the file that is not UTF-8 does not hide this one."""
    data = _read_git_bytes(packed, _PACKED_REFS_LIMIT)
    if data is None:
        return None
    want = ref.encode("utf-8")
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line.startswith((b"#", b"^")):
            continue
        sha, _, name = line.partition(b" ")
        if name == want:
            return _object_id(sha.decode("ascii", "replace"))
    return None
