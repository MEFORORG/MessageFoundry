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

This is **observational**: a fingerprint records, it does not gate — it never drops a message or
changes a disposition. It complements (does not replace) ADR 0036's load-time write-access refusal,
which stops an *unauthorized* principal from writing the config dir; the fingerprint attributes an
*authorized* change to a reviewed source.

Pure + offline: it hashes file *bytes* only — it never imports a config module, runs a subprocess, or
touches the network. The git-HEAD read is best-effort provenance (advisory), and the **content**
digest is the integrity anchor. Run it off the event loop (``asyncio.to_thread``) at the call site,
exactly like ``load_config`` itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from messagefoundry.config.snapshot import (
    ConfigDirMissing,
    ConfigSnapshot,
    is_missing_directory,
    read_config_snapshot,
)
from messagefoundry.credential import constant_time_equal

__all__ = [
    "FINGERPRINT_SCHEME",
    "UNREADABLE_FILES_KEY",
    "ConfigDirMissing",
    "config_fingerprint",
    "config_fingerprint_detail",
    "fingerprint_matches",
    "digest_coverage",
    "is_missing_directory",
    "same_digest",
    "snapshot_fingerprint",
]

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
#: the covered files, and of the folders a glob reads, that could not be read and were left out
#: (vault BACKLOG #2944). Absent when the digest covers the whole bundle. Paths, not a count, so two
#: partial digests can be compared like for like, and an operator can tell which file to fix. The
#: entry ``.`` is the config directory itself, which could not be listed. Not ``degraded``: an audit
#: row merges this detail into its own, and there ``degraded`` already names failed reload steps.
UNREADABLE_FILES_KEY = "unreadable_files"

# What is hashed is what :func:`~messagefoundry.config.snapshot.read_config_snapshot` reads: every
# config module (``config.snapshot.config_py_files``, the one rule the loader and ADR 0036's guard
# also use, ``_``-prefixed helpers included and a dot-named ``.IB_OLD.py`` or AppleDouble ``._X.py``
# skipped), ``connections.toml``, each ``codesets/`` table, and each ``environments/*.toml`` under
# the config directory. The last is never loaded as config. The value file a serve start reads sits
# under ``[environments].base_dir``; where that is this folder, a reload parses the very bytes
# hashed here (``ConfigSnapshot.environment_file``), so dropping them from the fold would let a
# released reload apply values its digest does not cover. ``__pycache__`` is never read:
# the loader compiles the source itself.


def _entries(snapshot: ConfigSnapshot) -> list[tuple[str, bytes]]:
    """``(posix-relpath, sha256(content))`` for every file in ``snapshot``, sorted.

    Sorting by relpath makes the fold order-independent (filesystem enumeration order can vary);
    keying on the *relative* path (not absolute) makes the digest location-independent, so two
    byte-identical bundles at different paths fingerprint identically."""
    return sorted((rel, hashlib.sha256(data).digest()) for rel, data in snapshot.files.items())


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


def snapshot_fingerprint(snapshot: ConfigSnapshot) -> str:
    """The content digest of ``snapshot``: the bytes one load read, and so the bytes it ran.

    A digest that gates a load, such as the one a dual-control release checks, is taken from the
    snapshot that load then runs, so nothing can change between the check and the run (vault
    BACKLOG #2596). Its files left out as unreadable, if any, are not covered: a caller that gates
    on it checks :attr:`~messagefoundry.config.snapshot.ConfigSnapshot.unreadable` first, or reads
    the snapshot strictly."""
    return _fold(_entries(snapshot))


def config_fingerprint(directory: str | Path, *, strict: bool = False) -> str:
    """Return a stable SHA-256 hex digest over the content of a config bundle's loaded files.

    By default it is observational, as the module docstring says: a file it cannot read is left out,
    and a missing directory digests as an empty bundle. ``strict`` is for a digest that GATES, the
    one a dual-control approval binds (vault BACKLOG #2596). There a skipped file would leave bytes
    the approval never covered, so ``strict`` raises instead: :class:`ConfigDirMissing` when
    ``directory`` is not a directory, and the ``OSError`` when a folder it reads cannot be listed or
    a file it covers cannot be stat'ed or read."""
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
    if snapshot.unreadable:
        detail[UNREADABLE_FILES_KEY] = list(snapshot.unreadable)
    head = _git_head(base)
    if head is not None:
        detail["git_head"] = head
    return detail


def digest_coverage(detail: Mapping[str, object] | None) -> tuple[str, tuple[str, ...]] | None:
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
        return fingerprint, ()
    if isinstance(left_out, list) and all(isinstance(rel, str) for rel in left_out):
        return fingerprint, tuple(left_out)
    return fingerprint, ("?",)


def same_digest(one: tuple[str, tuple[str, ...]], other: tuple[str, tuple[str, ...]]) -> bool:
    """Whether two :func:`digest_coverage` results name the same bytes of the same files. The fold
    does not hash what a digest left out, so a partial digest can fold to a whole one's value over
    other files: the lists are compared too (vault BACKLOG #3765). Every reader that asks whether
    two digests differ asks here, so a left-out file reads as different everywhere."""
    return one[1] == other[1] and fingerprint_matches(one[0], other[0])


def fingerprint_matches(current: object, loaded: str) -> bool:
    """Whether a recomputed fingerprint equals the loaded one, compared in constant time.

    ASVS 11.2.4 (BACKLOG #1167): never ``==``, which stops at the first differing character. Both
    digests are public, so this closes a bare compare rather than a leak. Total: a ``current`` that
    is not a string (a missing key) never matches.
    """
    return isinstance(current, str) and constant_time_equal(current, loaded)


def _git_head(start: Path) -> str | None:
    """Best-effort current commit of the git work tree containing ``start`` — no subprocess.

    Returns the 40-hex commit, or ``None`` when ``start`` is not in a work tree or the ref can't be
    resolved purely from on-disk files (e.g. an exotic ref layout). Handles a detached HEAD, a
    symbolic ``ref:`` HEAD (resolved against loose refs then ``packed-refs``), and a linked worktree
    (``.git`` is a file pointing at a ``gitdir``, whose refs live in the ``commondir``).
    """
    try:
        base = start.resolve()
    except OSError:
        return None
    git_dir: Path | None = None
    for parent in (base, *base.parents):
        candidate = parent / ".git"
        if candidate.is_dir():
            git_dir = candidate
            break
        if candidate.is_file():
            try:
                line = candidate.read_text(encoding="utf-8").strip()
            except OSError:
                return None
            if line.startswith("gitdir:"):
                pointed = (parent / line[len("gitdir:") :].strip()).resolve()
                git_dir = pointed if pointed.exists() else None
            break
    if git_dir is None:
        return None

    # Refs may live in this gitdir or, for a linked worktree, in the shared commondir.
    roots = [git_dir]
    common_file = git_dir / "commondir"
    if common_file.is_file():
        try:
            common = (git_dir / common_file.read_text(encoding="utf-8").strip()).resolve()
            if common != git_dir:
                roots.append(common)
        except OSError:
            pass

    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not head.startswith("ref:"):
        return head or None  # detached HEAD: the commit sha directly
    ref = head[len("ref:") :].strip()
    for root in roots:
        loose = root / ref
        try:
            sha = loose.read_text(encoding="utf-8").strip()
            if sha:
                return sha
        except OSError:
            pass
    for root in roots:
        packed = _scan_packed_refs(root / "packed-refs", ref)
        if packed is not None:
            return packed
    return None


def _scan_packed_refs(packed: Path, ref: str) -> str | None:
    try:
        lines = packed.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", "^")):
            continue
        sha, _, name = line.partition(" ")
        if name == ref:
            return sha or None
    return None
