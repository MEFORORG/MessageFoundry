# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from pathlib import Path

__all__ = ["config_fingerprint", "config_fingerprint_detail"]

# Version the scheme so a future change to *what* is hashed (or *how*) is itself detectable in the
# trail — a fingerprint produced by v1 can never collide with one produced by a later revision.
_SCHEME = b"mefor-cfg-fp:v1\n"

# Every file ``load_config`` consumes that defines the running graph's behaviour, transport config,
# or reference data. Globs are relative to the config dir. NB: ``*.py`` deliberately covers
# ``_``-prefixed helpers — the loader skips them as *top-level modules*, but a sibling can import
# them, so they are just as much "what runs" (the same candidate set ADR 0036's guard scans).
_FINGERPRINT_GLOBS: tuple[str, ...] = (
    "*.py",
    "connections.toml",
    "codesets/*.csv",
    "codesets/*.toml",
    "environments/*.toml",
)


def _iter_entries(base: Path) -> list[tuple[str, bytes]]:
    """Return ``(posix-relpath, sha256(content))`` for every fingerprinted file, sorted.

    Sorting by relpath makes the fold order-independent (filesystem enumeration order can vary);
    keying on the *relative* path (not absolute) makes the digest location-independent, so two
    byte-identical bundles at different paths fingerprint identically. An unreadable file is
    skipped rather than crashing the audit it feeds.
    """
    seen: set[Path] = set()
    entries: list[tuple[str, bytes]] = []
    for pattern in _FINGERPRINT_GLOBS:
        for path in base.glob(pattern):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                data = path.read_bytes()
            except OSError:
                continue
            rel = path.relative_to(base).as_posix()
            entries.append((rel, hashlib.sha256(data).digest()))
    entries.sort()
    return entries


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


def config_fingerprint(directory: str | Path) -> str:
    """Return a stable SHA-256 hex digest over the content of a config bundle's loaded files."""
    return _fold(_iter_entries(Path(directory)))


def config_fingerprint_detail(directory: str | Path) -> dict[str, object]:
    """Return the fingerprint plus the file count and a best-effort git HEAD, for an audit detail.

    ``git_head`` is included only when ``directory`` resolves inside a git work tree whose commit can
    be read purely from files; it is advisory provenance, not the integrity anchor (the content
    ``fingerprint`` is). Keys: ``fingerprint`` (str), ``files`` (int), and optionally ``git_head``.
    """
    base = Path(directory)
    entries = _iter_entries(base)
    detail: dict[str, object] = {"fingerprint": _fold(entries), "files": len(entries)}
    head = _git_head(base)
    if head is not None:
        detail["git_head"] = head
    return detail


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
