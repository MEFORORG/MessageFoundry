# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The CRL copies that live TLS contexts hold, so the expiry monitor judges those and not only the file
(BACKLOG #299).

**Why this exists.** A hop reads its CRL file once, when it builds its TLS context, and most hops keep
that context for every handshake until a restart or a config reload. The expiry monitor
(:mod:`messagefoundry.pipeline.cert_expiry`) read only the file on each pass. So an operator who
replaced an expiring CRL would have seen the ``crl_expiry`` alert clear while the running hop still held
the old copy, which would go on to lapse and refuse every peer. The monitor and the hop disagreed.

:func:`~messagefoundry.config.tls_policy.harden_crl_check` loads the CRL settings into a context, and
it records each load here. That covers at least every CRL *setting* found on 2026-09-28. It does not
cover a CRL block placed inside a CA bundle, which ``load_verify_locations`` loads with the CA and
nothing here records. The monitor takes one :func:`snapshot` per pass, asks it for the copies live
contexts still hold, and judges the soonest of those and the file. A held copy of a file no monitor
row names, such as an inbound ``tls_crl_file`` given as a deferred ``env()`` value, gets its own row.
So the alert stays up until every context holding the old copy is gone or has been brought current.

**A held copy can be brought current without a restart.** :mod:`messagefoundry.pipeline.crl_reload`
adds a replaced file to each context that holds an older copy, then calls :func:`replace_held_copy`,
so the record describes what the context now checks against. It refuses a replacement it cannot
apply exactly, and records why with :func:`record_reload_refusal`, so the monitor can say why the copy
is still old.

**The registry holds each context WEAKLY.** An entry lasts exactly as long as the context it describes.
A throwaway context (a ``check`` dry run, a ``verify`` probe, a test) drops out when it is collected,
and a hop rebuilt by a config reload drops its old entry when the old context goes. A context kept
alive by something that will never handshake with it again would keep its entry and raise a spurious
alert. That errs the safe way: a false "restart needed" over a false all-clear.

**A hop that rebuilds its context for every connection does not record.** The Postgres store builds a
fresh context per pool connection (BACKLOG #300), so its next handshake reads the file as it is then,
and the file is the truth for that hop. Recording those contexts would also be wrong, because an open
pool connection keeps its context alive long after its one handshake. Such a caller passes
``record_held_copy=False`` to ``harden_crl_check``.

**The key is the configured path, not the resolved file.** A common rotation replaces a symlink's
target. Resolving the link at load and again at the monitor pass would give two different keys, so
the monitor would find no held copy and clear the alert, which is the defect this module closes. The
key is the absolute, case-normalized path as configured, with no link resolution.

**The fingerprint is change detection inside one process, not an integrity check.** It is the
length and the builtin ``hash()`` of the file's bytes. Both sides of every comparison run in the
same process, so the per-process salt that makes ``hash()`` useless across processes does not
matter here. Nothing is authenticated by it: whoever can write the CRL file already decides what is
revoked, so a crafted collision would buy them nothing they do not have.

Engine-side, stdlib only. It stores public CRL metadata (issuer, ``nextUpdate``, a fingerprint of the
file), never key material and never message content.
"""

from __future__ import annotations

import os
import ssl
import threading
import weakref
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from messagefoundry.pki import CrlBlock, CrlFacts

__all__ = [
    "HeldCrl",
    "HeldCrlSnapshot",
    "ReloadRefusal",
    "clear_reload_refusal",
    "crl_fingerprint",
    "has_held_copies",
    "held_contexts",
    "held_crl_copies",
    "prune_reload_refusals",
    "record_crl_load",
    "record_reload_refusal",
    "reload_refusal",
    "replace_held_copy",
    "snapshot",
]


@dataclass(frozen=True)
class HeldCrl:
    """One CRL file load that a live context still holds.

    ``fingerprint`` is :func:`crl_fingerprint` of the bytes the load judged, so the monitor can tell
    a held copy from a replaced file. ``facts`` are those of the soonest-expiring CRL block in that
    load, the rule :func:`~messagefoundry.pki.soonest_crl` applies to the file; call
    :meth:`~messagefoundry.pki.CrlFacts.at` for the days left now. ``setting`` names the knob the
    hop loaded it from, such as ``[tls].crl_file``, or is ``None`` where the caller named none (an
    inbound connection's ``tls_crl_file``)."""

    path_key: str
    fingerprint: tuple[int, int]
    facts: CrlFacts
    #: The absolute path as configured, case kept, which the reload reads. ``path_key`` is
    #: case-folded on Windows, so it may not open the file on a case-sensitive folder.
    file_path: str
    setting: str | None = None
    #: Every CRL block of that load. A reload needs them to prove the replacement supersedes each
    #: one; empty means unknown, and a reload then refuses rather than guess.
    blocks: tuple[CrlBlock, ...] = ()
    #: The path as the operator configured it, for messages; ``path_key`` is the comparison form.
    configured_path: str | None = None
    #: How many reloads this context has taken for this file. Each one stays in its trust store.
    reloads: int = 0


@dataclass(frozen=True)
class ReloadRefusal:
    """Why the file now at a held path was not applied to a running context (BACKLOG #299).

    ``fingerprint`` is the refused file's :func:`crl_fingerprint`, so a refusal stops applying the
    moment the file changes again. ``remedy`` is what the operator does next, in the words both the
    reload and the expiry monitor log. ``sticky`` is True when nothing but a change to the file can
    alter the verdict, so the reload does not judge those bytes again; False for a refusal time can
    lift, such as a CRL not yet in effect."""

    fingerprint: tuple[int, int]
    reason: str
    remedy: str
    sticky: bool = True


# Keyed by context, held weakly: an entry lives exactly as long as its context. A context may load
# more than one CRL file in principle, so each value is a tuple; overwriting would drop a copy and
# read as an all-clear. The lock covers a load on one thread (the store and SMTP builders run off the
# event loop) racing a monitor read on another; the copy below is taken under it, so the monitor
# never iterates the live mapping.
_HELD: weakref.WeakKeyDictionary[ssl.SSLContext, tuple[HeldCrl, ...]] = weakref.WeakKeyDictionary()
# The latest refusal per path key. Keys are configured CRL paths, so this stays small.
_REFUSED: dict[str, ReloadRefusal] = {}
_LOCK = threading.Lock()


def _path_key(path: str | os.PathLike[str]) -> str:
    """Absolute and case-normalized, links NOT resolved; the module docstring says why."""
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def crl_fingerprint(pem: bytes) -> tuple[int, int]:
    """A cheap in-process identity for a CRL file's bytes; the module docstring says why it suffices."""
    return (len(pem), hash(pem))


def record_crl_load(
    ctx: ssl.SSLContext,
    crl_file: str,
    pem: bytes,
    facts: CrlFacts,
    *,
    setting: str | None = None,
    blocks: tuple[CrlBlock, ...] = (),
) -> None:
    """Record that ``ctx`` now holds the CRL file ``crl_file``, whose judged bytes were ``pem``,
    whose soonest-expiring block is ``facts`` and whose blocks are ``blocks``. Called by
    ``harden_crl_check`` after a load succeeds."""
    held = HeldCrl(
        path_key=_path_key(crl_file),
        fingerprint=crl_fingerprint(pem),
        facts=facts,
        file_path=os.path.abspath(crl_file),
        setting=setting,
        blocks=blocks,
        configured_path=crl_file,
    )
    with _LOCK:
        loads = _HELD.get(ctx, ())
        again = next((load for load in loads if load.path_key == held.path_key), None)
        if again is None:
            _HELD[ctx] = (*loads, held)
        else:
            # The same file loaded into one context twice, such as two settings naming it. One
            # record per file per context, or a reload would load it twice and count two hops.
            _HELD[ctx] = tuple(_merged(again, held) if load is again else load for load in loads)


def _merged(old: HeldCrl, new: HeldCrl) -> HeldCrl:
    """One record for a context that loaded one file twice: it holds the CRLs of both loads.

    The file as last read is ``new``'s, so its fingerprint stands. The soonest lapse of the two
    counts, as across the blocks of one file. The blocks are both loads', since a reload must
    supersede every CRL the context holds; if either load's are unknown, so are the union's."""
    from messagefoundry.pki import soonest_crl

    known = old.blocks and new.blocks
    blocks = (*old.blocks, *(b for b in new.blocks if b not in old.blocks)) if known else ()
    return HeldCrl(
        path_key=new.path_key,
        fingerprint=new.fingerprint,
        facts=soonest_crl([old.facts, new.facts]),
        file_path=new.file_path,
        setting=old.setting or new.setting,
        blocks=blocks,
        configured_path=old.configured_path or new.configured_path,
        reloads=old.reloads,
    )


def _copy() -> tuple[list[tuple[ssl.SSLContext, tuple[HeldCrl, ...]]], dict[str, ReloadRefusal]]:
    """A copy of the registry and the refusals, taken under one hold of the lock.

    A context collected while the copy is taken can make ``WeakKeyDictionary`` raise
    ``RuntimeError``, since its removal callback does not take this lock. The copy is retried rather
    than letting one pass fall back to the file alone, which is the gap this module closes."""
    attempts = 4
    for attempt in range(attempts):
        try:
            with _LOCK:
                return list(_HELD.items()), dict(_REFUSED)
        except RuntimeError:
            if attempt == attempts - 1:
                raise
    raise AssertionError("unreachable")


def has_held_copies() -> bool:
    """Whether any context, live or awaiting collection, has recorded a CRL load."""
    with _LOCK:
        return bool(_HELD)


def held_contexts() -> list[tuple[ssl.SSLContext, HeldCrl]]:
    """Every live context and each CRL load it holds, one pair per load.

    The pairs hold the contexts STRONGLY, so a caller keeps the list for one pass only."""
    return [(ctx, held) for ctx, loads in _copy()[0] for held in loads]


def replace_held_copy(ctx: ssl.SSLContext, old: HeldCrl, new: HeldCrl) -> bool:
    """Record that ``ctx`` now checks against ``new`` where it held ``old``. Returns False, changing
    nothing, when ``ctx`` no longer holds ``old``."""
    with _LOCK:
        loads = _HELD.get(ctx)
        if loads is None or not any(load is old for load in loads):
            return False
        _HELD[ctx] = tuple(new if load is old else load for load in loads)
        return True


def record_reload_refusal(path: str | os.PathLike[str], refusal: ReloadRefusal) -> None:
    """Record why the file now at ``path`` was not applied to a running context."""
    with _LOCK:
        _REFUSED[_path_key(path)] = refusal


def reload_refusal(
    path: str | os.PathLike[str], fingerprint: tuple[int, int]
) -> ReloadRefusal | None:
    """The refusal recorded for the file at ``path`` whose bytes have ``fingerprint``, if any."""
    with _LOCK:
        refusal = _REFUSED.get(_path_key(path))
    return _matching(refusal, fingerprint)


def _matching(refusal: ReloadRefusal | None, fingerprint: tuple[int, int]) -> ReloadRefusal | None:
    """``refusal`` when it was made about the bytes with ``fingerprint``, else ``None``."""
    return refusal if refusal is not None and refusal.fingerprint == fingerprint else None


def clear_reload_refusal(path: str | os.PathLike[str]) -> None:
    """Forget any refusal for ``path``, because every context holding it is now current."""
    with _LOCK:
        _REFUSED.pop(_path_key(path), None)


def prune_reload_refusals(held: Iterable[str]) -> None:
    """Forget the refusals for every path key not in ``held``: no context holds that file now."""
    keep = set(held)
    with _LOCK:
        for gone in [key for key in _REFUSED if key not in keep]:
            del _REFUSED[gone]


class HeldCrlSnapshot:
    """Every held copy at one instant, indexed by path key, for one monitor pass.

    One snapshot per pass keeps the pass linear in the number of held copies. A lookup per row
    against the live registry would take the lock and copy every entry once per row."""

    def __init__(
        self, copies: Iterable[HeldCrl], refusals: dict[str, ReloadRefusal] | None = None
    ) -> None:
        self._by_path: dict[str, list[HeldCrl]] = {}
        for held in copies:
            self._by_path.setdefault(held.path_key, []).append(held)
        self._refusals = dict(refusals or {})

    def copies(self, path: str | os.PathLike[str]) -> list[HeldCrl]:
        """Every copy of the CRL file at ``path`` held at the snapshot, one per load.

        Two settings that name one file share its copies, because the key is the file: a stale copy
        held by either hop is a stale copy of that file."""
        return list(self._by_path.get(_path_key(path), ()))

    def refusal(
        self, path: str | os.PathLike[str], fingerprint: tuple[int, int]
    ) -> ReloadRefusal | None:
        """Why the file at ``path``, whose bytes have ``fingerprint``, was not applied to a running
        context, or ``None`` when no reload refused those bytes."""
        return _matching(self._refusals.get(_path_key(path)), fingerprint)

    def unwatched(self, watched: Iterable[str | os.PathLike[str]]) -> list[str]:
        """The held paths that no entry of ``watched`` names, sorted, each once, in key form
        (absolute, case-normalized), which opens the same file."""
        seen = {_path_key(path) for path in watched}
        return sorted(set(self._by_path) - seen)


def snapshot() -> HeldCrlSnapshot:
    """The copies live contexts hold now, and the reload refusals that explain any still old."""
    items, refusals = _copy()
    return HeldCrlSnapshot([held for _, loads in items for held in loads], refusals)


def held_crl_copies(path: str | os.PathLike[str]) -> list[HeldCrl]:
    """Every copy of the CRL file at ``path`` that a live context still holds, one per load."""
    return snapshot().copies(path)
