# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The CRL copies that live TLS contexts hold, so the expiry monitor judges those and not only the file
(BACKLOG #299).

**Why this exists.** A hop reads its CRL file once, when it builds its TLS context, and most hops keep
that context for every handshake until a restart or a config reload. The expiry monitor
(:mod:`messagefoundry.pipeline.cert_expiry`) read only the file on each pass. So an operator who
replaced an expiring CRL would have seen the ``crl_expiry`` alert clear while the running hop still held
the old copy, which would go on to lapse and refuse every peer. The monitor and the hop disagreed.

:func:`~messagefoundry.config.tls_policy.harden_crl_check` is where the engine loads a CRL into a
context (every in-engine CRL load found on 2026-09-28 goes through it), and it records each load here. The monitor asks :func:`held_crl_copies` for the
copies that live contexts still hold and judges the soonest of those and the file. A held copy of a
file no monitor row names, such as an inbound ``tls_crl_file`` given as a deferred ``env()`` value, is
found through :func:`unwatched_held_crl_paths` and judged under its own row. So the alert stays
up until every context holding the old copy is gone, which is a restart or a rebuild of that hop.

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
    from messagefoundry.pki import CrlFacts

__all__ = [
    "HeldCrl",
    "crl_fingerprint",
    "held_crl_copies",
    "record_crl_load",
    "unwatched_held_crl_paths",
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
    setting: str | None = None


# Keyed by context, held weakly: an entry lives exactly as long as its context. A context may load
# more than one CRL file in principle, so each value is a tuple; overwriting would drop a copy and
# read as an all-clear. The lock covers a load on one thread (the store and SMTP builders run off the
# event loop) racing a monitor read on another; the copy below is taken under it, so the monitor
# never iterates the live mapping.
_HELD: weakref.WeakKeyDictionary[ssl.SSLContext, tuple[HeldCrl, ...]] = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()


def _path_key(path: str | os.PathLike[str]) -> str:
    """Absolute and case-normalized, links NOT resolved; the module docstring says why."""
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def crl_fingerprint(pem: bytes) -> tuple[int, int]:
    """A cheap in-process identity for a CRL file's bytes; the module docstring says why it suffices."""
    return (len(pem), hash(pem))


def record_crl_load(
    ctx: ssl.SSLContext, crl_file: str, pem: bytes, facts: CrlFacts, *, setting: str | None = None
) -> None:
    """Record that ``ctx`` now holds the CRL file ``crl_file``, whose judged bytes were ``pem`` and
    whose soonest-expiring block is ``facts``. Called by ``harden_crl_check`` after a load succeeds."""
    held = HeldCrl(_path_key(crl_file), crl_fingerprint(pem), facts, setting)
    with _LOCK:
        _HELD[ctx] = (*_HELD.get(ctx, ()), held)


def held_crl_copies(path: str | os.PathLike[str]) -> list[HeldCrl]:
    """Every copy of the CRL file at ``path`` that a live context still holds, one per load.

    Empty when no live context loaded that path. Two settings that name one file share its copies,
    because the key is the file: a stale copy held by either hop is a stale copy of that file."""
    key = _path_key(path)
    return [held for held in _snapshot() if held.path_key == key]


def _snapshot() -> list[HeldCrl]:
    with _LOCK:
        return [held for loads in list(_HELD.values()) for held in loads]


def unwatched_held_crl_paths(watched: Iterable[str | os.PathLike[str]]) -> list[str]:
    """The paths of held CRL copies that no entry of ``watched`` names, sorted, each once.

    The monitor watches the CRL paths its settings and registry spell out. A hop can also hold a CRL
    from a path the monitor cannot see, and that copy would lapse unwatched. Each path returned is in
    its key form (absolute, case-normalized), which opens the same file."""
    seen = {_path_key(path) for path in watched}
    return sorted({held.path_key for held in _snapshot()} - seen)
