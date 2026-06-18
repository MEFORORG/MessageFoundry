# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synchronous **read side** for reference sets (external-data enrichment, ADR 0006 Tier 1).

A **reference set** is a managed, versioned, read-only lookup snapshot the engine *materializes* from
an external source **off the message path** (a provider directory, a DB-backed translation table — the
Corepoint Data Point / DB Association pattern). A Handler/Router reads it **purely** at call time via
``reference("name").get(key)`` — a twin of :func:`~messagefoundry.config.wiring.code_set`, but the data
comes from a periodic sync (the :class:`~messagefoundry.pipeline.reference_sync.ReferenceSyncRunner`),
not a file in the bundle.

Because the snapshot lives in the **store** (encrypted at rest, it may carry PHI), this is shaped like
:mod:`messagefoundry.config.state`, not :mod:`messagefoundry.config.code_sets`: the store owns the
read-through cache and exposes it as a :data:`ReferenceView`; the runner publishes
``store.reference_view()`` as the active view around each router/transform run; :func:`reference`
resolves against it synchronously. This config-layer module owns only the active-view holder + the
accessor + the publish helpers, and does **not** import the store (one-way dependency, CLAUDE.md §4).

**Re-run-safe (ADR 0006 / ADR 0001).** A read carries no side effect, so re-run-identity reduces to
"does the snapshot change between a run and a crash-re-run?" The sync writes each new snapshot with a
build-new-then-atomic-flip and the read view swaps wholesale only after a sync commits — so the only
non-determinism is a flip landing in the narrow window between a run and its re-run, the **same**
already-accepted caveat as a code-set hot-reload (see :mod:`messagefoundry.config.code_sets`).

**Call-time only.** Unlike ``code_set()`` (file-loaded at config load, capturable at a module's top
level), a reference snapshot exists only once the store is open and synced — so call :func:`reference`
**inside a Handler/Router at run time**, like :func:`~messagefoundry.config.state.state_get`, not at
module import.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

__all__ = [
    "ReferenceSet",
    "ReferenceView",
    "ReferenceError",
    "reference",
    "set_active",
    "reset",
    "activated",
]

#: The engine-published read view: a read-only mapping ``{refset_name: {key: value}}`` of the **active**
#: snapshots. The store builds it (decrypting at load), so the config layer needs no store import.
ReferenceView = Mapping[str, Mapping[str, Any]]


class ReferenceError(ValueError):
    """A reference set was read but isn't available (no active view, or no such synced set).

    A subclass of :class:`ValueError`. Raised at **handler run time** (a reference is read inside a
    transform), so it surfaces as that message's ``ERROR`` disposition / dead-letter — fail loud, never
    a silent empty table — not as a load-time ``WiringError``."""


class ReferenceSet(Mapping[str, Any]):
    """A frozen, read-only reference snapshot: ``name`` + an immutable ``key → value`` mapping.

    Behaves like a read-only ``dict`` (``rs[key]``, ``rs.get(key, default)``, ``key in rs``,
    ``len(rs)``, iteration) but rejects mutation — one snapshot is shared across every transform, so a
    Handler must never edit it. ``rs[missing]`` raises a :class:`KeyError` naming the set;
    ``rs.get(missing, default)`` returns the default (sparse external data). Wraps the snapshot mapping
    **by reference** (no copy) — the view is already read-only and the sync swaps it wholesale, so a
    large table isn't copied on every lookup."""

    __slots__ = ("_name", "_data")

    def __init__(self, name: str, data: Mapping[str, Any]) -> None:
        self._name = name
        self._data = data

    @property
    def name(self) -> str:
        return self._name

    def __getitem__(self, key: str) -> Any:
        try:
            return self._data[key]
        except KeyError:
            raise KeyError(f"key {key!r} not in reference set {self._name!r}") from None

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"ReferenceSet(name={self._name!r}, entries={len(self._data)})"


# Active view as a ContextVar (mirrors state._active): the runner re-publishes the live snapshot view
# around each router/transform run so a call-time reference(...) inside a Handler resolves, and a clean
# reset restores the prior view (no leak across runs / overlapping reloads). Defaults to None = "no
# active view" so reference() can distinguish "not running" from "set not synced".
_active: ContextVar[ReferenceView | None] = ContextVar("mefor_active_reference", default=None)


def set_active(view: ReferenceView | None) -> Any:
    """Publish ``view`` as the active reference view and return a reset token (pass it to :func:`reset`).

    For callers that can't bracket the active span with a ``with`` (e.g. an async worker publishing
    around a single transform call). Prefer :func:`activated` where a ``with`` block fits."""
    return _active.set(view)


def reset(token: Any) -> None:
    """Restore the active reference view to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(view: ReferenceView | None) -> Iterator[None]:
    """Make ``view`` the active reference view for the duration of the ``with`` block, then restore.

    The runner brackets each router/transform run with it (and dry-run mirrors that), so
    :func:`reference` resolves at call time and the prior view is always restored — no leak."""
    token = _active.set(view)
    try:
        yield
    finally:
        _active.reset(token)


def reference(name: str) -> ReferenceSet:
    """Return the active reference set ``name`` (a frozen, read-only :class:`ReferenceSet`).

    Call it inside a Handler/Router at run time::

        npi = reference("provider_npi").get(msg["PV1-7.1"])

    Resolves against the engine-published snapshot view the runner brackets around the run. A missing
    **key** is not an error (use ``.get(key, default)`` — external data is sparse). A missing **set**
    (no active view, or the named set hasn't synced) raises :class:`ReferenceError` (fail loud) — it
    surfaces as that message's ``ERROR`` disposition, like any transform error."""
    view = _active.get()
    if view is None:
        raise ReferenceError(
            f"reference({name!r}) called with no active reference view — reference sets resolve only "
            "inside a Handler/Router while the graph is running (call it at run time, not at import)"
        )
    try:
        data = view[name]
    except KeyError:
        available = ", ".join(sorted(view)) or "(none synced)"
        raise ReferenceError(
            f"no such reference set {name!r} — declare it with Reference({name!r}, source=…) and let "
            f"it sync; available: {available}"
        ) from None
    return ReferenceSet(name, data)
