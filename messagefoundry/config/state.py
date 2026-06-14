"""Synchronous **read side** for transform-accessible state (cross-message correlation, ADR 0005).

A Handler **declares** writes by returning :class:`~messagefoundry.config.wiring.SetState` (applied
exactly-once inside the routed→outbound handoff transaction); it **reads** them back synchronously via
:func:`state_get`. Handlers are pure synchronous functions and a store read is async, so a read can't
await the DB: instead the engine keeps an in-memory **read-through cache** of the state table (loaded
at startup, updated as writes commit), and publishes a read-only **view** of it as the active state
for the duration of each router/transform run — exactly how :mod:`messagefoundry.config.code_sets`
publishes the active code sets. :func:`state_get` resolves against that view synchronously.

**Layering (information hiding).** This config-layer module owns only the active-view *holder* + the
accessor + the publish helpers (:func:`activated`/:func:`set_active`/:func:`reset`). It does **not**
import the store: the store owns the cache and exposes it as a ``StateView`` (the read-only mapping
``{(namespace, key): decrypted_value}``); the runner *bridges* the two by publishing
``store.state_view()`` here around each run. So the config layer stays free of any store dependency,
matching the one-way dependency direction (CLAUDE.md §4).

**Consistency caveat (ADR 0005).** The view is the live cache, so a read reflects every committed
write as of the call. Reads are *not* linearized with concurrent sibling-handler writes — fine for
read-mostly correlation (patient-id mapping); a race-sensitive read-modify-write within one namespace
needs author care. See docs/CONFIGURATION.md.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from messagefoundry.config.wiring import StateValue

__all__ = [
    "StateView",
    "state_get",
    "set_active",
    "reset",
    "activated",
]

#: The engine-published read view: a read-only mapping ``{(namespace, key): decrypted_value}``. The
#: store builds it (decrypting at load), so the config layer needs no store import — it only reads it.
StateView = Mapping[tuple[str, str], StateValue]

# Active view as a ContextVar (mirrors code_sets._active): the runner re-publishes the live cache view
# around each router/transform run so a call-time state_get(...) inside a Handler resolves, a clean
# reset restores the prior view (no leak across runs / overlapping reloads), and dry-run can publish a
# view too. Defaults to None = "no active view" so state_get distinguishes "not running" from "empty".
_active: ContextVar[StateView | None] = ContextVar("mefor_active_state", default=None)


def set_active(view: StateView | None) -> Any:
    """Publish ``view`` as the active state view and return a reset token (pass it to :func:`reset`).

    For callers that can't bracket the active span with a ``with`` (e.g. an async worker publishing
    around a single transform call). Prefer :func:`activated` where a ``with`` block fits."""
    return _active.set(view)


def reset(token: Any) -> None:
    """Restore the active state view to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(view: StateView | None) -> Iterator[None]:
    """Make ``view`` the active state view for the duration of the ``with`` block, then restore.

    The runner brackets each router/transform run with it (and dry-run mirrors that), so
    :func:`state_get` resolves at call time and the prior view is always restored — no leak."""
    token = _active.set(view)
    try:
        yield
    finally:
        _active.reset(token)


def state_get(namespace: str, key: str, default: StateValue = None) -> StateValue:
    """Read ``namespace``/``key`` from the active state view synchronously; ``default`` on a miss.

    Call it inside a Handler at run time::

        anon = state_get("patient_anon", mrn)
        if anon is None:
            anon = derive_anon_id(mrn)
            return [Send("OB_DOWNSTREAM", msg), SetState("patient_anon", mrn, anon)]

    Resolves against the engine-maintained read-through cache view the runner publishes around the run
    (it reflects every committed write as of this call — see the module note on non-linearization).
    Unlike :func:`messagefoundry.config.wiring.code_set`, a missing **key** is **not** an error (it
    returns ``default``): state is sparse correlation data, not a referenced config table. Calling it
    with **no active view** (outside a run/dry-run) returns ``default`` as well — there is no state to
    read there, and a transform must stay usable in isolation."""
    view = _active.get()
    if view is None:
        return default
    return view.get((namespace, key), default)
