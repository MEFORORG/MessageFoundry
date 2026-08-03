# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synchronous **read side** for captured request/response replies (ADR 0013).

A capturing outbound's reply is persisted (immutably, per message) by the delivery worker; a
Router/Handler reads a *prior committed* reply back synchronously via :func:`response_get`. Like
:mod:`messagefoundry.config.state` / :mod:`messagefoundry.config.reference`, the engine publishes a
read-only **view** as a :class:`~contextvars.ContextVar` for the duration of each run, and the
accessor resolves against it without awaiting the store (handlers are pure synchronous functions).

**Increment 1 scope.** A message has no captured reply *during its own transform* (capture happens
later, at delivery), so the engine currently publishes **no** view for a normal run — ``response_get``
returns its default, and the provider is a registered no-op that establishes the seam, the accessor,
and the registration order (between ``state`` and ``environment``). Increment 2 (re-ingress
orchestration) is where a re-ingressed answer's run publishes a per-message view bound to its
correlation lineage — at which point this accessor resolves a real reply. The view it reads is
**immutable committed** state, so it is re-run-stable by construction (ADR 0009).

**Layering (information hiding, CLAUDE.md §4).** This config-layer module owns the active-view holder,
the accessor, the publish helpers, and the :class:`CapturedResponse` *record shape* the view carries;
it does **not** import the store. The runner bridges the two by publishing a store-derived view here
around each run, so the config layer stays store-free. The record lives here rather than in
``store/store.py`` (which re-exports it, so every existing import path keeps working) because a
sandbox worker child has to rebuild it — and ``messagefoundry.store`` is on the sandbox's
forbidden-import list, so a store-homed record made ``[sandbox].mode=subprocess`` plus a correlated
LOOPBACK reply non-functional.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CapturedResponse",
    "ResponseView",
    "response_get",
    "set_active",
    "reset",
    "activated",
]


@dataclass(frozen=True)
class CapturedResponse:
    """One captured request/response reply (ADR 0013), as returned by ``correlate_response`` for the
    API/console read surface. ``body``/``detail`` are decrypted here; ``body`` is ``None`` once
    retention has nulled it (the row is kept, like a purged ``messages.raw``)."""

    message_id: str
    destination_name: str
    response_seq: int
    outcome: str
    detail: str | None
    captured_at: float
    body: str | None
    # ADR 0021 "Response Sent": 'response' (outbound reply, the default) | 'ack_sent' (inbound ACK we
    # returned). ack_code/ack_phase are non-PHI disposition metadata, populated only for ack_sent rows.
    kind: str = "response"
    ack_code: str | None = None
    ack_phase: str | None = None
    # BACKLOG #154 (ADR 0013 amendment): the captured allow-listed HTTP response headers ({} when none /
    # once retention nulls them). Decrypted + JSON-decoded here; a re-ingressed Handler reads it via
    # response_get(dest).headers.
    headers: Mapping[str, str] = field(default_factory=dict)


#: The engine-published read view: a read-only mapping ``{destination_name: latest_reply}`` for the
#: message in scope (Increment 2 populates it). The value shape is whatever the runner publishes; the
#: config layer only reads it, so it needs no store import. ``None`` means "no active view".
ResponseView = Mapping[str, Any]

# Active view as a ContextVar (mirrors state._active). Defaults to None = "no active view" so
# response_get distinguishes "not running / nothing captured" from a real reply.
_active: ContextVar[ResponseView | None] = ContextVar("mefor_active_response", default=None)


def set_active(view: ResponseView | None) -> Any:
    """Publish ``view`` as the active response view and return a reset token (pass it to :func:`reset`)."""
    return _active.set(view)


def reset(token: Any) -> None:
    """Restore the active response view to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(view: ResponseView | None) -> Iterator[None]:
    """Make ``view`` the active response view for the duration of the ``with`` block, then restore.

    The run-context registry brackets each transform run with it (via the ``response`` provider), so
    :func:`response_get` resolves at call time and the prior view is always restored — no leak."""
    token = _active.set(view)
    try:
        yield
    finally:
        _active.reset(token)


def response_get(destination_name: str, default: Any = None) -> Any:
    """Read the latest captured reply for ``destination_name`` from the active response view (ADR
    0013); ``default`` on a miss or with no active view.

    Synchronous (no ``await``) so it is callable inside a Handler. In Increment 1 there is no active
    view during a normal run, so this returns ``default``; Increment 2 publishes a per-message view a
    re-ingressed answer's handler can read. The view is immutable committed state, so a re-run reads
    the identical value (the re-run-stability the staged pipeline requires)."""
    view = _active.get()
    if view is None:
        return default
    return view.get(destination_name, default)
