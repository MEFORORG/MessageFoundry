# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Re-run-stable **ingest time** for Handlers/Routers — the message's engine-assigned receipt timestamp.

A Handler often needs "now" — e.g. defaulting an empty ``OBR-7`` to when the message arrived, or a
relative date filter. A live clock read (``time.time()``) would break the at-least-once re-run invariant
(CLAUDE.md §2 / ADR 0001): a re-run after a crash would read a *different* wall-clock value and produce a
different message. Instead the engine captures the message's **enqueue time once** — the queue row's
persisted ``created_at``, immutable across re-runs — and publishes it as a run-scoped provider (ADR 0009);
:func:`current_ingest_time` reads it synchronously. So it is **re-run-stable** — the *good* kind of
provider, unlike the live :func:`~messagefoundry.config.db_lookup.db_lookup` exception.

**Value + caveats.** Epoch seconds. In a **Router** it is the message's ingress receipt time; in a
**Handler** it is when the message was handed to the transform stage (within the router's processing time
of receipt — sub-second on a healthy pipeline). It is ``None`` where unavailable: **outside a run** (no
active value), or on a backend that doesn't surface the row timestamp (the **SQL Server** backend, which
is outbound-only and runs no transforms). A Handler that uses it **must tolerate ``None``** (fall back).

**Layering (CLAUDE.md §4).** This config-layer module owns only the active-value holder + the accessor +
the provider registration; the engine supplies the value per run via ``RunContext.ingest_time`` (the
runner reads the claimed row's ``created_at``). It imports no store — the value arrives through the
:mod:`~messagefoundry.config.run_context` seam, so ``config/`` stays free of any store dependency.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from messagefoundry.config.run_context import ROUTER, TRANSFORM, register_run_context

__all__ = ["current_ingest_time", "set_active", "reset", "activated"]

# Active value as a ContextVar (mirrors active_environment._active): the runner publishes the message's
# enqueue time around each router/transform run (via the run_context provider below), so a call-time
# current_ingest_time() inside a Handler resolves, and a clean reset restores the prior value. Default
# None = "no active value" (outside a run, or a backend that doesn't surface it).
_active: ContextVar[float | None] = ContextVar("mefor_active_ingest_time", default=None)


def set_active(value: float | None) -> Any:
    """Publish ``value`` as the active ingest time and return a reset token (pass it to :func:`reset`)."""
    return _active.set(value)


def reset(token: Any) -> None:
    """Restore the active ingest time to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(value: float | None) -> Iterator[None]:
    """Make ``value`` the active ingest time for the duration of the ``with`` block, then restore.

    Used by the run-scoped provider below, which the runner enters around each router/transform run, so
    :func:`current_ingest_time` resolves at call time and the prior value is always restored (no leak)."""
    token = _active.set(value)
    try:
        yield
    finally:
        _active.reset(token)


def current_ingest_time() -> float | None:
    """The message's re-run-stable ingest timestamp (epoch seconds), or ``None`` if unavailable.

    Call it inside a Handler/Router at run time::

        ts = current_ingest_time()
        if ts is not None and not msg["OBR-7"]:
            msg["OBR-7"] = format_hl7_timestamp(ts)

    ``None`` outside a run, or on the SQL Server backend (it runs no transforms). Re-run-stable — the
    same message re-derives the same value (it's the persisted enqueue time, not a live clock read), so
    using it keeps a transform pure for at-least-once (unlike :func:`db_lookup`)."""
    return _active.get()


# Register the ingest-time provider (ADR 0009) for both phases. It is re-run-stable (it activates the
# persisted RunContext.ingest_time, not a live clock), so it needs no dry-run exception.
register_run_context("ingest_time", lambda c: activated(c.ingest_time), phases={ROUTER, TRANSFORM})
