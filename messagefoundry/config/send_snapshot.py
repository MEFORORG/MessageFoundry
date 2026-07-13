# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Run-scoped copy-on-Send flag carrier (ADR 0104).

A single :class:`~contextvars.ContextVar` that says whether a :class:`~messagefoundry.config.wiring.Send`
should snapshot its payload **at construction time**. The engine activates it for the duration of one
transform run via the ``snapshot_on_send`` run-context provider
(:mod:`messagefoundry.config.run_context`), so it is set on **every** handler-executing path uniformly —
the split ``to_thread`` transform, the inline (ADR 0057) transform, the fused (ADR 0071) executor thread
that re-establishes ``run_contexts`` itself, and the subprocess-sandbox (ADR 0087) child that re-enters
``run_contexts`` from the marshalled :class:`~messagefoundry.config.run_context.RunContext`.

Reading the flag from a run-scoped ``ContextVar`` (never a ``Send`` constructor argument) is what makes
``Send.__post_init__`` a single choke point the fused path — which calls ``transform_one`` **without** a
``run_context=`` argument — cannot bypass. When inactive it returns its **default** ``False`` (Sends
constructed in tests / dry-run / outside any transform run), so copy-on-Send is a literal no-op and the
pipeline is byte-identical to the pre-ADR-0104 behaviour.

Stdlib-only and imports **nothing** from ``messagefoundry`` — so both ``config.wiring`` (which reads the
accessor in ``Send.__post_init__``) and ``config.run_context`` (which registers the provider) can import
it with no cycle.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = ["activated", "snapshot_on_send_active"]

# Run-scoped; defaults False so a Send constructed outside an active transform run never snapshots.
_snapshot_on_send: ContextVar[bool] = ContextVar("mf_snapshot_on_send", default=False)


@contextmanager
def activated(flag: bool) -> Iterator[None]:
    """Activate the copy-on-Send flag for the ``with`` body, restoring the prior value on exit.

    Entered by the ``snapshot_on_send`` run-context provider for the transform phase. Nested/reentrant-
    safe via the token returned by :meth:`~contextvars.ContextVar.set`."""
    token = _snapshot_on_send.set(bool(flag))
    try:
        yield
    finally:
        _snapshot_on_send.reset(token)


def snapshot_on_send_active() -> bool:
    """Whether copy-on-Send is active for the current run (``False`` when no transform run activated it)."""
    return _snapshot_on_send.get()
