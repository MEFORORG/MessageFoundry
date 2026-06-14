"""The active **environment** name, readable inside a transform (per-face logic).

A migrated feed sometimes branches on which deployment it is running as — e.g. stamp MSH-11 (Processing
Id) ``P`` in production vs ``T`` in test (Corepoint's ``If #Environment[ActiveFace]="Test"``). The
engine's single active-environment selector is ``[ai].environment`` / ``serve --env``
(``dev``/``staging``/``prod``); this module makes that name readable synchronously inside a Router or
Handler via :func:`current_environment`.

It is shaped like :mod:`messagefoundry.config.state` / :mod:`messagefoundry.config.reference`: a
ContextVar the runner publishes around each router/transform run, read synchronously by the accessor.
Unlike ``env()`` — which is a *deferred reference* resolved only when a **connection** spec is built
(using it inside a handler is an always-truthy object, a bug) — :func:`current_environment` returns the
**string** name, usable in handler control flow.

**Re-run-safe.** The active environment is fixed for the life of the engine process (a crash-re-run
restarts in the same environment; a config reload swaps the graph, not the environment), so reading it
is deterministic — pure, and compatible with the staged-pipeline re-run invariant (ADR 0001 /
CLAUDE.md §2). Distinct from ``env()`` *values*, which may differ per environment but are resolved at
connection-build time, not in a transform.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

__all__ = [
    "current_environment",
    "set_active",
    "reset",
    "activated",
]

# Active environment name as a ContextVar (mirrors state._active): the runner publishes it around each
# router/transform run so a call-time current_environment() inside a Handler resolves, and a clean
# reset restores the prior value (no leak across runs / tests). None = "no active environment" (outside
# a run / a dry-run with no live engine).
_active: ContextVar[str | None] = ContextVar("mefor_active_environment", default=None)


def set_active(name: str | None) -> Any:
    """Publish ``name`` as the active environment and return a reset token (pass it to :func:`reset`)."""
    return _active.set(name)


def reset(token: Any) -> None:
    """Restore the active environment to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(name: str | None) -> Iterator[None]:
    """Make ``name`` the active environment for the duration of the ``with`` block, then restore.

    The runner brackets each router/transform run with it, so :func:`current_environment` resolves at
    call time and the prior value is always restored — no leak."""
    token = _active.set(name)
    try:
        yield
    finally:
        _active.reset(token)


def current_environment() -> str | None:
    """The active environment name (``"dev"``/``"staging"``/``"prod"``), or ``None`` outside a run.

    Read it inside a Router/Handler for per-face logic::

        # Corepoint: If ActiveFace="Test" Then MSH-11.1 = "T"
        if current_environment() in ("staging", "dev"):
            msg.set("MSH-11.1", "T")

    Returns ``None`` in a dry-run / outside a run (no live engine) — a transform should default
    sensibly (treat None as the production / leave-as-is case). The value is a deployment constant, so
    the read is pure + re-run-safe (unlike a per-message external call)."""
    return _active.get()
