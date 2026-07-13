# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Run-scoped context providers — the one seam that activates per-run engine state for a Router/Handler.

Routers and Handlers read engine-published state at call time through **synchronous accessors**
(``code_set()``, ``reference()``, ``state_get()``, ``current_environment()``, …). Each resolves against
a :class:`~contextvars.ContextVar` the engine *activates* for the duration of one router/transform run.
Before this module, every call site — the router worker, the transform worker, and the dry-run path —
repeated its own ``with (activated(...), activated(...), …)`` tuple, so adding a new run-scoped accessor
meant **editing all three tuples**, which collided with every other feature doing the same.

This module replaces those tuples with a single registry of **providers**. A provider is a callable
``(RunContext) -> AbstractContextManager`` tagged with the phase(s) it applies to. The engine and the
dry-run path both call :func:`run_contexts` to enter every provider for a phase; a new run-scoped
accessor just calls :func:`register_run_context` once at import — it never edits a call site again.

**Layering (CLAUDE.md §4).** This lives in ``config/`` (not ``pipeline/``) so config-layer accessors —
e.g. ``config.db_lookup`` — can register a provider without importing ``pipeline/`` (which would invert
the one-way dependency). It depends only on the config activation helpers it pre-registers.

**Order = nesting.** Providers are entered in **registration order** via one
:class:`contextlib.ExitStack`, so registration order *is* the context-manager nesting order. The four
built-ins register at import here, before any feature module; a feature that must nest *inside* another
(e.g. an ingest-time provider inside ``db_lookup``'s executor scope) imports after it.

**Re-run stability (CLAUDE.md §2).** At-least-once re-runs a router/transform and relies on identical
output, so every provider's published state must be re-run-stable. The built-ins are (code sets /
reference snapshots / committed state / the deployment environment name); a provider exposing live,
non-deterministic data (``config.db_lookup``) is the documented exception and must refuse to run where
determinism is assumed. See docs/adr/0009-run-scoped-context-providers.md.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any

from messagefoundry.config.active_environment import activated as _environment_activated
from messagefoundry.config.code_sets import activated as _code_sets_activated
from messagefoundry.config.code_sets import capturing as _unmapped_capturing
from messagefoundry.config.reference import activated as _reference_activated
from messagefoundry.config.response import activated as _response_activated
from messagefoundry.config.send_snapshot import activated as _snapshot_activated
from messagefoundry.config.state import activated as _state_activated

__all__ = [
    "RunContext",
    "RunContextProvider",
    "ROUTER",
    "TRANSFORM",
    "register_run_context",
    "run_contexts",
    "registered_providers",
]

# The two points a router/transform runs. Routers see code sets / references / environment; transforms
# additionally see committed transform state (state is transform-only — see the built-in phases below).
ROUTER = "router"
TRANSFORM = "transform"
_PHASES = frozenset({ROUTER, TRANSFORM})


@dataclass(frozen=True)
class RunContext:
    """The per-run views a provider may read. The engine builds one per run from its live store/registry;
    the dry-run path builds one from its simulated views. A provider reads only the fields it needs (a
    phase that omits a provider never reads that provider's field — e.g. ``state_view`` in the router
    phase), so a caller may leave unused fields at their default."""

    code_sets: Any = None
    reference_view: Any = None
    state_view: Any = None
    response_view: Any = (
        None  # ADR 0013: per-message captured-reply view (transform phase; Increment 2 feeds it)
    )
    active_environment: str | None = None
    ingest_time: float | None = (
        None  # the message's re-run-stable enqueue time (ingest-time provider)
    )
    message_id: str | None = (
        None  # #162: the run's message id, so the unmapped-capture sink can key idempotently
    )
    snapshot_on_send: bool = (
        False  # ADR 0104: activate copy-on-Send for this transform run (default off)
    )


# A provider turns a run context into a context manager that activates one accessor's view for the run.
RunContextProvider = Callable[[RunContext], AbstractContextManager[Any]]

# (name, provider, phases) in REGISTRATION ORDER == ExitStack nesting order. Module-global, populated at
# IMPORT time: engine modules import once per process and user config modules never register here, so a
# config reload never re-appends. Keyed by `name` for idempotency + clear diagnostics.
_providers: list[tuple[str, RunContextProvider, frozenset[str]]] = []


def register_run_context(
    name: str, provider: RunContextProvider, *, phases: frozenset[str] | set[str]
) -> None:
    """Register a run-scoped context ``provider`` under ``name``, applied in the given ``phases``.

    Call **once at module import** (an engine module's top level), not per config load. Idempotent on
    ``name``: a second registration with the same name replaces the first **in place** (preserving
    order), so a re-imported engine module can't double-register. ``phases`` ⊆ {``"router"``,
    ``"transform"``}. Registration order is the runtime nesting order (see module docstring)."""
    ph = frozenset(phases)
    unknown = ph - _PHASES
    if unknown:
        raise ValueError(f"register_run_context({name!r}): unknown phase(s) {sorted(unknown)}")
    if not ph:
        raise ValueError(f"register_run_context({name!r}): phases must not be empty")
    for i, (existing, _, _) in enumerate(_providers):
        if existing == name:
            _providers[i] = (name, provider, ph)
            return
    _providers.append((name, provider, ph))


@contextmanager
def run_contexts(context: RunContext, *, phase: str) -> Iterator[None]:
    """Activate every provider registered for ``phase`` (in registration order) for the ``with`` body.

    Replaces the hand-written ``with (activated(...), …)`` tuples the router worker, transform worker,
    and dry-run path each used. Enters via one :class:`~contextlib.ExitStack`, so providers nest in
    registration order and unwind cleanly (each accessor's prior view restored) on exit — including on
    an exception raised inside the body."""
    with ExitStack() as stack:
        for _name, provider, phases in _providers:
            if phase in phases:
                stack.enter_context(provider(context))
        yield


def registered_providers() -> list[str]:
    """The registered provider names in registration (nesting) order — for diagnostics / tests."""
    return [name for name, _, _ in _providers]


# --- built-in providers (pre-registered so the seam is byte-identical to the old `with` tuples) -------
# Registration order below IS the nesting the workers used: code_sets (outermost) → reference → state →
# environment (innermost). `state` is transform-only; the other three apply in both phases. The dry-run
# path runs router+transform in one block under phase="transform" and supplies active_environment=None,
# so environment activates None — exactly the value current_environment() had when dry-run left it unset.
register_run_context(
    "code_sets", lambda c: _code_sets_activated(c.code_sets), phases={ROUTER, TRANSFORM}
)
register_run_context(
    "reference", lambda c: _reference_activated(c.reference_view), phases={ROUTER, TRANSFORM}
)
register_run_context("state", lambda c: _state_activated(c.state_view), phases={TRANSFORM})
# ADR 0013: the captured-reply view (transform phase only — a Handler reconciling an answer is a
# transform concern). Registered AFTER state and BEFORE environment, so the nesting order is
# code_sets → reference → state → response → environment (asserted by a registration-order test).
register_run_context("response", lambda c: _response_activated(c.response_view), phases={TRANSFORM})
register_run_context(
    "environment",
    lambda c: _environment_activated(c.active_environment),
    phases={ROUTER, TRANSFORM},
)
# ADR 0104: copy-on-Send. Registered AFTER environment and BEFORE unmapped_capture (which stays
# innermost, per this module's docstring). TRANSFORM-only — routers construct no Send objects, so the
# flag would be dead weight in the router phase. run_contexts(rc, phase="transform") is entered on every
# handler-executing path (split, inline, fused, and the sandbox child), so activating it here makes
# Send.__post_init__ snapshot uniformly wherever a handler runs.
register_run_context(
    "snapshot_on_send",
    lambda c: _snapshot_activated(c.snapshot_on_send),
    phases={TRANSFORM},
)
# #162: the run-scoped unmapped-input capture buffer. Registered LAST (innermost) — a router/handler's
# code_set(...).translate() miss is recorded regardless of nesting depth (the run body sits inside every
# provider), so appending here keeps the built-in five in their asserted order while activating capture
# for every router/transform run. On scope exit the buffer drains once (non-PHI counts + optional keyed
# sink) — the controlled, re-run-idempotent point (see config.code_sets.capturing / ADR 0033).
register_run_context(
    "unmapped_capture",
    lambda c: _unmapped_capturing(c.message_id),
    phases={ROUTER, TRANSFORM},
)
