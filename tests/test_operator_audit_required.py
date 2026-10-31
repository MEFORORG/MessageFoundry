# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The store's operator mutations take a REQUIRED ``audit``, with no default (BACKLOG #2624).

``replay``, ``replay_dead``, ``resend_to`` and ``reingress`` commit the operator's audit row in their
own transaction (``tests/_operator_audit_atomic_contract.py`` pins that). While ``audit`` defaulted
to ``None``, a new caller that left it out ran the mutation and recorded nothing, and neither mypy
nor a test said so. With no default, leaving it out is a type error and a ``TypeError`` at the call.
``cancel_queued`` has been required since vault BACKLOG #3217.

This reads signatures with :func:`inspect.signature`, on the Store protocol, on all three backends
and on the :class:`Engine` wrappers, so a backend that restores a default fails here even where no
Postgres or SQL Server is reachable. It does not keep a list of the methods to check: it walks every
public method that takes an ``audit``, so a new operator mutation is held to the rule the day it is
added. The methods that keep an optional ``audit`` on purpose are named in :data:`OPTIONAL`, each
with its reason, and the walk must find exactly those.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore, OperatorAudit

#: The protocol, every backend that implements it, and the engine that wraps them.
CLASSES: tuple[type[Any], ...] = (Store, MessageStore, PostgresStore, SqlServerStore, Engine)

#: The methods whose ``audit`` stays optional, and why. Narrowing one is welcome: delete it here.
OPTIONAL: dict[str, str] = {
    "enqueue_ingress": (
        "the partner receipt path, which has no operator; the operator inject reaches it through"
        " Engine.inject_message, whose audit is required and checked here"
    ),
    "create_pending_approval": "the approval gate's own audit contract (vault BACKLOG #2255)",
    "decide_pending_approval": "the approval gate's own audit contract (vault BACKLOG #2255)",
}

#: The operator mutations this item made required. The walk must reach each, so it cannot pass by
#: finding nothing.
FLOOR: dict[type[Any], frozenset[str]] = {
    **{
        cls: frozenset({"replay", "replay_dead", "resend_to", "reingress", "cancel_queued"})
        for cls in (Store, MessageStore, PostgresStore, SqlServerStore)
    },
    Engine: frozenset(
        {
            "replay",
            "replay_dead",
            "resend",
            "edit_resend_reroute",
            "edit_resend_direct",
            "inject_message",
        }
    ),
}


def audit_problem(cls: type[Any], method: str) -> str | None:
    """Why ``cls.method`` does not take a required, keyword-only, non-``None`` ``audit``."""
    params = inspect.signature(getattr(cls, method)).parameters
    audit = params.get("audit")
    if audit is None:
        return f"{cls.__name__}.{method} has no audit parameter"
    if audit.kind is not inspect.Parameter.KEYWORD_ONLY:
        return f"{cls.__name__}.{method} audit is {audit.kind.name}, not KEYWORD_ONLY"
    if audit.default is not inspect.Parameter.empty:
        return f"{cls.__name__}.{method} audit defaults to {audit.default!r}"
    if "None" in str(audit.annotation):
        return f"{cls.__name__}.{method} audit admits None: {audit.annotation}"
    return None


def audited_methods(cls: type[Any]) -> set[str]:
    """Every public method of ``cls`` that takes an ``audit`` parameter."""
    found = set()
    for name, member in inspect.getmembers(cls, callable):
        if name.startswith("_"):
            continue
        try:
            params = inspect.signature(member).parameters
        except (TypeError, ValueError):
            continue
        if "audit" in params:
            found.add(name)
    return found


@pytest.mark.parametrize("cls", CLASSES, ids=lambda c: c.__name__)
def test_every_audited_operator_method_requires_its_audit(cls: type[Any]) -> None:
    methods = audited_methods(cls)
    assert FLOOR[cls] <= methods, f"the walk missed {sorted(FLOOR[cls] - methods)}"
    problems = [audit_problem(cls, m) for m in sorted(methods - OPTIONAL.keys())]
    assert [p for p in problems if p is not None] == []


@pytest.mark.parametrize("cls", (Store, MessageStore, PostgresStore, SqlServerStore))
def test_the_optional_list_is_exactly_what_stays_optional(cls: type[Any]) -> None:
    """Positive control on the real classes: the check reports every method in :data:`OPTIONAL`, so
    a green run above is not a check that cannot fail. If one of them becomes required, this fails
    by design: take it out of :data:`OPTIONAL`, and the walk above then holds it to the rule."""
    optional = {m for m in audited_methods(cls) if audit_problem(cls, m) is not None}
    assert optional == set(OPTIONAL)


def test_control_a_restored_default_fails_the_check() -> None:
    """Control: the check refuses the shape this item removed, ``audit=None`` restored on one of the
    mutations, and a ``None``-admitting annotation with no default, and accepts the shape that
    replaced them."""

    class Restored:
        async def replay(
            self,
            message_id: str,
            now: float | None = None,
            *,
            audit: OperatorAudit[int] | None = None,
        ) -> int:
            return 0

    class Nullable:
        async def replay(
            self, message_id: str, now: float | None = None, *, audit: OperatorAudit[int] | None
        ) -> int:
            return 0

    class Required:
        async def replay(
            self, message_id: str, now: float | None = None, *, audit: OperatorAudit[int]
        ) -> int:
            return 0

    assert audit_problem(Restored, "replay") == "Restored.replay audit defaults to None"
    assert audit_problem(Nullable, "replay") == (
        "Nullable.replay audit admits None: OperatorAudit[int] | None"
    )
    assert audit_problem(Required, "replay") is None
