# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The store's operator mutations take a REQUIRED ``audit``, with no default (BACKLOG #2624).

``replay``, ``replay_dead``, ``resend_to`` and ``reingress`` commit the operator's audit row in their
own transaction (``tests/_operator_audit_atomic_contract.py`` pins that). While ``audit`` defaulted
to ``None``, a new caller that left it out ran the mutation and recorded nothing, and neither mypy
nor a test said so. With no default, leaving it out is a type error and a ``TypeError`` at the call.
``cancel_queued`` has been required since vault BACKLOG #3217 and is pinned here beside them.

This reads the signatures with :func:`inspect.signature`, on the Store protocol and on all three
backends, so a backend that restores a default fails here even where no Postgres or SQL Server is
reachable. ``enqueue_ingress`` keeps its optional ``audit``, because a live receipt has no operator;
it is the positive control that the check does see a default on the real classes.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from messagefoundry.pipeline import Engine
from messagefoundry.store.base import QueueStore
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore, OperatorAudit

#: The operator mutations whose ``audit`` must have no default.
REQUIRED = ("replay", "replay_dead", "resend_to", "reingress", "cancel_queued")

#: The protocol and every backend that implements it.
CLASSES: tuple[type[Any], ...] = (QueueStore, MessageStore, PostgresStore, SqlServerStore)


def audit_default_problem(cls: type[Any], method: str) -> str | None:
    """Why ``cls.method`` does not take a required keyword-only ``audit``, or ``None`` if it does."""
    params = inspect.signature(getattr(cls, method)).parameters
    audit = params.get("audit")
    if audit is None:
        return f"{cls.__name__}.{method} has no audit parameter"
    if audit.kind is not inspect.Parameter.KEYWORD_ONLY:
        return f"{cls.__name__}.{method} audit is {audit.kind.name}, not KEYWORD_ONLY"
    if audit.default is not inspect.Parameter.empty:
        return f"{cls.__name__}.{method} audit defaults to {audit.default!r}"
    return None


@pytest.mark.parametrize("cls", CLASSES, ids=lambda c: c.__name__)
@pytest.mark.parametrize("method", REQUIRED)
def test_operator_mutation_audit_has_no_default(cls: type[Any], method: str) -> None:
    assert audit_default_problem(cls, method) is None


@pytest.mark.parametrize(
    "method", ("replay", "replay_dead", "resend", "edit_resend_reroute", "edit_resend_direct")
)
def test_engine_wrapper_audit_has_no_default(method: str) -> None:
    """The engine wrappers the API calls already required it; this keeps them in step."""
    assert audit_default_problem(Engine, method) is None


@pytest.mark.parametrize("cls", CLASSES, ids=lambda c: c.__name__)
def test_control_the_check_sees_a_default_on_the_real_classes(cls: type[Any]) -> None:
    """Positive control: ``enqueue_ingress`` defaults ``audit`` to ``None`` on purpose, and the
    check reports it on every class, so a green run above is not a check that cannot fail."""
    assert audit_default_problem(cls, "enqueue_ingress") == (
        f"{cls.__name__}.enqueue_ingress audit defaults to None"
    )


def test_control_a_restored_default_fails_the_check() -> None:
    """Control: the check refuses exactly the shape this item removed, ``audit=None`` restored on
    one of the four mutations, and accepts the shape that replaced it."""

    class Restored:
        async def replay(
            self,
            message_id: str,
            now: float | None = None,
            *,
            audit: OperatorAudit[int] | None = None,
        ) -> int:
            return 0

    class Required:
        async def replay(
            self, message_id: str, now: float | None = None, *, audit: OperatorAudit[int]
        ) -> int:
            return 0

    assert audit_default_problem(Restored, "replay") == "Restored.replay audit defaults to None"
    assert audit_default_problem(Required, "replay") is None
