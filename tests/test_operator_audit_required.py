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
Postgres or SQL Server is reachable. It walks every public method that takes a parameter named
``audit``, so a new method that does is held to the rule without being listed here. The store
methods that keep an optional ``audit`` on purpose are named in :data:`OPTIONAL`, each with its
reason, and the walk must find exactly those; on :class:`Engine` none is exempt.

What it does not catch, at least: a new operator mutation that takes no ``audit`` at all, or names
it something else; a ``None``-admitting annotation spelled through an alias; and a caller that
passes an ``audit`` which never returns a row. None of these is a type the walk can see. The
runtime half, a ``TypeError`` on an explicit ``None`` before any write (BACKLOG #5069), is pinned on
every backend by ``tests/_operator_audit_atomic_contract.py``; the shared helpers are pinned here.

The account and approval writes' ``audits`` sequence is held the same way (BACKLOG #5070).
"""

from __future__ import annotations

import ast
import functools
import inspect
import textwrap
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Optional, Union

import pytest

from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import (
    OPERATOR_ORIGINS,
    AuditAppend,
    MessageOrigin,
    MessageStore,
    OperatorAudit,
    if_applied,
    operator_audits,
    require_ingress_audit,
)

#: The protocol, every backend that implements it, and the engine that wraps them.
CLASSES: tuple[type[Any], ...] = (Store, MessageStore, PostgresStore, SqlServerStore, Engine)

#: The store methods whose ``audit`` stays optional, and why. Narrowing one is welcome: delete it
#: here. It does not apply to :class:`Engine`.
OPTIONAL: dict[str, str] = {
    "enqueue_ingress": (
        "also the partner receipt path, which has no operator; the operator inject reaches it"
        " through Engine.inject_message, whose audit is required and checked here, and the store"
        " refuses an operator origin with no audit at runtime (BACKLOG #5071)"
    ),
    "create_pending_approval": "the approval gate's own audit contract (vault BACKLOG #2255)",
    "decide_pending_approval": "the approval gate's own audit contract (vault BACKLOG #2255)",
}

#: Operator mutations whose ``audit`` is required: the four this item made required, with
#: ``cancel_queued`` (#3217) and the Engine wrappers, which were already. The walk must reach each,
#: so it cannot pass by finding nothing.
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


#: Annotations, or top-level union members, that let ``None`` through (BACKLOG #5069).
_ADMITS_ANYTHING = frozenset({"None", "Any", "object"})


def _bare(name: str) -> str:
    """``name`` without the module prefix a formatted annotation may carry."""
    return name.strip().removeprefix("typing.").removeprefix("builtins.")


def _top_level(text: str, sep: str) -> list[str]:
    """``text`` split at each ``sep`` outside brackets, so ``Callable[[R], X | None]`` stays one
    member and its inner ``None`` is not read as the parameter's (BACKLOG #5069)."""
    parts: list[str] = []
    depth = start = 0
    for i, ch in enumerate(text):
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    return [*parts, text[start:].strip()]


def _admits_none(annotation: object) -> bool:
    """Whether the annotation, as written, lets ``None`` or anything at all through."""
    text = annotation if isinstance(annotation, str) else inspect.formatannotation(annotation)
    for member in _top_level(text, "|"):
        head, _, rest = member.partition("[")
        if _bare(member) in _ADMITS_ANYTHING or _bare(head) == "Optional":
            return True
        union = _top_level(rest[:-1], ",") if _bare(head) == "Union" else []
        if any(_bare(m) in _ADMITS_ANYTHING for m in union):
            return True
    return False


def _param_problem(where: str, name: str, param: inspect.Parameter | None) -> str | None:
    """Why ``param`` is not a required, keyword-only parameter that admits no ``None``."""
    if param is None:
        return f"{where} has no {name} parameter"
    if param.kind is not inspect.Parameter.KEYWORD_ONLY:
        return f"{where} {name} is {param.kind.name}, not KEYWORD_ONLY"
    if param.default is not inspect.Parameter.empty:
        return f"{where} {name} defaults to {param.default!r}"
    if param.annotation is inspect.Parameter.empty:
        return f"{where} {name} is unannotated"
    if _admits_none(param.annotation):
        return f"{where} {name} admits None: {param.annotation}"
    return None


def _passes_through(params: Mapping[str, inspect.Parameter]) -> bool:
    """A wrapper signature that forwards every argument unchanged: ``*args, **kwargs`` and at most
    one leading positional, the instance, whatever it is named. Such a decorator cannot default or
    drop ``audit``."""
    kinds = [p.kind for p in params.values()]
    if kinds[:1] in (
        [inspect.Parameter.POSITIONAL_ONLY],
        [inspect.Parameter.POSITIONAL_OR_KEYWORD],
    ):
        kinds = kinds[1:]
    return kinds == [inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD]


def signature_problem(cls: type[Any], method: str, name: str) -> str | None:
    """Why ``cls.method`` does not take ``name`` required, keyword-only and non-``None``.

    :func:`inspect.signature` follows ``__wrapped__``, so it reads the decorated function. The
    decorator's own signature is read too (BACKLOG #5069): one that names ``name`` is held to the
    same rule, and one that does not must forward every argument unchanged."""
    fn = getattr(cls, method)
    where = f"{cls.__name__}.{method}"
    problem = _param_problem(where, name, inspect.signature(fn).parameters.get(name))
    if problem is not None:
        return problem
    outer = inspect.signature(fn, follow_wrapped=False).parameters
    if name in outer:
        return _param_problem(f"{where} (its wrapper)", name, outer[name])
    if not _passes_through(outer):
        return f"{where} is wrapped by a signature that drops {name}: {list(outer)}"
    return None


def audit_problem(cls: type[Any], method: str) -> str | None:
    """Why ``cls.method`` does not take a required, keyword-only, non-``None`` ``audit``."""
    return signature_problem(cls, method, "audit")


def audited_methods(cls: type[Any]) -> set[str]:
    """Every public method of ``cls`` that takes an ``audit`` parameter. A signature that cannot be
    read raises rather than drop the method from the walk."""
    return {
        name
        for name, member in inspect.getmembers(cls, callable)
        if not name.startswith("_") and "audit" in inspect.signature(member).parameters
    }


@pytest.mark.parametrize("cls", CLASSES, ids=lambda c: c.__name__)
def test_every_audited_operator_method_requires_its_audit(cls: type[Any]) -> None:
    methods = audited_methods(cls)
    assert FLOOR[cls] <= methods, f"the walk missed {sorted(FLOOR[cls] - methods)}"
    exempt = set() if cls is Engine else OPTIONAL.keys()
    problems = [audit_problem(cls, m) for m in sorted(methods - exempt)]
    assert [p for p in problems if p is not None] == []


@pytest.mark.parametrize("cls", (Store, MessageStore, PostgresStore, SqlServerStore))
def test_the_optional_list_is_exactly_what_stays_optional(cls: type[Any]) -> None:
    """Positive control on the real classes: the check reports every method in :data:`OPTIONAL`, so
    a green run above is not a check that cannot fail. If one of them becomes required, this fails
    by design: take it out of :data:`OPTIONAL`, and the walk above then holds it to the rule."""
    problems = {m: audit_problem(cls, m) for m in audited_methods(cls)}
    optional = {m: p for m, p in problems.items() if p is not None}
    # Each is optional in the one way OPTIONAL means, a None default, and not for some other fault
    # the walk would report, such as a positional audit or a wrapper that drops it (BACKLOG #5071).
    assert optional == {m: f"{cls.__name__}.{m} audit defaults to None" for m in OPTIONAL}


#: The account and approval writes whose ``audits`` sequence is required with no default (BACKLOG
#: #5070), so a caller states what commits with the write, ``()`` included, rather than leave it out.
AUDITS_REQUIRED = frozenset(
    {"create_user", "set_user_username", "update_user_profile", "reject_seal_failed_approval"}
)


@pytest.mark.parametrize("cls", (Store, MessageStore, PostgresStore, SqlServerStore))
def test_every_audits_sequence_is_required(cls: type[Any]) -> None:
    """Every public store method taking ``audits`` takes it keyword-only with no default (BACKLOG
    #5070). The walk must reach the four the item named, so it cannot pass by finding nothing."""
    methods = {
        name
        for name, member in inspect.getmembers(cls, callable)
        if not name.startswith("_") and "audits" in inspect.signature(member).parameters
    }
    assert methods >= AUDITS_REQUIRED, f"the walk missed {sorted(AUDITS_REQUIRED - methods)}"
    problems = [signature_problem(cls, m, "audits") for m in sorted(methods)]
    assert [p for p in problems if p is not None] == []


def test_control_a_defaulted_audits_sequence_fails_the_check() -> None:
    """Control: the shape #5070 removed, ``audits=()``, is reported."""

    class Defaulted:
        async def create_user(self, *, user_id: str, audits: Sequence[AuditAppend] = ()) -> None:
            return None

    assert signature_problem(Defaulted, "create_user", "audits") == (
        "Defaulted.create_user audits defaults to ()"
    )


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

    class Spelled:
        async def replay(
            self,
            message_id: str,
            now: float | None = None,
            *,
            audit: Optional[OperatorAudit[int]],  # noqa: UP045
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
    assert audit_problem(Spelled, "replay") == (
        "Spelled.replay audit admits None: Optional[OperatorAudit[int]]"
    )
    assert audit_problem(Required, "replay") is None


def test_control_the_check_reads_what_lets_none_through() -> None:
    """Control (BACKLOG #5069): ``Any``, ``object``, a missing annotation and ``Union[..., None]``
    are reported; a ``None`` nested inside a member, as in a callable's own return type, is not."""

    class Loose:
        async def any_(self, *, audit: Any) -> None:
            return None

        async def object_(self, *, audit: object) -> None:
            return None

        async def bare(self, *, audit) -> None:  # noqa: ANN001
            return None

        async def union(self, *, audit: Union[OperatorAudit[int], None]) -> None:  # noqa: UP007
            return None

        async def nested(self, *, audit: Callable[[int], AuditAppend | None]) -> None:
            return None

    assert audit_problem(Loose, "any_") == "Loose.any_ audit admits None: Any"
    assert audit_problem(Loose, "object_") == "Loose.object_ audit admits None: object"
    assert audit_problem(Loose, "bare") == "Loose.bare audit is unannotated"
    assert audit_problem(Loose, "union") == (
        "Loose.union audit admits None: Union[OperatorAudit[int], None]"
    )
    assert audit_problem(Loose, "nested") is None


def test_control_a_wrapper_signature_is_read_too() -> None:
    """Control (BACKLOG #5069): a decorator that forwards every argument passes, as the store's
    ``audits_cell_tag`` does on ``resend_to`` and ``reingress``; one whose own signature defaults
    ``audit``, or drops it, is reported, though the function it wraps requires it."""

    async def inner(self: object, *, audit: OperatorAudit[int]) -> int:
        return 0

    async def forwards(self: object, /, *args: Any, **kwargs: Any) -> int:
        return 0

    async def defaults(self: object, *, audit: OperatorAudit[int] | None = None) -> int:
        return 0

    async def drops(self: object) -> int:
        return 0

    def wrapped(outer: Callable[..., Any]) -> Callable[..., Any]:
        return functools.update_wrapper(outer, inner)

    class Wrapped:
        forward = wrapped(forwards)
        default = wrapped(defaults)
        drop = wrapped(drops)

    assert audit_problem(Wrapped, "forward") is None
    assert audit_problem(Wrapped, "default") == (
        "Wrapped.default (its wrapper) audit defaults to None"
    )
    assert audit_problem(Wrapped, "drop") == (
        "Wrapped.drop is wrapped by a signature that drops audit: ['self']"
    )
    # And the real decorated methods are reached through the wrapper, not around it.
    outer = inspect.signature(MessageStore.resend_to, follow_wrapped=False).parameters
    assert "audit" not in outer
    assert audit_problem(MessageStore, "resend_to") is None


def test_operator_audits_refuses_a_missing_audit_and_a_bad_return() -> None:
    """The append helper every backend shares (BACKLOG #5069): ``None`` in place of the audit, or a
    return that is not an ``AuditAppend``, raises; a ``None`` return records nothing, as decided."""
    row = AuditAppend("test.op", actor="test")
    assert operator_audits(lambda _n: row, 1) == (row,)
    assert operator_audits(lambda _n: None, 1) == ()
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        operator_audits(None, 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        operator_audits(lambda _n: "row", 1)  # type: ignore[arg-type,return-value]
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        if_applied(None)  # type: ignore[arg-type]
    assert if_applied(row)(False) is None and if_applied(row)(True) is row


def test_the_ingress_refusal_keys_on_an_operator_origin() -> None:
    """``enqueue_ingress``'s refusal (BACKLOG #5071): an operator origin needs a callable audit
    that builds a row; a partner receipt needs none, and an audit it is given must be callable."""
    row = AuditAppend("test.inject", actor="test")
    for origin in (MessageOrigin.OPERATOR_UPLOAD, MessageOrigin.OPERATOR_EDIT):
        with pytest.raises(TypeError, match="BACKLOG #5071"):
            require_ingress_audit(None, origin)
        built = require_ingress_audit(lambda _mid: row, origin)
        assert built is not None and built("m") is row
        silent = require_ingress_audit(lambda _mid: None, origin)
        assert silent is not None
        with pytest.raises(TypeError, match="returned no row"):
            silent("m")
    assert require_ingress_audit(None, MessageOrigin.PARTNER) is None
    assert require_ingress_audit(None, MessageOrigin.REINGRESS) is None

    def partner_audit(_mid: str) -> None:
        return None

    # Not an operator origin, so a None row is not refused: the audit runs as given.
    assert require_ingress_audit(partner_audit, MessageOrigin.PARTNER) is partner_audit
    with pytest.raises(TypeError, match="BACKLOG #5071"):
        require_ingress_audit("not-a-callable", MessageOrigin.PARTNER)  # type: ignore[arg-type]


def test_every_origin_is_classified() -> None:
    """``OPERATOR_ORIGINS`` is a listed set, so a new ``MessageOrigin`` must be put on one side
    here: an operator origin the list missed would inject with no audit (BACKLOG #5071)."""
    not_operator = {MessageOrigin.PARTNER, MessageOrigin.REINGRESS}
    assert {MessageOrigin.OPERATOR_EDIT, MessageOrigin.OPERATOR_UPLOAD} == OPERATOR_ORIGINS
    assert set(MessageOrigin) == OPERATOR_ORIGINS | not_operator


#: Each backend's operator mutations, and the call each must make before anything else.
_ENTRY_GUARDS = {
    **dict.fromkeys(sorted(FLOOR[Store]), "require_operator_audit"),
    "enqueue_ingress": "require_ingress_audit",
}


@pytest.mark.parametrize("cls", (MessageStore, PostgresStore, SqlServerStore))
def test_each_mutation_refuses_before_its_first_statement(cls: type[Any]) -> None:
    """The runtime refusal comes BEFORE any write (BACKLOG #5069, #5071). The contract cannot tell
    that from the ``operator_audits`` backstop, which raises inside the transaction and rolls the
    write back with the same message. So this reads each method's syntax tree: its first statement
    after the docstring must call the guard, passing ``audit``."""
    problems = []
    for method, guard in _ENTRY_GUARDS.items():
        tree = ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(getattr(cls, method)))))
        fn = tree.body[0]
        assert isinstance(fn, ast.AsyncFunctionDef), f"{cls.__name__}.{method}"
        body = fn.body
        if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body = body[1:]
        first = body[0]
        call = first.value if isinstance(first, (ast.Expr, ast.Assign)) else None
        ok = (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == guard
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "audit"
        )
        if not ok:
            problems.append(f"{cls.__name__}.{method} starts with {ast.unparse(first)!r}")
    assert problems == []
