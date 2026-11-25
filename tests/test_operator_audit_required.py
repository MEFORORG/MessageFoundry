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
runtime half, a ``TypeError`` on an explicit ``None`` before any write, and on a ``None`` row for a
result that changed the store (BACKLOG #5069, ``require_mutation_audit``), is pinned on every
backend by ``tests/_operator_audit_atomic_contract.py``; the shared helpers are pinned here.

The account and approval writes' ``audits`` sequence is held the same way (BACKLOG #5070).
"""

from __future__ import annotations

import ast
import functools
import inspect
import textwrap
import typing
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, Union

import pytest

from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import (
    OPERATOR_ORIGINS,
    AuditAppend,
    InjectAudit,
    MessageOrigin,
    MessageStore,
    OperatorAudit,
    ReingressOutcome,
    ResendOutcome,
    if_applied,
    mutation_changed,
    operator_audits,
    require_ingress_audit,
    require_mutation_audit,
)
from tests._ast_sites import callee_name

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
    """``enqueue_ingress``'s refusal (BACKLOG #5071, #6589): an operator origin needs a callable
    audit that builds a row and an ``origin_actor`` naming the user; a partner receipt needs
    neither, and refuses either one it is given."""
    row = AuditAppend("test.inject", actor="test")
    for origin in (MessageOrigin.OPERATOR_UPLOAD, MessageOrigin.OPERATOR_EDIT):
        with pytest.raises(TypeError, match="BACKLOG #5071"):
            require_ingress_audit(None, origin, "op")
        built = require_ingress_audit(lambda _mid: row, origin, "op")
        assert built is not None and built("m") is row
        silent = require_ingress_audit(lambda _mid: None, origin, "op")
        assert silent is not None
        with pytest.raises(TypeError, match="returned no row"):
            silent("m")
        # BACKLOG #6589: the operator label names its user, so an inject with no actor is refused.
        for actor in (None, "", "  ", " op "):
            with pytest.raises(TypeError, match="needs the origin_actor"):
                require_ingress_audit(lambda _mid: row, origin, actor)
    for receipt in (MessageOrigin.PARTNER, MessageOrigin.REINGRESS):
        assert require_ingress_audit(None, receipt, None) is None

    def partner_audit(_mid: str) -> None:
        return None

    # An audit with any other origin is an inject that forgot its origin: refused, not run.
    with pytest.raises(TypeError, match="was given an audit with origin 'partner'"):
        require_ingress_audit(partner_audit, MessageOrigin.PARTNER, None)
    with pytest.raises(TypeError, match="BACKLOG #5071"):
        require_ingress_audit(
            "not-a-callable",  # type: ignore[arg-type]
            MessageOrigin.PARTNER,
            None,
        )
    # So is an actor with any other origin (BACKLOG #6589): only an operator origin names a user.
    with pytest.raises(TypeError, match="was given an origin_actor with origin 'partner'"):
        require_ingress_audit(None, MessageOrigin.PARTNER, "op")


def test_an_inject_audit_is_typed_to_build_a_row() -> None:
    """BACKLOG #6589: the engine's inject, and the store's, type their audit as ``InjectAudit``,
    whose return admits no ``None``, since the store refuses a ``None`` row for an inject. Read
    from the resolved annotation, so an alias back to ``OperatorAudit[str]`` fails here."""
    assert typing.get_args(InjectAudit.__value__) == ([str], AuditAppend)
    engine_audit = typing.get_type_hints(Engine.inject_message)["audit"]
    assert engine_audit is InjectAudit
    for cls in (Store, MessageStore, PostgresStore, SqlServerStore):
        hints = typing.get_type_hints(cls.enqueue_ingress)
        assert hints["audit"] == InjectAudit | None, cls.__name__


def test_the_mutation_audit_refuses_no_row_for_a_change() -> None:
    """The five mutations' audit (BACKLOG #5069): a ``None`` row is refused for a result that
    changed the store, and allowed for one that changed nothing. Control: a real row passes."""
    row = AuditAppend("test.mutation", actor="test")

    def silent(_result: object) -> None:
        return None

    changed: list[object] = [
        1,
        -1,  # a driver's unknown count
        ResendOutcome("resent", "m", "OB_B", "OB_A", "o1"),
        ReingressOutcome("resubmitted", "m", "m2", "IB_A"),
    ]
    unchanged: list[object] = [
        0,
        ResendOutcome("duplicate", "m", "OB_B", "OB_A", "o1"),
        ReingressOutcome("duplicate", "m", "m2", "IB_A"),
    ]
    guarded = require_mutation_audit(silent, "store.test")
    for result in changed:
        assert mutation_changed(result), result
        with pytest.raises(TypeError, match="BACKLOG #5069"):
            guarded(result)
        assert require_mutation_audit(lambda _r: row, "store.test")(result) is row
    for result in unchanged:
        assert not mutation_changed(result), result
        assert guarded(result) is None
    # A result type nothing classified is refused, not read as no change; a bool among them.
    for unknown in (True, False, "m", None):
        with pytest.raises(TypeError, match="does not classify"):
            mutation_changed(unknown)
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        require_mutation_audit(None, "store.test")  # type: ignore[arg-type]


def test_every_origin_is_classified() -> None:
    """``OPERATOR_ORIGINS`` is a listed set, so a new ``MessageOrigin`` must be put on one side
    here: an operator origin the list missed would inject with no audit (BACKLOG #5071)."""
    not_operator = {MessageOrigin.PARTNER, MessageOrigin.REINGRESS}
    assert {MessageOrigin.OPERATOR_EDIT, MessageOrigin.OPERATOR_UPLOAD} == OPERATOR_ORIGINS
    assert set(MessageOrigin) == OPERATOR_ORIGINS | not_operator


#: The alert mutations and the connection flag, which take one ``AuditAppend`` (vault BACKLOG
#: #3217).
_ALERT_MUTATIONS = (
    "set_connection_flag",
    "ack_alert_instance",
    "resolve_alert_instance",
    "suspend_alert_instance",
    "resume_alert_instance",
)


@dataclass(frozen=True)
class Guard:
    """The statement a mutation must open with: ``target = func(...)``, its arguments bound to
    ``func``'s own parameters and each compared as a syntax tree, so the spelling (positional or
    keyword, quotes, a type annotation on the target) does not matter (BACKLOG #6589)."""

    target: str
    func: Callable[..., Any]
    args: Mapping[str, str]


#: Each backend's operator mutations, and the guard each must open with.
_ENTRY_GUARDS: dict[str, Guard] = {
    **{
        m: Guard("audit", require_mutation_audit, {"audit": "audit", "mutation": f"'store.{m}'"})
        for m in sorted(FLOOR[Store])
    },
    "enqueue_ingress": Guard(
        "audit",
        require_ingress_audit,
        {"audit": "audit", "origin": "origin", "origin_actor": "origin_actor"},
    ),
    **{m: Guard("audit_row", if_applied, {"audit": "audit"}) for m in _ALERT_MUTATIONS},
}


def _same(node: ast.expr, expected: str) -> bool:
    return ast.dump(node) == ast.dump(ast.parse(expected, mode="eval").body)


def guard_problem(stmt: ast.stmt, guard: Guard) -> str | None:
    """Why ``stmt`` is not ``guard``'s statement, or ``None`` when it is."""
    shown = ast.unparse(stmt)
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        target, value = stmt.targets[0], stmt.value
    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        target, value = stmt.target, stmt.value
    else:
        return f"starts with {shown!r}, not an assignment to {guard.target}"
    if not (isinstance(target, ast.Name) and target.id == guard.target):
        return f"starts with {shown!r}, which does not bind {guard.target}"
    name = guard.func.__name__
    if not (isinstance(value, ast.Call) and callee_name(value, bare_only=True) == name):
        return f"starts with {shown!r}, not a call to {name}"
    if any(isinstance(a, ast.Starred) for a in value.args) or any(
        k.arg is None for k in value.keywords
    ):
        return f"starts with {shown!r}, whose arguments are unpacked"
    try:
        bound = inspect.signature(guard.func).bind(
            *value.args, **{k.arg: k.value for k in value.keywords if k.arg is not None}
        )
    except TypeError as exc:
        return f"starts with {shown!r}, which does not bind to {name}: {exc}"
    given = bound.arguments
    if set(given) != set(guard.args):
        return f"starts with {shown!r}, passing {sorted(given)} not {sorted(guard.args)}"
    wrong = [p for p, expected in guard.args.items() if not _same(given[p], expected)]
    return f"starts with {shown!r}, with the wrong {wrong}" if wrong else None


def entry_problem(where: str, source: str, guard: Guard) -> str | None:
    """Why the function in ``source`` does not open, after its docstring, with ``guard``."""
    fn = ast.parse(textwrap.dedent(source)).body[0]
    assert isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef), where
    body = fn.body
    if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    problem = guard_problem(body[0], guard)
    return None if problem is None else f"{where} {problem}"


@pytest.mark.parametrize("cls", (MessageStore, PostgresStore, SqlServerStore))
def test_each_mutation_refuses_before_its_first_statement(cls: type[Any]) -> None:
    """The runtime refusal comes BEFORE any write (BACKLOG #5069, #5071, #6589). The contract cannot
    tell that from the ``operator_audits`` backstop, which raises inside the transaction and rolls
    the write back with the same message. So this reads each method's syntax tree: its first
    statement after the docstring must be its guard, with the guard's result kept."""
    problems = [
        entry_problem(
            f"{cls.__name__}.{method}",
            inspect.getsource(inspect.unwrap(getattr(cls, method))),
            guard,
        )
        for method, guard in _ENTRY_GUARDS.items()
    ]
    assert [p for p in problems if p is not None] == []


def test_control_a_missing_or_discarded_guard_fails_the_check() -> None:
    """Control: the check refuses a mutation with no guard, a guard whose result is dropped, and
    one given the wrong argument, and accepts the real shape however it is spelled."""
    template = 'async def f(audit, origin, origin_actor):\n    """Doc."""\n    {}\n'

    def got(lines: Mapping[str, str], guard: Guard) -> dict[str, str | None]:
        return {n: entry_problem(n, template.format(line), guard) for n, line in lines.items()}

    ingress = got(
        {
            "absent": "now = time.time()",
            "dropped": "require_ingress_audit(audit, origin, origin_actor)",
            "wrong origin": (
                "audit = require_ingress_audit(audit, MessageOrigin.PARTNER, origin_actor)"
            ),
            "no actor": "audit = require_ingress_audit(audit, origin, None)",
            "two arguments": "audit = require_ingress_audit(audit, origin)",
            "elsewhere": "kept = require_ingress_audit(audit, origin, origin_actor)",
            "real": "audit = require_ingress_audit(audit, origin, origin_actor)",
            "keywords": (
                "audit = require_ingress_audit(origin_actor=origin_actor, audit=audit,"
                " origin=origin)"
            ),
            "annotated": "audit: Any = require_ingress_audit(audit, origin, origin_actor)",
        },
        _ENTRY_GUARDS["enqueue_ingress"],
    )
    assert {n for n, p in ingress.items() if p is None} == {"real", "keywords", "annotated"}
    # The five mutations' guard: the pre-#5069 line, the wrapped audit computed then dropped, and
    # another mutation's name, are refused; the keyword and double-quoted spellings are not.
    mutation = got(
        {
            "unwrapped": "require_operator_audit(audit, 'store.replay')",
            "dropped": "require_mutation_audit(audit, 'store.replay')",
            "other name": "audit = require_mutation_audit(audit, 'store.reingress')",
            "real": "audit = require_mutation_audit(audit, 'store.replay')",
            "keyword": 'audit = require_mutation_audit(audit, mutation="store.replay")',
        },
        _ENTRY_GUARDS["replay"],
    )
    assert {n for n, p in mutation.items() if p is None} == {"real", "keyword"}
    # The alert mutations' guard (BACKLOG #6589): the old shape, ``if_applied`` taken at the
    # append, opens with something else; so does one that drops the result.
    alert = got(
        {
            "at the append": "now = time.time() if now is None else now",
            "dropped": "if_applied(audit)",
            "real": "audit_row = if_applied(audit)",
        },
        _ENTRY_GUARDS["ack_alert_instance"],
    )
    assert {n for n, p in alert.items() if p is None} == {"real"}
