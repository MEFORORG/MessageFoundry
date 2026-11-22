# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5004 - pins on how the DATABASE connector reads "a cancel is unwinding".

Decision d20261122T111246796-0fae1e, decided by the Manager under the owner's delegation of
2026-11-22, keeps ``_unwinding_a_cancel``'s read of the exception in flight (``sys.exc_info()``)
rather than an explicit flag at each call site or a ``cancelling()`` baseline taken at entry. These
tests pin that read, so a change to it fails here rather than passing unseen:

* the predicate itself, for each kind of exception in flight, including an outer
  ``KeyboardInterrupt`` or ``SystemExit`` and a runner teardown's cancel, which the decision
  accepts as read as a cancel;
* the two cases the read exists to fix (an absorbed cancel, and an ``uncancel()`` before the
  ``finally``), at the predicate, beside the call-site arms in
  ``tests/test_backlog5010_database_gate_discard.py``;
* the two cases the predicate's docstring names as not seen, so that text stays true;
* a lexical census of the direct call sites of ``_close_and_release`` across the engine packages,
  for the forms it names that turn a cancel into something else before the release reads it. It
  is narrower than "no path converts a cancel": its own section says what it does not see.

Synthetic data only; no driver, no database.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Iterator

import pytest

from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError
from tests._ast_sites import call_sites, callee_name, package_trees
from tests.test_backlog5010_database_gate_discard import _absorb_a_cancel

_TARGET = "_close_and_release"


def _read_while_unwinding(exc: BaseException) -> bool:
    """What the predicate reads in a ``finally`` that ``exc`` is unwinding through."""
    seen: list[bool] = []
    with pytest.raises(type(exc)):
        try:
            raise exc
        finally:
            seen.append(database._unwinding_a_cancel())
    assert len(seen) == 1
    return seen[0]


# --- the predicate -------------------------------------------------------------------------------


def test_nothing_in_flight_reads_as_no_cancel() -> None:
    assert database._unwinding_a_cancel() is False


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(asyncio.CancelledError(), id="CancelledError"),
        pytest.param(KeyboardInterrupt(), id="KeyboardInterrupt"),
        pytest.param(SystemExit(1), id="SystemExit"),
        pytest.param(GeneratorExit(), id="GeneratorExit"),
    ],
)
def test_a_base_exception_in_flight_reads_as_a_cancel(exc: BaseException) -> None:
    """A ``BaseException`` that is not an ``Exception`` takes the cancel path, an outer
    ``KeyboardInterrupt`` or ``SystemExit`` included: a caller's ``except Exception`` rollback was
    skipped for it too, so the unwind does not wait on a statement that may still be running."""
    assert _read_while_unwinding(exc) is True


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(ValueError("synthetic"), id="ValueError"),
        pytest.param(TimeoutError(), id="TimeoutError"),
        pytest.param(DeliveryError("synthetic"), id="DeliveryError"),
    ],
)
def test_an_ordinary_exception_in_flight_reads_as_no_cancel(exc: BaseException) -> None:
    assert _read_while_unwinding(exc) is False


def test_a_handled_exception_no_longer_reads_as_in_flight() -> None:
    """A call site that handled its exception before the release (the login role probe does) is on
    the ordinary path: the handled cancel is gone from ``sys.exc_info()`` once its handler ends."""
    try:
        raise asyncio.CancelledError
    except asyncio.CancelledError:
        pass
    assert database._unwinding_a_cancel() is False


async def test_an_absorbed_cancel_does_not_read_as_a_cancel_later() -> None:
    """``cancelling()`` stays at one for the rest of the task, and a later borrow reads no cancel,
    with nothing in flight or with an ordinary exception in flight."""

    async def body() -> tuple[bool, bool]:
        await _absorb_a_cancel()
        quiet = database._unwinding_a_cancel()
        return quiet, _read_while_unwinding(ValueError("synthetic"))

    assert await asyncio.wait_for(asyncio.create_task(body()), 5.0) == (False, False)


async def test_a_cancel_still_reads_as_one_after_an_uncancel_before_the_finally() -> None:
    """``uncancel()`` brings ``cancelling()`` to zero while the cancel still unwinds; the read
    follows the unwinding exception, not the count."""
    seen: list[tuple[int, bool]] = []

    async def body() -> None:
        task = asyncio.current_task()
        assert task is not None
        try:
            await asyncio.sleep(10.0)
        finally:
            while task.cancelling():
                task.uncancel()
            seen.append((task.cancelling(), database._unwinding_a_cancel()))

    task = asyncio.create_task(body())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert seen == [(0, True)], seen


async def test_a_runner_teardown_cancel_reads_as_a_cancel() -> None:
    """A task cancelled as a runner tears down unwinds a ``CancelledError`` like any other."""
    seen: list[bool] = []

    def run() -> None:
        started = asyncio.Event()

        async def body() -> None:
            try:
                started.set()
                await asyncio.Event().wait()
            finally:
                seen.append(database._unwinding_a_cancel())

        async def main() -> None:
            asyncio.get_running_loop().create_task(body())
            await started.wait()  # main returns; asyncio.run cancels the task left running

        asyncio.run(main())

    await asyncio.to_thread(run)
    assert seen == [True], seen


# --- what the docstring says the read does not see -----------------------------------------------


async def test_a_cancel_asyncio_timeout_converts_reads_as_its_timeout() -> None:
    """``asyncio.timeout`` turns its cancel into ``TimeoutError`` before an outer ``finally``, which
    then reads no cancel. It is one of the forms the census below looks for at a call site."""
    seen: list[bool] = []
    with pytest.raises(TimeoutError):
        try:
            async with asyncio.timeout(0.01):
                await asyncio.sleep(10.0)
        finally:
            seen.append(database._unwinding_a_cancel())
    assert seen == [False], seen


def test_a_borrow_inside_a_cancel_handler_reads_that_cancel_as_its_own() -> None:
    seen: list[bool] = []
    try:
        raise asyncio.CancelledError
    except asyncio.CancelledError:
        try:
            pass
        finally:
            seen.append(database._unwinding_a_cancel())
    assert seen == [True], seen


# --- the call-site census ------------------------------------------------------------------------
#
# What it checks, for each direct call of ``_close_and_release`` (bare or as an attribute) in an
# engine module: walking up from the call to its function, every ``try`` that holds the call in
# a handler, ``else`` or ``finally`` runs nothing before it that is one of the forms below, and no
# enclosing handler catches a cancel without re-raising it.
#
# What it does not see, at least: anything inside a function the ``try`` awaits; an exception a
# cleanup step raises in place of the cancel (an inner ``finally`` that awaits, say); a cancel type
# imported under another name, or a ``suppress`` whose types are not spelled in the call.

# A handler naming one of these catches a cancel; a bare ``except:`` does too.
_CANCEL_TYPES = frozenset(
    {
        "CancelledError",
        "BaseException",
        "BaseExceptionGroup",
        "KeyboardInterrupt",
        "SystemExit",
        "GeneratorExit",
    }
)
# Context managers and calls that can end a cancel as something else inside the code they wrap: a
# TimeoutError, or (a task group whose child fails during the cancel) an ExceptionGroup.
_CONVERTING_CALLS = frozenset({"timeout", "timeout_at", "wait_for", "TaskGroup"})
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_TRIES = (ast.Try, ast.TryStar)
# The floors are the direct call sites counted when this census was written; a site that moves out
# of the census's reach lowers the count and fails here.
_FLOORS = {
    "messagefoundry/transports/database.py": 8,
    "messagefoundry/pipeline/reference_sync.py": 1,
}


def _names(node: ast.expr | None) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Tuple):
        return set().union(*(_names(e) for e in node.elts))
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    return set()


def _walk_body(nodes: list[ast.stmt]) -> Iterator[ast.AST]:
    """Every node under ``nodes``, not entering a ``def``, ``lambda`` or class at any depth."""
    stack: list[ast.AST] = [n for n in nodes if not isinstance(n, _SCOPES)]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in ast.iter_child_nodes(node) if not isinstance(c, _SCOPES))


def _converting_handler(handler: ast.ExceptHandler) -> bool:
    """A handler that catches a cancel and may end it: it raises something else, leaves by a
    ``return``, ``break`` or ``continue`` anywhere in its body, or does not end with a bare
    ``raise``."""
    catches = handler.type is None or bool(_names(handler.type) & _CANCEL_TYPES)
    if not catches:
        return False
    last = handler.body[-1]
    if not (isinstance(last, ast.Raise) and last.exc is None):
        return True
    return any(
        (isinstance(n, ast.Raise) and n.exc is not None)
        or isinstance(n, (ast.Return, ast.Break, ast.Continue))
        for n in _walk_body(handler.body)
    )


def _conversions(nodes: list[ast.stmt]) -> list[str]:
    found: list[str] = []
    for node in _walk_body(nodes):
        if isinstance(node, ast.Call):
            name = callee_name(node)
            if name in _CONVERTING_CALLS:
                found.append(f"{name}() at line {node.lineno}")
            if name == "suppress" and set().union(*map(_names, node.args)) & _CANCEL_TYPES:
                found.append(f"suppress() of a cancel at line {node.lineno}")
        elif isinstance(node, ast.ExceptHandler) and _converting_handler(node):
            found.append(f"a handler that ends a cancel at line {node.lineno}")
    return found


def _before(try_node: ast.Try | ast.TryStar, child: ast.AST) -> list[ast.stmt]:
    """The statements of ``try_node`` that may run before ``child``, one of its direct children."""
    handlers: list[ast.stmt] = []
    for handler in try_node.handlers:
        handlers.extend(handler.body)
    if child in try_node.finalbody:
        return [*try_node.body, *handlers, *try_node.orelse]
    # In a handler or the else: only the body ran first; a sibling handler never runs before it.
    return list(try_node.body) if child not in try_node.body else []


def _site_faults(tree: ast.Module) -> tuple[int, list[str]]:
    """How many direct call sites of ``_close_and_release`` ``tree`` holds, and each conversion
    the census finds on the way to one."""
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    sites = call_sites(tree, _TARGET)
    faults: list[str] = []
    for call in sites:
        node: ast.AST = call
        while node in parents and not isinstance(node, _SCOPES):
            child, node = node, parents[node]
            if isinstance(node, ast.ExceptHandler) and _converting_handler(node):
                faults.append(f"line {call.lineno}: inside a handler that ends a cancel")
            if isinstance(node, _TRIES):
                for what in _conversions(_before(node, child)):
                    faults.append(f"line {call.lineno}: {what}")
                if child in node.finalbody:
                    for handler in node.handlers:
                        if _converting_handler(handler):
                            faults.append(f"line {call.lineno}: handler at line {handler.lineno}")
        if isinstance(node, _SCOPES) and not isinstance(
            parents.get(node), (ast.Module, ast.ClassDef)
        ):
            # A release inside a closure is reached from wherever the closure is awaited, which
            # this walk cannot follow; such a site is reported rather than passed unread.
            faults.append(f"line {call.lineno}: inside a nested def the census cannot follow")
    return len(sites), faults


def test_no_call_site_turns_a_cancel_into_something_else() -> None:
    """The predicate reads the exception in flight, so a call site that turned the cancel into a
    ``TimeoutError``, swallowed it, or raised its own exception in its place would send a cancelled
    borrow down the ordinary path, which waits, through ``shield``, on a statement that may still be
    running. The census reads the forms named above; a green run is not proof that no other path
    does this."""
    counts: dict[str, int] = {}
    faults: list[str] = []
    for path, tree in package_trees().items():
        count, found = _site_faults(tree)
        if count:
            counts[path] = count
            faults.extend(f"{path} {fault}" for fault in found)
    for path, floor in _FLOORS.items():
        assert counts.get(path, 0) >= floor, f"the census reads fewer sites than {floor}: {counts}"
    assert faults == [], faults


_CONVERTED = {
    "asyncio.timeout": """
async def f():
    try:
        async with asyncio.timeout(1):
            await cur.execute(sql)
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "asyncio.wait_for": """
async def f():
    try:
        await asyncio.wait_for(cur.execute(sql), 1)
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "TaskGroup": """
async def f():
    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(cur.execute(sql))
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "suppress": """
async def f():
    try:
        with contextlib.suppress(asyncio.CancelledError):
            await cur.execute(sql)
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "timeout in else": """
async def f():
    try:
        cur = await conn.cursor()
    except Exception:
        raise
    else:
        async with asyncio.timeout(1):
            await cur.execute(sql)
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "timeout in a handler": """
async def f():
    try:
        await cur.execute(sql)
    except Exception:
        await asyncio.wait_for(conn.rollback(), 1)
        raise
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "except*": """
async def f():
    try:
        async with asyncio.timeout(1):
            await cur.execute(sql)
    except* ValueError:
        raise
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "inner handler": """
async def f():
    try:
        try:
            await cur.execute(sql)
        except asyncio.CancelledError as exc:
            raise DeliveryError("stopped") from exc
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "conditional conversion": """
async def f():
    try:
        await cur.execute(sql)
    except BaseException as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise DeliveryError("stopped") from exc
        raise
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "conditional return": """
async def f():
    try:
        await cur.execute(sql)
    except asyncio.CancelledError:
        if stopping:
            return
        raise
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "bare except": """
async def f():
    try:
        await cur.execute(sql)
    except:
        pass
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "enclosing handler": """
async def f():
    try:
        await work()
    except asyncio.CancelledError:
        conn = await acquire()
        try:
            await conn.ping()
        finally:
            await _close_and_release(pool, conn, None)
""",
    "attribute call": """
async def f():
    try:
        await asyncio.wait_for(cur.execute(sql), 1)
    finally:
        await database._close_and_release(pool, conn, cur)
""",
    "closure": """
async def f():
    async def release():
        await _close_and_release(pool, conn, cur)

    try:
        await cur.execute(sql)
    finally:
        await release()
""",
}

# The shapes the live call sites use: an ordinary handler that converts an Exception, and a
# BaseException handler that releases and re-raises.
_CLEAN = {
    "finally": """
async def f():
    try:
        await cur.execute(sql)
    except Exception as exc:
        raise DeliveryError("failed") from exc
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "handled then released": """
async def f():
    try:
        await cur.execute(sql)
    except Exception:
        pass
    except BaseException:
        await _close_and_release(pool, conn, cur)
        raise
    await _close_and_release(pool, conn, cur)
""",
    "handler beside a converting sibling": """
async def f():
    try:
        await cur.execute(sql)
    except asyncio.CancelledError:
        await _close_and_release(pool, conn, cur)
        raise
    except BaseException:
        return None
""",
    "released in the else": """
async def f():
    try:
        await cur.execute(sql)
    except Exception:
        raise
    else:
        await _close_and_release(pool, conn, cur)
""",
}


@pytest.mark.parametrize("source", list(_CONVERTED.values()), ids=list(_CONVERTED))
def test_the_census_finds_each_conversion(source: str) -> None:
    """Positive controls: each form the census looks for is found."""
    count, faults = _site_faults(ast.parse(source))
    assert count == 1 and faults, faults


@pytest.mark.parametrize("source", list(_CLEAN.values()), ids=list(_CLEAN))
def test_the_census_passes_a_release_that_keeps_the_cancel(source: str) -> None:
    """Negative controls: shapes that keep the cancel in flight pass."""
    count, faults = _site_faults(ast.parse(source))
    assert count >= 1 and faults == [], faults
