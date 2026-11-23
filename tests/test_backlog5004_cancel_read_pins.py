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
from tests._ast_sites import callee_name, package_trees
from tests.test_backlog5010_database_gate_discard import _absorb_a_cancel


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
    """Once a handler ends, its exception is gone from ``sys.exc_info()``, so a release after it
    reads no cancel. The login role probe relies on this for an ``Exception`` it handles before its
    ordinary release; on a cancel it releases inside its ``except BaseException`` instead, where the
    cancel is still in flight, and re-raises. The cancel handled here only stands in for the state
    after a handler ends; the census below flags a cancel handled before a release."""
    try:
        raise asyncio.CancelledError
    except asyncio.CancelledError:
        pass  # deliberate: the handled cancel is the state under test
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
        await asyncio.wait_for(task, 5.0)
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

    await asyncio.wait_for(asyncio.to_thread(run), 5.0)
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
# engine module:
# walking up from the call to its function, at each level, the statements that may run before it
# hold none of the forms below. Those are the statements of a ``try`` that holds the call in a
# handler, ``else`` or ``finally``, and the earlier statements of the same block. No enclosing
# handler catches a cancel, unless the release is a statement of that handler's own body and the
# handler re-raises.
#
# What it does not see, at least: anything inside a function the code awaits; an exception a
# cleanup step raises in place of the cancel (an inner ``finally`` that awaits, say); a cancel type
# or converting call imported under another name; a ``suppress`` whose types are not spelled in the
# call; a release reached through ``functools.partial`` or a wrapper. ``_discard_to_pool`` and
# ``_discard_held`` are such wrappers, left out because their docstrings restrict them to a
# connection no worker thread can still be using, which leaves no running statement for a release to
# wait on.

_TARGET = "_close_and_release"
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
_CONVERTING_CALLS = frozenset({"timeout", "timeout_at", "Timeout", "wait_for", "TaskGroup"})
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_TRIES = (ast.Try, ast.TryStar)
_LOOPS = (ast.For, ast.AsyncFor, ast.While)
# The floors are the direct ``_close_and_release`` call sites counted when this census was
# written; a site that moves out of the census's reach lowers the count and fails here.
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


def _walk_body(nodes: list[ast.stmt], *, skip: tuple[type[ast.AST], ...] = ()) -> Iterator[ast.AST]:
    """Every node under ``nodes``, entering no ``def``, ``lambda`` or class, nor a ``skip`` node."""
    stops = (*_SCOPES, *skip)
    stack: list[ast.AST] = [n for n in nodes if not isinstance(n, stops)]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in ast.iter_child_nodes(node) if not isinstance(c, stops))


def _catches_a_cancel(handler: ast.ExceptHandler) -> bool:
    return handler.type is None or bool(_names(handler.type) & _CANCEL_TYPES)


def _converting_handler(handler: ast.ExceptHandler) -> bool:
    """A handler that catches a cancel and may end it: it does not end with a bare ``raise``, or on
    some branch it raises something else or leaves by ``return``, ``break`` or ``continue``. A
    ``raise`` inside a nested handler, and a ``break`` or ``continue`` of a nested loop, are that
    construct's own."""
    if not _catches_a_cancel(handler):
        return False
    last = handler.body[-1]
    if not (isinstance(last, ast.Raise) and last.exc is None):
        return True
    leaves = any(
        isinstance(n, ast.Return) or (isinstance(n, ast.Raise) and n.exc is not None)
        for n in _walk_body(handler.body, skip=(ast.ExceptHandler,))
    )
    loops = any(
        isinstance(n, (ast.Break, ast.Continue)) for n in _walk_body(handler.body, skip=_LOOPS)
    )
    return leaves or loops


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


def _before(node: ast.AST, child: ast.AST) -> list[ast.stmt]:
    """The statements of ``node`` that may run before ``child``, one of its direct children."""
    earlier: list[ast.stmt] = []
    for field in ("body", "orelse", "finalbody"):
        block = getattr(node, field, None)
        if isinstance(block, list) and child in block:
            earlier = block[: block.index(child)]
    if isinstance(node, _TRIES):
        handlers = [s for h in node.handlers for s in h.body]
        if child in node.finalbody:
            return [*node.body, *handlers, *node.orelse, *earlier]
        if child not in node.body:  # in the else: only the body ran first
            return [*node.body, *earlier]
    # In a handler, the try's body ran first, and the try supplies it at the next level up; a
    # sibling handler never runs before it.
    return earlier


def _site_faults(tree: ast.Module) -> tuple[int, list[str]]:
    """How many direct ``_close_and_release`` call sites ``tree`` holds, and each conversion the
    census finds on the way to one."""
    sites = [
        sub for sub in ast.walk(tree) if isinstance(sub, ast.Call) and callee_name(sub) == _TARGET
    ]
    if not sites:
        return 0, []
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    faults: list[str] = []
    for call in sites:
        node: ast.AST = call
        while node in parents and not isinstance(node, _SCOPES):
            child, node = node, parents[node]
            for what in _conversions(_before(node, child)):
                faults.append(f"line {call.lineno}: {what}")
            if isinstance(node, ast.ExceptHandler) and _catches_a_cancel(node):
                own = child in node.body and isinstance(child, ast.Expr)
                if not own or _converting_handler(node):
                    faults.append(f"line {call.lineno}: inside a handler of a cancel")
            if isinstance(node, _TRIES) and child in node.finalbody:
                for handler in node.handlers:
                    if _converting_handler(handler):
                        faults.append(f"line {call.lineno}: handler at line {handler.lineno}")
        outer = parents.get(node)
        while outer is not None and not isinstance(outer, _DEFS):
            outer = parents.get(outer)
        if outer is not None:
            # A release inside a closure is reached from wherever the closure is awaited, which
            # this walk cannot follow; such a site is reported rather than passed unread.
            faults.append(f"line {call.lineno}: inside a nested def the census cannot follow")
    return len(sites), faults


def test_no_call_site_turns_a_cancel_into_something_else() -> None:
    """The predicate reads the exception in flight, so a call site that turned the cancel into a
    ``TimeoutError``, swallowed it, or raised its own exception in its place would send a cancelled
    borrow down the ordinary path, which waits, through ``shield``, on a statement that may still be
    running. A borrow made inside an enclosing cancel handler reads that handler's cancel as its own
    instead. The census reads the forms named above; a green run is not proof that no other path
    does either."""
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
    "swallowed by an earlier statement": """
async def f():
    try:
        await cur.execute(sql)
    except asyncio.CancelledError:
        pass
    await _close_and_release(pool, conn, cur)
""",
    "asyncio.timeouts.Timeout": """
async def f():
    try:
        async with asyncio.timeouts.Timeout(deadline):
            await cur.execute(sql)
    finally:
        await _close_and_release(pool, conn, cur)
""",
    "borrow in a re-raising cancel handler": """
async def f():
    try:
        await work()
    except asyncio.CancelledError:
        conn = await acquire()
        try:
            await conn.ping()
        finally:
            await _close_and_release(pool, conn, None)
        raise
""",
}

# Shapes that keep the cancel in flight. The first two are the shapes the live call sites use;
# the rest are synthetic, each a near miss of a positive control above.
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
    "a module-level def under an if": """
if PLATFORM:
    async def f():
        try:
            await cur.execute(sql)
        finally:
            await _close_and_release(pool, conn, cur)
""",
    "a guarded rollback before the re-raise": """
async def f():
    try:
        await cur.execute(sql)
    except BaseException:
        try:
            await conn.rollback()
        except Exception as exc:
            raise DeliveryError("rollback failed") from exc
        for _ in range(2):
            break
        await _close_and_release(pool, conn, cur)
        raise
""",
}


@pytest.mark.parametrize("source", list(_CONVERTED.values()), ids=list(_CONVERTED))
def test_the_census_finds_each_conversion(source: str) -> None:
    """Positive controls: each form the census looks for is found."""
    _count, faults = _site_faults(ast.parse(source))
    assert faults, faults


@pytest.mark.parametrize("source", list(_CLEAN.values()), ids=list(_CLEAN))
def test_the_census_passes_a_release_that_keeps_the_cancel(source: str) -> None:
    """Negative controls: shapes that keep the cancel in flight pass."""
    count, faults = _site_faults(ast.parse(source))
    assert count >= 1 and faults == [], faults
