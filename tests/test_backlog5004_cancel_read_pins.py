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
* a source census that no direct call site of ``_close_and_release``, in
  ``transports/database.py`` or ``pipeline/reference_sync.py``, turns a cancel into something else
  before the release reads it. The census is lexical: it reads the call site's own ``try``, not
  what the functions that ``try`` awaits do inside them.

Synthetic data only; no driver, no database.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError
from tests._ast_sites import call_sites, callee_name

_ROOT = Path(__file__).resolve().parents[1]
_SITES = (
    _ROOT / "messagefoundry" / "transports" / "database.py",
    _ROOT / "messagefoundry" / "pipeline" / "reference_sync.py",
)
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
    """Every ``BaseException`` that is not an ``Exception`` takes the cancel path. That includes an
    outer ``KeyboardInterrupt`` or ``SystemExit``: every caller's ``except Exception`` rollback was
    skipped for it too, so the connection goes back only once the gate has settled it, and the
    unwind does not wait on a statement that may still be running."""
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


async def _absorb_a_cancel() -> None:
    """Take a cancel and swallow it without ``uncancel()``, leaving ``cancelling()`` at one."""
    task = asyncio.current_task()
    assert task is not None
    asyncio.get_running_loop().call_soon(task.cancel)
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.sleep(1.0)
    assert task.cancelling() == 1, "the arm is vacuous: no cancel was absorbed"


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
    started = asyncio.Event()

    async def body() -> None:
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            seen.append(database._unwinding_a_cancel())

    def run() -> None:
        async def main() -> None:
            asyncio.get_running_loop().create_task(body())
            await started.wait()  # main returns; asyncio.run cancels the task left running

        asyncio.run(main())

    await asyncio.to_thread(run)
    assert seen == [True], seen


# --- what the docstring says the read does not see -----------------------------------------------


async def test_a_cancel_asyncio_timeout_converts_reads_as_its_timeout() -> None:
    """``asyncio.timeout`` turns its cancel into ``TimeoutError`` before an outer ``finally``, which
    then reads no cancel. That is why the census below finds no such conversion at a call site."""
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

# A handler naming one of these catches a cancel; a bare ``except:`` does too.
_CANCEL_TYPES = frozenset({"CancelledError", "BaseException", "KeyboardInterrupt", "SystemExit"})
# Calls that end a cancel or a timeout as a TimeoutError inside the code they wrap.
_CONVERTING_CALLS = frozenset({"timeout", "timeout_at", "wait_for"})


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


def _converting_handler(handler: ast.ExceptHandler) -> bool:
    """A handler that catches a cancel and does not end by re-raising it as it is."""
    catches = handler.type is None or bool(_names(handler.type) & _CANCEL_TYPES)
    last = handler.body[-1]
    reraises = isinstance(last, ast.Raise) and last.exc is None
    return catches and not reraises


def _walk_body(nodes: list[ast.stmt]) -> Iterator[ast.AST]:
    """Every node under ``nodes``, not entering a nested ``def``, ``lambda`` or class."""
    stack: list[ast.AST] = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                stack.append(child)


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


def _site_faults(tree: ast.Module) -> tuple[int, list[str]]:
    """How many direct call sites of ``_close_and_release`` ``tree`` holds, and each conversion
    found on the path from the start of its ``try`` to the call."""
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    sites = call_sites(tree, _TARGET, bare_only=True)
    faults: list[str] = []
    for call in sites:
        node: ast.AST = call
        while node in parents and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            child, node = node, parents[node]
            if isinstance(node, ast.ExceptHandler) and _converting_handler(node):
                faults.append(f"line {call.lineno}: inside a handler that ends a cancel")
            if isinstance(node, ast.Try) and child not in node.body:
                # The release is in this try's finally or handler: what the try runs before it
                # is what could turn a cancel into something else on the way there.
                for what in _conversions(node.body):
                    faults.append(f"line {call.lineno}: {what}")
                for handler in node.handlers:
                    if handler is not child and _converting_handler(handler):
                        faults.append(f"line {call.lineno}: handler at line {handler.lineno}")
    return len(sites), faults


@pytest.mark.parametrize("path", _SITES, ids=lambda p: p.name)
def test_no_call_site_turns_a_cancel_into_something_else(path: Path) -> None:
    """The predicate reads the exception in flight, so a call site that turned the cancel into a
    ``TimeoutError``, swallowed it, or raised its own exception in its place would send a cancelled
    borrow down the ordinary path, which waits, through ``shield``, on a statement that may still be
    running. The predicate's docstring states that no call site in these two modules does this."""
    count, faults = _site_faults(ast.parse(path.read_text(encoding="utf-8")))
    assert count >= 1, f"the census is vacuous: no {_TARGET} call found in {path.name}"
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
    "suppress": """
async def f():
    try:
        with contextlib.suppress(asyncio.CancelledError):
            await cur.execute(sql)
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
    "own handler": """
async def f():
    try:
        await cur.execute(sql)
    except BaseException:
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
}

_CLEAN = """
async def f():
    try:
        await cur.execute(sql)
    except Exception:
        raise
    except BaseException:
        await _close_and_release(pool, conn, cur)
        raise
    finally:
        await _close_and_release(pool, conn, cur)
"""


@pytest.mark.parametrize("source", list(_CONVERTED.values()), ids=list(_CONVERTED))
def test_the_census_finds_each_conversion(source: str) -> None:
    """Positive controls: each form the census forbids is found."""
    count, faults = _site_faults(ast.parse(source))
    assert count == 1 and faults, faults


def test_the_census_passes_a_release_that_re_raises_the_cancel() -> None:
    """Negative control: the shapes the live call sites use pass."""
    assert _site_faults(ast.parse(_CLEAN)) == (2, [])
