# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one fail-soft audit write (vault BACKLOG #2260): it logs a store refusal at ERROR and swallows
it, raises a defect when the caller asks, and lets a cancellation through. The call sites that
promise nothing escapes are pinned here too, since dropping their ``defects=()`` would pass every
other test."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.audit_write import AUDIT_WRITE_DEFECTS, write_audit_soft

_LOG = logging.getLogger("tests.audit_write")


def _raising(exc: BaseException) -> Callable[[], Awaitable[None]]:
    async def write() -> None:
        raise exc

    return write


async def _ok() -> None:
    return None


def test_a_written_row_returns_true_and_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=_LOG.name):
        assert asyncio.run(
            write_audit_soft(_ok, log=_LOG, message="lost %s", args=("row",), defects=())
        )
    assert caplog.records == []


async def _caller_named_like_a_call_site() -> bool:
    return await write_audit_soft(
        _raising(OSError("audit log full")),
        log=_LOG,
        message="lost %s row: %s",
        args=("config_reload", "detail"),
        defects=AUDIT_WRITE_DEFECTS,
    )


def test_a_store_refusal_is_logged_at_error_and_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR, logger=_LOG.name):
        written = asyncio.run(_caller_named_like_a_call_site())
    assert written is False
    [record] = caplog.records
    assert record.levelno == logging.ERROR
    assert record.getMessage() == "lost config_reload row: detail"
    assert record.exc_info is not None and isinstance(record.exc_info[1], OSError)
    # The record names the call site, not the helper, as it did before the copies were merged.
    assert record.funcName == "_caller_named_like_a_call_site"


def test_callable_args_are_read_only_on_a_failure(caplog: pytest.LogCaptureFixture) -> None:
    seen: list[str] = []
    built: str | None = None

    async def write() -> None:
        nonlocal built
        built = "half-built"
        raise RuntimeError("store refused")

    def args() -> tuple[object, ...]:
        seen.append("read")
        return (built,)

    assert asyncio.run(write_audit_soft(_ok, log=_LOG, message="%s", args=args, defects=()))
    assert seen == []
    with caplog.at_level(logging.ERROR, logger=_LOG.name):
        assert not asyncio.run(
            write_audit_soft(write, log=_LOG, message="lost %s", args=args, defects=())
        )
    assert seen == ["read"]
    assert caplog.records[-1].getMessage() == "lost half-built"


@pytest.mark.parametrize(
    "defect", [NotImplementedError(), RecursionError(), sqlite3.ProgrammingError()]
)
def test_a_defect_is_raised_not_logged(defect: Exception, caplog: pytest.LogCaptureFixture) -> None:
    assert isinstance(defect, AUDIT_WRITE_DEFECTS)
    # RuntimeError, the parent of the first two, is in the catch, so the defect check must win.
    with caplog.at_level(logging.ERROR, logger=_LOG.name), pytest.raises(type(defect)):
        asyncio.run(
            write_audit_soft(
                _raising(defect),
                log=_LOG,
                message="lost",
                errors=(RuntimeError, sqlite3.Error),
                defects=AUDIT_WRITE_DEFECTS,
            )
        )
    assert caplog.records == []


def test_defects_empty_swallows_a_defect_too(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger=_LOG.name):
        written = asyncio.run(
            write_audit_soft(_raising(NotImplementedError()), log=_LOG, message="lost", defects=())
        )
    assert written is False
    assert len(caplog.records) == 1


def test_a_fault_outside_the_catch_escapes(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger=_LOG.name), pytest.raises(ValueError):
        asyncio.run(
            write_audit_soft(
                _raising(ValueError("not a store refusal")),
                log=_LOG,
                message="lost",
                errors=(OSError,),
                defects=(),
            )
        )
    assert caplog.records == []


def test_a_cancellation_propagates() -> None:
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            write_audit_soft(
                _raising(asyncio.CancelledError()), log=_LOG, message="lost", defects=()
            )
        )


# --- call sites that promise nothing escapes ---------------------------------------------------


def _engine_whose_audit_raises(exc: Exception) -> Any:
    async def record_audit(*_a: object, **_k: object) -> None:
        raise exc

    return SimpleNamespace(
        store=SimpleNamespace(record_audit=record_audit),
        coordinator=SimpleNamespace(node_id="node-a"),
    )


def test_a_reload_row_defect_after_the_swap_reports_the_audit_step(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A raise here would turn a reload that ran into a 500 (BACKLOG #1940)."""
    engine = _engine_whose_audit_raises(NotImplementedError())
    with caplog.at_level(logging.ERROR, logger=app_module._log.name):
        failures = asyncio.run(
            app_module._record_reload_audit(
                engine,
                actor="alice",
                failed_steps=["references"],
                loaded=app_module._UNKNOWN_LOADED,
            )
        )
    assert failures == ["references", app_module._RELOAD_AUDIT_STEP]
    [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert record.funcName == "_record_reload_audit"


def test_a_refused_reload_row_defect_still_answers_the_refusal() -> None:
    engine = _engine_whose_audit_raises(sqlite3.ProgrammingError())
    status, _answer = asyncio.run(
        app_module._audit_refused_reload(
            engine, FileNotFoundError("gone"), actor="alice", requested="/x", dry_run=False
        )
    )
    assert status == 404


def test_a_gate_row_defect_is_logged_and_paged() -> None:
    """Some gate rows are written after a release executed; a raise would skip the page."""
    paged: list[tuple[str, str]] = []

    async def record_audit(*_a: object, **_k: object) -> None:
        raise RecursionError

    gate = object.__new__(ApprovalGate)
    gate._store = cast(Any, SimpleNamespace(record_audit=record_audit))
    gate._alert_sink = cast(
        Any,
        SimpleNamespace(audit_write_failed=lambda name, *, action: paged.append((name, action))),
    )
    asyncio.run(
        gate._record_audit_soft(
            "a1", "approval.too_early", actor="bob", detail="{}", client=None, context="refused"
        )
    )
    assert paged == [("approval:a1", "approval.too_early")]
