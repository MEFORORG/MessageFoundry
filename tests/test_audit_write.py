# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one fail-soft audit write (vault BACKLOG #2260): it logs a store refusal at ERROR and swallows
it, raises a defect, and lets a cancellation through."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable

import pytest

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
        assert asyncio.run(write_audit_soft(_ok, log=_LOG, message="lost %s", args=("row",)))
    assert caplog.records == []


def test_a_store_refusal_is_logged_at_error_and_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR, logger=_LOG.name):
        written = asyncio.run(
            write_audit_soft(
                _raising(OSError("audit log full")),
                log=_LOG,
                message="lost %s row: %s",
                args=("config_reload", "detail"),
            )
        )
    assert written is False
    [record] = caplog.records
    assert record.levelno == logging.ERROR
    assert record.getMessage() == "lost config_reload row: detail"
    assert record.exc_info is not None and isinstance(record.exc_info[1], OSError)


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

    assert asyncio.run(write_audit_soft(_ok, log=_LOG, message="%s", args=args))
    assert seen == []
    with caplog.at_level(logging.ERROR, logger=_LOG.name):
        assert not asyncio.run(write_audit_soft(write, log=_LOG, message="lost %s", args=args))
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
