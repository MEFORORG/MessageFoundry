# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DATABASE **source** live smoke against a real SQL Server (ADR 0003).

Sibling of [test_database_connector_integration.py](test_database_connector_integration.py), which
covers only the *destination* write path against a live driver. The source's poll/mark round-trip
(``_poll_once`` → ``_select`` real ``SELECT``/``fetchall`` → handler → ``_mark`` real ``UPDATE``) is
otherwise exercised only with a **faked pool** in
[test_database_transport.py](test_database_transport.py), so this suite closes the one gap a faked
pool can't: that the real aioodbc/ODBC round-trip actually reads rows out of a table and commits the
mark ``UPDATE`` against a live driver.

**One live test per process (see the destination file's docstring).** A *second* aioodbc test in the
same session destabilised the CI ODBC-18 driver at loop teardown (a ``fetchall`` segfault, then a
``SystemError`` from the corrupted loop), so this stays the **only** live test in its module and runs
in its **own** pytest invocation (a fresh process = one event loop = no cross-test corruption). It is
deliberately NOT a second test in the destination integration file. The source's other behaviours
(unmark-on-handler-failure, non-fatal poll errors, JSON body shaping) stay on the faked-driver unit
suite. (That docstring cited Python 3.13; we're on 3.14 now — the teardown instability still
reproduces on 3.14, see below.)

**One pool, opened once — driver-stability discipline.** The source path does *more* live driver work
than the single-write destination test: a ``SELECT`` + ``fetchall`` (the documented segfault trigger)
plus a mark ``UPDATE`` per row. Measured locally on Python 3.14 / ODBC Driver 18, opening a **second**
aioodbc pool, or **closing and reopening** a pool within the one test loop, intermittently corrupts
the driver at teardown (a ``SystemError`` from ``time.monotonic`` / "cannot acquire connection after
closing pool" / "attempt to use a closed connection"). So this test uses **exactly one** aioodbc pool,
opened once and closed once, and drives the source **on that same pool** (``src._pool`` injected) — the
source's own DSN build + ``_make_pool`` are byte-identical to the destination's and already covered by
the live destination test and the wiring unit suite, so the fidelity this test adds is the real
``SELECT``/``fetchall``/mark-``UPDATE`` round-trip, which it still exercises end-to-end. With one
opened-once pool the round-trip is stable across repeated local runs.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), so
it's a no-op locally and on PRs. Requires the ``sqlserver`` extra (``aioodbc`` + ODBC Driver 18).
Tables are uuid-named and **not dropped** (ephemeral container, unique names — skip the ``DROP``'s
exclusive schema lock). Every connector await is bounded by ``_DB_TIMEOUT`` so a stuck call fails fast.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import Any, TypeVar

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import DatabasePoll
from messagefoundry.transports import build_source
from messagefoundry.transports.database import DatabaseSource, _build_dsn, _make_pool

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run the SQL Server source round-trip",
)

# Hard ceiling on any single DB await: a stuck driver call fails the test in seconds rather than
# hanging the CI service-container leg until it is force-cancelled.
_DB_TIMEOUT = 60.0

_T = TypeVar("_T")


def _conn() -> dict[str, Any]:
    """Connector settings for the CI mssql service container (reuses the store job's ``MEFOR_STORE_*``).

    ``trust_server_certificate`` is on for the container's self-signed cert; the connector's TLS guard
    permits that MITM-able combination only because the job also sets ``MEFOR_ALLOW_INSECURE_TLS``."""
    return dict(  # noqa: C408
        server=os.environ.get("MEFOR_STORE_SERVER", "localhost"),
        port=int(os.environ.get("MEFOR_STORE_PORT", "1433")),
        database=os.environ.get("MEFOR_STORE_DATABASE", "MessageFoundry"),
        username=os.environ.get("MEFOR_STORE_USERNAME", "sa"),
        password=os.environ.get("MEFOR_STORE_PASSWORD", ""),
        trust_server_certificate=True,
    )


async def _bounded(coro: Awaitable[_T]) -> _T:  # noqa: UP047
    """Await ``coro`` under ``_DB_TIMEOUT`` so a hung driver call fails fast (see module docstring)."""
    return await asyncio.wait_for(coro, _DB_TIMEOUT)


@pytest.fixture
async def pool() -> AsyncIterator[Any]:
    """The single autocommit aioodbc pool for the whole test — opened once, closed once. Both the raw
    DDL/assertions *and* the source's poll/mark run on it, so the test never opens a second pool or
    reopens one (the ODBC-18 / Python-3.14 driver instability described in the module docstring)."""
    p = await _make_pool(_build_dsn(_conn()), 3, autocommit=True)
    try:
        yield p
    finally:
        p.close()
        await p.wait_closed()


async def _exec(pool: Any, sql: str) -> None:
    async with pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(sql)


async def _rows(pool: Any, sql: str) -> list[tuple[Any, ...]]:
    async with pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(sql)
        return [tuple(r) for r in await cur.fetchall()]


class _RecordingHandler:
    """Records each body handed to it and returns None (the pipeline handler contract)."""

    def __init__(self) -> None:
        self.bodies: list[bytes] = []

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        return None


async def test_source_polls_and_marks_rows(pool: Any) -> None:
    # The full inbound round-trip against a live driver: a real SELECT + fetchall reads the two NEW rows,
    # each payload column is decoded to a body, and — only after the handler returns — the :id→? mark
    # UPDATE commits (autocommit pool). The source runs on the shared pool (see the module docstring);
    # this is the read+mark half of the round-trip the destination live test doesn't cover.
    table = f"mf_src_{uuid.uuid4().hex[:12]}"
    # Synthetic payloads only — never real PHI. Table is uuid-named and left undropped.
    await _exec(
        pool,
        f"CREATE TABLE {table} "
        "(id INT IDENTITY(1,1) PRIMARY KEY, payload NVARCHAR(200), status NVARCHAR(10))",
    )
    await _exec(
        pool, f"INSERT INTO {table} (payload, status) VALUES ('AAA', 'NEW'), ('BBB', 'NEW')"
    )

    src = build_source(
        Source(
            type=ConnectorType.DATABASE,
            settings=DatabasePoll(
                **_conn(),
                poll_statement=f"SELECT id, payload FROM {table} WHERE status='NEW' ORDER BY id",
                mark_statement=f"UPDATE {table} SET status='DONE' WHERE id=:id",
                body_column="payload",
            ).settings,
        )
    )
    assert isinstance(src, DatabaseSource)
    handler = _RecordingHandler()
    src._handler = handler
    src._pool = (
        pool  # drive the source on the one shared pool (module docstring: no 2nd/reopened pool)
    )
    try:
        await _bounded(src._poll_once())
    finally:
        src._pool = None  # detach before teardown — the fixture, not aclose(), owns/closes the pool

    # Both rows were read out of the live table, in id order, decoded per body_column.
    assert handler.bodies == [b"AAA", b"BBB"]
    # The :id→? mark UPDATE actually committed: no NEW rows remain and both rows are now DONE.
    counts = await _rows(
        pool,
        f"SELECT "
        f"(SELECT COUNT(*) FROM {table} WHERE status='NEW'), "
        f"(SELECT COUNT(*) FROM {table} WHERE status='DONE')",
    )
    assert counts == [(0, 2)]
