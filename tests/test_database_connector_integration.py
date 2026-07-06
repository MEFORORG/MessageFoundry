# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DATABASE connector **live smoke** against a real SQL Server (ADR 0003).

The unit suite ([test_database_transport.py](test_database_transport.py)) fakes the pool, so it covers
the connector's *logic* (param translation, error classification, egress gating, response capture, the
poll/mark loop, ``db_lookup``) without a real driver. This suite closes the one gap a faked pool can't:
that the **real aioodbc/ODBC round-trip** actually works — the DSN the connector builds, ``?``-binding
into the Microsoft ODBC Driver 18, ``execute`` + ``commit``, and the reachability probe — against a
live SQL Server. It is what caught the malformed ``SERVER={host},port`` DSN that broke real TLS (#235).

**Scope is deliberately a single round-trip:** one parameterized write (create → ``send`` → read back).
It is intentionally the *only* live test — a **second** aioodbc test in the same session destabilises
the CI ODBC-18 / Python-3.13 driver (a response-capture ``fetchall`` on an ``INSERT … OUTPUT`` segfaulted
the driver thread at loop teardown, and even a trivial follow-up ``SELECT 1`` probe then failed with a
``SystemError`` raised from the corrupted event loop). One test = one event loop = no cross-test
corruption. The connector's other behaviors (response capture / poll-mark / ``db_lookup``) stay on the
faked-driver unit suite; this write path exercises the same DSN / pool / cursor / binding code every
connector in the family shares. Expanding live coverage is deferred until that driver instability is
understood (a separate per-test-process runner, or a different driver, would be the path).

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), so
it's a no-op locally and on PRs. The CI ``sql server`` service-container job sets the env (reusing the
same mssql container as the store suite) and runs it for real. Requires the ``sqlserver`` extra
(``aioodbc`` + ODBC Driver 18).

Robustness: raw DDL/assertions go through a **pooled** connection (acquire/release), mirroring the
store suite's proven shape — never a bare ``aioodbc.connect()`` + manual ``close()``. Tables are **not
dropped** (the container is ephemeral and names are unique, so we skip the ``DROP``'s exclusive schema
lock). Every connector await is bounded by ``_DB_TIMEOUT`` so a stuck driver call fails the test fast.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Awaitable
from typing import Any, AsyncIterator, TypeVar

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Database
from messagefoundry.transports import build_destination
from messagefoundry.transports.database import _build_dsn, _make_pool

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run the SQL Server connector round-trip",
)

# Hard ceiling on any single DB await: a stuck driver call fails the test in seconds rather than
# hanging the CI service-container leg until it is force-cancelled.
_DB_TIMEOUT = 60.0

_T = TypeVar("_T")


def _conn() -> dict[str, Any]:
    """Connector settings for the CI mssql service container (reuses the store job's ``MEFOR_STORE_*``).

    ``trust_server_certificate`` is on for the container's self-signed cert; the connector's TLS guard
    permits that MITM-able combination only because the job also sets ``MEFOR_ALLOW_INSECURE_TLS`` — the
    trusted-network dev/test escape this exact scenario exists for."""
    return dict(
        server=os.environ.get("MEFOR_STORE_SERVER", "localhost"),
        port=int(os.environ.get("MEFOR_STORE_PORT", "1433")),
        database=os.environ.get("MEFOR_STORE_DATABASE", "MessageFoundry"),
        username=os.environ.get("MEFOR_STORE_USERNAME", "sa"),
        password=os.environ.get("MEFOR_STORE_PASSWORD", ""),
        trust_server_certificate=True,
    )


async def _bounded(coro: Awaitable[_T]) -> _T:
    """Await ``coro`` under ``_DB_TIMEOUT`` so a hung driver call fails fast (see module docstring)."""
    return await asyncio.wait_for(coro, _DB_TIMEOUT)


@pytest.fixture
async def pool() -> AsyncIterator[Any]:
    """One autocommit aioodbc pool for raw DDL + assertions — acquire/release pooling mirrors the store
    suite's proven shape and avoids the bare-connection ``close()`` that once hung teardown."""
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


@pytest.fixture
async def table(pool: Any) -> str:
    """A fresh, uniquely-named table. Intentionally **not dropped**: the CI container is ephemeral and
    the uuid name avoids collisions, so we skip the ``DROP`` (an exclusive schema lock that can block on
    a lingering session and hang teardown)."""
    name = f"mf_ci_{uuid.uuid4().hex[:12]}"
    await _exec(
        pool,
        f"CREATE TABLE {name} (id INT IDENTITY(1,1) PRIMARY KEY, mrn NVARCHAR(50), val NVARCHAR(50))",
    )
    return name


async def test_destination_writes_row(pool: Any, table: str) -> None:
    # The full outbound round-trip: JSON body -> :name binding -> positional ?, execute + commit, then
    # read the row back. Exercises the real DSN, pool, cursor, and parameter binding the whole family
    # shares — and is what proved the SERVER=host,port DSN fix (#235) against a live SQL Server.
    dest = build_destination(
        Destination(
            name="OB_DB",
            type=ConnectorType.DATABASE,
            settings=Database(
                **_conn(), statement=f"INSERT INTO {table} (mrn, val) VALUES (:mrn, :val)"
            ).settings,
        )
    )
    try:
        result = await _bounded(dest.send(json.dumps({"mrn": "M1", "val": "V1"})))
    finally:
        await _bounded(dest.aclose())
    assert result is None  # capture_response defaults off → no DeliveryResponse
    assert await _rows(pool, f"SELECT mrn, val FROM {table}") == [("M1", "V1")]
