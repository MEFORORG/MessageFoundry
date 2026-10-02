# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Give a container-gated rig test a server store with no accounts and an empty audit log.

NOT a test module (the leading underscore keeps pytest from collecting it).

A load rig signs in (:mod:`harness.load.rigadmin`): it provisions one Administrator in the store of
the engine it starts, with a password drawn for that process. ``provision-admin`` declines when the
store already has an enabled Administrator, and the rig then signs in as the one it holds.

On a server database that goes wrong in two ways, and both are ordinary in CI. The gated suites run
as SEPARATE pytest processes against ONE database, so the second rig test finds the first one's
Administrator and holds a different password. And a store suite that ran earlier may have left an
account of its own behind. Either way the rig's sign-in is refused.

So each gated rig test empties the account tables first, and the rig provisions its own.

**The audit log is emptied with them.** Provisioning writes an audit row, and it refuses to write
anything when that row would be refused. The rig nodes run with no store key, and a KEYED chain an
earlier suite left refuses a keyless append. The store suites clear the log before every test for
the same reason (``tests/test_postgres_store.py``, ``tests/test_sqlserver_store.py``); this list is
the slice of theirs that provisioning touches, child tables first.

SQLite needs none of this: every SQLite rig test serves a store in its own temporary directory.
"""

from __future__ import annotations

import os

# Children of ``users`` before it: on SQL Server a DELETE is refused while a row still refers to it.
_TABLES = ("audit_log", "sessions", "webauthn_credentials", "user_roles", "users")


async def reset_accounts(backend: str) -> None:
    """Empty the account tables and the audit log of the ``MEFOR_STORE_*`` store, where they exist.

    A fresh database has none of them; the rig's own provisioning creates them empty.
    """
    from messagefoundry.config.settings import load_settings

    settings = load_settings(environ=os.environ).store
    if backend == "postgres":
        from messagefoundry.store.postgres import PostgresStore

        pg = await PostgresStore.open(settings)
        try:
            async with pg._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT tablename FROM pg_tables WHERE schemaname = ANY (current_schemas(false))"
                )
                existing = {r["tablename"] for r in rows}
                targets = [t for t in _TABLES if t in existing]
                if targets:
                    await conn.execute(f"TRUNCATE {', '.join(targets)} RESTART IDENTITY CASCADE")
        finally:
            await pg.close()
        return
    if backend == "sqlserver":
        from messagefoundry.store.sqlserver import SqlServerStore

        ss = await SqlServerStore.open(settings)
        try:
            async with ss._pool.acquire() as conn:
                cur = await conn.cursor()
                for table in _TABLES:
                    await cur.execute(
                        f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}"
                    )
                await conn.commit()
        finally:
            await ss.close()
        return
    raise ValueError(f"no account reset for store backend {backend!r}")
