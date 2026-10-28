# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Row seals under ``vault_transit`` on a live SQL Server (BACKLOG #2592, ADR-draft decision D14).

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env),
like ``test_sqlserver_store.py``, whose clean-slate ``store`` fixture this file reuses. It lives in
its own file so the SQL Server store suite is left to its other writers, and CI's SQL Server
catch-all step lists it by name, since a gated file nobody lists never runs.

Each seal contract the in-process store key runs there is run here on a handle whose only key is in
a stand-in for Vault Transit (``tests/_transit_seal_fake.py``), with the control that shows a
forged session resolves once Transit's check is switched off. The SQLite and PostgreSQL suites run
the same set.
"""

from __future__ import annotations

import importlib
import os
from typing import Any

import pytest

from tests._transit_seal_fake import (
    FakeTransit,
    assert_a_forged_session_needs_the_transit_check,
    transit_cipher,
)
from tests.test_sqlserver_store import store  # noqa: F401  (the clean-slate fixture)

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)


@pytest.mark.parametrize("contract", ["session", "user", "role", "approval", "control"])
async def test_transit_row_seal_contracts(
    store: Any,  # noqa: F811  (the imported fixture, which clears the tables on the next entry)
    contract: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.row_seal import TransitRowSealer
    from messagefoundry.store.sqlserver import SqlServerStore

    cipher = transit_cipher(FakeTransit())
    keyed = await SqlServerStore.open(
        load_settings(environ=os.environ).store,
        cipher=cipher,
        audit_mac_fn=cipher.audit_mac_fn(),
    )
    try:
        assert isinstance(keyed.row_sealer(), TransitRowSealer)

        async def raw(sql: str, params: tuple[Any, ...]) -> None:
            async with keyed._pool.acquire() as conn:
                cur = await conn.cursor()
                await cur.execute(sql, params)
                await conn.commit()

        if contract == "control":
            await assert_a_forged_session_needs_the_transit_check(keyed, raw, monkeypatch)
        else:
            module = importlib.import_module(f"tests._{contract}_seal_contract")
            await getattr(module, f"assert_{contract}_seal_contract")(keyed, raw)
    finally:
        await keyed.close()
