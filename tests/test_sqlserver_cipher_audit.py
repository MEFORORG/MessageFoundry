# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``cipher-audit`` against a real SQL Server store (BACKLOG #1719).

The SQL Server twin of ``tests/test_postgres_cipher_audit.py``, which says what the plain leg cannot
prove and why this file writes every cell through its real writer on a KEYED handle. What differs
here is the dialect this backend's chunk read uses: no row-value comparison, so the key bound is
spelled column by column, and ``key`` and ``count`` are reserved words.

**Gated**, like the rest of the server-backend suite: skipped unless ``MEFOR_TEST_SQLSERVER`` is set
(plus ``MEFOR_STORE_*`` connection env). The leg's database is shared across test files, so this
clears the tables it writes before and after, through a KEYLESS handle opened while they are empty.
Every value is synthetic.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
from collections.abc import AsyncIterator
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

#: Every table this file's writes and keyed open touch, children before parents: SQL Server refuses
#: a DELETE while a row still refers to the one it removes.
_TABLES = (
    "message_events",
    "audit_log",
    "cipher_meta",
    "keyed_surface",
    "connection_event",
    "state",
    "state_version",
    "reference",
    "reference_version",
    "message_attachment",
    "attachment_chunk",
    "attachment",
    "queue",
    "response",
    "delivered_keys",
    "alert_instance",
    "search_presets",
    "messages",
    "sessions",
    "session_lineage",
    "webauthn_credentials",
    "known_login_addresses",
    "user_roles",
    "users",
)


async def _clear(handle: Any) -> None:
    for table in _TABLES:
        await handle._execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}")


@pytest.fixture
async def keyed() -> AsyncIterator[tuple[Any, str]]:
    """A keyed handle over a cleared store with every cipher cell written once, and its key."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import generate_key, make_cipher
    from messagefoundry.store.sqlserver import SqlServerStore
    from tests._keyed_reopen_contract import write_every_cell

    settings = load_settings(environ=os.environ).store
    janitor = await SqlServerStore.open(settings)
    try:
        await _clear(janitor)
        key = generate_key()
        store = await SqlServerStore.open(settings, cipher=make_cipher(key, write_v2=True))
        try:
            await write_every_cell(store)
            yield store, key
        finally:
            await store.close()
    finally:
        try:
            await _clear(janitor)
        finally:
            await janitor.close()


async def _audit(store: Any, **kwargs: Any) -> Any:
    from messagefoundry.store.cipher_cells import SQLSERVER_CIPHER_CELLS, audit_server_cipher_cells

    return await audit_server_cipher_cells(
        store, store.cipher(), cells=SQLSERVER_CIPHER_CELLS, **kwargs
    )


async def _sealed(store: Any, table: str, column: str) -> int:
    row = await store._fetchone(
        f"SELECT COUNT_BIG(*) AS n FROM [{table}] WHERE [{column}] LIKE 'mfenc:%'"
    )
    return 0 if row is None else int(row["n"])


@pytest.mark.parametrize("chunk_rows", [1, 500])
async def test_cipher_audit_opens_every_written_cell(
    keyed: tuple[Any, str], chunk_rows: int
) -> None:
    """Every cell of the inventory is present in this schema, and every sealed value in it opens
    with the AAD the inventory declares: the count per cell is the number sealed there, at one row
    a chunk or many. One row a chunk drives the column-by-column key bound on every composite key."""
    from messagefoundry.store.cipher_cells import (
        SQLSERVER_CIPHER_CELLS,
        server_cell_present,
        server_walk_tables,
    )
    from tests._keyed_reopen_contract import cells_in_scope

    store, _key = keyed
    columns = await store.cipher_walk_columns(server_walk_tables(SQLSERVER_CIPHER_CELLS))
    absent = [c for c in SQLSERVER_CIPHER_CELLS if not server_cell_present(c, columns)]
    assert not absent, f"the inventory names columns this schema lacks: {absent}"

    audit = await _audit(store, chunk_rows=chunk_rows)
    assert audit.key_mismatch is None
    assert audit.failed == 0 and audit.blob == 0 and audit.unmarked == 0, [
        (t.name, t.failed, t.first_failure) for t in audit.tallies
    ]
    for tally in audit.tallies:
        assert tally.opened == await _sealed(store, tally.table, tally.column), tally
    written = {f"{t}.{c}" for t, c in cells_in_scope("sqlserver.py")}
    unread = sorted(t.name for t in audit.tallies if t.name in written and t.opened == 0)
    assert not unread, f"written cells the audit opened nothing in: {unread}"


async def _flip(store: Any, table: str, column: str, key: str) -> Any:
    """Flip one bit in the GCM tag of the first sealed value of ``table.column`` by ``key``;
    return that row's key value."""
    row = await store._fetchone(
        f"SELECT TOP (1) [{key}] AS k, [{column}] AS v FROM [{table}]"
        f" WHERE [{column}] LIKE 'mfenc:%' ORDER BY [{key}]"
    )
    assert row is not None, f"no sealed {table}.{column} to corrupt"
    head, _, payload = str(row["v"]).rpartition(":")
    blob = bytearray(base64.b64decode(payload))
    blob[-1] ^= 0x01
    await store._execute(
        f"UPDATE [{table}] SET [{column}] = ? WHERE [{key}] = ?",
        (f"{head}:{base64.b64encode(bytes(blob)).decode()}", row["k"]),
    )
    return row["k"]


async def test_a_corrupted_cell_is_named_by_a_phi_free_locator(keyed: tuple[Any, str]) -> None:
    """A flipped byte in an id-keyed cell is named by its id; in ``state``, whose key can be PHI,
    by its position. Nothing else fails."""
    store, _key = keyed
    ident = await _flip(store, "messages", "raw", "id")
    await _flip(store, "state", "value", "namespace")
    audit = await _audit(store)
    by_name = {t.name: t for t in audit.tallies}
    assert audit.failed == 2, [(t.name, t.failed) for t in audit.tallies]
    assert (by_name["messages.raw"].first_failure or "").startswith(
        f"messages.raw id={ident} did not decrypt"
    )
    state = by_name["state.value"].first_failure or ""
    assert re.match(r"state\.value position=\d+ did not decrypt", state), state
    assert "SYNTH" not in state


async def test_a_damaged_marker_is_counted_as_unmarked(keyed: tuple[Any, str]) -> None:
    """A value whose marker is damaged, on a surface the keyed open recorded, is unmarked: the
    store refuses it at read, and the audit counts it rather than skipping it."""
    store, _key = keyed
    row = await store._fetchone(
        "SELECT TOP (1) id, raw FROM messages WHERE raw LIKE 'mfenc:%' ORDER BY id"
    )
    assert row is not None
    await store._execute(
        "UPDATE messages SET raw = ? WHERE id = ?", ("x" + str(row["raw"])[1:], row["id"])
    )
    audit = await _audit(store)
    raw = next(t for t in audit.tallies if t.name == "messages.raw")
    assert raw.unmarked == 1 and raw.failed == 0, raw
    assert raw.first_unmarked == f"messages.raw id={row['id']} carries no at-rest marker"


async def test_the_cipher_audit_command_reads_this_store(
    keyed: tuple[Any, str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end: ``messagefoundry cipher-audit`` on this backend, from ``MEFOR_STORE_*``, opens
    it read-only and PASSes with the service's key, and is KEY_MISMATCH from a shell without one.
    Run off the event loop: the command calls ``asyncio.run`` itself."""
    from messagefoundry.__main__ import main

    store, key = keyed
    # At enforce the CLI passes the enforcing posture (BACKLOG #2532), which refuses this leg's
    # plaintext container; at warn it passes none, as the store suite's CLI cases do.
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    rc = await asyncio.to_thread(main, ["cipher-audit", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out.strip().splitlines()[-1])
    assert rc == 0 and payload["status"] == "PASS", out
    assert payload["opened"] == sum(
        [await _sealed(store, *row["cell"].split(".")) for row in payload["cells"]]
    )
    assert "SYNTH" not in out

    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY")
    rc = await asyncio.to_thread(main, ["cipher-audit", "--json"])
    out = capsys.readouterr().out
    assert rc == 4 and json.loads(out.strip().splitlines()[-1])["status"] == "KEY_MISMATCH", out
