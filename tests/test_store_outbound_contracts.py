# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQLite leg of the outbound-completion contracts (BACKLOG #5752, #5753, #5740).

The same bodies run on Postgres from ``tests/test_store_outbound_contracts_postgres.py`` and on SQL
Server from ``tests/test_store_outbound_contracts_sqlserver.py``, on their gated live legs.
"""

from __future__ import annotations

import inspect
import pathlib
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from tests import _attachment_put_contract as attachment_put
from tests import _dead_letter_purge_contract as dead_letter_purge
from tests import _response_completion_contract as completion
from tests._queue_tag_contract import RawFetch, RawSql


@pytest.fixture(params=["keyless", "keyed"])
async def store(request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> Any:
    cipher = make_cipher(generate_key(), write_v2=True) if request.param == "keyed" else None
    s = await MessageStore.open(tmp_path / "outbound_contracts.db", cipher=cipher)
    yield s
    await s.close()


def _fetch(store: MessageStore) -> RawFetch:
    async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        cur = await store._db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]

    return fetch


def _raw(store: MessageStore) -> RawSql:
    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        await store._db.execute(sql, params)
        await store._db.commit()

    return raw


@pytest.mark.parametrize("case", completion.CASES)
async def test_response_completion_contract(store: MessageStore, case: Any) -> None:
    await case(store, _fetch(store), _raw(store))


@pytest.mark.parametrize("case", attachment_put.CASES)
async def test_attachment_put_contract(store: MessageStore, case: Any) -> None:
    await case(store, _fetch(store), _raw(store))


@pytest.mark.parametrize("case", dead_letter_purge.CASES)
async def test_dead_letter_purge_contract(store: MessageStore, case: Any) -> None:
    await case(store, _fetch(store), _raw(store))


@pytest.mark.parametrize("cls", [PostgresStore, SqlServerStore])
def test_the_attachment_release_decrefs_exactly_what_it_deletes(cls: Any) -> None:
    """BACKLOG #5740: on a server backend a tally SELECT and a later DELETE read two snapshots, so
    the decref and the delete could cover different join rows. The release must take its counts
    from the DELETE itself; the race is not reproducible on demand, so the shape is pinned."""
    src = inspect.getsource(cls._release_message_attachments)
    assert "SELECT attachment_id" not in src, cls.__name__
    assert ("RETURNING attachment_id" in src) or ("OUTPUT deleted.attachment_id" in src)
    # The behavioural contract above runs on these backends only on their gated legs, so the
    # store-once release it needs is pinned here on every leg as well, before the payload blank.
    purge = inspect.getsource(cls.purge_dead_letters)
    assert purge.index("SET body_ref=NULL") < purge.index("UPDATE queue SET payload=''")
    assert "UPDATE shared_body SET refcount" in purge, cls.__name__


async def _bounded_store(tmp_path: pathlib.Path) -> tuple[MessageStore, AesGcmCipher]:
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    store = await MessageStore.open(
        tmp_path / "bound.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
    )
    if not cipher.invocation_bound_enabled:
        await store.close()
        raise AssertionError("the keyed store did not enable the AES-GCM invocation bound")
    return store, cipher


async def test_a_put_reserves_its_seals_before_spending_them(tmp_path: pathlib.Path) -> None:
    """BACKLOG #5753: every chunk seal is an AES-GCM invocation (ASVS 11.3.4). With the reserve
    spent, a put that seals without reserving first leaves the persisted total behind what the key
    actually spent, so an unclean exit would under-count."""
    store, cipher = await _bounded_store(tmp_path)
    try:
        before = await store.cipher_invocations(cipher.active_key_id)
        cipher.grant_invocations(-cipher._reserve_remaining, before)  # zero the reserve
        assert cipher.invocation_settlement() == 0
        await store.put_attachment(iter(attachment_put.CHUNKS), "application/pdf")
        # Positive would be an overspend no row accounts for; the reserve must lead.
        assert cipher.invocation_settlement() <= 0
        assert await store.cipher_invocations(cipher.active_key_id) >= before + len(
            attachment_put.CHUNKS
        )
    finally:
        await store.close()


async def test_a_dedup_put_seals_nothing(tmp_path: pathlib.Path) -> None:
    """BACKLOG #5753: a re-put of stored content keeps the one copy, so sealing its chunks first
    spends invocations on ciphertext that is then dropped."""
    store, cipher = await _bounded_store(tmp_path)
    try:
        spent = cipher.cumulative_invocations()
        await store.put_attachment(iter(attachment_put.CHUNKS), "application/pdf")
        # Control: the first put sealed one invocation per chunk.
        assert cipher.cumulative_invocations() == spent + len(attachment_put.CHUNKS)
        spent = cipher.cumulative_invocations()
        await store.put_attachment(iter(attachment_put.CHUNKS), "application/pdf")
        assert cipher.cumulative_invocations() == spent
    finally:
        await store.close()


@pytest.mark.parametrize("cls", [MessageStore, PostgresStore, SqlServerStore])
def test_every_backend_dedups_and_reserves_before_it_seals(cls: Any) -> None:
    """The server backends' behaviour runs only on their gated legs; this pins the order of the
    three steps on every leg. The dedup read and the reservation both come before the seal."""
    src = inspect.getsource(cls.put_attachment)
    dedup = src.index('"SELECT 1 FROM attachment WHERE id=')
    reserve = src.index("reserve_invocations_ahead(")
    seal = src.index("asyncio.to_thread(_seal, ")
    assert dedup < reserve < seal, cls.__name__
