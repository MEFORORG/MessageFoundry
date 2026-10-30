# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3495: the first keyed open seals a keyless store's live empty queue row.

The contract in ``tests/_keyless_blank_contract.py`` runs here on SQLite and from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py`` on their live legs. This file
adds the opt-out, the one-transaction property and a source gate that runs on every leg, because two
of the three backends need a live server and a skipped suite reads as green.
"""

from __future__ import annotations

import ast
import pathlib
import sqlite3
from typing import Any
from unittest.mock import patch

import pytest

from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.queue_tag import LIVE_INLINE_ROW
from tests import _keyless_blank_contract as contract
from tests._ast_sites import call_sites, named_func, parse_source
from tests._queue_tag_contract import RawFetch, RawSql

_STORE_DIR = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store"


def _adapters(db: pathlib.Path) -> tuple[RawFetch, RawSql]:
    """A connection per call, so a handle's own writer lock and open cursors play no part."""

    async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        conn = sqlite3.connect(db)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    return fetch, raw


@pytest.mark.parametrize("case", contract.CASES, ids=lambda c: c.__name__)
async def test_keyless_blank_contract(case: Any, tmp_path: pathlib.Path) -> None:
    db = tmp_path / "blank.db"
    key = generate_key()

    async def open_keyed() -> MessageStore:
        return await MessageStore.open(db, cipher=make_cipher(key, write_v2=True))

    fetch, raw = _adapters(db)
    keyless = await MessageStore.open(db)
    try:
        await case(keyless, open_keyed, fetch, raw)
    finally:
        await keyless.close()


async def _blank_row_at_rest(db: pathlib.Path) -> str:
    """A keyless store holding one live empty row, blank at rest; returns its message id."""
    keyless = await MessageStore.open(db)
    try:
        mid = await contract.outbound(keyless, "OB_KB", "")
    finally:
        await keyless.close()
    fetch, _ = _adapters(db)
    assert (await contract.row_of(fetch, mid))["payload"] == ""
    return mid


async def test_a_failed_seal_leaves_the_marker_unwritten(tmp_path: pathlib.Path) -> None:
    """The row and the marker commit together. A crash that sealed the row but kept no marker, or
    wrote the marker over a blank row, would leave the row refused forever, so the next open must
    still see an unsealed surface and finish the job."""
    db = tmp_path / "crash.db"
    mid = await _blank_row_at_rest(db)
    fetch, _ = _adapters(db)
    key = generate_key()

    failing = _failing_on_queue_payload(MessageStore._seal_surface)
    with (
        patch.object(MessageStore, "_seal_surface", failing),
        pytest.raises(RuntimeError, match="synthetic crash"),
    ):
        await MessageStore.open(db, cipher=make_cipher(key, write_v2=True))

    assert (await contract.row_of(fetch, mid))["payload"] == ""
    assert not await contract.marked(fetch)

    store = await MessageStore.open(db, cipher=make_cipher(key, write_v2=True))
    try:
        assert str((await contract.row_of(fetch, mid))["payload"]).startswith(MARKER_PREFIX)
        assert await contract.marked(fetch)
    finally:
        await store.close()


def _failing_on_queue_payload(seal: Any) -> Any:
    """``_seal_surface``, failing inside the seal's transaction on the queue payload only."""

    async def wrapped(self: MessageStore, table: str, column: str, *args: Any, **kw: Any) -> int:
        if (table, column) != ("queue", "payload"):
            return int(await seal(self, table, column, *args, **kw))

        def fail(_row: Any) -> bytes:
            raise RuntimeError("synthetic crash")

        return int(await seal(self, table, column, *args, **{**kw, "aad_of": fail}))

    return wrapped


async def test_the_opt_out_seals_a_blank_only_on_an_unsealed_surface(
    tmp_path: pathlib.Path,
) -> None:
    """``allow_unmarked_ciphertext`` reseals PLAINTEXT on a keyed surface. It does not extend to a
    blank, which carries no value to rescue and is what a plant looks like. On an unsealed surface
    the blank is sealed as it is without the opt-out."""
    db = tmp_path / "optout.db"
    mid = await _blank_row_at_rest(db)
    fetch, raw = _adapters(db)
    key = generate_key()

    store = await MessageStore.open(db, cipher=make_cipher(key, write_v2=True, allow_unmarked=True))
    await store.close()
    assert str((await contract.row_of(fetch, mid))["payload"]).startswith(MARKER_PREFIX)

    await raw("UPDATE queue SET payload='' WHERE message_id=?", (mid,))
    store = await MessageStore.open(db, cipher=make_cipher(key, write_v2=True, allow_unmarked=True))
    await store.close()
    assert (await contract.row_of(fetch, mid))["payload"] == ""


async def test_the_seal_reserves_the_blanks_on_the_invocation_bound(
    tmp_path: pathlib.Path,
) -> None:
    """A blank seal is a GCM invocation like any other, so the burst must reserve it (ASVS 11.3.4)."""
    db = tmp_path / "bound.db"
    await _blank_row_at_rest(db)
    seen: list[int] = []

    async def spy(_cipher: Any, _add: Any, count: int) -> None:
        seen.append(count)

    with patch("messagefoundry.store.store.reserve_invocations_ahead", spy):
        store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
        await store.close()
    assert 1 in seen  # the queue surface: no plaintext to seal, one blank


def test_the_live_row_literal_names_the_statuses_it_means() -> None:
    """The fragment is a literal so a backend can splice it, and the enum is what the rows hold."""
    assert OutboxStatus.PENDING.value in LIVE_INLINE_ROW
    assert OutboxStatus.INFLIGHT.value in LIVE_INLINE_ROW
    for terminal in (OutboxStatus.DONE, OutboxStatus.DEAD, OutboxStatus.CANCELLED):
        assert f"'{terminal.value}'" not in LIVE_INLINE_ROW


@pytest.mark.parametrize(
    ("module", "blank"),
    [
        ("store.py", "payload = ''"),
        ("postgres.py", "payload = ''"),
        # T-SQL pads trailing spaces before comparing, so `= ''` would match a whitespace value.
        ("sqlserver.py", "DATALENGTH([payload]) = 0"),
    ],
)
def test_every_backend_passes_the_blank_rows_to_its_queue_sweep(module: str, blank: str) -> None:
    """The queue pass of each backend's sweep names the live blank rows, and no other pass does."""
    tree = parse_source((_STORE_DIR / module).read_text(encoding="utf-8"))
    calls = call_sites(named_func(tree, "_encrypt_existing_rows"), "_seal_surface")
    with_blank = [call for call in calls if any(kw.arg == "blank_where" for kw in call.keywords)]
    assert len(calls) > 1  # the control: the walk found the sweep's passes
    assert len(with_blank) == 1
    [call] = with_blank
    assert [a.value for a in call.args[:2] if isinstance(a, ast.Constant)] == ["queue", "payload"]
    [keyword] = [kw for kw in call.keywords if kw.arg == "blank_where"]
    text = ast.unparse(keyword.value)
    assert blank in text and "LIVE_INLINE_ROW" in text
