# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The audit chain's behaviour, stated once and run on all three store backends (vault BACKLOG #2594).

A local ``pytest`` run skips the SQL Server and PostgreSQL legs, so a rule tested only against SQLite
would first fail in CI, or never. Each case here is written against :class:`ChainBackend`, a small
adapter a backend's own test module supplies, so the SAME assertions run on:

* SQLite -- ``tests/test_audit_chain_genesis.py``, on every leg;
* PostgreSQL -- ``tests/test_postgres_store.py``, on the leg that sets ``MEFOR_TEST_POSTGRES``;
* SQL Server -- ``tests/test_sqlserver_store.py``, on the leg that sets ``MEFOR_TEST_SQLSERVER``.

What the cases pin:

* a store that holds a key requires every audit row keyed, from a genesis row that names its key;
* nothing in the database says where keying starts, so nothing there can be changed to move it;
* every row carries its sequence number inside its MAC, starting at 1 and rising by one;
* a handle with no key learns from the chain that it is keyed, and refuses to append to it;
* a key rotation still opens a new range inside the chain.

**What a chain walk cannot see, stated here because a test file is where it gets forgotten.** A tail
cut off the END leaves a shorter chain that still verifies, and so does a log emptied altogether.
Only an anchor held outside the database shows either. :func:`a_cut_tail_needs_an_outside_anchor`
pins both halves: the bare walk passing, and the anchored walk reporting.

The raw statements here are written by a connection that never holds a key. They carry no
parameters, so one text runs on all three backends; the values they embed are hex digests and
integers this module computed.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from messagefoundry.store.crypto import generate_key
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    audit_row_hash,
    parse_audit_genesis,
)

__all__ = ["CASES", "ChainBackend"]


@dataclass(frozen=True)
class ChainBackend:
    """What a case needs from one backend. Every handle it opens is on the SAME store."""

    name: str
    #: Open a handle that holds ``active`` (and the ``retired`` keys) as its audit keying secret.
    open_keyed: Callable[[str, tuple[str, ...]], Awaitable[Any]]
    #: Open a handle that holds no keying secret.
    open_keyless: Callable[[], Awaitable[Any]]
    #: Run one statement as a database writer that holds no key.
    execute: Callable[[str], Awaitable[None]]
    #: Read rows the same way.
    fetch: Callable[[str], Awaitable[Sequence[Mapping[str, Any]]]]
    #: Empty ``audit_log``.
    reset: Callable[[], Awaitable[None]]
    #: Whether two handles may open the same fresh store at the same moment. The server backends
    #: serialise that in the database; a test's SQLite file is opened one handle at a time.
    concurrent_open: bool = False


async def _seed(store: Any, tag: str, n: int) -> None:
    for i in range(n):
        await store.record_audit(tag, actor="u", detail=json.dumps({"n": i}), now=float(i + 1))


async def _chain(b: ChainBackend) -> list[dict[str, Any]]:
    rows = await b.fetch(
        "SELECT id, seq, ts, actor, action, channel_id, detail, client, row_hash"
        " FROM audit_log ORDER BY seq"
    )
    return [dict(r) for r in rows]


async def _recompute_without_a_key(b: ChainBackend) -> None:
    """Renumber the rows from 1 and recompute every ``row_hash`` as plain SHA-256: the most a writer
    with no key can do to make a changed chain look whole."""
    rows = await _chain(b)
    await b.execute("UPDATE audit_log SET seq = -seq")  # step aside from the UNIQUE constraint
    prev = ""
    for position, r in enumerate(rows, start=1):
        prev = audit_row_hash(
            prev,
            seq=position,
            ts=r["ts"],
            actor=r["actor"],
            action=r["action"],
            channel_id=r["channel_id"],
            detail=r["detail"],
            client=r["client"],
        )
        await b.execute(
            f"UPDATE audit_log SET seq = {position}, row_hash = '{prev}' WHERE id = {int(r['id'])}"
        )


async def an_untouched_keyed_chain_verifies(b: ChainBackend) -> None:
    """The control every other case leans on: a keyed store's chain opens with a genesis row naming
    its key, numbers its rows 1, 2, 3, ..., and verifies."""
    await b.reset()
    key = generate_key()
    store = await b.open_keyed(key, ())
    try:
        assert store.audit_chain_unkeyed() is False
        await _seed(store, "act", 3)
        ok, message = await store.verify_audit_chain()
        assert ok, f"{b.name}: {message}"
        seq, head = await store.audit_anchor()
    finally:
        await store.close()
    rows = await _chain(b)
    assert [r["seq"] for r in rows] == [1, 2, 3, 4], f"{b.name}: {[r['seq'] for r in rows]}"
    assert rows[0]["action"] == AUDIT_KEY_EPOCH_ACTION
    assert parse_audit_genesis(rows[0]["detail"]), f"{b.name}: row 1 must name its key"
    assert [r["action"] for r in rows[1:]] == ["act", "act", "act"]
    # The anchor is the newest row's sequence number and hash: the coordinate the MAC covers.
    assert (seq, head) == (4, rows[-1]["row_hash"])
    # A second open adopts the genesis row already there and writes no second one.
    store = await b.open_keyed(key, ())
    try:
        ok, message = await store.verify_audit_chain()
        assert ok, f"{b.name}: {message}"
    finally:
        await store.close()
    assert len(await _chain(b)) == 4


async def a_chain_recomputed_without_the_key_is_reported(b: ChainBackend) -> None:
    """A row altered, a row removed, and the whole chain renumbered and recomputed with no key. A
    keyed store reports it, and holds no state a writer could change to make it pass."""
    await b.reset()
    key = generate_key()
    store = await b.open_keyed(key, ())
    try:
        await _seed(store, "act", 5)
        ok, message = await store.verify_audit_chain()
        assert ok, f"{b.name}: the control must verify: {message}"
    finally:
        await store.close()
    await b.execute("UPDATE audit_log SET actor = 'someone_else' WHERE seq = 3")
    await b.execute("DELETE FROM audit_log WHERE seq = 5")
    await _recompute_without_a_key(b)
    store = await b.open_keyed(key, ())
    try:
        ok, message = await store.verify_audit_chain()
        assert not ok, f"{b.name}: a chain recomputed with no key verified: {message}"
        # A row the engine appends afterwards does not turn the report off.
        await store.record_audit("after", actor="u")
        ok, message = await store.verify_audit_chain()
        assert not ok, f"{b.name}: {message}"
    finally:
        await store.close()


async def keyless_rows_on_a_keyed_store_are_a_reported_break(b: ChainBackend) -> None:
    """Rows written with no key, then the store opened with one. The keyed handle reports the chain,
    sets its posture flag, rewrites nothing, and keys what it appends. The control is the same rows
    under the handle that wrote them."""
    await b.reset()
    keyless = await b.open_keyless()
    try:
        await _seed(keyless, "early", 2)
        ok, message = await keyless.verify_audit_chain()
        assert ok, f"{b.name}: the keyless control must verify: {message}"
    finally:
        await keyless.close()
    before = await _chain(b)
    store = await b.open_keyed(generate_key(), ())
    try:
        assert store.audit_chain_unkeyed() is True, f"{b.name}: the posture flag must be set"
        ok, message = await store.verify_audit_chain()
        assert not ok and "genesis row" in (message or ""), f"{b.name}: {message}"
        assert await _chain(b) == before, f"{b.name}: the open rewrote a row"
        await store.record_audit("late", actor="u", now=9.0)
        rows = await _chain(b)
        assert [r["seq"] for r in rows] == [1, 2, 3]
        unkeyed = audit_row_hash(
            rows[1]["row_hash"],
            seq=3,
            ts=9.0,
            actor="u",
            action="late",
            channel_id=None,
            detail=None,
        )
        assert rows[2]["row_hash"] != unkeyed, f"{b.name}: a keyed handle appended a keyless row"
        ok, message = await store.verify_audit_chain()
        assert not ok, f"{b.name}: a keyed row after keyless rows made the chain verify"
        ok, message = await store.roll_audit_key_epoch()
        assert not ok, f"{b.name}: a chain with no genesis row was rolled: {message}"
    finally:
        await store.close()


async def a_chain_with_its_genesis_row_removed_is_reported(b: ChainBackend) -> None:
    """The genesis row deleted and the rest recomputed with no key: the chain then looks like one that
    was never keyed. A store that holds a key reports it all the same."""
    await b.reset()
    key = generate_key()
    store = await b.open_keyed(key, ())
    try:
        await _seed(store, "act", 3)
    finally:
        await store.close()
    await b.execute("DELETE FROM audit_log WHERE seq = 1")
    await _recompute_without_a_key(b)
    store = await b.open_keyed(key, ())
    try:
        assert store.audit_chain_unkeyed() is True
        ok, message = await store.verify_audit_chain()
        assert not ok and "genesis row" in (message or ""), f"{b.name}: {message}"
    finally:
        await store.close()


async def a_renumbered_or_missing_row_is_reported(b: ChainBackend) -> None:
    """The sequence number is inside the MAC and must run 1, 2, 3, ... . A row taken out of the
    middle, and every number shifted, are each reported at the position where the numbers stop
    matching."""
    await b.reset()
    key = generate_key()
    store = await b.open_keyed(key, ())
    try:
        await _seed(store, "act", 4)
        ok, message = await store.verify_audit_chain()
        assert ok, f"{b.name}: the control must verify: {message}"
        await b.execute("DELETE FROM audit_log WHERE seq = 3")
        ok, message = await store.verify_audit_chain()
        assert not ok and "seq=3" in (message or ""), f"{b.name}: {message}"
        assert "sequence number 4 where 3 was expected" in (message or ""), f"{b.name}: {message}"
    finally:
        await store.close()

    await b.reset()
    store = await b.open_keyed(key, ())
    try:
        await _seed(store, "act", 3)
        await b.execute("UPDATE audit_log SET seq = seq + 1000")
        ok, message = await store.verify_audit_chain()
        assert not ok and "seq=1" in (message or ""), f"{b.name}: {message}"
    finally:
        await store.close()


async def a_cut_tail_needs_an_outside_anchor(b: ChainBackend) -> None:
    """Rows cut off the END. The bare walk still verifies the shorter chain: nothing inside the
    database can show that rows are missing from its tail. The anchor taken before the cut -- the
    newest row's sequence number and hash, held outside -- shows it, as an exact anchor and as a
    prefix. The control is the anchor against the untouched chain."""
    await b.reset()
    store = await b.open_keyed(generate_key(), ())
    try:
        await _seed(store, "act", 4)
        anchor = await store.audit_anchor()
        assert anchor[0] == 5  # the genesis row and four rows
        ok, message = await store.verify_audit_chain(expected_anchor=anchor)
        assert ok, f"{b.name}: {message}"
        ok, message = await store.verify_audit_chain(expected_prefix=anchor)
        assert ok, f"{b.name}: {message}"

        await b.execute("DELETE FROM audit_log WHERE seq > 3")
        ok, message = await store.verify_audit_chain()
        assert ok, f"{b.name}: a cut tail is not visible to the bare walk, by design: {message}"
        ok, message = await store.verify_audit_chain(expected_anchor=anchor)
        assert not ok and "truncated or rewritten" in (message or ""), f"{b.name}: {message}"
        ok, message = await store.verify_audit_chain(expected_prefix=anchor)
        assert not ok and "truncated or rewritten" in (message or ""), f"{b.name}: {message}"
    finally:
        await store.close()


async def a_handle_with_no_key_refuses_to_append_to_a_keyed_chain(b: ChainBackend) -> None:
    """The handle reads from the genesis row that the chain is keyed. It says its append would be
    refused, refuses it, writes nothing, and says it cannot verify the chain. The control is the same
    handle on an empty log, which may start a keyless chain."""
    await b.reset()
    keyless = await b.open_keyless()
    try:
        assert keyless.audit_append_refusal() is None, f"{b.name}: the control must allow an append"
    finally:
        await keyless.close()
    store = await b.open_keyed(generate_key(), ())
    try:
        await _seed(store, "act", 2)
    finally:
        await store.close()
    before = await _chain(b)
    keyless = await b.open_keyless()
    try:
        refusal = keyless.audit_append_refusal()
        assert refusal is not None and "genesis row" in refusal, f"{b.name}: {refusal}"
        try:
            await keyless.record_audit("keyless", actor="u")
        except RuntimeError as exc:
            assert "refusing to append a keyless audit row" in str(exc), f"{b.name}: {exc}"
        else:
            raise AssertionError(f"{b.name}: a handle with no key appended to a keyed chain")
        ok, message = await keyless.verify_audit_chain()
        assert not ok and "no store encryption key/MAC" in (message or ""), f"{b.name}: {message}"
    finally:
        await keyless.close()
    assert await _chain(b) == before, f"{b.name}: the refused append wrote a row"


async def a_key_rotation_opens_a_range_inside_the_chain(b: ChainBackend) -> None:
    """ADR 0193, unchanged in what it promises: a rotation appends one range row under the new key,
    the old range stays provable with its key dropped, and an edit inside it is still reported."""
    await b.reset()
    old, new = generate_key(), generate_key()
    store = await b.open_keyed(old, ())
    try:
        await _seed(store, "under-old", 2)
    finally:
        await store.close()
    store = await b.open_keyed(new, (old,))
    try:
        ok, message = await store.roll_audit_key_epoch()
        assert ok and "closed" in message, f"{b.name}: {message}"
        await _seed(store, "under-new", 2)
        ok, message = await store.roll_audit_key_epoch()
        assert ok and "already" in message, f"{b.name}: {message}"
    finally:
        await store.close()
    rows = await _chain(b)
    assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5, 6], f"{b.name}: {[r['seq'] for r in rows]}"
    assert [r["action"] for r in rows].count(AUDIT_KEY_EPOCH_ACTION) == 2  # genesis, one range row
    closes = json.loads(rows[3]["detail"])["closes"]
    assert (closes["from_seq"], closes["to_seq"], closes["rows"]) == (1, 3, 3), (
        f"{b.name}: {closes}"
    )
    store = await b.open_keyed(new, ())  # the old key dropped
    try:
        ok, message = await store.verify_audit_chain()
        assert ok, f"{b.name}: the chain must verify with the old key dropped: {message}"
        await b.execute("UPDATE audit_log SET actor = 'someone_else' WHERE seq = 2")
        ok, message = await store.verify_audit_chain()
        assert not ok, f"{b.name}: an edit in the dropped key's range verified: {message}"
    finally:
        await store.close()


async def two_opens_of_a_fresh_keyed_store_share_one_genesis_row(b: ChainBackend) -> None:
    """Every handle that opens an empty keyed store tries to start its chain. Exactly one genesis row
    results, and the chain both handles then append to verifies with numbers that never collide."""
    await b.reset()
    key = generate_key()
    if b.concurrent_open:
        first, second = await asyncio.gather(b.open_keyed(key, ()), b.open_keyed(key, ()))
    else:
        first = await b.open_keyed(key, ())
        second = await b.open_keyed(key, ())
    try:
        await asyncio.gather(_seed(first, "one", 3), _seed(second, "two", 3))
        ok, message = await first.verify_audit_chain()
        assert ok, f"{b.name}: {message}"
    finally:
        await first.close()
        await second.close()
    rows = await _chain(b)
    assert [r["seq"] for r in rows] == list(range(1, 8)), f"{b.name}: {[r['seq'] for r in rows]}"
    assert [r["action"] for r in rows].count(AUDIT_KEY_EPOCH_ACTION) == 1


#: Every case, for a backend's test module to parametrise over.
CASES: tuple[Callable[[ChainBackend], Awaitable[None]], ...] = (
    an_untouched_keyed_chain_verifies,
    a_chain_recomputed_without_the_key_is_reported,
    keyless_rows_on_a_keyed_store_are_a_reported_break,
    a_chain_with_its_genesis_row_removed_is_reported,
    a_renumbered_or_missing_row_is_reported,
    a_cut_tail_needs_an_outside_anchor,
    a_handle_with_no_key_refuses_to_append_to_a_keyed_chain,
    a_key_rotation_opens_a_range_inside_the_chain,
    two_opens_of_a_fresh_keyed_store_share_one_genesis_row,
)
