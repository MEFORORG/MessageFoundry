# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: storing a detached document (BACKLOG #5753).

``put_attachment`` is content-addressed, so two puts of one document are one copy. On the server
backends a concurrent identical pair both passed the dedup read and the second failed the upload on
the ``attachment`` primary key. Every backend must return the same ref to both and keep one header
and one set of chunks.

Extra-free on the ``_erased_reply_contract`` precedent, so the gated Postgres and SQL Server suites
run the same body. ``fetch`` runs one ``?``-placeholder query outside the store.
"""

from __future__ import annotations

import asyncio
from typing import Any

from tests._queue_tag_contract import RawFetch, RawSql

#: Synthetic, never a real document: three chunks so a lost or doubled chunk set shows.
CHUNKS = ("JVBERi0xLjQK", "U1lOVEhFVElD", "JSVFT0YK")


async def _attachment_rows(fetch: RawFetch, ref: str) -> tuple[int, int]:
    headers = await fetch("SELECT refcount FROM attachment WHERE id=?", (ref,))
    chunks = await fetch("SELECT seq FROM attachment_chunk WHERE attachment_id=?", (ref,))
    return len(headers), len(chunks)


async def assert_concurrent_identical_puts_store_one_copy(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    for attempt in range(5):
        chunks = (*CHUNKS, f"QVRURU1QVC{attempt}")
        refs = await asyncio.gather(
            *(store.put_attachment(iter(chunks), "application/pdf") for _ in range(3))
        )
        assert len(set(refs)) == 1, attempt
        assert await _attachment_rows(fetch, refs[0]) == (1, len(chunks)), attempt
        read = [c async for c in store.read_attachment(refs[0])]
        assert "".join(read) == "".join(chunks), attempt


async def assert_a_re_put_returns_the_same_copy(store: Any, fetch: RawFetch, _raw: RawSql) -> None:
    first = await store.put_attachment(iter(CHUNKS), "application/pdf")
    # Control: the first put stored one header and every chunk.
    assert await _attachment_rows(fetch, first) == (1, len(CHUNKS))
    again = await store.put_attachment(iter(CHUNKS), "application/pdf")
    assert again == first
    assert await _attachment_rows(fetch, first) == (1, len(CHUNKS))


CASES = (
    assert_concurrent_identical_puts_store_one_copy,
    assert_a_re_put_returns_the_same_copy,
)
