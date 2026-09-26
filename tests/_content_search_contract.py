# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the content-search row cap (BACKLOG #2068).

Deliberately **extra-free**, on the ``_session_cap_contract`` precedent: the live Postgres / SQL
Server suites import it *inside* their test functions, so it runs on legs that install only
``.[dev,postgres]`` / ``.[dev,sqlserver]``.

The defect it pins: ``search_messages`` read every candidate row, raw body included, before the
scan cap applied, so ``scan_limit`` bounded decrypts but not memory. The contract counts the rows
the candidate ``SELECT`` hands to ``_scan_rows``, which is the read the cap must bound.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from messagefoundry.store.content_search import SearchSpec, make_spec

_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
_SCAN_LIMIT = 3


async def assert_search_select_is_capped(store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed an empty store in three steps and count the rows each scan_limit-3 search fetches.

    Three channels are seeded in turn: exactly at the cap, one past it, and well past it. Each step
    checks the channel pre-filter path and the unfiltered read of everything so far. Only a read with
    more than scan_limit + 1 candidates can catch a dropped LIMIT: at scan_limit + 1 an unbounded
    read fetches the same count.
    """
    counts: list[int] = []
    real = store._scan_rows

    def _spy(spec: SearchSpec, candidates: Sequence[Any], limit: int) -> Any:
        counts.append(len(candidates))
        return real(spec, candidates, limit)

    monkeypatch.setattr(store, "_scan_rows", _spy)
    spec = make_spec(
        content="zzz-no-match", field_path=None, field_value=None, scan_limit=_SCAN_LIMIT
    )
    total = 0
    for seeded in (_SCAN_LIMIT, _SCAN_LIMIT + 1, 12):
        channel = f"IB_{seeded}"
        for i in range(seeded):
            await store.enqueue_message(
                channel_id=channel, raw=_RAW, deliveries=[], control_id=f"C{i}", now=100.0 + total
            )
            total += 1
        for kwargs, rows in (({"channel_id": channel}, seeded), ({}, total)):
            counts.clear()
            res = await store.search_messages(spec, **kwargs)
            case = f"{rows} candidates, {kwargs or 'unfiltered'}"
            assert counts == [min(rows, _SCAN_LIMIT + 1)], case
            assert res.scanned == _SCAN_LIMIT and res.matched == 0, case
            assert res.truncated is (rows > _SCAN_LIMIT), case
