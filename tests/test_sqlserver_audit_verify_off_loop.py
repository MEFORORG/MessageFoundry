# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQL Server ``verify_audit_chain`` walks the chain off the event loop (BACKLOG #5741).

Each row MAC can be a blocking Transit round trip, so a walk on the loop would stall that loop for
its whole length, during engine start or an ``audit-verify`` run. Only the walk moves: the rows are
still read whole and built on the loop, so nothing here says the verify is bounded.

Offline: the store has no connection and its ``_fetchall`` serves synthetic rows. What only the
hosted SQL Server leg can prove is the real query.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    AUDIT_TRANSIT_KEY_ID,
    AuditVerdict,
    audit_genesis_detail,
    verify_audit_rows,
)
from tests.test_asvs_transit_audit_mac_server_backends import (
    _bare,
    chained_rows,
    serve_rows,
    stub_transit_mac,
)

#: How long the MAC waits for the loop to prove it is still running. Only a failing run waits it out.
_LOOP_PROOF_TIMEOUT_SECONDS = 5.0


def _chain() -> list[dict[str, Any]]:
    """A valid Transit-keyed chain: a genesis row, then ordinary rows."""
    genesis = (AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID))
    return chained_rows(
        [genesis, ("act", "two"), ("act", "three"), ("act", "four")], mac=stub_transit_mac
    )


def _store(rows: list[dict[str, Any]], mac: Callable[[bytes], str]) -> Any:
    store = _bare("sqlserver", mac_fn=mac)
    serve_rows(store, rows)
    return store


def _facts(verdict: AuditVerdict) -> tuple[Any, ...]:
    """Everything a verdict carries: ``==`` on it alone ignores the flags and the row count."""
    return (
        verdict[0],
        verdict[1],
        verdict.key_unavailable,
        verdict.keyless_walk,
        verdict.prefix_break,
        verdict.rows,
    )


async def test_a_slow_mac_does_not_block_the_event_loop() -> None:
    """Each MAC waits on a callback only the loop can run, so a walk on the loop times out."""
    loop = asyncio.get_running_loop()

    def gated_mac(data: bytes, /) -> str:
        # A fresh event per call: a shared one, once set, would prove nothing for later rows.
        released = threading.Event()
        loop.call_soon_threadsafe(released.set)
        assert released.wait(_LOOP_PROOF_TIMEOUT_SECONDS), "the walk blocked the event loop"
        return stub_transit_mac(data)

    verdict = await _store(_chain(), gated_mac).verify_audit_chain()

    assert verdict[0] is True


@pytest.mark.parametrize("tamper", [False, True], ids=["good-chain", "tampered-chain"])
async def test_the_verdict_is_the_shared_walks_verdict(tamper: bool) -> None:
    rows = _chain()
    if tamper:
        rows[2]["detail"] = "rewritten"

    verdict = await _store(rows, stub_transit_mac).verify_audit_chain()
    direct = verify_audit_rows(rows, mac_keys={}, mac_fn=stub_transit_mac, capable=True)

    assert verdict[0] is (not tamper)
    assert _facts(verdict) == _facts(direct)


async def test_every_comparator_argument_still_reaches_the_walk() -> None:
    rows = _chain()
    head = rows[-1]["row_hash"]
    store = _store(rows, stub_transit_mac)

    assert (await store.verify_audit_chain(expected_anchor=(len(rows), head)))[0] is True
    assert (await store.verify_audit_chain(expected_anchor=(len(rows) + 1, head)))[0] is False
    cut = await store.verify_audit_chain(expected_prefix=(len(rows) + 1, head))
    assert cut[0] is False and cut.prefix_break is True
    assert (await store.verify_audit_chain(expected_rows=[(2, "not-the-hash")]))[0] is False


async def test_a_mac_failure_still_raises_to_the_caller() -> None:
    """A walk that could not run must not turn into a verdict when it crosses the thread."""

    class _MacDown(RuntimeError):
        pass

    def failing_mac(data: bytes, /) -> str:
        raise _MacDown

    with pytest.raises(_MacDown):
        await _store(_chain(), failing_mac).verify_audit_chain()
