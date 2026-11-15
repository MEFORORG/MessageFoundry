# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The AES-GCM invocation bound's accounting under concurrency, cancellation and a failed first read
(BACKLOG #5608, ASVS 11.3.4).

Three ways the persisted add and the in-memory grant could come apart, each one an under-count:

* **Interleaved passes.** A settlement refund and a refill on one cipher, both computed from the same
  state, with their grants applied in the reverse of the database's order, left the cipher's figure a
  whole block BELOW the persisted total.
* **A cancellation between the add and the grant.** A refund the database committed with no grant
  left the cipher spending a reserve the store no longer held.
* **A failed first hydration.** It was logged and swallowed, so the cipher's figure stayed this
  process's own spend, and a key already at the ceiling kept encrypting.

The fake ``add`` below is the backend's atomic upsert-add, reduced to a counter; each test controls
only when its result comes back.
"""

from __future__ import annotations

import asyncio

import pytest

from messagefoundry.store.crypto import (
    _GCM_MAX_INVOCATIONS,
    _GCM_RESERVE_BLOCK,
    AesGcmCipher,
    CipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.gcm_bound import checkpoint_invocations, reserve_invocations_ahead


def _cipher() -> AesGcmCipher:
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    return cipher


class _Row:
    """One ``cipher_meta`` row: the add lands at once, its result returns after ``delay[count]``."""

    def __init__(self, total: int = 0) -> None:
        self.total = total
        self.delay: dict[int, float] = {}

    async def add(self, _key_id: str, count: int) -> int:
        self.total += count
        result = self.total
        await asyncio.sleep(self.delay.get(count, 0))
        return result


async def _hydrated_and_half_spent(row: _Row) -> tuple[AesGcmCipher, int]:
    """A hydrated cipher holding a 10,000 reserve the row has charged, with nothing yet spent.

    A refund of all but 10,000 of the first block stands in for spending it, so no test pays for tens
    of thousands of real encrypts; the cipher and the row agree afterwards, as after a real spend."""
    cipher = _cipher()
    await checkpoint_invocations(cipher, row.add)  # reserves and grants the first block
    refund = -(_GCM_RESERVE_BLOCK - 10_000)
    row.total += refund
    cipher.grant_invocations(refund, row.total)
    spent = 0
    assert cipher.invocation_settlement() == -10_000
    assert row.total + cipher.invocation_settlement() == spent
    return cipher, spent


async def test_a_refund_and_a_refill_on_one_cipher_never_under_count() -> None:
    row = _Row()
    cipher, spent = await _hydrated_and_half_spent(row)
    # The settlement's add lands first and returns last; the refill's lands second and returns first.
    row.delay = {-10_000: 0.05, _GCM_RESERVE_BLOCK: 0.0}
    settle = asyncio.ensure_future(checkpoint_invocations(cipher, row.add, settle=True))
    await asyncio.sleep(0)
    refill = asyncio.ensure_future(checkpoint_invocations(cipher, row.add))
    await asyncio.gather(settle, refill)
    assert cipher.cumulative_invocations() >= spent
    # And the cipher agrees with the row: what it would still settle squares the row with its spend.
    assert row.total + cipher.invocation_settlement() == spent


async def test_a_cancelled_settlement_still_applies_the_refund_it_committed() -> None:
    row = _Row()
    cipher, spent = await _hydrated_and_half_spent(row)
    row.delay = {-10_000: 0.05}
    settle = asyncio.ensure_future(checkpoint_invocations(cipher, row.add, settle=True))
    await asyncio.sleep(0.01)  # the refund is in the row; its result has not come back
    settle.cancel()
    with pytest.raises(asyncio.CancelledError):
        await settle
    assert row.total == spent, "the refund must have reached the row, or this proves nothing"
    # The grant was applied before the cancellation went through: no reserve is left to spend.
    assert cipher.invocation_settlement() == 0
    assert row.total + cipher.invocation_settlement() == spent


async def test_a_cancelled_refill_is_granted_once_and_not_reserved_again() -> None:
    row = _Row()
    cipher, _spent = await _hydrated_and_half_spent(row)
    row.delay = {_GCM_RESERVE_BLOCK: 0.05}
    refill = asyncio.ensure_future(checkpoint_invocations(cipher, row.add))
    await asyncio.sleep(0.01)
    refill.cancel()
    with pytest.raises(asyncio.CancelledError):
        await refill
    assert cipher.invocation_reserve_shortfall() == 0  # the block it paid for was granted


async def test_a_failed_first_hydration_fails_closed() -> None:
    async def _down(_key_id: str, _count: int) -> int:
        raise RuntimeError("db is down")

    cipher = _cipher()
    with pytest.raises(CipherError, match="persisted total"):
        await checkpoint_invocations(cipher, _down)
    with pytest.raises(CipherError, match="persisted"):
        cipher.encrypt("x")  # the key's lifetime count is unknown, so it seals nothing
    with pytest.raises(CipherError, match="persisted total"):
        await reserve_invocations_ahead(cipher, _down, 5)

    # A later pass that reads the row hydrates it; a key the row shows exhausted then refuses.
    exhausted = _Row(total=_GCM_MAX_INVOCATIONS)
    await checkpoint_invocations(cipher, exhausted.add)
    with pytest.raises(CipherError, match="invocation ceiling"):
        cipher.encrypt("x")


async def test_a_failure_after_hydration_is_still_logged_and_retried() -> None:
    row = _Row()
    cipher = _cipher()
    await checkpoint_invocations(cipher, row.add)
    cipher.encrypt("x")

    async def _down(_key_id: str, _count: int) -> int:
        raise RuntimeError("db is down")

    assert await checkpoint_invocations(cipher, _down, settle=True) == 1
    cipher.encrypt("y")  # hydrated, so a transient blip does not stop encrypts


async def test_a_strict_pass_fails_closed_even_on_a_hydrated_cipher() -> None:
    """A store open passes ``strict``: the cipher's figure may come from another store handle, and a
    failed read of THIS store's row must not leave it encrypting against that figure."""
    cipher = _cipher()
    await checkpoint_invocations(cipher, _Row().add)
    assert cipher.invocation_bound_hydrated

    async def _down(_key_id: str, _count: int) -> int:
        raise RuntimeError("db is down")

    with pytest.raises(CipherError, match="persisted total"):
        await checkpoint_invocations(cipher, _down, strict=True)
    # A strict pass reads the row even when the cipher's own reserve is healthy.
    exhausted = _Row(total=_GCM_MAX_INVOCATIONS)
    await checkpoint_invocations(cipher, exhausted.add, strict=True)
    with pytest.raises(CipherError, match="invocation ceiling"):
        cipher.encrypt("x")


async def test_a_strict_pass_against_a_row_another_handle_never_charged_never_lowers_the_count() -> (
    None
):
    """Round-2 review case: a cipher hydrated against one row, with real spend, then a strict pass
    against a fresh row. The fresh row's total alone would put the figure back near zero."""
    cipher = _cipher()
    await checkpoint_invocations(cipher, _Row().add)
    for _ in range(3):
        cipher.encrypt("x")
    before = cipher.cumulative_invocations()
    assert before == 3
    await checkpoint_invocations(cipher, _Row().add, strict=True)
    assert cipher.cumulative_invocations() >= before


async def test_a_settle_before_any_pass_leaves_the_cipher_able_to_encrypt() -> None:
    row = _Row()
    cipher = _cipher()
    assert await checkpoint_invocations(cipher, row.add, settle=True) == 0
    assert not cipher.invocation_bound_enabled
    cipher.encrypt("x")  # nothing was reserved, so nothing refuses
    assert row.total == 0
