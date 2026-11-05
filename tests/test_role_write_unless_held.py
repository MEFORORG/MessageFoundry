# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3085: the reconciler's role write is a compare-and-set on the roles it writes.

The store contract is in ``tests/_role_write_unless_held_contract.py``, which says why. This file
runs it on SQLite; the service half, two reconcilers applying one role revocation, is in
``tests/test_ad_session_reconcile.py``. Synthetic accounts only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from messagefoundry.store.store import MessageStore
from tests._role_write_unless_held_contract import (
    assert_concurrent_role_writes_write_once,
    assert_role_write_unless_held_contract,
)


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


async def test_the_role_write_writes_only_over_another_set(store: MessageStore) -> None:
    await assert_role_write_unless_held_contract(store)


async def test_two_concurrent_role_writes_of_one_set_write_once(store: MessageStore) -> None:
    await assert_concurrent_role_writes_write_once(store)
