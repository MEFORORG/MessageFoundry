# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Postgres leg of the outbound-completion contracts (BACKLOG #5752, #5753, #5740).

**Gated** like ``tests/test_postgres_store.py``, whose clean-slate ``store`` fixture and pooled
``(raw, fetch)`` adapters this reuses.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.store.base import Store
from tests import _attachment_put_contract as attachment_put
from tests import _dead_letter_purge_contract as dead_letter_purge
from tests import _response_completion_contract as completion
from tests.test_postgres_store import _raw_adapters, pytestmark, store

__all__ = ["pytestmark", "store"]


@pytest.mark.parametrize("case", completion.CASES)
async def test_response_completion_contract(store: Store, case: Any) -> None:
    raw, fetch = _raw_adapters(store)
    await case(store, fetch, raw)


@pytest.mark.parametrize("case", attachment_put.CASES)
async def test_attachment_put_contract(store: Store, case: Any) -> None:
    raw, fetch = _raw_adapters(store)
    await case(store, fetch, raw)


@pytest.mark.parametrize("case", dead_letter_purge.CASES)
async def test_dead_letter_purge_contract(store: Store, case: Any) -> None:
    raw, fetch = _raw_adapters(store)
    await case(store, fetch, raw)
