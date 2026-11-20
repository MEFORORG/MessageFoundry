# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What the Send and File tabs share about a generated batch.

A batch can be up to a million messages. Generating all of them before the worker starts ran on the
GUI thread and held every payload in memory at once, and a results row per message grew the table
without a bound (BACKLOG #5948, #5949). :func:`generated_items` is lazy, so the worker thread
generates each message as it sends it, and :data:`MAX_RESULT_ROWS` caps the rows a tab shows; the
tab's summary still counts every result.
"""

from __future__ import annotations

import random
from collections.abc import Iterator

from harness.mllp import SendItem
from messagefoundry_toolkit.generators import (
    _core,
    all_types,  # noqa: F401  (registers the built-in message types)
)

#: The most result rows a Send or File tab keeps in its table for one batch.
MAX_RESULT_ROWS = 10_000

#: The trigger choice that picks a trigger at random for each message.
RANDOM_TRIGGER = "(random across all)"


def generated_items(code: str, choice: str, count: int, rng: random.Random) -> Iterator[SendItem]:
    """Yield ``count`` generated ``code`` messages, numbered from 1. ``choice`` is a trigger, or
    :data:`RANDOM_TRIGGER` to pick one from ``rng`` per message. Runs on whichever thread iterates
    it, so ``rng`` must not be used elsewhere while it does."""
    triggers = _core.triggers_for(code)
    for i in range(1, count + 1):
        trigger = rng.choice(triggers) if choice == RANDOM_TRIGGER else choice
        payload = _core.generate_message(code, trigger, i)
        yield SendItem(i, code, trigger, _core.control_id(code, trigger, i), payload)
