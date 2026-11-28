# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared once-per-interval report throttle (BACKLOG #2592), which the layered search's refusal
log now holds with its own interval and bound instead of a copy (BACKLOG #5523 item 27)."""

from __future__ import annotations

import pytest

from messagefoundry.store import row_seal
from messagefoundry.store.row_seal import (
    SEAL_FAILURE_REPORT_INTERVAL_SECONDS,
    SEAL_FAILURE_TRACK_MAX,
    SealFailureThrottle,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(row_seal.time, "monotonic", c)
    return c


def test_a_key_is_due_once_per_its_interval(clock: _Clock) -> None:
    throttle = SealFailureThrottle(interval=3600.0, track_max=4)
    assert throttle.due(("p1", "malformed"))
    clock.now += 3599.0
    assert not throttle.due(("p1", "malformed"))
    assert throttle.due(("p1", "CipherError"))  # another cause is its own key
    clock.now += 1.0
    assert throttle.due(("p1", "malformed"))


def test_the_oldest_key_is_forgotten_past_the_bound(clock: _Clock) -> None:
    throttle = SealFailureThrottle(interval=3600.0, track_max=2)
    assert throttle.due("a") and throttle.due("b")
    assert throttle.due("c")  # "a" is forgotten to make room
    assert throttle.due("a")
    assert not throttle.due("c")  # still remembered


def test_the_defaults_are_the_seal_reporters_policy(clock: _Clock) -> None:
    throttle = SealFailureThrottle()
    assert throttle.due("row")
    clock.now += SEAL_FAILURE_REPORT_INTERVAL_SECONDS - 1.0
    assert not throttle.due("row")
    clock.now += 1.0
    assert throttle.due("row")
    for i in range(SEAL_FAILURE_TRACK_MAX):
        assert throttle.due(i)
    assert throttle.due("row")  # forgotten once the bound was passed
