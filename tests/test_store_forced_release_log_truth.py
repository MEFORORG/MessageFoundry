# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5720: what a failed store open's cleanup and the AES-GCM invocation bound write to the
log.

* A forced release that itself raised was reported as having released what the open built
  (engine PR 3140, the w1-219 branch's last-round note).
* The invocation bound's two fail-soft WARNINGs carried the add's traceback, whose message a
  driver may fill with a path or a value (engine PR 2941 open item 4; CLAUDE.md section 9).

Synthetic values only.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from messagefoundry.store import store as store_module
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.gcm_bound import checkpoint_invocations
from messagefoundry.store.store import _force_failed_open_release, cleanup_failed_open

_SECRET = "synthetic-row-value-5720"


def _cipher() -> AesGcmCipher:
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    return cipher


def _raising_force() -> None:
    raise OSError("synthetic forced release failure")


async def test_a_bound_cleanup_whose_forced_release_failed_does_not_say_it_released(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before the fix: the WARNING said what the open built "was released without waiting"."""
    monkeypatch.setattr(store_module, "FAILED_OPEN_CANCEL_BOUND_S", 0.05)
    unwedge = asyncio.Event()

    async def wedged_release() -> None:
        await unwedge.wait()

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        try:
            await cleanup_failed_open(
                asyncio.CancelledError(), wedged_release, _raising_force, cancels_before=0
            )
        finally:
            unwedge.set()
            for _ in range(10):  # let the abandoned cleanup finish before the test ends
                await asyncio.sleep(0)
    assert "did not finish within 0.05 s of a cancel" in caplog.text
    assert "forcing the release after a failed store open also failed (OSError)" in caplog.text
    assert "released without waiting" not in caplog.text
    assert "forcing its release failed" in caplog.text


async def test_a_failed_cleanup_whose_forced_release_failed_does_not_say_it_released(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Red before the fix: the ERROR said what the cleanup left "was released without waiting"."""

    async def failing_release() -> None:
        raise RuntimeError(_SECRET)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        await cleanup_failed_open(
            ValueError("open failed"), failing_release, _raising_force, cancels_before=0
        )
    assert "a failed store open's cleanup failed (RuntimeError)" in caplog.text
    assert "released without waiting" not in caplog.text
    assert "forcing its release failed, so what it had not closed may still be open" in (
        caplog.text
    )
    assert _SECRET not in caplog.text


async def test_a_cleanup_whose_forced_release_worked_still_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Control: a forced release that returned is still reported as a release."""
    released: list[str] = []

    async def failing_release() -> None:
        raise RuntimeError("synthetic cleanup failure")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        await cleanup_failed_open(
            ValueError("open failed"),
            failing_release,
            lambda: released.append("forced"),
            cancels_before=0,
        )
    assert released == ["forced"]
    assert "what it had not closed was released without waiting for it" in caplog.text


def _warnings_from_the_bound(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == "messagefoundry.store.gcm_bound" and r.levelno >= logging.WARNING
    ]


async def test_a_failed_add_after_hydration_is_logged_by_class_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Red before the fix: the WARNING carried the add's traceback, and with it its message."""
    total = 0

    async def add(_key_id: str, count: int) -> int:
        nonlocal total
        total += count
        return total

    cipher = _cipher()
    await checkpoint_invocations(cipher, add)  # hydrates
    cipher.encrypt("x")  # something spent, so the settle below has an add to make

    async def down(_key_id: str, _count: int) -> int:
        raise RuntimeError(_SECRET)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.gcm_bound"):
        await checkpoint_invocations(cipher, down, settle=True)
    records = _warnings_from_the_bound(caplog)
    assert len(records) == 1
    assert records[0].exc_info is None
    assert "(RuntimeError)" in records[0].getMessage()
    assert _SECRET not in caplog.text


async def test_an_add_that_fails_after_its_pass_was_cancelled_is_logged_by_class_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Red before the fix: the WARNING carried the add's traceback, and with it its message."""
    cipher = _cipher()
    started = asyncio.Event()

    async def slow_then_down(_key_id: str, _count: int) -> int:
        started.set()
        await asyncio.sleep(0.05)
        raise RuntimeError(_SECRET)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.gcm_bound"):
        task = asyncio.ensure_future(checkpoint_invocations(cipher, slow_then_down))
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    records = _warnings_from_the_bound(caplog)
    assert len(records) == 1
    assert records[0].exc_info is None
    assert "(RuntimeError)" in records[0].getMessage()
    assert _SECRET not in caplog.text


def test_a_release_that_reports_a_failed_step_is_not_counted_as_released() -> None:
    """A release made of several steps, such as SQLite's, returns False when a step failed; before
    the fix that was counted as released, so the cleanup's log said what the open built was
    released (engine PR 3140 review round-32b0c94714 finding 3)."""
    assert _force_failed_open_release(lambda: False) is False
    assert _force_failed_open_release(lambda: None) is True
    assert _force_failed_open_release(lambda: True) is True
    assert _force_failed_open_release(None) is False
