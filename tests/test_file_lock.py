# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one exclusive OS lock helper (BACKLOG #2279 item 9) and the callers that share it."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry import file_lock, log_spool
from messagefoundry.api import tls
from messagefoundry.config import atomic_edit
from messagefoundry.pipeline import dr_backup


@pytest.fixture
def two_handles(tmp_path: Path) -> Iterator[tuple[int, int]]:
    path = tmp_path / "x.lock"
    first = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    second = os.open(path, os.O_RDWR)
    try:
        yield first, second
    finally:
        os.close(first)
        os.close(second)


def test_two_handles_in_one_process_exclude_each_other(two_handles: tuple[int, int]) -> None:
    first, second = two_handles
    assert file_lock.lock_exclusive(first) is True
    assert file_lock.lock_exclusive(second) is False  # contention is an answer, not an error
    file_lock.unlock(first)
    assert file_lock.lock_exclusive(second) is True
    file_lock.unlock(second)


def test_a_waiting_lock_is_taken_once_free(two_handles: tuple[int, int]) -> None:
    first, second = two_handles
    assert file_lock.lock_exclusive(first, wait=True) is True
    file_lock.unlock(first)
    assert file_lock.lock_exclusive(second, wait=True) is True
    file_lock.unlock(second)


def test_the_lock_names_one_range_whatever_the_file_position(
    two_handles: tuple[int, int],
) -> None:
    """``msvcrt.locking`` locks from the current position, so both calls seek to 0 first."""
    first, second = two_handles
    os.write(first, b"0123456789")  # leaves the position at 10
    assert file_lock.lock_exclusive(first) is True
    os.lseek(second, 5, os.SEEK_SET)
    assert file_lock.lock_exclusive(second) is False
    os.lseek(first, 7, os.SEEK_SET)
    file_lock.unlock(first)
    assert file_lock.lock_exclusive(second) is True
    file_lock.unlock(second)


def test_a_fault_that_is_not_contention_raises(tmp_path: Path) -> None:
    fd = os.open(tmp_path / "gone.lock", os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)  # a closed descriptor: EBADF, not another holder
    with pytest.raises(OSError):
        file_lock.lock_exclusive(fd)


def test_the_spool_still_reads_any_lock_fault_as_not_ours(tmp_path: Path) -> None:
    """The spool's own reading, kept across the extraction: a fault opens no spool rather than
    raising out of :meth:`LogSpool.open`."""
    fd = os.open(tmp_path / "gone.lock", os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)
    assert log_spool._try_lock(fd) is False


@pytest.mark.parametrize("module", [tls, atomic_edit], ids=["tls", "atomic-edit"])
def test_the_patched_lock_names_are_the_shared_helper(module: ModuleType) -> None:
    """These two keep a private alias because their tests patch ``_try_lock`` by name."""
    assert module._try_lock is file_lock.lock_exclusive


def test_the_dr_staging_lock_still_excludes_a_second_handle(tmp_path: Path) -> None:
    """dr_backup's two lock calls now go through :mod:`file_lock`; its release still drops it."""
    path = tmp_path / "staging.lock"
    first = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    second = os.open(path, os.O_RDWR)
    try:
        assert file_lock.lock_exclusive(first, wait=True)
        assert file_lock.lock_exclusive(second) is False
        dr_backup._unlock_and_close(first)  # never raises, and closes the handle
        assert file_lock.lock_exclusive(second) is True
        file_lock.unlock(second)
    finally:
        os.close(second)
