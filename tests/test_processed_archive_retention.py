# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The File source's `.processed` archive has a default-on age bound (BACKLOG #1188).

Owner ruling A2 of 2026-10-08: bound `.processed` by default, as a fourth auto-bound window at the
body window, keyed on archive time. `.error` deletion was not ruled on and is not swept.

What these tests hold the sweep to: it deletes only aged regular files directly in the archive
directory, keeps young ones, never touches a file outside it or reaches through a link, refuses an
archive directory that overlaps a watch or `.error` directory, and keys on the time the File source
archived the copy rather than on the drop's own mtime.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.retention_classification import PHI_RETENTION_WINDOWS
from messagefoundry.config.settings import RetentionSettings
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import ProcessedArchive
from messagefoundry.transports.file import FileSource

DAY = 86_400.0
#: The sweep's cutoff in these tests: anything archived more than 30 days before "now" goes.
_NOW = time.time()
_CUTOFF = _NOW - 30 * DAY


def _source(inbox: Path, **settings: object) -> FileSource:
    return FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), **settings})
    )


def _aged(path: Path, days: float, body: str = "MSH|^~\\&|SYNTHETIC") -> Path:
    """Write ``path`` with an mtime ``days`` before now."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="ascii")
    when = _NOW - days * DAY
    os.utime(path, (when, when))
    return path


def _never() -> bool:
    return False


def _prune(src: FileSource, protected: frozenset[Path] = frozenset()) -> int:
    return src._prune_processed(_CUTOFF, protected, _never)


def test_the_window_is_auto_bounded_at_the_body_window() -> None:
    """The ruling's 'at the body window': the default bound equals the body window's.

    Mutation: give the new window `auto_bound_days=90`. Red."""
    by_setting = {w.setting: w for w in PHI_RETENTION_WINDOWS}
    body = by_setting["[security].delete_message_bodies_after_days"]
    processed = by_setting["[retention].processed_archive_days"]
    assert processed.auto_bound_days is not None
    assert processed.auto_bound_days == body.auto_bound_days
    assert processed.level == "PL-1"
    assert RetentionSettings().processed_archive_days == 0  # unset; the gate supplies the bound


def test_a_negative_window_is_refused() -> None:
    with pytest.raises(ValueError, match=">= 0"):
        RetentionSettings(processed_archive_days=-1)


def test_the_file_source_is_a_processed_archive(tmp_path: Path) -> None:
    assert isinstance(_source(tmp_path / "in"), ProcessedArchive)


def test_aged_copies_go_and_young_ones_stay(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    src = _source(inbox)
    old = _aged(src.processed_dir / "old.hl7", 31)
    young = _aged(src.processed_dir / "young.hl7", 29)

    assert _prune(src) == 1
    assert not old.exists()
    assert young.exists()


def test_nothing_outside_the_archive_directory_is_touched(tmp_path: Path) -> None:
    """An undelivered drop, a `.error` copy and a file in a subdirectory are all old, and all stay.

    Mutation: make the sweep recursive, or point it at `src.directory`. Red."""
    inbox = tmp_path / "in"
    src = _source(inbox)
    drop = _aged(inbox / "waiting.hl7", 90)
    quarantined = _aged(src.error_dir / "bad.hl7", 90)
    nested = _aged(src.processed_dir / "sub" / "nested.hl7", 90)
    archived = _aged(src.processed_dir / "done.hl7", 90)

    assert _prune(src) == 1
    assert not archived.exists()
    assert drop.exists() and quarantined.exists() and nested.exists()


def test_a_link_in_the_archive_is_never_followed(tmp_path: Path) -> None:
    """A link put in `.processed` that names an old file outside it: the outside file stays.

    Mutation: test `entry.is_file()` with links followed and unlink the resolved target. Red."""
    inbox = tmp_path / "in"
    src = _source(inbox)
    outside = _aged(tmp_path / "elsewhere" / "keep.hl7", 90)
    src.processed_dir.mkdir(parents=True)
    link = src.processed_dir / "link.hl7"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"cannot create a symbolic link here: {exc}")

    assert _prune(src) == 0
    assert outside.exists()


def test_a_linked_archive_directory_below_the_watch_root_is_refused(tmp_path: Path) -> None:
    """`.processed` replaced by a link to another directory: nothing there is deleted."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    elsewhere = tmp_path / "elsewhere"
    outside = _aged(elsewhere / "keep.hl7", 90)
    try:
        (inbox / ".processed").symlink_to(elsewhere, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"cannot create a symbolic link here: {exc}")
    src = _source(inbox)

    assert _prune(src) == 0
    assert outside.exists()


@pytest.mark.parametrize("subdir", [".", ".."])
def test_an_archive_directory_holding_the_watch_directory_is_refused(
    tmp_path: Path, subdir: str, caplog: pytest.LogCaptureFixture
) -> None:
    """`processed_subdir = "."` would make every undelivered drop an 'archive'. Refused, with one
    warning however many passes run.

    Mutation: drop the overlap guard. Red: the waiting drop is deleted."""
    inbox = tmp_path / "in"
    src = _source(inbox, processed_subdir=subdir)
    drop = _aged(inbox / "waiting.hl7", 90)

    assert _prune(src) == 0
    assert _prune(src) == 0
    assert drop.exists()
    refusals = [r for r in caplog.records if "skips this connection" in r.getMessage()]
    assert len(refusals) == 1
    assert "waiting.hl7" not in caplog.text


def test_an_archive_directory_shared_with_error_is_refused(tmp_path: Path) -> None:
    """`.error` deletion is unruled (#3335), so a `.processed` that IS `.error` deletes nothing."""
    inbox = tmp_path / "in"
    src = _source(inbox, processed_subdir="quarantine", error_subdir="quarantine")
    quarantined = _aged(src.error_dir / "bad.hl7", 90)

    assert _prune(src) == 0
    assert quarantined.exists()


@pytest.mark.parametrize("nested", [False, True])
def test_another_connections_watch_directory_is_protected(tmp_path: Path, nested: bool) -> None:
    """A's archive directory is, or holds, B's watch directory: A's sweep deletes nothing, not
    even its own old copy."""
    shared = tmp_path / "shared"
    b_inbox = shared / "b-inbox" if nested else shared
    a = _source(tmp_path / "a", processed_subdir=str(shared))
    b_drop = _aged(b_inbox / "waiting.hl7", 90)
    a_copy = _aged(a.processed_dir / "done.hl7", 90)

    assert _prune(a, frozenset({b_inbox})) == 0
    assert b_drop.exists() and a_copy.exists()


def test_a_missing_archive_directory_is_not_an_error(tmp_path: Path) -> None:
    assert _prune(_source(tmp_path / "in")) == 0


def test_the_deadline_stops_the_sweep_between_files(tmp_path: Path) -> None:
    src = _source(tmp_path / "in")
    for i in range(3):
        _aged(src.processed_dir / f"old-{i}.hl7", 90)

    assert src._prune_processed(_CUTOFF, frozenset(), lambda: True) == 0
    assert len(list(src.processed_dir.iterdir())) == 3


def test_archiving_stamps_the_archive_time(tmp_path: Path) -> None:
    """A drop whose own mtime is 90 days old is archived now, so it must not age out now.

    Mutation: drop `stamp=True` from `_after_processing`. Red: the copy keeps its 90-day mtime and
    the sweep deletes it the moment it lands."""
    inbox = tmp_path / "in"
    src = _source(inbox)
    src._prepare_subdirs()
    drop = _aged(inbox / "old-drop.hl7", 90)
    before = time.time()

    src._after_processing(drop)

    [copy] = list(src.processed_dir.iterdir())
    assert copy.stat().st_mtime >= before - 2
    assert copy.read_text(encoding="ascii") == "MSH|^~\\&|SYNTHETIC"  # bytes untouched
    assert _prune(src) == 0
    assert copy.exists()


def test_quarantine_is_not_stamped(tmp_path: Path) -> None:
    """Only the `.processed` move stamps; a `.error` move keeps the drop's own mtime."""
    inbox = tmp_path / "in"
    src = _source(inbox)
    src._prepare_subdirs()
    drop = _aged(inbox / "bad.hl7", 90)

    assert src._move(drop, src.error_dir)

    [copy] = list(src.error_dir.iterdir())
    assert copy.stat().st_mtime < _CUTOFF


# --- the retention pass ---------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "retention.db")
    yield s
    await s.close()


def _settings(**knobs: object) -> RetentionSettings:
    off = {"min_free_disk_mb": 0, "wal_checkpoint_seconds": 0, "audit_log_warn_rows": 0}
    return RetentionSettings.model_validate({**off, **knobs})


async def test_the_pass_sweeps_each_bound_archive_and_audits_the_count(
    store: MessageStore, tmp_path: Path
) -> None:
    a = _source(tmp_path / "a")
    b = _source(tmp_path / "b")
    gone = [_aged(a.processed_dir / "x.hl7", 31), _aged(b.processed_dir / "y.hl7", 31)]
    kept = _aged(b.processed_dir / "z.hl7", 1)
    runner = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (a, b),
    )
    assert runner.enabled

    result = await runner.run_once()

    assert result.processed_archives_deleted == 2
    assert not any(p.exists() for p in gone) and kept.exists()
    [row] = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    detail = json.loads(row["detail"])
    assert detail["processed_archive_days"] == 30
    assert detail["processed_archives_deleted"] == 2
    assert "x.hl7" not in row["detail"] and "y.hl7" not in row["detail"]


async def test_the_pass_protects_every_connections_directories(
    store: MessageStore, tmp_path: Path
) -> None:
    """The runner hands each archive the watch and `.error` directories of all of them.

    Mutation: pass `protected=frozenset()` in `_prune_processed_archives`. Red."""
    b = _source(tmp_path / "shared")
    a = _source(tmp_path / "a", processed_subdir=str(tmp_path / "shared"))
    b_drop = _aged(b.directory / "waiting.hl7", 90)
    runner = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (a, b),
    )

    result = await runner.run_once()

    assert result.processed_archives_deleted == 0
    assert b_drop.exists()


async def test_a_zero_window_sweeps_nothing(store: MessageStore, tmp_path: Path) -> None:
    src = _source(tmp_path / "in")
    old = _aged(src.processed_dir / "old.hl7", 365)
    runner = RetentionRunner(store, _settings(), clock=lambda: _NOW, archive_source=lambda: (src,))

    result = await runner.run_once()

    assert result.processed_archives_deleted == 0
    assert old.exists()
