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

import errno
import json
import os
import stat
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.retention_classification import PHI_RETENTION_WINDOWS
from messagefoundry.config.settings import EgressSettings, RetentionSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    env,
)
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import base as transport_base
from messagefoundry.transports import file as file_transport
from messagefoundry.transports.base import (
    ArchiveGuard,
    ProcessedArchive,
    build_archive_guard,
    guarded_source_dirs,
)
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
    return src._prune_processed(_CUTOFF, build_archive_guard(protected), _never)


@pytest.fixture(autouse=True)
def _mtime_keyed(monkeypatch: pytest.MonkeyPatch) -> None:
    """POSIX keys the sweep on the later of mtime and ctime, and a test cannot make an old ctime, so
    these tests age a file by its mtime alone. The ctime test undoes this."""
    monkeypatch.setattr(file_transport, "_archived_at", lambda st: st.st_mtime)


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
    """`processed_subdir = "."` would make every undelivered drop an 'archive'. Refused, and
    warned about on every pass, since while it holds the archive has no age bound at all.

    Mutation: drop the overlap guard. Red: the waiting drop is deleted."""
    inbox = tmp_path / "in"
    src = _source(inbox, processed_subdir=subdir)
    drop = _aged(inbox / "waiting.hl7", 90)

    assert _prune(src) == 0
    assert _prune(src) == 0
    assert drop.exists()
    refusals = [r for r in caplog.records if "skips this connection" in r.getMessage()]
    assert len(refusals) == 2
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


def test_the_overlap_guard_folds_case(tmp_path: Path) -> None:
    """B's watch directory named in another case still protects it: a case-insensitive volume names
    one directory both ways, and folding on a case-sensitive one only refuses more.

    Mutation: drop `.casefold()` from `archive_dir_key`. Red on a case-sensitive volume."""
    shared = tmp_path / "Shared"
    a = _source(tmp_path / "a", processed_subdir=str(shared))
    a_copy = _aged(a.processed_dir / "done.hl7", 90)

    assert _prune(a, frozenset({tmp_path / "shared"})) == 0
    assert a_copy.exists()


@pytest.mark.parametrize("after_read", ["leave", "delete"])
def test_a_source_that_does_not_move_sweeps_nothing(tmp_path: Path, after_read: str) -> None:
    """Only a move archives. A leave source's `.processed` may hold another system's files.

    Mutation: drop the `after_read != "move"` return. Red."""
    src = _source(tmp_path / "in", after_read=after_read)
    theirs = _aged(src.processed_dir / "theirs.hl7", 90)

    assert _prune(src) == 0
    assert theirs.exists()


def test_a_read_only_aged_copy_is_removed(tmp_path: Path) -> None:
    """Windows refuses a plain delete of a file with the read-only attribute, where a POSIX unlink
    ignores the mode. The sweep must bound both alike.

    Mutation: drop `ignore_readonly=True` from `_win_delete_aged`. Red on Windows."""
    src = _source(tmp_path / "in")
    old = _aged(src.processed_dir / "old.hl7", 90)
    os.chmod(old, stat.S_IREAD)
    try:
        assert _prune(src) == 1
        assert not old.exists()
    finally:
        if old.exists():
            os.chmod(old, stat.S_IREAD | stat.S_IWRITE)


async def test_a_stopping_source_stops_its_sweep(tmp_path: Path) -> None:
    """A source that is stopping stops its sweep between files, deadline or not."""
    src = _source(tmp_path / "in")
    old = _aged(src.processed_dir / "old.hl7", 90)
    src._stop.set()

    assert (
        await src.prune_processed_archive(_CUTOFF, protected=ArchiveGuard(), deadline_hit=_never)
        == 0
    )
    assert old.exists()


def test_the_file_source_declares_its_guarded_directories(tmp_path: Path) -> None:
    """From configuration alone, so a stopped or other-shard inbound is protected too."""
    inbox = tmp_path / "in"
    config = Source(
        type=ConnectorType.FILE, settings={"directory": str(inbox), "error_subdir": "bad"}
    )

    assert guarded_source_dirs(config) == (inbox, inbox / "bad")


@pytest.mark.skipif(os.name == "nt", reason="POSIX keys on ctime; Windows stamps by handle")
def test_posix_ages_a_copy_from_its_ctime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A copy whose old mtime the stamp could not replace still ages from its archive: the move set
    its ctime, which nobody can set back.

    Mutation: make `_archived_at` return `st.st_mtime`. Red."""
    monkeypatch.undo()
    src = _source(tmp_path / "in")
    copy = _aged(src.processed_dir / "kept-mtime.hl7", 90)  # ctime is now

    assert _prune(src) == 0
    assert copy.exists()


def test_an_aliased_protected_directory_is_refused_once_opened(tmp_path: Path) -> None:
    """The guard names B's watch directory by another path that the path compare cannot join (here a
    link). The opened archive is recognised by identity.

    Mutation: drop the `_opened_id(dest) in guard.ids` check. Red."""
    real = tmp_path / "shared"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"cannot create a symbolic link here: {exc}")
    a = _source(tmp_path / "a", processed_subdir=str(real))
    a_copy = _aged(real / "done.hl7", 90)
    guard = ArchiveGuard(keys=frozenset({"unrelated"}), ids=build_archive_guard({alias}).ids)

    assert a._prune_processed(_CUTOFF, guard, _never) == 0
    assert a_copy.exists()


@pytest.mark.parametrize("opened", [None, (7, 0)])
def test_an_archive_directory_with_no_readable_identity_is_not_swept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opened: tuple[int, int] | None
) -> None:
    """The opened directory's identity cannot be read, or is inode 0, which the guard never records.
    Either way an alias of a guarded directory would pass the identity check, so nothing goes.

    Mutation: test only `_opened_id(dest) in guard.ids`. Red."""
    src = _source(tmp_path / "in")
    copy = _aged(src.processed_dir / "done.hl7", 90)
    monkeypatch.setattr(file_transport, "_opened_id", lambda dest: opened)

    assert _prune(src) == 0
    assert copy.exists()


def test_archived_at_is_the_later_of_mtime_and_ctime(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real key, which the autouse fixture replaces everywhere else.

    Mutation: return `st.st_mtime`, or `min(...)`. Red."""
    monkeypatch.undo()
    st = os.stat_result((0o100644, 1, 1, 1, 0, 0, 0, 0, 100, 200))  # mtime 100, ctime 200

    assert file_transport._archived_at(st) == 200
    assert (
        file_transport._archived_at(os.stat_result((0o100644, 1, 1, 1, 0, 0, 0, 0, 300, 200)))
        == 300
    )


def test_the_registry_runner_guards_an_unbound_file_inbound(tmp_path: Path) -> None:
    """`archive_guard_dirs` reads the configuration, so an inbound that never started is named."""
    inbox = tmp_path / "stopped"
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_STOPPED", ConnectionSpec(ConnectorType.FILE, {"directory": str(inbox)}), router="r"
        )
    )
    runner = RegistryRunner(reg, None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]

    assert runner.processed_archives() == ()
    assert runner.archive_guard_dirs() == (inbox, inbox / ".error")


def _runner(reg: Registry) -> RegistryRunner:
    return RegistryRunner(reg, None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]


def _file_inbound(name: str, inbox: Path, shard: str | None = None) -> InboundConnection:
    return InboundConnection(
        name,
        ConnectionSpec(ConnectorType.FILE, {"directory": str(inbox)}),
        router="r",
        shard=shard,
    )


def _file_outbound(name: str, out: Path) -> OutboundConnection:
    return OutboundConnection(name, ConnectionSpec(ConnectorType.FILE, {"directory": str(out)}))


def _refuse_stat_of(monkeypatch: pytest.MonkeyPatch, refused: Path) -> None:
    """Make `stat` of ``refused`` fail as an unreadable directory would, and nothing else."""
    real_stat = os.stat
    target = Path(os.path.realpath(refused))

    def refusing(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if isinstance(path, (str, os.PathLike)) and Path(path) == target:
            raise PermissionError(errno.EACCES, "refused")
        return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "stat", refusing)


def test_the_guard_names_a_sibling_engine_shards_inbound(tmp_path: Path) -> None:
    """Under `serve --shard` the runner's registry holds only this shard's inbounds; the guard still
    names the sibling shard's watch and `.error` directories, from the whole config's specs.

    Mutation: read `self.registry.inbound` in `archive_guard_dirs`, or drop `all_inbound_specs`
    from the shard filter. Red."""
    reg = Registry()
    reg.add_inbound(_file_inbound("IB_MINE", tmp_path / "mine", shard="s1"))
    reg.add_inbound(_file_inbound("IB_SIBLING", tmp_path / "sibling", shard="s2"))
    s1 = filter_registry_for_shard(reg, "s1")
    assert set(s1.inbound) == {"IB_MINE"}  # the precondition the guard must not rely on

    dirs = _runner(s1).archive_guard_dirs()

    assert dirs is not None
    assert tmp_path / "sibling" in dirs and tmp_path / "sibling" / ".error" in dirs
    assert tmp_path / "mine" in dirs


def test_the_guard_names_every_file_outbound_target_directory(tmp_path: Path) -> None:
    """A File outbound's target directory holds deliveries awaiting a partner's pickup.

    Mutation: drop the outbound loop in `archive_guard_dirs`. Red."""
    reg = Registry()
    reg.add_outbound(_file_outbound("OB_PARTNER", tmp_path / "out"))

    assert _runner(reg).archive_guard_dirs() == (tmp_path / "out",)


def test_an_unresolvable_outbound_directory_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An outbound whose settings cannot be resolved makes the guard None, as an inbound's does."""
    reg = Registry()
    reg.add_outbound(_file_outbound("OB_PARTNER", tmp_path / "out"))
    runner = _runner(reg)

    def unresolved(*args: object, **kwargs: object) -> object:
        raise ValueError("unresolved")

    monkeypatch.setattr(wiring_runner, "resolve_env_settings", unresolved)

    assert runner.archive_guard_dirs() is None


def test_a_guarded_directory_whose_identity_cannot_be_read_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A guarded directory that exists but cannot be stat'ed adds no identity, so an alias of it
    would pass the check once the archive is open. The guard records it as unresolved.

    Mutation: `continue` on every stat failure in `build_archive_guard`. Red."""
    guarded = tmp_path / "share"
    guarded.mkdir()
    _refuse_stat_of(monkeypatch, guarded)

    assert build_archive_guard({guarded}).unresolved == {guarded}


def _as_credentialed(src: FileSource, monkeypatch: pytest.MonkeyPatch) -> None:
    """Mark ``src`` as running under an alternate credential, so it re-reads unresolved directories.
    The blocking half under test runs on the calling thread either way."""
    monkeypatch.setattr(src, "_cred_ctx", object())


@pytest.mark.parametrize("credentialed", [False, True])
def test_an_archive_that_cannot_read_an_unresolved_directory_sweeps_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credentialed: bool
) -> None:
    """Without a credential the archive refuses outright; with one it reads the unresolved directory
    again under its own identity and still cannot.

    Mutation: drop the `unreadable` refusal in `_prune_processed`. Red."""
    src = _source(tmp_path / "in")
    if credentialed:
        _as_credentialed(src, monkeypatch)
    copy = _aged(src.processed_dir / "done.hl7", 90)
    other = tmp_path / "share"
    other.mkdir()
    _refuse_stat_of(monkeypatch, other)

    assert src._prune_processed(_CUTOFF, ArchiveGuard(unresolved=frozenset({other})), _never) == 0
    assert copy.exists()


def test_an_archive_that_can_read_an_unresolved_directory_sweeps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory the pass could not read, which this archive's alternate credential can reach,
    does not stop this archive's sweep: its identity is used."""
    src = _source(tmp_path / "in")
    _as_credentialed(src, monkeypatch)
    copy = _aged(src.processed_dir / "done.hl7", 90)
    other = tmp_path / "share"
    other.mkdir()

    assert src._prune_processed(_CUTOFF, ArchiveGuard(unresolved=frozenset({other})), _never) == 1
    assert not copy.exists()


def test_an_unreadable_directory_that_is_the_archive_is_refused_once_reread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pass could not read B's watch directory; A's archive re-reads it, finds it is its own
    archive directory, and refuses (here by the resolved path; identity covers an alias)."""
    shared = tmp_path / "shared"
    a = _source(tmp_path / "a", processed_subdir=str(shared))
    _as_credentialed(a, monkeypatch)
    drop = _aged(shared / "waiting.hl7", 90)
    guard = ArchiveGuard(keys=frozenset({"unrelated"}), unresolved=frozenset({shared}))

    assert a._prune_processed(_CUTOFF, guard, _never) == 0
    assert drop.exists()


def test_only_the_directory_settings_are_resolved_for_the_guard(tmp_path: Path) -> None:
    """A not-deployed outbound's unrelated env() secret, missing in this environment, is not read and
    does not switch the sweep off.

    Mutation: resolve `spec.settings` whole in `archive_guard_dirs`. Red."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "OB_PARKED",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "out"), "credential_password": env("NOT_SET_HERE")},
            ),
            deployed=False,
        )
    )

    assert _runner(reg).archive_guard_dirs() == (tmp_path / "out",)


def test_an_unreachable_network_path_is_not_read_as_absent() -> None:
    """Windows maps ERROR_BAD_NETPATH (53) to ENOENT; only its own not-found codes count as absent.

    Mutation: read `exc.errno` alone in `_is_absent`. Red."""

    class _NetPath(OSError):
        winerror = 53

    class _NotFound(OSError):
        winerror = 3

    assert not transport_base._is_absent(_NetPath(errno.ENOENT, "unreachable"))
    assert transport_base._is_absent(_NotFound(errno.ENOENT, "absent"))


def test_a_guarded_directory_not_created_yet_stands_in_by_its_parent(tmp_path: Path) -> None:
    """A `.error` before the first quarantine does not switch the sweep off: its nearest existing
    ancestor's identity is recorded instead."""
    guard = build_archive_guard({tmp_path / "in" / ".error"})

    assert not guard.unresolved
    st = os.stat(tmp_path)
    assert not st.st_ino or (st.st_dev, st.st_ino) in guard.ids


def test_a_guarded_directory_of_inode_zero_is_unresolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows answers a refused directory's stat from its parent's listing, with inode 0, rather
    than raising. That is no identity, so the directory is unresolved, not silently passed.

    Mutation: drop the `not st.st_ino and not found` check in `build_archive_guard`. Red."""
    guarded = tmp_path / "share"
    guarded.mkdir()
    real_stat = os.stat
    target = Path(os.path.realpath(guarded))

    def listing_answer(path: object, *args: object, **kwargs: object) -> os.stat_result:
        st = real_stat(path, *args, **kwargs)  # type: ignore[arg-type]
        if isinstance(path, (str, os.PathLike)) and Path(path) == target:
            return os.stat_result((st.st_mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return st

    monkeypatch.setattr(os, "stat", listing_answer)

    assert build_archive_guard({guarded}).unresolved == {guarded}


def test_a_missing_archive_directory_is_not_an_error(tmp_path: Path) -> None:
    assert _prune(_source(tmp_path / "in")) == 0


def test_the_deadline_stops_the_sweep_between_files(tmp_path: Path) -> None:
    src = _source(tmp_path / "in")
    for i in range(3):
        _aged(src.processed_dir / f"old-{i}.hl7", 90)

    assert src._prune_processed(_CUTOFF, ArchiveGuard(), lambda: True) == 0
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
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
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


async def test_an_unbound_inbounds_directories_are_protected(
    store: MessageStore, tmp_path: Path
) -> None:
    """B is stopped, so it is not in the archive list; the guard source still names its watch
    directory, which A's archive directory holds.

    Mutation: ignore `guard_source` in `_prune_processed_archives`. Red."""
    stopped_inbox = tmp_path / "shared" / "b-inbox"
    a = _source(tmp_path / "a", processed_subdir=str(tmp_path / "shared"))
    b_drop = _aged(stopped_inbox / "waiting.hl7", 90)
    runner = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (a,),
        guard_source=lambda: (stopped_inbox, stopped_inbox / ".error"),
    )

    result = await runner.run_once()

    assert result.processed_archives_deleted == 0
    assert b_drop.exists()


async def test_an_unresolvable_guard_sweeps_nothing(store: MessageStore, tmp_path: Path) -> None:
    """A guard list that could not be built fails closed."""
    src = _source(tmp_path / "in")
    old = _aged(src.processed_dir / "old.hl7", 90)
    runner = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (src,),
        guard_source=lambda: None,
    )

    result = await runner.run_once()

    assert result.processed_archives_deleted == 0
    assert old.exists()


async def test_the_pass_spares_a_sibling_shards_drops(store: MessageStore, tmp_path: Path) -> None:
    """End to end: shard s1's archive directory is shard s2's watch directory. s2's drop survives.

    Mutation: as `test_the_guard_names_a_sibling_engine_shards_inbound`. Red."""
    sibling = tmp_path / "sibling"
    reg = Registry()
    reg.add_inbound(_file_inbound("IB_MINE", tmp_path / "mine", shard="s1"))
    reg.add_inbound(_file_inbound("IB_SIBLING", sibling, shard="s2"))
    runner = _runner(filter_registry_for_shard(reg, "s1"))
    a = _source(tmp_path / "mine", processed_subdir=str(sibling))
    drop = _aged(sibling / "waiting.hl7", 90)
    retention = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (a,),
        guard_source=runner.archive_guard_dirs,
    )

    result = await retention.run_once()

    assert result.processed_archives_deleted == 0
    assert drop.exists()


async def test_the_pass_spares_a_file_outbounds_deliveries(
    store: MessageStore, tmp_path: Path
) -> None:
    """End to end: the archive directory is a File outbound's target. The delivery survives.

    Mutation: as `test_the_guard_names_every_file_outbound_target_directory`. Red."""
    out = tmp_path / "out"
    reg = Registry()
    reg.add_inbound(_file_inbound("IB_A", tmp_path / "a"))
    reg.add_outbound(_file_outbound("OB_PARTNER", out))
    runner = _runner(reg)
    a = _source(tmp_path / "a", processed_subdir=str(out))
    delivered = _aged(out / "for-pickup.hl7", 90)
    retention = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (a,),
        guard_source=runner.archive_guard_dirs,
    )

    result = await retention.run_once()

    assert result.processed_archives_deleted == 0
    assert delivered.exists()


async def test_the_pass_sweeps_nothing_when_a_guarded_identity_is_unreadable(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: one guarded directory cannot be stat'ed, so no archive is swept.

    Mutation: as `test_an_archive_that_cannot_read_an_unresolved_directory_sweeps_nothing`.
    Red."""
    src = _source(tmp_path / "in")
    old = _aged(src.processed_dir / "old.hl7", 90)
    other = tmp_path / "other-share"
    other.mkdir()
    _refuse_stat_of(monkeypatch, other)
    retention = RetentionRunner(
        store,
        _settings(processed_archive_days=30),
        clock=lambda: _NOW,
        archive_source=lambda: (src,),
        guard_source=lambda: (other,),
    )

    result = await retention.run_once()

    assert result.processed_archives_deleted == 0
    assert old.exists()


async def test_a_zero_window_sweeps_nothing(store: MessageStore, tmp_path: Path) -> None:
    src = _source(tmp_path / "in")
    old = _aged(src.processed_dir / "old.hl7", 365)
    runner = RetentionRunner(store, _settings(), clock=lambda: _NOW, archive_source=lambda: (src,))

    result = await runner.run_once()

    assert result.processed_archives_deleted == 0
    assert old.exists()
