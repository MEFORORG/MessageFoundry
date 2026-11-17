# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A FILE source reaches healthy drops behind rejects it cannot move (BACKLOG #5717).

Every quarantine arm charges the per-tick budget whether or not the move to ``.error`` worked. Before
#5717 a reject that could not be moved stayed in place and was read and charged again on later scans,
so ``poll_max_files`` such rejects sorting first could spend the whole budget and hold back the
healthy drops behind them. Under ``move`` and ``delete`` a reject that stays for a lasting reason is
now remembered by path and mark and skipped unread and uncharged until it changes, and examined
again in full in a retry pass after the other candidates: after ``STUCK_RETRY_SECONDS`` for a
lasting failure, on the next scan for a transient one. ``leave`` is unchanged.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import errno
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import FileSource, ScanRejected, set_scan_hook

_HL7 = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL5717|P|2.5.1\rPID|1||12345\r"
_PDF = b"%PDF-1.7 not an HL7 message"


@pytest.fixture
def _no_scan_hook() -> Iterator[None]:
    yield
    set_scan_hook(None)


class _Rig:
    """A source over ``inbox`` whose moves into ``.error`` fail with ``fail_errno`` (None: they work),
    counting every read by file name and every hand-off."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        cap: int | None,
        after_read: str = "move",
        fail_errno: int | None = errno.EACCES,
    ) -> None:
        self.inbox = tmp_path / "in"
        self.inbox.mkdir()
        self.source = FileSource(
            Source(
                type=ConnectorType.FILE,
                settings={
                    "directory": str(self.inbox),
                    "poll_max_files": cap,
                    "after_read": after_read,
                },
            )
        )
        self.reads: list[str] = []
        self.handed_off: list[bytes] = []
        self.fail_errno = fail_errno

        async def handler(raw: bytes) -> str | None:
            self.handed_off.append(raw)
            return None

        self.source._handler = handler
        self.source._prepare_subdirs()

        real_read = file_mod._read_confined
        real_open_dest = file_mod._open_dest

        def read(path: Path, *args: Any) -> Any:
            self.reads.append(path.name)
            return real_read(path, *args)

        def open_dest(dest_dir: Path, *args: Any) -> Any:
            if dest_dir.name == ".error" and self.fail_errno is not None:
                raise OSError(self.fail_errno, os.strerror(self.fail_errno))
            return real_open_dest(dest_dir, *args)

        monkeypatch.setattr(file_mod, "_read_confined", read)
        monkeypatch.setattr(file_mod, "_open_dest", open_dest)

    def drop(self, name: str, body: bytes) -> Path:
        path = self.inbox / name
        path.write_bytes(body)
        return path

    async def scan(self) -> list[str]:
        """One scan; the names it read."""
        start = len(self.reads)
        await self.source._scan_once()
        return self.reads[start:]


def _drop_two_rejects_and_a_healthy_drop(rig: _Rig) -> None:
    rig.drop("a1.hl7", _PDF)
    rig.drop("a2.hl7", _PDF)
    rig.drop("b_healthy.hl7", _HL7)


#: What nine scans of :func:`_drop_two_rejects_and_a_healthy_drop` read with a cap of one, where every
#: move to ``.error`` fails and nothing remembers it: measured on main before #5717, under ``leave``
#: and ``move`` alike, for EACCES and EBUSY alike. A reject read on one scan leaves the settle map and
#: must settle again (BACKLOG #1811), which is why the reads alternate.
_MAIN_SEQUENCE = [
    [],
    ["a1.hl7"],
    ["a2.hl7"],
    ["a1.hl7"],
    ["b_healthy.hl7"],
    ["a1.hl7"],
    ["a2.hl7"],
    ["a1.hl7"],
    [],
]


@pytest.mark.parametrize("after_read", ["move", "delete"])
@pytest.mark.parametrize(("cap", "stuck"), [(1, 1), (1, 3), (2, 5), (3, 9)])
async def test_healthy_drop_is_reached_behind_unmovable_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_read: str, cap: int, stuck: int
) -> None:
    """The probe from the review of the first build: before #5717 the healthy drop was never handed
    off while ``stuck >= cap``. Each reject is read once, and no scan reads more than ``cap``.

    Mutation: make ``_stuck_step`` return None for an unchanged reject. Red: never handed off."""
    rig = _Rig(tmp_path, monkeypatch, cap=cap, after_read=after_read)
    for n in range(stuck):
        rig.drop(f"a_reject{n:03d}.hl7", _PDF)
    rig.drop("b_healthy.hl7", _HL7)

    await rig.scan()  # the settle poll (BACKLOG #1811) reads nothing
    ticks = 0
    while not rig.handed_off and ticks < 50:
        read = await rig.scan()
        assert len(read) <= cap, f"a scan read {len(read)} files over a cap of {cap}"
        ticks += 1

    assert rig.handed_off == [_HL7]
    assert ticks == stuck // cap + 1  # each scan reads cap rejects, then the healthy one fits
    assert sorted(rig.reads) == sorted(
        [f"a_reject{n:03d}.hl7" for n in range(stuck)] + ["b_healthy.hl7"]
    )
    assert len(rig.source._stuck) == stuck
    for _ in range(3):
        assert await rig.scan() == [], "a remembered reject is not read again"


async def test_a_changed_stuck_reject_is_examined_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rewrite gives the file a new mark, so it is forgotten, settles, and is read again."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    path = rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    assert await rig.scan() == []

    path.write_bytes(_PDF + b" and more")
    assert await rig.scan() == [], "the changed file settles first"
    assert await rig.scan() == ["a.hl7"]

    rig.fail_errno = None
    path.write_bytes(_PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    assert (rig.inbox / ".error" / "a.hl7").exists(), "once the move works, it is quarantined"
    assert rig.source._stuck == {}


async def test_a_new_file_under_the_same_name_size_and_mtime_is_examined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mark carries the file's identity, so a different file that matches the old one's size and
    mtime is not skipped as the stuck one.

    Mutation: drop ``st_dev, st_ino`` from ``_file_mark``. Red: the new file is never read."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    path = rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    old = path.stat()

    other = rig.inbox.parent / "other.hl7"
    other.write_bytes(_PDF)
    os.utime(other, ns=(old.st_atime_ns, old.st_mtime_ns))
    os.replace(other, path)  # a new inode while the old one still existed, so it cannot be reused
    new = path.stat()
    assert (new.st_size, new.st_mtime_ns) == (old.st_size, old.st_mtime_ns)
    if (new.st_dev, new.st_ino) == (old.st_dev, old.st_ino) or not new.st_ino:
        pytest.skip("this filesystem reports no distinct file identity")

    assert await rig.scan() == [], "the new file settles first"
    assert await rig.scan() == ["a.hl7"]


@pytest.mark.parametrize("fail_errno", [errno.EBUSY, errno.ENOSPC])
async def test_a_transient_move_failure_is_retried_on_the_next_scan_uncharged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_errno: int
) -> None:
    """A failure that may clear by itself is remembered as due at once, so each such reject is tried
    again on the next scan, in the retry pass, and spends none of the budget: the healthy drop is
    handed off a scan sooner than on main (:data:`_MAIN_SEQUENCE`), and no fresh pass reads a reject
    twice.

    Mutation: do not remember a transient failure. Red: the scans read :data:`_MAIN_SEQUENCE`."""
    rig = _Rig(tmp_path, monkeypatch, cap=1, fail_errno=fail_errno)
    _drop_two_rejects_and_a_healthy_drop(rig)
    scans = [await rig.scan() for _ in range(9)]
    assert scans != _MAIN_SEQUENCE
    assert scans == [
        [],
        ["a1.hl7"],
        ["a2.hl7", "a1.hl7"],  # a1 in the retry pass
        ["b_healthy.hl7", "a2.hl7"],
        ["a1.hl7"],
        ["a2.hl7"],
        ["a1.hl7"],
        ["a2.hl7"],
        ["a1.hl7"],
    ]
    assert rig.handed_off == [_HL7]
    assert len(rig.source._stuck) == 2


def _win_os_error(code: int, winerror: int) -> OSError:
    """An ``OSError`` carrying a Windows code, as Windows raises one, on any platform."""
    if os.name == "nt":
        return OSError(code, "test", None, winerror)
    exc = OSError(code, "test")
    setattr(exc, "winerror", winerror)  # noqa: B010 -- the attribute exists on Windows only
    return exc


@pytest.mark.parametrize("winerror", [21, 31, 32, 33, 53, 54, 64, 69, 70, 71, 303, 1224, 2250])
def test_a_transient_windows_code_wins_over_errno(winerror: int) -> None:
    """Windows maps several transient codes to EACCES or EINVAL, so the code is read first."""
    assert not file_mod._lasting(_win_os_error(errno.EACCES, winerror))
    assert not file_mod._lasting(_win_os_error(errno.EACCES, winerror), stage="archive_dir")


def test_windows_codes_that_are_lasting() -> None:
    assert file_mod._lasting(_win_os_error(errno.EACCES, 5))
    # ERROR_PATH_NOT_FOUND is lasting only on the move into the archive directory.
    path_not_found = _win_os_error(errno.ENOENT, 3)
    assert file_mod._lasting(path_not_found, stage="archive")
    assert not file_mod._lasting(path_not_found)
    # ERROR_FILENAME_EXCED_RANGE is lasting at every stage, although its errno reads as vanished.
    for stage in ("file", "archive_dir", "archive"):
        assert file_mod._lasting(_win_os_error(errno.ENOENT, 206), stage=stage)


async def test_an_archived_copy_whose_original_cannot_be_removed_is_retried_in_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copy in ``.error`` with the original left behind is remembered, so it is not copied again on
    every scan. When its retry falls due it takes the whole path, which archives a second copy and
    records a second event: accepted, rather than a remove-only retry that could delete unarchived
    bytes."""
    rig = _Rig(tmp_path, monkeypatch, cap=10, fail_errno=None)
    archives: list[str] = []

    def archive(_pin: Any, _dest: Any, name: str) -> bool:
        archives.append(name)
        return False  # linked or copied: the caller removes the original

    def remove(_pin: Any) -> None:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(file_mod, "_archive", archive)
    monkeypatch.setattr(file_mod, "_remove_pinned", remove)
    events = _sink(rig)
    rig.drop("a.hl7", _PDF)
    for _ in range(4):
        await rig.scan()
    assert archives == ["a.hl7"]
    assert events == ["file_content_mismatch"]
    assert rig.reads == ["a.hl7"]

    _age_stuck(rig)
    await rig.scan()  # the retry is read and judged again
    await rig.scan()  # and remembered again, not due
    assert archives == ["a.hl7", "a.hl7"]
    assert events == ["file_content_mismatch", "file_content_mismatch"]
    assert rig.reads == ["a.hl7", "a.hl7"]
    assert len(rig.source._stuck) == 1


@pytest.mark.usefixtures("_no_scan_hook")
async def test_a_scan_hook_failure_and_a_handler_failure_still_charge_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Left free by main, and still free: with a cap of one, the healthy drop behind both is handed
    off in the same scan."""
    rig = _Rig(tmp_path, monkeypatch, cap=1, fail_errno=None)
    rig.drop("a_hook.hl7", _HL7.replace(b"CTL5717", b"CTLHOOK"))
    rig.drop("b_handler.hl7", _HL7.replace(b"CTL5717", b"CTLFAIL"))
    rig.drop("c_healthy.hl7", _HL7)

    def hook(raw: bytes, _source: str) -> None:
        if b"CTLHOOK" in raw:
            raise RuntimeError("scanner unreachable")

    set_scan_hook(hook)

    async def handler(raw: bytes) -> str | None:
        if b"CTLFAIL" in raw:
            raise RuntimeError("store unavailable")
        rig.handed_off.append(raw)
        return None

    rig.source._handler = handler
    await rig.scan()
    assert await rig.scan() == ["a_hook.hl7", "b_handler.hl7", "c_healthy.hl7"]
    assert rig.handed_off == [_HL7]
    assert rig.source._stuck == {}


async def test_leave_mode_still_reads_and_charges_an_unmovable_reject_every_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``leave`` is unchanged by #5717: nothing is remembered, and the scans read exactly what they
    read before it (:data:`_MAIN_SEQUENCE`, measured on main).

    Mutation: let ``_quarantine`` remember under ``leave``. Red: the rejects stop being read."""
    rig = _Rig(tmp_path, monkeypatch, cap=1, after_read="leave")
    _drop_two_rejects_and_a_healthy_drop(rig)
    assert [await rig.scan() for _ in range(9)] == _MAIN_SEQUENCE
    assert rig.handed_off == [_HL7]
    assert rig.source._stuck == {}


def _sink(rig: _Rig) -> list[str]:
    """Record the kind of every connection event the source emits."""
    events: list[str] = []

    async def sink(kind: str, _peer: str | None, _reason: str | None) -> None:
        events.append(kind)

    rig.source.on_connection_event = sink
    return events


def _age_stuck(rig: _Rig) -> None:
    """Make every remembered reject due its retry."""
    stuck = rig.source._stuck
    for key, (seen, missed) in list(stuck.items()):
        stuck[key] = (seen._replace(due=seen.due - file_mod.STUCK_RETRY_SECONDS), missed)


async def test_a_due_retry_takes_the_whole_path_and_is_quarantined_once_the_move_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cause fixed outside the file (an ``.error`` made writable again) is picked up without a
    restart: once ``STUCK_RETRY_SECONDS`` pass the reject is read and judged afresh on the first scan
    that reaches it, and is moved.

    Mutation: drop the time test from ``_stuck_step``. Red: the reject is never read again."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    events = _sink(rig)
    rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    assert await rig.scan() == []

    rig.fail_errno = None
    _age_stuck(rig)
    assert await rig.scan() == ["a.hl7"], "unchanged since its move failed, so already settled"
    assert (rig.inbox / ".error" / "a.hl7").exists()
    assert events == ["file_content_mismatch"]
    assert rig.source._stuck == {}


@pytest.mark.usefixtures("_no_scan_hook")
async def test_a_retry_that_now_passes_the_verdict_is_ingested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry judges the file afresh: a scanner that rejected it and has since changed its mind
    lets it through, and it is handed off and archived to ``.processed``."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    verdicts = {"reject": True}

    def hook(_raw: bytes, _source: str) -> None:
        if verdicts["reject"]:
            raise ScanRejected("test signature")

    set_scan_hook(hook)
    rig.drop("a.hl7", _HL7)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    assert rig.handed_off == []
    assert len(rig.source._stuck) == 1

    verdicts["reject"] = False
    _age_stuck(rig)
    assert await rig.scan() == ["a.hl7"]
    assert rig.handed_off == [_HL7]
    assert (rig.inbox / ".processed" / "a.hl7").exists()
    assert rig.source._stuck == {}


async def test_due_retries_run_after_the_fresh_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retries sorting first are examined after every other candidate, so a healthy drop behind
    them is read first.

    Mutation: examine a due retry in the fresh pass. Red: the rejects are read first."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    for n in range(3):
        rig.drop(f"a_reject{n}.hl7", _PDF)
    await rig.scan()
    await rig.scan()
    assert len(rig.source._stuck) == 3
    rig.drop("b_healthy.hl7", _HL7)
    await rig.scan()  # the healthy drop settles
    _age_stuck(rig)
    assert await rig.scan() == ["b_healthy.hl7", "a_reject0.hl7", "a_reject1.hl7", "a_reject2.hl7"]
    assert rig.handed_off == [_HL7]
    assert len(rig.source._stuck) == 3, "still stuck, so remembered again"


async def test_due_retries_are_capped_per_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At most ``STUCK_RETRIES_PER_SCAN_MAX`` retries are examined in one scan; the rest stay due.

    Mutation: drop the slice in ``_scan_once``'s retry pass. Red: all four are read in one scan."""
    monkeypatch.setattr(file_mod, "STUCK_RETRIES_PER_SCAN_MAX", 2)
    rig = _Rig(tmp_path, monkeypatch, cap=None)
    for n in range(4):
        rig.drop(f"a{n}.hl7", _PDF)
    await rig.scan()
    await rig.scan()
    assert len(rig.source._stuck) == 4
    _age_stuck(rig)
    assert await rig.scan() == ["a0.hl7", "a1.hl7"], "a2 and a3 wait, still due"
    assert await rig.scan() == ["a2.hl7", "a3.hl7"]
    assert await rig.scan() == []
    assert len(rig.source._stuck) == 4


@pytest.mark.parametrize(
    ("cap", "disposed", "allowed"),
    [
        (None, 0, 100),  # no ceiling: the absolute constant alone
        (500, 500, 50),  # the budget is spent: a tenth is held back for retries
        (500, 100, 100),  # the leftover is larger, but the constant caps it
        (500, 470, 50),
        (200, 150, 50),  # the leftover beats a tenth
        (9, 9, 1),  # under ten, one slot is still held back
        (9, 6, 3),  # so retries use only the leftover
    ],
)
def test_the_retry_allowance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cap: int | None,
    disposed: int,
    allowed: int,
) -> None:
    rig = _Rig(tmp_path, monkeypatch, cap=cap)
    assert file_mod.STUCK_RETRIES_PER_SCAN_MAX == 100
    assert rig.source._retry_allowance(disposed) == allowed


async def test_retries_go_oldest_first_and_a_deferred_one_survives_pruning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the budget spent, the one retry slot goes to the oldest failure, and a due reject the
    allowance leaves for later is still listed, so pruning keeps it. The control: a remembered
    reject that is no longer listed is pruned in the same run, so pruning is live.

    Mutation: drop the ``due.sort`` in ``_scan_once``. Red: a0, which sorts first, is retried first.
    Mutation: let ``_prune_stuck`` drop an entry that is due. Red: a0 is forgotten."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    for name in ("a0.hl7", "a1.hl7", "c.hl7"):
        rig.drop(name, _PDF)
    await rig.scan()
    await rig.scan()
    assert len(rig.source._stuck) == 3
    rig.source.poll_max_files = 1
    for n in range(5):
        rig.drop(f"b{n}.hl7", _HL7)
    await rig.scan()  # the healthy drops settle; nothing is due yet
    stuck = rig.source._stuck
    retry = file_mod.STUCK_RETRY_SECONDS
    for name, age in (("a0.hl7", retry), ("a1.hl7", 2 * retry)):
        key = str(rig.inbox / name)
        seen, missed = stuck[key]
        stuck[key] = (seen._replace(due=seen.due - age), missed)
    (rig.inbox / "c.hl7").unlink()

    assert await rig.scan() == ["b0.hl7", "a1.hl7"], "one slot, to the oldest failure"
    a0_key = str(rig.inbox / "a0.hl7")
    for n in range(1, 4):
        assert a0_key in stuck, "deferred and still listed, so kept"
        if n == 1:
            assert await rig.scan() == ["b1.hl7", "a0.hl7"]
        else:
            await rig.scan()
    assert str(rig.inbox / "c.hl7") not in stuck, "the control: an unlisted entry is pruned"
    assert a0_key in stuck and str(rig.inbox / "a1.hl7") in stuck


async def test_a_failed_listing_does_not_wipe_the_stuck_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pruned like the settle map: one scan whose listing fails does not forget the rejects, so they
    are not all read and charged again once the listing recovers."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]

    real_candidates = FileSource._candidates

    def no_listing(_self: FileSource) -> list[Path]:
        return []

    monkeypatch.setattr(FileSource, "_candidates", no_listing)
    await rig.scan()
    monkeypatch.setattr(FileSource, "_candidates", real_candidates)
    assert await rig.scan() == []
    assert len(rig.source._stuck) == 1


async def test_a_missing_error_directory_is_a_lasting_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing recreates ``.error`` while the source runs, so ENOENT opening it is remembered, unlike
    ENOENT for a source file that vanished."""
    rig = _Rig(tmp_path, monkeypatch, cap=10, fail_errno=errno.ENOENT)
    rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    assert await rig.scan() == []
    assert len(rig.source._stuck) == 1


async def test_a_full_memory_is_logged_once_and_again_after_it_drains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Several rejects meet the full memory and it is logged once. Once it drains and fills again it
    is logged a second time, which is also the control: the count can reach two.

    Mutation: drop the ``_stuck_full_logged`` guard. Red: the first count is above one.
    Mutation: never reset the flag. Red: the second count stays at one."""
    monkeypatch.setattr(file_mod, "SETTLE_SEEN_MAX", 1)  # bounds the settle map too
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    for n in range(3):
        rig.drop(f"a{n}.hl7", _PDF)

    def full_logs() -> int:
        text = "memory of rejects that cannot be moved is full"
        return sum(text in r.message for r in caplog.records)

    def overflow_reads() -> int:
        return sum(name in ("a1.hl7", "a2.hl7") for name in rig.reads)

    for _ in range(20):
        await rig.scan()
        if overflow_reads() >= 3:
            break
    assert overflow_reads() >= 3, "several rejects met the full memory"
    assert len(rig.source._stuck) == 1
    assert full_logs() == 1

    (rig.inbox / "a0.hl7").unlink()  # drains once pruning forgets it
    for _ in range(20):
        await rig.scan()
        if full_logs() == 2:
            break
    assert full_logs() == 2


def test_lasting_reads_the_engines_own_refusals() -> None:
    assert not file_mod._lasting(file_mod._Replaced("not the file that was read"))
    assert file_mod._lasting(file_mod._Unconfined("a link"))
    assert not file_mod._lasting(OSError("no errno at all")), "unknown, so retried soon"
    assert not file_mod._lasting(OSError(errno.ENOENT, "gone"))
    assert file_mod._lasting(OSError(errno.ENOENT, "gone"), stage="archive_dir")
    assert not file_mod._lasting(OSError(errno.ENOENT, "gone"), stage="archive")


async def test_a_due_reject_past_the_ceiling_still_gets_its_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under a sustained backlog the fresh pass breaks at the ceiling before a reject sorting late,
    which is still due: the retry pass takes it anyway.

    Mutation: add only fresh-pass DUE steps to ``due``. Red: z.hl7 is never read again."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    rig.drop("z.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["z.hl7"]
    rig.source.poll_max_files = 1
    for n in range(5):
        rig.drop(f"a{n}.hl7", _HL7.replace(b"CTL5717", f"CTL{n}".encode()))
    await rig.scan()  # the backlog settles
    _age_stuck(rig)
    assert await rig.scan() == ["a0.hl7", "z.hl7"]
    assert len(rig.source._stuck) == 1, "still stuck, so remembered again"


async def test_a_retry_left_in_place_stays_remembered_and_due(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry whose read fails transiently is not forgotten: it stays due, so the next scan tries
    it again in the retry pass rather than reading and charging it in the fresh pass.

    Mutation: delete the entry in ``_examine``'s retry branch instead of making it due. Red: it is
    forgotten."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    _age_stuck(rig)
    real_read = file_mod._read_confined

    def locked(path: Path, *args: Any) -> Any:
        rig.reads.append(path.name)
        raise OSError(errno.EBUSY, "locked")

    monkeypatch.setattr(file_mod, "_read_confined", locked)
    assert await rig.scan() == ["a.hl7"]
    key = str(rig.inbox / "a.hl7")
    assert key in rig.source._stuck, "left in place, so still remembered"
    monkeypatch.setattr(file_mod, "_read_confined", real_read)
    rig.fail_errno = None
    assert await rig.scan() == ["a.hl7"], "due at once, so retried on the next scan"
    assert (rig.inbox / ".error" / "a.hl7").exists()
    assert rig.source._stuck == {}


async def test_failed_listings_do_not_wipe_the_stuck_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A watch directory that is gone lists nothing, which is no evidence the rejects have gone, so
    however many scans meet it the memory is not pruned. Real pathlib, nothing patched:
    ``Path.glob`` returns nothing for a missing directory rather than raising.

    Mutation: drop the ``os.scandir`` probe in ``_candidates``. Red: the reject is forgotten after
    SETTLE_MISS_LIMIT scans and read again once the directory returns."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]

    away = tmp_path / "away"
    rig.inbox.rename(away)
    for _ in range(file_mod.SETTLE_MISS_LIMIT + 2):
        assert await rig.scan() == []
    assert rig.source._listing_failed
    away.rename(rig.inbox)
    assert len(rig.source._stuck) == 1
    assert await rig.scan() == [], "still remembered once the directory returns"


async def test_a_full_memory_hovering_at_its_cap_is_not_logged_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """One entry leaving and one more reject arriving does not log the full memory a second time:
    only a memory drained to half its cap does.

    Mutation: reset the flag whenever the memory is below its cap. Red: logged twice."""
    monkeypatch.setattr(file_mod, "SETTLE_SEEN_MAX", 4)  # bounds the settle map too
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    for n in range(4):
        rig.drop(f"a{n}.hl7", _PDF)

    def full_logs() -> int:
        text = "memory of rejects that cannot be moved is full"
        return sum(text in r.message for r in caplog.records)

    await rig.scan()
    await rig.scan()
    assert len(rig.source._stuck) == 4
    rig.drop("b0.hl7", _PDF)
    await rig.scan()
    await rig.scan()
    assert full_logs() == 1
    (rig.inbox / "a0.hl7").unlink()
    for _ in range(10):
        await rig.scan()
        if str(rig.inbox / "b0.hl7") in rig.source._stuck:
            break
    assert len(rig.source._stuck) == 4, "a0 forgotten, b0 remembered in its place"
    rig.drop("c0.hl7", _PDF)
    await rig.scan()
    await rig.scan()
    assert len(rig.source._stuck) == 4
    assert full_logs() == 1


async def test_a_reject_gone_after_a_failed_move_is_not_remembered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A transient failure leaves a file to retry only while it is still the file that was read: one
    deleted or replaced meanwhile is not remembered, and no "stays in place" line is logged.

    Mutation: return ``stays=True`` for every failed move. Red: a phantom entry and the line."""
    rig = _Rig(tmp_path, monkeypatch, cap=10, fail_errno=None)
    gone = rig.drop("a_gone.hl7", _PDF)
    # Windows refuses a rename over the file the move holds open, so the replaced case is POSIX's.
    replaced = rig.drop("b_replaced.hl7", _PDF) if os.name != "nt" else None

    def vanishing_dest(_dest_dir: Path, *_args: Any) -> Any:
        if gone.exists():
            gone.unlink()
        elif replaced is not None:
            other = rig.inbox.parent / "other.hl7"
            other.write_bytes(_HL7)
            os.replace(other, replaced)
        raise OSError(errno.EBUSY, "busy")

    monkeypatch.setattr(file_mod, "_open_dest", vanishing_dest)
    await rig.scan()
    read = await rig.scan()
    assert read == ["a_gone.hl7"] + (["b_replaced.hl7"] if replaced else [])
    assert rig.source._stuck == {}
    assert not any("stays in place" in r.message for r in caplog.records)


async def test_a_due_reject_replaced_before_its_retry_is_forgotten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry's own stat sees the new file, so the entry is dropped and the new file takes the
    settle gate like any drop, rather than staying in the stuck memory under the old mark."""
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    path = rig.drop("a.hl7", _PDF)
    await rig.scan()
    assert await rig.scan() == ["a.hl7"]
    _age_stuck(rig)
    path.write_bytes(_HL7)
    assert await rig.scan() == [], "a changed file settles first"
    assert rig.source._stuck == {}
    assert await rig.scan() == ["a.hl7"]
    assert rig.handed_off == [_HL7]


async def test_a_full_memory_still_reschedules_a_retried_reject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A retried reject already holds its slot, so a full memory does not stop it being remembered
    again, due after ``STUCK_RETRY_SECONDS``, and the full memory is not logged for it.

    Mutation: refuse every remember once the memory is full. Red: read again on the next scan."""
    monkeypatch.setattr(file_mod, "SETTLE_SEEN_MAX", 2)  # bounds the settle map too
    rig = _Rig(tmp_path, monkeypatch, cap=10)
    rig.drop("a0.hl7", _PDF)
    rig.drop("a1.hl7", _PDF)
    await rig.scan()
    await rig.scan()
    assert len(rig.source._stuck) == 2
    _age_stuck(rig)
    assert await rig.scan() == ["a0.hl7", "a1.hl7"]
    assert await rig.scan() == [], "remembered again, not due"
    assert not any("is full" in r.message for r in caplog.records)


async def test_a_copy_left_in_error_waits_like_a_lasting_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A copy archived whose original could not be removed for a transient reason is not retried on
    the next scan, which would write another copy and event each time; and the "stays in place"
    WARNING is written once, not per retry.

    Mutation: remember it as transient. Red: a second copy on the next scan."""
    rig = _Rig(tmp_path, monkeypatch, cap=10, fail_errno=None)
    archives: list[str] = []

    def archive(_pin: Any, _dest: Any, name: str) -> bool:
        archives.append(name)
        return False  # linked or copied: the caller removes the original

    def remove(_pin: Any) -> None:
        raise OSError(errno.EBUSY, "busy")

    monkeypatch.setattr(file_mod, "_archive", archive)
    monkeypatch.setattr(file_mod, "_remove_pinned", remove)
    rig.drop("a.hl7", _PDF)
    for _ in range(4):
        await rig.scan()
    assert archives == ["a.hl7"]
    _age_stuck(rig)
    await rig.scan()
    await rig.scan()
    assert archives == ["a.hl7", "a.hl7"]
    stays = [r for r in caplog.records if "stays in place" in r.message]
    assert stays, "the line was logged at all"
    assert sum(r.levelno >= logging.WARNING for r in stays) == 1
