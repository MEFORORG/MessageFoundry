# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The FILE source checks confinement on the handle it reads, not only on the name it listed (#2507).

``_candidates`` screens each listed name with ``_within_root``, a ``resolve()`` of the path. The read
and the archive move come later, and the settle gate can put a whole poll between them. So whoever can
write the drop directory could swap a checked file for a symbolic link, or a checked subdirectory for a
link to another directory, after the screen and before the read or the move. Before this change the
read then followed the link and read the outside file whole, and the move hard-linked or copied it into
``.error`` or ``.processed``. A file that grew past ``max_file_bytes`` after its stat was also read
whole, because the cap was charged against the stat, not against the bytes read.

Every swap here happens at the exact point the old code trusted, through a hook on the source, so each
test is deterministic. The outside file is given the drop's size and modification time where the old
code compared them, so what stops it is the new check and not the #116 partial-write compare.

Symbolic links need a privilege on Windows. The tests that make one skip where the process cannot, and
run on every Linux runner. All HL7 is synthetic.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import tracemalloc
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import FileSource

_FILE_LOGGER = "messagefoundry.transports.file"

_DROP = rb"MSH|^~\&|LAB|FAC|EHR|FAC|20260930||ADT^A01|CTRL1|P|2.5" + b"\rPID|1||SYN01\r"
#: Outside files the same length as the drop, so a size compare cannot tell them apart.
_SECRET_HL7 = _DROP.replace(b"SYN01", b"SEC99")
_SECRET_OTHER = b"%PDF-" + b"s" * (len(_DROP) - 5)
_SECRETS = pytest.mark.parametrize(
    "secret", [_SECRET_HL7, _SECRET_OTHER], ids=["outside-hl7", "outside-not-hl7"]
)


class _Recorder:
    def __init__(self, on_first: Callable[[], None] | None = None) -> None:
        self.got: list[bytes] = []
        self._on_first = on_first

    async def __call__(self, raw: bytes) -> str | None:
        self.got.append(raw)
        if len(self.got) == 1 and self._on_first is not None:
            self._on_first()
        return None


def _source(inbox: Path, **over: object) -> FileSource:
    settings: dict[str, object] = {"directory": str(inbox), "pattern": "*.hl7"}
    settings.update(over)
    src = FileSource(Source(type=ConnectorType.FILE, settings=settings))
    src._prepare_subdirs()
    return src


def _require_symlinks(tmp_path: Path) -> None:
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        pytest.skip("this process cannot create a symbolic link here")
    probe.unlink()


def _twin(drop: Path, outside: Path, body: bytes) -> None:
    """Write ``outside`` with ``drop``'s size and modification time."""
    outside.write_bytes(body)
    st = drop.stat()
    os.utime(outside, ns=(st.st_atime_ns, st.st_mtime_ns))


def _layout(
    tmp_path: Path, kind: str, secret: bytes
) -> tuple[Path, Path, Path, Callable[[], None]]:
    """The drop, the watch root, the outside file, and a swap that puts a link where the drop was.

    ``kind="file"`` swaps the drop itself for a link to the outside file. ``kind="dir"`` swaps the
    drop's subdirectory for a link to the outside directory, which holds a file of the same name: the
    component a ``O_NOFOLLOW`` on the last name alone would miss."""
    inbox = tmp_path / "in"
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    parked = tmp_path / "parked"
    parked.mkdir()
    if kind == "file":
        inbox.mkdir()
        drop = inbox / "drop.hl7"
        drop.write_bytes(_DROP)
        outside = outside_dir / "secret.hl7"
        _twin(drop, outside, secret)

        def swap() -> None:
            drop.rename(parked / drop.name)
            drop.symlink_to(outside)

    else:
        sub = inbox / "sub"
        sub.mkdir(parents=True)
        drop = sub / "drop.hl7"
        drop.write_bytes(_DROP)
        outside = outside_dir / drop.name
        _twin(drop, outside, secret)

        def swap() -> None:
            sub.rename(parked / sub.name)
            sub.symlink_to(outside_dir, target_is_directory=True)

    return drop, inbox, outside, swap


def _swap_when_settled(
    monkeypatch: pytest.MonkeyPatch, src: FileSource, drop: Path, swap: Callable[[], None]
) -> None:
    """Swap once the settle gate has admitted ``drop``: after the listing and the stat, before the read."""
    real = src._settled
    done: list[bool] = []

    def settled(path: Path, sig: tuple[int, int]) -> bool:
        admitted = real(path, sig)
        if admitted and path == drop and not done:
            done.append(True)
            swap()
        return admitted

    monkeypatch.setattr(src, "_settled", settled)


def _holds(directory: Path, body: bytes) -> list[str]:
    """Entries under ``directory`` that are links, or that read back as ``body`` through any link."""
    found: list[str] = []
    for entry in directory.rglob("*"):
        if entry.is_symlink():
            found.append(f"{entry.name} (a link)")
        elif entry.is_file() and entry.read_bytes() == body:
            found.append(entry.name)
    return found


def _assert_outside_untouched(inbox: Path, outside: Path, secret: bytes) -> None:
    assert outside.is_file(), "the outside file was moved or deleted through the link"
    assert outside.read_bytes() == secret, "the outside file was changed"
    for sub in (".error", ".processed"):
        assert _holds(inbox / sub, secret) == [], f"the outside file reached {sub}"


# === the read ======================================================================================


@_SECRETS
@pytest.mark.parametrize("kind", ["file", "dir"])
async def test_a_link_swapped_in_before_the_read_is_refused_and_never_archived(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    kind: str,
    secret: bytes,
) -> None:
    """The outside file is neither handed to the pipeline nor linked or copied into ``.error``.

    Red on origin/main: the HL7 twin is emitted, because ``read_bytes()`` follows the link and its
    size and mtime match the stat taken before the swap. The non-HL7 twin is quarantined through the
    link, so ``.error`` holds the outside file (a hard link on Linux, a link to the link on
    Windows)."""
    _require_symlinks(tmp_path)
    drop, inbox, outside, swap = _layout(tmp_path, kind, secret)
    src = _source(inbox, recursive=kind == "dir")
    handler = _Recorder()
    src._handler = handler
    await src._scan_once()  # the settle poll (BACKLOG #1811) records the stat
    _swap_when_settled(monkeypatch, src, drop, swap)
    with caplog.at_level(logging.WARNING, logger=_FILE_LOGGER):
        await src._scan_once()
    assert handler.got == [], "a file reached through a link was handed to the pipeline"
    _assert_outside_untouched(inbox, outside, secret)
    assert os.path.lexists(drop), "the refused entry is left in place for the operator"
    assert "refusing" in caplog.text
    assert drop.name not in caplog.text, "the file name must be logged as a safe label only"


# === the moves =====================================================================================


async def test_a_link_swapped_in_before_a_quarantine_move_is_not_archived(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The content-mismatch arm quarantines a drop it has read. A link swapped in after that read must
    not carry the outside file into ``.error``.

    Red on origin/main: ``_move`` links through the swapped name, so ``.error`` holds the outside
    file."""
    _require_symlinks(tmp_path)
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_SECRET_OTHER)  # not HL7, so the content-mismatch arm quarantines it
    outside = tmp_path / "secret.hl7"
    outside.write_bytes(_SECRET_HL7)
    src = _source(inbox)
    src._handler = _Recorder()
    await src._scan_once()
    real_read = src._read_settled

    def read_then_swap(path: Path) -> tuple[bytes, tuple[int, int]]:
        result = real_read(path)
        path.rename(tmp_path / "parked.hl7")
        path.symlink_to(outside)
        return result

    monkeypatch.setattr(src, "_read_settled", read_then_swap)
    await src._scan_once()
    _assert_outside_untouched(inbox, outside, _SECRET_HL7)
    assert drop.is_symlink(), "the refused link is left in place"


@pytest.mark.parametrize(
    ("kind", "after_read"),
    [("file", "move"), ("dir", "move"), ("dir", "delete")],
)
async def test_a_link_swapped_in_after_the_hand_off_is_neither_archived_nor_deleted_through(
    tmp_path: Path, kind: str, after_read: str
) -> None:
    """The drop is read and handed off, then swapped for a link before it is archived or deleted.

    Red on origin/main: ``move`` archives the outside file into ``.processed``, and ``delete``
    through a linked subdirectory deletes the outside file itself."""
    _require_symlinks(tmp_path)
    drop, inbox, outside, swap = _layout(tmp_path, kind, _SECRET_HL7)
    src = _source(inbox, recursive=kind == "dir", after_read=after_read)
    handler = _Recorder(on_first=swap)
    src._handler = handler
    await src._scan_once()
    await src._scan_once()
    assert handler.got == [_DROP], "the drop itself was read and handed off before the swap"
    _assert_outside_untouched(inbox, outside, _SECRET_HL7)


# === the size cap ==================================================================================


async def test_a_file_that_grows_past_the_cap_after_its_stat_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The cap is charged on the handle, so growth after the stat is caught and nothing is read whole.

    Red on origin/main: ``read_bytes()`` reads all 8 MiB (the traced peak passes it) and the file is
    left in place as "changed while it was read" rather than quarantined."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)
    grow_by = 8 << 20
    src = _source(inbox, max_file_bytes=1024)
    handler = _Recorder()
    src._handler = handler
    await src._scan_once()

    def grow() -> None:
        os.truncate(drop, len(_DROP) + grow_by)  # extends it without allocating the bytes here

    _swap_when_settled(monkeypatch, src, drop, grow)
    tracemalloc.start()
    try:
        with caplog.at_level(logging.WARNING, logger=_FILE_LOGGER):
            await src._scan_once()
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert handler.got == []
    assert peak < grow_by // 4, f"the grown file was read into memory (traced peak {peak} bytes)"
    assert (inbox / ".error" / drop.name).exists(), "the over-cap file is quarantined"
    assert "exceeds max_file_bytes" in caplog.text


def test_the_read_is_cut_off_at_the_cap_even_when_the_handle_under_reports_its_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The handle's own size is a shortcut, not the bound: the read stops at ``cap + 1`` bytes.

    Mutation: read the handle without a limit. Red: all 4096 bytes are returned instead of a
    refusal."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(b"X" * 4096)
    real_fstat = os.fstat

    def under_reports(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        fields = list(st)
        fields[6] = 10  # st_size: a share whose size attribute lags the bytes it serves
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", under_reports)
    with pytest.raises(file_mod._OverCap):
        file_mod._read_confined(drop, inbox, inbox.resolve(), 100)
    monkeypatch.undo()
    assert file_mod._read_confined(drop, inbox, inbox.resolve(), 4096) == b"X" * 4096


def test_a_small_drop_does_not_reserve_the_whole_cap(tmp_path: Path) -> None:
    """A buffered ``read(n)`` allocates ``n`` up front, so the read asks for the handle's size first.

    Mutation: read ``cap + 1`` at once. Red: about 16 MiB is traced for a 60-byte file."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)
    tracemalloc.start()
    try:
        raw = file_mod._read_confined(drop, inbox, inbox.resolve(), 16 << 20)
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raw == _DROP
    assert peak < 1 << 20, f"the read reserved the cap (traced peak {peak} bytes)"


async def test_a_refused_link_is_not_charged_and_is_warned_about_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A refusal leaves the entry in place, so it must not spend the per-tick budget, and a link left
    there must not write a WARNING on every poll.

    Mutations: charge the refusal arm (``disposed += 1``); red, the healthy file behind it waits. Drop
    the once-only memory; red, a second WARNING."""
    _require_symlinks(tmp_path)
    inbox = tmp_path / "in"
    inbox.mkdir()
    first = inbox / "a_first.hl7"
    first.write_bytes(_DROP)
    (inbox / "b_second.hl7").write_bytes(_SECRET_HL7)
    target = inbox / "target.txt"  # inside the root, so the listing keeps passing the link
    _twin(first, target, _SECRET_OTHER)
    src = _source(inbox, poll_max_files=1)
    handler = _Recorder()
    src._handler = handler
    await src._scan_once()

    def swap() -> None:
        first.rename(tmp_path / "parked.hl7")
        first.symlink_to(target)

    _swap_when_settled(monkeypatch, src, first, swap)
    with caplog.at_level(logging.WARNING, logger=_FILE_LOGGER):
        await src._scan_once()
        assert handler.got == [_SECRET_HL7], "the healthy file behind the refusal was not reached"
        await src._scan_once()  # the link is still listed; its settle poll
        await src._scan_once()  # and its second refusal
    assert caplog.text.count("refusing") == 1


@pytest.mark.skipif(sys.platform == "win32", reason="no FIFOs on Windows")
async def test_a_fifo_swapped_in_is_refused_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last name is opened ``O_NONBLOCK``, so a FIFO swapped in fails the regular-file check at once.

    Mutation: drop ``O_NONBLOCK``. Red: the open waits for a writer and the scan times out."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)
    src = _source(inbox)
    handler = _Recorder()
    src._handler = handler
    await src._scan_once()

    def swap() -> None:
        drop.unlink()
        if sys.platform != "win32":  # narrows mypy; the test is skipped there
            os.mkfifo(drop)

    _swap_when_settled(monkeypatch, src, drop, swap)
    await asyncio.wait_for(src._scan_once(), timeout=10)
    assert handler.got == []
    assert list((inbox / ".error").iterdir()) == []
