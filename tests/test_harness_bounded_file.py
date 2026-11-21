# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness's bounded file reader (ASVS 5.1.1), and the File sink that reads through it.

``harness.bounded_file.read_capped`` is shared by the File tab's watch pane, the File and remote-file
sinks and the reconcile loader. These tests pin each refusal, including the stat-then-open window: a
file swapped or grown between the size check and the read is judged on the open handle. Qt-free, so
they run where PySide6 cannot load. Synthetic bytes only.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from harness.bounded_file import NOT_REGULAR, read_capped, read_fd_capped
from harness.sinks.file import FileSink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

_BODY = b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X1|P|2.5.1\r"


def test_a_file_at_the_cap_is_read_and_one_past_it_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = len(_BODY)
    at_cap, over = tmp_path / "at.hl7", tmp_path / "over.hl7"
    at_cap.write_bytes(_BODY)
    over.write_bytes(_BODY + b"X")
    opened: list[str] = []
    real_open = os.open

    def spy(path: object, *args: object, **kwargs: object) -> int:
        opened.append(Path(str(path)).name)
        return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", spy)
    assert read_capped(at_cap, cap) == (_BODY, "")
    assert read_capped(over, cap) == (b"", f"{cap + 1} bytes, over the {cap}-byte cap; not read")
    assert opened == ["at.hl7"], "the over-cap file was opened before it was refused"


def test_a_directory_is_not_regular(tmp_path: Path) -> None:
    (tmp_path / "d.hl7").mkdir()
    assert read_capped(tmp_path / "d.hl7", 1024) == (b"", NOT_REGULAR)


def _within(seconds: float, fn: Callable[[], object]) -> object:
    """``fn()``'s result, or a failure if it has not returned in ``seconds``: a FIFO that is opened
    blocking waits for a writer forever, and a regression must fail, not hang the run."""
    box: list[object] = []
    worker = threading.Thread(target=lambda: box.append(fn()), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "blocked on a FIFO"
    return box[0]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO")
def test_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "p.hl7"
    os.mkfifo(fifo)
    assert _within(5.0, lambda: read_capped(fifo, 1024)) == (b"", NOT_REGULAR)


def test_a_file_swapped_for_a_bigger_one_after_the_stat_is_judged_on_the_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stat-then-open window: the path's stat says small, the file actually opened is over the
    cap. Without the fstat on the handle this read up to the cap and kept it."""
    cap = 64
    big = tmp_path / "big.hl7"
    big.write_bytes(b"x" * (cap * 4))
    small = tmp_path / "small.hl7"
    small.write_bytes(b"x")
    small_stat = small.stat()
    monkeypatch.setattr(Path, "stat", lambda self, **kw: small_stat)
    assert read_capped(big, cap) == (b"", f"{cap * 4} bytes, over the {cap}-byte cap; not read")


def test_a_file_that_grows_while_read_is_refused_not_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both stats report a small size, but more is there to read: at most one byte past the cap is
    read, and the file is refused rather than kept cut short."""
    cap = 64
    grown = tmp_path / "grown.hl7"
    grown.write_bytes(b"x" * (cap * 4))
    small = tmp_path / "small.hl7"
    small.write_bytes(b"x")
    small_stat = small.stat()
    monkeypatch.setattr(Path, "stat", lambda self, **kw: small_stat)
    monkeypatch.setattr(os, "fstat", lambda fd: small_stat)
    assert read_capped(grown, cap) == (b"", f"grew past the {cap}-byte cap while read; not kept")


@pytest.mark.parametrize("reported", [0, 1, 63, 64])
def test_a_file_that_grows_while_read_is_read_at_most_one_byte_past_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reported: int
) -> None:
    """The handle's offset after the read is the bytes taken from the file: never more than one
    past the cap, however far the file has grown past what its ``fstat`` reported (PR 3076's known
    defect 4: a buffered read could take up to its buffer's worth more)."""
    cap = 64
    grown = tmp_path / "grown.hl7"
    grown.write_bytes(b"x" * (1 << 20))
    real_fstat = os.fstat

    def fstat(fd: int) -> os.stat_result:
        st = list(real_fstat(fd))
        st[6] = reported  # st_size
        return os.stat_result(st)

    monkeypatch.setattr(os, "fstat", fstat)
    fd = os.open(grown, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        assert read_fd_capped(fd, cap) == (
            b"",
            f"grew past the {cap}-byte cap while read; not kept",
        )
        assert os.lseek(fd, 0, os.SEEK_CUR) <= cap + 1
    finally:
        os.close(fd)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privilege on Windows")
def test_a_symlink_is_not_followed_when_asked(tmp_path: Path) -> None:
    target = tmp_path / "t.hl7"
    target.write_bytes(_BODY)
    link = tmp_path / "l.hl7"
    link.symlink_to(target)
    assert read_capped(link, 1024, follow_symlinks=False) == (b"", NOT_REGULAR)
    assert read_capped(link, 1024) == (
        _BODY,
        "",
    )  # followed by default; the reconcile loader relies on it


# --- the File sink -----------------------------------------------------------------------------------


def test_the_file_sink_cap_defaults_to_the_engine_message_cap(tmp_path: Path) -> None:
    assert FileSink(tmp_path).max_file_bytes == DEFAULT_MAX_MESSAGE_BYTES


def test_the_file_sink_records_an_over_cap_file_as_refused_and_unread(tmp_path: Path) -> None:
    with FileSink(tmp_path) as sink:
        sink.max_file_bytes = len(_BODY)
        (tmp_path / "ok.hl7").write_bytes(_BODY)
        (tmp_path / "big.hl7").write_bytes(_BODY + b"X")
        (tmp_path / "dir.hl7").mkdir()
        records = sink.records()
        assert sink.records() == records  # a refused file is recorded once, not on every scan
    by_name = {r.meta["name"]: r for r in records}
    assert set(by_name) == {"ok.hl7", "big.hl7"}  # a directory is skipped, as before
    assert by_name["ok.hl7"].payload == _BODY and "refused" not in by_name["ok.hl7"].meta
    assert by_name["big.hl7"].payload == b""
    assert by_name["big.hl7"].meta["refused"].endswith(f"over the {len(_BODY)}-byte cap; not read")


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:
        if sys.platform != "win32":
            raise  # POSIX makes a symlink unprivileged: a failure here is a broken test
        pytest.skip(f"no symlink privilege here (Developer Mode off): {exc}")


def test_the_file_sink_reports_a_symlink_unread_with_where_it_resolves(tmp_path: Path) -> None:
    """A symlink is not followed, and it is not skipped either: it is recorded unread, so a link
    out of the directory reads as an escape rather than as nothing at all."""
    outside = tmp_path / "outside.txt"
    outside.write_bytes(_BODY)
    out = tmp_path / "out"
    out.mkdir()
    with FileSink(out) as sink:
        (out / "ok.hl7").write_bytes(_BODY)
        _symlink_or_skip(out / "link.hl7", outside)
        _symlink_or_skip(out / "in.hl7", out / "ok.hl7")
        # A name the sink skips for a file (a dot-file, an engine temp) does not hide a link.
        _symlink_or_skip(out / ".dot", outside)
        _symlink_or_skip(out / "x.part", outside)
        records = sink.records()
        assert sink.records() == records  # recorded once, not on every scan
    by_name = {r.meta["name"]: r for r in records}
    assert set(by_name) == {"ok.hl7", "link.hl7", "in.hl7", ".dot", "x.part"}
    assert {by_name[n].meta["inside"] for n in (".dot", "x.part")} == {"false"}
    assert by_name["ok.hl7"].payload == _BODY and "symlink" not in by_name["ok.hl7"].meta
    for name, inside in (("link.hl7", "false"), ("in.hl7", "true")):
        record = by_name[name]
        assert record.payload == b"", name  # never read through the link
        assert record.meta["refused"] == NOT_REGULAR
        assert record.meta["symlink"] == "true"
        assert record.meta["inside"] == inside, name


@pytest.mark.skipif(sys.platform != "win32", reason="a junction is a Windows reparse point")
def test_the_file_sink_reports_a_junction_as_a_link_not_a_directory(tmp_path: Path) -> None:
    """``S_ISLNK`` does not report a junction, so the sink reads the reparse tag as well: a junction
    out of the directory is recorded as a link that resolves outside, and never walked through, so
    nothing beyond it is listed or read. One to a folder inside is the control: it reads inside."""
    import _winapi  # type: ignore[import-not-found,unused-ignore]

    junction = _winapi.CreateJunction  # type: ignore[attr-defined,unused-ignore]
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "secret.hl7").write_bytes(_BODY)
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    with FileSink(out) as sink:
        junction(str(outside), str(out / "j.hl7"))
        junction(str(out / "sub"), str(out / "jin.hl7"))
        junction(str(out), str(out / "loop"))
        records = sink.records()
    by_name = {r.meta["name"]: r for r in records}
    assert set(by_name) == {"j.hl7", "jin.hl7", "loop"}  # nothing read through any of them
    assert all(r.meta["symlink"] == "true" and r.payload == b"" for r in records)
    assert by_name["j.hl7"].meta["inside"] == "false"
    assert by_name["jin.hl7"].meta["inside"] == "true"


def test_the_file_sink_reports_a_symlink_loop_as_not_inside(tmp_path: Path) -> None:
    with FileSink(tmp_path) as sink:
        _symlink_or_skip(tmp_path / "loop.hl7", tmp_path / "loop.hl7")
        records = sink.records()
    assert [(r.meta["name"], r.meta["inside"]) for r in records] == [("loop.hl7", "false")]


def test_the_file_sink_reports_a_path_it_cannot_resolve_as_not_inside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resolve that fails mid-scan neither ends the scan nor passes for inside: the file is still
    recorded, judged not inside, and the files after it are still read."""
    with FileSink(tmp_path) as sink:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "a.hl7").write_bytes(_BODY)
        (tmp_path / "b.hl7").write_bytes(_BODY)
        real = Path.resolve

        def resolve(self: Path, strict: bool = False) -> Path:
            if self.name == "sub":
                raise OSError(errno.ENOENT, "gone mid-scan")
            return real(self, strict)

        monkeypatch.setattr(Path, "resolve", resolve)
        records = sink.records()
    inside = {r.meta["relpath"]: r.meta["inside"] for r in records}
    assert inside == {"sub/a.hl7": "false", "b.hl7": "true"}


def test_the_file_sink_records_a_file_changed_while_read_once_it_settles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file replaced between the scan's lstat and its read is not recorded under the stale
    signature, which would record the new bytes a second time on the next scan."""
    import harness.sinks.file as file_sink

    target = tmp_path / "x.hl7"
    with FileSink(tmp_path) as sink:
        target.write_bytes(b"MSH|first\r")
        real = read_fd_capped

        def swap_then_read(fd: int, cap: int) -> tuple[bytes, str]:
            monkeypatch.setattr(file_sink, "read_fd_capped", real)
            target.write_bytes(_BODY)  # a different size: the signature moves
            return real(fd, cap)

        monkeypatch.setattr(file_sink, "read_fd_capped", swap_then_read)
        assert sink.records() == []  # changed while read: not recorded yet
        settled = sink.records()
        assert sink.records() == settled
    assert [r.payload for r in settled] == [_BODY]


def test_the_file_sink_records_a_file_removed_right_after_its_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file read whole and then moved away is still a delivery, judged inside by its folder."""
    target = tmp_path / "x.hl7"
    with FileSink(tmp_path) as sink:
        target.write_bytes(_BODY)
        real = FileSink._inside

        def remove_after_read(self: FileSink, path: Path, link: bool, *rest: Any) -> bool:
            path.unlink()  # the handle is closed by now, as it is when the engine moves a file on
            return real(self, path, link, *rest)

        monkeypatch.setattr(FileSink, "_inside", remove_after_read)
        records = sink.records()
    assert [(r.payload, r.meta["inside"]) for r in records] == [(_BODY, "true")]


def test_the_file_sink_does_not_record_a_chmod_as_a_write(tmp_path: Path) -> None:
    target = tmp_path / "x.hl7"
    with FileSink(tmp_path) as sink:
        target.write_bytes(_BODY)
        first = sink.records()
        target.chmod(0o444)
        try:
            assert sink.records() == first
        finally:
            target.chmod(0o644)
    assert len(first) == 1


def test_the_file_sink_records_a_file_overwritten_in_place(tmp_path: Path) -> None:
    """A file present at start is ignored only while it is unchanged, and a recorded file that is
    written again is recorded again: an in-place overwrite is a delivery, not a repeat."""
    old = tmp_path / "old.hl7"
    old.write_bytes(b"MSH|stale\r")
    with FileSink(tmp_path) as sink:
        assert sink.records() == []
        old.write_bytes(_BODY)
        first = sink.records()
        assert [r.payload for r in first] == [_BODY]
        assert sink.records() == first  # unchanged since: not recorded again
        old.write_bytes(_BODY + b"PID|1\r")
        again = sink.records()
    assert [r.payload for r in again] == [_BODY, _BODY + b"PID|1\r"]


@pytest.mark.parametrize("code", [errno.ELOOP, errno.EMLINK], ids=["ELOOP", "EMLINK"])
def test_a_symlink_swapped_in_after_the_lstat_is_not_regular(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """Where O_NOFOLLOW exists, a file swapped for a symlink between the lstat and the open fails the
    open with ELOOP (EMLINK on FreeBSD). Not following, that is NOT_REGULAR, as a symlink seen by the
    lstat is, so every caller treats it alike; following, or for any other errno, it still raises."""
    target = tmp_path / "f.hl7"
    target.write_bytes(b"MSH|")

    def refuse(path: object, flags: int, *args: object) -> int:
        raise OSError(code, "link")

    monkeypatch.setattr(os, "open", refuse)
    assert read_capped(target, 1024, follow_symlinks=False) == (b"", NOT_REGULAR)
    with pytest.raises(OSError):
        read_capped(target, 1024)

    def locked(path: object, flags: int, *args: object) -> int:
        raise PermissionError(errno.EACCES, "locked")

    monkeypatch.setattr(os, "open", locked)
    with pytest.raises(PermissionError):
        read_capped(target, 1024, follow_symlinks=False)


_BAD_NAMES = ("", ".", "..", "a/b", "a\0b", "a\\b", "x.", "x ")
#: Refused by Windows rules only: a colon, and names `ntpath.isreserved` reports (`nul` is
#: the NUL device; `NUL.txt` is refused only because `isreserved` reports it).
_WINDOWS_BAD_NAMES = ("C:", "D:x", "a:b", "nul", "NUL.txt")


@pytest.mark.parametrize("windows", [False, True], ids=["posix-rules", "windows-rules"])
def test_the_file_sink_refuses_an_unsafe_listed_name_before_joining_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    """Each listed name passes ``_unsafe_listed_name`` before it is joined onto its folder. A name a
    real listing should never yield (empty, ``.``, ``..``, a separator, a NUL) or, by Windows rules,
    one holding a colon or that ``ntpath.isreserved`` reports (a trailing dot or space, ``nul``,
    ``NUL.txt``), is recorded
    unread and refused, once, and never joined, entered or read. The names are mocked into the
    listing, since no filesystem here can create them."""
    from harness.sinks import file as file_sink

    monkeypatch.setattr(file_sink, "_WINDOWS", windows)
    real = os.scandir

    class _Entry:
        def __init__(self, name: str) -> None:
            self.name = name

    class _Listing:
        def __init__(self, folder: Path | int) -> None:
            self.folder = folder

        def __enter__(self) -> list[_Entry]:
            with real(self.folder) as listing:
                names = [entry.name for entry in listing]
            held = self.folder
            listed = os.fstat(held) if isinstance(held, int) else os.stat(held)
            if os.path.samestat(listed, os.stat(tmp_path)):
                # Never by POSIX rules on a Windows host, where `C:` would join to the folder
                # or a path on that drive, depending on the folder's drive.
                names += _BAD_NAMES + (_WINDOWS_BAD_NAMES if windows else ())
            return [_Entry(n) for n in names]

        def __exit__(self, *exc: object) -> None:
            return None

    with FileSink(tmp_path) as sink:
        (tmp_path / "ok.hl7").write_bytes(_BODY)
        monkeypatch.setattr(os, "scandir", _Listing)
        records = sink.records()
        assert sink.records() == records  # recorded once, not on every scan
        monkeypatch.setattr(os, "scandir", real)
    expected = {"", ".", "..", "a/b", "a\0b"}
    if windows or os.name == "nt":
        expected.add("a\\b")
    if windows:
        expected |= {"x.", "x ", *_WINDOWS_BAD_NAMES}
    unsafe = file_sink.UNSAFE_NAME
    refused = {r.meta["name"]: r for r in records if r.meta.get("refused") == unsafe}
    assert set(refused) == expected
    for record in refused.values():
        assert record.payload == b""
        assert record.meta["inside"] == "false"
        assert record.meta["folder"] == "."
        assert "path" not in record.meta  # never joined, so no path to report
    assert [r.meta["name"] for r in records if "refused" not in r.meta] == ["ok.hl7"]
