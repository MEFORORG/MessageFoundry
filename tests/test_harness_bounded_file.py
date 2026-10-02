# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness's bounded file reader (ASVS 5.1.1), and the File sink that reads through it.

``harness.bounded_file.read_capped`` is shared by the File tab's watch pane, the File and remote-file
sinks and the reconcile loader. These tests pin each refusal, including the stat-then-open window: a
file swapped or grown between the size check and the read is judged on the open handle. Qt-free, so
they run where PySide6 cannot load. Synthetic bytes only.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from harness.bounded_file import NOT_REGULAR, read_capped
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


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privilege on Windows")
def test_the_file_sink_does_not_follow_a_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_bytes(_BODY)
    out = tmp_path / "out"
    out.mkdir()
    with FileSink(out) as sink:
        (out / "ok.hl7").write_bytes(_BODY)
        (out / "link.hl7").symlink_to(outside)
        names = [r.meta["name"] for r in sink.records()]
    assert len(names) >= 1 and names == ["ok.hl7"]
