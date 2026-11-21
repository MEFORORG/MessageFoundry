# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness File sink's walk (BACKLOG #5426): the swap races it closes, its checked and bounded
root, a file replaced right after its read, the pattern, the checks that read its records, and the
errors it logs. Each race is staged at the exact moment it names, through a hook on the call that
opens or lists the swapped entry. Synthetic bytes only."""

from __future__ import annotations

import logging
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import harness.bounded_file as bounded_file
import harness.sinks.file as file_sink
from harness.bounded_file import NOT_REGULAR
from harness.scenarios import SCENARIOS
from harness.scenarios._core import Scenario, _verify_sink, sink_faults
from harness.scenarios.internal import TimerScenario
from harness.scenarios.remotefile import RemoteFileScenario, verify_written
from harness.sinks import Record, Sink
from harness.sinks.file import ROOT_CHANGED, UNSAFE_NAME, WALK_BOUND, FileSink

_BODY = b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X1|P|2.5.1\r"
_SECRET = b"MSH|^~\\&|S|S|S|S|20260101||ADT^A01|SECRET|P|2.5.1\r"
_LATER = b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X2|P|2.5.1\rPID|1\r"


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:
        if sys.platform != "win32":
            raise  # POSIX makes a symlink unprivileged: a failure here is a broken test
        pytest.skip(f"no symlink privilege here (Developer Mode off): {exc}")


def _named(target: object, name: str) -> bool:
    """Whether a path or a name passed to ``os.open``/``os.scandir`` names ``name``; a held
    directory handle (an int) names nothing here."""
    return isinstance(target, (str, os.PathLike)) and Path(os.fspath(target)).name == name


def _once(action: Callable[[], None]) -> Callable[[], None]:
    done: list[bool] = []

    def run() -> None:
        if not done:
            done.append(True)
            action()

    return run


# --- step 1: the swap races ----------------------------------------------------------------------


@pytest.mark.skipif(
    not file_sink._DIR_FD,
    reason="no dir_fd here (Windows): a folder is listed by path, and this race stays open",
)
def test_a_folder_swapped_for_a_link_after_its_lstat_is_not_listed_or_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk saw ``sub`` as a plain folder; it is swapped for a link to a folder outside before
    it is listed. Opened relative to its held parent with ``O_NOFOLLOW``, the link is refused, so
    nothing outside is listed or read; the next scan records the link itself, unread."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.hl7").write_bytes(_SECRET)
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)

    fired: list[bool] = []

    def swap() -> None:
        fired.append(True)
        (out / "sub").rename(tmp_path / "sub-moved")
        (out / "sub").symlink_to(outside, target_is_directory=True)

    swap_once = _once(swap)
    real_scandir, real_open = os.scandir, os.open

    def scandir(target: Any = ".") -> Any:
        if _named(target, "sub"):
            swap_once()
        return real_scandir(target)

    def open_(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if _named(target, "sub"):
            swap_once()
        return real_open(target, flags, *args, **kwargs)

    with FileSink(out) as sink:
        (out / "sub" / "a.hl7").write_bytes(_BODY)
        monkeypatch.setattr(os, "scandir", scandir)
        monkeypatch.setattr(os, "open", open_)
        sink.records()
        monkeypatch.undo()
        records = sink.records()
    assert fired, "the hook never fired: the swap was not staged"
    assert all(r.payload != _SECRET for r in records), "a file outside was read through the link"
    assert [(r.meta["relpath"], r.meta.get("symlink")) for r in records] == [("sub", "true")]


def _is_unread_link(record: Record) -> bool:
    return record.payload == b"" and record.meta.get("symlink") == "true"


@pytest.mark.parametrize("restore", [True, False], ids=["swapped-back", "left-swapped"])
def test_a_file_swapped_for_a_link_between_lstat_and_open_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore: bool
) -> None:
    """``a.hl7`` is swapped for a link to a file outside right as it is opened, and either swapped
    back once the open returns, so a later ``lstat`` of the path sees the original file again, or
    left a link. Nothing outside is read either way. Where the OS has ``O_NOFOLLOW`` the open
    refuses the link and it is recorded as a link. Where the open follows it (Windows), the handle
    is the outside file, not the file the ``lstat`` saw: a link still there is recorded as a link,
    and one swapped back leaves the real file for the next scan to read."""
    outside = tmp_path / "secret.hl7"
    outside.write_bytes(_SECRET)
    out = tmp_path / "out"
    out.mkdir()
    target, kept = out / "a.hl7", tmp_path / "a.keep"
    probe = tmp_path / "probe"
    _symlink_or_skip(probe, outside)
    probe.unlink()
    real_open = os.open
    fired: list[bool] = []

    def open_(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not _named(path, "a.hl7") or fired:
            return real_open(path, flags, *args, **kwargs)
        fired.append(True)
        target.rename(kept)
        target.symlink_to(outside)
        try:
            return real_open(path, flags, *args, **kwargs)
        finally:
            if restore:
                target.unlink()
                kept.rename(target)

    with FileSink(out) as sink:
        target.write_bytes(_BODY)
        monkeypatch.setattr(os, "open", open_)
        sink.records()
        records = sink.records()
    assert fired, "the hook never fired: the swap was not staged"
    if restore:
        # Nothing recorded for the swap itself; the real file is read once it is back.
        assert [r.payload for r in records] == [_BODY]
    else:
        assert [(r.meta["relpath"], _is_unread_link(r)) for r in records] == [("a.hl7", True)]


@pytest.mark.parametrize("restore", [True, False], ids=["swapped-back", "left-swapped"])
def test_the_by_path_walk_still_refuses_a_file_swapped_for_a_link_at_its_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore: bool
) -> None:
    """The by-path walk (Windows, or any OS without ``dir_fd``) is exercised on every OS: the
    handle check refuses the swap there too."""
    monkeypatch.setattr(file_sink, "_DIR_FD", False)
    test_a_file_swapped_for_a_link_between_lstat_and_open_is_not_read(
        tmp_path, monkeypatch, restore
    )


# --- step 2: the root, and the bound -----------------------------------------------------------


def test_the_sink_refuses_a_directory_that_is_a_link(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "out"
    _symlink_or_skip(link, real)
    with pytest.raises(NotADirectoryError):
        FileSink(link).start()


@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_a_root_swapped_after_start_is_reported_and_not_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, by_path: bool
) -> None:
    """The sink directory renamed away and replaced by another folder holding a file: the scan
    records one ``ROOT_CHANGED`` refusal and reads nothing from the new folder."""
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    out = tmp_path / "out"
    with FileSink(out) as sink:
        out.rename(tmp_path / "out-moved")
        out.mkdir()
        (out / "a.hl7").write_bytes(_SECRET)
        records = sink.records()
        assert sink.records() == records  # reported once, not on every scan
    assert [(r.payload, r.meta["refused"]) for r in records] == [(b"", ROOT_CHANGED)]


@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_a_root_briefly_missing_is_retried_not_reported_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, by_path: bool
) -> None:
    """The sink directory missing for a poll (a dropped share, a rename away and back) is not
    ``ROOT_CHANGED``: back with the same identity, scanning carries on and nothing is at fault."""
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    out = tmp_path / "out"
    with FileSink(out) as sink:
        out.rename(tmp_path / "out-away")
        assert sink.records() == []
        (tmp_path / "out-away").rename(out)
        (out / "a.hl7").write_bytes(_BODY)
        records = sink.records()
    assert [r.payload for r in records] == [_BODY]
    assert sink_faults(records) == ""


def test_a_root_swapped_for_a_link_after_start_is_reported_and_not_scanned(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.hl7").write_bytes(_SECRET)
    out = tmp_path / "out"
    with FileSink(out) as sink:
        out.rename(tmp_path / "out-moved")
        _symlink_or_skip(out, outside)
        records = sink.records()
    assert [(r.payload, r.meta["refused"]) for r in records] == [(b"", ROOT_CHANGED)]


def test_a_scan_has_no_entry_bound(tmp_path: Path) -> None:
    """A large output directory starts and is polled whole: only depth bounds a scan, so a tree
    with many names, in the directory and in sub-folders, is recorded with no WALK_BOUND."""
    assert not hasattr(FileSink, "max_entries")
    (tmp_path / "sub").mkdir()
    for i in range(20):
        (tmp_path / f"old{i}.hl7").write_bytes(_BODY)
        (tmp_path / "sub" / f"old{i}.hl7").write_bytes(_BODY)
    with FileSink(tmp_path) as sink:
        assert sink.records() == []  # all taken as already there, none past a bound
        for i in range(20):
            (tmp_path / "sub" / f"new{i}.hl7").write_bytes(_BODY)
        records = sink.records()
    assert len(records) == 20 and all("refused" not in r.meta for r in records)


@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_an_unreadable_sub_folder_does_not_fail_start_and_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, by_path: bool
) -> None:
    """A sub-folder that cannot be listed (``lost+found``, ``System Volume Information``) is logged
    and skipped, at start and on every scan; only the directory itself failing fails start()."""
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    (tmp_path / "locked").mkdir()
    locked = os.stat(tmp_path / "locked")
    real_scandir = os.scandir

    def scandir(target: Any = ".") -> Any:
        listed = os.fstat(target) if isinstance(target, int) else os.stat(target)
        if os.path.samestat(listed, locked):
            raise PermissionError(13, "denied")
        return real_scandir(target)

    monkeypatch.setattr(os, "scandir", scandir)
    with FileSink(tmp_path) as sink:
        (tmp_path / "a.hl7").write_bytes(_BODY)
        records = sink.records()
    assert [r.payload for r in records] == [_BODY]


def test_a_scan_stops_at_its_depth_bound(tmp_path: Path) -> None:
    with FileSink(tmp_path) as sink:
        sink.max_depth = 1
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "top.hl7").write_bytes(_BODY)
        (tmp_path / "a" / "one.hl7").write_bytes(_BODY)
        (tmp_path / "a" / "b" / "two.hl7").write_bytes(_BODY)
        records = sink.records()
    assert [r.meta.get("relpath") for r in records if "relpath" in r.meta] == [
        "a/one.hl7",
        "top.hl7",
    ]
    assert [r.meta["refused"] for r in records if "relpath" not in r.meta] == [WALK_BOUND]


# --- step 3: a file replaced right after its read ----------------------------------------------


def test_a_file_replaced_right_after_its_read_is_recorded_and_so_is_its_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What was read was the whole, settled file: an atomic replace at its path just after the
    read neither drops it nor stops the next scan recording the replacement."""
    target = tmp_path / "x.hl7"
    replacement = tmp_path.parent / f"{tmp_path.name}-next.hl7"
    real = FileSink._inside

    def replace_after_read(self: FileSink, path: Path, link: bool, *rest: Any) -> bool:
        if replacement.exists():
            os.replace(replacement, target)
        return real(self, path, link, *rest)

    with FileSink(tmp_path) as sink:
        target.write_bytes(_BODY)
        replacement.write_bytes(_LATER)
        monkeypatch.setattr(FileSink, "_inside", replace_after_read)
        sink.records()
        records = sink.records()
    assert [r.payload for r in records] == [_BODY, _LATER]


# --- step 4: the pattern, and the checks that read the records ---------------------------------


def test_a_recursive_pattern_matches_a_top_level_file_too(tmp_path: Path) -> None:
    with FileSink(tmp_path, pattern="**/*.hl7") as sink:
        (tmp_path / "sub").mkdir()
        (tmp_path / "top.hl7").write_bytes(_BODY)
        (tmp_path / "sub" / "nested.hl7").write_bytes(_BODY)
        (tmp_path / "other.txt").write_bytes(_BODY)
        records = sink.records()
    assert [r.meta["relpath"] for r in records] == ["sub/nested.hl7", "top.hl7"]


def test_verify_written_fails_on_an_over_cap_record() -> None:
    scenario = SCENARIOS["remotefile_write_out"]
    assert isinstance(scenario, RemoteFileScenario)
    good = Record(_BODY, {"relpath": "X1.hl7", "inside": "true"})
    over = Record(b"", {"relpath": "big.hl7", "inside": "true", "refused": "9 bytes, over the cap"})
    assert verify_written(scenario, [good], {"X1": _BODY}, "p").ok
    result = verify_written(scenario, [good, over], {"X1": _BODY}, "p")
    assert not result.ok and "was not read ('big.hl7')" in result.detail


class _Fake(Sink):
    kind = "file"


def _link_record() -> Record:
    meta = {"relpath": "L.hl7", "inside": "false", "symlink": "true", "refused": "x"}
    return Record(b"", meta)


def test_verify_sink_fails_on_a_link_in_the_sink() -> None:
    scenario = Scenario("s", "", "ADT", "A01", 1, sink="file", sink_endpoint="file_out")
    fake = _Fake()
    fake._add(Record(_BODY))
    assert _verify_sink(scenario, fake, ["X1"], 0.2, "p").ok
    fake._add(_link_record())
    result = _verify_sink(scenario, fake, ["X1"], 0.2, "p")
    assert not result.ok and "a link appeared in the sink ('L.hl7')" in result.detail


def test_the_timer_scenario_fails_on_a_link_in_the_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    from harness import sinks

    scenario = TimerScenario("t", "")
    timer = _BODY.replace(b"|X1|", f"|{scenario.control_id}|".encode())
    fake = _Fake()
    for _ in range(scenario.arrivals):
        fake._add(Record(timer))
    monkeypatch.setattr(sinks, "build", lambda *args: fake)
    monkeypatch.setattr(
        TimerScenario, "_statuses_since", lambda *args: ["processed"] * scenario.arrivals
    )
    ctx: Any = SimpleNamespace(endpoints=None, client=None, timeout=0.5)
    assert scenario.run(ctx).ok
    fake._add(_link_record())
    result = scenario.run(ctx)
    assert not result.ok and "a link appeared in the sink ('L.hl7')" in result.detail


# --- step 6: the errors it logs ----------------------------------------------------------------


@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_listing_lstat_and_open_errors_are_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    by_path: bool,
) -> None:
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    real_scandir, real_open, real_stat, real_lstat = os.scandir, os.open, os.stat, os.lstat

    def denied(target: Any, name: str) -> None:
        if _named(target, name):
            raise PermissionError(13, "denied", name)

    locked: list[os.stat_result] = []

    def scandir(target: Any = ".") -> Any:
        denied(target, "locked")
        if isinstance(target, int) and os.path.samestat(os.fstat(target), locked[0]):
            raise PermissionError(13, "denied", "locked")  # the folder, held by its handle
        return real_scandir(target)

    def open_(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        denied(target, "c.hl7")
        return real_open(target, flags, *args, **kwargs)

    def stat_(target: Any, *args: Any, **kwargs: Any) -> Any:
        denied(target, "b.hl7")
        return real_stat(target, *args, **kwargs)

    def lstat_(target: Any, *args: Any, **kwargs: Any) -> Any:
        denied(target, "b.hl7")
        return real_lstat(target, *args, **kwargs)

    with FileSink(tmp_path) as sink:
        (tmp_path / "locked").mkdir()
        locked.append(real_stat(tmp_path / "locked"))
        for name in ("b.hl7", "c.hl7"):
            (tmp_path / name).write_bytes(_BODY)
        monkeypatch.setattr(os, "scandir", scandir)
        monkeypatch.setattr(os, "open", open_)
        monkeypatch.setattr(os, "stat", stat_)
        monkeypatch.setattr(os, "lstat", lstat_)
        with caplog.at_level(logging.WARNING, logger="harness.sinks.file"):
            assert sink.records() == []
            assert sink.records() == []  # a fault that persists is logged once, not every poll
    messages = [r.getMessage() for r in caplog.records]
    for said in ("cannot list a folder", "cannot lstat an entry", "cannot open a file"):
        assert len([m for m in messages if said in m]) == 1, (said, messages)
    # A File outbound can render a name from HL7 fields, so no listed name reaches the log.
    assert not any(name in caplog.text for name in ("locked", "b.hl7", "c.hl7"))


@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_a_directory_that_cannot_be_listed_is_retried_not_reported_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, by_path: bool
) -> None:
    """A permissions or handle fault on the sink directory itself is a failed scan, retried on
    the next one; it is not the ``ROOT_CHANGED`` refusal, which says the directory was replaced.
    At start it is an error, since without a whole first scan files already there would later
    read as new deliveries."""
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    real_scandir = os.scandir
    denied: list[bool] = [False]

    def scandir(target: Any = ".") -> Any:
        if denied[0]:
            raise PermissionError(13, "denied")
        return real_scandir(target)

    monkeypatch.setattr(os, "scandir", scandir)
    denied[0] = True
    with pytest.raises(NotADirectoryError):
        FileSink(tmp_path).start()
    denied[0] = False
    with FileSink(tmp_path) as sink:
        (tmp_path / "a.hl7").write_bytes(_BODY)
        denied[0] = True
        assert sink.records() == []
        denied[0] = False
        records = sink.records()
    assert [r.payload for r in records] == [_BODY]


@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_start_ignores_a_lstat_fault_on_an_entry_it_would_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, by_path: bool
) -> None:
    """An engine temp the sink never records (here ``x.part``, e.g. delete-pending on Windows)
    whose lstat fails does not make the first scan partial, so start() succeeds."""
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    (tmp_path / "x.part").write_bytes(b"half")
    real_stat, real_lstat = os.stat, os.lstat

    def stat_(target: Any, *args: Any, **kwargs: Any) -> Any:
        if _named(target, "x.part"):
            raise PermissionError(13, "denied")
        return real_stat(target, *args, **kwargs)

    def lstat_(target: Any, *args: Any, **kwargs: Any) -> Any:
        if _named(target, "x.part"):
            raise PermissionError(13, "denied")
        return real_lstat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_)
    monkeypatch.setattr(os, "lstat", lstat_)
    with FileSink(tmp_path) as sink:
        (tmp_path / "a.hl7").write_bytes(_BODY)
        records = sink.records()
    assert [r.payload for r in records] == [_BODY]


def test_an_over_cap_file_is_refused_from_its_lstat_and_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[str] = []
    real_open = os.open

    def open_(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if isinstance(target, (str, os.PathLike)):
            opened.append(Path(os.fspath(target)).name)
        return real_open(target, flags, *args, **kwargs)

    with FileSink(tmp_path) as sink:
        sink.max_file_bytes = len(_BODY)
        (tmp_path / "ok.hl7").write_bytes(_BODY)
        (tmp_path / "big.hl7").write_bytes(_BODY + b"X")
        monkeypatch.setattr(os, "open", open_)
        records = sink.records()
    by_name = {r.meta["name"]: r for r in records}
    assert by_name["big.hl7"].payload == b""
    assert by_name["big.hl7"].meta["refused"].endswith(f"over the {len(_BODY)}-byte cap; not read")
    assert "ok.hl7" in opened, "the spy saw no open: the test proves nothing"
    assert "big.hl7" not in opened


def test_verify_sink_fails_on_a_non_file_entry_in_the_sink() -> None:
    scenario = Scenario("s", "", "ADT", "A01", 1, sink="file", sink_endpoint="file_out")
    fake = _Fake()
    fake._add(Record(_BODY))
    meta = {"relpath": "f.hl7", "inside": "true", "refused": NOT_REGULAR}
    fake._add(Record(b"", meta))
    result = _verify_sink(scenario, fake, ["X1"], 0.2, "p")
    assert not result.ok and "a non-file entry appeared in the sink ('f.hl7')" in result.detail


def test_verify_sink_fails_on_an_incomplete_file_scan() -> None:
    scenario = Scenario("s", "", "ADT", "A01", 1, sink="file", sink_endpoint="file_out")
    fake = _Fake()
    fake._add(Record(_BODY))
    fake._add(Record(b"", {"name": "out", "folder": ".", "inside": "false", "refused": WALK_BOUND}))
    result = _verify_sink(scenario, fake, ["X1"], 0.2, "p")
    assert not result.ok and "scan was incomplete" in result.detail


def test_a_volume_with_no_file_id_gives_no_identity() -> None:
    """``st_ino`` 0 (a volume with no file id) is no identity, so two folders that both report it
    are not taken for one already entered, and a root that reports it is not compared."""
    zero = os.stat_result((0o040755, 0, 7, 1, 0, 0, 0, 0, 0, 0))
    assert file_sink._identity(zero) is None
    assert file_sink._identity(os.stat_result((0o040755, 5, 7, 1, 0, 0, 0, 0, 0, 0))) == (7, 5)


# --- the checks that read its records (PR 3076's known defects 2 and 7) -------------------------


def _escaped_record() -> Record:
    """A regular file the sink read whose path resolves outside the directory: no link and no
    refusal, only ``inside`` false."""
    return Record(_SECRET, {"relpath": "sub/x.hl7", "inside": "false"})


def test_verify_sink_fails_on_a_file_read_from_outside_the_directory() -> None:
    scenario = Scenario("s", "", "ADT", "A01", 1, sink="file", sink_endpoint="file_out")
    fake = _Fake()
    fake._add(Record(_BODY))
    assert _verify_sink(scenario, fake, ["X1"], 0.2, "p").ok
    fake._add(_escaped_record())
    result = _verify_sink(scenario, fake, ["X1"], 0.2, "p")
    assert not result.ok and "outside the sink directory was read ('sub/x.hl7')" in result.detail


def test_the_timer_scenario_fails_on_a_file_read_from_outside_the_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from harness import sinks

    scenario = TimerScenario("t", "")
    timer = _BODY.replace(b"|X1|", f"|{scenario.control_id}|".encode())
    fake = _Fake()
    for _ in range(scenario.arrivals):
        fake._add(Record(timer))
    monkeypatch.setattr(sinks, "build", lambda *args: fake)
    monkeypatch.setattr(
        TimerScenario, "_statuses_since", lambda *args: ["processed"] * scenario.arrivals
    )
    ctx: Any = SimpleNamespace(endpoints=None, client=None, timeout=0.5)
    assert scenario.run(ctx).ok
    fake._add(_escaped_record())
    result = scenario.run(ctx)
    assert not result.ok and "outside the sink directory" in result.detail


def test_sink_faults_flags_an_over_cap_file_the_sink_left_unread() -> None:
    over = {"relpath": "big.hl7", "inside": "true", "refused": "9 bytes, over the 8-byte cap"}
    assert "was not read ('big.hl7')" in sink_faults([Record(_BODY), Record(b"", over)])
    # A record that carries no ``inside`` is not a file sink's: its own refusal is that sink's
    # business, and an unread delivery carries no control id either way.
    assert sink_faults([Record(b"", {"refused": "over the cap"})]) == ""


def test_sink_faults_quotes_a_link_name() -> None:
    meta = {"relpath": "a\nb.hl7", "inside": "false", "symlink": "true", "refused": NOT_REGULAR}
    note = sink_faults([Record(b"", meta)])
    assert "\n" not in note and "'a\\nb.hl7'" in note


def test_sink_faults_names_a_refused_name_with_its_folder() -> None:
    def refused(folder: str) -> Record:
        meta = {"name": "nul", "folder": folder, "inside": "false", "refused": UNSAFE_NAME}
        return Record(b"", meta)

    note = sink_faults([refused("."), refused("sub/deeper")])
    assert "('nul', 'sub/deeper/nul')" in note


def test_verify_sink_stops_waiting_on_a_sink_fault() -> None:
    """A link in the sink fails the check whatever else arrives, so the wait ends there rather than
    running out the timeout."""
    scenario = Scenario("s", "", "ADT", "A01", 1, sink="file", sink_endpoint="file_out")
    fake = _Fake()
    fake._add(_link_record())
    started = time.monotonic()
    result = _verify_sink(scenario, fake, ["X1"], 30.0, "p")
    assert not result.ok and time.monotonic() - started < 5.0


# --- the walk's own faults (PR 3076's known defects 5, 6, 8 and 9) ------------------------------


def test_a_directory_gone_before_its_first_listing_fails_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The by-path walk took the directory itself vanishing before its listing for an empty
    folder, so start() took an empty first scan for a whole one."""
    monkeypatch.setattr(file_sink, "_DIR_FD", False)
    out = tmp_path / "out"
    real_scandir = os.scandir

    def scandir(target: Any = ".") -> Any:
        if _named(target, "out"):
            raise FileNotFoundError(2, "gone")
        return real_scandir(target)

    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(NotADirectoryError):
        FileSink(out).start()


def test_a_root_read_fault_at_start_is_raised_with_its_error_not_logged_as_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def scandir(target: Any = ".") -> Any:
        raise PermissionError(13, "denied")

    monkeypatch.setattr(os, "scandir", scandir)
    with (
        caplog.at_level(logging.WARNING, logger="harness.sinks.file"),
        pytest.raises(NotADirectoryError) as raised,
    ):
        FileSink(tmp_path).start()
    assert "retried next scan" not in caplog.text
    assert "errno 13" in str(raised.value)
    assert isinstance(raised.value.__cause__, PermissionError)


def test_a_root_with_a_file_id_where_start_found_none_is_reported_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Started on a volume that reported no file id, a later scan that reads one is not of the
    directory start() found: it is not adopted as that directory."""
    real_identity = file_sink._identity
    no_ids = [True]

    def identity(st: os.stat_result) -> tuple[int, int] | None:
        return None if no_ids[0] else real_identity(st)

    monkeypatch.setattr(file_sink, "_identity", identity)
    with FileSink(tmp_path) as sink:
        no_ids[0] = False
        (tmp_path / "a.hl7").write_bytes(_BODY)
        records = sink.records()
    assert [(r.payload, r.meta["refused"]) for r in records] == [(b"", ROOT_CHANGED)]


def test_the_handle_check_refuses_a_followed_link_on_every_os(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With ``O_NOFOLLOW`` off the file open, as on Windows, a file swapped for a link at its open
    is followed, so only the handle check stands between the walk and the file outside. Where the
    OS has ``O_NOFOLLOW`` the swap tests above are refused at the open before that check runs."""
    monkeypatch.setattr(file_sink, "_DIR_FD", False)
    monkeypatch.setattr(file_sink, "_FILE_FLAGS", file_sink._FILE_FLAGS & ~file_sink._NOFOLLOW)
    test_a_file_swapped_for_a_link_between_lstat_and_open_is_not_read(tmp_path, monkeypatch, False)


@pytest.mark.skipif(not file_sink._DIR_FD, reason="no dir_fd here (Windows): the walk is by path")
def test_a_swap_is_read_again_through_the_held_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``a.hl7`` is replaced by another file between its ``lstat`` and its open. The entry is
    ``lstat``-ed again relative to the held folder, never by its full path."""
    target, other = tmp_path / "a.hl7", tmp_path / "b.tmp"
    real_open, real_stat, real_lstat = os.open, os.stat, os.lstat
    fired: list[bool] = []
    again: list[bool] = []

    def open_(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if _named(path, "a.hl7") and not fired:
            fired.append(True)
            other.write_bytes(_LATER)
            other.replace(target)
        return real_open(path, flags, *args, **kwargs)

    def stat_(path: Any, *args: Any, **kwargs: Any) -> Any:
        if _named(path, "a.hl7"):
            assert kwargs.get("dir_fd") is not None, "the entry was stat-ed by its full path"
            if fired:
                again.append(True)
        return real_stat(path, *args, **kwargs)

    def lstat_(path: Any, *args: Any, **kwargs: Any) -> Any:
        assert not _named(path, "a.hl7"), "the entry was lstat-ed again by its full path"
        return real_lstat(path, *args, **kwargs)

    with FileSink(tmp_path) as sink:
        target.write_bytes(_BODY)
        monkeypatch.setattr(os, "open", open_)
        monkeypatch.setattr(os, "stat", stat_)
        monkeypatch.setattr(os, "lstat", lstat_)
        assert sink.records() == []  # not the file its lstat saw: retried
        monkeypatch.undo()
        records = sink.records()
    assert fired, "the hook never fired: the swap was not staged"
    assert again, "the entry was never stat-ed again after the swap: the test proves nothing"
    assert [r.payload for r in records] == [_LATER]


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows refuses to rename a folder holding an open file"
)
@pytest.mark.parametrize("by_path", [False, True], ids=["native-walk", "by-path-walk"])
def test_a_file_whose_folder_moves_out_after_its_read_is_not_taken_as_inside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, by_path: bool
) -> None:
    """Its folder moved out of the sink directory right after the read: the file is judged by its
    folder's resolved path, so it is not recorded as inside, on either walk."""
    if by_path:
        monkeypatch.setattr(file_sink, "_DIR_FD", False)
    (tmp_path / "sub").mkdir()
    real_read = bounded_file.read_fd_capped

    def read_then_move(fd: int, cap: int) -> tuple[bytes, str]:
        got = real_read(fd, cap)
        (tmp_path / "sub").rename(tmp_path.parent / f"{tmp_path.name}-moved")
        return got

    with FileSink(tmp_path) as sink:
        (tmp_path / "sub" / "a.hl7").write_bytes(_BODY)
        monkeypatch.setattr(file_sink, "read_fd_capped", read_then_move)
        records = sink.records()
    assert not (tmp_path / "sub").exists(), "the folder never moved: the test proves nothing"
    assert [(r.payload, r.meta["inside"]) for r in records] == [(_BODY, "false")]
