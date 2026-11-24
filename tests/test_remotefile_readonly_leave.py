# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5750: a remote-file poll on a share it cannot write to.

Under ``after_read = "leave"`` the poll asked for ``.processed`` and ``.error`` on every tick, so a
share that refused the check aborted the poll before it listed anything. A reject whose move to
``.error`` failed stayed in the poll directory, was read again whenever it settled, and spent the
per-tick budget each time, which held back the valid files sorted after it.
"""

from __future__ import annotations

import ftplib
import logging
import stat
import time
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.transports import remotefile
from messagefoundry.transports.file import (
    SETTLE_MISS_LIMIT,
    STUCK_RETRY_SECONDS,
    STUCK_TRANSIENT_RETRY_SECONDS,
    _content_matches_declared,
)
from messagefoundry.transports.remotefile import _FtpClient, _Listed, _RemoteError, _SftpClient
from tests.test_remotefile_leave_replacement import _LOGGER, _Ftp, _StampedClient
from tests.test_remotefile_transport import (
    _FakeClient,
    _FakeLedger,
    _RecordingHandler,
    _settle,
    _src,
)

_GOOD = b"MSH|^~\\&|A|B"
_BAD = b"this is not an HL7 message"
_GOOD_AT_BAD_SIZE = _GOOD + b"x" * (len(_BAD) - len(_GOOD))  # lists as the reject it replaced
_REFUSED = _RemoteError("FTP rejected the operation: 550", permanent=True)


class _RefusingDirsClient(_FakeClient):
    """A share that refuses the directory check, as an SFTP server does when ``stat`` of a path the
    account may not see answers permission denied rather than no such file."""

    def ensure_dir(self, remote_dir: str) -> bool:
        self.dirs.append(remote_dir)
        raise _RemoteError("SFTP operation failed: PermissionError", permanent=False)


def _read_only(files: dict[str, bytes]) -> _RefusingDirsClient:
    return _RefusingDirsClient(files=files, rename_exc=_REFUSED)


def _retrieved(client: _FakeClient, path: str) -> int:
    return sum(1 for op, target in client.ops if op == "retrieve" and target == path)


def _leave(
    monkeypatch: pytest.MonkeyPatch, client: _FakeClient, after_read: str = "leave", **over: Any
) -> Any:
    src = _src(monkeypatch, client, after_read=after_read, **over)
    src.processed_ledger = _FakeLedger()
    src._handler = _RecordingHandler()
    return src


def _make_due(src: Any, name: str, due: float = 0.0) -> None:
    seen, missed = src._stuck[name]
    src._stuck[name] = (seen._replace(due=due), missed)


def test_the_sftp_directory_check_raises_on_a_refused_stat() -> None:
    """The premise of the first test below: the check is best-effort about a refused ``mkdir``, but
    a refused ``stat`` escapes it, so the fake's refusal is one a real server can produce."""

    class _Sftp:
        def stat(self, path: str) -> None:
            raise PermissionError(13, "synthetic")

    with pytest.raises(PermissionError):
        _SftpClient._ensure(_Sftp(), "/in/.processed")


async def test_a_leave_poll_asks_for_no_directory_and_survives_a_refusing_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/a.hl7": _GOOD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_GOOD]
    assert client.dirs == []
    assert "/in/a.hl7" in client.files


@pytest.mark.parametrize("after_read", ["move", "delete"])
async def test_the_other_modes_still_ask_for_both_directories(
    monkeypatch: pytest.MonkeyPatch, after_read: str
) -> None:
    """The control: only ``leave`` stopped asking."""
    client = _FakeClient(files={})
    src = _src(monkeypatch, client, after_read=after_read)
    src._handler = _RecordingHandler()
    await src._poll_once()
    assert client.dirs == ["/in/.processed", "/in/.error"]


async def test_a_leave_reject_on_a_writable_share_still_reaches_the_error_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The directory is asked for when a reject needs it, so quarantine works as it did."""
    client = _FakeClient(files={"/in/bad.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert client.dirs == ["/in/.error"]
    assert client.files == {"/in/.error/bad.hl7": _BAD}
    assert src._stuck == {}


async def test_a_leave_poll_asks_for_the_error_dir_at_most_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each ask is a connection, so several rejects on one poll share one."""
    client = _read_only({"/in/a.hl7": _BAD, "/in/b.hl7": _BAD, "/in/c.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert client.dirs == ["/in/.error"]
    assert sorted(src._stuck) == ["a.hl7", "b.hl7", "c.hl7"]


async def test_a_remembered_reject_costs_no_ledger_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/bad.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    reads = 0
    held = src.processed_ledger.is_processed

    async def counting(file_key: str) -> bool:
        nonlocal reads
        reads += 1
        return await held(file_key)

    src.processed_ledger.is_processed = counting
    await src._poll_once()
    assert reads == 0


async def test_a_refused_error_dir_does_not_stop_the_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/bad.hl7": _BAD, "/in/good.hl7": _GOOD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_GOOD]
    assert "/in/bad.hl7" in client.files, "a reject that cannot move is never dropped"


async def test_a_reject_that_cannot_move_is_not_read_again_on_later_polls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/bad.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    for _ in range(8):
        await src._poll_once()
    assert _retrieved(client, "/in/bad.hl7") == 1
    assert "/in/bad.hl7" in client.files


async def test_a_reject_that_cannot_move_is_read_again_once_its_retry_falls_due(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later retry judges it afresh, so a cause fixed outside the file does not need a restart,
    and the file keeps showing in the log rather than going quiet for good."""
    client = _read_only({"/in/bad.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    _make_due(src, "bad.hl7")
    await src._poll_once()  # a due retry settles first, like any other read
    assert _retrieved(client, "/in/bad.hl7") == 1
    await src._poll_once()
    assert _retrieved(client, "/in/bad.hl7") == 2
    await src._poll_once()  # the retry started a new wait
    assert _retrieved(client, "/in/bad.hl7") == 2


async def test_a_reject_waits_longer_after_its_first_retry_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed move does not say whether it will clear, so the first wait is the short one."""
    client = _read_only({"/in/bad.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    before = time.monotonic()
    await src._poll_once()
    first = src._stuck["bad.hl7"][0].due - before
    assert first <= STUCK_TRANSIENT_RETRY_SECONDS + 5
    _make_due(src, "bad.hl7")
    await _settle(src)
    before = time.monotonic()
    await src._poll_once()
    assert src._stuck["bad.hl7"][0].due - before >= STUCK_RETRY_SECONDS - 5


async def test_a_due_retry_of_a_file_still_being_rewritten_waits_to_settle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rewrite can pass through the remembered size, so that one listing does not admit it."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    _make_due(src, "a.hl7")
    partial = _GOOD_AT_BAD_SIZE  # the remembered size, mid-rewrite
    client.files["/in/a.hl7"] = partial
    await src._poll_once()
    assert src._handler.bodies == [], "one listing at the remembered size must not admit it"
    client.files["/in/a.hl7"] = partial + b"tail"
    await src._poll_once()
    assert src._handler.bodies == []
    await src._poll_once()
    assert src._handler.bodies == [partial + b"tail"]


async def test_a_retried_reject_that_now_passes_is_ingested_and_forgotten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    # The same listed size and no listed time, so only the retry can see the new content.
    client.files["/in/a.hl7"] = _GOOD_AT_BAD_SIZE
    await src._poll_once()
    assert src._handler.bodies == []
    _make_due(src, "a.hl7")
    await _settle(src)
    await src._poll_once()
    assert len(src._handler.bodies) == 1
    assert src._stuck == {}
    assert len(src.processed_ledger.keys) == 1


async def test_a_changed_reject_is_examined_without_waiting_for_its_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    client.files["/in/a.hl7"] = _GOOD  # a different size, so the memory no longer applies
    await src._poll_once()  # it settles again first
    assert src._handler.bodies == []
    await src._poll_once()
    assert src._handler.bodies == [_GOOD]


@pytest.mark.parametrize("after_read", ["leave", "move", "delete"])
async def test_rejects_that_cannot_move_do_not_hold_back_a_valid_file(
    monkeypatch: pytest.MonkeyPatch, after_read: str
) -> None:
    """With a ceiling of one, each reject sorted first spent the whole budget whenever it settled,
    so the wait for the valid file behind them roughly doubled with every reject."""
    files = {f"/in/bad{i}.hl7": _BAD for i in range(6)} | {"/in/z.hl7": _GOOD}
    client = _FakeClient(files=files, rename_exc=_REFUSED)
    src = _leave(monkeypatch, client, after_read=after_read, poll_max_files=1)
    await _settle(src)
    for _ in range(8):  # one poll per reject, one to reach the valid file, and one spare
        await src._poll_once()
    assert src._handler.bodies == [_GOOD]
    assert all(_retrieved(client, f"/in/bad{i}.hl7") == 1 for i in range(6))


async def test_retries_due_on_one_poll_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _read_only({f"/in/bad{i}.hl7": _BAD for i in range(5)})
    src = _leave(monkeypatch, client, poll_max_files=20)  # a retry allowance of two
    await _settle(src)
    await src._poll_once()
    for i in range(5):
        _make_due(src, f"bad{i}.hl7")
    await _settle(src)
    client.ops.clear()
    await src._poll_once()
    assert sum(1 for op, _ in client.ops if op == "retrieve") == 2


async def test_due_retries_past_the_allowance_cost_no_ledger_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({f"/in/bad{i}.hl7": _BAD for i in range(5)})
    src = _leave(monkeypatch, client, poll_max_files=10)  # a retry allowance of one
    await _settle(src)
    await src._poll_once()
    for i in range(5):
        _make_due(src, f"bad{i}.hl7")
    reads = 0
    held = src.processed_ledger.is_processed

    async def counting(file_key: str) -> bool:
        nonlocal reads
        reads += 1
        return bool(await held(file_key))

    src.processed_ledger.is_processed = counting
    await src._poll_once()
    assert reads <= 2, "one slot, at most two key forms"


async def test_a_retry_held_back_by_the_allowance_does_not_keep_an_old_sighting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """b settles on the only slot, then loses it to a, which is due earlier. What b's sighting saw
    must not admit a partial rewrite that only the last poll lists."""
    client = _read_only({"/in/a.hl7": _BAD, "/in/b.hl7": _BAD})
    src = _leave(monkeypatch, client, poll_max_files=5)  # a retry allowance of one
    await _settle(src)
    await src._poll_once()  # both are rejected and remembered
    _make_due(src, "b.hl7", 1.0)
    _make_due(src, "a.hl7", 2.0)
    await src._poll_once()  # b takes the slot and settles
    assert "b.hl7" in src._settle_seen
    _make_due(src, "a.hl7", 0.5)  # as a reject one listing missed comes back due before b
    await src._poll_once()  # a takes the slot and settles; b has none
    client.files["/in/b.hl7"] = _GOOD_AT_BAD_SIZE
    await src._poll_once()  # a is read; b still has no slot
    await src._poll_once()  # b's first sighting of this content
    assert src._handler.bodies == [], "a single listing must not admit it"


async def test_a_skipped_reject_does_not_keep_an_old_sighting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retrieve that saw the file change records a sighting and leaves the reject waiting. The
    poll that skips it must drop that sighting, or the first listing after its wait admits it."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    src._settle_seen["a.hl7"] = ((len(_BAD), None), 0)
    await src._poll_once()  # not due, so skipped
    client.files["/in/a.hl7"] = _GOOD_AT_BAD_SIZE
    _make_due(src, "a.hl7")
    await src._poll_once()  # its first sighting of this content
    assert src._handler.bodies == [], "a single listing must not admit it"
    assert _retrieved(client, "/in/a.hl7") == 1


async def test_a_waiting_reject_past_the_ceiling_does_not_keep_an_old_sighting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pass never reaches it, so the retry pass is what drops the sighting."""
    client = _read_only({"/in/z.hl7": _BAD})
    src = _leave(monkeypatch, client, poll_max_files=1)
    await _settle(src)
    await src._poll_once()
    client.files |= {"/in/a.hl7": _GOOD, "/in/b.hl7": _GOOD}
    await src._poll_once()  # a and b are first seen
    src._settle_seen["z.hl7"] = ((len(_BAD), None), 0)
    await src._poll_once()  # a spends the budget, so the pass stops before z
    assert _retrieved(client, "/in/b.hl7") == 0, "the premise: the ceiling cut this poll"
    assert "z.hl7" not in src._settle_seen


async def test_a_stopped_poll_drops_the_sighting_of_a_due_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stop during the pass gives no reject a slot, so none keeps a sighting into the next start."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    client.files["/in/z.hl7"] = _GOOD
    _make_due(src, "a.hl7")
    await src._poll_once()  # z is first seen; a takes the slot and settles
    assert "a.hl7" in src._settle_seen
    handler = _RecordingHandler()

    async def stopping(raw: bytes) -> str | None:
        src._stop.set()  # after the pass has met a, which is due
        return await handler(raw)

    src._handler = stopping
    await src._poll_once()
    assert handler.bodies == [_GOOD]
    assert "a.hl7" not in src._settle_seen
    assert _retrieved(client, "/in/a.hl7") == 1


async def test_a_retry_is_judged_on_a_listing_taken_after_the_fresh_hand_offs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partner starts rewriting z while a's hand-off runs, so the poll's first listing no longer
    describes it. The retry must see that, as the File source's re-stat does."""
    client = _read_only({"/in/z.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()  # z is rejected and remembered
    client.files["/in/a.hl7"] = _GOOD
    _make_due(src, "z.hl7")
    await src._poll_once()  # a is first seen; z takes the slot and settles
    partial = b"MSH|^~\\&|PARTIAL"
    handler = _grows_during_hand_off(src, client, "/in/z.hl7", partial)
    await src._poll_once()
    assert handler.bodies == [_GOOD], "the partial must not be handed over"
    assert _retrieved(client, "/in/z.hl7") == 1
    assert "z.hl7" not in src._stuck, "a changed listing is a new file"


@pytest.mark.parametrize("failure", ["refused", "name_gone"])
async def test_a_second_listing_that_cannot_judge_a_slot_drops_its_sighting(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, failure: str
) -> None:
    """Open item 3. The slot stays due, and its next sighting must come from consecutive polls."""
    client = _read_only({"/in/z.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    client.files["/in/a.hl7"] = _GOOD
    _make_due(src, "z.hl7")
    await src._poll_once()  # a is first seen; z takes the slot and settles
    assert "z.hl7" in src._settle_seen
    listed = client.list_dir
    calls = 0

    def second_differs(remote_dir: str) -> list[tuple[str, int]]:
        nonlocal calls
        calls += 1
        if calls == 2 and failure == "refused":
            raise _RemoteError("synthetic listing failure", permanent=False)
        rows = listed(remote_dir)
        return [row for row in rows if row[0] != "z.hl7"] if calls == 2 else rows

    monkeypatch.setattr(client, "list_dir", second_differs)
    await src._poll_once()
    assert calls == 2
    assert _retrieved(client, "/in/z.hl7") == 1, "a slot this listing cannot judge must not be read"
    assert src._stuck["z.hl7"][0].due <= time.monotonic(), "it stays due"
    assert "z.hl7" not in src._settle_seen
    assert ("could not list" in caplog.text) is (failure == "refused")


async def test_a_due_retry_already_in_the_ledger_does_not_hold_a_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/a.hl7": _BAD, "/in/b.hl7": _BAD})
    src = _leave(monkeypatch, client, poll_max_files=5)  # a retry allowance of one
    await _settle(src)
    await src._poll_once()  # both are rejected and remembered
    await src.processed_ledger.mark_processed(src._file_key("a.hl7", len(_BAD), None))
    _make_due(src, "a.hl7")
    _make_due(src, "b.hl7")
    for _ in range(4):
        await src._poll_once()
    assert _retrieved(client, "/in/b.hl7") == 2, "the retry sorted after it still runs"
    assert _retrieved(client, "/in/a.hl7") == 1, "a file the ledger holds is not read again"
    assert "a.hl7" not in src._stuck
    assert "/in/a.hl7" in client.files


async def test_a_due_retry_the_full_settle_memory_refuses_gives_up_its_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remotefile, "SETTLE_SEEN_MAX", 2)
    client = _read_only(
        {"/in/a.hl7": _BAD, "/in/b.hl7": _BAD, "/in/x.txt": b"x", "/in/y.txt": b"y"}
    )
    src = _leave(monkeypatch, client, poll_max_files=5)  # a retry allowance of one
    await _settle(src)
    await src._poll_once()  # both are rejected and remembered
    assert sorted(src._stuck) == ["a.hl7", "b.hl7"]
    src._settle_seen.update({"x.txt": ((1, None), 0), "y.txt": ((1, None), 0)})
    _make_due(src, "a.hl7")
    _make_due(src, "b.hl7")
    await src._poll_once()  # a takes the slot and the memory refuses it
    assert src._stuck["a.hl7"][0].due > time.monotonic()
    await src._poll_once()  # so b gets the slot rather than waiting behind a
    assert src._stuck["b.hl7"][0].due > time.monotonic()


async def test_every_stuck_reject_gets_its_retry_when_slots_are_scarce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fifty minutes of 30-second polls with one slot each. In name order the last never ran."""
    names = [f"bad{i:02}.hl7" for i in range(40)]
    client = _read_only({f"/in/{name}": _BAD for name in names})
    src = _leave(monkeypatch, client, poll_max_files=10)  # a retry allowance of one
    await _settle(src)
    for _ in range(4):
        await src._poll_once()  # the ceiling lets ten through a poll
    assert len(src._stuck) == len(names)
    for _ in range(100):
        for name, (seen, _) in list(src._stuck.items()):
            _make_due(src, name, seen.due - 30.0)
        await src._poll_once()
    remembered = sorted(src._stuck)  # what the run itself still holds as stuck
    assert len(remembered) >= len(names), "the premise: every reject is still remembered"
    retried = [name for name in remembered if _retrieved(client, f"/in/{name}") >= 2]
    assert len(retried) >= 1, "the premise: the retry pass ran at all"
    never = [name for name in remembered if name not in retried]
    assert never == []


async def test_a_due_retry_past_the_ceiling_is_not_held_back_by_a_backlog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/z.hl7": _BAD})
    src = _leave(monkeypatch, client, poll_max_files=1)
    await _settle(src)
    await src._poll_once()
    client.files |= {"/in/a.hl7": _GOOD, "/in/b.hl7": _GOOD}
    _make_due(src, "z.hl7")
    await src._poll_once()  # a and b are first seen; z takes the slot and settles
    await src._poll_once()  # a spends the budget, so the pass stops before b and z
    assert src._handler.bodies == [_GOOD]
    assert _retrieved(client, "/in/b.hl7") == 0
    assert _retrieved(client, "/in/z.hl7") == 2


@pytest.mark.parametrize("failure", ["retrieve", "hand_off"])
async def test_a_failed_retry_does_not_promise_the_next_poll(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, failure: str
) -> None:
    """A remembered reject waits its back-off, so the log must not say the next poll retries it."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    client.files["/in/a.hl7"] = _GOOD_AT_BAD_SIZE
    _make_due(src, "a.hl7")
    await _settle(src)
    if failure == "retrieve":
        client._retrieve_exc = _RemoteError("synthetic retrieve failure", permanent=False)
    else:
        src._handler = _RecordingHandler(exc=RuntimeError("synthetic store failure"))
    caplog.clear()
    await src._poll_once()
    assert "will retry" in caplog.text
    assert "next poll" not in caplog.text


async def test_a_listing_without_a_time_does_not_erase_the_remembered_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rejected again on a poll whose listing lost the time, the file must still show a later
    change of it, or a replacement waits for the retry."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    size = len(_BAD)
    src._remember_stuck("a.hl7", size, "20261123080000")
    src._remember_stuck("a.hl7", size, None)
    assert src._stuck["a.hl7"][0].mtime == "20261123080000"
    assert src._stuck_reject("a.hl7", size, "20261123090000") is None


async def test_a_retry_whose_hand_off_fails_keeps_its_memory_on_the_short_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    client.files["/in/a.hl7"] = _GOOD_AT_BAD_SIZE
    _make_due(src, "a.hl7")
    await _settle(src)
    src._handler = _RecordingHandler(exc=RuntimeError("synthetic store failure"))
    before = time.monotonic()
    await src._poll_once()
    assert len(src._handler.bodies) == 1
    assert src._stuck["a.hl7"][0].due - before <= STUCK_TRANSIENT_RETRY_SECONDS + 5
    await src._poll_once()  # the wait holds, so the outage does not re-read it
    assert len(src._handler.bodies) == 1


async def test_a_time_first_listed_after_the_reject_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reject remembered from a listing with no time still sees a later change of the time."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._stuck["a.hl7"][0].mtime is None
    size = len(_BAD)
    assert src._stuck_reject("a.hl7", size, "20261123080000") is not None
    assert src._stuck_reject("a.hl7", size, "20261123090000") is None
    assert "a.hl7" not in src._stuck


async def test_a_full_memory_leaves_a_reject_read_and_charged_as_before(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(remotefile, "SETTLE_SEEN_MAX", 1)
    # z.txt is outside the pattern: the ceiling check it reaches shows what b charged.
    client = _read_only({"/in/a.hl7": _BAD, "/in/b.hl7": _BAD, "/in/z.txt": b"skip"})
    src = _leave(monkeypatch, client)
    charged: list[int] = []
    at_ceiling = src._at_ceiling

    def spy(disposed: int, remaining: int) -> bool:
        charged.append(disposed)
        return bool(at_ceiling(disposed, remaining))

    src._at_ceiling = spy
    await src._poll_once()  # a's first sighting; b waits for room in the settle memory
    await src._poll_once()  # a is read and remembered, and b gets its first sighting
    await src._poll_once()  # b is read, and the memory is full of a
    assert list(src._stuck) == ["a.hl7"]
    assert "memory of rejects that cannot be moved is full" in caplog.text
    assert _retrieved(client, "/in/b.hl7") == 1
    await src._poll_once()  # b settles again, since it could not be remembered
    charged.clear()
    await src._poll_once()
    assert _retrieved(client, "/in/b.hl7") == 2, "a reject the memory cannot hold is read again"
    assert _retrieved(client, "/in/a.hl7") == 1
    assert charged[-1] == 1, "and it charges the budget"


async def test_a_reject_no_longer_listed_is_forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _read_only({"/in/bad.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert list(src._stuck) == ["bad.hl7"]
    del client.files["/in/bad.hl7"]
    for _ in range(SETTLE_MISS_LIMIT):
        await src._poll_once()
    assert src._stuck == {}


async def test_the_encoded_sniff_is_what_the_poll_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Row item 1 (S36-19), already fixed by BACKLOG #5684. A UTF-16 HL7 drop fails the raw sniff,
    which is the check the finding read, and is handed over all the same. A UTF-16 drop that is not
    HL7 is still quarantined, so the fix did not simply open the gate."""
    good = "MSH|^~\\&|A|B\r".encode("utf-16")
    bad = "not an HL7 message".encode("utf-16")
    assert not _content_matches_declared(ContentType.HL7V2, good)
    client = _FakeClient(files={"/in/bad.hl7": bad, "/in/good.hl7": good})
    src = _src(monkeypatch, client, encoding="utf-16")
    src._handler = _RecordingHandler()
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [good]
    assert client.files["/in/.error/bad.hl7"] == bad


# === the retrieve-time size check =================================================================


_GROWN = _GOOD + b"|the rest of the message"


def _grows_during_hand_off(src: Any, client: _FakeClient, path: str, body: bytes) -> Any:
    """Install a handler that rewrites ``path`` while the first hand-off runs, as a partner's writer
    would between the poll's one listing and a later file's retrieve."""
    handler = _RecordingHandler()

    async def rewriting(raw: bytes) -> str | None:
        if not handler.bodies:
            client.files[path] = body
        return await handler(raw)

    src._handler = rewriting
    return handler


async def test_a_fresh_file_that_grew_after_the_listing_is_not_handed_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Open item 2: a file written between the listing and its retrieve was taken as it stood."""
    client = _FakeClient(files={"/in/a.hl7": _GOOD, "/in/b.hl7": _GOOD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    handler = _grows_during_hand_off(src, client, "/in/b.hl7", _GROWN)
    await src._poll_once()
    assert handler.bodies == [_GOOD], "b was retrieved at a length its listing did not give"
    assert len(src.processed_ledger.keys) == 1, "a held file is not recorded as seen"
    assert "/in/b.hl7" in client.files
    assert src._stuck == {}, "a held file is not a reject"
    await src._poll_once()  # its read length is the sighting this listing agrees with
    assert handler.bodies == [_GOOD, _GROWN]
    assert len(src.processed_ledger.keys) == 2


async def test_a_later_retry_slot_is_not_taken_on_a_listing_older_than_an_earlier_hand_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Open item 1: every slot read one listing, so y's hand-off could outdate z's."""
    client = _read_only({"/in/y.hl7": _BAD, "/in/z.hl7": _BAD})
    src = _leave(monkeypatch, client, poll_max_files=20)  # a retry allowance of two
    await _settle(src)
    await src._poll_once()  # both are rejected and remembered
    client.files |= {"/in/y.hl7": _GOOD_AT_BAD_SIZE, "/in/z.hl7": _GOOD_AT_BAD_SIZE}
    _make_due(src, "y.hl7", 1.0)
    _make_due(src, "z.hl7", 2.0)
    await _settle(src)  # both take a slot and settle
    partial = b"MSH|^~\\&|PARTIAL"
    handler = _grows_during_hand_off(src, client, "/in/z.hl7", partial)
    await src._poll_once()
    assert handler.bodies == [_GOOD_AT_BAD_SIZE], "z's partial must not be handed over"


async def test_a_size_mismatch_is_never_quarantined_or_recorded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A partial body can fail the sniff, so the check runs first: being written is not a reject."""
    secret = b"PARTIAL-BODY-MRN1234567"
    client = _FakeClient(files={"/in/a.hl7": _GOOD, "/in/b.hl7": _GOOD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    _grows_during_hand_off(src, client, "/in/b.hl7", secret)
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    await src._poll_once()
    assert "/in/.error/b.hl7" not in client.files
    assert client.files["/in/b.hl7"] == secret
    assert src._stuck == {}
    assert len(src.processed_ledger.keys) == 1
    assert "not handed off" in caplog.text, "a hold is logged"
    assert "MRN1234567" not in caplog.text, "and without the content"
    assert "b.hl7" not in caplog.text, "or the file name in the clear"


async def test_a_listing_that_stays_wrong_does_not_hold_the_file_for_good(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """RFC 3659 calls the MLSD size approximate, so a server can list a steady wrong size. Two reads
    of one length show the file is not moving."""
    client = _FakeClient(files={"/in/a.hl7": _GROWN}, sizes={"/in/a.hl7": 5})
    src = _leave(monkeypatch, client)
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    for _ in range(3):
        await src._poll_once()
    assert src._handler.bodies == [], "the first read is held"
    assert _retrieved(client, "/in/a.hl7") == 1
    await src._poll_once()
    assert src._handler.bodies == [_GROWN], "the second read of that length is handed off"
    assert _retrieved(client, "/in/a.hl7") == 2
    assert "listed" in caplog.text and "handing" in caplog.text
    assert src._size_held == {}
    for _ in range(3):
        await src._poll_once()
    assert src._handler.bodies == [_GROWN], "and it is ingested once"


async def test_a_file_whose_read_length_keeps_moving_stays_held_and_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the agreement above: two reads must give ONE length. A repeat then waits,
    so a share that keeps disagreeing is not downloaded again on every poll."""
    client = _FakeClient(files={"/in/a.hl7": _GROWN}, sizes={"/in/a.hl7": 5})
    src = _leave(monkeypatch, client)
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    for n in range(1, 40):
        client.files["/in/a.hl7"] = _GROWN + b"x" * n
        await src._poll_once()
    assert src._handler.bodies == []
    assert _retrieved(client, "/in/a.hl7") == 2, "the repeat started a wait"
    assert "/in/a.hl7" in client.files
    assert "not handed off" in caplog.text, "a repeat is logged at WARNING"
    seen, missed = src._size_held["a.hl7"]
    src._size_held["a.hl7"] = (seen._replace(due=0.0), missed)
    for _ in range(3):
        await src._poll_once()
    assert _retrieved(client, "/in/a.hl7") == 3, "and it is read again once the wait ends"


async def test_a_changed_listing_ends_a_size_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wait is for a listing that says nothing new. A writer that finishes is read at once."""
    client = _FakeClient(files={"/in/a.hl7": _GROWN}, sizes={"/in/a.hl7": 5})
    src = _leave(monkeypatch, client)
    await _settle(src)
    for n in (1, 2):
        client.files["/in/a.hl7"] = _GROWN + b"x" * n
        await _settle(src)
        await src._poll_once()
    assert src._size_held["a.hl7"][0].due > time.monotonic(), "the premise: it is waiting"
    client._sizes.clear()  # the listing now gives the true length
    for _ in range(3):
        await src._poll_once()
    assert src._handler.bodies == [_GROWN + b"xx"]
    assert src._size_held == {}


async def test_a_full_poll_of_moving_files_cannot_pass_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = [f"/in/f{i:02}.hl7" for i in range(40)]
    client = _FakeClient(files=dict.fromkeys(paths, _GROWN), sizes=dict.fromkeys(paths, 5))
    retrieve = client.retrieve
    reads = 0

    def lengthening(path: str, *, max_bytes: int | None = None) -> bytes:
        nonlocal reads
        reads += 1
        client.files[path] += b"x"
        return retrieve(path, max_bytes=max_bytes)

    monkeypatch.setattr(client, "retrieve", lengthening)
    src = _leave(monkeypatch, client, poll_max_files=2)
    for _ in range(30):
        reads = 0
        await src._poll_once()
        assert reads <= 2
    assert src._handler.bodies == []


async def test_a_moved_quarantine_or_a_ledger_hit_clears_the_size_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A record left behind would let the next file of that name skip its first held read."""
    client = _FakeClient(files={"/in/x.hl7": _BAD}, sizes={"/in/x.hl7": 5})
    src = _leave(monkeypatch, client)
    for _ in range(4):
        await src._poll_once()
    assert client.files == {"/in/.error/x.hl7": _BAD}
    assert src._size_held == {}

    client = _FakeClient(files={"/in/y.hl7": _GROWN}, sizes={"/in/y.hl7": 5})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert "y.hl7" in src._size_held
    await src.processed_ledger.mark_processed(src._file_key("y.hl7", 5, None))
    await src._poll_once()
    assert src._size_held == {}


async def test_a_no_size_retry_rewritten_during_a_hand_off_is_caught_by_the_second_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The size check has nothing to compare here, so the second listing's time is what sees it."""

    class _NoSizeClient(_StampedClient):
        def list_entries(self, remote_dir: str) -> list[_Listed]:
            return [e._replace(size=0, size_known=False) for e in super().list_entries(remote_dir)]

    client = _NoSizeClient({"/in/z.hl7": _BAD}, {"/in/z.hl7": "1", "/in/a.hl7": "1"})
    client._rename_exc = _REFUSED
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()  # z is rejected and remembered
    client.files["/in/a.hl7"] = _GOOD
    _make_due(src, "z.hl7")
    await src._poll_once()  # a is first seen; z takes the slot and settles
    handler = _RecordingHandler()

    async def rewriting(raw: bytes) -> str | None:
        client.files["/in/z.hl7"] = b"MSH|^~\\&|PARTIAL"
        client.mtimes["/in/z.hl7"] = "2"
        return await handler(raw)

    src._handler = rewriting
    await src._poll_once()
    assert handler.bodies == [_GOOD], "the partial must not be handed over"


async def test_a_failed_hand_off_still_leaves_the_retry_a_current_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed hand-off disposes of nothing, yet it takes time, and a no-size retry that runs on the
    listing from before it cannot see a rewrite made meanwhile."""

    class _NoSizeClient(_StampedClient):
        def list_entries(self, remote_dir: str) -> list[_Listed]:
            return [e._replace(size=0, size_known=False) for e in super().list_entries(remote_dir)]

    client = _NoSizeClient({"/in/z.hl7": _BAD}, {"/in/z.hl7": "1", "/in/a.hl7": "1"})
    client._rename_exc = _REFUSED
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()  # z is rejected and remembered
    client.files["/in/a.hl7"] = _GOOD
    _make_due(src, "z.hl7")
    await src._poll_once()  # a is first seen; z takes the slot and settles
    handler = _RecordingHandler()

    async def failing(raw: bytes) -> str | None:
        client.files["/in/z.hl7"] = b"MSH|^~\\&|PARTIAL"
        client.mtimes["/in/z.hl7"] = "2"
        if not handler.bodies:
            handler.bodies.append(b"")  # only the first call fails
            raise RuntimeError("synthetic store outage")
        return await handler(raw)

    src._handler = failing
    await src._poll_once()
    assert b"MSH|^~\\&|PARTIAL" not in handler.bodies, "the partial must not be handed over"


def test_the_nlst_fallback_asks_for_sizes_in_binary_mode() -> None:
    """ftplib's NLST leaves the session in ASCII mode, where several servers refuse SIZE."""

    class _AsciiRefusing(_Ftp):
        binary = False

        def nlst(self, path: str) -> list[str]:
            self.binary = False
            return ["a.hl7"]

        def voidcmd(self, command: str) -> str:
            self.binary = command == "TYPE I"
            return "200 ok"

        def size(self, path: str) -> int:
            if not self.binary:
                raise ftplib.error_perm("550 SIZE not allowed in ASCII mode")
            return 7

    [entry] = _FtpClient._list(_AsciiRefusing(None), "/in")  # type: ignore[arg-type]
    assert (entry.size, entry.size_known) == (7, True)


async def test_a_full_hold_memory_makes_a_file_wait_and_never_lose_its_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remotefile, "SETTLE_SEEN_MAX", 1)
    client = _FakeClient(
        files={"/in/a.hl7": _GROWN, "/in/b.hl7": _GROWN},
        sizes={"/in/a.hl7": 5, "/in/b.hl7": 5},
    )
    src = _leave(monkeypatch, client)
    for _ in range(16):
        await src._poll_once()
    assert src._handler.bodies == [_GROWN, _GROWN]
    assert src._size_held == {}


async def test_held_reads_charge_the_ceiling_and_every_file_still_arrives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A server listing every file at a wrong size must not pull its whole backlog in one poll."""
    paths = [f"/in/f{i}.hl7" for i in range(5)]
    client = _FakeClient(files=dict.fromkeys(paths, _GROWN), sizes=dict.fromkeys(paths, 5))
    src = _leave(monkeypatch, client, poll_max_files=2)
    await _settle(src)
    await src._poll_once()
    assert sum(_retrieved(client, path) for path in paths) == 2
    for _ in range(12):
        await src._poll_once()
    assert src._handler.bodies == [_GROWN] * 5, "every file still arrives"


async def test_a_held_file_no_longer_listed_is_forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": _GROWN}, sizes={"/in/a.hl7": 5})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert "a.hl7" in src._size_held
    del client.files["/in/a.hl7"]
    for _ in range(SETTLE_MISS_LIMIT):
        await src._poll_once()
    assert src._size_held == {}


async def test_a_listing_with_no_size_keeps_todays_behaviour(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stated limit: 0 from a client that cannot say is no evidence, so nothing is held."""
    client = _FakeClient(files={"/in/a.hl7": _GROWN}, sizes={"/in/a.hl7": 0})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_GROWN]
    assert _retrieved(client, "/in/a.hl7") == 1


async def test_a_real_listed_zero_is_a_size_and_holds_a_file_since_filled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A writer that creates the file and fills it later lists a true 0, the likeliest partial."""
    client = _StampedClient({"/in/a.hl7": b""}, {"/in/a.hl7": "20261123080000"})
    src = _leave(monkeypatch, client)
    await _settle(src)
    real = client.retrieve

    def filled(path: str, *, max_bytes: int | None = None) -> bytes:
        client.files[path] = _GROWN  # written between the listing and this read
        return real(path, max_bytes=max_bytes)

    monkeypatch.setattr(client, "retrieve", filled)
    await src._poll_once()
    assert src._handler.bodies == []


def test_each_real_listing_says_whether_it_gave_a_size() -> None:
    class _Nlst(_Ftp):
        def nlst(self, path: str) -> list[str]:
            return ["sized.hl7", "unsized.hl7"]

        def size(self, path: str) -> int:
            if path.endswith("unsized.hl7"):
                raise ftplib.error_perm("550 SIZE not allowed")
            return 0

    mlsd = [("sized.hl7", {"type": "file", "size": "0"}), ("unsized.hl7", {"type": "file"})]
    for fake in (_Ftp(mlsd), _Nlst(None)):
        known = {e.name: e.size_known for e in _FtpClient._list(fake, "/in")}  # type: ignore[arg-type]
        assert known == {"sized.hl7": True, "unsized.hl7": False}

    class _Sftp:
        def listdir_attr(self, path: str) -> list[Any]:
            regular = stat.S_IFREG | 0o644
            return [
                SimpleNamespace(filename="sized.hl7", st_mode=regular, st_size=0, st_mtime=1),
                SimpleNamespace(filename="unsized.hl7", st_mode=regular, st_size=None, st_mtime=1),
            ]

    sftp = _SftpClient.__new__(_SftpClient)
    sftp._op = lambda fn, **_: fn(_Sftp())  # type: ignore[method-assign]
    known = {e.name: e.size_known for e in sftp.list_entries("/in")}
    assert known == {"sized.hl7": True, "unsized.hl7": False}


async def test_a_poll_with_a_due_retry_and_no_retrieve_before_it_lists_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The listing is taken again only after a retrieve has begun since it. A listing that aged
    with elapsed time alone is not covered. The one due retry here settles first, so no retrieve
    precedes its slot."""
    client = _read_only({"/in/z.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    _make_due(src, "z.hl7")
    client.list_calls = 0
    await src._poll_once()
    assert client.list_calls == 1


async def test_a_second_retry_slot_lists_again_after_the_first_slot_retrieved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two slots on a no-size listing: the first slot's hand-off lets a partner rewrite the second
    file, and only a listing taken after that retrieve shows the moved time."""

    class _NoSizeClient(_StampedClient):
        def list_entries(self, remote_dir: str) -> list[_Listed]:
            return [e._replace(size=0, size_known=False) for e in super().list_entries(remote_dir)]

    client = _NoSizeClient(
        {"/in/y.hl7": _BAD, "/in/z.hl7": _BAD}, {"/in/y.hl7": "1", "/in/z.hl7": "1"}
    )
    client._rename_exc = _REFUSED
    src = _leave(monkeypatch, client, poll_max_files=20)  # a retry allowance of two
    await _settle(src)
    await src._poll_once()  # both are rejected and remembered
    client.files["/in/y.hl7"] = _GOOD
    _make_due(src, "y.hl7", 1.0)
    _make_due(src, "z.hl7", 2.0)
    await _settle(src)  # both take a slot and settle
    handler = _RecordingHandler()

    async def rewriting(raw: bytes) -> str | None:
        client.files["/in/z.hl7"] = b"MSH|^~\\&|PARTIAL"
        client.mtimes["/in/z.hl7"] = "2"
        return await handler(raw)

    src._handler = rewriting
    await src._poll_once()
    assert handler.bodies == [_GOOD], "z's partial must not be handed over"


async def test_a_stop_landing_during_the_relist_starts_no_further_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second slot lists again because the first retrieved. A stop that lands during that
    listing must not let the slot go on to download."""
    trigger: list[Any] = []

    class _StoppingClient(_StampedClient):
        def list_entries(self, remote_dir: str) -> list[_Listed]:
            if trigger:
                trigger[0]._stop.set()
            return super().list_entries(remote_dir)

    client = _StoppingClient(
        {"/in/y.hl7": _BAD, "/in/z.hl7": _BAD}, {"/in/y.hl7": "1", "/in/z.hl7": "1"}
    )
    client._rename_exc = _REFUSED
    src = _leave(
        monkeypatch, client, after_read="move", poll_max_files=20
    )  # a retry allowance of two
    await _settle(src)
    await src._poll_once()  # both are rejected and remembered
    _make_due(src, "y.hl7", 1.0)
    _make_due(src, "z.hl7", 2.0)
    await _settle(src)  # both take a slot and settle
    before = _retrieved(client, "/in/z.hl7")
    seen = _retrieved(client, "/in/y.hl7")
    original = client.list_entries
    calls = 0

    def arm(remote_dir: str) -> list[_Listed]:
        nonlocal calls
        calls += 1
        if calls == 2:  # the poll's own listing is the first; the relist before slot two is next
            trigger.append(src)
        return original(remote_dir)

    client.list_entries = arm  # type: ignore[method-assign]
    await src._poll_once()
    assert _retrieved(client, "/in/y.hl7") == seen + 1, "the premise: the first slot retrieved"
    assert _retrieved(client, "/in/z.hl7") == before, "no download after the stop"


@pytest.mark.parametrize("time_returns", [True, False])
async def test_a_leave_retry_on_a_listing_that_lost_the_time_is_ingested_once(
    monkeypatch: pytest.MonkeyPatch, time_returns: bool
) -> None:
    """Open item 4: the retry keyed on the time-less listing, so the next listing with the time
    read as a new version. Recorded under both, it stays ingested whichever the server lists."""
    stamp = "20261123080000"
    client = _StampedClient({"/in/a.hl7": _BAD}, {"/in/a.hl7": stamp})
    client._rename_exc = _REFUSED
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()  # rejected, and remembered with its time
    assert src._stuck["a.hl7"][0].mtime == stamp
    client.files["/in/a.hl7"] = _GOOD_AT_BAD_SIZE
    client.mtimes.clear()  # an MLSD refusal that falls back to NLST
    _make_due(src, "a.hl7")
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_GOOD_AT_BAD_SIZE]
    if time_returns:
        client.mtimes["/in/a.hl7"] = stamp
    for _ in range(4):
        await src._poll_once()
    assert src._handler.bodies == [_GOOD_AT_BAD_SIZE], "one version is ingested once"
