# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5750: a remote-file poll on a share it cannot write to.

Under ``after_read = "leave"`` the poll asked for ``.processed`` and ``.error`` on every tick, so a
share that refused the check aborted the poll before it listed anything. A reject whose move to
``.error`` failed stayed in the poll directory, was read again whenever it settled, and spent the
per-tick budget each time, which held back the valid files sorted after it.
"""

from __future__ import annotations

import time
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
from messagefoundry.transports.remotefile import _RemoteError, _SftpClient
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
    """A stop gives no reject a slot, so none keeps a sighting into the next start."""
    client = _read_only({"/in/a.hl7": _BAD})
    src = _leave(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    _make_due(src, "a.hl7")
    await src._poll_once()  # it takes the slot and settles
    assert "a.hl7" in src._settle_seen
    src._stop.set()
    await src._poll_once()
    assert "a.hl7" not in src._settle_seen
    assert _retrieved(client, "/in/a.hl7") == 1


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
    never = [name for name in names if _retrieved(client, f"/in/{name}") < 2]
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
