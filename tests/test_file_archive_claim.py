# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The inbound archive move claims its destination name atomically (BACKLOG #1046, ASVS 15.4.4).

`FileSource._move` used to relocate a processed file with `path.replace(_unique(dest))` — a
check-then-act pair, where `_unique` asked `exists()` and `replace` then overwrote whatever sat at
the name it chose. The delivery path had already replaced that pattern with `_claim_unique`'s
`os.link`/`O_EXCL` claim (FILE-5); the archive move was the caller left behind.

The default config cannot race it (one poller per source over an engine-owned `processed_dir`, and
the canonical raw message is durable in the store before the ACK regardless), so this is a
concurrency defect with no integrity consequence on the shipping configuration. It bites the
non-default config the item names: two FILE sources sharing one `processed_dir`.

`_claim_unique` is therefore the one claim both callers share, so its semantics are covered here from
both sides: the inbound archive move above, and — in the fail-closed section at the foot of the file —
the outbound delivery path that reaches the same helper under the default `overwrite=false`.
"""

from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path
from typing import IO

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.transports.base import DeliveryError, build_destination
from messagefoundry.transports.file import FileSource, _claim_unique

#: Enough rounds to make the interleaving reliable rather than lucky. Measured on the pre-fix code
#: (Windows, NTFS, 2026-08-10): five runs of this shape archived 61, 61, 64, 63 and 62 of 120 —
#: roughly half of every archived message lost or refused. Post-fix: 120 of 120, five runs of five.
_ROUNDS = 60


def _source(directory: Path) -> FileSource:
    """A FILE source whose `processed_dir` is the SHARED `../processed` beside its watch dir — the
    non-default config the item names, where two sources archive into one directory."""
    return FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(directory), "processed_subdir": "../processed"},
        )
    )


def test_two_sources_sharing_one_processed_dir_lose_no_archive(tmp_path: Path) -> None:
    """The scenario the item names. Two FILE sources, one shared `processed_dir`, files with the
    SAME name archived at the same instant: every archived message must survive under its own name.

    Real threads and a per-round barrier rather than an injected interleaving: the window only
    exists in the pre-fix code, so a hook placed inside it could not be carried across the fix. The
    barrier makes both archives decide their destination name in the same instant, which is the
    whole of the race.

    Mutation: restore `path.replace(_unique(dest_dir / path.name))`. Red: roughly half the archived
    files are missing, and the assertion names how many."""
    processed = tmp_path / "processed"
    processed.mkdir()
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []

    def archive(tag: str) -> None:
        inbox = tmp_path / tag
        inbox.mkdir()
        source = _source(inbox)
        try:
            for i in range(_ROUNDS):
                dropped = inbox / "message.hl7"  # deliberately the SAME name in both sources
                dropped.write_text(f"{tag}-{i:04d}", encoding="ascii")
                barrier.wait(timeout=30)
                source._after_processing(dropped)  # default after_read="move"
        except BaseException as exc:  # noqa: BLE001 — re-raised in the main thread below
            failures.append(exc)
            barrier.abort()

    threads = [threading.Thread(target=archive, args=(tag,)) for tag in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        raise failures[0]

    archived = sorted(p.read_text(encoding="ascii") for p in processed.iterdir())
    expected = sorted(f"{tag}-{i:04d}" for tag in ("a", "b") for i in range(_ROUNDS))
    assert archived == expected, (
        f"{len(expected) - len(archived)} of {len(expected)} archived messages were lost or "
        f"overwritten by the other source"
    )


def test_archive_move_removes_the_original(tmp_path: Path) -> None:
    """The claim is a MOVE, not a copy. `_claim_unique` links (or copies) and leaves the source
    behind, so the unlink that completes the move is a separate step — this is what reds if it is
    ever dropped, leaving every processed file to be re-read forever."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    processed = tmp_path / "processed"
    processed.mkdir()
    dropped = inbox / "m.hl7"
    dropped.write_text("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\r", encoding="ascii")

    FileSource._move(dropped, processed)

    assert not dropped.exists(), "the archived file must not be left in the watch directory"
    assert (processed / "m.hl7").read_text(encoding="ascii").startswith("MSH|"), (
        "the archived copy must carry the original bytes"
    )


def test_archive_move_escalates_instead_of_clobbering_a_taken_name(tmp_path: Path) -> None:
    """Positive control on the escalation the claim inherits: an already-taken destination name
    yields `m-1.hl7`, and the file already sitting there is untouched.

    Without this, a `_move` that refused every archive whose name was taken — or one that simply
    overwrote — would still pass the concurrency test above on a lucky scheduling."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    processed = tmp_path / "processed"
    processed.mkdir()
    (processed / "m.hl7").write_text("already-archived", encoding="ascii")
    dropped = inbox / "m.hl7"
    dropped.write_text("newly-processed", encoding="ascii")

    FileSource._move(dropped, processed)

    assert (processed / "m.hl7").read_text(encoding="ascii") == "already-archived"
    assert (processed / "m-1.hl7").read_text(encoding="ascii") == "newly-processed"
    assert not dropped.exists()


def test_claim_unique_copy_fallback_streams_the_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `O_EXCL` copy fallback (filesystems without hard links: FAT/exFAT, many SMB mounts) must
    reproduce the source exactly. It matters more now that the archive move claims through here: a
    delivered payload is one message, but an inbound file is only as small as `max_file_bytes`,
    which is unset by default.

    Mutation: drop the `copyfileobj` loop. Red: the copied file is empty or truncated."""

    def _no_hard_links(*_a: object, **_k: object) -> None:
        raise OSError("hard links unsupported on this filesystem")

    monkeypatch.setattr(os, "link", _no_hard_links)
    payload = bytes(range(256)) * 5000  # 1.28 MB, several read chunks, NUL bytes included
    source = tmp_path / "src.bin"
    source.write_bytes(payload)

    claimed = _claim_unique(source, tmp_path / "dst.bin")

    assert claimed.read_bytes() == payload


# --- the copy fallback is fail-closed ----------------------------------------
#
# `_claim_unique`'s `os.link` branch publishes the whole file or nothing. The copy fallback does not:
# it exclusive-creates the destination and THEN streams into it, so a stream that dies part-way (a
# full volume, a dropped SMB share) would leave a truncated file at the DELIVERED name. On the
# outbound path that is a partial message handed to a downstream system, and the retry cannot correct
# it: the claim already consumed the name, so the retry lands at `name-1.ext` and the fragment stays.
#
# Measured on the pre-fix code (Windows, 2026-09-14): a copy raising ENOSPC after 1024 of 400000 bytes
# left `delivered.hl7` on disk at 1024 bytes, with no `.part` temp to mark it as incomplete.


def _no_hard_links(*_a: object, **_k: object) -> None:
    """Stand in for FAT/exFAT and the many SMB/NAS mounts where `os.link` raises a non-
    `FileExistsError` `OSError`, which is what sends `_claim_unique` down the copy fallback."""
    raise OSError("hard links unsupported on this filesystem")


def _dying_copy(prefix: int) -> object:
    """A `copyfileobj` that writes `prefix` bytes and then fails the way a full volume does."""

    def _copy(fsrc: IO[bytes], fdst: IO[bytes], length: int = 0) -> None:
        fdst.write(fsrc.read(prefix))
        raise OSError(28, "No space left on device")

    return _copy


def test_claim_unique_removes_the_partial_when_the_copy_dies_mid_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed claim must leave NOTHING at the name it claimed.

    Mutation: drop the `finally` cleanup. Red: `dst.bin` exists at 1024 of 400000 bytes."""
    monkeypatch.setattr(os, "link", _no_hard_links)
    # `shutil.copyfileobj` has exactly one caller in the file transport (`_claim_unique`), so patching
    # it module-wide reaches only the stream under test on this path.
    monkeypatch.setattr(shutil, "copyfileobj", _dying_copy(1024))
    payload = b"A" * 400_000
    source = tmp_path / "src.bin"
    source.write_bytes(payload)
    target = tmp_path / "dst.bin"

    with pytest.raises(OSError):
        _claim_unique(source, target)

    assert not target.exists(), "a truncated claim was left at the delivered name"
    # The source is untouched, so the caller's retry (or `FileSource._move`'s re-read) still has it.
    assert source.read_bytes() == payload
    assert sorted(p.name for p in tmp_path.iterdir()) == ["src.bin"]


def test_claim_unique_never_deletes_the_file_it_lost_the_name_race_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cleanup above must NOT cover the exclusive create.

    `FileExistsError` from `os.open` is the loop's normal control flow — it is how a taken name
    advances to `name-1.ext` — and the file sitting at that name belongs to whoever won it. A naive
    guard wrapped around the whole loop body deletes that file on EVERY collision, turning a
    no-clobber claim into a clobbering one.

    Mutation: widen the `try` to enclose the `os.open`. Red: `out.hl7` is gone."""
    monkeypatch.setattr(os, "link", _no_hard_links)
    source = tmp_path / "src.part"
    source.write_bytes(b"PAYLOAD")
    winner = tmp_path / "out.hl7"
    winner.write_bytes(b"the winner's bytes")

    claimed = _claim_unique(source, winner)

    assert claimed.name == "out-1.hl7"
    assert claimed.read_bytes() == b"PAYLOAD"
    assert winner.read_bytes() == b"the winner's bytes"
    # Assert the whole directory, not just the winner: a guard that deletes and then re-creates would
    # satisfy a bytes-only check on a lucky ordering.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out-1.hl7", "out.hl7", "src.part"]


async def test_file_delivery_leaves_no_partial_when_the_claim_copy_dies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gap is reachable from the OUTBOUND path under the DEFAULT config, not just from the helper.

    `overwrite` defaults to false, so `FileDestination._write` publishes through `_claim_unique`; on a
    filesystem without hard links that is the copy fallback. Delivery is at-least-once and outbound
    connections must be idempotent, so a failed send must leave the destination directory exactly as it
    found it — no truncated message for a downstream reader to pick up before the retry."""
    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(shutil, "copyfileobj", _dying_copy(8))
    dest = build_destination(
        Destination(
            name="OB_TEST_ADT",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "delivered.hl7"},
        )
    )

    with pytest.raises(DeliveryError):
        await dest.send("MSH|^~\\&|A|B|C|D|20260914||ADT^A01|MSG00001|P|2.5\r")

    # Empty: no delivered file, and no `.part` temp either (the caller's own `finally` takes that one).
    assert sorted(p.name for p in tmp_path.iterdir()) == []
