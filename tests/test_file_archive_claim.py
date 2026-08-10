# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The inbound archive move claims its destination name atomically (BACKLOG #1046, ASVS 15.4.4).

`FileSource._move` used to relocate a processed file with `path.replace(_unique(dest))` — a
check-then-act pair, where `_unique` asked `exists()` and `replace` then overwrote whatever sat at
the name it chose. The delivery path had already replaced that pattern with `_claim_unique`'s
`os.link`/`O_EXCL` claim (FILE-5); the archive move was the caller left behind.

The default config cannot race it (one poller per source over an engine-owned `processed_dir`, and
the canonical raw message is durable in the store before the ACK regardless), so this is a
concurrency defect with no integrity consequence on the shipping configuration. It bites the
non-default config the item names: two FILE sources sharing one `processed_dir`.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
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
