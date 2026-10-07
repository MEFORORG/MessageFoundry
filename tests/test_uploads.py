# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""UploadStore — offline uploaded-logs storage (BACKLOG #125/#126, ADR 0134)."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any, Literal

import pydantic
import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.crypto import CipherError, generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import (
    PruneResult,
    UploadContentError,
    UploadedFileMeta,
    UploadNotFoundError,
    UploadPathError,
    UploadQuotaError,
    UploadRetentionRunner,
    UploadStore,
    UploadTooLargeError,
    _SweepTally,
    sanitize_filename,
    validate_upload_content,
)

_ADT = "MSH|^~\\&|A|B|C|D|202601011200||ADT^A01|MSGID1|P|2.5\rPID|1||MRN123^^^HOSP||DOE^JOHN\r"
_BATCH = _ADT + "MSH|^~\\&|A|B|C|D|202601011201||ADT^A04|MSGID2|P|2.5\rPID|1||MRN999\r"


def _store(tmp_path: Path, *, key: bool, aad: bool = False) -> UploadStore:
    cipher = make_cipher(generate_key() if key else None, write_v2=aad)
    return UploadStore(tmp_path / "uploads", cipher, max_bytes=1024)


async def test_save_encrypts_and_lists(tmp_path: Path) -> None:
    store = _store(tmp_path, key=True, aad=True)
    meta = await store.save(
        data=_BATCH.encode(),
        filename="acme.hl7",
        uploader="op",
        uploader_id="u-op",
        content_type=None,
    )
    assert isinstance(meta, UploadedFileMeta)
    assert meta.filename == "acme.hl7"
    assert meta.content_type == "hl7v2"
    assert meta.message_count == 2  # split_batch found both MSH boundaries
    assert meta.size == len(_BATCH.encode())

    # On-disk sidecars are ciphertext, not the raw body (PHI at rest is encrypted).
    blob = (tmp_path / "uploads" / f"{meta.file_id}.blob").read_text()
    assert blob.startswith("mfenc:")
    assert "MRN123" not in blob

    listed = await store.list_files()
    assert [m.file_id for m in listed] == [meta.file_id]

    got = await store.read_bytes(meta.file_id)
    assert got == _BATCH.encode()


async def test_identity_cipher_plaintext_on_disk(tmp_path: Path) -> None:
    # No key configured → identity cipher → plaintext-on-disk (the documented File-connector-spill tier).
    store = _store(tmp_path, key=False)
    meta = await store.save(data=_ADT.encode(), filename="x.hl7", uploader="op", uploader_id="u-op")
    blob = (tmp_path / "uploads" / f"{meta.file_id}.blob").read_text()
    # base64 of the plaintext (identity cipher does not add the mfenc marker).
    assert not blob.startswith("mfenc:")
    assert await store.read_bytes(meta.file_id) == _ADT.encode()


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "..\\..\\secret",
        "abc",  # too short
        "g" * 32,  # non-hex
        "0123456789abcdef0123456789abcdef/x",
        "0123456789ABCDEF0123456789ABCDEF",  # uppercase not minted by token_hex
        "0123456789abcdef0123456789abcde\n",
    ],
)
async def test_path_traversal_rejected(tmp_path: Path, bad: str) -> None:
    store = _store(tmp_path, key=True)
    for op in (store.get_meta, store.read_bytes, store.delete):
        with pytest.raises(UploadPathError):
            await op(bad)


async def test_missing_file_ids_are_not_found(tmp_path: Path) -> None:
    store = _store(tmp_path, key=True)
    missing = "0" * 32  # well-formed, but never saved
    with pytest.raises(UploadNotFoundError):
        await store.read_bytes(missing)
    with pytest.raises(UploadNotFoundError):
        await store.get_meta(missing)
    with pytest.raises(UploadNotFoundError):
        await store.delete(missing)


async def test_delete_removes_both_sidecars(tmp_path: Path) -> None:
    store = _store(tmp_path, key=True)
    meta = await store.save(data=_ADT.encode(), filename="x.hl7", uploader="op", uploader_id="u-op")
    deleted = await store.delete(meta.file_id)
    assert deleted.file_id == meta.file_id
    assert not (tmp_path / "uploads" / f"{meta.file_id}.blob").exists()
    assert not (tmp_path / "uploads" / f"{meta.file_id}.meta").exists()
    assert await store.list_files() == []


async def test_too_large_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path, key=True)  # max_bytes=1024
    with pytest.raises(UploadTooLargeError):
        await store.save(data=b"x" * 2048, filename="big.hl7", uploader="op", uploader_id="u-op")


# --- ASVS 5.2.2: extension allowlist + content-vs-extension sniff at the chokepoint ----------


async def test_save_rejects_disallowed_extension(tmp_path: Path) -> None:
    # Only text diagnostic logs (.hl7/.hl7v2/.txt/.xml) are permitted; a .png (or any other extension) is
    # refused at the chokepoint before any PHI is written, even if its content looks like HL7.
    store = _store(tmp_path, key=True)
    with pytest.raises(UploadContentError):
        await store.save(data=_ADT.encode(), filename="evil.png", uploader="op", uploader_id="u-op")
    assert await store.list_files() == []  # nothing written


async def test_save_rejects_content_extension_mismatch(tmp_path: Path) -> None:
    # PNG magic bytes in a .hl7 → the HL7 header sniff fails → refused (a mislabelled binary can't slip in
    # on a text extension). Nothing is written.
    store = _store(tmp_path, key=True)
    png = b"\x89PNG\r\n\x1a\n" + b"not hl7 at all"
    with pytest.raises(UploadContentError):
        await store.save(data=png, filename="fake.hl7", uploader="op", uploader_id="u-op")
    assert await store.list_files() == []


async def test_save_rejects_nul_bearing_txt(tmp_path: Path) -> None:
    # .txt has no magic signature, so the check is weak — but a NUL-bearing body is not plain text and is
    # refused (the same residual the plain-text connectors carry).
    store = _store(tmp_path, key=True)
    with pytest.raises(UploadContentError):
        await store.save(
            data=b"hello\x00world", filename="notes.txt", uploader="op", uploader_id="u-op"
        )


async def test_save_accepts_valid_txt_and_xml(tmp_path: Path) -> None:
    # Accepted formats flow through: a plain-text .txt and a leading-'<' .xml both store cleanly.
    store = _store(tmp_path, key=True)
    txt = await store.save(
        data=b"a plain diagnostic log line\n",
        filename="notes.txt",
        uploader="op",
        uploader_id="u-op",
    )
    assert txt.content_type == "text"
    xml = await store.save(
        data=b"\xef\xbb\xbf<root><child/></root>",
        filename="doc.xml",
        uploader="op",
        uploader_id="u-op",
    )
    assert xml.content_type == "xml"
    assert {m.content_type for m in await store.list_files()} == {"text", "xml"}


def test_validate_upload_content_is_pure_and_matches_extensions() -> None:
    # The pure chokepoint helper: allowlist + per-extension sniff. Valid cases pass silently.
    validate_upload_content("a.hl7", b"MSH|^~\\&|A|B")
    validate_upload_content("a.hl7v2", b"BHS|^~\\&|A")
    validate_upload_content("a.xml", b"<x/>")
    validate_upload_content("a.txt", b"just text")
    for name, data in [
        ("a.png", b"MSH|^~\\&|A"),  # disallowed extension
        ("a.hl7", b"\x89PNG"),  # PNG in .hl7
        ("a.xml", b"nope not xml"),  # no leading '<'
        ("a.txt", b"x\x00y"),  # NUL in .txt
    ]:
        with pytest.raises(UploadContentError):
            validate_upload_content(name, data)


def test_sanitize_filename_strips_path_and_control() -> None:
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("C:\\Temp\\a.hl7") == "a.hl7"
    assert sanitize_filename("bad\x00name.hl7") == "badname.hl7"
    assert sanitize_filename("") == "upload"
    assert sanitize_filename(None) == "upload"
    # DEL, CR/LF and US go too: the alphabet is controlchars' (BACKLOG #1273).
    assert sanitize_filename("a\x7fb\r\n\x1fc.hl7") == "abc.hl7"


# --- ASVS 5.2.4: per-user quotas + age-based retention prune --------------------------------


def _quota_store(
    tmp_path: Path,
    *,
    max_files: int = 100,
    max_total: int = 250 * 1024 * 1024,
    retention_days: int = 30,
) -> UploadStore:
    return UploadStore(
        tmp_path / "uploads",
        make_cipher(generate_key()),
        max_bytes=4096,
        max_files_per_user=max_files,
        max_total_bytes_per_user=max_total,
        retention_days=retention_days,
    )


async def test_file_count_quota_rejects_and_does_not_write(tmp_path: Path) -> None:
    # ASVS 5.2.4: the (N+1)th file for one uploader is refused BEFORE any write; the store still holds
    # exactly N files.
    store = _quota_store(tmp_path, max_files=2)
    for i in range(2):
        await store.save(
            data=f"line {i}\n".encode(), filename=f"a{i}.txt", uploader="op", uploader_id="u-op"
        )
    with pytest.raises(UploadQuotaError):
        await store.save(
            data=b"one too many\n", filename="a2.txt", uploader="op", uploader_id="u-op"
        )
    assert len(await store.list_files()) == 2  # nothing written for the over-quota upload


async def test_byte_quota_rejects_when_aggregate_would_exceed(tmp_path: Path) -> None:
    # ASVS 5.2.4: an upload that would push the uploader's aggregate bytes over the cap is refused.
    store = _quota_store(tmp_path, max_total=40)
    await store.save(
        data=b"x" * 20 + b"\n", filename="a.txt", uploader="op", uploader_id="u-op"
    )  # 21 bytes, ok
    with pytest.raises(UploadQuotaError):
        await store.save(
            data=b"y" * 30 + b"\n", filename="b.txt", uploader="op", uploader_id="u-op"
        )  # 21+31 > 40
    assert len(await store.list_files()) == 1


async def test_quota_is_per_user(tmp_path: Path) -> None:
    # ASVS 5.2.4: user A being at quota never blocks user B — the cap is scoped to the uploader.
    store = _quota_store(tmp_path, max_files=1)
    await store.save(data=b"a\n", filename="a.txt", uploader="alice", uploader_id="u-alice")
    with pytest.raises(UploadQuotaError):  # alice is at her cap
        await store.save(data=b"a2\n", filename="a2.txt", uploader="alice", uploader_id="u-alice")
    b = await store.save(
        data=b"b\n", filename="b.txt", uploader="bob", uploader_id="u-bob"
    )  # bob unaffected
    assert b.uploader == "bob"
    assert {m.uploader for m in await store.list_files()} == {"alice", "bob"}


async def test_quota_buckets_by_account_id_not_by_username(tmp_path: Path) -> None:
    """ASVS 5.2.4 + 8.2.2: the budget keys on the IMMUTABLE account id, exactly like ownership.

    A username is reusable — delete an account and the name is free to recreate, minting a new
    ``user_id`` — so a name-keyed budget would bill a recycled account for files it cannot read, and
    the two rules would disagree about who a file belongs to. Both arms are checked here: same name
    with two different ids gets two budgets, and one id under two different names shares one.
    """
    store = _quota_store(tmp_path, max_files=1)
    await store.save(data=b"a\n", filename="a.txt", uploader="op", uploader_id="u-first")
    # The departed operator's name, recreated: a DIFFERENT account, so a fresh budget.
    second = await store.save(data=b"b\n", filename="b.txt", uploader="op", uploader_id="u-second")
    assert second.uploader_id == "u-second"
    # The same ACCOUNT under a different display name is still one budget, and it is at its cap.
    with pytest.raises(UploadQuotaError):
        await store.save(data=b"c\n", filename="c.txt", uploader="renamed", uploader_id="u-second")
    assert {(m.uploader, m.uploader_id) for m in await store.list_files()} == {
        ("op", "u-first"),
        ("op", "u-second"),
    }


async def test_save_refuses_an_upload_with_no_owner_id(tmp_path: Path) -> None:
    # Fail closed at the write, not only at the read: a sidecar with no uploader_id matches nobody at
    # the ownership check, so writing one would burn disk and quota on a file only a files:access_any
    # holder could ever reach. The shipped caller always passes Identity.user_id, so an empty one is a
    # programming error.
    store = _quota_store(tmp_path)
    with pytest.raises(ValueError):
        await store.save(data=b"a\n", filename="a.txt", uploader="op", uploader_id="")
    assert await store.list_files() == []


async def test_quota_is_shared_by_stores_over_one_dir_not_per_process(tmp_path: Path) -> None:
    """ASVS 2.3.4 / 5.2.4: the budget is scoped to the uploads_dir, NOT to the process.

    Two UploadStore instances over one directory stand in for two engine shards. The settings
    comment and the ASVS 2.3.4 residual both used to assert that shards at one dir "multiply the
    budget"; measured 2026-08-10, they do not -- the sidecar scan is uncached, so the second store
    sees the first's files. This test pins that, so the corrected claim cannot silently regress
    back into a per-process budget (which WOULD be the double-booking 2.3.4 forbids).
    """
    # The cipher MUST be shared: real engine shards run off one unified store and therefore one
    # keyring/DEK. Giving each store its own key would make shard B skip shard A's sidecars as
    # undecryptable and fake a per-process budget -- an artifact of the fixture, not the system.
    cipher = make_cipher(generate_key())

    def _shard() -> UploadStore:
        return UploadStore(tmp_path / "uploads", cipher, max_bytes=4096, max_files_per_user=2)

    shard_a, shard_b = _shard(), _shard()  # two processes, ONE uploads dir

    for i in range(2):
        await shard_a.save(
            data=f"a{i}\n".encode(), filename=f"a{i}.txt", uploader="alice", uploader_id="u-alice"
        )
    # Positive control: the cap engages at all on the store that wrote the files.
    with pytest.raises(UploadQuotaError):
        await shard_a.save(
            data=b"overflow\n", filename="a2.txt", uploader="alice", uploader_id="u-alice"
        )

    # The question: does the OTHER store grant alice a fresh budget?
    with pytest.raises(UploadQuotaError):
        await shard_b.save(
            data=b"from b\n", filename="b.txt", uploader="alice", uploader_id="u-alice"
        )
    assert len(await shard_b.list_files()) == 2  # still exactly the cap, nothing extra written


async def test_concurrent_uploads_cannot_double_book_the_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ASVS 2.3.4: the quota check and the write it authorises are ONE critical section.

    Made deterministic rather than timing-dependent: the sidecar scan is slowed so both coroutines
    are guaranteed to overlap. Without the lock both read a count of 0 and both write, double-booking
    a quota of 1. With it, the second scan sees the first file and refuses.
    """
    store = _quota_store(tmp_path, max_files=1)

    real_scan = store._scan_metas_sync

    def _slow_scan() -> list[UploadedFileMeta]:
        out = real_scan()
        time.sleep(0.05)  # widen the window so an unlocked check-then-write WOULD lose the race
        return out

    monkeypatch.setattr(store, "_scan_metas_sync", _slow_scan)

    results = await asyncio.gather(
        store.save(data=b"first\n", filename="a.txt", uploader="alice", uploader_id="u-alice"),
        store.save(data=b"second\n", filename="b.txt", uploader="alice", uploader_id="u-alice"),
        return_exceptions=True,
    )

    ok = [r for r in results if isinstance(r, UploadedFileMeta)]
    refused = [r for r in results if isinstance(r, UploadQuotaError)]
    assert len(ok) == 1, f"exactly one upload may win a quota of 1, got {results}"
    assert len(refused) == 1, f"the loser must be refused on quota, got {results}"
    assert len(await store.list_files()) == 1  # and only the winner is on disk


async def test_prune_deletes_aged_pairs_and_is_idempotent(tmp_path: Path) -> None:
    # ASVS 5.2.4: files older than retention_days are deleted (blob AND meta), and a re-run is a no-op.
    store = _quota_store(tmp_path, retention_days=30)
    meta = await store.save(
        data=b"old diagnostic\n", filename="old.txt", uploader="op", uploader_id="u-op"
    )
    fresh = await store.save(
        data=b"fresh diagnostic\n", filename="new.txt", uploader="op", uploader_id="u-op"
    )
    # A prune "now" (nothing aged yet) removes nothing.
    assert await store.prune_expired() == PruneResult()
    # Backdate `old` by rewriting its meta uploaded_at 31 days into the past (re-encrypted under the same
    # store cipher + file_id AAD), then prune at real-now so only the aged pair is swept.
    root = tmp_path / "uploads"
    aged_meta = dataclasses.replace(meta, uploaded_at=time.time() - 31 * 86_400)
    (root / f"{meta.file_id}.meta").write_text(
        store._encrypt_meta(aged_meta),
        encoding="utf-8",  # noqa: SLF001 — test drives the cipher seam
    )
    result = await store.prune_expired()
    assert [m.file_id for m in result.pruned] == [meta.file_id]
    assert not (root / f"{meta.file_id}.blob").exists()
    assert not (root / f"{meta.file_id}.meta").exists()
    # Idempotent — the aged pair is already gone, and the orphan sweep found nothing to remove.
    assert await store.prune_expired() == PruneResult()
    assert [m.file_id for m in await store.list_files()] == [fresh.file_id]  # fresh file untouched


async def test_retention_runner_prunes_and_audits(tmp_path: Path) -> None:
    # The periodic runner drives prune_expired with its injected clock and audits each pruned file
    # (file_id + uploader, never content).
    store = _quota_store(tmp_path, retention_days=30)
    meta = await store.save(
        data=b"aging out\n", filename="a.txt", uploader="op", uploader_id="u-op"
    )
    audited: list[UploadedFileMeta] = []

    async def _audit(m: UploadedFileMeta) -> None:
        audited.append(m)

    # Inject a clock 31 days ahead so the just-saved file is past the window.
    runner = UploadRetentionRunner(store, audit=_audit, clock=lambda: time.time() + 31 * 86_400)
    result = await runner.run_once()
    assert [m.file_id for m in result.pruned] == [meta.file_id]
    assert [m.file_id for m in audited] == [meta.file_id]
    assert await store.list_files() == []


def _pause_sweep_at_pair(store: UploadStore, pair: int) -> tuple[threading.Event, threading.Event]:
    """Make the prune's worker thread block just before it deletes its ``pair``-th (1-based) aged
    pair. Returns ``(paused, release)``: ``paused`` is set once the thread is blocked, and the thread
    resumes when the test sets ``release``. ``_paths`` is the call the prune makes right before each
    unlink, so blocking there parks the thread mid-sweep with earlier pairs already gone."""
    paused = threading.Event()
    release = threading.Event()
    real_paths = store._paths
    calls = 0

    def _paths(file_id: str) -> tuple[Path, Path]:
        nonlocal calls
        calls += 1
        if calls == pair:
            paused.set()
            release.wait(timeout=10)
        return real_paths(file_id)

    store._paths = _paths  # type: ignore[method-assign]
    return paused, release


async def test_stopping_the_runner_mid_sweep_audits_every_file_it_deleted(tmp_path: Path) -> None:
    """BACKLOG #2065: ``stop()`` used to cancel the sweep and lose its audit rows.

    The sweep is parked in its worker thread before its SECOND pair, so one pair is already gone
    when ``stop()`` is called. The invariant is set equality between what left the disk and what was
    audited. Some files must also remain, which proves the stop cut the sweep short rather than
    waiting out the whole directory."""
    store = _quota_store(tmp_path, retention_days=30)
    ids = {
        (
            await store.save(
                data=f"aging {i}\n".encode(),
                filename=f"f{i}.txt",
                uploader="op",
                uploader_id="u-op",
            )
        ).file_id
        for i in range(4)
    }
    paused, release = _pause_sweep_at_pair(store, 2)
    audited: list[str] = []

    async def _audit(m: UploadedFileMeta) -> None:
        audited.append(m.file_id)

    runner = UploadRetentionRunner(
        store, audit=_audit, clock=lambda: time.time() + 31 * 86_400, interval_seconds=3600
    )
    runner.start()
    try:
        assert await asyncio.to_thread(paused.wait, 10), "the sweep never reached its second pair"
        stopping = asyncio.create_task(runner.stop())
        await asyncio.sleep(0)  # stop() raises its flags before its first await
    finally:
        release.set()
        await runner.stop()  # a no-op once `stopping` has run; stops the loop if an assert failed
    await asyncio.wait_for(stopping, 10)

    remaining = {m.file_id for m in await store.list_files()}
    deleted = ids - remaining
    assert deleted, "the sweep deleted nothing, so this run cannot tell audited from unaudited"
    assert sorted(audited) == sorted(deleted), (
        f"deleted {len(deleted)} file(s) but wrote {len(audited)} upload.prune row(s)"
    )
    assert remaining, "stop() waited out the whole sweep instead of stopping it at the next file"


async def test_a_refused_unlink_keeps_the_rest_of_the_sweep_auditable(tmp_path: Path) -> None:
    """BACKLOG #2065, same gap by another route. An unlink that raised used to abort the whole
    pass, which dropped the list naming the pairs already deleted, so none of them was audited.
    Now a pair whose BODY cannot be removed is left whole, still listed, for the next pass, and
    every other pair is still reported."""
    store = _quota_store(tmp_path, retention_days=30)
    metas = [
        await store.save(
            data=f"aging {i}\n".encode(), filename=f"f{i}.txt", uploader="op", uploader_id="u-op"
        )
        for i in range(3)
    ]
    stuck = metas[1].file_id
    real_paths = store._paths
    undeletable = tmp_path / "a-directory-cannot-be-unlinked"
    undeletable.mkdir()

    def _paths(file_id: str) -> tuple[Path, Path]:
        blob, meta = real_paths(file_id)
        return (undeletable, meta) if file_id == stuck else (blob, meta)

    store._paths = _paths  # type: ignore[method-assign]
    result = await store.prune_expired(now=time.time() + 31 * 86_400)

    assert sorted(m.file_id for m in result.pruned) == sorted(
        m.file_id for m in metas if m.file_id != stuck
    )
    assert [m.file_id for m in await store.list_files()] == [stuck]


async def _stop_stuck_runner(
    store: UploadStore,
    paused: threading.Event,
    release: threading.Event,
    caplog: pytest.LogCaptureFixture,
    audit: Callable[[UploadedFileMeta], Awaitable[None]] | None = None,
) -> logging.LogRecord:
    """Start a runner over ``store``, wait for its sweep to park on ``paused``, stop it with a
    0.05 s bound, release the sweep, and return the one record ``stop()`` logged about it."""
    runner = UploadRetentionRunner(
        store,
        audit=audit or _audited_to([]),
        clock=lambda: time.time() + 31 * 86_400,
        stop_timeout_seconds=0.05,
    )
    runner.start()
    try:
        assert await asyncio.to_thread(paused.wait, 10), "the sweep never reached its park point"
        with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
            await asyncio.wait_for(runner.stop(), 10)
    finally:
        release.set()
        await runner.stop()  # a no-op once stop() has run; stops the loop if an assert failed
    [record] = [r for r in caplog.records if "retention sweep" in r.getMessage()]
    return record


async def test_a_sweep_stuck_past_the_stop_bound_is_cancelled_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #2065, the bound. A sweep stuck inside one filesystem call cannot be stopped, so
    ``stop()`` waits only ``stop_timeout_seconds`` and then names the audit gap at ERROR rather than
    holding shutdown open forever or returning in silence. The sweep is parked on its SECOND pair,
    past that pair's abort check, so two pairs go with no audit row and the ERROR counts both."""
    store = _quota_store(tmp_path, retention_days=30)
    for i in range(2):
        await store.save(
            data=f"aging {i}\n".encode(), filename=f"f{i}.txt", uploader="op", uploader_id="u-op"
        )
    record = await _stop_stuck_runner(store, *_pause_sweep_at_pair(store, 2), caplog)
    assert record.levelno == logging.ERROR, record.getMessage()
    assert "did not finish within 0.05s of shutdown" in record.getMessage()
    assert "2 file(s) it removed, or was removing, may have no" in record.getMessage()


async def test_a_stuck_sweep_that_deleted_nothing_logs_no_audit_gap(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2264 item 1. ``stop()`` logged its possible-audit-gap ERROR even when the sweep had
    deleted nothing. Parked in its sidecar scan, the sweep has deleted nothing, and once released
    it sees the abort and deletes nothing more, so no row is lost: a WARNING, not an ERROR."""
    store = _quota_store(tmp_path, retention_days=30)
    meta = await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    paused, release, decided = threading.Event(), threading.Event(), threading.Event()
    real_scan = store._scan_metas_sync
    real_begin = _SweepTally.begin
    began: list[bool] = []

    def _stuck_scan() -> list[UploadedFileMeta]:
        paused.set()
        release.wait(timeout=10)
        return real_scan()

    def _begin(tally: _SweepTally, m: UploadedFileMeta, abort: threading.Event) -> bool:
        began.append(real_begin(tally, m, abort))
        decided.set()
        return began[-1]

    monkeypatch.setattr(store, "_scan_metas_sync", _stuck_scan)
    monkeypatch.setattr(_SweepTally, "begin", _begin)
    record = await _stop_stuck_runner(store, paused, release, caplog)
    assert record.levelno == logging.WARNING, record.getMessage()
    assert "no upload.prune row is lost" in record.getMessage()
    # Nothing joins a cancelled to_thread job, so wait for the released thread's decision on the
    # pair. The abort was set before the release, so it declines, and the pair stays whole.
    assert await asyncio.to_thread(decided.wait, 10), "the released sweep never reached the pair"
    assert began == [False]
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]


async def test_a_sweep_stuck_in_its_audit_writes_names_each_unaudited_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #2264, code review. The sweep removed three pairs and its audit write hangs on the
    second, so two rows are missing. The ERROR names exactly those two files, by ``file_id``."""
    store = _quota_store(tmp_path, retention_days=30)
    for i in range(3):
        await store.save(
            data=f"aging {i}\n".encode(), filename=f"f{i}.txt", uploader="op", uploader_id="u-op"
        )
    paused = threading.Event()
    written: list[str] = []

    async def _audit(m: UploadedFileMeta) -> None:
        if written:
            paused.set()
            await asyncio.Event().wait()  # hangs until stop() cancels the sweep
        written.append(m.file_id)

    record = await _stop_stuck_runner(store, paused, threading.Event(), caplog, audit=_audit)
    assert record.levelno == logging.ERROR, record.getMessage()
    assert "2 file(s) it removed, or was removing, may have no" in record.getMessage()
    assert await store.list_files() == []
    named = set(record.getMessage().rsplit(": ", 1)[1].split(", "))
    assert len(written) == 1 and written[0] not in named and len(named) == 2


async def test_a_refused_unlink_is_not_counted_as_an_audit_gap(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2264 item 1, code review. A pair whose body unlink is refused was never removed, so
    it owes no row. A sweep that then stalls in its orphan sweep loses nothing: a WARNING."""
    store = _quota_store(tmp_path, retention_days=30)
    await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    undeletable = tmp_path / "a-directory-cannot-be-unlinked"
    undeletable.mkdir()
    real_paths = store._paths
    monkeypatch.setattr(store, "_paths", lambda fid: (undeletable, real_paths(fid)[1]))
    paused, release = threading.Event(), threading.Event()

    def _stuck_orphans(*, now: float, abort: threading.Event | None = None) -> int:
        paused.set()
        release.wait(timeout=10)
        return 0

    monkeypatch.setattr(store, "_sweep_orphans_sync", _stuck_orphans)
    record = await _stop_stuck_runner(store, paused, release, caplog)
    assert record.levelno == logging.WARNING, record.getMessage()


async def test_a_refused_body_unlink_is_not_reported_and_the_pair_stays_whole(
    tmp_path: Path,
) -> None:
    """Round-2 finding: removing the sidecar first reported a pair as pruned while its body, the
    PHI, was still on disk because its unlink was refused. The body goes first now, so a refused
    body unlink leaves the whole pair listed for the next pass and writes no audit row."""
    store = _quota_store(tmp_path, retention_days=30)
    meta = await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    real_paths = store._paths
    undeletable = tmp_path / "a-directory-cannot-be-unlinked"
    undeletable.mkdir()
    store._paths = lambda file_id: (undeletable, real_paths(file_id)[1])  # type: ignore[method-assign]

    result = await store.prune_expired(now=time.time() + 31 * 86_400)

    assert result.pruned == [], "a pair whose body is still on disk was reported as pruned"
    assert result.orphans_removed == 0
    store._paths = real_paths  # type: ignore[method-assign]
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]
    assert (tmp_path / "uploads" / f"{meta.file_id}.blob").exists()


async def test_a_refused_sidecar_unlink_reports_the_pair_once(tmp_path: Path) -> None:
    """Once the body is gone the deletion that matters has happened, so the pair is reported even
    when its sidecar will not unlink. The next pass removes that sidecar and finds the body already
    gone, so it does not report the pair a second time."""
    store = _quota_store(tmp_path, retention_days=30)
    meta = await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    real_paths = store._paths
    undeletable = tmp_path / "a-directory-cannot-be-unlinked"
    undeletable.mkdir()
    store._paths = lambda file_id: (real_paths(file_id)[0], undeletable)  # type: ignore[method-assign]
    later = time.time() + 31 * 86_400

    first = await store.prune_expired(now=later)
    store._paths = real_paths  # type: ignore[method-assign]
    second = await store.prune_expired(now=later)

    assert [m.file_id for m in first.pruned] == [meta.file_id]
    assert second.pruned == []
    assert list((tmp_path / "uploads").iterdir()) == []


async def test_a_pair_another_pass_already_removed_is_not_reported_twice(tmp_path: Path) -> None:
    """The save-time sweep and the runner can overlap. A sidecar that is already gone when this pass
    reaches it was removed and reported by the other pass, so this one must not audit it again."""
    store = _quota_store(tmp_path, retention_days=30)
    await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    seen = store._scan_metas_sync()
    first = await store.prune_expired(now=time.time() + 31 * 86_400)
    store._scan_metas_sync = lambda: seen  # type: ignore[method-assign]
    second = await store.prune_expired(now=time.time() + 31 * 86_400)

    assert len(first.pruned) == 1
    assert second.pruned == []


async def test_stop_without_start_leaves_run_once_able_to_prune(tmp_path: Path) -> None:
    """stop() on a runner that never started must not leave its abort flag set, or every later
    run_once() silently prunes nothing."""
    store = _quota_store(tmp_path, retention_days=30)
    await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    runner = UploadRetentionRunner(store, clock=lambda: time.time() + 31 * 86_400)
    await runner.stop()
    assert len((await runner.run_once()).pruned) == 1


async def test_a_cancelled_shutdown_does_not_escape_stop(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The API lifespan stops the runner FIRST in its teardown. A cancellation of that teardown
    while stop() waits must not propagate out of stop(), or engine.stop() is skipped."""
    store = _quota_store(tmp_path, retention_days=30)
    await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    paused, release = _pause_sweep_at_pair(store, 1)
    runner = UploadRetentionRunner(
        store, clock=lambda: time.time() + 31 * 86_400, stop_timeout_seconds=30
    )
    runner.start()
    try:
        assert await asyncio.to_thread(paused.wait, 10), "the sweep never started deleting"

        async def _teardown() -> str:
            await runner.stop()
            return "teardown continued"

        teardown = asyncio.create_task(_teardown())
        await asyncio.sleep(0.05)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
            teardown.cancel()
            assert await asyncio.wait_for(teardown, 10) == "teardown continued"
    finally:
        release.set()
        await runner.stop()  # a no-op once stop() has run; stops the loop if an assert failed
    assert "shutdown itself was cancelled" in caplog.text, caplog.text


class _RecordingLedger:
    """An UploadQuotaLedger that records when each release arrives."""

    def __init__(self, uploads_root: Path) -> None:
        self.root = uploads_root
        self.metas_at_release: list[int] = []

    async def reserve_upload_quota(
        self,
        uploader_id: str,
        *,
        files: int,
        size_bytes: int,
        max_files: int = 0,
        max_total_bytes: int = 0,
    ) -> bool:
        if files < 0:
            self.metas_at_release.append(len(list(self.root.glob("*.meta"))))
        return True

    async def upload_quota_in_flight(self, uploader_id: str) -> tuple[int, int]:
        return (1, 0)


async def test_a_cancelled_save_releases_its_reservation_only_after_the_file_lands(
    tmp_path: Path,
) -> None:
    """BACKLOG #1941's ordering needs a release to follow the landing. A bare to_thread re-raises
    the cancellation at once while the write thread runs on, so the reservation used to be paid
    back, and _quota_lock dropped, before the sidecar existed."""
    root = tmp_path / "uploads"
    ledger = _RecordingLedger(root)
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    writing, finish = threading.Event(), threading.Event()
    real_encrypt_meta = store._encrypt_meta

    def _slow_encrypt_meta(meta: UploadedFileMeta) -> str:
        writing.set()
        finish.wait(10)
        return real_encrypt_meta(meta)

    store._encrypt_meta = _slow_encrypt_meta  # type: ignore[method-assign]
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    try:
        assert await asyncio.to_thread(writing.wait, 10), "the write never started"
        save.cancel()
        await asyncio.sleep(0.05)
        assert ledger.metas_at_release == [], "released while the write thread was still running"
    finally:
        finish.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    assert ledger.metas_at_release == [1]


async def test_a_forced_shutdown_cancelling_every_task_still_waits_for_the_write(
    tmp_path: Path,
) -> None:
    """Round-2 finding 2. ``asyncio.run`` cancels EVERY pending task at shutdown, not only the one
    awaiting the save. If the write's own wait is a Task, that cancel ends it early and the
    reservation is paid back before the file lands, which is the #1941 premise broken again."""
    root = tmp_path / "uploads"
    ledger = _RecordingLedger(root)
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    writing, finish = threading.Event(), threading.Event()
    real_encrypt_meta = store._encrypt_meta

    def _slow_encrypt_meta(meta: UploadedFileMeta) -> str:
        writing.set()
        finish.wait(10)
        return real_encrypt_meta(meta)

    store._encrypt_meta = _slow_encrypt_meta  # type: ignore[method-assign]
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    try:
        assert await asyncio.to_thread(writing.wait, 10), "the write never started"
        # What asyncio.run's teardown does, scoped to this test: cancel the tasks it would reach.
        mine = asyncio.current_task()
        for task in asyncio.all_tasks():
            if task is not mine and task.get_coro().__name__ in ("to_thread", "save"):  # type: ignore[union-attr]
                task.cancel()
        await asyncio.sleep(0.05)
        assert ledger.metas_at_release == [], "released while the write thread was still running"
    finally:
        finish.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    assert ledger.metas_at_release == [1]


def _hold_after_the_sidecar_lands(
    mp: pytest.MonkeyPatch,
) -> tuple[threading.Event, threading.Event]:
    """Patch the module's atomic write so the write thread pauses just AFTER the sidecar lands.
    Returns ``(landed, finish)``: ``landed`` is set once the pair is on disk, and the thread
    returns only once ``finish`` is set."""
    from messagefoundry import uploads as uploads_mod

    landed, finish = threading.Event(), threading.Event()
    real = uploads_mod._atomic_write_text

    def _write_then_hold(root: Path, path: Path, text: str) -> None:
        real(root, path, text)
        if path.suffix == ".meta":
            landed.set()
            finish.wait(10)

    mp.setattr(uploads_mod, "_atomic_write_text", _write_then_hold)
    return landed, finish


async def _cancel_once_landed(store: UploadStore, mp: pytest.MonkeyPatch) -> None:
    """Start a save, cancel it just AFTER its sidecar lands, and assert the cancellation propagates."""
    landed, finish = _hold_after_the_sidecar_lands(mp)
    save = asyncio.create_task(
        store.save(data=_ADT.encode(), filename="x.hl7", uploader="op", uploader_id="u-op")
    )
    try:
        assert await asyncio.to_thread(landed.wait, 10), "the sidecar never landed"
        # The control: the pair IS on disk when the cancellation is sent.
        assert len(list(store._root.glob("*.meta"))) == 1
        save.cancel()
    finally:
        finish.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)


async def test_a_save_cancelled_after_its_file_lands_leaves_no_file(tmp_path: Path) -> None:
    """BACKLOG #2262. The API writes ``upload.create`` only once ``save`` returns, so a cancellation
    reaching ``save`` after the pair landed left a stored upload with no creation row while the
    request answered an error. The pair is removed before the cancellation propagates. Red before
    the fix: one ``.blob`` and one ``.meta`` stayed, and ``list_files`` returned the upload."""
    store = _store(tmp_path, key=True)
    with pytest.MonkeyPatch.context() as mp:
        await _cancel_once_landed(store, mp)
    assert list((tmp_path / "uploads").iterdir()) == []
    assert await store.list_files() == []


async def test_an_anyio_scope_cancel_still_removes_the_landed_file(tmp_path: Path) -> None:
    """BACKLOG #2262 under the cancellation production delivers. The request deadline reaches the
    route through anyio task groups (``BaseHTTPMiddleware``), which cancel again at every await. A
    plain ``to_thread`` cleanup cancelled before a worker picked it up never ran; measured in review
    at 25 runs of 200. The cleanup now waits through repeat cancellations, as the write does."""
    import functools

    import anyio

    store = _store(tmp_path, key=True)
    with pytest.MonkeyPatch.context() as mp:
        landed, finish = _hold_after_the_sidecar_lands(mp)
        save = functools.partial(
            store.save, data=_ADT.encode(), filename="x.hl7", uploader="op", uploader_id="u-op"
        )
        async with anyio.create_task_group() as tg:
            tg.start_soon(save)
            try:
                assert await asyncio.to_thread(landed.wait, 10), "the sidecar never landed"
                tg.cancel_scope.cancel()
            finally:
                finish.set()
    assert list((tmp_path / "uploads").iterdir()) == []


async def test_a_cancel_in_the_reservation_release_still_removes_the_landed_file(
    tmp_path: Path,
) -> None:
    """BACKLOG #2262, the later window: the write returned, then the cancellation landed in the
    cross-shard release await. That raised out of ``save`` with the file on disk just the same.
    BACKLOG #2263: the release itself now finishes before the cancellation propagates."""
    root = tmp_path / "uploads"
    releasing, finish = asyncio.Event(), asyncio.Event()

    class _SlowReleaseLedger(_RecordingLedger):
        async def reserve_upload_quota(
            self,
            uploader_id: str,
            *,
            files: int,
            size_bytes: int,
            max_files: int = 0,
            max_total_bytes: int = 0,
        ) -> bool:
            if files < 0:
                releasing.set()
                await finish.wait()
            return await super().reserve_upload_quota(
                uploader_id, files=files, size_bytes=size_bytes
            )

    ledger = _SlowReleaseLedger(root)
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(releasing.wait(), 10)
    assert len(list(root.glob("*.meta"))) == 1  # the control: the write had returned
    save.cancel()
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    assert list(root.iterdir()) == []
    assert ledger.metas_at_release == [1], "the cancelled release never paid the slot back"


@pytest.fixture
async def ledger_db(tmp_path: Path) -> AsyncIterator[MessageStore]:
    """A real SQLite store, for tests that read the upload-quota ledger back."""
    db = await MessageStore.open(tmp_path / "engine.db")
    try:
        yield db
    finally:
        await db.close()


class _GatedLedger:
    """The real SQLite ledger with one pause: just AFTER a reserve commits (``hold="reserve"``), or
    just BEFORE a release starts (``hold="release"``). ``at_gate`` is set on arrival and the call
    goes on once ``gate`` is set. A cancellation delivered at the reserve pause is the shape of one
    that lands in the store's commit await while its thread commits anyway."""

    def __init__(self, store: MessageStore, *, hold: Literal["reserve", "release"]) -> None:
        self.store = store
        self.hold = hold
        self.at_gate, self.gate = asyncio.Event(), asyncio.Event()

    async def _pause(self) -> None:
        self.at_gate.set()
        await self.gate.wait()

    async def reserve_upload_quota(
        self,
        uploader_id: str,
        *,
        files: int,
        size_bytes: int,
        max_files: int = 0,
        max_total_bytes: int = 0,
    ) -> bool:
        if files < 0 and self.hold == "release":
            await self._pause()
        applied = await self.store.reserve_upload_quota(
            uploader_id,
            files=files,
            size_bytes=size_bytes,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
        if files > 0 and self.hold == "reserve":
            await self._pause()
        return applied

    async def upload_quota_in_flight(self, uploader_id: str) -> tuple[int, int]:
        return await self.store.upload_quota_in_flight(uploader_id)


async def test_a_reserve_cancelled_after_its_commit_pays_the_slot_back(
    tmp_path: Path, ledger_db: MessageStore
) -> None:
    """BACKLOG #2263. A cancellation that reached ``save`` after the reserve had committed, but
    before the store call returned, skipped the release, because ``reserved`` was never assigned.
    The slot then narrowed the uploader's budget, and its refusal blamed a shard that is not there.
    Red before the fix: the ledger still read ``(1, 2)`` in flight."""
    root = tmp_path / "uploads"
    ledger = _GatedLedger(ledger_db, hold="reserve")
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(ledger.at_gate.wait(), 10)
    assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)  # the control: it committed
    save.cancel()
    ledger.gate.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)
    assert not root.exists() or list(root.iterdir()) == []


@pytest.mark.parametrize("hold", ["reserve", "release"])
async def test_an_anyio_scope_cancel_at_either_ledger_call_pays_the_slot_back(
    tmp_path: Path, ledger_db: MessageStore, hold: Literal["reserve", "release"]
) -> None:
    """BACKLOG #2263 under the cancellation production delivers: an anyio scope cancels again at
    every await, the release's own included. ``reserve``: the cancel lands just after the reserve
    commits. ``release``: it lands while the release itself is in flight."""
    import functools

    import anyio

    root = tmp_path / "uploads"
    ledger = _GatedLedger(ledger_db, hold=hold)
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    save = functools.partial(
        store.save, data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op"
    )
    async with anyio.create_task_group() as tg:
        tg.start_soon(save)
        try:
            await asyncio.wait_for(ledger.at_gate.wait(), 10)
            assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)  # the control
            tg.cancel_scope.cancel()
        finally:
            ledger.gate.set()
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)
    assert not root.exists() or list(root.iterdir()) == []


async def test_a_deadline_mid_write_still_pays_the_reservation_back(
    tmp_path: Path, ledger_db: MessageStore
) -> None:
    """BACKLOG #2263, the release half. A request deadline arrives through an anyio scope while
    the write runs. The write waits it out, and then the release in ``save``'s ``finally`` was
    cancelled again at its first await and never committed. Red before the fix: ``(1, len)`` stayed
    in flight on the ledger, while #2262's cleanup removed the file."""
    import functools

    import anyio

    root = tmp_path / "uploads"
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=1024, store=ledger_db)
    with pytest.MonkeyPatch.context() as mp:
        landed, finish = _hold_after_the_sidecar_lands(mp)
        save = functools.partial(
            store.save, data=_ADT.encode(), filename="x.hl7", uploader="op", uploader_id="u-op"
        )
        async with anyio.create_task_group() as tg:
            tg.start_soon(save)
            try:
                assert await asyncio.to_thread(landed.wait, 10), "the sidecar never landed"
                tg.cancel_scope.cancel()
            finally:
                finish.set()
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("hold", ["reserve", "release"])
async def test_a_ledger_call_stuck_past_the_bound_lets_the_cancellation_through(
    tmp_path: Path,
    ledger_db: MessageStore,
    caplog: pytest.LogCaptureFixture,
    hold: Literal["reserve", "release"],
) -> None:
    """BACKLOG #2263's wait is bounded. A store that never answers must not hold ``_quota_lock``
    and the request's cancellation forever: past the bound the call is left running, a WARNING
    names it, and the cancellation propagates. A landed file is still removed (#2262). Once the
    call does finish, the slot is paid back: a late reserve by a fresh release."""
    from messagefoundry import uploads as uploads_mod

    root = tmp_path / "uploads"
    ledger = _GatedLedger(ledger_db, hold=hold)
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    with (
        pytest.MonkeyPatch.context() as mp,
        caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"),
    ):
        mp.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.2)
        save = asyncio.create_task(
            store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
        )
        await asyncio.wait_for(ledger.at_gate.wait(), 10)
        save.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(save, 10)
            assert not store._quota_lock.locked()
            assert f"upload {hold} for u-op did not finish" in caplog.text, caplog.text
            assert not root.exists() or list(root.iterdir()) == []
        finally:
            ledger.gate.set()  # let the abandoned call finish before the store closes
            await _drain_stragglers(store)
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)


async def _drain_stragglers(store: UploadStore) -> None:
    """Wait for every ledger call a cancelled save left running, a late release included."""
    for _ in range(100):
        if not store._stragglers:
            return
        await asyncio.wait(set(store._stragglers), timeout=10)
    raise AssertionError("ledger calls were still running")


async def test_a_cancel_absorbed_by_the_write_still_bounds_the_release(
    tmp_path: Path, ledger_db: MessageStore
) -> None:
    """A plain asyncio cancel is used up by the write's wait, so the release in ``save``'s
    ``finally`` starts with no cancellation pending. It is bounded all the same, because the task
    is still cancelling. Found in review: without that, the release waited forever."""
    from messagefoundry import uploads as uploads_mod

    root = tmp_path / "uploads"
    ledger = _GatedLedger(ledger_db, hold="release")
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=1024, store=ledger)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.2)
        landed, finish = _hold_after_the_sidecar_lands(mp)
        save = asyncio.create_task(
            store.save(data=_ADT.encode(), filename="x.hl7", uploader="op", uploader_id="u-op")
        )
        try:
            assert await asyncio.to_thread(landed.wait, 10), "the sidecar never landed"
            save.cancel()
        finally:
            finish.set()
        try:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(save, 10)
            assert not store._quota_lock.locked()
            assert list(root.iterdir()) == []
        finally:
            ledger.gate.set()
            await _drain_stragglers(store)
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)


async def test_a_reserve_that_fails_while_cancelled_is_logged_and_not_blindly_released(
    tmp_path: Path, ledger_db: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A reserve whose outcome is unknown is not paid back: a release here could subtract a
    sibling shard's live slot and let an upload past the cap. It is logged instead. The ledger
    keeping ``(1, 2)`` is the control that no release ran."""

    class _CommitThenFail(_GatedLedger):
        async def reserve_upload_quota(
            self,
            uploader_id: str,
            *,
            files: int,
            size_bytes: int,
            max_files: int = 0,
            max_total_bytes: int = 0,
        ) -> bool:
            await super().reserve_upload_quota(
                uploader_id,
                files=files,
                size_bytes=size_bytes,
                max_files=max_files,
                max_total_bytes=max_total_bytes,
            )
            raise ConnectionError("lost after the commit")

    root = tmp_path / "uploads"
    ledger = _CommitThenFail(ledger_db, hold="reserve")
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=4096, store=ledger)
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(ledger.at_gate.wait(), 10)
    save.cancel()
    ledger.gate.set()
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"),
        pytest.raises(asyncio.CancelledError),
    ):
        await asyncio.wait_for(save, 10)
    assert "reserve for u-op failed while the upload was being cancelled" in caplog.text
    # Logged once, by this module. An asyncio.shield wait also handed it to the loop's handler.
    assert "shielded future" not in caplog.text, caplog.text
    assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)


async def test_a_refused_removal_keeps_the_pair_and_logs_the_audit_gap(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A body the filesystem will not unlink keeps its sidecar too, so the upload stays listed and
    billed rather than hidden, and the missing ``upload.create`` row is named at ERROR."""
    store = _store(tmp_path, key=True)
    root = tmp_path / "uploads"
    real_unlink = Path.unlink

    def _refuse_the_body(self: Path, missing_ok: bool = False) -> None:
        if self.suffix == ".blob":
            raise PermissionError(13, "in use")
        real_unlink(self, missing_ok=missing_ok)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "unlink", _refuse_the_body)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
            await _cancel_once_landed(store, mp)
    assert len(list(root.glob("*.blob"))) == 1
    assert len(list(root.glob("*.meta"))) == 1
    assert "no upload.create audit row" in caplog.text, caplog.text
    assert "x.hl7" not in caplog.text  # the filename can carry PHI


async def _save_aged(store: UploadStore, root: Path, count: int) -> set[str]:
    """Save ``count`` files and backdate each past a 30-day window, so a sweep at real-now takes
    them. The sidecar is re-encrypted under the store's own cipher and ``file_id`` AAD."""
    ids: set[str] = set()
    for i in range(count):
        meta = await store.save(
            data=f"aging {i}\n".encode(), filename=f"f{i}.txt", uploader="op", uploader_id="u-op"
        )
        aged = dataclasses.replace(meta, uploaded_at=time.time() - 31 * 86_400)
        (root / f"{meta.file_id}.meta").write_text(
            store._encrypt_meta(aged),
            encoding="utf-8",  # noqa: SLF001 — test drives the cipher seam
        )
        ids.add(meta.file_id)
    return ids


def _park_sweep_until_aborted(store: UploadStore, pair: int) -> threading.Event:
    """Park the prune's worker thread just before its ``pair``-th (1-based) pair until the pass's
    ``abort`` is set, and return an event set once it is parked.

    Released by the abort itself, not by the test, so the sweep resumes only once the cancelled
    caller has asked it to stop. The parked pair is still deleted, because the thread is past the
    abort check for it; the next one is not. A caller that never sets ``abort`` lets the thread
    resume after 5 s."""
    parked = threading.Event()
    aborts: list[threading.Event] = []
    real_prune = store.prune_expired
    real_paths = store._paths
    calls = 0

    async def _prune(**kwargs: Any) -> PruneResult:
        aborts.append(kwargs.get("abort") or threading.Event())
        return await real_prune(**kwargs)

    def _paths(file_id: str) -> tuple[Path, Path]:
        nonlocal calls
        calls += 1
        if calls == pair:
            parked.set()
            aborts[-1].wait(timeout=5)
        return real_paths(file_id)

    store.prune_expired = _prune  # type: ignore[method-assign]
    store._paths = _paths  # type: ignore[method-assign]
    return parked


def _audited_to(rows: list[str]) -> Callable[[UploadedFileMeta], Awaitable[None]]:
    async def _audit(m: UploadedFileMeta) -> None:
        rows.append(m.file_id)

    return _audit


async def test_a_save_time_sweep_cancelled_mid_sweep_audits_every_file_it_deleted(
    tmp_path: Path,
) -> None:
    """BACKLOG #2261. The upload route's sweep had #2065's shape: the request deadline cancelled
    it, the worker thread kept deleting, and no ``upload.prune`` row was written for any file.

    The deadline arrives through an anyio scope, which cancels again at every await. The invariant
    is set equality between what left the disk and what was audited, and some files must remain,
    which proves the cancel stopped the sweep. Red before the fix: every file went, and no row."""
    import anyio

    store = _quota_store(tmp_path, retention_days=30)
    ids = await _save_aged(store, tmp_path / "uploads", 4)
    parked = _park_sweep_until_aborted(store, 2)
    audited: list[str] = []
    audit = _audited_to(audited)

    async with anyio.create_task_group() as tg:
        tg.start_soon(store.prune_on_save, audit)
        assert await asyncio.to_thread(parked.wait, 10), "the sweep never reached its second pair"
        tg.cancel_scope.cancel()

    remaining = {m.file_id for m in await store.list_files()}
    deleted = ids - remaining
    assert len(deleted) == 2, f"expected the first two pairs deleted, got {len(deleted)}"
    assert sorted(audited) == sorted(deleted), (
        f"deleted {len(deleted)} file(s) but wrote {len(audited)} upload.prune row(s)"
    )
    assert remaining, "the cancel waited out the whole sweep instead of stopping it"


async def test_a_plain_cancel_of_the_save_time_sweep_also_audits_what_it_deleted(
    tmp_path: Path,
) -> None:
    """BACKLOG #2261, the single cancel ``asyncio.timeout`` delivers, which the route's own
    deadline middleware uses. The cancellation still propagates once the rows are written."""
    store = _quota_store(tmp_path, retention_days=30)
    ids = await _save_aged(store, tmp_path / "uploads", 3)
    parked = _park_sweep_until_aborted(store, 2)
    audited: list[str] = []
    sweep = asyncio.create_task(store.prune_on_save(_audited_to(audited)))
    assert await asyncio.to_thread(parked.wait, 10), "the sweep never reached its second pair"
    sweep.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(sweep, 10)
    deleted = ids - {m.file_id for m in await store.list_files()}
    assert sorted(audited) == sorted(deleted) and len(deleted) == 2


async def test_a_task_run_to_completion_lands_after_its_caller_is_cancelled(
    tmp_path: Path,
) -> None:
    """BACKLOG #2261, the primitive. Under an anyio scope, which cancels again at every await, a
    write run through ``_run_to_completion`` still lands before the cancellation propagates."""
    import anyio

    store = _store(tmp_path, key=True)
    landed: list[str] = []

    async def _write() -> None:
        await asyncio.sleep(0.2)
        landed.append("row")

    started = asyncio.Event()

    async def _caller() -> None:
        started.set()
        await store._run_to_completion(_write())

    async with anyio.create_task_group() as tg:
        tg.start_soon(_caller)
        await started.wait()
        await asyncio.sleep(0)
        tg.cancel_scope.cancel()
    assert landed == ["row"]


async def test_a_write_stuck_past_the_bound_is_left_to_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #2261, the bound. A cancelled caller waits only so long, then its cancellation
    propagates. The write is held, not cancelled, so it can still finish late, and a late failure
    is logged rather than lost."""
    monkeypatch.setattr("messagefoundry.uploads._LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    store = _store(tmp_path, key=True)
    release = asyncio.Event()

    async def _write() -> None:
        await release.wait()
        raise RuntimeError("store unreachable")

    caller = asyncio.create_task(store._run_to_completion(_write()))
    await asyncio.sleep(0)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(caller, 10)
    assert store._stragglers, "the write was dropped instead of left to finish"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        release.set()
        await _drain_stragglers(store)
        await asyncio.sleep(0)  # the done callback runs one loop pass after the task ends
    assert "left running after its caller was cancelled failed" in caplog.text, caplog.text


async def test_a_save_time_sweep_shutdown_cancels_names_each_unaudited_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #2264, code review. The save-time sweep removed three pairs and its audit write
    hangs on the second. Its request is cancelled, the bound passes, and shutdown then cancels
    the held sweep. The ERROR names exactly the two files with no row, as the runner's stop does,
    rather than a bare "may have" that also fires for a sweep that removed nothing."""
    monkeypatch.setattr("messagefoundry.uploads._LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    store = _quota_store(tmp_path, retention_days=30)
    ids = await _save_aged(store, tmp_path / "uploads", 3)
    hung = asyncio.Event()
    written: list[str] = []

    async def _audit(m: UploadedFileMeta) -> None:
        if written:
            hung.set()
            await asyncio.Event().wait()  # hangs until shutdown cancels the sweep
        written.append(m.file_id)

    sweep = asyncio.create_task(store.prune_on_save(_audit))
    await asyncio.wait_for(hung.wait(), 10)
    sweep.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(sweep, 10)
    [held] = list(store._stragglers)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        held.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await held
        await asyncio.sleep(0)  # the done callback runs one loop pass after the task ends
    [record] = [r for r in caplog.records if "save-time upload prune" in r.getMessage()]
    assert record.levelno == logging.ERROR, record.getMessage()
    assert "2 file(s) it removed, or was removing, may have no" in record.getMessage()
    named = set(record.getMessage().rsplit(": ", 1)[1].split(", "))
    assert named == ids - set(written) and len(written) == 1


async def test_an_orphan_sweep_failure_keeps_the_pruned_pairs_reported(tmp_path: Path) -> None:
    """BACKLOG #2261. The orphan sweep runs after the deletions, so a failure in it used to raise
    out of the pass and drop the list naming the pairs already deleted, and with it their rows."""
    store = _quota_store(tmp_path, retention_days=30)
    ids = await _save_aged(store, tmp_path / "uploads", 2)

    def _boom(*, now: float, abort: threading.Event | None = None) -> int:
        raise PermissionError("uploads root unreadable")

    store._sweep_orphans_sync = _boom  # type: ignore[method-assign]
    result = await store.prune_expired()
    assert {m.file_id for m in result.pruned} == ids
    assert result.orphans_removed == 0


async def test_run_once_after_start_and_stop_still_prunes(tmp_path: Path) -> None:
    """Round-2 finding 3. stop() sets the abort flag for the sweep in flight. Left set, it made every
    later run_once() prune nothing, silently."""
    store = _quota_store(tmp_path, retention_days=30)
    await store.save(data=b"aging\n", filename="a.txt", uploader="op", uploader_id="u-op")
    runner = UploadRetentionRunner(
        store, clock=lambda: time.time() + 31 * 86_400, interval_seconds=3600
    )
    runner.start()
    await runner.stop()
    await store.save(data=b"aging too\n", filename="b.txt", uploader="op", uploader_id="u-op")
    assert len((await runner.run_once()).pruned) >= 1, "run_once pruned nothing after stop()"


def test_store_settings_quota_defaults_are_on_and_enforced() -> None:
    # Regression guard (ASVS 5.2.4): the quota/retention defaults are non-None, ON, and floored at ge=1,
    # so a future default-off cannot silently reopen the cell. A directly-constructed UploadStore inherits
    # the same enforced defaults.
    s = StoreSettings()
    assert s.max_upload_files_per_user == 100
    assert s.max_upload_total_bytes_per_user == 250 * 1024 * 1024
    assert s.uploads_retention_days == 30
    for key in (
        "max_upload_files_per_user",
        "max_upload_total_bytes_per_user",
        "uploads_retention_days",
    ):
        with pytest.raises(pydantic.ValidationError):  # ge=1 floor: cannot be disabled with 0
            StoreSettings.model_validate({key: 0})
    us = UploadStore(Path("uploads"), make_cipher(None), max_bytes=1024)
    assert us.max_files_per_user == 100
    assert us.max_total_bytes_per_user == 250 * 1024 * 1024
    assert us.retention_days == 30


async def test_cell_aad_binds_blob_to_file_id(tmp_path: Path) -> None:
    # A v2 ciphertext moved to another file_id must fail the auth tag (cell-bound AAD, ADR 0019/0134).
    store = _store(tmp_path, key=True, aad=True)
    a = await store.save(data=_ADT.encode(), filename="a.hl7", uploader="op", uploader_id="u-op")
    b = await store.save(data=_BATCH.encode(), filename="b.hl7", uploader="op", uploader_id="u-op")
    root = tmp_path / "uploads"
    # Swap a's blob ciphertext under b's id — decrypt of b's body must now fail (bound to b's id).
    (root / f"{b.file_id}.blob").write_text(
        (root / f"{a.file_id}.blob").read_text(), encoding="utf-8"
    )
    with pytest.raises(CipherError):  # auth-tag mismatch — never a silent mis-decrypt
        await store.read_bytes(b.file_id)
