# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""UploadStore — offline uploaded-logs storage (BACKLOG #125/#126, ADR 0134)."""

from __future__ import annotations

import asyncio
import dataclasses
import time
from pathlib import Path

import pydantic
import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.crypto import CipherError, generate_key, make_cipher
from messagefoundry.uploads import (
    UploadContentError,
    UploadedFileMeta,
    UploadNotFoundError,
    UploadPathError,
    UploadQuotaError,
    UploadRetentionRunner,
    UploadStore,
    UploadTooLargeError,
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
    assert await store.prune_expired() == []
    # Backdate `old` by rewriting its meta uploaded_at 31 days into the past (re-encrypted under the same
    # store cipher + file_id AAD), then prune at real-now so only the aged pair is swept.
    root = tmp_path / "uploads"
    aged_meta = dataclasses.replace(meta, uploaded_at=time.time() - 31 * 86_400)
    (root / f"{meta.file_id}.meta").write_text(
        store._encrypt_meta(aged_meta),
        encoding="utf-8",  # noqa: SLF001 — test drives the cipher seam
    )
    pruned = await store.prune_expired()
    assert [m.file_id for m in pruned] == [meta.file_id]
    assert not (root / f"{meta.file_id}.blob").exists()
    assert not (root / f"{meta.file_id}.meta").exists()
    assert await store.prune_expired() == []  # idempotent — the aged pair is already gone
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
    pruned = await runner.run_once()
    assert [m.file_id for m in pruned] == [meta.file_id]
    assert [m.file_id for m in audited] == [meta.file_id]
    assert await store.list_files() == []


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
            StoreSettings(**{key: 0})
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
