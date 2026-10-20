# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0129 / BACKLOG #142 — the process-in-place (`after_read='leave'`) processed-file dedup ledger.

Covers the SQLite `processed_files` store methods (`is_file_processed` / `record_processed_file` /
`prune_processed_files`) and an end-to-end runner test proving a leave-in-place File source ingests a
file ONCE across many polls, leaving it in place, with the durable store ledger. SQL Server / Postgres
parity is validated on the CI legs (no live server DB here)."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import (
    FILE_KEY_SCHEME,
    FILE_KEY_SCHEMES,
    FileKeyError,
    check_file_key,
    file_key_forms,
)

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "pf.db")
    yield s
    await s.close()


async def _wait_count(
    store: MessageStore, channel_id: str, want: int, timeout: float = 10.0
) -> None:
    elapsed = 0.0
    while await store.count_messages(channel_id=channel_id, allowed_channels=None) < want:
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("message count not reached within timeout")


def _bare_digest(root: Path, path: Path) -> str:
    """The key every release before BACKLOG #3424 wrote: the untagged digest."""
    st = path.stat()
    rel = path.relative_to(root).as_posix()  # path folded relative to the watch root (ADR 0129)
    ident = f"{rel}\x00{st.st_mtime_ns}\x00{st.st_size}"
    return hashlib.sha256(ident.encode("utf-8", "surrogatepass")).hexdigest()


def _expected_key(root: Path, path: Path) -> str:
    """The key this release writes: the scheme tag, then the same digest (BACKLOG #3424)."""
    return "fk1:" + _bare_digest(root, path)


def _leave_registry(share: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {
                    "directory": str(share),
                    "pattern": "*.hl7",
                    "poll_seconds": 0.02,
                    "after_read": "leave",
                },
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


# --- store methods ----------------------------------------------------------


async def test_record_query_and_idempotent(store: MessageStore) -> None:
    assert not await store.is_file_processed(channel_id="ch", file_key="k1")
    await store.record_processed_file(channel_id="ch", file_key="k1")
    assert await store.is_file_processed(channel_id="ch", file_key="k1")
    # Idempotent on the (channel_id, file_key) PK — a crash-re-run is a no-op, never a PK error.
    await store.record_processed_file(channel_id="ch", file_key="k1")
    assert await store.is_file_processed(channel_id="ch", file_key="k1")
    # Scoped per channel: the SAME key under another connection is distinct.
    assert not await store.is_file_processed(channel_id="other", file_key="k1")


async def test_prune_by_age_then_count(store: MessageStore) -> None:
    for i in range(5):
        await store.record_processed_file(channel_id="ch", file_key=f"k{i}", now=100.0 + i)
    # Age prune: rows recorded before 102 (k0@100, k1@101) go; k2/k3/k4 stay.
    assert await store.prune_processed_files(channel_id="ch", older_than=102.0, keep_last=1000) == 2
    assert not await store.is_file_processed(channel_id="ch", file_key="k0")
    assert await store.is_file_processed(channel_id="ch", file_key="k4")
    # Count cap: keep only the newest 1 (k4@104); k2/k3 go. older_than=0 → no age deletes.
    assert await store.prune_processed_files(channel_id="ch", older_than=0.0, keep_last=1) == 2
    assert await store.is_file_processed(channel_id="ch", file_key="k4")
    assert not await store.is_file_processed(channel_id="ch", file_key="k2")
    # A pruned-then-re-seen file simply re-ingests (bounded duplicate) — the query is False again.
    assert not await store.is_file_processed(channel_id="ch", file_key="k3")


# --- end-to-end via the runner ----------------------------------------------


async def test_leave_in_place_ingests_once_across_polls(
    store: MessageStore, tmp_path: Path
) -> None:
    # An after_read='leave' File inbound on a (writable, but treated-as-read-only) share ingests the drop
    # exactly ONCE despite many polls, leaves the file in place, and never creates a .processed copy —
    # the durable store ledger provides the cross-poll dedup.
    share = tmp_path / "share"
    share.mkdir()
    (share / "a.hl7").write_bytes(ADT.encode("utf-8"))
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {
                    "directory": str(share),
                    "pattern": "*.hl7",
                    "poll_seconds": 0.02,
                    "after_read": "leave",
                },
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])  # UNROUTED — still counted RECEIVED (count-and-log)
    expected_key = _expected_key(share, share / "a.hl7")
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await runner.start()
    try:
        await _wait_count(store, "file_in", 1)
        await asyncio.sleep(0.2)  # many more poll cycles — must NOT re-ingest
    finally:
        await runner.stop()
    assert (
        await store.count_messages(channel_id="file_in", allowed_channels=None) == 1
    )  # ingested ONCE
    assert (share / "a.hl7").exists()  # left in place
    assert not (share / ".processed" / "a.hl7").exists()  # never moved
    # The ledger recorded exactly one file for this connection (a HASHED key — no cleartext filename).
    assert await store.is_file_processed(channel_id="file_in", file_key=expected_key)
    # ...under the scheme-tagged form only (BACKLOG #3424); the bare pre-tag digest is never written.
    bare = _bare_digest(share, share / "a.hl7")
    assert not await store.is_file_processed(channel_id="file_in", file_key=bare)


# --- the key's scheme tag (BACKLOG #3424, ASVS 11.2.2 census row 15) -------------


async def test_a_file_recorded_under_the_untagged_key_is_not_read_again(
    store: MessageStore, tmp_path: Path
) -> None:
    """A ledger row written before the tag existed still marks its file read, so a share left in
    place does not arrive downstream again after the upgrade. Mutation: drop the bare digest from
    ``file_key_forms``. Red: the file is ingested once."""
    share = tmp_path / "share"
    share.mkdir()
    (share / "a.hl7").write_bytes(ADT.encode("utf-8"))
    bare = _bare_digest(share, share / "a.hl7")
    await store.record_processed_file(channel_id="file_in", file_key=bare)
    runner = RegistryRunner(
        _leave_registry(share),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        await asyncio.sleep(0.3)  # many poll cycles
    finally:
        await runner.stop()
    assert await store.count_messages(channel_id="file_in", allowed_channels=None) == 0
    assert (share / "a.hl7").exists()


async def test_the_ledger_refuses_a_key_scheme_it_does_not_know(store: MessageStore) -> None:
    """A marker may only choose among the schemes compiled into the release. Mutation: drop the
    ``check_file_key`` calls from the runner's ledger adapter. Red: no error is raised."""
    from messagefoundry.pipeline.wiring_runner import _StoreProcessedLedger

    ledger = _StoreProcessedLedger(store, "ch")
    digest = "ab" * 32
    for unknown in (f"fk9:{digest}", f"sha3:{digest}", f":{digest}"):
        with pytest.raises(FileKeyError):
            await ledger.is_processed(unknown)
        with pytest.raises(FileKeyError):
            await ledger.mark_processed(unknown)
    with pytest.raises(FileKeyError):  # a tag this release knows, but not a digest it derived
        await ledger.is_processed("fk1:not-a-digest")
    with pytest.raises(FileKeyError):  # the bare pre-tag form reads, but is never written again
        await ledger.mark_processed(digest)
    assert not await ledger.is_processed(digest)
    await ledger.mark_processed(f"{FILE_KEY_SCHEME}:{digest}")
    assert await ledger.is_processed(f"{FILE_KEY_SCHEME}:{digest}")
    assert FILE_KEY_SCHEME in FILE_KEY_SCHEMES


def test_every_form_is_the_same_digest_and_todays_comes_first() -> None:
    digest = hashlib.sha256(b"a.hl7\x001\x002").hexdigest()
    forms = file_key_forms(digest)
    assert forms == (f"{FILE_KEY_SCHEME}:{digest}", digest)
    check_file_key(forms[0], write=True)
    check_file_key(forms[1], write=False)
