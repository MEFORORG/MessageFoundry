# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.3.4 — the PERSISTED per-key AES-GCM invocation bound.

Nonce generation was never the defect (a fresh 96-bit ``os.urandom`` per encrypt, one per DR frame). The
defect was the BOUND: the counter lived in ``AesGcmCipher.__init__`` and reset on every process start, so
across a deployment's lifetime the 2**32 ceiling was unreachable and the 2**31 warning could not fire.

What each group asserts:

* **arithmetic** — reserve-then-spend can only over-count, and the cumulative figure folds in other
  processes' reservations;
* **persistence** — the count survives a store reopen, and aggregates across independent store handles on
  the ONE unified store (the engine-shard / `[cluster]` topology, modelled here as concurrent handles on
  one SQLite file, which is the only backend a local run can actually exercise);
* **thresholds** — 2**31 warns through the AlertSink, 2**32 refuses;
* **rotation** — a new key_id starts at zero while the old key's row is retained, and no "zero the
  active key" operation exists;
* **the binding correction** — a DR backup run advances the SAME persisted per-key_id count, because the
  backup codec builds its own ``AESGCM`` from the raw DEK and would otherwise be invisible to the bound.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.pipeline.gcm_invocations import GcmInvocationRunner
from messagefoundry.store import MessageStore, crypto
from messagefoundry.store import backup_codec as bc
from messagefoundry.store.crypto import (
    _GCM_MAX_INVOCATIONS,
    _GCM_RESERVE_BLOCK,
    _GCM_SOFT_WARN_INVOCATIONS,
    AesGcmCipher,
    CipherError,
    IdentityCipher,
    generate_key,
    make_cipher,
)
from messagefoundry.store.gcm_bound import GCM_RESERVE_BLOCK, bounded_cipher, checkpoint_invocations

#: A synthetic placeholder body. enqueue_ingress stores the raw str verbatim (no parsing),
#: so no real-shaped HL7 - and no temptation toward real PHI - is needed in this suite.
_MSG = "synthetic-ingress-body-{i}"


def _cipher() -> AesGcmCipher:
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    return cipher


async def _keyed_store(path: Path, key: str | None = None) -> tuple[MessageStore, AesGcmCipher]:
    cipher = make_cipher(key or generate_key())
    assert isinstance(cipher, AesGcmCipher)
    store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    return store, cipher


# --- the accounting arithmetic ----------------------------------------------


def test_unbounded_cipher_keeps_the_pre_existing_process_local_behaviour() -> None:
    cipher = _cipher()
    assert cipher.invocation_bound_enabled is False
    cipher.encrypt("x")
    assert cipher.cumulative_invocations() == 1
    assert cipher.invocation_reserve_shortfall() == 0  # nothing to reserve without a store


def test_enabling_the_bound_asks_for_a_whole_block_up_front() -> None:
    cipher = _cipher()
    cipher.enable_invocation_bound()
    assert cipher.invocation_reserve_shortfall() == _GCM_RESERVE_BLOCK


def test_enabling_the_bound_carries_across_already_spent_invocations() -> None:
    # The on-open `_encrypt_existing_rows` migration encrypts BEFORE the bound is enabled; those
    # invocations must not be lost.
    cipher = _cipher()
    for _ in range(5):
        cipher.encrypt("x")
    cipher.enable_invocation_bound()
    assert cipher.cumulative_invocations() == 5
    assert cipher.invocation_reserve_shortfall() >= _GCM_RESERVE_BLOCK + 5


async def test_the_persisted_row_leads_actual_spend_on_a_live_store(tmp_path: Path) -> None:
    """The crash-safety property, read from the DURABLE row rather than asserted about a constant.

    What an unclean kill leaves behind is exactly ``cipher_meta.invocations``; if that figure ever
    trails what the key has actually encrypted, the ceiling is wrong in the unsafe direction."""
    store, cipher = await _keyed_store(tmp_path / "leads.db")
    try:
        for i in range(40):
            await store.enqueue_ingress(channel_id="c", raw=_MSG.format(i=i))
        spent = cipher.cumulative_invocations()
        assert spent > 0, "the writes must have spent invocations, or this proves nothing"
        persisted_if_killed_now = await store.cipher_invocations(cipher.active_key_id)
        assert persisted_if_killed_now >= spent
    finally:
        await store.close()


def test_refill_is_requested_only_once_half_a_block_is_spent() -> None:
    cipher = _cipher()
    cipher.enable_invocation_bound()
    cipher.grant_invocations(_GCM_RESERVE_BLOCK, _GCM_RESERVE_BLOCK)
    for _ in range(_GCM_RESERVE_BLOCK // 2 - 1):
        cipher.encrypt("x")
    assert cipher.invocation_reserve_shortfall() == 0  # still healthy: no DB write on the hot path
    cipher.encrypt("x")
    assert (
        cipher.invocation_reserve_shortfall() == _GCM_RESERVE_BLOCK
    )  # rounded UP to a whole block


def test_overspend_still_counts_and_is_settled_exactly() -> None:
    cipher = _cipher()
    cipher.enable_invocation_bound()
    cipher.grant_invocations(10, 10)  # a deliberately tiny grant
    for _ in range(25):
        cipher.encrypt("x")
    # Counting never stalls at the reservation — the overspend is added in, so the ceiling still fires.
    assert cipher.cumulative_invocations() == 25
    assert cipher.invocation_settlement() == 15


def test_an_unspent_reserve_is_refunded_by_the_settlement() -> None:
    # Forfeiting the block on every clean close does not survive arithmetic: ~2**16 opens would exhaust
    # the key on paper, and a crash-looping service under NSSM auto-restart (~8.6k opens/day) would reach
    # the fail-closed ceiling in about a week with no cryptographic cause. A CLEAN settlement writes the
    # exact figure; only an unclean exit (which never settles) still forfeits its block.
    cipher = _cipher()
    cipher.enable_invocation_bound()
    cipher.grant_invocations(_GCM_RESERVE_BLOCK, _GCM_RESERVE_BLOCK)
    for _ in range(3):
        cipher.encrypt("x")
    assert cipher.invocation_settlement() == -(_GCM_RESERVE_BLOCK - 3)
    # Applying the settlement squares the persisted total with the 3 actually spent...
    cipher.grant_invocations(cipher.invocation_settlement(), 3)
    assert cipher.cumulative_invocations() == 3
    assert cipher.invocation_settlement() == 0  # ...and a second settle is a no-op


def test_cumulative_figure_folds_in_other_processes_reservations() -> None:
    cipher = _cipher()
    cipher.enable_invocation_bound()
    # Our block is 2**16 but the key's persisted total is 5 blocks: four siblings reserved too.
    cipher.grant_invocations(_GCM_RESERVE_BLOCK, 5 * _GCM_RESERVE_BLOCK)
    cipher.encrypt("x")
    # Biased HIGH: a sibling's unspent reserve is charged as consumed. The bound may fire early, never
    # late — the only safe direction.
    assert cipher.cumulative_invocations() == 4 * _GCM_RESERVE_BLOCK + 1


def test_bounded_cipher_excludes_identity_and_non_local_ciphers() -> None:
    assert bounded_cipher(IdentityCipher()) is None
    assert bounded_cipher(None) is None
    assert bounded_cipher(_cipher()) is not None


# --- thresholds --------------------------------------------------------------


def test_soft_warn_and_fail_closed_fire_on_the_CUMULATIVE_total(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cipher = _cipher()
    cipher.enable_invocation_bound()
    # A restart-surviving total just below the soft threshold, with nothing spent in THIS process — the
    # exact case the old per-process counter could never reach.
    cipher.grant_invocations(
        _GCM_RESERVE_BLOCK, _GCM_SOFT_WARN_INVOCATIONS + _GCM_RESERVE_BLOCK - 1
    )
    assert cipher.cumulative_invocations() == _GCM_SOFT_WARN_INVOCATIONS - 1
    with caplog.at_level("WARNING"):
        cipher.encrypt("x")
    assert any("2**31" in r.message for r in caplog.records)

    cipher.grant_invocations(0, _GCM_MAX_INVOCATIONS + _GCM_RESERVE_BLOCK - 2)
    with pytest.raises(CipherError, match="cumulative for this key"):
        cipher.encrypt("y")


# --- persistence + multi-process aggregation ---------------------------------


async def test_count_survives_a_store_reopen(tmp_path: Path) -> None:
    key = generate_key()
    db = tmp_path / "bound.db"

    store, cipher = await _keyed_store(db, key)
    try:
        assert cipher.invocation_bound_enabled, (
            "open() must enable + reserve before the first write"
        )
        for i in range(5):
            await store.enqueue_ingress(channel_id="c", raw=_MSG.format(i=i))
        reserved = await store.cipher_invocations(cipher.active_key_id)
        assert reserved >= GCM_RESERVE_BLOCK  # a whole block was reserved AHEAD of the writes
        spent = cipher.cumulative_invocations()
        assert 0 < spent < GCM_RESERVE_BLOCK
    finally:
        await store.close()

    # A KEYLESS handle reads the row without reserving anything of its own — the only way to observe
    # what the closed process actually left behind.
    plain = await MessageStore.open(db)
    try:
        assert await plain.cipher_invocations(cipher.active_key_id) == spent, (
            "a CLEAN close must settle to the exact spend — neither losing the overspend nor "
            "permanently burning the unspent remainder of the reserved block"
        )
    finally:
        await plain.close()

    store2, cipher2 = await _keyed_store(db, key)
    try:
        assert cipher2.active_key_id == cipher.active_key_id  # same DEK → same key_id row
        # THE requirement: the new process starts from the KEY's surviving lifetime figure, not zero.
        assert cipher2.cumulative_invocations() == spent
        await store2.enqueue_ingress(channel_id="c", raw=_MSG.format(i=99))
        assert cipher2.cumulative_invocations() > spent
    finally:
        await store2.close()


async def test_independent_store_handles_aggregate_onto_one_row(tmp_path: Path) -> None:
    # The engine-shard / [cluster] topology: N processes, ONE unified store. Modelled as two concurrent
    # store handles on one file — the atomic add IS the aggregation, so the row is shared.
    key = generate_key()
    db = tmp_path / "shards.db"
    a, ca = await _keyed_store(db, key)
    b, cb = await _keyed_store(db, key)
    try:
        assert ca.active_key_id == cb.active_key_id
        total = await a.cipher_invocations(ca.active_key_id)
        # Two independent handles each reserved their own block against the SAME key_id row.
        assert total >= 2 * GCM_RESERVE_BLOCK
        await b.add_cipher_invocations(cb.active_key_id, 7)
        assert await a.cipher_invocations(ca.active_key_id) == total + 7
    finally:
        await a.close()
        await b.close()


async def test_close_settles_the_overspend(tmp_path: Path) -> None:
    key = generate_key()
    db = tmp_path / "settle.db"
    store, cipher = await _keyed_store(db, key)
    before = await store.cipher_invocations(cipher.active_key_id)
    # Simulate a burst that outran the refill cadence (rotate-key's shape).
    cipher.grant_invocations(-cipher._reserve_remaining, before)  # zero the reserve
    for _ in range(11):
        cipher.encrypt("x")
    assert cipher.invocation_settlement() == 11
    await store.close()

    reader, _ = await _keyed_store(db, key)
    try:
        assert await reader.cipher_invocations(cipher.active_key_id) >= before + 11
    finally:
        await reader.close()


async def test_the_at_rest_migration_burst_is_charged_PER_BATCH_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enabling a key on an existing plaintext store is itself a large encrypt burst (one per stored
    value). It runs on open, so the bound must be enabled + reserved AHEAD of it and topped up per batch
    — otherwise a kill during the migration under-counts everything it already encrypted."""
    db = tmp_path / "migrate.db"
    plain = await MessageStore.open(db)  # keyless: rows land as plaintext
    for i in range(30):
        await plain.enqueue_ingress(channel_id="c", raw=_MSG.format(i=i))
    await plain.close()

    monkeypatch.setattr(crypto, "_GCM_RESERVE_BLOCK", 8)
    monkeypatch.setattr(crypto, "_GCM_RESERVE_REFILL_AT", 4)
    keyed, cipher = await _keyed_store(db)  # open() runs _encrypt_existing_rows
    try:
        spent = cipher.cumulative_invocations()
        assert spent > 8, "the migration must outrun a single reserved block, or nothing is proven"
        persisted = await keyed.cipher_invocations(cipher.active_key_id)
        assert persisted >= spent
    finally:
        await keyed.close()


async def test_keyless_store_has_no_bound_and_writes_no_meta_row(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert await store.checkpoint_cipher_invocations() is None
        assert await store.cipher_invocations("anything") == 0
    finally:
        await store.close()


# --- rotation ----------------------------------------------------------------


async def test_rotating_to_a_new_key_starts_at_zero_and_keeps_the_old_row(tmp_path: Path) -> None:
    db = tmp_path / "rotate.db"
    old_key = generate_key()
    store, old_cipher = await _keyed_store(db, old_key)
    for i in range(6):
        await store.enqueue_ingress(channel_id="c", raw=_MSG.format(i=i))
    await store.close()

    # Rotate: a NEW active key (the old one stays decrypt-only), i.e. a NEW one-way key_id.
    new_key = generate_key()
    new_cipher = make_cipher(new_key, [old_key])
    assert isinstance(new_cipher, AesGcmCipher)
    rotated = await MessageStore.open(
        db, cipher=new_cipher, audit_mac_key=new_cipher.audit_mac_key()
    )
    try:
        assert new_cipher.active_key_id != old_cipher.active_key_id
        old_total = await rotated.cipher_invocations(old_cipher.active_key_id)
        assert old_total > 0, "the retired key's accumulated count must be RETAINED"
        # The new key's own consumption starts from its own fresh row — that IS the reset.
        assert new_cipher.cumulative_invocations() == 0
        before_burst = new_cipher.cumulative_invocations()
        rewritten = await rotated.reencrypt_to_active()
        assert rewritten > 0, "nothing was re-encrypted — the burst assertions below prove nothing"
        # The burst itself is counted, not merely covered by the open-time block reservation.
        assert new_cipher.cumulative_invocations() - before_burst >= rewritten
    finally:
        await rotated.close()

    plain = await MessageStore.open(db)  # keyless: observes the rows without reserving
    try:
        # Rotation's re-encrypt burst is charged to the NEW key, durably...
        assert await plain.cipher_invocations(new_cipher.active_key_id) >= rewritten
        # ...and never to the old one, whose row is left exactly as it was.
        assert await plain.cipher_invocations(old_cipher.active_key_id) == old_total
    finally:
        await plain.close()


async def test_a_rotation_burst_is_charged_PER_BATCH_not_only_at_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kill mid-rotation must not permanently under-count what was already re-encrypted.

    ``reencrypt_to_active`` is the single largest encrypt burst in the product and it runs inside the
    store's write lock; charging it only at ``close()`` means an unclean exit loses every invocation the
    burst had already performed (a re-run only re-encrypts what is still left). The reserve block is
    shrunk here so a small store outruns one block exactly the way a real store outruns 2**16."""
    monkeypatch.setattr(crypto, "_GCM_RESERVE_BLOCK", 8)
    monkeypatch.setattr(crypto, "_GCM_RESERVE_REFILL_AT", 4)
    db = tmp_path / "burst.db"
    old_key = generate_key()
    store, _old = await _keyed_store(db, old_key)
    for i in range(30):
        await store.enqueue_ingress(channel_id="c", raw=_MSG.format(i=i))
    await store.close()

    new_key = generate_key()
    new_cipher = make_cipher(new_key, [old_key])
    assert isinstance(new_cipher, AesGcmCipher)
    rotated = await MessageStore.open(
        db, cipher=new_cipher, audit_mac_key=new_cipher.audit_mac_key()
    )
    try:
        rewritten = await rotated.reencrypt_to_active()
        assert rewritten > 8, "the burst must outrun a single reserved block, or nothing is proven"
        # WITHOUT closing: this is what a `kill -9` mid-rotation would leave behind.
        persisted = await rotated.cipher_invocations(new_cipher.active_key_id)
        assert persisted >= new_cipher.cumulative_invocations(), (
            "the durable count trails the burst — a crash here loses every re-encrypt already done"
        )
    finally:
        await rotated.close()


def test_every_batched_encrypt_burst_charges_the_bound_on_every_backend() -> None:
    """OMISSION GUARD — the class of defect, not one instance of it.

    Any batch loop that encrypts (a rotation pass, an at-rest migration pass) must charge the bound
    per committed batch; one that does not silently reintroduces the mid-burst under-count on whichever
    backend it was added to. Enumerated from the source so a NEW pass — or a fourth backend — has to
    opt in deliberately rather than by being forgotten."""
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    checked: list[str] = []
    for cls in (MessageStore, PostgresStore, SqlServerStore):
        for name, fn in vars(cls).items():
            if not inspect.isfunction(fn):
                continue
            try:
                src = inspect.getsource(fn)
            except OSError:  # pragma: no cover — source is always available in-tree
                continue
            encrypts = ".encrypt(" in src or "_reencrypt_value(" in src
            if "while True" not in src or not encrypts:
                continue
            checked.append(f"{cls.__name__}.{name}")
            assert "_charge_bound_batch()" in src, (
                f"{cls.__name__}.{name} loops over batches of encrypts without charging the AES-GCM "
                "invocation bound (ASVS 11.3.4) — an unclean exit mid-burst would permanently "
                "under-count every value it had already encrypted"
            )
    # The enumeration itself must not silently go empty (a rename would make the guard vacuous).
    assert len(checked) >= 20, checked


def test_no_operation_zeroes_an_existing_keys_counter() -> None:
    # A "reset the active key's counter" verb would let an operator refresh the birthday budget of a key
    # they never changed. The only reset is a new key_id, so no such API may exist.
    from messagefoundry.store import base

    forbidden = {"reset_cipher_invocations", "clear_cipher_invocations", "zero_cipher_invocations"}
    assert forbidden.isdisjoint(dir(MessageStore))
    assert forbidden.isdisjoint(dir(base.Store))


# --- the binding correction: DR backup frames charge the SAME bound ----------


def test_encrypt_stream_reports_one_invocation_per_frame() -> None:
    frames: list[int] = []
    key = base64.b64decode(generate_key())
    payload = b"z" * 5000
    bc.encrypt_stream(
        io.BytesIO(payload), io.BytesIO(), key, chunk_size=1024, on_frames=frames.append
    )
    # 5000 bytes at 1 KiB chunks = 4 full frames + a 904-byte final frame.
    assert frames == [5]

    frames.clear()
    bc.encrypt_stream(io.BytesIO(b""), io.BytesIO(), key, on_frames=frames.append)
    assert frames == [1]  # an empty source still emits exactly one (final, empty) frame


def test_a_backup_that_dies_part_way_still_reports_what_it_spent() -> None:
    """A failed run has still SPENT the invocations it already made.

    Reporting only on success charges zero for them, leaving the key's persisted bound trailing what
    the DEK actually encrypted — the same under-count, in the same direction, that counting only the
    store cipher would produce. A full disk mid-archive is the ordinary way this happens.
    """

    class _DiesAfter(io.BytesIO):
        def __init__(self, after: int) -> None:
            super().__init__()
            self._left = after

        def write(self, b: Any) -> int:  # type: ignore[override]
            if self._left <= 0:
                raise OSError(28, "No space left on device")
            self._left -= 1
            return super().write(b)

    frames: list[int] = []
    key = base64.b64decode(generate_key())
    # 5 KiB at 1 KiB frames = 5 frames; each writes header/nonce/len/ct, so this dies mid-archive.
    with pytest.raises(OSError):
        bc.encrypt_stream(
            io.BytesIO(b"z" * 5000),
            _DiesAfter(9),
            key,
            chunk_size=1024,
            on_frames=frames.append,
        )
    assert frames, "the aborted run charged nothing for the frames it had already encrypted"
    assert 0 < frames[0] < 5, f"expected a partial count, got {frames}"


async def test_the_archive_key_id_is_the_stores_own_key_id(tmp_path: Path) -> None:
    """The frames must land on the SAME row the store cipher charges — the archive is encrypted under
    the store DEK, and the codec fingerprints it the same one-way way.

    (That a real run actually charges them is asserted end-to-end through the BackupRunner in
    ``tests/test_backup_runner.py::test_a_real_backup_run_advances_the_persisted_invocation_count`` —
    doing the aggregate add by hand here would assert only this test's own arithmetic.)"""
    key = generate_key()
    store, cipher = await _keyed_store(tmp_path / "dr.db", key)
    try:
        assert bc.key_fingerprint(base64.b64decode(key)) == cipher.active_key_id
    finally:
        await store.close()


# --- the engine-side runner ---------------------------------------------------


class _RecordingSink:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def gcm_invocations(self, name: str, *, key_id: str, invocations: int, ceiling: int) -> None:
        self.calls.append(
            {"name": name, "key_id": key_id, "invocations": invocations, "ceiling": ceiling}
        )


async def test_runner_checkpoints_and_stays_quiet_below_the_threshold(tmp_path: Path) -> None:
    store, cipher = await _keyed_store(tmp_path / "runner.db", generate_key())
    try:
        sink = _RecordingSink()
        runner = GcmInvocationRunner(store, alert_sink=sink)  # type: ignore[arg-type]
        total = await runner.run_once()
        assert total is not None and total >= 0
        assert sink.calls == []
    finally:
        await store.close()


async def test_runner_alerts_once_over_the_soft_threshold(tmp_path: Path) -> None:
    store, cipher = await _keyed_store(tmp_path / "runner_warn.db", generate_key())
    try:
        sink = _RecordingSink()
        runner = GcmInvocationRunner(store, alert_sink=sink, warn_at=4, ceiling=64)  # type: ignore[arg-type]
        assert await runner.run_once() is not None
        for _ in range(10):
            cipher.encrypt("x")
        total = await runner.run_once()
        assert total is not None and total >= 4
        assert len(sink.calls) == 1
        call = sink.calls[0]
        assert call["key_id"] == cipher.active_key_id  # a one-way fingerprint, never key bytes
        assert call["ceiling"] == 64
    finally:
        await store.close()


async def test_runner_refills_ON_DEMAND_without_waiting_out_the_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fixed poll alone loses the reserve-leads-spend guarantee above ``block / interval`` encrypts
    per second: the reserve goes persistently negative between passes and an unclean exit under-counts.
    Crossing the watermark must therefore WAKE the runner, not wait for it."""
    monkeypatch.setattr(crypto, "_GCM_RESERVE_BLOCK", 8)
    monkeypatch.setattr(crypto, "_GCM_RESERVE_REFILL_AT", 4)
    store, cipher = await _keyed_store(tmp_path / "demand.db")
    # An interval long enough that a poll-driven refill could not possibly be what we observe.
    runner = GcmInvocationRunner(store, alert_sink=_RecordingSink(), interval_seconds=600.0)  # type: ignore[arg-type]
    runner.start()
    try:
        await asyncio.sleep(0)  # let the first (no-op) pass run
        before = await store.cipher_invocations(cipher.active_key_id)
        for _ in range(6):  # cross the half-block watermark
            cipher.encrypt("x")
        deadline = time.monotonic() + 5.0
        grew = False
        while time.monotonic() < deadline:
            await asyncio.sleep(0.01)
            if await store.cipher_invocations(cipher.active_key_id) > before:
                grew = True
                break
        assert grew, "the reserve was not topped up until the poll interval elapsed"
    finally:
        await runner.stop()
        await store.close()


async def test_runner_is_a_noop_on_a_keyless_store(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "runner_plain.db")
    try:
        sink = _RecordingSink()
        runner = GcmInvocationRunner(store, alert_sink=sink, warn_at=0)  # type: ignore[arg-type]
        assert await runner.run_once() is None
        assert sink.calls == []  # warn_at=0 would fire on ANY total; None must short-circuit first
    finally:
        await store.close()


async def test_checkpoint_never_raises_when_the_store_write_fails() -> None:
    # A transient DB blip must not take the engine down; the in-process ceiling still applies.
    cipher = _cipher()

    async def _boom(_key_id: str, _count: int) -> int:
        raise RuntimeError("db is down")

    total = await checkpoint_invocations(cipher, _boom)
    assert total == 0
    cipher.encrypt("x")
    assert await checkpoint_invocations(cipher, _boom) == 1


# --- the OTHER writer under the same DEK: uploaded logs (ADR 0134) -----------


async def test_uploaded_logs_encrypts_charge_the_SAME_persisted_bound(tmp_path: Path) -> None:
    """The uploaded-logs store (ADR 0134) encrypts under the SAME store DEK. Built from its own
    ``build_store_cipher`` instance it charged nothing to the key's persisted row and never saw the
    fleet cumulative — so it would keep encrypting under a key the store's cipher had already
    fail-closed on at 2**32. It must share the LIVE instance."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app
    from messagefoundry.pipeline import Engine

    store, cipher = await _keyed_store(tmp_path / "uploads.db")
    try:
        app = create_app(
            Engine(store),
            store_settings=StoreSettings(
                uploads_dir=str(tmp_path / "up"), max_upload_bytes=1_000_000
            ),
            allow_no_auth=True,
        )
        uploads = app.state.upload_store
        assert uploads is not None
        assert uploads._cipher is store.cipher(), "a SECOND cipher over the same DEK is the defect"
        before = cipher.cumulative_invocations()
        await uploads.save(
            data=b"MSH|test synthetic log",  # valid HL7 head: 5.2.2 sniff requires MSH/FHS/BHS
            filename="up.hl7",
            uploader="tester",
            uploader_id="u-tester",
        )
        # One encrypt for the blob, one for the metadata — both on the key's budget.
        assert cipher.cumulative_invocations() >= before + 2
        await store.checkpoint_cipher_invocations(settle=True)
        assert (
            await store.cipher_invocations(cipher.active_key_id) == cipher.cumulative_invocations()
        )
    finally:
        await store.close()


def test_managed_serve_binds_uploaded_logs_to_the_LIVE_store_cipher(tmp_path: Path) -> None:
    # The shipping path: `serve` builds the store, then the app. The uploads store must be handed that
    # store's cipher instance (the one carrying the enabled bound), not a fresh build_store_cipher.
    pytest.importorskip("psutil")
    from fastapi.testclient import TestClient

    from messagefoundry.api import create_managed_app

    settings = StoreSettings(
        path=str(tmp_path / "managed.db"),
        encryption_key=generate_key(),
        uploads_dir=str(tmp_path / "managed-uploads"),
    )
    app = create_managed_app(store_settings=settings, poll_interval=0.05)
    with TestClient(app):  # drives the lifespan (opens the store, starts the engine)
        uploads = app.state.upload_store
        assert uploads is not None, "[store].uploads_dir was set — the subsystem must be wired"
        live = app.state.engine.store.cipher()
        assert uploads._cipher is live
        assert live.invocation_bound_enabled


def test_managed_serve_threads_upload_quotas_and_retention(tmp_path: Path) -> None:
    # ASVS 5.2.4 regression: the serve-path lifespan rebuild of the upload store (needed to share the
    # store cipher) must carry the operator's per-user quota + retention values, not silently fall back
    # to the UploadStore 100/250 MiB/30 d defaults. A non-default [store] config must reach the store.
    pytest.importorskip("psutil")
    from fastapi.testclient import TestClient

    from messagefoundry.api import create_managed_app

    settings = StoreSettings(
        path=str(tmp_path / "quota.db"),
        encryption_key=generate_key(),
        uploads_dir=str(tmp_path / "quota-uploads"),
        max_upload_files_per_user=7,
        max_upload_total_bytes_per_user=123_456,
        uploads_retention_days=3,
    )
    app = create_managed_app(store_settings=settings, poll_interval=0.05)
    with TestClient(app):
        us = app.state.upload_store
        assert us is not None
        assert us._max_files_per_user == 7
        assert us._max_total_bytes_per_user == 123_456
        assert us._retention_days == 3


def test_gcm_invocations_is_a_routable_alert_event_type() -> None:
    # Without the _ALERT_EVENT_TYPES member, a legitimate operator [[alerts.rules]] targeting this
    # event fails config validation — the alert would ship unroutable.
    from messagefoundry.config.settings import AlertRule

    assert AlertRule(event_type="gcm_invocations").event_type == "gcm_invocations"


def test_the_bound_is_settled_only_AFTER_the_message_graph_has_quiesced() -> None:
    """``Engine.stop()`` must stop the GCM runner AFTER the registry runner, never before.

    ``GcmInvocationRunner.stop()`` SETTLES: it writes back this process's unspent remainder and unhooks
    the refill signal. Every encrypt performed after that point is charged against no reservation, with
    no checkpointer left to refill one — so an early settle silently under-counts the whole shutdown
    drain, which is exactly the "the durable figure trails what the key actually encrypted" defect the
    persisted bound exists to remove. The registry runner is what drives those encrypts.

    Asserted on statement order because the fault IS an ordering one: a behavioural test would have to
    stand up a whole engine, drain it, and still would not say why it broke.
    """
    import ast
    import textwrap

    from messagefoundry.pipeline import engine as engine_mod

    tree = ast.parse(textwrap.dedent(inspect.getsource(engine_mod.Engine.stop)))

    def first_line(attr: str) -> int:
        lines = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == attr
        ]
        assert lines, f"Engine.stop() no longer touches self.{attr} — this guard needs updating"
        return min(lines)

    assert first_line("_gcm_invocation_runner") > first_line("_registry_runner"), (
        "Engine.stop() settles the AES-GCM invocation bound before the registry runner has quiesced, "
        "so every encrypt performed during the shutdown drain is unreserved and uncheckpointed. Move "
        "the _gcm_invocation_runner.stop() block to AFTER `await self._registry_runner.stop()`."
    )
