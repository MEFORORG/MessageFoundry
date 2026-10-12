# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A keyed store refuses an unmarked value in a cipher column (BACKLOG #1169, ASVS 11.3.3).

**The gap.** The cipher's read seam returned any value without an ``mfenc:`` marker unchanged, as
"legacy plaintext or a purged blank". So a stripped marker or a planted plaintext row read back as that
row's content, and the next ``rotate-key`` sealed it into genuine ciphertext. Substitution has a tag to
fail; a downgrade to plaintext has none, so only a refusal protects it.

**What each test pins.**

* A sealed surface -- one (table, column) that already holds ciphertext -- refuses an unmarked value
  and raises the ``store-cipher`` alert, which names the table and column and nothing else.
* An unsealed surface still has its legacy plaintext sealed at a keyed open.
* NULL and a purged ``''`` are never sealed and never refused.
* A keyless store is unchanged.
* ``[store].allow_unmarked_ciphertext`` restores the passthrough and the seal-everything sweep.
* The uploaded-file store's own refusal (owner ruling 2026-09-23) is pinned in
  ``tests/test_uploads_strict_ciphertext.py``.
* A crash part-way through a first keyed open leaves the surface all sealed or all unsealed, and the
  AES-GCM invocation bound (ASVS 11.3.4) still leads every encrypt of the one-transaction seal.
* The persisted ``keyed_surface`` marker (BACKLOG #3383, owner ruling 2026-10-10): once a keyed open
  has visited a surface, a plaintext value planted there later is refused, even when the surface held
  no ciphertext -- a column never written, or one every purge has blanked. Legacy plaintext is still
  sealed once, at the first keyed open, in the same transaction as its marker.

SQLite only. The server-backend runtime twins live in ``tests/test_postgres_store.py`` and
``tests/test_sqlserver_store.py`` and run only on the hosted ``postgres-store`` / ``sqlserver-store``
legs.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import (
    ApiSettings,
    ApprovalsSettings,
    BackupSettings,
    CertMonitorSettings,
    EgressSettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.pipeline.engine import Engine
from messagefoundry.store import MessageStore
from messagefoundry.store import crypto as crypto_mod
from messagefoundry.store.base import build_store_cipher
from messagefoundry.store.crypto import (
    MARKER_PREFIX,
    AesGcmCipher,
    CipherError,
    aad_cell_name,
    cell_aad,
    generate_key,
    make_cipher,
)

_RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG{i}|P|2.5.1\rPID|1||{i}^^^H^MR||DOE^JANE\r"
_PLANT = "MSH|^~\\&|EVIL|F|R|RF|20260101||ADT^A01|PLANTED|P|2.5.1\rPID|1||666^^^H^MR||ROE^RICH\r"


def _keyed(key: str, **kw: Any) -> AesGcmCipher:
    cipher = make_cipher(key, **kw)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


async def _seed(db: Path, n: int, cipher: AesGcmCipher | None = None) -> list[str]:
    """Open the store (keyless unless ``cipher``), write ``n`` ingress messages, return their ids."""
    store = await MessageStore.open(db, cipher=cipher)
    try:
        return [await store.enqueue_ingress(channel_id="c", raw=_RAW.format(i=i)) for i in range(n)]
    finally:
        await store.close()


def _raw_at_rest(db: Path, mid: str) -> str | None:
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT raw FROM messages WHERE id=?", (mid,)).fetchone()
    return None if row is None else row[0]


def _set_raw(db: Path, mid: str, value: str) -> None:
    _set_cell(db, "raw", mid, value)


def _set_cell(db: Path, column: str, mid: str, value: str | None) -> None:
    """Write ``messages.<column>`` for one row behind the store's back -- a plant, or a purge."""
    conn = sqlite3.connect(db)
    try:
        conn.execute(f"UPDATE messages SET {column}=? WHERE id=?", (value, mid))
        conn.commit()
    finally:
        conn.close()


def _cell_at_rest(db: Path, column: str, mid: str) -> str | None:
    with sqlite3.connect(db) as conn:
        row = conn.execute(f"SELECT {column} FROM messages WHERE id=?", (mid,)).fetchone()
    return None if row is None else row[0]


def _keyed_surfaces(db: Path) -> set[tuple[str, str]]:
    """The persisted ``keyed_surface`` markers (BACKLOG #3383), read behind the store's back."""
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT surface_table, surface_column FROM keyed_surface").fetchall()
    return {(str(t), str(c)) for t, c in rows}


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.events.append((name, reason, drift_count))


# --- the refusal ---------------------------------------------------------------------------------


async def test_unmarked_value_on_a_sealed_surface_is_refused_and_alerts(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db = tmp_path / "sealed.db"
    key = generate_key()
    good, planted = await _seed(db, 2, _keyed(key))
    assert (_raw_at_rest(db, planted) or "").startswith(MARKER_PREFIX)  # the surface IS sealed
    _set_raw(db, planted, _PLANT)  # a stripped marker / planted plaintext row

    cipher = _keyed(key)
    with caplog.at_level(logging.WARNING):
        store = await MessageStore.open(db, cipher=cipher)
    try:
        # The keyed open did NOT seal the plant: sealing would launder it into genuine ciphertext.
        assert _raw_at_rest(db, planted) == _PLANT
        assert "messages.raw is sealed and holds 1 unmarked value(s)" in caplog.text

        sink = _Sink()
        engine = Engine(
            store,
            alert_sink=sink,  # type: ignore[arg-type]
            egress_settings=EgressSettings(deny_by_default=False),
        )
        engine._arm_cipher_refusal_alert()
        try:
            assert (await store.get_message(good) or {})["raw"] == _RAW.format(i=0)
            with pytest.raises(CipherError, match=r"messages\.raw"):
                await store.get_message(planted)
            await asyncio.sleep(0)  # the hook hops onto the loop with call_soon_threadsafe
            await asyncio.sleep(0)
        finally:
            engine._disarm_cipher_refusal_alert()
        assert len(sink.events) == 1, sink.events
        subject, reason, count = sink.events[0]
        assert (subject, count) == ("store-cipher", 1)
        assert "messages.raw" in reason
        # Names the cell, never the row or the value: no row key, no PHI.
        assert planted not in reason and "ROE" not in reason and "666" not in reason
        # Disarmed: a later refusal reaches no sink.
        with pytest.raises(CipherError):
            await store.get_message(planted)
        await asyncio.sleep(0)
        assert len(sink.events) == 1
    finally:
        await store.close()


def test_the_refusal_hook_gets_the_cell_from_the_aad_and_never_the_row() -> None:
    cipher = _keyed(generate_key())
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    with pytest.raises(CipherError, match=r"queue\.payload"):
        cipher.decrypt("plain", aad=cell_aad("queue", "payload", 42))
    assert seen == [("queue", "payload")]
    assert aad_cell_name(cell_aad("state", "value", "ns", "PATIENT-KEY")) == ("state", "value")
    assert aad_cell_name(None) == ("?", "?")
    assert aad_cell_name(b"garbage") == ("?", "?")


# --- sealing an unsealed surface -----------------------------------------------------------------


async def test_legacy_plaintext_on_an_unsealed_surface_is_sealed(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    ids = await _seed(db, 3)
    assert all(not (_raw_at_rest(db, m) or "").startswith(MARKER_PREFIX) for m in ids)

    store = await MessageStore.open(db, cipher=_keyed(generate_key()))
    try:
        for i, mid in enumerate(ids):
            at_rest = _raw_at_rest(db, mid) or ""
            # '^' is outside the base64 alphabet, so this fails only on real plaintext (the rule in
            # tests/test_store_encryption.py); a bare "DOE" turns up in random ciphertext by chance.
            assert at_rest.startswith(MARKER_PREFIX) and "DOE^JANE" not in at_rest
            assert (await store.get_message(mid) or {})["raw"] == _RAW.format(i=i)
    finally:
        await store.close()


async def test_blank_and_null_values_are_untouched(tmp_path: Path) -> None:
    db = tmp_path / "blank.db"
    purged, _other = await _seed(db, 2)
    _set_raw(db, purged, "")  # what every purge path writes
    key = generate_key()

    store = await MessageStore.open(db, cipher=_keyed(key))
    try:
        assert _raw_at_rest(db, purged) == ""  # not sealed into ciphertext-of-empty
        record = await store.get_message(purged) or {}
        assert record["raw"] == "" and record["summary"] is None  # neither refused
    finally:
        await store.close()
    # And on a surface that is now SEALED, a blank still reads without a refusal.
    store = await MessageStore.open(db, cipher=_keyed(key))
    try:
        assert (await store.get_message(purged) or {})["raw"] == ""
    finally:
        await store.close()


async def test_a_keyless_store_is_unchanged(tmp_path: Path) -> None:
    db = tmp_path / "keyless.db"
    (mid,) = await _seed(db, 1)
    _set_raw(db, mid, _PLANT)
    store = await MessageStore.open(db)
    try:
        assert (await store.get_message(mid) or {})["raw"] == _PLANT
        assert _raw_at_rest(db, mid) == _PLANT
    finally:
        await store.close()


# --- the opt-out ---------------------------------------------------------------------------------


async def test_the_opt_out_restores_passthrough_and_the_seal_everything_sweep(
    tmp_path: Path,
) -> None:
    db = tmp_path / "optout.db"
    key = generate_key()
    _good, planted = await _seed(db, 2, _keyed(key))
    _set_raw(db, planted, _PLANT)

    cipher = build_store_cipher(StoreSettings(encryption_key=key, allow_unmarked_ciphertext=True))
    assert isinstance(cipher, AesGcmCipher) and cipher.allow_unmarked
    assert cipher.decrypt("unmarked") == "unmarked"
    store = await MessageStore.open(db, cipher=cipher)
    try:
        # The old sweep: every unmarked value is sealed, even beside ciphertext.
        assert (_raw_at_rest(db, planted) or "").startswith(MARKER_PREFIX)
        assert (await store.get_message(planted) or {})["raw"] == _PLANT
    finally:
        await store.close()


def test_the_setting_ships_off_and_on_is_a_named_loosening() -> None:
    from messagefoundry.config.settings import (
        AlertsSettings,
        AuthSettings,
        SecretRotationSettings,
        SecuritySettings,
    )

    assert StoreSettings().allow_unmarked_ciphertext is False
    shipped = build_store_cipher(StoreSettings(encryption_key=generate_key()))
    assert isinstance(shipped, AesGcmCipher) and not shipped.allow_unmarked

    def names(store: StoreSettings) -> dict[str, str]:
        return dict(
            security_loosenings(
                SecuritySettings(),
                store,
                AuthSettings(),
                AlertsSettings(),
                SecretRotationSettings(),
                cleartext_hops=(),
                expiry_relaxed_hops=(),
                hostname_unchecked_hops=(),
                query_credential_hops=(),
                unverified_db_hops=(),
                attested_hops=(),
                revocation_attested_hops=(),
                path_form_fhir_hops=(),
                api=ApiSettings(),
                approvals=ApprovalsSettings(),
                cert_monitor=CertMonitorSettings(),
                backup=BackupSettings(),
                store_privilege=None,
                audit_chain_unkeyed=None,
                remote_debug=None,
                startup=None,
                service_env=None,
            )
        )

    assert "allow_unmarked_ciphertext" not in names(StoreSettings())
    risk = names(StoreSettings(allow_unmarked_ciphertext=True))["allow_unmarked_ciphertext"]
    assert "no effect without a store key" in risk


# --- crash safety and the 11.3.4 bound -----------------------------------------------------------


async def test_a_crash_mid_seal_leaves_the_surface_all_unsealed(tmp_path: Path) -> None:
    """600 legacy rows span two of the sweep's 500-row batches, and the simulated crash lands in the
    second. Committing per batch -- the pre-#1169 sweep -- leaves 500 sealed and 100 not, and option A
    would then refuse those 100 legitimate rows forever."""
    db = tmp_path / "crash.db"
    ids = await _seed(db, 600)
    key = generate_key()

    cipher = _keyed(key)
    real_encrypt = cipher.encrypt
    calls = 0

    def dies_part_way(plaintext: str, *, aad: bytes | None = None) -> str:
        nonlocal calls
        calls += 1
        if calls > 550:
            raise RuntimeError("simulated crash mid-seal")
        return real_encrypt(plaintext, aad=aad)

    cipher.encrypt = dies_part_way  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated crash"):
        await MessageStore.open(db, cipher=cipher)
    with sqlite3.connect(db) as conn:
        (marked,) = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE raw LIKE ?", (f"{MARKER_PREFIX}%",)
        ).fetchone()
    assert marked == 0, f"{marked} of 600 rows committed sealed: the surface is half-sealed"
    # The marker rolled back with the seal (BACKLOG #3383): a marker that survived the crash would
    # make the next open refuse the 600 legitimate legacy rows instead of sealing them.
    assert ("messages", "raw") not in _keyed_surfaces(db)

    healthy = _keyed(key)
    store = await MessageStore.open(db, cipher=healthy)
    try:
        assert ("messages", "raw") in _keyed_surfaces(db)
        assert all((_raw_at_rest(db, m) or "").startswith(MARKER_PREFIX) for m in ids)
        assert (await store.get_message(ids[0]) or {})["raw"] == _RAW.format(i=0)
        assert (await store.get_message(ids[-1]) or {})["raw"] == _RAW.format(i=599)
    finally:
        await store.close()


async def test_the_one_transaction_seal_never_outruns_its_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ASVS 11.3.4. The seal commits a surface once, so it cannot top the reserve up part-way. At every
    encrypt, the COMMITTED persisted total must already cover what the cipher has spent, or a kill at
    that instant under-counts the key. A small block makes a 30-row surface outrun one block."""
    monkeypatch.setattr(crypto_mod, "_GCM_RESERVE_BLOCK", 8)
    monkeypatch.setattr(crypto_mod, "_GCM_RESERVE_REFILL_AT", 4)
    db = tmp_path / "bound.db"
    await _seed(db, 30)

    cipher = _keyed(generate_key())
    real_encrypt = cipher.encrypt
    shortfalls: list[tuple[int, int]] = []

    def checked(plaintext: str, *, aad: bytes | None = None) -> str:
        out = real_encrypt(plaintext, aad=aad)
        # A separate connection sees only what is COMMITTED -- what a crash would leave behind.
        with sqlite3.connect(db) as conn:
            row = conn.execute(
                "SELECT invocations FROM cipher_meta WHERE key_id=?", (cipher.active_key_id,)
            ).fetchone()
        persisted = int(row[0]) if row else 0
        spent = cipher.cumulative_invocations()
        if persisted < spent:
            shortfalls.append((persisted, spent))
        return out

    cipher.encrypt = checked  # type: ignore[method-assign]
    store = await MessageStore.open(db, cipher=cipher)
    await store.close()
    # Liveness: a wrapper that never ran would make the assertion below vacuous. 30 rows on
    # messages.raw, 30 ingress payloads on queue.payload.
    assert cipher.cumulative_invocations() >= 60
    assert not shortfalls, f"the persisted bound trailed the encrypts: {shortfalls[:5]}"


# --- repair round 2: alerts reach the operator even where no read path runs ----------------------


def _plant_state(db: Path, key: str) -> None:
    """Seal the ``state`` surface with one genuine value, then plant a plaintext one beside it."""
    cipher = _keyed(key)
    sealed = cipher.encrypt('{"a": 1}', aad=cell_aad("state", "value", "ns", "sealed"))
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "INSERT INTO state (namespace, key, value, set_at, message_id) VALUES (?,?,?,?,?)",
            ("ns", "sealed", sealed, 0.0, "m1"),
        )
        conn.execute(
            "INSERT INTO state (namespace, key, value, set_at, message_id) VALUES (?,?,?,?,?)",
            ("ns", "row-key-9", '{"mrn": "666"}', 0.0, "m2"),
        )
        conn.commit()
    finally:
        conn.close()


async def test_open_store_arms_the_refusal_hook_before_the_open(tmp_path: Path) -> None:
    """A planted ``state`` value on a sealed surface stops the store from opening, because the open
    reads that table eagerly. The refusal must still reach a hook, so it can alert."""
    from messagefoundry.store.base import open_store

    db = tmp_path / "state.db"
    key = generate_key()
    await _seed(db, 1, _keyed(key))
    _plant_state(db, key)
    seen: list[tuple[str, str]] = []
    with pytest.raises(CipherError, match=r"state\.value"):
        await open_store(
            StoreSettings(path=str(db), encryption_key=key),
            refusal_hook=lambda table, column: seen.append((table, column)),
        )
    assert ("state", "value") in seen


class _LifecycleSink:
    """A stand-in notifier: records alerts and whether its queue was drained."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []
        self.started = False
        self.drained = False

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.events.append((name, reason, drift_count))

    def set_store(self, store: object) -> None:
        pass

    def start(self) -> None:
        self.started = True

    async def aclose(self) -> None:
        self.drained = True

    async def prime_suspensions(self) -> None:
        pass


def test_serve_alerts_when_a_planted_state_value_blocks_the_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("psutil")
    import importlib

    from fastapi.testclient import TestClient

    from messagefoundry.api import create_managed_app
    from messagefoundry.config.settings import AlertsSettings

    app_mod = importlib.import_module("messagefoundry.api.app")
    sink = _LifecycleSink()
    monkeypatch.setattr(app_mod, "notifier_from_settings", lambda *a, **k: sink)
    db = tmp_path / "serve.db"
    key = generate_key()
    asyncio.run(_seed(db, 1, _keyed(key)))
    _plant_state(db, key)

    app = create_managed_app(
        store_settings=StoreSettings(path=str(db), encryption_key=key),
        alerts_settings=AlertsSettings(),
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(CipherError), TestClient(app):
        pass
    # Two findings, both expected: the sweep finds the planted row and leaves it, then the eager
    # cache load reads it and the refusal aborts the open. The sink's subject throttle folds repeats.
    assert sink.events and {e[0] for e in sink.events} == {"store-cipher"}, sink.events
    for _subject, reason, _count in sink.events:
        assert "state.value" in reason and "666" not in reason and "row-key-9" not in reason
    # The open failed before the notifier would normally start, so it must be started and drained
    # here, or the one alert that explains the refusal is queued and never sent.
    assert sink.started and sink.drained


async def test_a_planted_row_the_open_finds_alerts_without_being_read(tmp_path: Path) -> None:
    db = tmp_path / "found.db"
    key = generate_key()
    _good, planted = await _seed(db, 2, _keyed(key))
    _set_raw(db, planted, _PLANT)
    cipher = _keyed(key)
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    store = await MessageStore.open(db, cipher=cipher)
    await store.close()
    assert seen == [("messages", "raw")]  # nothing read it; the sweep found it


async def test_the_document_strip_pass_contains_a_refused_row(tmp_path: Path) -> None:
    from messagefoundry.parsing import binary

    db = tmp_path / "strip.db"
    body = binary.encode(b"SYNTHETIC-DOCUMENT-BYTES " * 200)
    store = await MessageStore.open(db, cipher=_keyed(generate_key()))
    try:
        ids: list[str] = []
        for i in range(2):
            mid = await store.enqueue_message(
                channel_id="IB", raw=body, deliveries=[("OB", "x")], control_id=f"C{i}", now=0.0
            )
            [row] = await store.outbox_for(mid)
            await store.claim_ready(now=0.0)
            await store.mark_done(row["id"], now=0.0)
            ids.append(mid)
        _set_raw(db, ids[0], body)  # planted: an unmarked body the pass will be refused on
        result = await store.strip_embedded_documents(older_than=10.0, now=20.0)
        assert result.messages_stripped == 1  # the other row was still stripped
        assert _raw_at_rest(db, ids[0]) == body  # the refused row is left exactly as found
    finally:
        await store.close()


def test_the_logging_sink_does_not_call_a_store_cipher_alert_an_engine_module(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from messagefoundry.pipeline.alerts import LoggingAlertSink

    with caplog.at_level(logging.WARNING):
        LoggingAlertSink().integrity_drift("store-cipher", reason="messages.raw", drift_count=1)
    assert "store-cipher" in caplog.text and "engine module" not in caplog.text


async def test_the_open_reports_a_surface_once_and_each_refused_read_once(tmp_path: Path) -> None:
    """The SQLite twin of the server-backend ``test_unmarked_value_on_a_sealed_surface_is_refused_not_
    sealed``, and the pin behind its corrected assertion. The hook fires on two DIFFERENT events:
    the keyed open's sweep finds the planted row once (it visits each surface once), then every read
    that refuses it fires again. Two calls after one open plus one read is the design, not a
    double visit."""
    db = tmp_path / "once.db"
    key = generate_key()
    _good, planted = await _seed(db, 2, _keyed(key))
    _set_raw(db, planted, _PLANT)
    cipher = _keyed(key)
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    store = await MessageStore.open(db, cipher=cipher)
    try:
        assert seen == [("messages", "raw")]  # the open: one finding for the one surface
        with pytest.raises(CipherError, match=r"messages\.raw"):
            await store.get_message(planted)
        assert seen == [("messages", "raw")] * 2  # plus one per refused read
    finally:
        await store.close()


# --- the persisted keyed-surface marker (BACKLOG #3383, owner ruling 2026-10-10) ------------------


async def test_a_plant_on_a_never_written_keyed_surface_is_refused(tmp_path: Path) -> None:
    """The gap #3383 closes. ``messages.error`` is never written on these rows, so it holds no
    ciphertext. Before the marker, the next keyed open read that as unsealed and sealed the plant as
    legacy data, which then read back as genuine content."""
    db = tmp_path / "never.db"
    key = generate_key()
    _good, planted = await _seed(db, 2, _keyed(key))
    assert ("messages", "error") in _keyed_surfaces(db)  # keyed while empty
    _set_cell(db, "error", planted, _PLANT)

    cipher = _keyed(key)
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    store = await MessageStore.open(db, cipher=cipher)
    try:
        assert _cell_at_rest(db, "error", planted) == _PLANT  # NOT sealed into ciphertext
        assert seen == [("messages", "error")]  # the open found it and alerted
        with pytest.raises(CipherError, match=r"messages\.error"):
            await store.get_message(planted)
    finally:
        await store.close()


async def test_a_plant_on_a_purged_keyed_surface_is_refused(tmp_path: Path) -> None:
    """Every row of ``messages.raw`` purged to ``''``, so no ciphertext is left on the surface. The
    marker still holds it sealed, so a plant written there afterwards is refused, not sealed."""
    db = tmp_path / "purged.db"
    key = generate_key()
    ids = await _seed(db, 2, _keyed(key))
    for mid in ids:
        _set_raw(db, mid, "")  # what retention writes
    _set_raw(db, ids[1], _PLANT)

    store = await MessageStore.open(db, cipher=_keyed(key))
    try:
        assert _raw_at_rest(db, ids[1]) == _PLANT
        assert (await store.get_message(ids[0]) or {})["raw"] == ""
        with pytest.raises(CipherError, match=r"messages\.raw"):
            await store.get_message(ids[1])
    finally:
        await store.close()


async def test_a_plant_on_the_keyed_queue_payload_is_refused_not_sealed(tmp_path: Path) -> None:
    """``queue.payload`` is sealed under the row's routing tag (BACKLOG #2593), through the same
    ``_seal_surface`` with its own ``aad_of``. The marker must short-circuit it like any other
    surface: a plant there is left as it is and reported, never sealed under a genuine tag. Every
    other payload is purged first, so no ciphertext is left and only the marker can refuse it."""
    db = tmp_path / "queue.db"
    key = generate_key()
    await _seed(db, 2, _keyed(key))
    assert ("queue", "payload") in _keyed_surfaces(db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE queue SET payload=''")  # what retention writes
        qid = conn.execute("SELECT id FROM queue ORDER BY id LIMIT 1").fetchone()[0]
        conn.execute("UPDATE queue SET payload=? WHERE id=?", (_PLANT, qid))
    cipher = _keyed(key)
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    store = await MessageStore.open(db, cipher=cipher)
    try:
        with sqlite3.connect(db) as conn:
            at_rest = conn.execute("SELECT payload FROM queue WHERE id=?", (qid,)).fetchone()[0]
        assert at_rest == _PLANT  # NOT sealed under the row's routing tag
        assert seen == [("queue", "payload")]  # the open found it and alerted
    finally:
        await store.close()


async def test_legacy_plaintext_is_sealed_once_then_the_surface_stays_keyed(tmp_path: Path) -> None:
    """An existing keyless store: its first keyed open seals the legacy rows and writes the marker
    for every surface, the empty ones included. The markers survive a restart, a keyless open in
    between, and a later plant is refused rather than sealed."""
    db = tmp_path / "once.db"
    ids = await _seed(db, 3)
    assert _keyed_surfaces(db) == set()  # a keyless open writes no marker
    key = generate_key()

    store = await MessageStore.open(db, cipher=_keyed(key))
    try:
        assert all((_raw_at_rest(db, m) or "").startswith(MARKER_PREFIX) for m in ids)
    finally:
        await store.close()
    keyed = _keyed_surfaces(db)
    # Every surface the sweep visits, sealed or empty. A floor, not the full list: adding a cipher
    # column is routine and must not red this test.
    assert {("messages", "raw"), ("queue", "payload"), ("users", "totp_secret")} <= keyed
    assert {("state", "value"), ("attachment_chunk", "ciphertext")} <= keyed

    store = await MessageStore.open(db)  # a keyless restart changes nothing
    await store.close()
    assert _keyed_surfaces(db) == keyed

    _set_cell(db, "summary", ids[0], _PLANT)  # never written by this seed
    store = await MessageStore.open(db, cipher=_keyed(key))
    try:
        assert _keyed_surfaces(db) == keyed
        assert _cell_at_rest(db, "summary", ids[0]) == _PLANT
        with pytest.raises(CipherError, match=r"messages\.summary"):
            await store.get_message(ids[0])
    finally:
        await store.close()


async def test_the_opt_out_seals_a_plant_on_a_keyed_surface(tmp_path: Path) -> None:
    """``[store].allow_unmarked_ciphertext`` keeps its documented meaning: the open seals every
    unmarked value, the marker notwithstanding, and the marker stays."""
    db = tmp_path / "optout-marker.db"
    key = generate_key()
    _good, planted = await _seed(db, 2, _keyed(key))
    _set_cell(db, "error", planted, _PLANT)

    cipher = build_store_cipher(StoreSettings(encryption_key=key, allow_unmarked_ciphertext=True))
    store = await MessageStore.open(db, cipher=cipher)
    try:
        assert (_cell_at_rest(db, "error", planted) or "").startswith(MARKER_PREFIX)
        assert (await store.get_message(planted) or {})["error"] == _PLANT
    finally:
        await store.close()
    assert ("messages", "error") in _keyed_surfaces(db)


async def test_a_peer_seal_between_the_count_and_the_probe_is_not_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An engine shard's peer can seal a surface's legacy rows after this open counted them and
    before it probed for ciphertext. The probe then finds the peer's ciphertext. Reporting the
    first count would raise a false plant alert, so the open counts again and stays quiet."""
    db = tmp_path / "race.db"
    ids = await _seed(db, 2)
    for mid in ids:
        _set_cell(db, "error", mid, "legacy parse failure")
    cipher = _keyed(generate_key())
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    real_probe = MessageStore._surface_holds_ciphertext

    async def peer_seals_first(self: MessageStore, table: str, column: str, like: str) -> bool:
        if (table, column) == ("messages", "error"):
            for mid in ids:  # the peer's seal lands between this open's count and its probe
                sealed = cipher.encrypt("legacy parse failure", aad=cell_aad(table, column, mid))
                await self._db.execute("UPDATE messages SET error=? WHERE id=?", (sealed, mid))
        return await real_probe(self, table, column, like)

    monkeypatch.setattr(MessageStore, "_surface_holds_ciphertext", peer_seals_first)
    store = await MessageStore.open(db, cipher=cipher)
    try:
        assert seen == [], "a peer's legitimate seal was reported as a plant"
        assert ("messages", "error") in _keyed_surfaces(db)
        assert (await store.get_message(ids[0]) or {})["error"] == "legacy parse failure"
    finally:
        await store.close()


async def test_a_surface_keyed_by_another_process_mid_open_is_not_sealed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The seal writes the marker first, in its own transaction. If the marker is already there,
    another process keyed the surface after this open read it, so this open seals nothing. Simulated
    by hiding the marker from the read that precedes the seal, on a surface with no ciphertext, so
    the data check cannot call it sealed either."""
    db = tmp_path / "peer.db"
    key = generate_key()
    _good, planted = await _seed(db, 2, _keyed(key))
    _set_cell(db, "error", planted, _PLANT)
    assert ("messages", "error") in _keyed_surfaces(db)

    async def unkeyed_read(self: MessageStore, table: str, column: str) -> bool:
        return False

    monkeypatch.setattr(MessageStore, "_surface_keyed", unkeyed_read)
    cipher = _keyed(key)
    seen: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: seen.append((table, column)))
    store = await MessageStore.open(db, cipher=cipher)
    try:
        assert _cell_at_rest(db, "error", planted) == _PLANT  # the claim lost; nothing was sealed
        # The losing open counted again and reported the plant the peer left, not silence.
        assert seen == [("messages", "error")]
        with pytest.raises(CipherError, match=r"messages\.error"):
            await store.get_message(planted)
    finally:
        await store.close()
