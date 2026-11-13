# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The vault_transit AES-GCM bound attestation (BACKLOG #2337, owner rulings 2026-10-07).

On ``vault_transit`` the engine counts no AES-GCM invocations, so ``serve`` needs a recorded, audited
attestation naming the configured Transit data key. These tests run the SQLite store over the fake
Transit from ``tests/test_crypto_transit.py``; the SQL Server and Postgres twins run in
``tests/test_transit_bound_attestation_server_backends.py`` on the CI legs that have those servers.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import hmac as _hmac_lib
import json
import logging
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, NoReturn

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AiSettings,
    AuthSettings,
    EgressSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.base import open_store
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.row_seal import transit_mac_version
from messagefoundry.store.store import MessageStore
from messagefoundry.store.transit_attestation import (
    TRANSIT_BOUND_ATTESTED_ACTION,
    TRANSIT_BOUND_WITHDRAWN_ACTION,
    TransitBoundAttestation,
    TransitBoundUnattestedError,
)
from tests._admin_account import create_local_user_chosen
from tests.test_crypto_transit import _KEY_NAME, _FakeTransit, _use_fake

PW = "a-strong-test-passphrase"


async def _transit_store(db: Path) -> MessageStore:
    store = await open_store(
        StoreSettings(path=str(db), cipher_provider="vault_transit"),
        create=True,
        keyless_chain_refusal=None,
    )
    assert isinstance(store, MessageStore)
    return store


@pytest.fixture
async def store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[MessageStore]:
    _use_fake(monkeypatch)
    s = await _transit_store(tmp_path / "transit.db")
    try:
        yield s
    finally:
        await s.close()


async def _attest(store: MessageStore, key_name: str = _KEY_NAME) -> TransitBoundAttestation:
    return await store.record_transit_bound_attestation(
        key_name=key_name,
        reason="Transit auto-rotates this key every 30 days",
        actor="cli:tester",
    )


async def _withdraw(store: MessageStore) -> TransitBoundAttestation | None:
    return await store.withdraw_transit_bound_attestation(actor="cli:tester")


async def _start(store: MessageStore, enforcement: SecurityEnforcement) -> None:
    engine = Engine(
        store,
        security_enforcement=enforcement,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
    finally:
        await engine.stop()


# --- the start gate ------------------------------------------------------------------------------


async def test_enforce_refuses_a_transit_store_with_no_attestation(store: MessageStore) -> None:
    with pytest.raises(TransitBoundUnattestedError, match="attest-transit-bound"):
        await _start(store, SecurityEnforcement.ENFORCE)


async def test_warn_starts_with_a_warning(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.transit_attestation"):
        await _start(store, SecurityEnforcement.WARN)
    warned = [r for r in caplog.records if "vault_transit" in r.getMessage()]
    assert warned and warned[0].levelno == logging.WARNING
    assert "no attestation is recorded" in warned[0].getMessage()


async def test_an_attestation_naming_the_configured_key_lets_enforce_start(
    store: MessageStore,
) -> None:
    await _attest(store)
    await _start(store, SecurityEnforcement.ENFORCE)  # no raise


async def test_an_attestation_for_another_key_name_does_not_satisfy(store: MessageStore) -> None:
    await _attest(store, key_name="mefor-store-old")
    with pytest.raises(TransitBoundUnattestedError, match="mefor-store-old"):
        await _start(store, SecurityEnforcement.ENFORCE)


async def test_withdraw_re_arms_the_refusal(store: MessageStore, tmp_path: Path) -> None:
    await _attest(store)
    await _start(store, SecurityEnforcement.ENFORCE)  # stopping the engine closes the store
    again = await _transit_store(tmp_path / "transit.db")
    withdrawn = await _withdraw(again)
    assert withdrawn is not None and withdrawn.key_name == _KEY_NAME
    with pytest.raises(TransitBoundUnattestedError):
        await _start(again, SecurityEnforcement.ENFORCE)


async def test_a_non_transit_store_is_not_gated(tmp_path: Path) -> None:
    keyless = await MessageStore.open(tmp_path / "plain.db")
    await _start(keyless, SecurityEnforcement.ENFORCE)  # no raise: the engine counts the bound


# --- the row is bound to its audit row (DML alone forges nothing) --------------------------------


def _dml(db: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    """Write the store file directly, as someone with DML on the table and no audit key would."""
    con = sqlite3.connect(db)
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


def _attestation_row(db: Path) -> tuple[object, ...]:
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "SELECT key_name, reason, actor, attested_at, audit_seq, audit_hash"
            " FROM transit_bound_attestation WHERE id = 1"
        ).fetchone()
    finally:
        con.close()
    assert row is not None
    return tuple(row)


_INSERT = (
    "INSERT OR REPLACE INTO transit_bound_attestation"
    " (id, key_name, reason, actor, attested_at, audit_seq, audit_hash)"
    " VALUES (1, ?, ?, ?, ?, ?, ?)"
)


async def _refused_with(db: Path, needle: str) -> None:
    store = await _transit_store(db)
    got = await store.get_transit_bound_attestation()
    assert got is not None and got.audit_gap is not None and needle in got.audit_gap, got
    with pytest.raises(TransitBoundUnattestedError, match="not backed by its audit row"):
        await _start(store, SecurityEnforcement.ENFORCE)


async def test_a_row_inserted_by_dml_with_no_audit_row_does_not_count(
    store: MessageStore, tmp_path: Path
) -> None:
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, _INSERT, (_KEY_NAME, "forged", "cli:tester", time.time(), 9999, "0" * 64))
    await _refused_with(db, "not in the audit log")


async def test_a_dml_edit_of_the_key_name_does_not_count(
    store: MessageStore, tmp_path: Path
) -> None:
    await _attest(store, key_name="mefor-store-old")
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, "UPDATE transit_bound_attestation SET key_name = ? WHERE id = 1", (_KEY_NAME,))
    await _refused_with(db, "different key, reason, actor or time")


async def test_a_row_replayed_after_a_withdraw_does_not_count(
    store: MessageStore, tmp_path: Path
) -> None:
    await _attest(store)
    db = tmp_path / "transit.db"
    saved = _attestation_row(db)
    assert await _withdraw(store) is not None
    await store.close()
    _dml(db, _INSERT, saved)  # the old row, byte for byte, pointing at its real audit row
    await _refused_with(db, "supersedes")


async def test_a_forged_audit_row_does_not_verify(store: MessageStore, tmp_path: Path) -> None:
    """A writer who also appends an audit row cannot seal it: the MAC is computed in Transit."""
    await _attest(store, key_name="mefor-store-old")
    await store.close()
    db = tmp_path / "transit.db"
    con = sqlite3.connect(db)
    try:
        seq, prev = con.execute("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC").fetchone()
        ts = time.time()
        detail = json.dumps({"key_name": _KEY_NAME, "reason": "forged"})
        con.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (?, ?, ?, ?, NULL, ?, NULL, ?)",
            (seq + 1, ts, "cli:tester", TRANSIT_BOUND_ATTESTED_ACTION, detail, "f" * 64),
        )
        con.execute(
            _INSERT.replace("INSERT OR REPLACE", "REPLACE"),
            (_KEY_NAME, "forged", "cli:tester", ts, seq + 1, "f" * 64),
        )
        con.commit()
    finally:
        con.close()
    assert prev  # the chain had a head to forge after
    await _refused_with(db, "MAC does not verify")


class _RotatingTransit(_FakeTransit):
    """Fake Transit with key versions, each MACing under its own secret, and the key's two policy
    floors, modelled on Vault's ``path_hmac.go`` at cbc874e2358f. ``generate_hmac`` uses the latest
    unless ``key_version`` pins one, and refuses a pinned version below ``min_encryption_version``.
    ``verify_signed_data`` checks at the version the MAC names: one above the latest, or below
    ``min_decryption_version``, is refused with HTTP 400; ``min_encryption_version`` plays no part
    there, as in Vault."""

    def __init__(self) -> None:
        super().__init__()
        self.latest = 1
        self.min_encryption_version = 1
        self.min_decryption_version = 1
        #: The ``key_version`` of every ``generate_hmac`` call (``None`` is the latest).
        self.pinned: list[int | None] = []
        #: The version every ``verify_signed_data`` call checked at.
        self.verified: list[int] = []

    @staticmethod
    def _refuse(text: str) -> NoReturn:
        # The [vault] extra's class, which the cipher classifies on. Only a test that reaches a
        # refusal gets here, and _needs_hvac() skips those without the extra.
        from hvac.exceptions import InvalidRequest  # type: ignore[import-untyped]

        # hvac carries Vault's JSON `errors` list.
        raise InvalidRequest(errors=[text])

    def _mac(self, name: str, version: int, hash_input: str) -> str:
        secret = self._hmac_secret[name] + version.to_bytes(4, "big")
        digest = hmac.new(secret, base64.b64decode(hash_input), hashlib.sha256).digest()
        return f"vault:v{version}:" + base64.b64encode(digest).decode("ascii")

    def generate_hmac(
        self,
        *,
        name: str,
        hash_input: str,
        algorithm: str = "sha2-256",
        key_version: int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        self.pinned.append(key_version)
        if key_version is not None and key_version > self.latest:
            self._refuse(f"key version does not exist; latest key version is {self.latest}")
        if key_version is not None and key_version < self.min_encryption_version:
            self._refuse("cannot generate HMAC: version is too old (disallowed by policy)")
        version = self.latest if key_version is None else key_version
        return {"data": {"hmac": self._mac(name, version, hash_input)}}

    def verify_signed_data(
        self, *, name: str, hash_input: str, hmac: str, hash_algorithm: str | None = None, **_: Any
    ) -> dict[str, Any]:
        # A check that names no algorithm, or another one, fails here, where Transit
        # would verify under its own default and read every row as forged.
        assert hash_algorithm == "sha2-256", hash_algorithm
        version = transit_mac_version(hmac)
        assert version is not None, hmac  # the cipher hands Transit only a well-formed MAC
        self.verified.append(version)
        if version > self.latest:
            self._refuse("invalid HMAC: version is too new")
        if version < self.min_decryption_version:
            self._refuse("cannot verify HMAC: version is too old (disallowed by policy)")
        expected = self._mac(name, version, hash_input)
        return {"data": {"valid": _hmac_lib.compare_digest(expected, hmac)}}


async def test_rotating_the_transit_key_keeps_the_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The operator attests that they rotate the key, so a rotation must not read as a forgery: the
    check asks Transit to verify the audit row's MAC at the version that row names."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "rotating.db"
    store = await _transit_store(db)
    await _attest(store)
    await store.close()
    transit.latest = 2  # Transit rotated the key; new MACs are vault:v2:
    again = await _transit_store(db)
    try:
        got = await again.get_transit_bound_attestation()
        # The audit chain walk pins the same way, so the rotation reads as no break there either.
        chain_ok, chain_msg = await again.verify_audit_chain()
    except BaseException:
        await again.close()
        raise
    assert got is not None and got.audit_gap is None, got
    assert chain_ok, chain_msg
    # Checked by Transit's verify at the version the row names, never regenerated (BACKLOG #2720).
    assert 1 in transit.verified
    assert set(transit.pinned) == {None}, transit.pinned
    await _start(again, SecurityEnforcement.ENFORCE)  # no raise; stopping closes the store


# --- the audit chain checks each row with Transit's verify (BACKLOG #2720) -----------------------


async def _mixed_chain(transit: _RotatingTransit, db: Path) -> dict[str, int]:
    """A Transit store whose audit chain has rows under key version 1, then, after a rotation,
    rows under version 2. Returns each test row's sequence number, by action."""
    store = await _transit_store(db)
    try:
        await store.record_audit("test.v1", actor="cli:tester")
        transit.latest = 2  # Transit rotated the key; new MACs are vault:v2:
        await store.record_audit("test.v2", actor="cli:tester")
    finally:
        await store.close()
    con = sqlite3.connect(db)
    try:
        rows = con.execute("SELECT seq, action, row_hash FROM audit_log ORDER BY seq").fetchall()
    finally:
        con.close()
    versions = {transit_mac_version(str(h)) for _, _, h in rows}
    assert versions == {1, 2}, rows  # the chain really is mixed
    return {str(action): int(seq) for seq, action, _ in rows}


async def test_a_mixed_v1_and_v2_chain_verifies_after_a_rotation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "mixed.db"
    await _mixed_chain(transit, db)
    transit.pinned.clear()
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert ok, msg
    assert {1, 2} <= set(transit.verified), transit.verified
    # No MAC was regenerated to compare: every hmac call since is an unpinned append or probe.
    assert set(transit.pinned) <= {None}, transit.pinned


async def test_raising_min_encryption_version_past_v1_leaves_v1_rows_verifying(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``min_encryption_version`` stops Transit making a v1 MAC, not checking one. A walk that
    regenerated each row's MAC at its own version broke at row 1 here; verify does not."""
    _needs_hvac()
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "min-encryption.db"
    seqs = await _mixed_chain(transit, db)
    transit.min_encryption_version = 2
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
        await store.record_audit("test.after", actor="cli:tester")  # appends still work, at v2
        again_ok, again_msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert ok, msg
    assert again_ok, again_msg
    assert sink.events == [], sink.events
    assert not any("could not run" in line for line in lines), lines
    assert 1 in transit.verified and seqs["test.v1"] > 1


async def test_raising_min_decryption_version_past_v1_is_a_break_with_the_alert(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``min_decryption_version`` IS the floor for checking an HMAC: a v1 row Transit will no
    longer verify is still a break at row 1, with the tamper alert, never a walk that could not
    run."""
    _needs_hvac()
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "min-decryption.db"
    await _mixed_chain(transit, db)
    transit.min_encryption_version = transit.min_decryption_version = 2
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert not ok and "seq=1," in str(msg), msg
    assert "Transit refused audit key version 1" in str(msg), msg
    assert [name for name, _ in sink.events] == ["audit-chain"], sink.events
    assert not any("could not run" in line for line in lines), lines


@pytest.mark.parametrize("which", ["test.v1", "test.v2"])
@pytest.mark.parametrize("edit", ["detail", "mac"])
async def test_a_tampered_row_in_a_mixed_chain_still_breaks(
    which: str, edit: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An edited row, or an altered MAC of the right shape, is Transit's ``valid: false`` at that
    row, under either version."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "tampered.db"
    seq = (await _mixed_chain(transit, db))[which]
    if edit == "detail":
        _dml(db, "UPDATE audit_log SET detail = 'edited' WHERE seq = ?", (seq,))
    else:
        con = sqlite3.connect(db)
        try:
            (stored,) = con.execute(
                "SELECT row_hash FROM audit_log WHERE seq = ?", (seq,)
            ).fetchone()
        finally:
            con.close()
        head, _, body = str(stored).rpartition(":")
        flipped = bytes([base64.b64decode(body)[0] ^ 1]) + base64.b64decode(body)[1:]
        _dml(
            db,
            "UPDATE audit_log SET row_hash = ? WHERE seq = ?",
            (f"{head}:" + base64.b64encode(flipped).decode("ascii"), seq),
        )
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg


@pytest.mark.parametrize(
    "stored",
    [
        pytest.param("vault:v1:AAAA", id="short-digest"),
        pytest.param("vault:v1:!!not base64!!", id="not-base64"),
        pytest.param("vault:v01:" + base64.b64encode(bytes(32)).decode("ascii"), id="zero-padded"),
        pytest.param("f" * 64, id="no-prefix"),
    ],
)
async def test_a_malformed_stored_mac_is_a_break_with_no_verify_call(
    stored: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A stored MAC Transit would refuse for its shape never reaches Transit's verify, so no 400
    on it can read as an outage: it is a break at that row. It still costs one round trip, an
    unpinned hmac, so a malformed row is no cheaper to check than a clean one."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "malformed.db"
    seq = (await _mixed_chain(transit, db))["test.v1"]
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = ?", (stored, seq))
    store = await _transit_store(db)
    transit.verified.clear()
    transit.pinned.clear()
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert transit.pinned == [None], transit.pinned
    con = sqlite3.connect(db)
    try:
        (rows,) = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()
    finally:
        con.close()
    assert len(transit.verified) == rows - 1, transit.verified  # every row but the malformed one


async def test_a_non_text_row_hash_still_costs_one_round_trip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SQLite keeps a BLOB in the TEXT column. It is a break, and it costs the same one round trip
    a malformed MAC does."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "blob.db"
    seq = (await _mixed_chain(transit, db))["test.v1"]
    _dml(db, "UPDATE audit_log SET row_hash = X'00' WHERE seq = ?", (seq,))
    store = await _transit_store(db)
    transit.pinned.clear()
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert transit.pinned == [None], transit.pinned


async def test_a_failed_cost_call_beside_a_malformed_mac_is_still_a_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The round trip a malformed MAC costs carries no verdict, so its failure must not turn the
    row's break into a walk that could not run."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "cost-fails.db"
    seq = (await _mixed_chain(transit, db))["test.v1"]
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = ?", ("f" * 64, seq))
    store = await _transit_store(db)

    def refused(**_kw: Any) -> dict[str, Any]:
        raise httpx.ConnectError("rate limited")

    monkeypatch.setattr(transit, "generate_hmac", refused)
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg


def test_a_verify_reply_of_an_unexpected_shape_is_a_plain_cipher_error() -> None:
    """Transit's ``valid`` must be a bool; anything else is a check that could not run, never a
    pass and never a refused version."""
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError
    from messagefoundry.store.crypto_transit import TransitCipher
    from tests.test_crypto_transit import _FakeClient

    class _Transit(_FakeTransit):
        def verify_signed_data(self, **_kw: Any) -> dict[str, Any]:
            return {"data": {"valid": "true"}}

    cipher = TransitCipher(_FakeClient(_Transit()), _KEY_NAME)
    with pytest.raises(CipherError) as caught:
        cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row"))
    assert not isinstance(caught.value, AuditKeyVersionRefusedError)


@pytest.mark.parametrize(
    "reply", [{"data": {}}, {}, None, "not a mapping"], ids=["no-valid", "no-data", "none", "text"]
)
def test_a_verify_reply_with_no_valid_is_a_plain_cipher_error(reply: Any) -> None:
    """A reply that carries no ``valid`` at all is a check that could not run, never a break:
    the reply's shape is read once the call returned, not classified as a failed call."""
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError
    from messagefoundry.store.crypto_transit import TransitCipher
    from tests.test_crypto_transit import _FakeClient

    class _Transit(_FakeTransit):
        def verify_signed_data(self, **_kw: Any) -> Any:
            return reply

    cipher = TransitCipher(_FakeClient(_Transit()), _KEY_NAME)
    with pytest.raises(CipherError) as caught:
        cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row"))
    assert not isinstance(caught.value, AuditKeyVersionRefusedError)
    assert "unexpected shape" in str(caught.value)


#: A Transit key version the fake does not hold, as a DML writer would plant it.
_UNHELD_VERSION = 9999999
#: Well-formed, so it reaches Transit; a malformed one is a break with no Transit call at all.
_PLANTED = f"vault:v{_UNHELD_VERSION}:" + base64.b64encode(bytes(32)).decode("ascii")


def _needs_hvac() -> None:
    """Skip without the [vault] extra: the cipher tells a refused version by hvac's own class."""
    pytest.importorskip("hvac.exceptions")


async def test_a_transit_refusal_of_a_forged_key_version_is_a_gap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A DML writer sets both hashes to a key version Transit does not hold. Transit refuses to
    verify at it; that must read as unattested, so a warn start still starts."""
    _needs_hvac()
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "forged-version.db"
    store = await _transit_store(db)
    recorded = await _attest(store)
    await store.close()
    _dml(db, "UPDATE transit_bound_attestation SET audit_hash = ? WHERE id = 1", (_PLANTED,))
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = ?", (_PLANTED, recorded.audit_seq))
    again = await _transit_store(db)
    transit.verified.clear()
    try:
        got = await again.get_transit_bound_attestation()
        # The whole gap text, so it is the refused-version outcome and no other: an AssertionError
        # in the fake, or any CipherError the cipher does not classify as a refused version, also
        # writes a gap starting "Transit refused to check", and must fail here.
        assert got is not None
        assert got.audit_gap == (
            f"Transit refused to check audit row {recorded.audit_seq}'s MAC: "
            f"{AuditKeyVersionRefusedError(_UNHELD_VERSION)}"
        ), got.audit_gap
        # The refusal came from Transit's verify, at the planted version.
        assert transit.verified == [_UNHELD_VERSION], transit.verified
    except BaseException:
        await again.close()
        raise
    await _start(again, SecurityEnforcement.WARN)  # no raise


# --- a planted key version on the audit chain is a break, not a walk that could not run ----------


class _StartupSink(LoggingAlertSink):
    """Records every ``integrity_drift`` the startup audit walk fires."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.events.append((name, reason))


async def _chain_with_a_tampered_middle_row(db: Path, column: str, value: str) -> int:
    """A Transit store whose audit chain has one middle row whose ``column`` a DML writer set to
    ``value``. Returns that row's sequence number."""
    _needs_hvac()
    store = await _transit_store(db)
    try:
        await store.record_audit("test.tampered", actor="cli:tester")
        await store.record_audit("test.after", actor="cli:tester")
    finally:
        await store.close()
    con = sqlite3.connect(db)
    try:
        (seq,) = con.execute("SELECT seq FROM audit_log WHERE action = 'test.tampered'").fetchone()
    finally:
        con.close()
    _dml(db, f"UPDATE audit_log SET {column} = ? WHERE seq = ?", (value, seq))
    return int(seq)


async def _chain_with_a_planted_version(db: Path) -> int:
    """One middle row naming a key version Transit does not hold, as a DML writer would plant it."""
    return await _chain_with_a_tampered_middle_row(db, "row_hash", _PLANTED)


async def _walk_on_start(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> tuple[_StartupSink, list[str]]:
    """Run only the engine's startup audit check, returning the alerts and the engine's log lines."""
    sink = _StartupSink()
    engine = Engine(
        store,
        alert_sink=sink,
        audit_verify_on_start=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.engine"):
        await engine._verify_audit_chain_on_start()
    lines = [r.getMessage() for r in caplog.records if r.name == "messagefoundry.pipeline.engine"]
    # Proves the capture saw the walk at all, so an absent "could not run" line means something.
    assert any("startup audit-chain verification" in line for line in lines), lines
    return sink, lines


async def test_a_planted_unheld_key_version_is_a_chain_break_on_the_startup_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A DML writer names a Transit key version Transit does not hold. Transit refuses to verify
    at it, and that is the row's own evidence: the startup walk must raise the tamper alert at
    that row, never stop with "could not run" and no alert (the sixth defect on PR 2167)."""
    _use_fake(monkeypatch, _RotatingTransit())
    db = tmp_path / "planted.db"
    seq = await _chain_with_a_planted_version(db)
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert f"key version {_UNHELD_VERSION}" in str(msg), msg
    assert [name for name, _ in sink.events] == ["audit-chain"], sink.events
    assert f"seq={seq}," in sink.events[0][1], sink.events
    assert not any("could not run" in line for line in lines), lines


async def test_a_planted_unheld_key_version_on_the_genesis_row_opens_and_reads_as_a_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The open MACs the genesis row too. A planted version there must not stop the open; the
    walk reports the break at row 1."""
    _use_fake(monkeypatch, _RotatingTransit())
    db = tmp_path / "planted-genesis.db"
    await _chain_with_a_planted_version(db)
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = 1", (_PLANTED,))
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and "seq=1," in str(msg), msg


async def test_a_verify_failure_whose_fixed_input_probe_fails_on_the_startup_walk_could_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An ``httpx.ConnectError`` is not one :func:`is_vault_unavailable` reads as an outage (that
    branch is ``test_a_service_failure_of_the_verify_call_still_could_not_run``), so the row's
    failed verify goes to the fixed-input check, whose ``hmac`` fails too: that is not evidence
    about any row, so the walk could not run, and no tamper alert fires."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "outage.db"
    await _chain_with_a_planted_version(db)
    store = await _transit_store(db)

    def unreachable(**_kw: Any) -> dict[str, Any]:
        raise httpx.ConnectError("Vault is unreachable")

    monkeypatch.setattr(transit, "generate_hmac", unreachable)
    monkeypatch.setattr(transit, "verify_signed_data", unreachable)
    try:
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert sink.events == []
    assert any("could not run" in line for line in lines), lines


async def test_a_verify_failure_whose_fixed_input_verify_fails_could_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A failure on every verify call, the fixed-input check's included, while the latest version
    still answers its ``hmac``, must not read as a refused key version or as the row's. The
    ``httpx.ConnectError`` is not one :func:`is_vault_unavailable` reads as an outage, so this
    reaches the fixed-input check, not the outage branch: a check that could not run, so a clean
    row is never reported as tampered."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "transient.db"
    store = await _transit_store(db)
    await store.record_audit("test.clean", actor="cli:tester")

    def drop(**_kw: Any) -> dict[str, Any]:
        raise httpx.ConnectError("connection reset")

    monkeypatch.setattr(transit, "verify_signed_data", drop)
    try:
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert sink.events == []
    assert any("could not run" in line for line in lines), lines


#: The longest ``hash_input`` the size-capped fake takes, standing in for Vault's
#: ``max_request_size``. Far past any row the tests append, and far short of the planted one.
_REQUEST_CAP_CHARS = 4096


class _SizeCappedTransit(_RotatingTransit):
    """Fake Transit that answers a request past :data:`_REQUEST_CAP_CHARS` with HTTP 413, which
    hvac raises as ``UnexpectedError``, as Vault does past its listener's ``max_request_size``."""

    @staticmethod
    def _cap(hash_input: str) -> None:
        if len(hash_input) > _REQUEST_CAP_CHARS:
            from hvac.exceptions import UnexpectedError

            raise UnexpectedError("http: request body too large")

    def generate_hmac(self, *, hash_input: str, **kw: Any) -> dict[str, Any]:
        self._cap(hash_input)
        return super().generate_hmac(hash_input=hash_input, **kw)

    def verify_signed_data(self, *, hash_input: str, **kw: Any) -> dict[str, Any]:
        self._cap(hash_input)
        return super().verify_signed_data(hash_input=hash_input, **kw)


async def _chain_with_an_oversize_row(db: Path) -> int:
    """One middle row a DML writer grew past the request cap, MAC left as it was."""
    return await _chain_with_a_tampered_middle_row(db, "detail", "x" * (4 * _REQUEST_CAP_CHARS))


async def test_a_row_transit_refuses_for_its_size_is_a_chain_break_on_the_startup_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A forged row whose own content makes Transit refuse its verify (here a 413 past
    ``max_request_size``) is evidence about that row: a break there with the tamper alert, as a
    forged MAC is, never a walk that could not run (BACKLOG #2720)."""
    _use_fake(monkeypatch, _SizeCappedTransit())
    db = tmp_path / "oversize.db"
    seq = await _chain_with_an_oversize_row(db)
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert [name for name, _ in sink.events] == ["audit-chain"], sink.events
    assert f"seq={seq}," in sink.events[0][1], sink.events
    assert not any("could not run" in line for line in lines), lines


def _service_error(name: str) -> Exception:
    """An instance of the hvac or requests error class ``name`` names."""
    import requests
    from hvac import exceptions  # type: ignore[import-untyped]

    if name.startswith("requests."):
        error: type[Exception] = getattr(requests.exceptions, name.removeprefix("requests."))
    else:
        error = getattr(exceptions, name)
    return error("the service failed")


@pytest.mark.parametrize(
    ("error", "probe_fails"),
    [
        pytest.param("RateLimitExceeded", False, id="429"),
        pytest.param("InternalServerError", False, id="500"),
        pytest.param("BadGateway", False, id="502"),
        pytest.param("VaultDown", False, id="503"),
        pytest.param("requests.ConnectionError", False, id="dropped-connection"),
        pytest.param("requests.ReadTimeout", False, id="timeout"),
        pytest.param("UnexpectedError", True, id="504-gateway-down"),
    ],
)
async def test_a_service_failure_of_the_verify_call_still_could_not_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    error: str,
    probe_fails: bool,
) -> None:
    """A failure on a row's verify that :func:`is_vault_unavailable` reads as an outage (at least
    a 429, 500, 502 or 503, a dropped connection and a timeout) is the service, not the row: the
    walk could not run, and no tamper alert fires. Those are never probed, so here they fail only
    the rows' own calls. A status hvac does not name, a 504 among them, is read as the service
    when a verify over fixed input fails too, as it does while the gateway is down."""
    _needs_hvac()
    from messagefoundry.store.crypto_transit import _VERSION_PROBE_INPUT

    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    store = await _transit_store(tmp_path / "service.db")
    try:
        await store.record_audit("test.clean", actor="cli:tester")
        real_verify = transit.verify_signed_data

        def failing(*, hash_input: str, **kw: Any) -> dict[str, Any]:
            if hash_input == _VERSION_PROBE_INPUT and not probe_fails:
                return real_verify(hash_input=hash_input, **kw)
            raise _service_error(error)

        monkeypatch.setattr(transit, "verify_signed_data", failing)
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert sink.events == []
    assert any("could not run" in line for line in lines), lines


async def test_a_verify_failure_that_clears_on_the_second_ask_is_not_a_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A failure hvac does not name (a 504, say) on one row's verify, gone by the time the
    fixed-input probe and the second ask run, reads as Transit's answer to that second ask: a clean
    row stays clean, and no tamper alert fires (BACKLOG #2720)."""
    _needs_hvac()
    from hvac.exceptions import UnexpectedError

    from messagefoundry.store.crypto_transit import _VERSION_PROBE_INPUT

    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    store = await _transit_store(tmp_path / "cleared.db")
    try:
        await store.record_audit("test.clean", actor="cli:tester")
        real_verify = transit.verify_signed_data
        failed: list[str] = []

        def once(*, hash_input: str, **kw: Any) -> dict[str, Any]:
            if hash_input != _VERSION_PROBE_INPUT and not failed:
                failed.append(hash_input)
                raise UnexpectedError("gateway timeout")
            return real_verify(hash_input=hash_input, **kw)

        monkeypatch.setattr(transit, "verify_signed_data", once)
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert failed, "the fake never failed a row's verify"
    assert ok, msg
    assert sink.events == []
    assert not any("could not run" in line for line in lines), lines


def _scripted_cipher(row_failures: list[Exception | None], *, fixed_fails_after: int = -1) -> Any:
    """A Transit cipher over :class:`_RotatingTransit` whose row verifies (any input but the
    fixed probe's) raise the next of ``row_failures`` in turn, ``None`` passing through, and whose
    fixed-input verify fails from its ``fixed_fails_after``-th call on (``-1``: never)."""
    _needs_hvac()
    from hvac.exceptions import Forbidden

    from messagefoundry.store.crypto_transit import _VERSION_PROBE_INPUT, TransitCipher
    from tests.test_crypto_transit import _FakeClient

    transit = _RotatingTransit()
    real_verify = transit.verify_signed_data
    fixed_calls = [0]

    def scripted(*, hash_input: str, **kw: Any) -> dict[str, Any]:
        if hash_input == _VERSION_PROBE_INPUT:
            fixed_calls[0] += 1
            if 0 <= fixed_fails_after < fixed_calls[0]:
                raise Forbidden("permission denied")
        elif row_failures:
            failure = row_failures.pop(0)
            if failure is not None:
                raise failure
        return real_verify(hash_input=hash_input, **kw)

    transit.verify_signed_data = scripted  # type: ignore[method-assign]
    return TransitCipher(_FakeClient(transit), _KEY_NAME)


def test_a_400_on_the_row_alone_at_the_latest_version_is_a_break() -> None:
    """A 400 on one row's verify, at a version the key holds, while the fixed input verifies and
    the row is refused again, is evidence about that row: ``False``, a break (BACKLOG #2720)."""
    _needs_hvac()
    from hvac.exceptions import InvalidRequest

    cipher = _scripted_cipher([InvalidRequest("bad"), InvalidRequest("bad")])
    assert cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row")) is False


def test_a_failed_fixed_input_verify_keeps_the_rows_failure_as_the_cause() -> None:
    """When the fixed input fails too, the check could not run, and the error's cause is the
    row's own failure, so a reader of the cause's class still tells an outage from a refusal."""
    _needs_hvac()
    from hvac.exceptions import UnexpectedError

    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    cipher = _scripted_cipher([UnexpectedError("gateway")], fixed_fails_after=0)
    with pytest.raises(CipherError) as caught:
        cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row"))
    assert not isinstance(caught.value, AuditKeyVersionRefusedError)
    assert isinstance(caught.value.__cause__, UnexpectedError)


def test_a_service_failure_between_the_two_asks_could_not_run() -> None:
    """The fixed input verified after the first ask, the row's second ask is refused, and then the
    fixed input fails: the service failed between the asks, so the check could not run, never a
    break on a clean row."""
    _needs_hvac()
    from hvac.exceptions import Forbidden, UnexpectedError

    cipher = _scripted_cipher(
        [UnexpectedError("gateway"), Forbidden("expired")], fixed_fails_after=1
    )
    with pytest.raises(CipherError) as caught:
        cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row"))
    assert isinstance(caught.value.__cause__, Forbidden)


def test_a_refused_version_on_the_second_ask_keeps_its_label() -> None:
    """A version Transit refuses on the second ask, after a failure that cleared, is labelled as
    a refused version, as on the first ask."""
    _needs_hvac()
    from hvac.exceptions import UnexpectedError

    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    cipher = _scripted_cipher([UnexpectedError("gateway"), None])
    with pytest.raises(AuditKeyVersionRefusedError):
        cipher.verify_audit_hmac(b"row", _PLANTED)


# --- BACKLOG #8222 items 1 and 5: a timeout is an outage, a malformed handover reply a break --------


def _status_error(status: int) -> Exception:
    """hvac's ``UnexpectedError`` for an HTTP ``status`` it does not name, as the store's Vault
    client raises it: through the adapter's ``_raise_for_error``, which records the status."""
    _needs_hvac()
    import requests

    from messagefoundry.store.keyprovider_vault import _record_reply_status

    class _Adapter:
        def _raise_for_error(self, method: str, url: str, response: Any) -> None:
            from hvac import utils

            utils.raise_for_error(method, url, response.status_code, "the reply")

    class _Client:
        adapter = _Adapter()

    client = _Client()
    _record_reply_status(client)
    reply = requests.Response()
    reply.status_code = status
    try:
        client.adapter._raise_for_error("POST", "https://vault.example.test/v1/x", reply)
    except Exception as exc:  # noqa: BLE001 -- the error under test, returned for the caller
        return exc
    raise AssertionError("hvac raised nothing")


@pytest.mark.parametrize("status", [504, 408])
def test_a_timeout_on_one_rows_verify_could_not_run_though_the_fixed_input_verifies(
    status: int,
) -> None:
    """A 504 or 408 on both asks of one row's verify, while the verify over fixed input succeeds,
    is the service timing out, not Transit refusing that row: the check could not run, never a
    break (BACKLOG #8222 item 1, owner ruling 2026-11-13). Before this it read as a break."""
    _needs_hvac()
    from hvac.exceptions import UnexpectedError

    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    cipher = _scripted_cipher([_status_error(status), _status_error(status)])
    rechecked: list[bool] = []
    real_fixed = cipher._fixed_input_verifies

    def counted() -> bool:
        rechecked.append(True)
        return bool(real_fixed())

    cipher._fixed_input_verifies = counted
    with pytest.raises(CipherError) as caught:
        cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row"))
    assert not isinstance(caught.value, AuditKeyVersionRefusedError)
    assert isinstance(caught.value.__cause__, UnexpectedError)
    assert rechecked, "the fixed input was checked between the asks"
    assert real_fixed(), "the control: the fixed input verifies"


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param(400, 504, id="400-then-504"),
        pytest.param(413, 504, id="413-then-504"),
        pytest.param(504, 413, id="504-then-413"),
        pytest.param(504, 400, id="504-then-400"),
    ],
)
def test_a_timeout_on_only_one_ask_is_still_a_break(first: int, second: int) -> None:
    """A timeout on one ask beside a 400 or a 413 on the other, while the fixed input verifies,
    is a break: only a 408 or 504 on both asks reads as could not run (BACKLOG #8222)."""
    cipher = _scripted_cipher([_status_error(first), _status_error(second)])
    assert cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row")) is False


def test_a_timeout_that_clears_on_the_second_ask_is_not_a_break() -> None:
    """A 504 on the first ask that clears on the second is read as the second answer: a clean row
    stays clean, and the check does not fail (BACKLOG #8222)."""
    cipher = _scripted_cipher([_status_error(504), None])
    assert cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row")) is True


def test_a_504_hvac_could_not_parse_still_reads_as_a_timeout() -> None:
    """hvac raises ``TypeError`` or ``AttributeError``, not ``UnexpectedError``, for a 504 whose
    JSON ``errors`` it cannot join; the recorded status still makes it a timeout (BACKLOG #8222)."""
    _needs_hvac()
    import requests

    from messagefoundry.store import keyprovider_vault
    from messagefoundry.store.keyprovider_vault import is_vault_timeout_reply

    client = keyprovider_vault._build_client(
        "https://vault.example.test:8200", "s.synthetic-token", revocation_attested=True
    )
    for body in (b'{"errors":[{"message":"upstream timed out"}]}', b"null", b"[]"):
        reply = requests.Response()
        reply.status_code = 504
        reply.headers["Content-Type"] = "application/json"
        reply._content = body
        with pytest.raises(Exception) as caught:
            client.adapter._raise_for_error("POST", "https://vault.example.test:8200/v1/x", reply)
        assert is_vault_timeout_reply(caught.value), (body, type(caught.value))


def test_a_413_on_one_rows_verify_is_still_a_break() -> None:
    """A 413 is what Vault answers a planted oversize row, so it stays evidence about that row: a
    break, not a check that could not run, though hvac raises it as the same class as a 504."""
    cipher = _scripted_cipher([_status_error(413), _status_error(413)])
    assert cipher.verify_audit_hmac(b"row", cipher.audit_hmac(b"row")) is False


async def test_a_persistent_504_on_one_rows_verify_could_not_run_on_the_startup_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The startup walk over a clean chain whose last row's verify answers 504 every time, while
    the fixed input and every other row verify: no tamper alert, and the walk could not run
    (BACKLOG #8222 item 1)."""
    _needs_hvac()
    from messagefoundry.store.crypto_transit import _VERSION_PROBE_INPUT

    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    store = await _transit_store(tmp_path / "timeout.db")
    try:
        await store.record_audit("test.clean", actor="cli:tester")
        real_verify = transit.verify_signed_data
        last_mac = _dml_last_row_hash(tmp_path / "timeout.db")
        others: list[str] = []

        def timing_out(*, hash_input: str, hmac: str, **kw: Any) -> dict[str, Any]:
            if hash_input != _VERSION_PROBE_INPUT and hmac == last_mac:
                raise _status_error(504)
            if hash_input != _VERSION_PROBE_INPUT:
                others.append(hmac)
            return real_verify(hash_input=hash_input, hmac=hmac, **kw)

        monkeypatch.setattr(transit, "verify_signed_data", timing_out)
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert others, "the control: the rows before the last one verified"
    assert sink.events == []
    assert any("could not run" in line for line in lines), lines


def _dml_last_row_hash(db: Path) -> str:
    """The stored MAC of the newest audit row, read directly from the SQLite file."""
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    assert row is not None and isinstance(row[0], str)
    return row[0]


def test_a_504_through_the_store_clients_request_path_reads_as_a_timeout() -> None:
    """A Transit ``verify`` call made through the store's real hvac client, whose session answers
    504, raises an error that reads as a timeout: hvac's request path goes through the recorded
    ``_raise_for_error`` (BACKLOG #8222)."""
    _needs_hvac()
    import requests

    from messagefoundry.store import keyprovider_vault
    from messagefoundry.store.keyprovider_vault import is_vault_timeout_reply

    client = keyprovider_vault._build_client(
        "https://vault.example.test:8200", "s.synthetic-token", revocation_attested=True
    )

    def answer_504(*_a: Any, **_kw: Any) -> requests.Response:
        reply = requests.Response()
        reply.status_code = 504
        reply._content = b"<html>gateway timeout</html>"
        return reply

    client.adapter.session.request = answer_504
    with pytest.raises(Exception) as caught:
        client.secrets.transit.verify_signed_data(
            name=_KEY_NAME, hash_input="cm93", hmac="vault:v1:AAAA", hash_algorithm="sha2-256"
        )
    assert is_vault_timeout_reply(caught.value), type(caught.value)


def test_the_store_vault_client_records_the_reply_status_on_hvacs_error() -> None:
    """The client the store's Transit cipher is built from records each failed reply's status, so
    a 504 is told from a 413 that hvac raises as the same class (BACKLOG #8222)."""
    _needs_hvac()
    import requests
    from hvac.exceptions import UnexpectedError

    from messagefoundry.store import keyprovider_vault
    from messagefoundry.store.keyprovider_vault import is_vault_timeout_reply

    client = keyprovider_vault._build_client(
        "https://vault.example.test:8200", "s.synthetic-token", revocation_attested=True
    )
    for status, timeout in ((504, True), (408, True), (413, False), (412, False)):
        reply = requests.Response()
        reply.status_code = status
        with pytest.raises(UnexpectedError) as caught:
            client.adapter._raise_for_error("POST", "https://vault.example.test:8200/v1/x", reply)
        assert is_vault_timeout_reply(caught.value) is timeout, status
    assert not is_vault_timeout_reply(UnexpectedError("no status recorded"))


def _transit_to_in_heap_chain(cipher: Any) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """A chain whose first range is MAC'd in Transit under ``cipher`` and whose second is under an
    in-heap key, so its range row carries a handover tag Transit made."""
    from messagefoundry.store.crypto import audit_key_id, generate_key
    from messagefoundry.store.store import (
        AUDIT_KEY_EPOCH_ACTION,
        AUDIT_TRANSIT_KEY_ID,
        audit_genesis_detail,
        audit_handover_tag,
        audit_range_closing,
        audit_row_hash,
        audit_scheme_for,
    )
    from tests.audit_chain_cases import _mac_key, epoch_record

    mac_fn = cipher.audit_mac_fn()
    b_mac = _mac_key(generate_key())
    b_id = audit_key_id(b_mac)
    rows: list[dict[str, Any]] = []

    def add(action: str, detail: str, key: bytes | None) -> None:
        row: dict[str, Any] = {
            "id": len(rows) + 1,
            "seq": len(rows) + 1,
            "ts": float(len(rows) + 1),
            "actor": "u",
            "action": action,
            "channel_id": None,
            "detail": detail,
            "client": None,
        }
        prev = rows[-1]["row_hash"] if rows else ""
        fields = {k: v for k, v in row.items() if k != "id"}
        row["row_hash"] = audit_row_hash(
            prev, **fields, key=key, mac=None if key is not None else mac_fn
        )
        rows.append(row)

    add(AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID), None)
    add("act", "{}", None)
    closes = audit_range_closing(rows, key_id=AUDIT_TRANSIT_KEY_ID, from_seq=1, prev_hash="")
    scheme = audit_scheme_for(b_id)
    tag = audit_handover_tag(b_id, closes, (None, mac_fn), scheme=scheme)
    add(AUDIT_KEY_EPOCH_ACTION, epoch_record(b_id, closes, tag, scheme), b_mac)
    add("act", "{}", b_mac)
    return rows, {b_id: b_mac}


def _malformed_handover_walk(reply: object) -> Any:
    """The walk over :func:`_transit_to_in_heap_chain` once Transit answers every ``hmac`` with
    ``reply``, the regenerated handover tag among them."""
    from messagefoundry.store.crypto_transit import TransitCipher
    from messagefoundry.store.store import verify_audit_rows
    from tests.test_crypto_transit import _FakeClient

    transit = _RotatingTransit()
    cipher = TransitCipher(_FakeClient(transit), _KEY_NAME)
    rows, keys = _transit_to_in_heap_chain(cipher)
    ok, message = verify_audit_rows(rows, mac_keys=keys, mac_fn=cipher.audit_mac_fn(), capable=True)
    assert ok, message  # the control: the chain verifies while Transit answers well-formed MACs

    def malformed(**_kw: Any) -> dict[str, Any]:
        return {"data": {"hmac": reply}}

    transit.generate_hmac = malformed  # type: ignore[method-assign]
    return verify_audit_rows(rows, mac_keys=keys, mac_fn=cipher.audit_mac_fn(), capable=True)


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param("vault:not-a-version", id="names-no-version"),
        pytest.param("vault:v1:AAAA", id="short-digest"),
    ],
)
def test_a_malformed_transit_reply_to_a_handover_tag_is_a_break_in_the_walk(reply: str) -> None:
    """A non-empty Transit reply that is no well-formed MAC, such as one naming no key version,
    to the walk's regeneration of a range row's handover tag reads as a tag that does not match: a
    break at that range row, as before engine PR 2903, never a walk that could not run (BACKLOG
    #8222 item 5, owner ruling 2026-11-13)."""
    ok, message = _malformed_handover_walk(reply)
    assert not ok and "seq=3" in (message or "") and "not authorised" in (message or ""), message


@pytest.mark.parametrize("reply", [pytest.param("", id="empty"), pytest.param(None, id="none")])
def test_an_empty_or_non_text_transit_reply_to_a_handover_tag_still_could_not_run(
    reply: object,
) -> None:
    """An empty or non-string reply raised a plain cipher error before engine PR 2903 too, so it
    still ends the walk as one that could not run."""
    from messagefoundry.store.crypto import AuditMacMalformedError

    with pytest.raises(CipherError) as caught:
        _malformed_handover_walk(reply)
    assert not isinstance(caught.value, AuditMacMalformedError)


class _MalformedHandoverTransit(_RotatingTransit):
    """``_RotatingTransit`` that answers the ``hmac`` of a handover tag, and nothing else, with a
    non-empty string naming no key version."""

    def generate_hmac(self, *, hash_input: str, **kw: Any) -> dict[str, Any]:
        from messagefoundry.store.store import _AUDIT_HANDOVER_INFO

        if base64.b64decode(hash_input).startswith(_AUDIT_HANDOVER_INFO):
            return {"data": {"hmac": "vault:not-a-version"}}
        return super().generate_hmac(hash_input=hash_input, **kw)


async def test_a_malformed_handover_reply_at_open_still_refuses_the_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A planted range row closing the Transit range, whose handover tag Transit answers with no
    well-formed MAC, still refuses the store open, as on engine PR 2903: the open path is unruled
    and on the owner's queue (BACKLOG #8222 item 5). This pins the limit: while the open refuses,
    the walk's reading of such a row as a break is not observable for it."""
    _needs_hvac()
    from messagefoundry.store.crypto import audit_key_id, generate_key
    from messagefoundry.store.store import (
        AUDIT_KEY_EPOCH_ACTION,
        AUDIT_TRANSIT_KEY_ID,
        audit_range_closing,
        audit_scheme_for,
    )
    from tests.audit_chain_cases import _mac_key, epoch_record

    _use_fake(monkeypatch, _MalformedHandoverTransit())
    db = tmp_path / "handover.db"
    store = await _transit_store(db)
    try:
        await store.record_audit("test.before", actor="cli:tester")
    finally:
        await store.close()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in con.execute("SELECT * FROM audit_log ORDER BY seq")]
    finally:
        con.close()
    b_id = audit_key_id(_mac_key(generate_key()))
    closes = audit_range_closing(rows, key_id=AUDIT_TRANSIT_KEY_ID, from_seq=1, prev_hash="")
    seq = len(rows) + 1
    detail = epoch_record(b_id, closes, "vault:v1:planted", audit_scheme_for(b_id))
    _dml(
        db,
        "INSERT INTO audit_log (seq, ts, actor, action, detail, row_hash) VALUES (?, ?, ?, ?, ?, ?)",
        (seq, time.time(), "cli:tester", AUDIT_KEY_EPOCH_ACTION, detail, "0" * 64),
    )
    from messagefoundry.store.crypto import AuditMacMalformedError

    with pytest.raises(AuditMacMalformedError):
        await _transit_store(db)


#: Vault's own text for an audit-MAC call refused for its version, as hvac carries it.
_VERSION_400 = ("key version does not exist; latest key version is 2",)
#: A proxy's or WAF's own 400 page: no Vault JSON at all.
_PROXY_PAGE = "<html><body><h1>400 Bad Request</h1></body></html>"


#: A well-formed stored MAC naming key version 3, as the cipher's verify call is handed one.
_V3_MAC = "vault:v3:" + base64.b64encode(bytes(32)).decode("ascii")


def _verify_refusal(
    answer: Any, errors: Any = _VERSION_400, *, text: str | None = None
) -> CipherError:
    """What the cipher raises when its verify of a MAC naming version 3 gets a 400 carrying
    ``errors`` (hvac's ``errors`` list) and body ``text``, and the probe gets ``answer`` (a reply,
    or an exception to raise)."""
    _needs_hvac()
    from hvac.exceptions import InvalidRequest

    from messagefoundry.store.crypto_transit import TransitCipher
    from tests.test_crypto_transit import _FakeClient

    class _Transit(_FakeTransit):
        def verify_signed_data(self, **_kw: Any) -> dict[str, Any]:
            listed = list(errors) if errors is not None else None
            raise InvalidRequest("bad request", errors=listed, text=text)

        def generate_hmac(self, **_kw: Any) -> dict[str, Any]:
            if isinstance(answer, Exception):
                raise answer
            return {"data": {"hmac": answer}}

    cipher = TransitCipher(_FakeClient(_Transit()), _KEY_NAME)
    with pytest.raises(CipherError) as caught:
        cipher.verify_audit_hmac(b"row", _V3_MAC)
    return caught.value


def test_a_verify_400_with_a_working_probe_is_a_refused_version() -> None:
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    assert isinstance(_verify_refusal("vault:v2:AAAA"), AuditKeyVersionRefusedError)


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(RuntimeError("key not found"), id="probe-fails"),
        pytest.param("vault:v3:AAAA", id="probe-names-the-same-version"),
    ],
)
def test_a_verify_400_the_probe_does_not_clear_is_a_plain_cipher_error(answer: Any) -> None:
    """A missing key also answers 400, and so may a refusal that has nothing to do with the version.
    Neither may read as a planted version. Here every verify fails, the fixed-input one included,
    so the check could not run rather than read as the row's."""
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    assert not isinstance(_verify_refusal(answer), AuditKeyVersionRefusedError)


@pytest.mark.parametrize(
    ("errors", "text"),
    [
        pytest.param(["no such key version"], None, id="known-refusal-text"),
        pytest.param(
            ["cannot generate HMAC: version is too old (disallowed by policy)"],
            None,
            id="known-policy-refusal",
        ),
        pytest.param(["key version 3 is not held by this key"], None, id="unknown-wording"),
        pytest.param(
            ["no such key version", "missing input for HMAC"], None, id="refusal-beside-non-version"
        ),
        pytest.param(
            ["missing input for HMAC: and more"], None, id="non-version-only-as-substring"
        ),
        pytest.param([], None, id="empty-vault-list"),
        pytest.param(["invalid HMAC: version is too new"], None, id="verify-too-new"),
        pytest.param(
            ["invalid HMAC: version is too new", "encryption key not found"],
            None,
            id="verify-too-new-beside-non-version",
        ),
        pytest.param(
            ["cannot verify HMAC: version is too old (disallowed by policy)"],
            None,
            id="verify-below-min-decryption",
        ),
        pytest.param(None, '{"errors": ["no such key version"]}', id="vault-json-in-text-only"),
        pytest.param(None, '{"errors": ["reworded refusal"]}', id="unknown-wording-in-text-only"),
    ],
)
def test_a_verify_400_read_as_a_version_refusal_keeps_the_refused_label(
    errors: Any, text: str | None
) -> None:
    """BACKLOG #6707: a 400 whose ``errors`` value is a list is labelled a refused version unless
    that list is non-empty and holds only whole known non-version texts. An empty list and unknown
    Vault wording keep that label, so a reworded refusal on an upgraded Vault is labelled as
    before. hvac fills ``errors`` only for a Content-Type of exactly ``application/json``, so the
    same JSON in the body (a charset-tagged reply) must read the same way."""
    from messagefoundry.store.crypto import (
        AuditKeyVersionRefusedError,
        AuditKeyVersionUnverifiedError,
    )

    refused = _verify_refusal("vault:v2:AAAA", errors, text=text)
    assert isinstance(refused, AuditKeyVersionRefusedError)
    assert not isinstance(refused, AuditKeyVersionUnverifiedError)


@pytest.mark.parametrize(
    ("errors", "text"),
    [
        pytest.param(None, _PROXY_PAGE, id="proxy-page"),
        pytest.param(None, None, id="no-body"),
        pytest.param(None, '["no such key version"]', id="json-but-not-vault-shaped"),
        pytest.param(None, '{"message": "bad request"}', id="json-without-errors"),
        pytest.param(["missing input for HMAC"], None, id="known-non-version-text"),
        pytest.param(["  Encryption key not found "], None, id="known-non-version-any-case"),
    ],
)
def test_a_verify_400_not_read_as_a_version_refusal_is_labelled_unconfirmed(
    errors: Any, text: str | None
) -> None:
    """BACKLOG #6707: after a rotation the probe answers under a newer version, so the probe alone
    labelled ANY 400 on a check a refused version. A 400 with no ``errors`` value that is a list, even
    one whose reply holds a refusal text elsewhere, or with a list of only whole known non-version
    texts, is labelled unconfirmed instead. It stays a subclass, so its handlers handle the row as
    on main."""
    from messagefoundry.store.crypto import AuditKeyVersionUnverifiedError

    refused = _verify_refusal("vault:v2:AAAA", errors, text=text)
    assert isinstance(refused, AuditKeyVersionUnverifiedError)
    assert str(refused) == (
        "the Transit audit MAC check at key version 3 got HTTP 400 that was not read as a "
        "version refusal, so the version could not be confirmed; the key may not hold it, or its "
        "policy may retire it"
    )
    assert _KEY_NAME not in str(refused)  # the walk puts this text in the tamper alert


def test_a_proxy_400_the_probe_does_not_clear_is_a_plain_cipher_error() -> None:
    """The label changes nothing else: a proxy 400 whose probe also fails is an outage, as on main."""
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    refused = _verify_refusal(RuntimeError("down"), None, text=_PROXY_PAGE)
    assert not isinstance(refused, AuditKeyVersionRefusedError)


def test_a_non_text_entry_in_vault_errors_is_labelled_a_refused_version() -> None:
    """A Vault error list holding an entry that is not text could name the version, so it keeps
    the refused-version label (BACKLOG #6707)."""
    _needs_hvac()
    from hvac.exceptions import InvalidRequest

    from messagefoundry.store.crypto_transit import _names_no_version_reason

    exc = InvalidRequest(errors=["missing input for HMAC"])
    exc.errors = ["missing input for HMAC", 7]  # hvac's constructor joins entries, so set it after
    assert not _names_no_version_reason(exc)


class _ProxiedRotatingTransit(_RotatingTransit):
    """``_RotatingTransit`` behind a proxy that replaces every 400 reply with its own: the body
    ``page`` and, as hvac fills it from JSON, the ``errors`` list."""

    page: str | None = _PROXY_PAGE
    errors: list[str] | None = None

    def verify_signed_data(self, **kw: Any) -> dict[str, Any]:
        from hvac.exceptions import InvalidRequest

        try:
            return super().verify_signed_data(**kw)
        except InvalidRequest:
            raise InvalidRequest(self.page, errors=self.errors, text=self.page) from None


async def test_a_planted_version_behind_a_proxy_is_a_chain_break_on_the_startup_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #6707: a proxy's page in place of Transit's refusal changes the label only. The walk
    still reports the planted row as a break, raises the tamper alert and keeps going."""
    _needs_hvac()
    _use_fake(monkeypatch, _ProxiedRotatingTransit())
    db = tmp_path / "proxied-planted.db"
    seq = await _chain_with_a_planted_version(db)
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert f"check at key version {_UNHELD_VERSION} got HTTP 400" in str(msg), msg
    assert [name for name, _ in sink.events] == ["audit-chain"], sink.events
    assert not any("could not run" in line for line in lines), lines


async def test_a_planted_genesis_version_behind_a_proxy_opens_and_reads_as_a_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """BACKLOG #6707: the genesis row behaves as on main behind a proxy too; the open goes on."""
    _needs_hvac()
    _use_fake(monkeypatch, _ProxiedRotatingTransit())
    db = tmp_path / "proxied-genesis.db"
    await _chain_with_a_planted_version(db)
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = 1", (_PLANTED,))
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and "seq=1," in str(msg), msg


def _past_the_reparse_bound(head: str, tail: str, *, over: int = 1) -> str:
    """``head`` + padding + ``tail``, ``over`` characters longer than the longest body the cipher
    re-parses (0 gives a body of exactly that length)."""
    from messagefoundry.store.crypto_transit import _REPARSED_BODY_MAX_CHARS

    return head + " " * (_REPARSED_BODY_MAX_CHARS + over - len(head) - len(tail)) + tail


def test_an_oversized_vault_shaped_body_is_labelled_unconfirmed_unparsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #6707 item 48: a body past the bound is never parsed, so a huge reply cannot raise
    a MemoryError out of the label. It is labelled unconfirmed, even though it holds Vault's own
    refusal text."""
    from messagefoundry.store import crypto_transit
    from messagefoundry.store.crypto import AuditKeyVersionUnverifiedError

    def must_not_parse(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("an oversized body was parsed")

    monkeypatch.setattr(crypto_transit, "json_loads_or_refusal", must_not_parse)
    body = _past_the_reparse_bound('{"errors": ["no such key version"], "pad": "', '"}')
    assert len(body) == crypto_transit._REPARSED_BODY_MAX_CHARS + 1
    assert isinstance(
        _verify_refusal("vault:v2:AAAA", None, text=body), AuditKeyVersionUnverifiedError
    )


def test_a_vault_shaped_body_at_the_bound_is_still_read() -> None:
    """The bound is inclusive: a body of exactly ``_REPARSED_BODY_MAX_CHARS`` is parsed, so its
    refusal text keeps the refused-version label (BACKLOG #6707)."""
    from messagefoundry.store.crypto import (
        AuditKeyVersionRefusedError,
        AuditKeyVersionUnverifiedError,
    )

    body = _past_the_reparse_bound('{"errors": ["no such key version"], "pad": "', '"}', over=0)
    refused = _verify_refusal("vault:v2:AAAA", None, text=body)
    assert isinstance(refused, AuditKeyVersionRefusedError)
    assert not isinstance(refused, AuditKeyVersionUnverifiedError)


def test_a_body_hvac_already_parsed_is_not_parsed_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """hvac sets ``json`` when it parsed the reply; an ``errors`` it did not find there is not
    looked for in the same text again (BACKLOG #6707)."""
    _needs_hvac()
    from hvac.exceptions import InvalidRequest

    from messagefoundry.store import crypto_transit

    def must_not_parse(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("a body hvac parsed was parsed again")

    monkeypatch.setattr(crypto_transit, "json_loads_or_refusal", must_not_parse)
    reply = '{"message": "bad request"}'
    exc = InvalidRequest(reply, text=reply, json={"message": "bad request"})
    assert crypto_transit._names_no_version_reason(exc)


class _PaddedProxiedRotatingTransit(_ProxiedRotatingTransit):
    """A proxy whose 400 page is padded past the body the cipher re-parses."""

    page = _past_the_reparse_bound(_PROXY_PAGE, "")


class _ExplodingText(str):
    """An ``errors`` entry whose ``strip``, the first step of the cipher's lower-cased copy, fails
    as copying a huge list would: with MemoryError."""

    __slots__ = ()

    def strip(self, chars: str | None = None) -> str:
        raise MemoryError


class _HugeErrorsRotatingTransit(_ProxiedRotatingTransit):
    """A 400 carrying a huge Vault ``errors`` list, as hvac fills it, and no body to re-parse."""

    page = None
    errors = [_ExplodingText("no such key version")] * 20_000


@pytest.mark.parametrize(
    "transit_class",
    [
        pytest.param(_PaddedProxiedRotatingTransit, id="oversized-body"),
        pytest.param(_HugeErrorsRotatingTransit, id="oversized-errors-list"),
    ],
)
async def test_a_reply_too_large_to_read_is_still_a_chain_break_on_the_startup_walk(
    transit_class: type[_RotatingTransit],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #6707 item 48: a MemoryError while reading the 400 must not escape as a non-cipher
    error, or the walk logs "could not run" and drops the row's break and its alert. The parser
    raises MemoryError if it is reached at all, and it must not be reached for a body past the
    bound; a huge ``errors`` list, which hvac parsed, fails in the lower-cased copy instead."""
    from messagefoundry.store import crypto_transit

    parsed: list[int] = []

    def out_of_memory(raw: str, **_kw: Any) -> Any:
        parsed.append(len(raw))
        raise MemoryError

    monkeypatch.setattr(crypto_transit, "json_loads_or_refusal", out_of_memory)
    _needs_hvac()
    _use_fake(monkeypatch, transit_class())
    db = tmp_path / "oversized-reply.db"
    seq = await _chain_with_a_planted_version(db)
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert f"check at key version {_UNHELD_VERSION} got HTTP 400" in str(msg), msg
    assert [name for name, _ in sink.events] == ["audit-chain"], sink.events
    assert f"seq={seq}," in sink.events[0][1], sink.events
    assert not any("could not run" in line for line in lines), lines
    # For the padded body the bound, not the MemoryError catch, kept the parser away; hvac's own
    # errors list is never re-parsed at all.
    assert parsed == [], parsed


def test_a_refused_key_version_survives_a_pickle_with_its_text() -> None:
    import pickle

    from messagefoundry.store.crypto import (
        AuditKeyVersionRefusedError,
        AuditKeyVersionUnverifiedError,
    )

    exc = AuditKeyVersionRefusedError(7)
    again = pickle.loads(pickle.dumps(exc))
    assert isinstance(again, AuditKeyVersionRefusedError) and isinstance(again, CipherError)
    assert again.version == 7 and str(again) == str(exc)
    unverified = AuditKeyVersionUnverifiedError(7)
    back = pickle.loads(pickle.dumps(unverified))
    assert isinstance(back, AuditKeyVersionUnverifiedError)
    assert back.version == 7 and str(back) == str(unverified)


def test_cli_audit_verify_exits_1_on_a_planted_unheld_key_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio

    _use_fake(monkeypatch, _RotatingTransit())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    db = tmp_path / "planted-cli.db"
    seq = asyncio.run(_chain_with_a_planted_version(db))
    rc = main(["audit-verify", "--db", str(db)])
    captured = capsys.readouterr()
    assert rc == 1, captured
    assert f"seq={seq}," in captured.out + captured.err, captured


async def test_a_non_numeric_attested_at_is_a_gap_not_a_crash(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """SQLite's REAL affinity keeps text. The row must read as unattested, warn must still start,
    and the withdraw must still remove it."""
    await _attest(store)
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, "UPDATE transit_bound_attestation SET attested_at = 'x' WHERE id = 1")
    again = await _transit_store(db)
    got = await again.get_transit_bound_attestation()
    assert got is not None and got.audit_gap is not None and "finite" in got.audit_gap
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.transit_attestation"):
        await _start(again, SecurityEnforcement.WARN)  # no raise
    third = await _transit_store(db)
    try:
        assert await _withdraw(third) is not None
        assert await third.get_transit_bound_attestation() is None
        [withdrawn] = _audit_rows(db, TRANSIT_BOUND_WITHDRAWN_ACTION)
        assert json.loads(withdrawn["detail"])["attested_at"] is None
    finally:
        await third.close()


async def test_warn_names_the_audit_gap(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, _INSERT, (_KEY_NAME, "forged", "cli:tester", time.time(), 9999, "0" * 64))
    again = await _transit_store(db)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.transit_attestation"):
        await _start(again, SecurityEnforcement.WARN)
    assert any("not backed by its audit row" in r.getMessage() for r in caplog.records)


# --- the store rows ------------------------------------------------------------------------------


def _audit_rows(db: Path, action: str) -> list[sqlite3.Row]:
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(
            "SELECT actor, ts, detail FROM audit_log WHERE action = ? ORDER BY id", (action,)
        ).fetchall()
    finally:
        con.close()


async def test_record_replaces_and_withdraw_of_nothing_writes_no_audit_row(
    store: MessageStore, tmp_path: Path
) -> None:
    commits = store.committed_txns
    assert await _withdraw(store) is None
    assert store.committed_txns == commits  # rolled back, not an empty commit
    assert _audit_rows(tmp_path / "transit.db", TRANSIT_BOUND_WITHDRAWN_ACTION) == []
    await _attest(store, key_name="first")
    recorded = await _attest(store, key_name=_KEY_NAME)
    current = await store.get_transit_bound_attestation()
    assert current == recorded and current.audit_gap is None
    assert current.key_name == _KEY_NAME and current.actor == "cli:tester"
    [_, newest] = _audit_rows(tmp_path / "transit.db", TRANSIT_BOUND_ATTESTED_ACTION)
    assert json.loads(newest["detail"])["key_name"] == _KEY_NAME


async def test_a_refused_audit_append_records_no_attestation(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*_a: object, **_k: object) -> object:
        raise RuntimeError("audit append refused")

    monkeypatch.setattr(store, "_append_audit_row", refuse)
    with pytest.raises(RuntimeError, match="audit append refused"):
        await _attest(store)
    monkeypatch.undo()
    assert await store.get_transit_bound_attestation() is None


# --- the CLI -------------------------------------------------------------------------------------


@pytest.fixture
def transit_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A SQLite store on fake Transit, closed, with the CLI's environment pointed at it."""
    import asyncio

    _use_fake(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    db = tmp_path / "cli.db"

    async def make() -> None:
        await (await _transit_store(db)).close()

    asyncio.run(make())
    return db


def _read(db: Path) -> TransitBoundAttestation | None:
    import asyncio

    async def read() -> TransitBoundAttestation | None:
        s = await _transit_store(db)
        try:
            return await s.get_transit_bound_attestation()
        finally:
            await s.close()

    return asyncio.run(read())


def test_cli_record_and_withdraw_write_audit_rows_with_actor_and_time(
    transit_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = time.time()
    reason = "Transit auto_rotate_period is 720h"
    rc = main(
        ["store", "attest-transit-bound", "--reason", reason, "--db", str(transit_db), "--json"]
    )
    assert rc == 0, capsys.readouterr()
    out = json.loads(capsys.readouterr().out)
    actor = f"cli:{getpass.getuser()}"
    assert out["action"] == "attested" and out["attestation"]["key_name"] == _KEY_NAME

    recorded = _read(transit_db)
    assert recorded is not None
    assert (recorded.key_name, recorded.reason, recorded.actor) == (_KEY_NAME, reason, actor)
    assert recorded.attested_at >= before

    [attested] = _audit_rows(transit_db, TRANSIT_BOUND_ATTESTED_ACTION)
    assert attested["actor"] == actor and attested["ts"] >= before
    assert json.loads(attested["detail"]) == {"key_name": _KEY_NAME, "reason": reason}

    assert main(["store", "withdraw-transit-bound", "--db", str(transit_db)]) == 0
    assert "withdrew" in capsys.readouterr().out
    assert _read(transit_db) is None
    [withdrawn] = _audit_rows(transit_db, TRANSIT_BOUND_WITHDRAWN_ACTION)
    assert withdrawn["actor"] == actor and withdrawn["ts"] >= attested["ts"]
    detail = json.loads(withdrawn["detail"])
    assert detail["key_name"] == _KEY_NAME and detail["attested_by"] == actor


def test_cli_record_refuses_a_blank_reason(
    transit_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["store", "attest-transit-bound", "--reason", "  ", "--db", str(transit_db)])
    assert rc == 1
    assert "--reason" in capsys.readouterr().err
    assert _read(transit_db) is None


def test_cli_reason_is_bounded_in_utf16_code_units(
    transit_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """600 characters outside the Basic Multilingual Plane are 1200 UTF-16 code units, which SQL
    Server's NVARCHAR(1000) cannot hold, although a code-point count would pass them."""
    reason = "\U0001f512" * 600
    rc = main(["store", "attest-transit-bound", "--reason", reason, "--db", str(transit_db)])
    assert rc == 1
    assert "UTF-16" in capsys.readouterr().err
    assert _read(transit_db) is None


def test_cli_a_write_the_store_refuses_is_exit_1_not_a_failed_open(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A SQLite error from the WRITE, such as a locked file, is a refused write (exit 1), not
    "cannot open the store" (exit 2), although both are sqlite3.DatabaseError."""

    async def locked(*_a: object, **_k: object) -> object:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(MessageStore, "record_transit_bound_attestation", locked)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 1, err
    assert "refused the write" in err and "database is locked" in err
    assert "cannot open" not in err
    assert "stop it and re-run" in err  # a SQLite lock is the one case the hint is for


def test_cli_a_close_that_fails_after_the_write_does_not_report_it_refused(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The attestation has committed when the close runs, so a failed close warns and the result
    stands: exit 0, not "the store refused the write, so nothing was recorded"."""
    real_close = MessageStore.close

    async def failing_close(self: MessageStore) -> None:
        await real_close(self)
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(MessageStore, "close", failing_close)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "refused the write" not in captured.err
    assert "closing the store failed" in captured.err
    monkeypatch.setattr(MessageStore, "close", real_close)
    assert _read(transit_db) is not None

    # The withdraw twin: its write has committed too, so the row is gone and the exit is 0.
    monkeypatch.setattr(MessageStore, "close", failing_close)
    rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "withdrew" in captured.out, captured.out
    assert "refused the write" not in captured.err
    assert "closing the store failed" in captured.err
    monkeypatch.setattr(MessageStore, "close", real_close)
    assert _read(transit_db) is None


def test_cli_a_file_that_is_not_a_database_is_exit_2(
    transit_db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not a SQLite database, just some bytes" * 100)
    rc = main(["store", "withdraw-transit-bound", "--db", str(junk)])
    assert rc == 2
    assert "cannot open the store" in capsys.readouterr().err


def test_cli_a_store_that_cannot_be_reached_is_exit_2(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A server backend refusing the connection fails in the OPEN: exit 2, not a refused write."""
    import messagefoundry.store.base as store_base

    async def unreachable(*_a: object, **_k: object) -> object:
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(store_base, "open_store", unreachable)
    rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert "cannot open the store" in err and "refused the write" not in err


# The two commands, each with what it needs to reach the store's write.
_TRANSIT_ARMS = {
    "attest": (
        ["store", "attest-transit-bound", "--reason", "r"],
        "record_transit_bound_attestation",
    ),
    "withdraw": (["store", "withdraw-transit-bound"], "withdraw_transit_bound_attestation"),
}
# A server's text can quote a stored value. Each error below carries this marker in its text, and
# no line the commands print may carry it.
_ROW_TEXT = "ROWMARKER"


def _stand_in_server_drivers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stand-ins from the audit-verify tests, with pyodbc's root stand-in also read as a server
    driver's error, as the real ``pyodbc.Error`` is. pyodbc is not installed on every leg."""
    from messagefoundry.store import base as store_base
    from tests.test_keyless_chain_every_command import (
        _PyodbcError,
        _ServerDriverError,
        _stand_in_drivers,
    )

    _stand_in_drivers(monkeypatch)
    real = store_base._is_server_driver_error
    monkeypatch.setattr(
        store_base,
        "_is_server_driver_error",
        lambda exc: isinstance(exc, (_ServerDriverError, _PyodbcError)) or real(exc),
    )


def _open_error(kind: str) -> Exception:
    """Built per test, so no instance carries one test's traceback into the next."""
    from tests.test_keyless_chain_every_command import _InterfaceError, _ServerDriverError

    if kind == "login":
        return _InterfaceError(
            "28000", f"[28000] Login failed for user '{_ROW_TEXT}' (18456) (SQLDriverConnect)"
        )
    return _ServerDriverError("42P01", f'relation "{_ROW_TEXT}" does not exist')


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
@pytest.mark.parametrize("kind", ["login", "relation"])
def test_cli_a_server_driver_error_at_the_open_is_exit_2_and_its_text_is_not_printed(
    arm: str,
    kind: str,
    transit_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed login (pyodbc's InterfaceError) or a missing relation at the open is "could not
    start", exit 2, in the line the audit commands print, with the error's class and SQLSTATE and
    never the server's text."""
    import messagefoundry.store.base as store_base

    _stand_in_server_drivers(monkeypatch)
    error = _open_error(kind)

    async def refusing(*_a: object, **_k: object) -> object:
        raise error

    monkeypatch.setattr(store_base, "open_store", refusing)
    argv, _ = _TRANSIT_ARMS[arm]
    rc = main([*argv, "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 2, captured.err
    assert f"cannot open the store at {transit_db}: " in captured.err, captured.err
    assert f"SQLSTATE {error.args[0]}" in captured.err, captured.err
    assert _ROW_TEXT not in captured.out + captured.err
    assert "refused the write" not in captured.err


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
def test_cli_a_deadlock_at_the_write_is_a_refused_write_and_its_text_is_not_printed(
    arm: str, transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """pyodbc raises its bare Error root for a deadlock victim (40001). The server rolled the
    transaction back, so it is a refused write, exit 1, rendered as its class, SQLSTATE and native
    number. The stop-the-engine hint is for a SQLite lock only."""
    from tests.test_keyless_chain_every_command import _PyodbcError

    _stand_in_server_drivers(monkeypatch)
    argv, method = _TRANSIT_ARMS[arm]

    async def refusing(*_a: object, **_k: object) -> object:
        raise _PyodbcError("40001", f"[40001] deadlock on {_ROW_TEXT} (1205) (SQLExecDirectW)")

    monkeypatch.setattr(MessageStore, method, refusing)
    rc = main([*argv, "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "refused the write" in captured.err, captured.err
    assert "SQLSTATE 40001] native error 1205" in captured.err, captured.err
    assert _ROW_TEXT not in captured.out + captured.err
    assert "stop it and re-run" not in captured.err
    if arm == "withdraw":
        assert "nothing was withdrawn, and any attestation on record still stands" in captured.err


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
def test_cli_a_link_lost_at_the_write_reports_an_unknown_outcome(
    arm: str, transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A lost link (SQLSTATE 08S01, a DatabaseError subclass in pyodbc) may land after the server
    applied the COMMIT, so the line claims neither outcome. Exit 1, and the driver's text hidden."""
    from tests.test_keyless_chain_every_command import _ServerDriverError

    _stand_in_server_drivers(monkeypatch)
    argv, method = _TRANSIT_ARMS[arm]

    async def refusing(*_a: object, **_k: object) -> object:
        raise _ServerDriverError(
            "08S01", f"[08S01] link failure reading {_ROW_TEXT} (10054) (SQLExecDirectW)"
        )

    monkeypatch.setattr(MessageStore, method, refusing)
    rc = main([*argv, "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "whether it took effect is unknown" in captured.err, captured.err
    assert "SQLSTATE 08S01] native error 10054" in captured.err, captured.err
    assert "nothing was" not in captured.err
    assert _ROW_TEXT not in captured.out + captured.err


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
def test_cli_pyodbcs_bare_error_root_at_the_write_is_a_defect_not_a_refused_write(
    arm: str,
    transit_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """pyodbc raises its bare ``Error`` root for a SQLSTATE it does not map, such as 07002, a bind
    count that does not match the statement: a defect in the code. The write arm counts the root as
    a refusal only with a transient SQLSTATE, so the dispatch floor reports this one."""
    from tests.test_keyless_chain_every_command import _PyodbcError

    _stand_in_server_drivers(monkeypatch)
    argv, method = _TRANSIT_ARMS[arm]

    async def defect(*_a: object, **_k: object) -> object:
        raise _PyodbcError("07002", f"[07002] COUNT field incorrect near {_ROW_TEXT}")

    monkeypatch.setattr(MessageStore, method, defect)
    rc = main([*argv, "--db", str(transit_db), "--json"])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "refused the write" not in captured.out + captured.err
    # The dispatch floor's line names the defect by class and SQLSTATE, never the server's text.
    assert "_StoreDefect: _PyodbcError [SQLSTATE 07002]" in captured.out, captured.out
    assert _ROW_TEXT not in captured.out + captured.err + caplog.text


def test_cli_a_sqlite_bind_count_error_at_the_write_is_a_defect(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """SQLite's own bind-count error is a ProgrammingError, a DatabaseError subclass, but a defect
    in the code all the same: the dispatch floor reports it, not "refused the write"."""

    async def defect(*_a: object, **_k: object) -> object:
        raise sqlite3.ProgrammingError("Incorrect number of bindings supplied")

    monkeypatch.setattr(MessageStore, "record_transit_bound_attestation", defect)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "refused the write" not in captured.out + captured.err


def test_cli_a_schema_not_provisioned_refusal_prints_its_remedy_in_full(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An engine refusal at the open is printed whole: ``SchemaNotProvisionedError`` is longer
    than ``safe_exc``'s cap, and its remedy, the provision-schema command, comes late in it. This
    build moves the schema hash, so it is the expected first run of either command on a server
    store."""
    import messagefoundry.store.base as store_base
    from messagefoundry.config.settings import StoreBackend

    refusal = store_base.SchemaNotProvisionedError(StoreBackend.SQLSERVER, "mefor", "a" * 64)
    assert len(str(refusal)) > 200  # the control: safe_exc would have cut it

    async def refusing(*_a: object, **_k: object) -> object:
        raise refusal

    monkeypatch.setattr(store_base, "open_store", refusing)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert f"cannot open the store at {transit_db}: {refusal}" in err, err
    assert f"run `{store_base.PROVISION_SCHEMA_COMMAND}`" in err


async def _real_rcsi_refusal(monkeypatch: pytest.MonkeyPatch, driver: Exception) -> RuntimeError:
    """The refusal ``SqlServerStore._ensure_database_options`` itself raises when the RCSI ALTER
    fails with ``driver`` and no peer turned RCSI on, over an ``aioodbc`` stand-in, so the test
    reads the production message rather than a copy of its format string."""
    import sys
    import types

    import messagefoundry.store.sqlserver as sqlserver_module
    from messagefoundry.config.settings import SchemaManagement, StoreBackend
    from messagefoundry.store.sqlserver import SqlServerStore

    class Cursor:
        async def execute(self, sql: str, *_params: object) -> None:
            if sql.startswith("ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT"):
                raise driver

        async def fetchone(self) -> tuple[int, int]:
            return (0, 0)  # RCSI off, on every read

    class Conn:
        async def cursor(self) -> Cursor:
            return Cursor()

        async def close(self) -> None:
            return None

    async def connect(**_kwargs: object) -> Conn:
        return Conn()

    module = types.ModuleType("aioodbc")
    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setattr(sqlserver_module, "_RCSI_REREAD_DELAY_S", 0.0)
    settings = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor",
        username="sa",
        schema_management=SchemaManagement.AUTO,
    )
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF") as info:
        await SqlServerStore._ensure_database_options(settings)
    return info.value


def test_cli_an_engine_refusal_quoting_a_driver_error_prints_the_remedy_not_the_driver_text(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The SQL Server open's READ_COMMITTED_SNAPSHOT refusal quotes the driver error it was raised
    from. Its remedy prints; the quoted driver text is replaced by the error's class, SQLSTATE and
    native number."""
    import asyncio

    import messagefoundry.store.base as store_base
    from messagefoundry.store.sqlserver import _rcsi_remedy
    from tests.test_keyless_chain_every_command import _ServerDriverError

    _stand_in_server_drivers(monkeypatch)
    driver = _ServerDriverError(
        "42000", f"[42000] permission denied on {_ROW_TEXT} (5011) (SQLExecDirectW)"
    )
    refusal = asyncio.run(_real_rcsi_refusal(monkeypatch, driver))
    assert _ROW_TEXT in str(refusal)  # the control: the refusal does quote the driver's text

    async def refusing(*_a: object, **_k: object) -> object:
        raise refusal

    monkeypatch.setattr(store_base, "open_store", refusing)
    rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert _rcsi_remedy("mefor") in err, err
    assert "(_ServerDriverError [SQLSTATE 42000] native error 5011)" in err, err
    assert _ROW_TEXT not in err


def test_cli_record_refuses_a_store_not_on_vault_transit(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "aesgcm")
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    assert rc == 1
    assert "vault_transit" in capsys.readouterr().err


def test_cli_a_runtime_error_the_engine_did_not_write_is_rendered_safely(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only the engine's own refusals print whole. A RuntimeError subclass from elsewhere, such as
    ``NotImplementedError``, and a plain RuntimeError raised outside engine code (here, by this
    test, standing in for a library) go through ``safe_exc``, which bounds its length."""
    import messagefoundry.store.base as store_base

    for error in (NotImplementedError("x" * 400), RuntimeError("x" * 400)):

        async def refusing(*_a: object, _error: Exception = error, **_k: object) -> object:
            raise _error

        monkeypatch.setattr(store_base, "open_store", refusing)
        rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
        err = capsys.readouterr().err
        assert rc == 2, err
        assert type(error).__name__ in err and "x" * 400 not in err, err


def test_a_refusal_quoting_its_cause_by_repr_renders_the_cause_once() -> None:
    """A refusal that quotes its cause with ``!r`` gets one rendering, not a rendering nested in
    another, and the remedy after it survives."""
    from messagefoundry.__main__ import _engine_refusal_text

    try:
        try:
            raise OSError("reset by peer")
        except OSError as exc:
            raise RuntimeError(f"could not connect: {exc!r}; ask a DBA") from exc
    except RuntimeError as refusal:
        text = _engine_refusal_text(refusal)
    assert text.count("reset by peer") == 1, text
    assert text.endswith("; ask a DBA"), text


# --- GET /security/posture -----------------------------------------------------------------------


async def _posture(store: MessageStore) -> dict[str, object]:
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    service = AuthService(store, AuthSettings(require_mfa=False))
    await service.initialize()
    if await store.get_user_by_username("vw") is None:
        await _add_viewer(service, store)
    app = create_app(
        engine,
        auth=service,
        ai_settings=AiSettings(environment="dev"),
        store_settings=StoreSettings(cipher_provider="vault_transit"),
        security_settings=SecuritySettings(require_mfa=False),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        login = await c.post(
            "/auth/login", json={"username": "vw", "password": PW, "provider": "local"}
        )
        headers = {"Authorization": f"Bearer {login.json()['token']}"}
        body: dict[str, object] = (await c.get("/security/posture", headers=headers)).json()
    return body


async def _add_viewer(service: AuthService, store: MessageStore) -> None:
    user_id = await create_local_user_chosen(
        service,
        username="vw",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    user = await store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def test_posture_reports_the_attestation(store: MessageStore) -> None:
    unattested = await _posture(store)
    assert unattested["transit_bound_attestation"] == {
        "key_name": _KEY_NAME,
        "attested": False,
        "gap": f"no attestation is recorded for the Transit data key {_KEY_NAME!r}",
        "attested_key_name": None,
        "attested_by": None,
        "attested_at": None,
        "reason": None,
    }
    recorded = await _attest(store)
    view = (await _posture(store))["transit_bound_attestation"]
    assert isinstance(view, dict)
    assert view["attested"] is True and view["gap"] is None
    assert view["attested_by"] == "cli:tester"
    assert view["attested_at"] == recorded.attested_at


async def test_posture_shows_no_attribution_from_an_unbacked_row(
    store: MessageStore, tmp_path: Path
) -> None:
    """A DML-forged row names whoever the forger chose. The posture must not repeat it."""
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, _INSERT, (_KEY_NAME, "forged", "cli:officer", time.time(), 9999, "0" * 64))
    again = await _transit_store(db)
    try:
        view = (await _posture(again))["transit_bound_attestation"]
    finally:
        await again.close()
    assert isinstance(view, dict)
    assert view["attested"] is False and "not backed" in str(view["gap"])
    assert view["attested_by"] is None and view["reason"] is None
    assert view["attested_key_name"] is None and view["attested_at"] is None


async def test_posture_survives_a_transit_failure(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Vault outage during the MAC check reads as not attested; the rest of the posture still
    answers."""
    import messagefoundry.store.store as store_module

    await _attest(store)

    def boom(*_a: object, **_k: object) -> str | None:
        raise CipherError("Transit audit HMAC failed (key='mefor-store'): ConnectionError")

    # The attestation's MAC check is the only caller of _audit_row_mac on this path; appends
    # (the login's audit rows) hash through audit_row_hash directly.
    monkeypatch.setattr(store_module, "_audit_row_mac", boom)
    view = (await _posture(store))["transit_bound_attestation"]
    assert isinstance(view, dict)
    assert view["attested"] is False and "Transit refused" in str(view["gap"])


async def test_posture_reports_no_attestation_off_vault_transit(tmp_path: Path) -> None:
    keyless = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert (await _posture(keyless))["transit_bound_attestation"] is None
    finally:
        await keyless.close()
