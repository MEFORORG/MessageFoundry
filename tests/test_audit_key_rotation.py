# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1904 -- a store key rotation must not break the audit chain.

The defect, reproduced at engine ``fcbe2f93a`` with synthetic data: ``AesGcmCipher`` derived the
audit MAC key from the ACTIVE key only, ``audit_chain_meta`` recorded no key, and ``rotate-key`` never
touched the audit chain. So after the rotation ``docs/PHI.md`` documents -- new key B active, old key A
retired, ``rotate-key``, then drop A -- ``audit-verify`` reported the chain broken at row 1, for good
once A was gone, and ``rekey-audit`` still printed OK over it.

The design these tests pin (ADR 0193): every keyed range of the chain names its key, the first in
``audit_chain_meta.key_id`` and each later one in an ``audit.key_epoch`` row that ``rotate-key``
appends. That row is the first row of the new range, MAC'd under the NEW key, and it carries a
digest of the range it closes. So the old range stays provable after its key is dropped, and a
forged or moved range fails verification instead of redirecting it.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what the first key
rotation on a first deployment would have hit.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION, MessageStore, audit_row_hash

_AT_REST_ENV = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEY_FILE",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
    "MEFOR_STORE_KEY_PROVIDER",
    "MEFOR_STORE_CIPHER_PROVIDER",
)


async def _open(path: Path, active: str, retired: tuple[str, ...] = ()) -> MessageStore:
    cipher = make_cipher(active, retired)
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


async def _seed(store: MessageStore, tag: str, n: int) -> None:
    for i in range(n):
        await store.record_audit(tag, actor="u", detail=json.dumps({"n": i}))


async def _verify(
    path: Path, active: str, retired: tuple[str, ...] = ()
) -> tuple[bool, str | None]:
    store = await _open(path, active, retired)
    try:
        return await store.verify_audit_chain()
    finally:
        await store.close()


async def _rotate(path: Path, a: str, b: str) -> None:
    """A active -> B active with A retired -> roll the audit range, the store-level rotate-key step."""
    store = await _open(path, b, (a,))
    try:
        ok, msg = await store.roll_audit_key_epoch()
        assert ok, msg
    finally:
        await store.close()


# --- the round trip --------------------------------------------------------------------------------


async def test_a_chain_with_no_rotation_verifies(tmp_path: Path) -> None:
    """The control: the no-rotation arm must pass, so a red below is about rotation."""
    path, a = tmp_path / "control.db", generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "before", 3)
    finally:
        await store.close()
    assert (await _verify(path, a))[0]


async def test_the_documented_rotation_verifies_at_every_step(tmp_path: Path) -> None:
    path, a, b = tmp_path / "rotate.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "under-a", 3)
    finally:
        await store.close()
    ok, msg = await _verify(path, a)
    assert ok, msg

    # Step 1: B active, A retired. Before rotate-key the chain must still verify, and appends made
    # in this window stay in A's range rather than silently starting an unannounced B range.
    ok, msg = await _verify(path, b, (a,))
    assert ok, f"B active with A retired must verify before the roll: {msg}"
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "pending", 1)
    finally:
        await store.close()
    ok, msg = await _verify(path, b, (a,))
    assert ok, msg

    # Step 2: rotate-key rolls the audit range; new rows land under B.
    await _rotate(path, a, b)
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "under-b", 2)
    finally:
        await store.close()
    ok, msg = await _verify(path, b, (a,))
    assert ok, msg

    # Step 3: A dropped. A's range is proved by the digest the B-keyed epoch row carries.
    ok, msg = await _verify(path, b)
    assert ok, f"the chain must verify with A dropped: {msg}"
    store = await _open(path, b)
    try:
        await _seed(store, "after-drop", 1)
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
    finally:
        await store.close()


async def test_two_rotations_chain_the_proof_through_a_dropped_middle_key(tmp_path: Path) -> None:
    """A -> B -> C, then drop A and B: C's epoch row proves B's range, which carries A's proof."""
    path, a, b, c = tmp_path / "twice.db", generate_key(), generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
    finally:
        await store.close()
    await _rotate(path, a, b)
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "b", 2)
    finally:
        await store.close()
    await _rotate(path, b, c)
    ok, msg = await _verify(path, c)
    assert ok, msg


async def test_rolling_is_idempotent_and_refuses_a_broken_chain(tmp_path: Path) -> None:
    path, a, b = tmp_path / "roll.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
        ok, msg = await store.roll_audit_key_epoch()
        assert ok and "already" in msg, msg  # nothing to roll under the same key
        await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
        await store._db.commit()
    finally:
        await store.close()
    store = await _open(path, b, (a,))
    try:
        ok, msg = await store.roll_audit_key_epoch()
        assert not ok and "refusing" in msg, msg
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 0, "a refused roll must write nothing"
    finally:
        await store.close()


# --- forged and moved ranges -----------------------------------------------------------------------


async def _rotated_and_dropped(tmp_path: Path) -> tuple[Path, str, str]:
    path, a, b = tmp_path / "forge.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 3)
    finally:
        await store.close()
    await _rotate(path, a, b)
    store = await _open(path, b)
    try:
        await _seed(store, "b", 2)
    finally:
        await store.close()
    assert (await _verify(path, b))[0]
    return path, a, b


async def test_editing_a_row_of_a_dropped_keys_range_is_caught(tmp_path: Path) -> None:
    path, _a, b = await _rotated_and_dropped(tmp_path)
    store = await _open(path, b)
    try:
        await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
        await store._db.commit()
        ok, msg = await store.verify_audit_chain()
        assert not ok, "A's range must stay tamper-evident after A is dropped"
    finally:
        await store.close()


async def test_a_moved_range_boundary_is_caught(tmp_path: Path) -> None:
    """End to end on a real store. B is held, so the edited range row's own MAC catches this; the
    closing-record check is pinned on its own, by a key-holder's forgery, in
    ``test_a_key_holders_range_row_that_misstates_its_range_is_caught``."""
    path, _a, b = await _rotated_and_dropped(tmp_path)
    store = await _open(path, b)
    try:
        cur = await store._db.execute(
            "SELECT id, detail FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None
        detail = json.loads(row["detail"])
        detail["closes"]["to_id"] -= 1  # claim A's range ended one row earlier
        await store._db.execute(
            "UPDATE audit_log SET detail=? WHERE id=?", (json.dumps(detail), row["id"])
        )
        await store._db.commit()
        ok, msg = await store.verify_audit_chain()
        assert not ok and f"id={row['id']}" in (msg or ""), msg
    finally:
        await store.close()


async def test_a_forged_range_meta_is_caught(tmp_path: Path) -> None:
    """Re-pointing the first range at the key that is still configured must fail, not redirect."""
    path, _a, b = await _rotated_and_dropped(tmp_path)
    store = await _open(path, b)
    try:
        cur = await store._db.execute(
            "SELECT detail FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None
        b_id = json.loads(row["detail"])["key_id"]
        await store._db.execute("UPDATE audit_chain_meta SET key_id=? WHERE id=1", (b_id,))
        await store._db.commit()
    finally:
        await store.close()
    ok, _msg = await _verify(
        path, b
    )  # the range record is read at open, so reopen after the forgery
    assert not ok


async def test_rotate_key_refuses_to_reopen_a_key_that_already_keyed_a_range(
    tmp_path: Path,
) -> None:
    """Rolling A -> B -> back to A would append a range row that can never verify, since a key opens
    one range only. The roll must refuse and write nothing, not print OK over a permanent break."""
    path, a, b = tmp_path / "back.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
    finally:
        await store.close()
    await _rotate(path, a, b)
    store = await _open(path, a, (b,))
    try:
        ok, msg = await store.roll_audit_key_epoch()
        assert not ok and "NEW key" in msg, msg
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 1, "a refused roll must write nothing"
    finally:
        await store.close()


async def test_a_forged_range_row_does_not_route_live_appends(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The open-time answer routes every append, so it is authenticated, not read. A row naming a
    leaked configured key X that X alone signed must not send new rows to X."""
    import logging

    from messagefoundry.store.crypto import audit_key_id
    from messagefoundry.store.store import audit_epoch_detail, audit_handover_tag

    path, a, b = await _rotated_and_dropped(tmp_path)
    x = generate_key()
    x_mac = make_cipher(x).audit_mac_key()
    assert x_mac is not None
    x_id = audit_key_id(x_mac)
    store = await _open(path, b, (x,))
    try:
        cur = await store._db.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        head = await cur.fetchone()
        assert head is not None
        closes = {
            "key_id": "whatever",
            "from_id": 1,
            "to_id": 1,
            "rows": 1,
            "digest": "",
            "prev_hash": "",
        }
        detail = audit_epoch_detail(x_id, closes, audit_handover_tag(x_id, closes, (x_mac, None)))
        forged = audit_row_hash(
            head["row_hash"],
            ts=9.0,
            actor="mallory",
            action=AUDIT_KEY_EPOCH_ACTION,
            channel_id=None,
            detail=detail,
            key=x_mac,
        )
        await store._db.execute(
            "INSERT INTO audit_log (ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (?,?,?,?,?,?,?)",
            (9.0, "mallory", AUDIT_KEY_EPOCH_ACTION, None, detail, None, forged),
        )
        await store._db.commit()
    finally:
        await store.close()
    with caplog.at_level(logging.ERROR, logger="messagefoundry.store.store"):
        store = await _open(path, b, (x,))
    try:
        b_mac = make_cipher(b).audit_mac_key()
        assert b_mac is not None
        assert store._audit_range_key_id == audit_key_id(b_mac), (
            "appends must stay on the active key"
        )
        assert any("does not follow" in r.getMessage() for r in caplog.records)
        ok, msg = await store.roll_audit_key_epoch()
        assert not ok and "do not authenticate" in msg
        ok, _msg = await store.verify_audit_chain()
        assert not ok
    finally:
        await store.close()


def test_a_deeply_nested_range_row_is_a_break_not_an_exception() -> None:
    """``detail`` is attacker-writable. ``json.loads`` raises RecursionError on deep nesting, which
    must be reported as a malformed row, never escape and silence the startup tamper alarm."""
    from messagefoundry.store.store import parse_audit_epoch, verify_audit_rows

    deep = "[" * 100_000
    assert parse_audit_epoch(deep) is None
    rows = [
        {
            "id": 1,
            "ts": 1.0,
            "actor": "u",
            "action": AUDIT_KEY_EPOCH_ACTION,
            "channel_id": None,
            "detail": deep,
            "client": None,
            "row_hash": audit_row_hash(
                "",
                ts=1.0,
                actor="u",
                action=AUDIT_KEY_EPOCH_ACTION,
                channel_id=None,
                detail=deep,
                key=b"k" * 32,
            ),
        }
    ]
    ok, msg = verify_audit_rows(
        rows, keyed_from=1, first_key_id="k", mac_keys={"k": b"k" * 32}, mac_fn=None, capable=True
    )
    assert not ok and "malformed" in (msg or ""), msg


# --- the CLI surface -------------------------------------------------------------------------------


def test_rotate_key_then_audit_verify_round_trip_through_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a, b = tmp_path / "cli.db", generate_key(), generate_key()

    async def seed() -> None:
        store = await _open(db, a)
        try:
            await _seed(store, "a", 3)
        finally:
            await store.close()

    asyncio.run(seed())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", a)
    assert main(["audit-verify", "--db", str(db)]) == 0

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", b)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", a)
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()
    assert main(["rotate-key", "--db", str(db)]) == 0, capsys.readouterr()
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()

    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED")
    capsys.readouterr()
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()


def test_rekey_audit_does_not_print_ok_over_a_chain_that_does_not_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a = tmp_path / "rekey.db", generate_key()

    async def seed_and_tamper() -> None:
        store = await _open(db, a)
        try:
            await _seed(store, "a", 3)
            await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
            await store._db.commit()
        finally:
            await store.close()

    asyncio.run(seed_and_tamper())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", a)
    assert main(["rekey-audit", "--db", str(db)]) != 0
    out = capsys.readouterr().out
    assert "OK" not in out and "FAIL" in out, out


# --- the server backends, offline ------------------------------------------------------------------


def _rows_across_a_rotation(
    a_key: bytes,
    b_key: bytes,
    *,
    tag_key: bytes | None = None,
    closes_edit: dict[str, object] | None = None,
    then: tuple[bytes, bytes] | None = None,
) -> list[dict[str, object]]:
    """Three rows under A, a range row opening B, two rows under B -- the shape ``rotate-key`` leaves,
    built with the shared helpers so every test reads one fixture.

    ``tag_key`` signs the handover (the outgoing key A by default -- pass another to forge it);
    ``closes_edit`` overrides fields of the ``closes`` record; ``then=(outgoing, incoming)`` appends a
    SECOND range row opening ``incoming``, handed over under ``outgoing``, and one row under it."""
    from messagefoundry.store.crypto import audit_key_id
    from messagefoundry.store.store import (
        audit_epoch_detail,
        audit_handover_tag,
        audit_range_closing,
    )

    rows: list[dict[str, object]] = []
    prev = ""

    def add(action: str, detail: str | None, key: bytes) -> None:
        nonlocal prev
        rid = len(rows) + 1
        row: dict[str, object] = {
            "id": rid,
            "ts": float(rid),
            "actor": "u",
            "action": action,
            "channel_id": None,
            "detail": detail,
            "client": None,
        }
        prev = audit_row_hash(
            prev,
            ts=float(rid),
            actor="u",
            action=action,
            channel_id=None,
            detail=detail,
            key=key,
        )
        row["row_hash"] = prev
        rows.append(row)

    def open_range(outgoing: bytes, incoming: bytes, signer: bytes, from_id: int) -> None:
        closed = [r for r in rows if int(str(r["id"])) >= from_id]
        before = [r for r in rows if int(str(r["id"])) < from_id]
        closes = dict(
            audit_range_closing(
                closed,
                key_id=audit_key_id(outgoing),
                from_id=from_id,
                prev_hash=str(before[-1]["row_hash"]) if before else "",
            )
        )
        closes.update(closes_edit or {})
        tag = audit_handover_tag(audit_key_id(incoming), closes, (signer, None))
        add(
            AUDIT_KEY_EPOCH_ACTION,
            audit_epoch_detail(audit_key_id(incoming), closes, tag),
            incoming,
        )

    for i in range(3):
        add("a", json.dumps({"n": i}), a_key)
    open_range(a_key, b_key, tag_key or a_key, 1)
    for i in range(2):
        add("b", json.dumps({"n": i}), b_key)
    if then is not None:
        outgoing, incoming = then
        open_range(outgoing, incoming, outgoing, 4)
        add("c", json.dumps({"n": 0}), incoming)
    return rows


def _verify_rows(
    rows: list[dict[str, object]], first: bytes, held: tuple[bytes, ...]
) -> tuple[bool, str | None]:
    from messagefoundry.store.crypto import audit_key_id
    from messagefoundry.store.store import verify_audit_rows

    return verify_audit_rows(
        rows,
        keyed_from=1,
        first_key_id=audit_key_id(first),
        mac_keys={audit_key_id(k): k for k in held},
        mac_fn=None,
        capable=True,
    )


_A, _B, _X = b"a" * 32, b"b" * 32, b"x" * 32


def test_the_offline_fixture_verifies_so_each_forgery_below_is_the_only_change() -> None:
    assert _verify_rows(_rows_across_a_rotation(_A, _B), _A, (_A, _B))[0]
    assert _verify_rows(_rows_across_a_rotation(_A, _B, then=(_B, _X)), _A, (_B, _X))[0]


def test_a_configured_key_that_never_keyed_a_range_cannot_open_one() -> None:
    """The redirect the handover tag exists for. X is configured (retired) and leaked, and never keyed
    a range. A writer holding X appends a range row naming X, with a CORRECT closing record and a
    valid MAC under X -- everything but the outgoing key's tag. The tag check alone catches it."""
    rows = _rows_across_a_rotation(_A, _B, tag_key=_X)
    ok, msg = _verify_rows(rows, _A, (_A, _B, _X))
    assert not ok and "not authorised" in (msg or ""), msg


def test_a_key_cannot_open_a_second_range_even_when_authorised() -> None:
    """A -> B -> back to A, handed over correctly under B. Only the one-range-per-key rule catches it,
    and it is what stops a leaked old key being brought back by anyone who can get one tag signed."""
    rows = _rows_across_a_rotation(_A, _B, then=(_B, _A))
    ok, msg = _verify_rows(rows, _A, (_A, _B))
    assert not ok and "second range" in (msg or ""), msg


def test_a_key_holders_range_row_that_misstates_its_range_is_caught() -> None:
    """A key holder signs a range row whose closing record claims A's range ended a row early. MAC
    and tag are both valid, so the closing-record check alone catches it."""
    rows = _rows_across_a_rotation(_A, _B, closes_edit={"to_id": 2})
    ok, msg = _verify_rows(rows, _A, (_A, _B))
    assert not ok and "does not match" in (msg or ""), msg


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_both_server_backends_verify_across_a_rotation_with_the_old_key_dropped(
    backend: str,
) -> None:
    """The real ``verify_audit_chain`` of each server backend, driven offline through the same
    bare-instance seam the Transit rider uses. Their live-database legs run on a hosted runner."""
    from typing import Any

    from messagefoundry.store.crypto import audit_key_id
    from tests.test_asvs_transit_audit_mac_server_backends import _bare

    a_key, b_key = b"a" * 32, b"b" * 32
    rows = _rows_across_a_rotation(a_key, b_key)
    store = _bare(backend, mac_key=b_key)  # A dropped: only B is held
    store._audit_keyed_from = 1
    store._audit_first_key_id = audit_key_id(a_key)

    async def _fetchall(_sql: str, *_a: Any, **_kw: Any) -> list[dict[str, Any]]:
        return rows

    store._fetchall = _fetchall
    ok, msg = await store.verify_audit_chain()
    assert ok, f"{backend}: {msg}"

    rows[1]["actor"] = "mallory"  # a row of the dropped key's range
    ok, msg = await store.verify_audit_chain()
    assert not ok and "id=4" in (msg or ""), (
        f"{backend}: the closing range row must catch it: {msg}"
    )


# --- review round 2 --------------------------------------------------------------------------------


async def test_a_row_with_a_negative_id_is_still_walked(tmp_path: Path) -> None:
    """The walk reads every row. A lower bound of 0 silently dropped a row a writer inserted with an
    explicit negative id, which the unfiltered pre-#1904 walk reported."""
    path, a = tmp_path / "neg.db", generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
        await store._db.execute(
            "INSERT INTO audit_log (id, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (-5, 1.0, 'admin', 'auth.login', NULL, NULL, NULL, 'deadbeef')"
        )
        await store._db.commit()
        ok, msg = await store.verify_audit_chain()
        assert not ok and "id=-5" in (msg or ""), msg
    finally:
        await store.close()


async def test_a_nested_closing_record_neither_raises_at_open_nor_in_verify(tmp_path: Path) -> None:
    """The tag check re-serialises ``closes``; nested values would raise RecursionError there. A
    closing record takes scalars only, so the row is simply malformed."""
    from messagefoundry.store.crypto import audit_key_id

    path, a = tmp_path / "nest.db", generate_key()
    a_mac = make_cipher(a).audit_mac_key()
    assert a_mac is not None
    a_id = audit_key_id(a_mac)  # names the CURRENT range, so the open reaches the tag check
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
        nested = (
            '{"key_id":"feedfacefeedface","handover":"00","closes":{"key_id":'
            + json.dumps(a_id)
            + ',"z":'
            # Deep enough that json.dumps raises and shallow enough that json.loads does not, on
            # CPython 3.14 -- the gap the tag check's re-serialisation fell into.
            + '{"a":' * 10000
            + "1"
            + "}" * 10000
            + "}}"
        )
        await store._db.execute(
            "INSERT INTO audit_log (ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (9.0, 'mallory', ?, NULL, ?, NULL, 'deadbeef')",
            (AUDIT_KEY_EPOCH_ACTION, nested),
        )
        await store._db.commit()
    finally:
        await store.close()
    store = await _open(path, a)  # must not raise
    try:
        ok, _msg = await store.verify_audit_chain()
        assert not ok
    finally:
        await store.close()


async def test_an_empty_first_range_is_not_read_as_a_forged_first_key(tmp_path: Path) -> None:
    """A fresh keyed store rolled before any row is written has an EMPTY first range, so its first
    keyed row is the next range's own row. That is not a check of the first key."""
    path, a, b, c = tmp_path / "empty.db", generate_key(), generate_key(), generate_key()
    store = await _open(path, a)
    await store.close()
    await _rotate(path, a, b)
    store = await _open(path, b, (a,))
    try:
        assert store._audit_ranges_trusted, "a legitimate empty first range must authenticate"
    finally:
        await store.close()
    await _rotate(path, b, c)
    assert (await _verify(path, c))[0]


async def test_a_lost_range_key_keeps_the_audit_trail_writing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Refusing every append while the current range's key is missing would stop every audited action,
    sign-in included. The rows go under the active key instead, loudly, and verify reports the break."""
    import logging

    path, a, b = tmp_path / "lost.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
    finally:
        await store.close()
    with caplog.at_level(logging.ERROR, logger="messagefoundry.store.store"):
        store = await _open(path, b)  # A lost before rotate-key ran
    try:
        await store.record_audit("auth.login", actor="u")  # must not raise
        assert any("NOT configured" in r.getMessage() for r in caplog.records)
        ok, _msg = await store.verify_audit_chain()
        assert not ok
    finally:
        await store.close()


def test_rotate_key_does_not_print_ok_when_the_audit_roll_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a, b = tmp_path / "partial.db", generate_key(), generate_key()

    async def seed_and_tamper() -> None:
        store = await _open(db, a)
        try:
            await _seed(store, "a", 3)
            await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
            await store._db.commit()
        finally:
            await store.close()

    asyncio.run(seed_and_tamper())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", b)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", a)
    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "OK:" not in captured.out and "PARTIAL:" in captured.out, captured.out
    assert "Do NOT remove" in captured.err


# --- Lander blocker on PR 1446: the keyless prefix below a dropped first range ----------------------


async def _keyless_then_rekeyed_then_rotated(tmp_path: Path) -> tuple[Path, str]:
    """The Lander's reproduction, the path #1905 points operators down: keyless rows, `rekey-audit`
    under A (watermark id=4), two A rows, `rotate-key` to B, one B row. Returns (path, B)."""
    path, a, b = tmp_path / "prefix.db", generate_key(), generate_key()
    store = await MessageStore.open(path)
    try:
        await _seed(store, "keyless", 3)
    finally:
        await store.close()
    store = await _open(path, a)
    try:
        ok, msg = await store.rekey_audit_chain()
        assert ok and "keyed from id=4" in msg, msg
        await _seed(store, "a", 2)
    finally:
        await store.close()
    await _rotate(path, a, b)
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "b", 1)
    finally:
        await store.close()
    return path, b


async def test_an_untampered_keyless_prefix_verifies_after_the_first_key_is_dropped(
    tmp_path: Path,
) -> None:
    """The control: without it, a red below could be the drop itself, not the forgery."""
    path, b = await _keyless_then_rekeyed_then_rotated(tmp_path)
    ok, msg = await _verify(path, b)
    assert ok, msg


async def test_a_forged_keyless_prefix_is_caught_after_the_first_key_is_dropped(
    tmp_path: Path,
) -> None:
    """Edit keyless row 2 and recompute SHA-256 for rows 2 and 3. Only A's MAC on row 4 tied the
    keyless prefix in; with A dropped, the B-keyed range row must still pin it."""
    path, b = await _keyless_then_rekeyed_then_rotated(tmp_path)
    store = await _open(path, b)
    try:
        cur = await store._db.execute(
            "SELECT id, ts, actor, action, channel_id, detail, client, row_hash"
            " FROM audit_log WHERE id <= 3 ORDER BY id"
        )
        rows = [dict(r) for r in await cur.fetchall()]
        rows[1]["actor"] = "mallory"
        prev = rows[0]["row_hash"]
        for r in rows[1:]:
            r["row_hash"] = audit_row_hash(
                prev,
                ts=r["ts"],
                actor=r["actor"],
                action=r["action"],
                channel_id=r["channel_id"],
                detail=r["detail"],
                client=r["client"],
            )
            prev = r["row_hash"]
            await store._db.execute(
                "UPDATE audit_log SET actor=?, row_hash=? WHERE id=?",
                (r["actor"], r["row_hash"], r["id"]),
            )
        await store._db.commit()
        ok, msg = await store.verify_audit_chain()
        assert not ok, f"a forged keyless prefix verified with the first key dropped: {msg}"
        # Reported at the B-keyed range row (id=6), which holds the proof, naming the rows below id=4.
        assert "id=6" in (msg or "") and "rows before id=4" in (msg or ""), msg
    finally:
        await store.close()


def test_a_key_holders_range_row_that_misstates_its_link_is_caught() -> None:
    """Offline, with every key held: a key holder signs a range row whose ``prev_hash`` is wrong.
    MAC, tag, digest and fields are all valid, so only the link check catches it."""
    rows = _rows_across_a_rotation(_A, _B, closes_edit={"prev_hash": "0" * 64})
    ok, msg = _verify_rows(rows, _A, (_A, _B))
    assert not ok and "rows before id=1" in (msg or ""), msg


def test_a_closing_record_without_its_link_is_malformed() -> None:
    from messagefoundry.store.store import parse_audit_epoch

    closes = {"key_id": "k", "from_id": 1, "to_id": 1, "rows": 1, "digest": "d"}
    assert parse_audit_epoch(json.dumps({"key_id": "n", "closes": closes, "handover": "t"})) is None
    closes["prev_hash"] = ""
    assert parse_audit_epoch(json.dumps({"key_id": "n", "closes": closes, "handover": "t"}))


async def test_the_roll_refuses_when_the_head_moves_after_it_sealed(tmp_path: Path) -> None:
    """A row appended between the roll's read and its append would sit inside the closed range but
    outside its digest. The append names the head it sealed and is refused before writing."""
    path, a, b = tmp_path / "moved.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
    finally:
        await store.close()
    store = await _open(path, b, (a,))
    try:
        real_rows = store._audit_rows

        async def rows_then_a_racing_append(from_id: int, *, limit: int | None = None) -> object:
            got = await real_rows(from_id, limit=limit)
            await store.record_audit("racing", actor="engine")  # lands after the seal
            return got

        store._audit_rows = rows_then_a_racing_append  # type: ignore[method-assign]
        ok, msg = await store.roll_audit_key_epoch()
        assert not ok and "changed while" in msg, msg
        store._audit_rows = real_rows  # type: ignore[method-assign]
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 0, "a refused roll must write nothing"
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
    finally:
        await store.close()


async def test_sql_server_clamps_the_every_row_floor_to_int() -> None:
    """``audit_log.id`` is INT on SQL Server; the floor handed to it must be INT's minimum, and a real
    lower bound must pass through unchanged."""
    from typing import Any

    from messagefoundry.store.store import AUDIT_ALL_ROWS
    from tests.test_asvs_transit_audit_mac_server_backends import _bare

    store = _bare("sqlserver")
    seen: list[tuple[Any, ...]] = []

    async def _fetchall(_sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        seen.append(params)
        return []

    store._fetchall = _fetchall
    await store._audit_rows(AUDIT_ALL_ROWS)
    await store._audit_rows(7)
    assert seen == [(-(2**31),), (7,)]
