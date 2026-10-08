# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2615: an operator edit-resend can be proved after retention blanks the bodies.

Two pieces of evidence, pinned here:

* the ``message_edit_resend`` audit row carries keyed digests of the original and the edited body,
  plus the origin. The digest is HMAC-SHA256 under a key derived from the audit key, never a plain
  hash, so it reproduces from the bodies under the store key and tells a reader without the key
  nothing. A store with no in-heap key records no digest at all;
* every ``messages`` row records a plain ``origin`` (and, for an operator origin, ``origin_actor``)
  at insert, and retention leaves both in place when it blanks the body.

SQLite only. The Postgres and SQL Server writers are the same change; their legs run in CI.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus, Row
from messagefoundry.store.crypto import (
    BODY_DIGEST_ALG,
    audit_body_digests,
    generate_key,
    make_cipher,
    verify_audit_body_digest,
)
from messagefoundry.store.store import AuditAppend, MessageOrigin, MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
EDITED = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"
TRANSFORMED = "MSH|^~\\&|MEFOR|RF|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rZXF|sent\r"


def _plain_digests(body: str) -> set[str]:
    """The bare SHA-256 and SHA-1 of a body: the plain hashes this change must not store. Not every
    unkeyed derivation; the re-route child id is one, and it predates this change."""
    data = body.encode()
    return {hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest()}


# --- the digest primitive --------------------------------------------------------------------------


def test_a_keyless_cipher_gives_no_digest_rather_than_a_plain_hash() -> None:
    assert audit_body_digests(make_cipher(None), edited=EDITED) is None


def test_the_digest_is_keyed_reproducible_and_names_its_key() -> None:
    cipher = make_cipher(generate_key())
    got = audit_body_digests(cipher, original=ADT, edited=EDITED)
    assert got is not None
    assert got["alg"] == BODY_DIGEST_ALG
    assert got == audit_body_digests(cipher, original=ADT, edited=EDITED)  # reproducible
    original, edited, key_id = got["original"], got["edited"], got["key_id"]
    assert isinstance(original, str) and isinstance(edited, str) and isinstance(key_id, str)
    assert original != edited
    assert verify_audit_body_digest(cipher, ADT, key_id=key_id, digest=original)
    assert verify_audit_body_digest(cipher, EDITED, key_id=key_id, digest=edited)
    # A guess that is not the body fails, and the digest is no plain hash anyone could recompute.
    assert not verify_audit_body_digest(cipher, ADT, key_id=key_id, digest=edited)
    assert edited not in _plain_digests(EDITED) and original not in _plain_digests(ADT)


def test_without_the_store_key_the_digest_reveals_nothing() -> None:
    # The digest is all that survives retention. A reader holding the audit log and every candidate
    # body, but another key, can neither recompute it nor confirm a guess against it.
    cipher = make_cipher(generate_key())
    other = make_cipher(generate_key())
    got = audit_body_digests(cipher, edited=EDITED)
    assert got is not None and isinstance(got["edited"], str) and isinstance(got["key_id"], str)
    theirs = audit_body_digests(other, edited=EDITED)
    assert theirs is not None and theirs["edited"] != got["edited"]
    assert not verify_audit_body_digest(other, EDITED, key_id=got["key_id"], digest=got["edited"])
    assert not verify_audit_body_digest(
        make_cipher(None), EDITED, key_id=got["key_id"], digest=got["edited"]
    )


def test_a_digest_still_verifies_after_the_key_rotates() -> None:
    old_key, new_key = generate_key(), generate_key()
    got = audit_body_digests(make_cipher(old_key), edited=EDITED)
    assert got is not None and isinstance(got["edited"], str) and isinstance(got["key_id"], str)
    rotated = make_cipher(new_key, [old_key])
    assert verify_audit_body_digest(rotated, EDITED, key_id=got["key_id"], digest=got["edited"])


def test_a_blanked_body_digests_to_none_not_to_the_digest_of_nothing() -> None:
    cipher = make_cipher(generate_key())
    got = audit_body_digests(cipher, original="", edited=EDITED)
    assert got is not None and got["original"] is None and got["edited"] is not None
    # Checking the recorded null is an answer, not a crash.
    assert isinstance(got["key_id"], str)
    assert not verify_audit_body_digest(cipher, ADT, key_id=got["key_id"], digest=got["original"])
    assert not verify_audit_body_digest(cipher, ADT, key_id=got["key_id"], digest="not-hex")


def test_a_body_named_like_a_field_is_refused() -> None:
    with pytest.raises(ValueError, match="collide"):
        audit_body_digests(make_cipher(generate_key()), key_id=EDITED)


# --- the origin column ------------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "origin.db")
    try:
        yield s
    finally:
        await s.close()


async def _origin(store: MessageStore, mid: str) -> tuple[Any, Any]:
    row = await store.get_message(mid)
    assert row is not None
    return row["origin"], row["origin_actor"]


async def test_each_insert_path_records_its_origin(store: MessageStore) -> None:
    received = await store.enqueue_ingress(channel_id="in1", raw=ADT)
    assert await _origin(store, received) == (MessageOrigin.PARTNER.value, None)
    refused = await store.record_received(
        channel_id="in1", raw=ADT, status=MessageStatus.ERROR, error="bad"
    )
    assert await _origin(store, refused) == (MessageOrigin.PARTNER.value, None)
    origin = await store.enqueue_message(
        channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)]
    )
    assert await _origin(store, origin) == (MessageOrigin.PARTNER.value, None)

    reroute = await store.reingress(
        origin_message_id=origin, raw=EDITED, idempotency_key="k1", actor="alice"
    )
    assert await _origin(store, reroute.new_message_id) == (
        MessageOrigin.OPERATOR_EDIT.value,
        "alice",
    )
    direct = await store.resend_to(
        message_id=origin, to="OB2", idempotency_key="k2", body_override=EDITED, actor="bob"
    )
    assert direct.new_message_id is not None
    assert await _origin(store, direct.new_message_id) == (
        MessageOrigin.OPERATOR_EDIT.value,
        "bob",
    )
    # A plain resend adds a delivery to the same message and names no child.
    plain = await store.resend_to(message_id=origin, to="OB3", idempotency_key="k3")
    assert plain.new_message_id is None
    # The origin row is untouched by any of this.
    assert await _origin(store, origin) == (MessageOrigin.PARTNER.value, None)


async def test_an_upload_inject_records_the_operator(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "inject.db")
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    try:
        mid = await engine.inject_message(
            channel_id="in1",
            raw=ADT,
            audit=lambda new_mid: AuditAppend("upload.resend", actor="carol", detail=new_mid),
            actor="carol",
        )
        assert await _origin(store, mid) == (MessageOrigin.OPERATOR_UPLOAD.value, "carol")
    finally:
        await engine.stop()


async def test_retention_keeps_the_origin_when_it_blanks_the_body(store: MessageStore) -> None:
    origin = await store.enqueue_message(channel_id="in1", raw=ADT, deliveries=[])
    child = await store.reingress(
        origin_message_id=origin, raw=EDITED, idempotency_key="k1", actor="alice", now=1.0
    )
    # Resolve the child so retention may take its body.
    await store._db.execute(
        "UPDATE messages SET status=?, received_at=1.0 WHERE id IN (?,?)",
        (MessageStatus.PROCESSED.value, origin, child.new_message_id),
    )
    await store._db.execute("DELETE FROM queue")
    await store._db.commit()
    assert await store.purge_message_bodies(older_than=2.0) >= 1
    row = await store.get_message(child.new_message_id)
    assert row is not None and row["raw"] == ""  # the body is gone
    assert (row["origin"], row["origin_actor"]) == (MessageOrigin.OPERATOR_EDIT.value, "alice")


# --- the edit-resend route ---------------------------------------------------------------------


def _registry(tmp_path: Path) -> Registry:
    for d in ("in", "o1", "o2"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    for name, d in (("OB1", "o1"), ("OB2", "o2")):
        reg.add_outbound(
            OutboundConnection(
                name, ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / d)})
            )
        )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    return reg


async def _engine(tmp_path: Path, key: str | None) -> Engine:
    store = await MessageStore.open(tmp_path / "api.db", cipher=make_cipher(key))
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    engine.add_registry(_registry(tmp_path))
    await engine.start()
    return engine


async def _edit_resend(engine: Engine, payload: dict[str, Any]) -> tuple[str, Row]:
    """Seed an origin, POST one edit-resend, and return the origin id and the audit row."""
    from messagefoundry.api import create_app

    mid = await engine.store.enqueue_message(
        channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
    )
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(f"/messages/{mid}/edit-resend", json=payload)
        assert r.status_code == 200, r.text
    [rec] = [a for a in await engine.store.list_audit() if a["action"] == "message_edit_resend"]
    return mid, rec


@pytest.mark.parametrize(
    "payload",
    [
        {"raw": EDITED, "idempotency_key": "k1"},
        {"raw": EDITED, "idempotency_key": "k1", "to": "OB2"},
    ],
    ids=["reroute", "direct"],
)
async def test_the_audit_row_proves_what_was_sent(tmp_path: Path, payload: dict[str, Any]) -> None:
    pytest.importorskip("psutil")
    key = generate_key()
    engine = await _engine(tmp_path, key)
    try:
        mid, rec = await _edit_resend(engine, payload)
        detail = json.loads(str(rec["detail"]))
        assert detail["origin"] == MessageOrigin.OPERATOR_EDIT.value
        digest = detail["body_digest"]
        assert digest["alg"] == BODY_DIGEST_ALG
        cipher = engine.store.cipher()
        kid = digest["key_id"]
        assert verify_audit_body_digest(cipher, ADT, key_id=kid, digest=digest["original"])
        assert verify_audit_body_digest(cipher, EDITED, key_id=kid, digest=digest["edited"])
        # The row names the new message, and that message names the same operator.
        child = await engine.store.get_message(detail["new_message_id"])
        assert child is not None and child["raw"] == EDITED
        assert (child["origin"], child["origin_actor"]) == (
            MessageOrigin.OPERATOR_EDIT.value,
            rec["actor"],
        )
        # No body, and no bare hash of one, reaches the row.
        text = str(rec["detail"])
        assert "PID|" not in text and "DOE^JOHN" not in text
        for plain in _plain_digests(EDITED) | _plain_digests(ADT):
            assert plain not in text
        assert mid != detail["new_message_id"]
    finally:
        await engine.stop()


async def test_a_keyless_store_records_the_origin_and_no_digest(tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    engine = await _engine(tmp_path, None)
    try:
        _mid, rec = await _edit_resend(engine, {"raw": EDITED, "idempotency_key": "k1"})
        detail = json.loads(str(rec["detail"]))
        assert detail["origin"] == MessageOrigin.OPERATOR_EDIT.value
        assert detail["body_digest"] is None
        for plain in _plain_digests(EDITED) | _plain_digests(ADT):
            assert plain not in str(rec["detail"])
    finally:
        await engine.stop()
