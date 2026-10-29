# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2608: a refused inbound body stores whole only inside a per-inbound allowance.

Every refusal before ingress used to store the full body, up to the 16 MiB frame limit, and no intake
bound counted it. These tests flood the refusal path and pin four properties:

* the allowance holds: past it, only the head of each refused body is stored, so the bytes stored
  stay under ``allowance + count * head``;
* every refused body's length is stored, inside the allowance and past it, and so is a digest of it
  keyed from the store's audit key, never a plain hash, whenever the store holds a key in heap;
* count-and-log holds: every refusal is still one ``ERROR`` row, and the ACK or NAK the sender gets
  is the same as with an unspent allowance;
* it covers EVERY refusal phase, the parse failure included, because a bound that skipped one phase
  would not bound a sender who sends bodies that fail there.

Synthetic HL7 only; no real PHI.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings, InboundSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.binary import decode as decode_carriage
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline import refused_body
from messagefoundry.pipeline.ingress_guards import store_safe_raw
from messagefoundry.pipeline.refused_body import (
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.redaction import safe_text
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.crypto import (
    REFUSED_BODY_DIGEST_KDF,
    Cipher,
    audit_body_digests,
    generate_key,
    make_cipher,
    refused_body_digest,
    verify_refused_body_digest,
)
from messagefoundry.store.metadata import user_metadata
from messagefoundry.transports.database import DatabaseSource
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.mllp import MLLPSource

_MSH = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|MSG1|P|2.5.1\r"
_STRICT_OK = _MSH + b"EVN|A01|20260101\rPID|1||MRN123^^^H^MR||DOE^JANE\rPV1|1|I\r"
#: A store cipher with no key: the allowance's own tests do not need a digest.
_KEYLESS = make_cipher(None)


def _plain_digests(body: bytes) -> set[str]:
    """The bare SHA-256 and SHA-1 of a body: the plain hashes the record must not hold."""
    return {hashlib.sha256(body).hexdigest(), hashlib.sha1(body).hexdigest()}


def _parse_failure(n: int = 4000) -> bytes:
    """A body that decodes and passes every pre-parse guard, then fails ``Peek.parse``: no MSH."""
    return b"NOT-HL7 " + b"A" * (n - 8)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _ic(
    name: str = "IB_A",
    content_type: ContentType = ContentType.HL7V2,
    *,
    source: ConnectorType = ConnectorType.MLLP,
    strict: bool = False,
) -> InboundConnection:
    ic = InboundConnection(
        name=name,
        spec=ConnectionSpec(source, {}),
        router="r",
        content_type=content_type,
    )
    if strict:
        ic = dataclasses.replace(ic, validation=Validation(strict=True, hl7_version="2.5.1"))
    return ic


def _runner(
    store: MessageStore, inbounds: list[InboundConnection], allowance: RefusedBodyAllowance
) -> RegistryRunner:
    reg = Registry()
    for ic in inbounds:
        reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])
    return RegistryRunner(
        reg, store, egress=EgressSettings(deny_by_default=False), refused_body_allowance=allowance
    )


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def _rows(store: MessageStore) -> list[dict]:
    cur = await store._db.execute(
        "SELECT id, channel_id, status, error, raw FROM messages ORDER BY rowid"
    )
    return [dict(r) for r in await cur.fetchall()]


async def _record(store: MessageStore, mid: str) -> dict:
    meta = await store.message_metadata_json(mid)
    assert meta is not None
    return dict(json.loads(meta)[METADATA_KEY])


def _msa(ack: str | None) -> str | None:
    """The MSA segment of an ACK, the part that does not carry a fresh timestamp or control id."""
    if ack is None:
        return None
    return next(seg for seg in ack.split("\r") if seg.startswith("MSA|"))


# --- the flood -------------------------------------------------------------------------------------


async def test_a_reject_flood_stores_heads_past_the_allowance_and_counts_every_refusal(
    store: MessageStore,
) -> None:
    clock = _Clock()
    policy = RefusedBodyPolicy(allowance_bytes=8192, window_seconds=60.0, head_bytes=1024)
    allowance = RefusedBodyAllowance(policy, clock=clock)
    runner = _runner(store, [_ic("IB_A"), _ic("IB_B")], allowance)
    ic_a = runner.registry.inbound["IB_A"]
    body = _parse_failure(4000)
    flood = 200

    acks = [await runner._handle_inbound(ic_a, body) for _ in range(flood)]

    # The sender is NAKed AR every time, exactly as before: the allowance only shapes what is stored.
    assert all(ack is not None and "MSA|AR|" in ack for ack in acks)
    rows = await _rows(store)
    # Count-and-log: one ERROR row per refusal, none dropped.
    assert len(rows) == flood
    assert all(r["status"] == MessageStatus.ERROR.value for r in rows)
    whole = [r for r in rows if r["raw"] == body.decode()]
    heads = [r for r in rows if r["raw"] != body.decode()]
    # 8192 covers two 4000-byte bodies, so two are stored whole and the rest are heads.
    assert len(whole) == 2 and len(heads) == flood - 2
    stored = sum(len(r["raw"].encode()) for r in rows)
    assert stored <= policy.allowance_bytes + flood * policy.head_bytes
    # Without the allowance this flood would store flood * 4000 bytes; it stores about a quarter.
    assert stored < flood * len(body) // 3
    for r in heads:
        assert r["raw"] == body.decode()[: policy.head_bytes]
        assert "refused-body allowance spent" in r["error"]
        assert r["error"].startswith("[refused-body allowance spent: ")
        assert "parse error:" in r["error"]
    # The length is stored for every refusal, whole or head. This store holds no key, so the digest
    # is recorded as absent, never as a plain hash.
    for r in rows:
        rec = await _record(store, r["id"])
        assert rec["bytes"] == len(body) and rec["body_hmac"] is None
        assert "sha256" not in rec
        assert rec["stored"] == ("whole" if r in whole else "head")
        # A head records the bound it was cut to; the edit-and-resubmit refusal names it.
        assert rec.get("head_bytes") == (None if r in whole else policy.head_bytes)
        # Engine-internal: the API's user-metadata view never shows it.
        assert user_metadata(await store.message_metadata_json(r["id"])) is None

    # The allowance is per inbound: IB_A's flood did not spend IB_B's.
    await runner._handle_inbound(runner.registry.inbound["IB_B"], body)
    last = (await _rows(store))[-1]
    assert last["channel_id"] == "IB_B" and last["raw"] == body.decode()

    # It is rolling: after a window with no refusals, IB_A stores whole again.
    clock.now += policy.window_seconds
    await runner._handle_inbound(ic_a, body)
    assert (await _rows(store))[-1]["raw"] == body.decode()


async def test_the_http_receipt_path_is_bounded_too(store: MessageStore) -> None:
    policy = RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=512)
    runner = _runner(store, [_ic(source=ConnectorType.HTTP)], RefusedBodyAllowance(policy))
    body = _parse_failure(3000)

    for _ in range(20):
        assert await runner._handle_inbound_http(runner.registry.inbound["IB_A"], body) is None

    rows = await _rows(store)
    assert len(rows) == 20
    assert all(r["raw"] == body.decode()[:512] for r in rows)


# --- every refusal phase ---------------------------------------------------------------------------

_LONG = b"Z" * 3000


def _decode_failure() -> tuple[InboundConnection, bytes]:
    return _ic(), _MSH + b"PID|1||" + b"\xff\xfe" * 1500 + b"\r"


def _nul_body() -> tuple[InboundConnection, bytes]:
    return _ic(), _MSH + b"PID|1||" + _LONG + b"\x00" + _LONG + b"\r"


def _declared_type_mismatch() -> tuple[InboundConnection, bytes]:
    return _ic(
        content_type=ContentType.JSON, source=ConnectorType.TCP
    ), b"<xml>" + _LONG + b"</xml>"


def _binary_type_mismatch() -> tuple[InboundConnection, bytes]:
    # Not a DICOM Part-10 object, and NUL-bearing, so the stored view is mfb64 byte carriage.
    return _ic(content_type=ContentType.DICOM, source=ConnectorType.TCP), b"\x00\x01" * 2000


def _text_oversize() -> tuple[InboundConnection, bytes]:
    return (
        _ic(content_type=ContentType.TEXT, source=ConnectorType.TCP),
        b"t" * (16 * 1024 * 1024 + 1),
    )


def _parse() -> tuple[InboundConnection, bytes]:
    return _ic(), _parse_failure(4000)


def _strict() -> tuple[InboundConnection, bytes]:
    # One PV1 too many, so hl7apy refuses it; the padding makes it larger than a head.
    return _ic(strict=True), _STRICT_OK + b"PV1|2|" + _LONG + b"\r"


_PHASES: dict[str, Callable[[], tuple[InboundConnection, bytes]]] = {
    "decode": _decode_failure,
    "nul": _nul_body,
    "declared-type": _declared_type_mismatch,
    "binary-declared-type": _binary_type_mismatch,
    "size": _text_oversize,
    "parse": _parse,
    "strict": _strict,
}


@pytest.mark.parametrize("phase", list(_PHASES))
async def test_every_refusal_phase_stores_a_head_and_the_body_record_once_spent(
    tmp_path: Path, phase: str
) -> None:
    ic, body = _PHASES[phase]()
    head = 512
    spent = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=head)
    )
    unspent = RefusedBodyAllowance()
    results = {}
    for label, allowance in (("spent", spent), ("unspent", unspent)):
        s = await MessageStore.open(tmp_path / f"{label}.db")
        try:
            runner = _runner(s, [ic], allowance)
            ack = await runner._handle_inbound(runner.registry.inbound[ic.name], body)
            rows = await _rows(s)
            assert len(rows) == 1  # count-and-log: the refusal is recorded either way
            row = rows[0]
            assert row["status"] == MessageStatus.ERROR.value
            results[label] = (ack, row, await _record(s, row["id"]))
        finally:
            await s.close()

    (ack_spent, row, rec), (ack_unspent, whole_row, whole_rec) = (
        results["spent"],
        results["unspent"],
    )
    # The sender's answer does not depend on the allowance.
    assert _msa(ack_spent) == _msa(ack_unspent)
    # The record describes the body as received, in both cases.
    assert rec["bytes"] == whole_rec["bytes"] == len(body)
    # These stores hold no key, so the digest is absent; the keyed case has its own test below.
    assert rec["body_hmac"] is None and whole_rec["body_hmac"] is None
    assert (rec["stored"], whole_rec["stored"]) == ("head", "whole")
    # The head is the start of what came in, so an operator still sees it. Byte carriage is kept
    # only when the head itself needs it; a NUL-free head of a carried body stays readable.
    if is_marked(row["raw"]):
        assert decode_carriage(row["raw"]) == body[:head]
    else:
        assert row["raw"] and len(row["raw"].encode()) <= head
        if is_marked(whole_row["raw"]):
            assert body[:head].decode("latin-1").startswith(row["raw"])
        else:
            assert whole_row["raw"].startswith(row["raw"])
    assert "refused-body allowance spent" in row["error"]
    # The note leads, and the reason itself survives after it.
    note, reason = row["error"].split("-byte body] ", 1)
    assert note.startswith("[refused-body allowance spent: ")
    assert reason[:20] and reason[:20] in whole_row["error"]


# --- the allowance itself --------------------------------------------------------------------------


def test_a_body_whose_head_is_the_whole_body_is_stored_whole_and_charges_nothing() -> None:
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=2000, window_seconds=60.0, head_bytes=1000)
    )
    small_text = "x" * 1000
    small_carried = b"\x00\x01" * 400  # 800 bytes, stored as byte carriage of about 1080 characters
    for _ in range(50):
        for wire, text in ((small_text.encode(), small_text), (small_carried, None)):
            bounded = allowance.bound(
                "IB_A", wire, text, ContentType.TEXT.value, "e", cipher=_KEYLESS
            )
            assert json.loads(bounded.metadata)[METADATA_KEY]["stored"] == "whole"
            assert bounded.error == "e"
    # The 100 small bodies charged nothing, so a body the allowance covers is still admitted.
    assert allowance.try_charge("IB_A", 2000)
    assert not allowance.try_charge("IB_A", 1)


def test_the_charge_is_the_utf8_the_store_writes_not_the_characters() -> None:
    # A decode failure stores the latin-1 view, which writes two UTF-8 bytes for each high byte. So
    # a 1500-byte body of high bytes costs 3000, and an allowance of 2999 cannot store it whole.
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=2999, window_seconds=60.0, head_bytes=1000)
    )
    wire = b"\xff" * 1500
    bounded = allowance.bound(
        "IB_A", wire, None, ContentType.HL7V2.value, "decode error", cipher=_KEYLESS
    )
    assert json.loads(bounded.metadata)[METADATA_KEY]["stored"] == "head"
    assert len(bounded.raw.encode()) <= 1000
    # The refusal above charged nothing, so a body costing 2998 still fits the 2999.
    fits = allowance.bound(
        "IB_A", b"\xff" * 1499, None, ContentType.HL7V2.value, "e", cipher=_KEYLESS
    )
    assert json.loads(fits.metadata)[METADATA_KEY]["stored"] == "whole"


def test_the_note_survives_the_stores_own_bound_on_the_error() -> None:
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=256)
    )
    long_reason = "strict-validation failed: " + "PID.3 bad; " * 40
    wire = b"A" * 20_000_000
    bounded = allowance.bound(
        "IB_A", wire, None, ContentType.TEXT.value, long_reason, cipher=_KEYLESS
    )
    assert len(bounded.error) <= 200
    # The store runs safe_text again; the stored text must come through it unchanged.
    assert safe_text(bounded.error) == bounded.error
    assert bounded.error.startswith(
        "[refused-body allowance spent: stored only the head of a 20,000,000-byte body] "
        "strict-validation failed:"
    )


@pytest.mark.parametrize(
    "reason", ["parse error: HL7PeekError: bad MSH|^~\\&|SND", "strict-validation failed: PID|x"]
)
def test_the_note_survives_a_reason_quoting_a_segment(reason: str) -> None:
    # The store's HL7-segment rule redacts from a segment id to the end of the text, so a note after
    # such a reason would be eaten by the store's own second pass.
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=256)
    )
    bounded = allowance.bound(
        "IB_A", b"A" * 5000, None, ContentType.TEXT.value, reason, cipher=_KEYLESS
    )
    assert safe_text(bounded.error).startswith("[refused-body allowance spent: ")


def test_keep_whole_stores_whole_and_charges_nothing() -> None:
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=256)
    )
    wire = b"A" * 5000
    bounded = allowance.bound(
        "IB_A", wire, None, ContentType.TEXT.value, "e", cipher=_KEYLESS, keep_whole=True
    )
    assert bounded.raw == wire.decode() and bounded.error == "e"
    rec = json.loads(bounded.metadata)[METADATA_KEY]
    assert rec == {"bytes": 5000, "body_hmac": None, "stored": "whole"}


# --- the keyed digest ------------------------------------------------------------------------------


def test_the_digest_is_keyed_equal_under_one_key_and_different_under_two() -> None:
    wire = _parse_failure(3000)
    key = generate_key()
    one = refused_body_digest(make_cipher(key), wire)
    assert one is not None
    assert one["alg"] == "hmac-sha256" and one["kdf"] == REFUSED_BODY_DIGEST_KDF
    assert "mefor/refused-body-digest/v1" in one["kdf"]
    # Deterministic under one key, even across two cipher instances built from it.
    assert refused_body_digest(make_cipher(key), wire) == one
    other = refused_body_digest(make_cipher(generate_key()), wire)
    assert other is not None and other["digest"] != one["digest"]
    assert other["key_id"] != one["key_id"]
    # No plain hash: a reader without the key cannot recompute it from a guessed body.
    assert one["digest"] not in _plain_digests(wire)


def test_the_digest_confirms_the_body_only_with_its_key() -> None:
    wire = _parse_failure(3000)
    guess = wire[:-1] + b"B"  # the same head, a different last byte
    old_key, new_key = generate_key(), generate_key()
    record = refused_body_digest(make_cipher(old_key), wire)
    assert verify_refused_body_digest(make_cipher(old_key), wire, record) is True
    assert verify_refused_body_digest(make_cipher(old_key), guess, record) is False
    # Another key, or none, cannot check it: an "unknown", never a "not this body".
    assert verify_refused_body_digest(make_cipher(new_key), wire, record) is None
    assert verify_refused_body_digest(_KEYLESS, wire, record) is None
    # A rotation keeps it checkable while the retired key stays configured.
    assert verify_refused_body_digest(make_cipher(new_key, [old_key]), wire, record) is True
    # A record that is not one (a null body_hmac included), or names another scheme, is "unknown".
    assert record is not None
    cut = record["digest"][:62]  # valid hex, one byte short: a corrupt record, not a mismatch
    for bad in (
        None,
        "x",
        {},
        {**record, "kdf": "hkdf-sha256:other"},
        {**record, "digest": "zz"},
        {**record, "digest": ""},
        {**record, "digest": cut},
        {"bytes": len(wire), "body_hmac": None, "stored": "whole"},
    ):
        assert verify_refused_body_digest(make_cipher(old_key), wire, bad) is None
    # The whole refused-body record, as read back from the metadata, checks like its body_hmac.
    whole = {"bytes": len(wire), "body_hmac": record, "stored": "whole"}
    assert verify_refused_body_digest(make_cipher(old_key), wire, whole) is True


def test_the_digest_is_not_the_edit_resend_audit_digest_of_the_same_bytes() -> None:
    # Its own HKDF label: the same bytes under the same audit key digest differently, so a refused
    # body's digest can never pass for an edit-resend audit digest, or the reverse.
    cipher = make_cipher(generate_key())
    wire = _parse_failure(3000)
    refused = refused_body_digest(cipher, wire)
    audit = audit_body_digests(cipher, body=wire.decode())
    assert refused is not None and audit is not None
    assert refused["key_id"] == audit["key_id"]  # one parent key
    assert refused["digest"] != audit["body"] and refused["kdf"] != audit["kdf"]


class _NoInHeapKey:
    """A cipher that encrypts but holds no audit key in heap, as a Vault Transit cipher does. Only
    the one method the digest reads."""

    def audit_mac_key(self) -> None:
        return None


def test_a_store_with_no_in_heap_key_records_no_digest_rather_than_a_plain_hash() -> None:
    assert refused_body_digest(_KEYLESS, b"MSH|anything") is None
    transit_like = cast(Cipher, _NoInHeapKey())
    assert refused_body_digest(transit_like, b"MSH|anything") is None
    allowance = RefusedBodyAllowance()
    bounded = allowance.bound(
        "IB_A", b"NOT-HL7", None, ContentType.TEXT.value, "e", cipher=transit_like
    )
    assert json.loads(bounded.metadata)[METADATA_KEY]["body_hmac"] is None


async def test_a_keyed_store_records_the_keyed_digest_of_every_refusal(tmp_path: Path) -> None:
    key = generate_key()
    s = await MessageStore.open(tmp_path / "keyed.db", cipher=make_cipher(key))
    try:
        policy = RefusedBodyPolicy(allowance_bytes=4096, window_seconds=60.0, head_bytes=512)
        runner = _runner(s, [_ic()], RefusedBodyAllowance(policy))
        body = _parse_failure(3000)
        for _ in range(3):
            await runner._handle_inbound(runner.registry.inbound["IB_A"], body)
        rows = await _rows(s)
        recs = [await _record(s, r["id"]) for r in rows]
    finally:
        await s.close()
    assert [r["stored"] for r in recs] == ["whole", "head", "head"]
    first = recs[0]["body_hmac"]
    assert all(r["body_hmac"] == first for r in recs)
    assert verify_refused_body_digest(make_cipher(key), body, first) is True
    assert "sha256" not in recs[0] and first["digest"] not in _plain_digests(body)


@pytest.mark.parametrize("phase", list(_PHASES))
async def test_every_refusal_phase_digests_the_body_as_received(tmp_path: Path, phase: str) -> None:
    # The digest is over the received bytes in every phase, never the decoded text, the stored view
    # or the head, so it matches the sender's copy whichever phase refused it.
    ic, body = _PHASES[phase]()
    key = generate_key()
    spent = RefusedBodyAllowance(RefusedBodyPolicy(allowance_bytes=0, head_bytes=512))
    for label, allowance in (("spent", spent), ("unspent", RefusedBodyAllowance())):
        s = await MessageStore.open(tmp_path / f"{label}.db", cipher=make_cipher(key))
        try:
            runner = _runner(s, [ic], allowance)
            await runner._handle_inbound(runner.registry.inbound[ic.name], body)
            (row,) = await _rows(s)
            rec = await _record(s, row["id"])
        finally:
            await s.close()
        assert rec["stored"] == ("head" if label == "spent" else "whole")
        assert verify_refused_body_digest(make_cipher(key), body, rec["body_hmac"]) is True


async def test_a_poll_sources_refusals_are_kept_whole(store: MessageStore) -> None:
    # A poll source consumes the only copy (a file it deletes, a row it marks), so the runner never
    # stores its refusals as heads. Keyed on the transport's own declared contract.
    assert FileSource.polls_shared_resource and DatabaseSource.polls_shared_resource
    assert not MLLPSource.polls_shared_resource and not HttpSource.polls_shared_resource
    policy = RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=512)
    runner = _runner(store, [_ic()], RefusedBodyAllowance(policy))
    runner._refusals_kept_whole.add("IB_A")  # what binding a poll source sets
    body = _parse_failure(4000)
    for _ in range(5):
        await runner._handle_inbound(runner.registry.inbound["IB_A"], body)
    assert [r["raw"] for r in await _rows(store)] == [body.decode()] * 5


@pytest.mark.parametrize(
    ("wire", "text"),
    [
        (b"plain ascii", None),
        (b"\xff\xfe high bytes", None),
        (b"has a \x00 nul", None),
        ("caf\u00e9".encode(), "caf\u00e9"),
        (b"nul \x00 text", "nul \x00 text"),
        (b"", None),
    ],
)
def test_the_charge_matches_what_store_safe_raw_writes(wire: bytes, text: str | None) -> None:
    carried, size = refused_body._stored_form(wire, text)
    written = store_safe_raw(wire, ContentType.TEXT.value, text=text)
    assert carried == is_marked(written)
    assert size == len(written.encode())


def test_a_text_that_opens_with_the_carriage_marker_is_never_cut_into_broken_carriage() -> None:
    payload = b"\x00\x01" * 3000
    text = "mfb64:v1:" + base64.b64encode(payload).decode()
    head = refused_body._head(text.encode(), text, ContentType.JSON.value, 512)
    assert is_marked(head)
    assert decode_carriage(head) == text.encode()[:512]


def test_the_allowance_refills_evenly_and_never_past_its_capacity() -> None:
    clock = _Clock()
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=6000, window_seconds=60.0, head_bytes=10), clock=clock
    )
    assert allowance.try_charge("IB_A", 6000)
    assert not allowance.try_charge("IB_A", 100)
    clock.now += 30.0  # half a window refills half the allowance
    assert allowance.try_charge("IB_A", 3000)
    assert not allowance.try_charge("IB_A", 100)
    clock.now += 600.0  # ten windows idle still refill only one allowance
    assert not allowance.try_charge("IB_A", 6001)
    assert allowance.try_charge("IB_A", 6000)


def test_a_text_head_is_cut_at_a_character_boundary() -> None:
    view = "é" * 100  # two UTF-8 bytes each
    head = refused_body._head(view.encode(), view, ContentType.TEXT.value, 51)
    assert head == "é" * 25 and len(head.encode()) <= 51


def test_the_policy_refuses_values_that_would_switch_it_off() -> None:
    with pytest.raises(ValueError):
        RefusedBodyPolicy(allowance_bytes=-1)
    with pytest.raises(ValueError):
        RefusedBodyPolicy(window_seconds=0)
    with pytest.raises(ValueError):
        RefusedBodyPolicy(head_bytes=0)


def test_the_settings_ship_on_with_the_module_defaults() -> None:
    s = InboundSettings()
    assert s.refused_body_allowance_bytes == refused_body.DEFAULT_ALLOWANCE_BYTES
    assert s.refused_body_window_seconds == refused_body.DEFAULT_WINDOW_SECONDS
    assert s.refused_body_head_bytes == refused_body.DEFAULT_HEAD_BYTES
    assert s.refused_body_allowance_bytes > 0
    for bad in (
        {"refused_body_allowance_bytes": -1.0},
        {"refused_body_window_seconds": 0.5},
        {"refused_body_head_bytes": 1048577.0},
        {"refused_body_head_bytes": 255.0},
    ):
        with pytest.raises(ValidationError):
            InboundSettings.model_validate(bad)
