# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2608: a refused inbound body stores whole only inside a per-inbound allowance.

Every refusal before ingress used to store the full body, up to the 16 MiB frame limit, and no intake
bound counted it. These tests flood the refusal path and pin four properties:

* the allowance holds: past it, only the head of each refused body is stored, so the bytes stored
  stay under ``allowance + count * head``;
* every refused body's length and SHA-256 are stored, inside the allowance and past it;
* count-and-log holds: every refusal is still one ``ERROR`` row, and the ACK or NAK the sender gets
  is the same as with an unspent allowance;
* it covers EVERY refusal phase, the parse failure included, because a bound that skipped one phase
  would not bound a sender who sends bodies that fail there.

Synthetic HL7 only; no real PHI.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings, InboundSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.binary import decode as decode_carriage
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline import refused_body
from messagefoundry.pipeline.refused_body import (
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.metadata import user_metadata

_MSH = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|MSG1|P|2.5.1\r"
_STRICT_OK = _MSH + b"EVN|A01|20260101\rPID|1||MRN123^^^H^MR||DOE^JANE\rPV1|1|I\r"


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
        assert r["error"].startswith("parse error:")
    # Length and SHA-256 are stored for every refusal, whole or head.
    digest = hashlib.sha256(body).hexdigest()
    for r in rows:
        rec = await _record(store, r["id"])
        assert rec["bytes"] == len(body) and rec["sha256"] == digest
        assert rec["stored"] == ("whole" if r in whole else "head")
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
    digest = hashlib.sha256(body).hexdigest()
    assert rec["bytes"] == whole_rec["bytes"] == len(body)
    assert rec["sha256"] == whole_rec["sha256"] == digest
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
    # The reason itself survives in front of the note.
    assert row["error"].split(" [refused-body")[0] in whole_row["error"]


# --- the allowance itself --------------------------------------------------------------------------


def test_a_body_no_larger_than_a_head_is_stored_whole_and_charges_nothing() -> None:
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=2000, window_seconds=60.0, head_bytes=1000)
    )
    for _ in range(100):
        assert allowance.admit("IB_A", 1000)
    # The 100 small bodies charged nothing, so a body the allowance covers is still admitted.
    assert allowance.admit("IB_A", 2000)
    assert not allowance.admit("IB_A", 1001)


def test_the_allowance_refills_evenly_and_never_past_its_capacity() -> None:
    clock = _Clock()
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=6000, window_seconds=60.0, head_bytes=10), clock=clock
    )
    assert allowance.admit("IB_A", 6000)
    assert not allowance.admit("IB_A", 100)
    clock.now += 30.0  # half a window refills half the allowance
    assert allowance.admit("IB_A", 3000)
    assert not allowance.admit("IB_A", 100)
    clock.now += 600.0  # ten windows idle still refill only one allowance
    assert not allowance.admit("IB_A", 6001)
    assert allowance.admit("IB_A", 6000)


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
        {"refused_body_window_seconds": 0.0},
        {"refused_body_head_bytes": 255.0},
    ):
        with pytest.raises(ValidationError):
            InboundSettings.model_validate(bad)
