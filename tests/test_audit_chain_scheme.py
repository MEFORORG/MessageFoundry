# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3420 -- each keyed range of the audit chain names the scheme it is sealed with.

The genesis row and every range row name the row MAC algorithm and the key derivation beside the
key (ADR 0193, amendment 2026-10-20). A record that names none is read as the scheme this release
seals that key with; any other name is refused, and no record may name the keyless store mode.

The backend behaviour runs on all three backends from ``tests/audit_chain_cases.py``. This file
holds what is not backend behaviour: the refusal rule, the two parsers, the handover tag over the
scheme, one-row evidence reads, the anchor width and the Transit algorithm.

Severity is conditional (CLAUDE.md section 0): zero deployments, so a swap of either name would
have stranded the rows of a first deployment, not of a live one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    AUDIT_KEYLESS_MAC,
    AUDIT_SCHEME_IN_HEAP,
    AUDIT_SCHEME_TRANSIT,
    AUDIT_SCHEME_UNNAMED_IN_HEAP,
    AUDIT_SCHEME_UNNAMED_TRANSIT,
    AuditScheme,
    audit_key_id,
    generate_key,
    make_cipher,
)
from messagefoundry.store.store import (
    AUDIT_ANCHOR_DIGEST_HEX_LEN,
    AUDIT_KEY_EPOCH_ACTION,
    AUDIT_TRANSIT_KEY_ID,
    audit_genesis_detail,
    audit_handover_tag,
    audit_range_closing,
    audit_row_hash,
    audit_scheme_for,
    audit_scheme_refusal,
    parse_audit_anchor,
    parse_audit_epoch,
    parse_audit_genesis,
    parse_audit_genesis_record,
    verify_audit_rows,
)
from tests.audit_chain_cases import _mac_key, _write_chain, epoch_record, genesis_record

_UNKNOWN = AuditScheme(mac="hmac-sha3-256", kdf="hkdf-sha256:mefor/audit-chain/v2")
_KEYLESS = AuditScheme(mac=AUDIT_KEYLESS_MAC, kdf="none")
_KEY_ID = "key-under-test"


# --- the refusal rule ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_id", [_KEY_ID, AUDIT_TRANSIT_KEY_ID])
def test_a_record_naming_no_scheme_or_its_own_is_held(key_id: str) -> None:
    assert audit_scheme_refusal(key_id, None) is None
    assert audit_scheme_refusal(key_id, audit_scheme_for(key_id)) is None


@pytest.mark.parametrize("key_id", [_KEY_ID, AUDIT_TRANSIT_KEY_ID])
def test_the_keyless_mode_is_refused_for_every_key_kind(key_id: str) -> None:
    for kdf in ("none", AUDIT_SCHEME_IN_HEAP.kdf, AUDIT_SCHEME_TRANSIT.kdf):
        refusal = audit_scheme_refusal(key_id, AuditScheme(mac=AUDIT_KEYLESS_MAC, kdf=kdf))
        assert refusal is not None and "keyless store mode" in refusal


def test_an_unknown_scheme_and_the_other_key_kinds_scheme_are_refused() -> None:
    # A stored marker chooses only among the schemes compiled in, and only the one for its key.
    assert audit_scheme_refusal(_KEY_ID, _UNKNOWN) is not None
    assert audit_scheme_refusal(_KEY_ID, AUDIT_SCHEME_TRANSIT) is not None
    assert audit_scheme_refusal(AUDIT_TRANSIT_KEY_ID, AUDIT_SCHEME_IN_HEAP) is not None
    # A refusal quotes attacker-written text bounded, never whole.
    long = AuditScheme(mac="x" * 10_000, kdf="y" * 10_000)
    refusal = audit_scheme_refusal(_KEY_ID, long)
    assert refusal is not None and len(refusal) < 400


def test_the_in_heap_scheme_names_the_label_the_key_is_derived_under() -> None:
    assert (
        AuditScheme(mac="hmac-sha256", kdf="hkdf-sha256:mefor/audit-chain/v1")
        == AUDIT_SCHEME_IN_HEAP
    )
    assert audit_scheme_for(AUDIT_TRANSIT_KEY_ID) == AUDIT_SCHEME_TRANSIT


# --- the parsers ----------------------------------------------------------------------------------


def test_a_genesis_record_names_its_scheme_and_one_written_before_does_not() -> None:
    named = audit_genesis_detail(_KEY_ID)
    assert json.loads(named)["mac"] == AUDIT_SCHEME_IN_HEAP.mac
    assert parse_audit_genesis_record(named) == (_KEY_ID, AUDIT_SCHEME_IN_HEAP)
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID}, sort_keys=True)
    assert genesis_record(_KEY_ID, None) == legacy
    assert parse_audit_genesis_record(legacy) == (_KEY_ID, None)
    assert parse_audit_genesis(legacy) == parse_audit_genesis(named) == _KEY_ID
    # A Transit genesis row names Transit's scheme.
    transit = parse_audit_genesis_record(audit_genesis_detail(AUDIT_TRANSIT_KEY_ID))
    assert transit == (AUDIT_TRANSIT_KEY_ID, AUDIT_SCHEME_TRANSIT)
    # An unknown scheme still reads as a genesis row: refusing it is the refusal rule's job, so a
    # handle with no key still reads the chain as keyed.
    assert parse_audit_genesis_record(genesis_record(_KEY_ID, _UNKNOWN)) == (
        _KEY_ID,
        _UNKNOWN,
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"mac": "hmac-sha256"},  # half a scheme
        {"mac": AUDIT_KEYLESS_MAC},  # half of the keyless mode
        {"mac": "hmac-sha256", "kdf": 1},
        {"mac": "", "kdf": "x"},
        {"other": 1},  # a field beyond the record, which before #3420 the range parser ignored
        {"mac": AUDIT_SCHEME_IN_HEAP.mac, "kdf": AUDIT_SCHEME_IN_HEAP.kdf, "other": 1},
    ],
)
def test_a_malformed_scheme_still_reads_as_a_record_and_is_refused(extra: dict[str, Any]) -> None:
    """Read as no record, a malformed pair would let a writer of rows turn a keyed chain's genesis
    row into none, and its chain into a keyless one for a handle with no key. So it reads as a
    record naming a scheme no release holds. The control is the in-heap pair, which is held."""
    genesis = parse_audit_genesis_record(json.dumps({"genesis": 1, "key_id": _KEY_ID, **extra}))
    assert genesis is not None and genesis[0] == _KEY_ID
    assert audit_scheme_refusal(*genesis) is not None
    closes = {"key_id": "a", "from_seq": 1, "to_seq": 1, "rows": 1, "digest": "", "prev_hash": ""}
    epoch = parse_audit_epoch(
        json.dumps({"key_id": _KEY_ID, "closes": closes, "handover": "t", **extra})
    )
    assert epoch is not None and audit_scheme_refusal(epoch.key_id, epoch.scheme) is not None
    held = {"mac": AUDIT_SCHEME_IN_HEAP.mac, "kdf": AUDIT_SCHEME_IN_HEAP.kdf}
    genesis = parse_audit_genesis_record(json.dumps({"genesis": 1, "key_id": _KEY_ID, **held}))
    assert genesis is not None and audit_scheme_refusal(*genesis) is None


def test_a_record_missing_one_of_its_own_fields_is_no_record() -> None:
    """Only a record missing a field of its own is no record at all; that, and renaming the row's
    action, is the rewrite a handle with no key still reads as a keyless chain (ADR 0193 amendment
    2026-10-20, item 4). The control is the whole record, which parses."""
    closes = {"key_id": "a", "from_seq": 1, "to_seq": 1, "rows": 1, "digest": "", "prev_hash": ""}
    epoch = {"key_id": _KEY_ID, "closes": closes, "handover": "t"}
    assert parse_audit_epoch(json.dumps({"key_id": _KEY_ID, "closes": closes})) is None
    assert parse_audit_genesis_record(json.dumps({"genesis": 1})) is None
    assert parse_audit_epoch(json.dumps(epoch)) is not None


def test_a_record_that_names_no_scheme_is_read_as_a_fixed_pre_3420_name() -> None:
    """Fixed, not "whatever this release writes": a release that changes the written scheme must
    still read an older record as what sealed it. Today the two are the same."""
    assert (
        AuditScheme(mac="hmac-sha256", kdf="hkdf-sha256:mefor/audit-chain/v1")
        == AUDIT_SCHEME_UNNAMED_IN_HEAP
    )
    assert (
        AuditScheme(mac="vault-transit:hmac-sha2-256", kdf="vault-transit")
        == AUDIT_SCHEME_UNNAMED_TRANSIT
    )
    assert audit_scheme_for(_KEY_ID) == AUDIT_SCHEME_UNNAMED_IN_HEAP
    assert audit_scheme_for(AUDIT_TRANSIT_KEY_ID) == AUDIT_SCHEME_UNNAMED_TRANSIT


# --- a range row, walked in memory ---------------------------------------------------------------


def _rotated_chain(
    *, scheme: AuditScheme | None, tag_scheme: AuditScheme | None
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """A chain of genesis, one row, a range row from key A to key B, and one row, each MAC'd by the
    holder of its key. The range row names ``scheme``; its handover tag was taken over
    ``tag_scheme``."""
    a_mac, b_mac = _mac_key(generate_key()), _mac_key(generate_key())
    a_id, b_id = audit_key_id(a_mac), audit_key_id(b_mac)
    rows: list[dict[str, Any]] = []

    def add(action: str, detail: str, key: bytes) -> None:
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
        row["row_hash"] = audit_row_hash(
            prev, **{k: v for k, v in row.items() if k != "id"}, key=key
        )
        rows.append(row)

    add(AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(a_id), a_mac)
    add("act", "{}", a_mac)
    closes = audit_range_closing(rows, key_id=a_id, from_seq=1, prev_hash="")
    tag = audit_handover_tag(b_id, closes, (a_mac, None), scheme=tag_scheme)
    add(AUDIT_KEY_EPOCH_ACTION, epoch_record(b_id, closes, tag, scheme), b_mac)
    add("act", "{}", b_mac)
    return rows, {a_id: a_mac, b_id: b_mac}


def _verify(rows: list[dict[str, Any]], keys: dict[str, bytes]) -> tuple[bool, str | None]:
    ok, message = verify_audit_rows(rows, mac_keys=keys, mac_fn=None, capable=True)
    return ok, message


@pytest.mark.parametrize("scheme", [AUDIT_SCHEME_IN_HEAP, None])
def test_a_range_row_naming_its_scheme_or_none_verifies(scheme: AuditScheme | None) -> None:
    # None is a range row written before #3420, tagged without a scheme.
    assert _verify(*_rotated_chain(scheme=scheme, tag_scheme=scheme)) == (
        True,
        "verified 4 audit row(s)",
    )


@pytest.mark.parametrize(("scheme", "reason"), [(_UNKNOWN, "does not seal"), (_KEYLESS, "keyless")])
def test_a_range_row_naming_a_refused_scheme_is_a_break_though_its_holders_sealed_it(
    scheme: AuditScheme, reason: str
) -> None:
    ok, message = _verify(*_rotated_chain(scheme=scheme, tag_scheme=scheme))
    assert not ok and "seq=3" in (message or "") and reason in (message or ""), message


def test_the_handover_tag_covers_the_scheme_the_range_row_names() -> None:
    """A holder of the incoming key alone cannot change the scheme a range row names: the outgoing
    key's tag was taken over it. The row's MAC is valid here, since the incoming key's holder
    sealed it, so the tag is the check that fires."""
    ok, message = _verify(*_rotated_chain(scheme=None, tag_scheme=AUDIT_SCHEME_IN_HEAP))
    assert not ok and "not authorised" in (message or ""), message
    ok, message = _verify(*_rotated_chain(scheme=AUDIT_SCHEME_IN_HEAP, tag_scheme=None))
    assert not ok and "not authorised" in (message or ""), message


# --- one-row evidence reads ------------------------------------------------------------------------


@pytest.mark.parametrize(("scheme", "found"), [(AUDIT_SCHEME_IN_HEAP, True), (_UNKNOWN, False)])
async def test_a_one_row_evidence_read_refuses_a_range_naming_an_unknown_scheme(
    tmp_path: Path, scheme: AuditScheme, found: bool
) -> None:
    """``newest_keyed_audit_row`` checks one row against its range's key, so it reads the scheme
    the range names too. The control is the in-heap scheme, whose row is returned."""
    from tests.test_audit_chain_genesis import _sqlite_backend

    backend = _sqlite_backend(tmp_path / "chain.db")
    await backend.reset()
    key = generate_key()
    mac = _mac_key(key)
    key_id = audit_key_id(mac)
    await _write_chain(
        backend,
        [
            (AUDIT_KEY_EPOCH_ACTION, genesis_record(key_id, scheme), mac),
            ("act", "{}", mac),
        ],
    )
    cipher = make_cipher(key)
    store = await MessageStore.open(
        tmp_path / "chain.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
    )
    try:
        row = await store.newest_keyed_audit_row("act", actor="u", after_seq=0)
    finally:
        await store.close()
    assert (row is not None) is found


# --- the anchor width and the Transit algorithm ----------------------------------------------------


def test_the_anchor_width_is_the_width_of_every_hex_head_the_chain_can_produce() -> None:
    keyless = audit_row_hash(
        "", seq=1, ts=1.0, actor=None, action="a", channel_id=None, detail=None
    )
    keyed = audit_row_hash(
        "", seq=1, ts=1.0, actor=None, action="a", channel_id=None, detail=None, key=b"k" * 32
    )
    assert len(keyless) == len(keyed) == AUDIT_ANCHOR_DIGEST_HEX_LEN
    assert 2 * hmac.new(b"k", b"", hashlib.sha256).digest_size == AUDIT_ANCHOR_DIGEST_HEX_LEN
    assert parse_audit_anchor(f"1:{keyed}") == (1, keyed)
    with pytest.raises(ValueError, match="hex characters"):
        parse_audit_anchor(f"1:{keyed[:-2]}")
