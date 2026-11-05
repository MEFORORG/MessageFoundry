# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3411, key custody slice S3: the genesis row may record the store id.

A label only: the row MAC covers it, and no key is derived from it. No caller passes one yet, so a
store writes today's shape. These tests pin the record and its parser; the chain behaviour runs on all
three backends from ``tests/audit_chain_cases.py``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.store.crypto import (
    AUDIT_KEYLESS_MAC,
    AUDIT_SCHEME_IN_HEAP,
    NO_STORE_ID,
    STORE_ID_BYTES,
)
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    AuditGenesisStoreId,
    _audit_row_mac_check,
    audit_genesis_detail,
    audit_scheme_refusal,
    parse_audit_epoch,
    parse_audit_genesis,
    parse_audit_genesis_record,
    parse_audit_genesis_store_id,
)
from tests.audit_chain_cases import MALFORMED_STORE_IDS, genesis_record_with_store_id

_KEY_ID = "key-under-test"
_STORE_ID = bytes(range(STORE_ID_BYTES))


# --- the genesis record ------------------------------------------------------------------------------


def test_a_genesis_record_in_todays_shape_records_no_store_id() -> None:
    detail = audit_genesis_detail(_KEY_ID)
    assert "store_id" not in json.loads(detail)
    # NO_STORE_ID, what every other store-id API takes before one is minted, records none too.
    assert audit_genesis_detail(_KEY_ID, NO_STORE_ID) == detail
    assert parse_audit_genesis_record(detail) == (_KEY_ID, AUDIT_SCHEME_IN_HEAP)
    assert parse_audit_genesis_store_id(detail) == AuditGenesisStoreId(None, refused=False)
    # Not a genesis record at all is a third answer, apart from both.
    assert parse_audit_genesis_store_id(json.dumps({"key_id": _KEY_ID})) is None


def test_a_genesis_record_with_a_store_id_round_trips() -> None:
    detail = audit_genesis_detail(_KEY_ID, _STORE_ID)
    assert json.loads(detail)["store_id"] == _STORE_ID.hex()
    assert parse_audit_genesis_record(detail) == (_KEY_ID, AUDIT_SCHEME_IN_HEAP)
    assert parse_audit_genesis(detail) == _KEY_ID
    assert parse_audit_genesis_store_id(detail) == AuditGenesisStoreId(_STORE_ID, refused=False)
    # A store id does not make a genesis record a range record, nor a range record a genesis one.
    assert parse_audit_epoch(detail) is None


def test_a_store_id_on_a_record_naming_no_scheme_is_refused_as_naming_no_scheme() -> None:
    """No release wrote that shape: the field postdates BACKLOG #3420, and every writer since names
    the scheme. So a well-formed id there is refused, never read as the unnamed scheme, and the
    refusal names the missing scheme, the real defect, not the well-formed id."""
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID, "store_id": _STORE_ID.hex()})
    record = parse_audit_genesis_record(legacy)
    assert record is not None and record[0] == _KEY_ID
    refusal = audit_scheme_refusal(*record)
    assert refusal is not None and "names no scheme" in refusal, refusal
    assert "malformed" not in refusal, refusal
    assert parse_audit_genesis_store_id(legacy) == AuditGenesisStoreId(None, refused=True)


@pytest.mark.parametrize("length", [1, STORE_ID_BYTES - 1, STORE_ID_BYTES + 1])
def test_the_writer_refuses_a_store_id_of_another_length(length: int) -> None:
    with pytest.raises(ValueError, match="a store id is 16 bytes"):
        audit_genesis_detail(_KEY_ID, b"\x01" * length)


@pytest.mark.parametrize(
    "store_id",
    [
        *MALFORMED_STORE_IDS,
        " " + "ab" * STORE_ID_BYTES,
        "ab" * STORE_ID_BYTES + "\n",
        {"id": "ab" * STORE_ID_BYTES},
    ],
)
def test_a_malformed_store_id_reads_as_a_genesis_record_and_is_refused(store_id: object) -> None:
    """Refused, never read as no store id and never as no genesis record: either would let a writer
    of rows change what the chain is. Beside a well-formed scheme the refusal names the store id;
    on a record naming no scheme it names the missing scheme first, whatever the id. The
    well-formed id in :func:`test_a_genesis_record_with_a_store_id_round_trips` is the control."""
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID, "store_id": store_id})
    named = genesis_record_with_store_id(_KEY_ID, store_id)
    for detail, needle in ((legacy, "names no scheme"), (named, "malformed store_id")):
        record = parse_audit_genesis_record(detail)
        assert record is not None and record[0] == _KEY_ID
        refusal = audit_scheme_refusal(*record)
        assert refusal is not None and needle in refusal, refusal
        assert parse_audit_genesis_store_id(detail) == AuditGenesisStoreId(None, refused=True)


def test_a_store_id_refusal_cannot_be_named_by_a_record() -> None:
    """The store-id refusal is a class of its own: a record naming an empty scheme pair is refused
    as a scheme, and does not borrow the store-id message."""
    detail = json.dumps({"genesis": 1, "key_id": _KEY_ID, "mac": "", "kdf": ""})
    record = parse_audit_genesis_record(detail)
    assert record is not None
    refusal = audit_scheme_refusal(*record)
    assert refusal is not None and "store_id" not in refusal
    assert parse_audit_genesis_store_id(detail) == AuditGenesisStoreId(None, refused=True)


@pytest.mark.parametrize("store_id", ["ab" * STORE_ID_BYTES, "AB" * STORE_ID_BYTES])
def test_a_refused_scheme_speaks_before_the_store_id(store_id: str) -> None:
    """A record naming the keyless mode is reported as that, whatever its store id: a malformed
    label must not hide it, and a well-formed one on a refused record is never handed out."""
    keyless = {"mac": AUDIT_KEYLESS_MAC, "kdf": "x"}
    detail = json.dumps({"genesis": 1, "key_id": _KEY_ID, **keyless, "store_id": store_id})
    record = parse_audit_genesis_record(detail)
    assert record is not None
    refusal = audit_scheme_refusal(*record)
    assert refusal is not None and "keyless store mode" in refusal, refusal
    assert parse_audit_genesis_store_id(detail) == AuditGenesisStoreId(None, refused=True)


def test_a_store_id_does_not_rescue_a_record_missing_its_own_fields() -> None:
    assert (
        parse_audit_genesis_record(json.dumps({"genesis": 1, "store_id": _STORE_ID.hex()})) is None
    )
    assert parse_audit_genesis_record(json.dumps({"store_id": _STORE_ID.hex()})) is None


#: A range record's ``closes`` and the scheme this release holds for an in-heap key.
_CLOSES = {"key_id": "a", "from_seq": 1, "to_seq": 1, "rows": 1, "digest": "", "prev_hash": ""}
_HELD = {"mac": AUDIT_SCHEME_IN_HEAP.mac, "kdf": AUDIT_SCHEME_IN_HEAP.kdf}


def test_a_range_record_carrying_a_store_id_is_not_yet_admitted() -> None:
    """Not yet, not never: until the key-custody restore slice lands, a store id on a range record
    is a field beyond the record, refused as such (ADR 0193 item 3, amended 2026-11-04). That
    draft's rule 4 restore appends a range row naming the new store id, and that slice changes this
    test. The control is the same record without it, which is held."""
    record = {"key_id": _KEY_ID, "closes": _CLOSES, "handover": "t", **_HELD}
    epoch = parse_audit_epoch(json.dumps(record))
    assert epoch is not None and audit_scheme_refusal(epoch.key_id, epoch.scheme) is None
    epoch = parse_audit_epoch(json.dumps({**record, "store_id": _STORE_ID.hex()}))
    assert epoch is not None and audit_scheme_refusal(epoch.key_id, epoch.scheme) is not None


# --- the Transit attestation gap names a class, never a record's text --------------------------------

#: A value anyone who can write the audit log could put in a record.
_MARKER = "RECORD-SUPPLIED-TEXT"
_UNKNOWN = {"mac": _MARKER + "-mac", "kdf": _MARKER + "-kdf"}
_KEYLESS = {"mac": AUDIT_KEYLESS_MAC, "kdf": _MARKER + "-kdf"}
_KEY = _MARKER + "-key"
_SCHEME = "names an audit scheme this release does not hold"


@pytest.mark.parametrize(
    ("opening_seq", "record", "phrase"),
    [
        (1, {"genesis": 1, "key_id": _KEY, **_UNKNOWN}, _SCHEME),
        (1, {"genesis": 1, "key_id": _KEY, **_UNKNOWN, "store_id": _MARKER}, _SCHEME),
        (
            1,
            {"genesis": 1, "key_id": _KEY, **_KEYLESS, "store_id": _MARKER},
            "names the keyless store mode, which no audit record may name",
        ),
        (
            1,
            {"genesis": 1, "key_id": _KEY, **_HELD, "store_id": _MARKER},
            "opens with a record that carries a malformed store_id",
        ),
        (
            1,
            {"genesis": 1, "key_id": _KEY, "store_id": _MARKER},
            "opens with a record that carries a store_id but names no scheme",
        ),
        (2, {"key_id": _KEY, "closes": _CLOSES, "handover": _MARKER, **_UNKNOWN}, _SCHEME),
    ],
)
async def test_the_one_row_check_names_the_refusal_class_in_fixed_words(
    opening_seq: int, record: dict[str, Any], phrase: str
) -> None:
    """The Transit attestation gap and the one-row evidence read report a refused range in fixed
    words from a fixed set. The refusal's own words quote ``mac``, ``kdf`` and ``key_id``, which
    anyone who can write the audit log chooses, so none of the record's text reaches the message.
    The marker check bites only where the refusal quotes the record (the control below); in the
    other cases the exact phrase is what the test pins."""
    detail = json.dumps(record)

    async def fetch(sql: str, params: tuple[object, ...]) -> dict[str, Any] | None:
        if sql.startswith("SELECT row_hash"):
            return {"row_hash": "0" * 64}
        return {"seq": opening_seq, "action": AUDIT_KEY_EPOCH_ACTION, "detail": detail}

    found = await _audit_row_mac_check({}, 3, fetch, mac_keys={}, mac_fn=None)
    assert found == f"audit row 3's key range {phrase}"
    assert isinstance(found, str) and _MARKER not in found
    # The control: where the refusal itself quotes the record, the check above would see a leak.
    if phrase == _SCHEME:
        epoch = parse_audit_epoch(detail)
        parsed = (
            parse_audit_genesis_record(detail) if epoch is None else (epoch.key_id, epoch.scheme)
        )
        assert parsed is not None and _MARKER in (audit_scheme_refusal(*parsed) or "")
