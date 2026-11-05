# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3411, key custody slice S3: the genesis row may record the store id.

A label only: the row MAC covers it, and no key is derived from it. No caller passes one yet, so a
store writes today's shape. These tests pin the record and its parser; the chain behaviour runs on all
three backends from ``tests/audit_chain_cases.py``.
"""

from __future__ import annotations

import json

import pytest

from messagefoundry.store.crypto import AUDIT_SCHEME_IN_HEAP, NO_STORE_ID, STORE_ID_BYTES
from messagefoundry.store.store import (
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
    assert parse_audit_genesis_store_id(detail) is None


def test_a_genesis_record_with_a_store_id_round_trips() -> None:
    detail = audit_genesis_detail(_KEY_ID, _STORE_ID)
    assert json.loads(detail)["store_id"] == _STORE_ID.hex()
    assert parse_audit_genesis_record(detail) == (_KEY_ID, AUDIT_SCHEME_IN_HEAP)
    assert parse_audit_genesis(detail) == _KEY_ID
    assert parse_audit_genesis_store_id(detail) == _STORE_ID
    # A store id does not make a genesis record a range record, nor a range record a genesis one.
    assert parse_audit_epoch(detail) is None


def test_a_store_id_on_a_record_naming_no_scheme_is_refused() -> None:
    """No release wrote that shape: the field postdates BACKLOG #3420, and every writer since names
    the scheme. So a well-formed id there is refused, never read as the unnamed scheme."""
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID, "store_id": _STORE_ID.hex()})
    record = parse_audit_genesis_record(legacy)
    assert record is not None and record[0] == _KEY_ID
    refusal = audit_scheme_refusal(*record)
    assert refusal is not None and "malformed store_id" in refusal
    with pytest.raises(ValueError, match="store_id is malformed"):
        parse_audit_genesis_store_id(legacy)


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
    of rows change what the chain is. The refusal names the store id, not the scheme, which is
    well formed here. A record naming no scheme is refused the same way; the well-formed id in
    :func:`test_a_genesis_record_with_a_store_id_round_trips` is the control."""
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID, "store_id": store_id})
    for detail in (legacy, genesis_record_with_store_id(_KEY_ID, store_id)):
        record = parse_audit_genesis_record(detail)
        assert record is not None and record[0] == _KEY_ID
        refusal = audit_scheme_refusal(*record)
        assert refusal is not None and "malformed store_id" in refusal, refusal
        with pytest.raises(ValueError, match="store_id is malformed"):
            parse_audit_genesis_store_id(detail)


def test_a_store_id_refusal_cannot_be_named_by_a_record() -> None:
    """The store-id refusal is matched by identity: a record naming an empty scheme pair is refused
    as a scheme, and does not borrow the store-id message."""
    detail = json.dumps({"genesis": 1, "key_id": _KEY_ID, "mac": "", "kdf": ""})
    record = parse_audit_genesis_record(detail)
    assert record is not None
    refusal = audit_scheme_refusal(*record)
    assert refusal is not None and "store_id" not in refusal
    assert parse_audit_genesis_store_id(detail) is None


def test_a_store_id_does_not_rescue_a_record_missing_its_own_fields() -> None:
    assert (
        parse_audit_genesis_record(json.dumps({"genesis": 1, "store_id": _STORE_ID.hex()})) is None
    )
    assert parse_audit_genesis_record(json.dumps({"store_id": _STORE_ID.hex()})) is None


def test_a_range_record_carrying_a_store_id_is_refused() -> None:
    """The label is a genesis field only: on a range record it is a field beyond the record, refused
    as such (ADR 0193 item 3). The control is the same record without it, which is held."""
    closes = {"key_id": "a", "from_seq": 1, "to_seq": 1, "rows": 1, "digest": "", "prev_hash": ""}
    held = {"mac": AUDIT_SCHEME_IN_HEAP.mac, "kdf": AUDIT_SCHEME_IN_HEAP.kdf}
    record = {"key_id": _KEY_ID, "closes": closes, "handover": "t", **held}
    epoch = parse_audit_epoch(json.dumps(record))
    assert epoch is not None and audit_scheme_refusal(epoch.key_id, epoch.scheme) is None
    epoch = parse_audit_epoch(json.dumps({**record, "store_id": _STORE_ID.hex()}))
    assert epoch is not None and audit_scheme_refusal(epoch.key_id, epoch.scheme) is not None
