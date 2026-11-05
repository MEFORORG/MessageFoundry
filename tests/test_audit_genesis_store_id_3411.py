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

from messagefoundry.store.crypto import AUDIT_SCHEME_IN_HEAP, STORE_ID_BYTES
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
    # A record that names no scheme, written before BACKLOG #3420, may carry one too.
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID, "store_id": _STORE_ID.hex()})
    assert parse_audit_genesis_record(legacy) == (_KEY_ID, None)
    assert parse_audit_genesis_store_id(legacy) == _STORE_ID


@pytest.mark.parametrize("length", [0, STORE_ID_BYTES - 1, STORE_ID_BYTES + 1])
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
    of rows change what the chain is. A record naming no scheme is refused the same way; the
    well-formed id in :func:`test_a_genesis_record_with_a_store_id_round_trips` is the control."""
    legacy = json.dumps({"genesis": 1, "key_id": _KEY_ID, "store_id": store_id})
    for detail in (legacy, genesis_record_with_store_id(_KEY_ID, store_id)):
        record = parse_audit_genesis_record(detail)
        assert record is not None and record[0] == _KEY_ID
        assert audit_scheme_refusal(*record) is not None
        assert parse_audit_genesis_store_id(detail) is None


def test_a_store_id_does_not_rescue_a_record_missing_its_own_fields() -> None:
    assert (
        parse_audit_genesis_record(json.dumps({"genesis": 1, "store_id": _STORE_ID.hex()})) is None
    )
    assert parse_audit_genesis_record(json.dumps({"store_id": _STORE_ID.hex()})) is None
