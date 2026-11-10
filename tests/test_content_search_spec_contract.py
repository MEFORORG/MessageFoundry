# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``make_spec`` input contract and ``newest_first`` tie order (BACKLOG #6700, #6699).

``make_spec`` keeps a needle exactly as given (only an all-whitespace value counts as not sent),
refuses a ``field_value`` sent beside ``content`` rather than dropping it unread, and refuses a
``scan_limit`` that is not an ``int`` with :class:`ContentSearchError` (the type the search routes
catch for a 400) instead of coercing it or leaking a bare ``ValueError``/``TypeError``. The clamp
stays a clamp.

``newest_first`` breaks equal timestamps on the id in code-point order; the test pins the premise
that makes that agree with each backend's ``ORDER BY ... id DESC``: every message id is 32 lowercase
hex characters. Synthetic data only.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any
from uuid import uuid4

import pytest

from messagefoundry.api.validation import RESOURCE_ID_PATTERN
from messagefoundry.store.content_search import (
    MAX_SCAN_LIMIT,
    ContentSearchError,
    SearchSpec,
    SearchTarget,
    make_spec,
    newest_first,
    row_matches,
)
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN9001^^^H^MR||JDOE^JANE\r"


# --- BACKLOG #6700: whitespace-significant needles ----------------------------------------------


def test_a_content_needle_keeps_its_leading_and_trailing_spaces() -> None:
    """Stripping turned ``" DOE"`` into ``"DOE"``, which matched ``JDOE`` the space excludes."""
    spec = make_spec(content=" DOE", field_path=None, field_value=None)
    assert spec.substring == " DOE"
    assert row_matches(spec, raw=ADT, summary=None) is False
    trailing = make_spec(content="DOE ", field_path=None, field_value=None)
    assert trailing.substring == "DOE "
    assert (
        row_matches(trailing, raw=ADT, summary=None) is False
    )  # JDOE is followed by ^, not a space
    assert row_matches(
        make_spec(content="DOE", field_path=None, field_value=None), raw=ADT, summary=None
    )


def test_a_field_value_keeps_its_spaces() -> None:
    spec = make_spec(content=None, field_path="PID-5.1", field_value=" DOE")
    assert spec.field_value == " DOE"
    assert row_matches(spec, raw=ADT, summary=None) is False
    control = make_spec(content=None, field_path="PID-5.1", field_value="DOE")
    assert row_matches(control, raw=ADT, summary=None) is True  # the path does resolve


def test_an_all_whitespace_value_still_counts_as_not_sent() -> None:
    spec = make_spec(content="   ", field_path=" PID-3 ", field_value="  ")
    assert spec.substring is None
    assert spec.field_path == "PID-3"  # a path is a locator, so its padding is not significant
    assert spec.field_value is None  # presence test
    with pytest.raises(ContentSearchError, match="exactly one"):
        make_spec(content=" \t ", field_path=None, field_value=None)


# --- BACKLOG #6700: field_value beside content ------------------------------------------------


def test_a_field_value_beside_content_is_refused_not_dropped() -> None:
    with pytest.raises(ContentSearchError, match="field_value"):
        make_spec(content="DOE", field_path=None, field_value="MRN9001")


def test_a_field_value_alone_is_refused_by_name() -> None:
    with pytest.raises(ContentSearchError, match="field_value needs an HL7 field path"):
        make_spec(content=None, field_path=None, field_value="MRN9001")


def test_a_target_outside_the_enum_is_a_content_search_error() -> None:
    raw = make_spec(content="x", field_path=None, field_value=None, target="raw")
    assert (
        raw.target is SearchTarget.RAW
    )  # a plain string is normalized, so .value works downstream
    with pytest.raises(ContentSearchError, match="target"):
        make_spec(content="x", field_path=None, field_value=None, target="nope")


def test_a_blank_field_value_beside_content_is_still_accepted() -> None:
    """A submitted-but-empty form box is not a value, so it must not refuse the search."""
    for blank in (None, "", "   "):
        spec = make_spec(content="DOE", field_path=None, field_value=blank)
        assert spec.substring == "DOE"
        assert spec.field_value is None


# --- BACKLOG #6700: scan_limit type -----------------------------------------------------------


@pytest.mark.parametrize("bad", [True, False, "5", "abc", 2.5, None, b"5"])
def test_a_non_int_scan_limit_is_a_content_search_error(bad: Any) -> None:
    with pytest.raises(ContentSearchError, match="scan_limit must be an int"):
        make_spec(content="DOE", field_path=None, field_value=None, scan_limit=bad)


def test_the_scan_limit_clamp_is_still_a_clamp() -> None:
    assert make_spec(content="x", field_path=None, field_value=None, scan_limit=-5).scan_limit == 1
    big = make_spec(content="x", field_path=None, field_value=None, scan_limit=MAX_SCAN_LIMIT + 1)
    assert big.scan_limit == MAX_SCAN_LIMIT


# --- BACKLOG #6699: equal-timestamp tie order ------------------------------------------------

_MESSAGE_ID = re.compile(RESOURCE_ID_PATTERN)  # the API's rule for an engine-minted id


def _minted_ids() -> list[str]:
    """Ids from every way the store mints a message id: ``uuid4().hex`` and the three
    content-addressed helpers."""
    ids = [uuid4().hex for _ in range(40)]
    for n in range(20):
        body = f"MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|C{n}|P|2.5.1\r"
        ids.append(MessageStore._passthrough_message_id(uuid4().hex, "IB_PT", body))
        ids.append(MessageStore._reingress_message_id(uuid4().hex, "OB_X", n, body))
        ids.append(MessageStore._edit_resubmit_message_id(uuid4().hex, "IB_A", body))
    return ids


def test_every_minted_message_id_is_32_lowercase_hex() -> None:
    for mid in _minted_ids():
        assert _MESSAGE_ID.fullmatch(mid), mid


def test_newest_first_tie_order_matches_a_case_insensitive_sql_order() -> None:
    """SQLite's NOCASE stands in for SQL Server's default case-insensitive collation: on the ids the
    store mints, both put equal-timestamp rows in the order ``newest_first`` does."""
    ids = _minted_ids()
    rows = [{"id": mid, "received_at": 1000.0 + (i % 3)} for i, mid in enumerate(ids)]
    ours = [r["id"] for r in newest_first(rows)]
    db = sqlite3.connect(":memory:")
    try:
        db.execute("CREATE TABLE m (id TEXT, received_at REAL)")
        db.executemany("INSERT INTO m VALUES (:id, :received_at)", rows)
        for collation in ("BINARY", "NOCASE"):
            sql_order = [
                r[0]
                for r in db.execute(
                    f"SELECT id FROM m ORDER BY received_at DESC, id COLLATE {collation} DESC"
                )
            ]
            assert ours == sql_order, collation
        # Control: the NOCASE leg can tell the orders apart. On ids that differ in case, code-point
        # order puts "B..." below "a..." and NOCASE puts it above, so the premise is what agrees.
        mixed = [{"id": "a" * 32, "received_at": 1.0}, {"id": "B" * 32, "received_at": 1.0}]
        db.executemany("INSERT INTO m VALUES (:id, :received_at)", mixed)
        nocase = [
            r[0]
            for r in db.execute(
                "SELECT id FROM m WHERE received_at = 1.0 ORDER BY id COLLATE NOCASE DESC"
            )
        ]
        assert [r["id"] for r in newest_first(mixed)] != nocase
    finally:
        db.close()


@pytest.mark.parametrize("bad", [True, "5"])
def test_a_spec_built_outside_make_spec_refuses_a_non_int_cap(bad: Any) -> None:
    """``True == 1`` passes the range check, so ``SearchSpec`` refuses a non-int by type (#6700)."""
    with pytest.raises(ValueError, match="scan_limit must be an int"):
        SearchSpec(
            substring="x",
            field_path=None,
            field_value=None,
            target=SearchTarget.BOTH,
            scan_limit=bad,
        )
