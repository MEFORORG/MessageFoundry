# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2984: the store scrubs a captured reply's ``detail``, and scrubs before it holds the writer.

``complete_with_response`` stored ``detail`` as the connector handed it, on all three backends, while
``record_ack_sent`` ran it through ``safe_text(detail, limit=200)``. Most in-tree connectors build a
reply ``detail`` from a fixed phrase, a status code, or ``safe_exc``, but at least X12's ``TA1*`` detail
carries the partner's TA1-04 element verbatim, and the store was not the chokepoint ``docs/PHI.md``
names it as. Both methods now scrub before the writer lock (SQLite) or the pooled connection and its
transaction (Postgres, SQL Server) is taken.

``resp_headers`` is deliberately NOT scrubbed: a Handler reads the captured values back through
``response_get(dest).headers``, and ``docs/PHI.md`` section 3 says what covers it. ``safe_text`` over
the encoded JSON would rewrite an allow-listed value and, once cut, make the decode return ``{}`` with
no error. One test pins that it round-trips unchanged.

The Postgres and SQL Server value arms live in ``tests/test_postgres_store.py`` and
``tests/test_sqlserver_store.py``, which the server CI legs run; this file pins only their ordering,
offline.

Synthetic values only: ``ZEPHYRTEST^QUINN`` and ``MRN7731`` are invented for this file.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.store.store import MessageStore, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"

#: A reply detail carrying an HL7 PID fragment, the shape the scrubber recognises.
_PHI_DETAIL = "partner note PID|1||MRN7731^^^H^MR||ZEPHYRTEST^QUINN||19700101"


async def _delivered(store: Any, dest: str = "OB_2984", now: float = 100.0) -> tuple[str, Any]:
    """A message with one claimed outbound row, ready for ``complete_with_response``."""
    mid = await store.enqueue_message(
        channel_id="IB_2984", raw=RAW, deliveries=[(dest, "req")], now=now
    )
    item = await store.claim_next_fifo(dest, stage=Stage.OUTBOUND.value, now=now)
    assert item is not None
    return mid, item


async def _assert_reply_detail_scrubbed(store: Any) -> None:
    mid, item = await _delivered(store)
    await store.complete_with_response(
        item.id, body="MSA|AA", outcome="accepted", detail=_PHI_DETAIL, now=101.0
    )
    (reply,) = await store.correlate_response(mid)
    assert reply.detail == safe_text(_PHI_DETAIL, limit=200)
    assert "ZEPHYRTEST" not in reply.detail and "MRN7731" not in reply.detail
    assert reply.detail.startswith("partner note ")  # the prose survives; only the fragment goes


# --- SQLite, offline -----------------------------------------------------------------------------


@pytest.fixture
async def sqlite_store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "b2984.db")
    try:
        yield s
    finally:
        await s.close()


async def test_reply_detail_is_stored_scrubbed_on_sqlite(sqlite_store: MessageStore) -> None:
    await _assert_reply_detail_scrubbed(sqlite_store)
    # And on disk: the identity cipher stores the value as written, so the column itself is clean.
    cur = await sqlite_store._db.execute("SELECT detail FROM response")
    rows = list(await cur.fetchall())
    assert len(rows) == 1 and "ZEPHYRTEST" not in rows[0]["detail"]


async def test_reply_detail_is_held_to_the_200_bound(sqlite_store: MessageStore) -> None:
    long_detail = "partner said " + "word " * 120
    mid, item = await _delivered(sqlite_store)
    await sqlite_store.complete_with_response(
        item.id, body="", outcome="no_reply", detail=long_detail, now=101.0
    )
    (reply,) = await sqlite_store.correlate_response(mid)
    assert reply.detail == safe_text(long_detail, limit=200)
    assert reply.detail.endswith(" chars)") and len(reply.detail) < len(long_detail)


@pytest.mark.parametrize(
    "detail",
    [
        "MSA-1=AA",
        "HTTP 201",
        "SOAP fault (HTTP 500)",
        "3 row(s)",
        "no OUT params / return value",
        "result-set exceeded capture_max_rows=1000",
        "TA1*E accepted-with-errors",
        "business response",
        "",
        None,
    ],
)
async def test_in_tree_reply_details_are_unchanged(
    sqlite_store: MessageStore, detail: str | None
) -> None:
    # At least these in-tree fixed phrases and status codes pass the scrub byte-identical, so the
    # operator's reason (and the empty and absent cases) reads exactly as before. Not every in-tree
    # detail does: MLLP's and X12's unparseable-reply details embed safe_exc text, which the store
    # cuts again near its bound (the item 4 test below), and a number the scrubber reads as a date,
    # such as a capture_max_bytes cap of 20971520, reads back as [redacted].
    mid, item = await _delivered(sqlite_store)
    await sqlite_store.complete_with_response(
        item.id, body="x", outcome="accepted", detail=detail, now=101.0
    )
    (reply,) = await sqlite_store.correlate_response(mid)
    assert reply.detail == detail


async def test_scrub_runs_before_the_sqlite_writer_lock(
    sqlite_store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.store.store as sqlite_mod

    held: list[bool] = []

    def recording(text: str, *, limit: int = 200) -> str:
        # Only this test's detail: _event scrubs its own fixed "attempt N" text inside the transaction.
        if text == _PHI_DETAIL:
            held.append(sqlite_store._lock.locked())
        return safe_text(text, limit=limit)

    monkeypatch.setattr(sqlite_mod, "safe_text", recording)
    mid, item = await _delivered(sqlite_store)
    await sqlite_store.complete_with_response(
        item.id, body="x", outcome="accepted", detail=_PHI_DETAIL, now=101.0
    )
    await sqlite_store.record_ack_sent(
        message_id=mid,
        inbound_name="IB_2984",
        ack_body=None,
        ack_code="AE",
        ack_phase="parse",
        outcome="rejected",
        detail=_PHI_DETAIL,
    )
    assert held == [False, False]  # one scrub per method, neither under the writer lock


# --- Postgres and SQL Server: the ordering, offline ------------------------------------------------


class _Stop(Exception):
    """Raised by the stand-in scrub so the method stops there, before any statement."""


@pytest.mark.parametrize(
    ("module_name", "class_name", "acquire_attr"),
    [
        ("messagefoundry.store.postgres", "PostgresStore", "_timed_acquire"),
        ("messagefoundry.store.sqlserver", "SqlServerStore", "_acquire"),
    ],
)
@pytest.mark.parametrize("method", ["complete_with_response", "record_ack_sent"])
async def test_server_backends_scrub_before_taking_a_connection(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    class_name: str,
    acquire_attr: str,
    method: str,
) -> None:
    import importlib

    module = importlib.import_module(module_name)
    calls: list[str] = []

    def scrub(text: str, *, limit: int = 200) -> str:
        # Only this test's detail stops the method, so another safe_text call ahead of the acquire
        # cannot stand in for the detail scrub.
        if text != _PHI_DETAIL:
            return text
        calls.append("scrub")
        raise _Stop

    def acquire(*_a: object, **_k: object) -> object:
        calls.append("acquire")
        raise AssertionError("a connection was taken before the scrub")

    monkeypatch.setattr(module, "safe_text", scrub)
    store = object.__new__(getattr(module, class_name))  # no pool, no server: only the order runs
    monkeypatch.setattr(store, acquire_attr, acquire, raising=False)
    with pytest.raises(_Stop):
        if method == "complete_with_response":
            await store.complete_with_response(
                "row-1", body="x", outcome="accepted", detail=_PHI_DETAIL
            )
        else:
            await store.record_ack_sent(
                message_id="m-1",
                inbound_name="IB_2984",
                ack_body=None,
                ack_code="AE",
                ack_phase="parse",
                outcome="rejected",
                detail=_PHI_DETAIL,
            )
    assert calls == ["scrub"]


# --- resp_headers: the store keeps an allow-listed value whole -------------------------------------


async def test_allow_listed_headers_round_trip_unchanged(sqlite_store: MessageStore) -> None:
    # Values safe_text WOULD change: a date-shaped path segment it redacts, and a long correlation id
    # it would cut, after which the encoded JSON no longer decodes and the map reads back as {}.
    headers = {
        "Location": "https://fhir.example.test/Patient/19700101/_history/2",
        "X-Correlation-Id": "c" * 300,
    }
    mid, item = await _delivered(sqlite_store)
    await sqlite_store.complete_with_response(
        item.id, body="{}", outcome="accepted", detail="HTTP 201", response_headers=headers
    )
    (reply,) = await sqlite_store.correlate_response(mid)
    assert reply.headers == headers


# --- Item 4: the count a second bound writes is per call (vault BACKLOG #3034) --------------------


async def test_a_second_bound_counts_only_its_own_input(sqlite_store: MessageStore) -> None:
    # The MLLP shape: a connector prefix plus safe_exc's own bounded text, which a second bound at
    # the store cuts again. The stored count is what THIS cut held back, earlier note included, and
    # not how much of the original text is missing. docs/PHI.md, "The store's 200-character bound",
    # states that; the earlier count is not carried forward because it is text a peer can write.
    first = safe_exc(ValueError("word " * 120))
    assert first.endswith("(+400 chars)")
    detail = f"unparseable ACK: {first}"
    mid, item = await _delivered(sqlite_store)
    await sqlite_store.complete_with_response(
        item.id, body="", outcome="unparseable", detail=detail, now=101.0
    )
    (reply,) = await sqlite_store.correlate_response(mid)
    assert reply.detail is not None
    head = reply.detail[: reply.detail.rindex("(+") - 1]  # less the note and its one-char opener
    assert detail.startswith(head)
    assert reply.detail.endswith("(+43 chars)")  # this call's cut only; the (+400) note is gone
    assert "(+400 chars)" not in reply.detail
