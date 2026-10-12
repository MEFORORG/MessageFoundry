# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The queue payload's routing tag (BACKLOG #2593).

The unit half pins :func:`queue_payload_aad`: every routing field is in the tag, a NULL is not the
text ``None``, and the tag keeps the ``queue.payload`` cell name. The integration half runs the
cross-backend contract in ``tests/_queue_tag_contract.py`` on SQLite; the Postgres and SQL Server
legs run the same contract from ``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``.
"""

from __future__ import annotations

import pathlib
import sqlite3
from typing import Any

import pytest

from messagefoundry.pipeline.alerts import QUEUE_TAG_SUBJECT, alert_cell_tag_failure
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    aad_cell_name,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    QUEUE_TAG_COLUMNS,
    QueueTagError,
    open_queue_cell,
    queue_payload_aad,
    queue_row_aad,
)
from tests._queue_tag_contract import assert_queue_tag_contract

_BASE: dict[str, Any] = {
    "row_id": "row-1",
    "message_id": "msg-1",
    "stage": "outbound",
    "channel_id": "IB_A",
    "destination_name": "OB_A",
    "handler_name": None,
    "body_ref": None,
}


def _row(**changes: Any) -> dict[str, Any]:
    fields = {**_BASE, **changes}
    return {
        "id": fields["row_id"],
        "message_id": fields["message_id"],
        "stage": fields["stage"],
        "channel_id": fields["channel_id"],
        "destination_name": fields["destination_name"],
        "handler_name": fields["handler_name"],
        "body_ref": fields["body_ref"],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("row_id", "row-2"),
        ("message_id", "msg-2"),
        ("stage", "routed"),
        ("channel_id", "IB_B"),
        ("destination_name", "OB_B"),
        ("handler_name", "H1"),
        ("body_ref", "0" * 64),
    ],
)
def test_each_routing_field_changes_the_tag(field: str, value: object) -> None:
    assert queue_payload_aad(**{**_BASE, field: value}) != queue_payload_aad(**_BASE)


def test_a_null_destination_is_not_the_text_none_or_blank() -> None:
    """AC-10: ``cell_aad`` str()-encodes, so NULL and ``"None"`` once built the same bytes."""
    tags = {
        queue_payload_aad(**{**_BASE, "destination_name": value}) for value in (None, "None", "")
    }
    assert len(tags) == 3
    # The control that shows why the encoder matters: the id-only cell_aad conflates them.
    assert cell_aad("queue", "payload", None) == cell_aad("queue", "payload", "None")


def test_the_tag_still_names_its_cell_and_reads_off_a_row() -> None:
    aad = queue_payload_aad(**_BASE)
    assert aad_cell_name(aad) == ("queue", "payload")
    assert queue_row_aad(_row()) == aad
    assert aad != cell_aad("queue", "payload", "row-1")  # not the old id-only tag
    with pytest.raises((KeyError, IndexError)):  # a reader that skipped a column fails closed
        queue_row_aad({k: v for k, v in _row().items() if k != "handler_name"})


def test_open_queue_cell_binds_the_row_and_its_reference() -> None:
    cipher = make_cipher(generate_key(), write_v2=True)
    row = _row()
    row["payload"] = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    assert open_queue_cell(cipher, row) == "SYNTH-BODY"  # control
    with pytest.raises(QueueTagError, match="integrity"):
        open_queue_cell(cipher, {**row, "destination_name": "OB_B"})
    with pytest.raises(QueueTagError, match="no sealed payload"):
        open_queue_cell(cipher, {**row, "payload": ""})
    assert issubclass(QueueTagError, CipherError)  # every claim's dead-letter path catches it

    ref_row = _row(body_ref="a" * 64)
    ref_row["payload"] = cipher.encrypt("a" * 64, aad=queue_row_aad(ref_row))
    assert open_queue_cell(cipher, ref_row) == "a" * 64  # control
    with pytest.raises(QueueTagError):  # re-pointed: the kind still matches, the reference does not
        open_queue_cell(cipher, {**ref_row, "body_ref": "b" * 64})
    with pytest.raises(QueueTagError):  # dropped: the cell was sealed as a reference
        open_queue_cell(cipher, {**ref_row, "body_ref": None})


def test_a_keyless_store_delivers_an_empty_inline_body() -> None:
    """Keyless, an empty body is stored as ''. Only a reference row must hold a value there."""
    cipher = make_cipher(None)
    assert open_queue_cell(cipher, {**_row(), "payload": ""}) == ""
    with pytest.raises(QueueTagError):
        open_queue_cell(cipher, {**_row(body_ref="a" * 64), "payload": ""})


def test_the_tag_failure_hook_and_alert() -> None:
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    seen: list[tuple[str, str]] = []
    cipher.set_tag_failure_hook(lambda table, reason: seen.append((table, reason)))
    cipher.report_tag_failure("queue", "a reason")
    assert seen == [("queue", "a reason")]

    def _raising(table: str, reason: str) -> None:
        raise RuntimeError("an alert sink that fails")

    cipher.set_tag_failure_hook(_raising)
    cipher.report_tag_failure("queue", "swallowed")  # a raising hook never escapes

    class _Sink:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
            self.calls.append((name, reason))

    sink = _Sink()
    alert_cell_tag_failure(sink, "queue", "r")  # type: ignore[arg-type]
    assert sink.calls == [(QUEUE_TAG_SUBJECT, "r")]


def test_queue_tag_columns_are_queue_columns() -> None:
    conn = sqlite3.connect(":memory:")
    from messagefoundry.store.store import _SCHEMA

    conn.executescript(_SCHEMA)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(queue)")}
    conn.close()
    # body_ref is added by the migration on SQLite; the rest are in the base schema.
    assert set(QUEUE_TAG_COLUMNS) - {"body_ref"} <= columns


async def test_queue_tag_contract_sqlite(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "queue-tag.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    side.row_factory = sqlite3.Row
    try:

        async def raw(sql: str, params: tuple[Any, ...]) -> None:
            side.execute(sql, params)
            side.commit()

        async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            return [dict(r) for r in side.execute(sql, params).fetchall()]

        await assert_queue_tag_contract(store, raw, fetch, store_once=True)
    finally:
        side.close()
        await store.close()
