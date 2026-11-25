# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One message whose stored metadata is too deep to read no longer fails the whole API page it is
on (BACKLOG #6712 item 2). Synthetic data only."""

from __future__ import annotations

import logging
import uuid

import pytest

from messagefoundry.api.app import _summary
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore
from messagefoundry.store.cell_tag import message_cell_aad
from tests.test_content_search import (  # noqa: F401
    ADT,
    _add_user,
    _auth,
    _client,
    _login,
    _service,
    enc_engine,
)

# Deep enough to exhaust json's C scanner on every supported platform, as in
# tests/test_metadata_json_hardening.py.
_DEEP_CELL = '{"user": {"k": "v"}, "z": ' + "[" * 200_000 + "]" * 200_000 + "}"


def _row(metadata: str | None, message_id: str = "a" * 32) -> dict[str, object]:
    return {
        "id": message_id,
        "channel_id": "IB_A",
        "received_at": 1.0,
        "status": "PROCESSED",
        "metadata": metadata,
    }


def test_a_too_deep_metadata_cell_shows_as_none_and_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``user_metadata`` raises ``MetadataTooDeepError`` on such a cell; the summary reads it as no
    metadata and logs a WARNING that names the message and carries none of the cell, once per
    message per interval, so a second read of the same row logs nothing. The control: a readable
    cell still shows its user bag."""
    assert _summary(_row('{"user": {"k": "v"}}')).metadata == '{"k": "v"}'
    message_id = uuid.uuid4().hex
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        assert _summary(_row(_DEEP_CELL, message_id)).metadata is None
        assert _summary(_row(_DEEP_CELL, message_id)).metadata is None
    [record] = [r for r in caplog.records if "too deeply nested" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert message_id[:12] in record.getMessage()
    assert '"k"' not in record.getMessage()


async def test_a_too_deep_metadata_cell_does_not_fail_the_message_list(
    enc_engine: Engine,  # noqa: F811
) -> None:
    """End to end: ``GET /messages`` over two messages, one with a too-deep metadata cell, answers
    200 with that row's metadata null, where it answered 500 for the whole page. The control: the
    other message's readable user bag still comes back non-null."""
    store = enc_engine.store
    assert isinstance(store, MessageStore)
    deep = await store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    readable = await store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    for mid, cell in ((deep, _DEEP_CELL), (readable, '{"user": {"k": "v"}}')):
        aad = message_cell_aad("metadata", message_id=mid, channel_id="IB_A")
        await store._db.execute(
            "UPDATE messages SET metadata=? WHERE id=?", (store._enc(cell, aad=aad), mid)
        )
    await store._db.commit()
    service = await _service(enc_engine)
    await _add_user(service, "boss", [Role.ADMINISTRATOR.value])
    async with _client(enc_engine, service) as c:
        token = await _login(c, "boss")
        r = await c.get("/messages", headers=_auth(token))
        assert r.status_code == 200, r.text
        rows = {m["id"]: m for m in r.json()["messages"]}
    assert set(rows) == {deep, readable}
    assert rows[deep]["metadata"] is None
    # This caller reads a present bag masked; masked or not, it is not null.
    assert rows[readable]["metadata"] is not None
