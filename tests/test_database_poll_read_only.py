# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DATABASE source refuses a ``poll_statement`` that could write (BACKLOG #2178).

The poll runs on an autocommit pool, so a write in it commits at execute. ``UPDATE ... RETURNING``
marks every row it matches while ``_select`` hands off at most ``poll_max_rows``, so the rows past the
ceiling were marked and never ingested, and so were the rows behind a failed hand-off or a stop. The
source now refuses any poll that fails the ``db_lookup`` read-only test, at construction, whatever
``poll_max_rows`` is."""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import DatabasePoll
from messagefoundry.transports import build_source
from messagefoundry.transports.database import DatabaseSource


def _build(poll_statement: str, **over: Any) -> Any:
    settings = DatabasePoll(
        server="sql.example.com",
        database="MFDB",
        poll_statement=poll_statement,
        mark_statement="UPDATE mf_inbox SET status='DONE' WHERE id=:id",
        **over,
    ).settings
    return build_source(
        Source(type=ConnectorType.DATABASE, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )


_WRITING_POLLS = [
    pytest.param(
        "UPDATE mf_inbox SET status='CLAIMED' WHERE status='NEW' RETURNING id, payload",
        id="update-returning",
    ),
    pytest.param(
        "UPDATE TOP (500) mf_inbox SET status='CLAIMED' OUTPUT inserted.id, inserted.payload "
        "WHERE status='NEW'",
        id="tsql-update-output",
    ),
    pytest.param(
        "WITH c AS (SELECT id FROM mf_inbox WHERE status='NEW') "
        "UPDATE mf_inbox SET status='CLAIMED' FROM c WHERE mf_inbox.id = c.id",
        id="cte-update",
    ),
    pytest.param(
        "DELETE FROM mf_inbox OUTPUT deleted.id, deleted.payload WHERE status='NEW'",
        id="delete-output",
    ),
    pytest.param("EXEC dbo.claim_next_batch", id="exec"),
    pytest.param("{CALL dbo.claim_next_batch}", id="odbc-call"),
    pytest.param("SELECT id, payload FROM mf_inbox; UPDATE mf_inbox SET status='X'", id="chained"),
]


@pytest.mark.parametrize("poll", _WRITING_POLLS)
@pytest.mark.parametrize("ceiling", [500, 0], ids=["ceiling-on", "ceiling-off"])
def test_a_writing_poll_statement_is_refused_at_construction(poll: str, ceiling: int) -> None:
    """Refused whether or not the ceiling is on: with it off, a failed hand-off or a stop still left
    marked rows behind.

    Red mutation: drop the ``_require_read_only_poll`` call from ``DatabaseSource.__init__`` and the
    source builds."""
    with pytest.raises(ValueError, match="poll_statement must be a read-only SELECT/WITH") as info:
        _build(poll, poll_max_rows=ceiling)
    message = str(info.value)
    assert "mark_statement" in message  # points at the pattern that works
    assert "EXEC" in message and "{CALL" in message  # and says stored procedures are refused too
    assert "mf_inbox" not in message  # PHI-free: never echoes the statement


@pytest.mark.parametrize(
    "poll",
    [
        "SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id",
        "SELECT TOP (500) id, payload FROM mf_inbox WITH (UPDLOCK, READPAST) WHERE status='NEW'",
        "WITH n AS (SELECT id, payload FROM mf_inbox WHERE status='NEW') SELECT * FROM n;",
        "-- a comment naming UPDATE is data\nSELECT id, payload FROM mf_inbox WHERE note='DELETE'",
    ],
)
def test_a_read_only_poll_statement_still_builds(poll: str) -> None:
    """Negative control: a plain read builds as before.

    Red mutation: refuse every poll, or test the ceiling instead of the statement, and these red."""
    assert isinstance(_build(poll), DatabaseSource)
