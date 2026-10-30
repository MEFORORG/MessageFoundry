# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DATABASE source refuses a ``poll_statement`` that could write (BACKLOG #2178).

Why, and what is refused: ``transports.database._read_only_poll_refusal``. ``DatabasePoll`` tests a
literal statement when declared, and ``DatabaseSource`` tests every statement when built."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import DatabasePoll, WiringError
from messagefoundry.transports import build_source
from messagefoundry.transports.database import DatabaseSource

_MARK = "UPDATE mf_inbox SET status='DONE' WHERE id=:id"


def _build_raw(poll_statement: str, **over: Any) -> Any:
    """Build from a raw settings dict, NOT through ``DatabasePoll``, so the construction check is the
    one under test (a spec can reach the builder without the factory)."""
    settings: dict[str, Any] = {
        "server": "sql.example.com",
        "database": "MFDB",
        "poll_statement": poll_statement,
        "mark_statement": _MARK,
        **over,
    }
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
    # Decided, not accidental: the lock ends with the statement on the autocommit pool, so refusing a
    # locking read loses nothing, and the message says so.
    pytest.param(
        "SELECT id, payload FROM mf_inbox WHERE status='NEW' FOR UPDATE SKIP LOCKED",
        id="for-update",
    ),
]


def _assert_refusal_text(message: str) -> None:
    assert "poll_statement must be a read-only SELECT/WITH" in message
    assert "mark_statement" in message  # points at the pattern that works
    assert "EXEC" in message and "{CALL" in message  # stored procedures are refused too
    assert "FOR UPDATE" in message  # and a locking read, with the reason
    assert "mf_inbox" not in message  # PHI-free: never echoes the statement


@pytest.mark.parametrize("poll", _WRITING_POLLS)
@pytest.mark.parametrize("ceiling", [500, 0], ids=["ceiling-on", "ceiling-off"])
def test_a_writing_poll_statement_is_refused_at_construction(poll: str, ceiling: int) -> None:
    """Refused whether or not the ceiling is on: with it off, a failed hand-off or a stop still left
    marked rows behind.

    Red mutation: drop the refusal from ``DatabaseSource.__init__`` and the source builds."""
    with pytest.raises(ValueError) as info:
        _build_raw(poll, poll_max_rows=ceiling)
    _assert_refusal_text(str(info.value))


@pytest.mark.parametrize("poll", _WRITING_POLLS)
def test_a_writing_poll_statement_is_refused_when_declared(poll: str) -> None:
    """``DatabasePoll`` refuses it too, so ``messagefoundry check`` catches it on a config dir with no
    ``messagefoundry.toml``, where no connector is built (as BACKLOG #2617 did for ``DatabaseRef``).

    Red mutation: drop the declaration check from ``DatabasePoll`` and the spec is returned."""
    with pytest.raises(WiringError) as info:
        DatabasePoll(server="sql.example.com", database="MFDB", poll_statement=poll)
    _assert_refusal_text(str(info.value))


def test_the_refusal_comes_before_the_hop_is_built(caplog: pytest.LogCaptureFixture) -> None:
    """A refused poll leaves no hop log line behind for a connection that was never built.

    Red mutation: move the refusal after ``_build_connection`` and the generic hop's TLS warning is
    logged first."""
    with caplog.at_level(logging.DEBUG, logger="messagefoundry"), pytest.raises(ValueError):
        _build_raw(
            "UPDATE mf_inbox SET status='CLAIMED' RETURNING id",
            dialect="generic",
            odbc_driver="PostgreSQL Unicode",
        )
    assert not caplog.records


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
    """Negative control: a plain read is declared and built as before.

    Red mutation: refuse every poll, or test the ceiling instead of the statement, and these red."""
    settings = DatabasePoll(
        server="sql.example.com", database="MFDB", poll_statement=poll, mark_statement=_MARK
    ).settings
    assert settings["poll_statement"] == poll
    assert isinstance(_build_raw(poll), DatabaseSource)
