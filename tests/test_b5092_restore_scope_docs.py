# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The docs say which restores the engine records, and no more than the code does (BACKLOG #5092).

BACKLOG #2614 records a restore at the first start, but only through the marker
``messagefoundry restore`` writes into the SQLite store it places. A PostgreSQL or SQL Server store
restored by its DBA, or a SQLite store put back by copying its files, carries no marker, so the
first start ends no session, writes no ``store_restored`` row and raises no alert. The early-adopter
guide's restore paragraph read as if any restore were covered.

These tests pin both halves together. The code half: the server stores'
``consume_restore_record`` returns ``None``. The docs half: SECURITY.md and the guide say so and
name the steps an operator takes by hand. If a server store ever gains detection, the code half
goes red, and the docs must be revised with it rather than left understating the control.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore

_ROOT = Path(__file__).resolve().parents[1]
_SECURITY = _ROOT / "docs" / "SECURITY.md"
_GUIDE = _ROOT / "docs" / "EARLY-ADOPTER-GUIDE.md"
_HEADING = (
    "### A restored store brings its sessions back, and only `messagefoundry restore` records it"
)


def _section(text: str, heading: str) -> str:
    """The body under ``heading``, up to the next heading of the same or a higher level."""
    start = text.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    rest = text[start + len(heading) :]
    nxt = re.search(rf"^#{{1,{level}}} ", rest, flags=re.MULTILINE)
    return rest[: nxt.start()] if nxt else rest


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("store_cls", [PostgresStore, SqlServerStore])
async def test_a_server_store_records_no_restore_at_start(store_cls: Any) -> None:
    """``consume_restore_record`` is the start's only restore detection (``_record_a_restore``);
    on a server store it answers ``None`` without a database, so nothing could be recorded."""
    store = store_cls.__new__(store_cls)
    assert await store.consume_restore_record() is None


def test_security_md_says_only_messagefoundry_restore_onto_sqlite_is_recorded() -> None:
    body = _flat(_section(_SECURITY.read_text(encoding="utf-8"), _HEADING))
    for needle in (
        "The engine records a restore only when `messagefoundry restore` placed a SQLite store",
        "Every other restore writes no marker",
        "a PostgreSQL or SQL Server store restored with the database's own tools",
        "a SQLite store put back by copying its files",
        "the first `serve` ends no session, writes no `store_restored` row and raises no "
        "`store_restored` alert",
        # The audit anchor's start-up walk is one signal, not the only one, and it is opt-in; the
        # docs must not say the engine cannot tell, nor that the anchor ends sessions.
        "One start-up signal that can catch such a restore is the audit anchor's, and only where "
        "it is set up.",
        "Other start-up signals may follow from what the restore rolled back",
        "none of them records the restore as one",
        "stop every engine process and cluster node on the store before the restore",
        "That alert ends no session and writes no `store_restored` row.",
        "run `messagefoundry admin-revoke-sessions` against the restored store",
        "`messagefoundry restore --help` prints the statement of what a restore rolls back",
    ):
        assert needle in body, needle


def test_the_guide_restore_paragraph_is_scoped_to_messagefoundry_restore() -> None:
    body = _flat(_GUIDE.read_text(encoding="utf-8"))
    assert "Only `messagefoundry restore` onto SQLite is recorded (BACKLOG #5092)." in body
    assert (
        "SECURITY.md#a-restored-store-brings-its-sessions-back-and-only-messagefoundry-restore-records-it"
        in body
    )
    assert "run `messagefoundry admin-revoke-sessions` against the restored store" in body
    assert "re-apply by hand the changes listed above" in body
