# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Premises stated beside a control, each with a test that fails when it is false (BACKLOG #1746,
limb 3; docs/Code_Quality_Standards.md section 4.0 rule 9).

Two prose premises are pinned in the shape of ``tests/test_ech_record_premise.py``: ADR 0159's
corrected "next borrower" sentence on SQLite (BACKLOG #1548), and the comment beside the SQL Server
in-process audit lock (BACKLOG #1605). Each positive control is the ORIGINAL text, embedded as a
literal so it works on a shallow clone. The audit lock's premise also has an offline half, that
every append takes the database applock before it reads the chain head, pinned with a fake cursor;
its cross-process half needs a live server and is ``tests/test_sqlserver_audit_applock.py``.
"""

from __future__ import annotations

import re
import types
from itertools import takewhile
from pathlib import Path
from typing import Any

from messagefoundry.store.sqlserver import _AUDIT_APPEND_LOCK, SqlServerStore

_ROOT = Path(__file__).resolve().parent.parent

# --- 1: ADR 0159, SQLite has a next borrower -------------------------------------------------------

_ADR_0159 = (
    _ROOT
    / "docs"
    / "adr"
    / "0159-cancellation-safe-pooled-connection-release-mid-txn-discard-at-the-acquire-chokepoint.md"
)
_REFUTED_BORROWER = re.compile(r"no next[- ]borrower")
#: The correction's opening of its quotation of the old sentence. A refuted phrase after this, with
#: no closing ``"*`` between, is being quoted to deny it.
_QUOTE_OPEN = 'This bullet used to end: *"'
_QUOTE_CLOSE = '"*'
_BORROWER_CORRECTION = "One connection does not remove the next borrower"

#: The bullet before the 2026-09-14 correction: the unchanged lead plus the closing sentence the
#: correction quotes, reflowed.
_ORIGINAL_BORROWER_BULLET = """\
- **Backend scope: SQL Server only.** Postgres is structurally safe twice over — `async with
  conn.transaction()` rolls back on any `BaseException` (asyncpg's `__aexit__` tests `extype is not None`,
  with no `Exception` filter), and asyncpg's pool additionally resets under `asyncio.shield`. SQLite
  shares the `except Exception` shape but has a single writer connection under an `asyncio.Lock` and no
  pool, so there is no next-borrower to inherit anything.
"""


def _flat(text: str) -> str:
    return " ".join(text.split())


def asserted_no_next_borrower(text: str) -> list[int]:
    """Offsets (in the whitespace-flattened text) where SQLite's "no next borrower" is ASSERTED,
    meaning it does not sit inside the correction's quotation of the old sentence."""
    flat = _flat(text)
    asserted: list[int] = []
    for match in _REFUTED_BORROWER.finditer(flat):
        opened = flat.rfind(_QUOTE_OPEN, 0, match.start())
        quoted = (
            opened != -1 and _QUOTE_CLOSE not in flat[opened + len(_QUOTE_OPEN) : match.start()]
        )
        if not quoted:
            asserted.append(match.start())
    return asserted


def test_adr_0159_does_not_assert_that_sqlite_has_no_next_borrower() -> None:
    text = _ADR_0159.read_text(encoding="utf-8")
    flat = _flat(text)
    assert len(flat) > 5000, f"expected the whole ADR, read {len(flat)} characters"
    assert _BORROWER_CORRECTION in flat, "the #1548 correction sentence is gone from ADR 0159"
    assert _REFUTED_BORROWER.search(flat), (
        "the correction no longer quotes the refuted sentence, so this check reads nothing; "
        "re-point it at whatever the ADR now says"
    )
    assert asserted_no_next_borrower(text) == [], (
        "ADR 0159 asserts SQLite has no next borrower outside the correction's quotation; one "
        "writer connection makes every later writer the next borrower (BACKLOG #1548)"
    )


def test_the_borrower_check_fires_on_the_original_text() -> None:
    """Positive controls: the shipped bullet, and today's ADR with its quotation unmarked."""
    assert asserted_no_next_borrower(_ORIGINAL_BORROWER_BULLET) != []
    unquoted = _ADR_0159.read_text(encoding="utf-8").replace(_QUOTE_OPEN, "")
    assert asserted_no_next_borrower(unquoted) != []


# --- 2: the SQL Server in-process audit lock -------------------------------------------------------

_SQLSERVER = _ROOT / "messagefoundry" / "store" / "sqlserver.py"
_AUDIT_LOCK_LINE = "self._audit_lock = asyncio.Lock()"
_LIVE_TEST = "tests/test_sqlserver_audit_applock.py"
#: Searched over the whole flattened file, not only the lock's comment, so the refuted premise cannot
#: move to another comment (``record_audit``'s, say); the ``# `` covers a comment line break.
_REFUTED_AUDIT = re.compile(r"single audit writer per engine (?:# )?process")

#: The comment and line as they shipped before this limb.
_ORIGINAL_AUDIT_LOCK = """\
        # Serializes audit-chain appends in-process (the store is the single audit writer per engine
        # process; active-passive = one active node) — see record_audit.
        self._audit_lock = asyncio.Lock()
"""


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def audit_lock_premise_faults(source: str) -> list[str]:
    """What is wrong with the premise stated beside the in-process audit lock, if anything."""
    lines = source.splitlines()
    at = [n for n, line in enumerate(lines) if line.strip() == _AUDIT_LOCK_LINE]
    if len(at) != 1:
        return [f"expected one {_AUDIT_LOCK_LINE!r}, found {len(at)}"]
    above = reversed(lines[: at[0]])
    comment = [line.strip().lstrip("#").strip() for line in takewhile(_is_comment, above)]
    block = " ".join(reversed(comment))
    faults: list[str] = []
    if _REFUTED_AUDIT.search(_flat(source)):
        faults.append("asserts the refuted single-writer premise")
    if "_AUDIT_APPEND_LOCK" not in block:
        faults.append("the comment above the lock does not name _AUDIT_APPEND_LOCK")
    if _LIVE_TEST not in block:
        faults.append(f"the comment above the lock does not name {_LIVE_TEST}")
    return faults


def test_the_audit_lock_states_its_premise_and_names_its_live_test() -> None:
    assert audit_lock_premise_faults(_SQLSERVER.read_text(encoding="utf-8")) == []
    # The stated reason is only true while the live test exists and a CI leg runs it.
    assert (_ROOT / _LIVE_TEST).is_file()
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert _LIVE_TEST in ci, f"no ci.yml leg names {_LIVE_TEST}"


def test_the_audit_lock_check_fires_on_the_original_text() -> None:
    """Positive control: the shipped comment fails on both the refuted premise and the missing lock."""
    faults = audit_lock_premise_faults(_ORIGINAL_AUDIT_LOCK)
    assert "asserts the refuted single-writer premise" in faults
    assert "the comment above the lock does not name _AUDIT_APPEND_LOCK" in faults


class _RecordingCursor:
    """Records every statement; answers the applock with a granted code and the head read with an
    empty chain, which is all ``_append_audit_row`` needs to reach its INSERT."""

    def __init__(self) -> None:
        self.executed: list[tuple[str, Any]] = []

    async def execute(self, sql: str, params: Any = None) -> None:
        self.executed.append((sql, params))

    async def fetchone(self) -> Any:
        sql = self.executed[-1][0]
        if "sp_getapplock" in sql:
            return (0,)
        if sql.startswith("INSERT INTO audit_log"):
            return (1,)
        return None  # the head read: an empty chain


async def test_every_audit_append_takes_the_database_applock_before_it_reads_the_head() -> None:
    store = SqlServerStore.__new__(SqlServerStore)
    store._settings = types.SimpleNamespace(command_timeout=0)  # type: ignore[assignment]
    store._audit_append_mac = lambda: (None, None)  # type: ignore[method-assign]
    cur = _RecordingCursor()
    await store._append_audit_row(
        cur, "premise_probe", actor=None, channel_id=None, detail=None, client=None, now=1.0
    )
    statements = [sql for sql, _ in cur.executed]
    assert any(sql.startswith("INSERT INTO audit_log") for sql in statements), statements
    head = next(i for i, sql in enumerate(statements) if "FROM audit_log" in sql)
    locks = [params for sql, params in cur.executed[:head] if "sp_getapplock" in sql]
    assert [p[0] for p in locks] == [_AUDIT_APPEND_LOCK], (
        "the audit append read the chain head without first taking the cross-shard applock; "
        "the in-process lock alone forks the chain under engine sharding (BACKLOG #1605)"
    )
