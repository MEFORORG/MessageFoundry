# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5726: the audit lookups behind keyed audit evidence and transit-bound attestation
match their text keys EXACTLY, whatever the database collation.

The three lookups are shared by every backend and used to take ``MAX(seq)`` over a ``WHERE`` that
compares in the database collation. SQL Server's is case-insensitive and pads trailing spaces, so a
variant row could win the ``MAX`` and shadow the row the lookup wants; the exact recheck after it
then refused genuine evidence. Usernames are binary on SQL Server, so ``u`` and ``U`` are two
accounts, and one's newer row hid the other's.

The instrument is a stdlib SQLite ``audit_log`` whose text columns use a collation that folds case
and ignores trailing spaces, as SQL Server's default does; each case has a control that the same
lookup finds the same row when no variant row stands above it. The SQL Server live leg runs the
role-seal and audit contracts in ``tests/test_sqlserver_store.py``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from messagefoundry.store.crypto import AUDIT_SCHEME_IN_HEAP, audit_key_id, generate_key
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    _exact_audit_row,
    _transit_attestation_audit_gap,
    audit_row_hash,
    read_newest_keyed_audit_row,
    settle_newest_keyed_audit_row,
)
from messagefoundry.store.transit_attestation import (
    TRANSIT_BOUND_ATTESTED_ACTION,
    TRANSIT_BOUND_WITHDRAWN_ACTION,
    TransitBoundAttestation,
)
from tests.audit_chain_cases import _mac_key, genesis_record


def _ci_pad(a: str, b: str) -> int:
    """SQL Server's default comparison, near enough: case folded, trailing spaces ignored."""
    x, y = a.rstrip(" ").lower(), b.rstrip(" ").lower()
    return (x > y) - (x < y)


class _Log:
    """An audit log in an in-memory SQLite database whose ``actor`` and ``action`` compare like
    SQL Server's default collation, each row sealed under one audit key as a holder would seal it."""

    def __init__(self) -> None:
        key = generate_key()
        self.mac = _mac_key(key)
        self.key_id = audit_key_id(self.mac)
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.create_collation("CIPAD", _ci_pad)
        self.db.execute(
            "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, ts REAL, actor TEXT COLLATE CIPAD,"
            " action TEXT COLLATE CIPAD, channel_id TEXT, detail TEXT, client TEXT, row_hash TEXT)"
        )
        self.prev = ""
        self.seq = 0
        self.append(AUDIT_KEY_EPOCH_ACTION, "u", genesis_record(self.key_id, AUDIT_SCHEME_IN_HEAP))

    def append(self, action: str, actor: str, detail: str = "{}") -> int:
        self.seq += 1
        row: dict[str, Any] = {
            "seq": self.seq,
            "ts": float(self.seq),
            "actor": actor,
            "action": action,
            "channel_id": None,
            "detail": detail,
            "client": None,
        }
        row["row_hash"] = self.prev = audit_row_hash(self.prev, **row, key=self.mac)
        self.db.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (:seq, :ts, :actor, :action, :channel_id, :detail, :client, :row_hash)",
            row,
        )
        return self.seq

    async def fetch(self, sql: str, params: tuple[object, ...]) -> Mapping[str, Any] | None:
        found = self.db.execute(sql, params).fetchone()
        return None if found is None else dict(found)

    async def keyed(self, action: str, actor: str, after_seq: int = 0) -> int | None:
        check = await read_newest_keyed_audit_row(
            self.fetch,
            action=action,
            actor=actor,
            after_seq=after_seq,
            active_key_id=self.key_id,
            mac_keys={self.key_id: self.mac},
            mac_fn=None,
        )
        row = await settle_newest_keyed_audit_row(check)
        return None if row is None else int(row["seq"])


@pytest.fixture
def log() -> Iterator[_Log]:
    made = _Log()
    yield made
    made.db.close()


def test_the_instrument_folds_case_and_pads() -> None:
    """Positive control: the collation really widens a plain equality, or the cases below prove
    nothing."""
    made = _Log()
    made.append("act", "u")
    hits = made.db.execute("SELECT COUNT(*) FROM audit_log WHERE actor = ?", ("U ",)).fetchone()
    assert hits[0] == 2  # the genesis row and the act row, both by u
    made.db.close()


@pytest.mark.parametrize("variant", ["U", "u ", "U  "])
async def test_a_variant_actors_newer_row_does_not_shadow_the_actors_evidence(
    log: _Log, variant: str
) -> None:
    mine = log.append("act", "u")
    assert await log.keyed("act", "u") == mine  # control: no variant above it yet
    theirs = log.append("act", variant)
    assert await log.keyed("act", "u") == mine
    assert await log.keyed("act", variant) == theirs  # the variant's own evidence still reads


async def test_a_variant_action_row_does_not_shadow_the_evidence(log: _Log) -> None:
    mine = log.append("act", "u")
    log.append("ACT ", "u")
    assert await log.keyed("act", "u") == mine


async def test_a_variant_key_epoch_row_does_not_shadow_the_rows_key_range(log: _Log) -> None:
    """The row's key is read from the newest genesis or range row at or below it; a variant of that
    action between them must not read as the range opening, or the row reads as unkeyed."""
    log.append(AUDIT_KEY_EPOCH_ACTION.upper(), "u")
    mine = log.append("act", "u")
    assert await log.keyed("act", "u") == mine


async def test_after_seq_still_bounds_the_walk(log: _Log) -> None:
    mine = log.append("act", "u")
    log.append("act", "U")
    assert await log.keyed("act", "u", after_seq=mine) is None


def _attestation(log: _Log, seq: int) -> TransitBoundAttestation:
    row = log.db.execute("SELECT row_hash FROM audit_log WHERE seq = ?", (seq,)).fetchone()
    return TransitBoundAttestation(
        key_name="k",
        reason="r",
        actor="u",
        attested_at=float(seq),
        audit_seq=seq,
        audit_hash=str(row["row_hash"]),
    )


async def _gap(log: _Log, seq: int) -> str | None:
    found = await _transit_attestation_audit_gap(
        _attestation(log, seq), log.fetch, mac_keys={log.key_id: log.mac}, mac_fn=None
    )
    return found if isinstance(found, str) else None


async def test_a_variant_attest_row_does_not_supersede_the_attestation(log: _Log) -> None:
    detail = json.dumps({"key_name": "k", "reason": "r"})
    seq = log.append(TRANSIT_BOUND_ATTESTED_ACTION, "u", detail)
    assert await _gap(log, seq) is None  # control
    log.append(TRANSIT_BOUND_ATTESTED_ACTION.upper(), "u", detail)
    log.append(TRANSIT_BOUND_WITHDRAWN_ACTION + " ", "u")
    assert await _gap(log, seq) is None


async def test_an_exact_later_withdraw_still_supersedes_it(log: _Log) -> None:
    """The walk steps past variants only: a real withdraw above the attestation still refuses it,
    variant or no variant between them."""
    detail = json.dumps({"key_name": "k", "reason": "r"})
    seq = log.append(TRANSIT_BOUND_ATTESTED_ACTION, "u", detail)
    log.append(TRANSIT_BOUND_ATTESTED_ACTION.upper(), "u", detail)
    log.append(TRANSIT_BOUND_WITHDRAWN_ACTION, "u")
    assert "supersedes" in (await _gap(log, seq) or "")


async def test_the_walk_steps_strictly_and_ends(log: _Log) -> None:
    for _ in range(5):
        log.append("ACT", "u")
    assert (
        await _exact_audit_row(
            log.fetch, "seq, action", "action = ?", ("act",), lambda r: r["action"] == "act"
        )
        is None
    )
    # Within the bounds, each step moves down past a row the check refuses, to the one it takes.
    found = await _exact_audit_row(
        log.fetch,
        "seq, action",
        "action = ?",
        ("act",),
        lambda r: r["seq"] == 3,
        above=2,
        at_most=5,
    )
    assert found is not None and found["seq"] == 3


async def test_a_variant_row_with_a_malformed_seq_is_returned_so_callers_refuse_it() -> None:
    """A row the walk cannot step past fails closed: it is handed back, so the supersession check
    reads it as superseding and the evidence check rechecks it and refuses it."""
    rows = iter([{"seq": "3", "action": "ACT"}])

    async def fetch(sql: str, params: tuple[object, ...]) -> Mapping[str, Any] | None:
        return next(rows, None)

    found = await _exact_audit_row(
        fetch, "seq, action", "action = ?", ("act",), lambda r: r["action"] == "act", above=1
    )
    assert found == {"seq": "3", "action": "ACT"}
