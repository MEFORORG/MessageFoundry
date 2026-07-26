# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.2.4 — constant-time, full-walk audit-chain MAC verification on all THREE store backends.

The L3 assessment residual for 11.2.4 named one mechanism: the product's one MAC (``audit_log.row_hash``) was
verified with a plain ``!=`` and a data-dependent early return, on every backend. Two properties close
it and both are asserted here:

1. **Constant-time comparator.** Every row MAC — and the external-anchor head, a MAC the disposition's
   route did not enumerate — goes through :func:`hmac.compare_digest`. Asserted by counting calls
   to a monkeypatched ``hmac.compare_digest``, not by grepping source.
2. **Full walk.** The walk never returns early, so the number of comparisons (and hence verify duration)
   is a function of the chain LENGTH, never of where a forgery sits. Asserted by comparing the counts
   for a tamper at the FIRST row against a tamper at the LAST row.

**Backend coverage without a live server.** ``verify_audit_chain`` on the Postgres / SQL Server backends
needs only ``_audit_keyed_from``, ``_audit_mac_key`` and ``_fetchall``, so the real method is driven here
against a bare instance with a stubbed row source. That is deliberate: the ``sql-server`` and Postgres
pytest legs SKIP SILENTLY without a live container, so a three-backend parity change that is only covered
by gated tests looks green locally and is in truth untested. These offline cases run on EVERY leg.
"""

from __future__ import annotations

import asyncio
import hmac
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.store import audit_mac_bytes, audit_row_hash


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


class _CompareCounter:
    """Counts (and delegates) ``hmac.compare_digest`` calls made while installed."""

    def __init__(self) -> None:
        self.calls = 0
        self._real = hmac.compare_digest

    def __call__(self, a: Any, b: Any) -> bool:
        self.calls += 1
        return bool(self._real(a, b))


@pytest.fixture
def counted(monkeypatch: pytest.MonkeyPatch) -> _CompareCounter:
    counter = _CompareCounter()
    # Patch the hmac MODULE attribute: every backend calls hmac.compare_digest through the module, so
    # one patch covers SQLite, Postgres and SQL Server alike.
    monkeypatch.setattr(hmac, "compare_digest", counter)
    return counter


# --- the shared normalizer ---------------------------------------------------


def test_audit_mac_bytes_maps_null_row_hash_to_never_equal_bytes() -> None:
    # row_hash is NULLable on all three backends; `hmac.compare_digest(None, ...)` raises TypeError,
    # which the startup verifier would swallow into a fail-OPEN "could not run" log with no alert.
    assert audit_mac_bytes(None) == b""
    assert not hmac.compare_digest(audit_mac_bytes(None), audit_mac_bytes("deadbeef"))


def test_audit_mac_bytes_is_total_on_non_ascii_and_lone_surrogates() -> None:
    # row_hash is attacker-writable; the str overload of compare_digest raises on non-ASCII. Encoding
    # first keeps the comparison total, so a forged row is REPORTED rather than raising.
    assert not hmac.compare_digest(audit_mac_bytes("brøken"), audit_mac_bytes("deadbeef"))
    assert not hmac.compare_digest(audit_mac_bytes("\ud800"), audit_mac_bytes("deadbeef"))
    assert hmac.compare_digest(audit_mac_bytes("ab"), audit_mac_bytes("ab"))


# --- SQLite ------------------------------------------------------------------


async def test_sqlite_verify_uses_compare_digest_once_per_row(
    store: MessageStore, counted: _CompareCounter
) -> None:
    for i in range(5):
        await store.record_audit("action", actor="u", detail=f'{{"n":{i}}}')
    ok, _ = await store.verify_audit_chain()
    assert ok
    # Exactly one constant-time comparison per row — proof the comparator is on the path at all, and
    # that no row was skipped.
    assert counted.calls == 5


async def test_sqlite_anchor_head_is_compared_constant_time(
    store: MessageStore, counted: _CompareCounter
) -> None:
    for i in range(3):
        await store.record_audit("a", actor="u", detail=f'{{"n":{i}}}')
    anchor = await store.audit_anchor()
    before = counted.calls
    ok, _ = await store.verify_audit_chain(expected_anchor=anchor)
    assert ok
    # 3 row compares + 1 anchor-head compare: the `prev != exp_head` limb three lines below the loop
    # is a MAC comparison too, and it is evaluated unconditionally (never short-circuited by the count
    # check) so the comparison count stays independent of the row count.
    assert counted.calls - before == 4


async def test_sqlite_full_walk_comparison_count_is_independent_of_break_position(
    tmp_path: Path,
) -> None:
    async def run(tamper_id: int) -> tuple[int, str | None]:
        s = await MessageStore.open(tmp_path / f"walk{tamper_id}.db")
        try:
            for i in range(6):
                await s.record_audit("act", actor="u", detail=f'{{"n":{i}}}')
            await s._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=?", (tamper_id,))
            await s._db.commit()
            counter = _CompareCounter()
            real = hmac.compare_digest
            hmac.compare_digest = counter  # type: ignore[assignment]
            try:
                ok, message = await s.verify_audit_chain()
            finally:
                hmac.compare_digest = real  # type: ignore[assignment]
            assert not ok
            return counter.calls, message
        finally:
            await s.close()

    first_calls, first_msg = await run(1)
    last_calls, last_msg = await run(6)
    # The tamper position moved from the FIRST row to the LAST; the comparison work did not change.
    # Under the old early-return this was 1 vs 6.
    assert first_calls == last_calls == 6
    # The first divergent row is still named (deliberate disclosure in the operator-facing result —
    # what the change removed is the TIMING channel, not the intentional report).
    assert "id=1" in (first_msg or "")
    assert "id=6" in (last_msg or "")


async def test_sqlite_first_divergent_row_is_reported_not_the_last(store: MessageStore) -> None:
    for i in range(4):
        await store.record_audit("act", actor="u", detail=f'{{"n":{i}}}')
    # Break TWO rows; the report must name the earlier one.
    await store._db.execute("UPDATE audit_log SET action='X' WHERE id IN (2, 4)")
    await store._db.commit()
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=2" in (message or "")


async def test_sqlite_null_row_hash_is_a_break_not_a_type_error(store: MessageStore) -> None:
    # A row whose hash was never filled (pre-chaining legacy row reaching verify before the backfill,
    # or an out-of-band write on a live server DB) must REPORT a break, not raise.
    for i in range(3):
        await store.record_audit("act", actor="u", detail=f'{{"n":{i}}}')
    await store._db.execute("UPDATE audit_log SET row_hash=NULL WHERE id=2")
    await store._db.commit()
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=2" in (message or "")


# --- Postgres / SQL Server: the real verify method, offline ------------------


def _rows(n: int, *, key: bytes | None = None) -> list[dict[str, Any]]:
    """A well-formed audit chain of ``n`` rows, hashed exactly as the backends hash it."""
    rows: list[dict[str, Any]] = []
    prev = ""
    for i in range(1, n + 1):
        row: dict[str, Any] = {
            "id": i,
            "ts": float(i),
            "actor": "u",
            "action": "act",
            "channel_id": None,
            "detail": f'{{"n":{i}}}',
            "client": None,
        }
        prev = audit_row_hash(
            prev,
            ts=row["ts"],
            actor=row["actor"],
            action=row["action"],
            channel_id=row["channel_id"],
            detail=row["detail"],
            client=row["client"],
            key=key,
        )
        row["row_hash"] = prev
        rows.append(row)
    return rows


def _offline_server_store(module_name: str, rows: list[dict[str, Any]]) -> Any:
    """A bare Postgres/SQL Server store whose only wired collaborator is the row source.

    ``verify_audit_chain`` touches exactly ``_audit_keyed_from``, ``_audit_mac_key`` and ``_fetchall``,
    so this drives the REAL method (no reimplementation) with no DB, no driver and no container."""
    import importlib

    module = importlib.import_module(f"messagefoundry.store.{module_name}")
    cls = getattr(module, "PostgresStore" if module_name == "postgres" else "SqlServerStore")
    store = object.__new__(cls)
    store._audit_keyed_from = None
    store._audit_mac_key = None
    store._audit_mac_fn = None  # ADR 0138 isolated-module MAC (the 13.3.3 rider seam); unused here

    async def _fetchall(_sql: str, *_a: Any, **_kw: Any) -> list[dict[str, Any]]:
        return rows

    store._fetchall = _fetchall  # type: ignore[method-assign]
    return store


BACKENDS: list[str] = ["postgres", "sqlserver"]


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_backend_verify_uses_compare_digest_once_per_row(
    backend: str, counted: _CompareCounter
) -> None:
    store = _offline_server_store(backend, _rows(5))
    ok, message = await store.verify_audit_chain()
    assert ok, message
    assert counted.calls == 5, f"{backend}: expected one constant-time compare per row"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_backend_anchor_head_is_compared_constant_time(
    backend: str, counted: _CompareCounter
) -> None:
    rows = _rows(3)
    store = _offline_server_store(backend, rows)
    ok, message = await store.verify_audit_chain(expected_anchor=(3, rows[-1]["row_hash"]))
    assert ok, message
    assert counted.calls == 4, f"{backend}: the anchor head must be compared constant-time too"


@pytest.mark.parametrize("backend", BACKENDS)
def test_server_backend_full_walk_count_is_independent_of_break_position(backend: str) -> None:
    # Synchronous on purpose: each measurement drives its own event loop so the comparator swap is
    # scoped to exactly one verify pass.
    def counts_for(tamper_index: int) -> tuple[int, str | None]:
        rows = _rows(6)
        rows[tamper_index]["row_hash"] = "0" * 64  # a forged digest at a chosen position
        store = _offline_server_store(backend, rows)
        counter = _CompareCounter()
        real = hmac.compare_digest
        hmac.compare_digest = counter  # type: ignore[assignment]
        try:
            ok, message = asyncio.run(store.verify_audit_chain())
        finally:
            hmac.compare_digest = real  # type: ignore[assignment]
        assert not ok
        return counter.calls, message

    first_calls, first_msg = counts_for(0)
    last_calls, last_msg = counts_for(5)
    assert first_calls == last_calls == 6, (
        f"{backend}: the walk must complete regardless of position"
    )
    assert "id=1" in (first_msg or "")
    assert "id=6" in (last_msg or "")


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_backend_reports_the_first_divergent_row(backend: str) -> None:
    rows = _rows(5)
    rows[1]["row_hash"] = "0" * 64
    rows[3]["row_hash"] = "1" * 64
    store = _offline_server_store(backend, rows)
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=2" in (message or ""), f"{backend}: must name the EARLIER break"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_backend_null_row_hash_is_a_break_not_a_type_error(backend: str) -> None:
    rows = _rows(4)
    rows[2]["row_hash"] = None
    store = _offline_server_store(backend, rows)
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=3" in (message or ""), f"{backend}: a NULL hash must report, not raise"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_backend_clean_chain_still_verifies_with_the_anchor(backend: str) -> None:
    # Regression: tail-truncation is caught ONLY via the anchor limb, which now runs after a full walk.
    rows = _rows(4)
    store = _offline_server_store(backend, rows[:3])  # newest row deleted out-of-band
    ok, _ = await store.verify_audit_chain()
    assert ok  # the within-DB walk cannot see tail-truncation
    ok, message = await store.verify_audit_chain(expected_anchor=(4, rows[-1]["row_hash"]))
    assert not ok and "anchor" in (message or "")


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_backend_keyed_chain_verifies(backend: str) -> None:
    key = b"k" * 32
    rows = _rows(3, key=key)
    store = _offline_server_store(backend, rows)
    store._audit_keyed_from = 1
    store._audit_mac_key = key
    ok, message = await store.verify_audit_chain()
    assert ok, message


def test_backend_module_list_matches_the_shipped_server_backends() -> None:
    # A fourth server backend added without a row here would silently skip this cell's coverage.
    from messagefoundry.config.settings import StoreBackend

    server = {b.value for b in StoreBackend} - {"sqlite"}
    assert server == set(BACKENDS)


# --- the comparator is genuinely load-bearing (the counted assertion can fail) -


def test_counted_comparator_fixture_would_catch_a_plain_equality(
    counted: _CompareCounter,
) -> None:
    # Guard against an identity-confirmation check: prove the fixture counts nothing when a plain `!=`
    # is used, so the per-row assertions above genuinely fail if a backend regresses to `!=`.
    plain: Callable[[str, str], bool] = lambda a, b: a == b  # noqa: E731
    assert plain("a", "a")
    assert counted.calls == 0
