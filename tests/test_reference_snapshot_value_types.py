# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1090 — ``write_reference_snapshot`` must encode the value types its sources actually
produce, not only the ones CSV happens to produce.

``store/{store,postgres,sqlserver}.py::write_reference_snapshot`` called ``json.dumps(v)`` over a
``Mapping[str, Any]`` with **no** ``default=`` hook. ``tomllib`` materializes a TOML date as
``datetime.date``, which ``json.dumps`` cannot encode. Measured against the pre-fix tree on
2026-08-10, with an ordinary reference TOML carrying ``effective = 2026-01-01``:

    _load_file_source(...)                       -> {'acme': {'code': 'A1', 'effective': date(...)}}
    store.write_reference_snapshot(rows=...)     -> TypeError: Object of type date is not JSON
                                                   serializable

Both the flat and the nested-table TOML shapes failed. The sync then keeps the last-good snapshot
and logs one WARNING naming the exception class, so on a first deployment every Handler using that
code set would raise with the cause obscured.

**Why the fix is at the sink and not at the file producer.** ``_load_database_source`` routes its
cells through ``_cell``; ``_load_file_source`` returns ``dict(load_code_set(path))`` uncoerced. That
is two of three serialization boundaries hardened. Coercing the file producer fixes this instance;
giving the sink a ``default=`` hook fixes the class, including the producer nobody has written yet.

**Why no existing test caught it:** every reference test in ``test_reference_sets.py`` uses CSV,
where every value is already ``str`` — the suite was structurally incapable of reaching the defect.
``Mapping[str, Any]`` defeats mypy strict at exactly the point that matters.

Only the SQLite leg runs here. SQL Server and Postgres share ``encode_reference_value`` and are
covered by the encoder tests below plus their own (CI-only) store suites.
"""

from __future__ import annotations

import json
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path

import pytest

from messagefoundry.config.settings import ReferenceSettings
from messagefoundry.config.wiring import FileRef, ReferenceSpec
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner, _load_file_source
from messagefoundry.store.metadata import encode_reference_value
from messagefoundry.store.store import MessageStore

REF = ReferenceSettings()

# A reference TOML a site would plausibly hand-author: a nested table per key, and a bare date.
NESTED_TOML = """
[acme]
plan = "PPO"
effective = 2026-01-01

[zenith]
plan = "HMO"
effective = 2025-07-15
"""

# The same defect one level up: a flat TOML whose top-level value is itself the date.
FLAT_TOML = 'plan = "PPO"\neffective = 2026-01-01\n'


def _toml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


# --- the producer really does hand the sink a date ---------------------------


def test_toml_file_source_yields_an_uncoerced_date(tmp_path: Path) -> None:
    """The premise of the whole item, asserted rather than assumed: the FILE producer does not
    coerce, so a ``datetime.date`` reaches the sink. If this ever stops being true the sink guard is
    still correct, but this file's other arms would be testing nothing."""
    rows = _load_file_source({"path": str(_toml(tmp_path / "payers.toml", NESTED_TOML))})
    assert isinstance(rows["acme"]["effective"], date)


# --- the sink ----------------------------------------------------------------


async def test_toml_date_snapshot_writes_and_reads_back(tmp_path: Path) -> None:
    src = _toml(tmp_path / "payers.toml", NESTED_TOML)
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        rows = _load_file_source({"path": str(src)})
        await store.write_reference_snapshot(name="payers", version="v1", rows=rows)
        view = store.reference_view()["payers"]
        assert view["acme"]["plan"] == "PPO"
        # The cache holds the pre-encode value; the point of the arm is that the write COMMITTED.
        assert view["acme"]["effective"] == date(2026, 1, 1)
    finally:
        await store.close()


async def test_toml_date_survives_a_reopen(tmp_path: Path) -> None:
    """The round-trip that proves the value was really persisted, not just cached: reopening loads
    the snapshot back out of the table, decrypting and JSON-decoding it."""
    src = _toml(tmp_path / "payers.toml", NESTED_TOML)
    db = tmp_path / "r.db"
    store = await MessageStore.open(db)
    await store.write_reference_snapshot(
        name="payers", version="v1", rows=_load_file_source({"path": str(src)})
    )
    await store.close()

    reopened = await MessageStore.open(db)
    try:
        assert reopened.reference_view()["payers"]["acme"] == {
            "plan": "PPO",
            "effective": "2026-01-01",  # ISO-8601 at rest, per the sink's default= hook
        }
    finally:
        await reopened.close()


async def test_flat_toml_date_snapshot_writes(tmp_path: Path) -> None:
    """The same defect where the top-level value IS the date (no nested table)."""
    src = _toml(tmp_path / "flat.toml", FLAT_TOML)
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await store.write_reference_snapshot(
            name="flat", version="v1", rows=_load_file_source({"path": str(src)})
        )
        assert store.reference_view()["flat"]["plan"] == "PPO"
    finally:
        await store.close()


async def test_full_sync_of_a_toml_source_succeeds(tmp_path: Path) -> None:
    """End to end through the runner — the surface a deploying site actually uses. Pre-fix this
    reported ``failed=1`` and kept the (absent) last-good snapshot."""
    src = _toml(tmp_path / "payers.toml", NESTED_TOML)
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(
            store,
            lambda: [ReferenceSpec(name="payers", source=FileRef(path=str(src)))],
            REF,
        )
        result = await runner.sync_all()
        assert (result.synced, result.failed) == (1, 0)
        assert store.reference_view()["payers"]["zenith"]["plan"] == "HMO"
    finally:
        await store.close()


# --- the encoder itself (backend-independent: all three sinks call it) -------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (date(2026, 1, 1), "2026-01-01"),
        (datetime(2026, 1, 1, 9, 30), "2026-01-01T09:30:00"),
        (time(9, 30), "09:30:00"),
        (Decimal("10.25"), "10.25"),
        (b"\x00\xff", "AP8="),
    ],
    ids=["date", "datetime", "time", "decimal", "bytes"],
)
def test_encode_reference_value_coerces(value: object, expected: str) -> None:
    assert json.loads(encode_reference_value(value)) == expected


def test_encode_reference_value_leaves_json_native_types_alone() -> None:
    """A positive control against over-coercion: the hook must only fire for types ``json.dumps``
    cannot already handle, so every CSV-sourced snapshot encodes byte-identically to before."""
    for native in ("x", 1, 1.5, True, None, {"a": ["b", 2]}):
        assert encode_reference_value(native) == json.dumps(native)


def test_encode_reference_value_still_refuses_an_unencodable_type() -> None:
    """Never accept-and-drop: an unknown type raises so the sync keeps the last-good snapshot,
    rather than committing a set with a value silently replaced by a placeholder."""
    with pytest.raises(TypeError, match="cannot serialize"):
        encode_reference_value(object())


# --- the two server backends' sinks, without a database ----------------------
#
# `SqlServerStore` / `PostgresStore.write_reference_snapshot` build the whole encrypted row list
# BEFORE they acquire a connection, so the JSON-encode step is reachable with no server running --
# which matters because a local pytest silently skips both DB legs. A pool whose acquire raises a
# sentinel separates the two outcomes cleanly: reaching the sentinel proves the encode succeeded,
# while the pre-fix code never got there (it raised TypeError while building the list).


class _Sentinel(RuntimeError):
    """Raised by the fake pool: reaching it means the encode step is already past."""


class _RefusingPool:
    def acquire(self, *args: object, **kwargs: object) -> object:
        raise _Sentinel("reached the connection acquire")


class _PlainCipher:
    """The `Cipher` surface `write_reference_snapshot` uses: encrypt(str, aad=...) -> str."""

    def encrypt(self, value: str, *, aad: bytes | None = None) -> str:
        return value


@pytest.mark.parametrize("backend", ["sqlserver", "postgres"])
async def test_server_backend_sinks_encode_a_toml_date(backend: str, tmp_path: Path) -> None:
    if backend == "sqlserver":
        from messagefoundry.store.sqlserver import SqlServerStore as _Store
    else:
        from messagefoundry.store.postgres import PostgresStore as _Store

    store = _Store.__new__(_Store)
    store._cipher = _PlainCipher()  # type: ignore[assignment]
    store._pool = _RefusingPool()  # type: ignore[assignment]

    rows = _load_file_source({"path": str(_toml(tmp_path / "payers.toml", NESTED_TOML))})
    # Pre-fix this raised TypeError from json.dumps; the sentinel proves the list was built.
    with pytest.raises(_Sentinel):
        await store.write_reference_snapshot(name="payers", version="v1", rows=rows)


def test_sink_and_database_producer_agree_on_every_shared_type() -> None:
    """The drift gate. ``transports/`` may not import ``store/`` (ADR 0154 AC-17), so the sink's
    hook and the DATABASE producer's ``_json_default`` are two copies of one contract. A reader
    cannot tell which source wrote a snapshot value, so the two must never disagree."""
    from messagefoundry.transports.database import _json_default

    for value in (date(2026, 1, 1), datetime(2026, 1, 1, 9, 30), Decimal("10.25"), b"\x00\xff"):
        assert json.loads(encode_reference_value(value)) == _json_default(value), (
            f"the reference sink and the DATABASE producer encode {type(value).__name__} "
            "differently — the same value would read back differently depending on its source"
        )
