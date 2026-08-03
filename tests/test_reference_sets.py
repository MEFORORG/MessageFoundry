# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Reference sets — external-data enrichment (ADR 0006 Tier 1): read side, store snapshot, sync."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from messagefoundry.config.reference import (
    ReferenceError,
    ReferenceSet,
    activated,
    reference,
    reset,
    set_active,
)
from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import (
    DatabaseRef,
    FileRef,
    Reference,
    ReferenceSpec,
    Registry,
    Send,
    env,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import route_message
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

REF = ReferenceSettings()  # defaults


def _csv(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


# --- config/reference.py: the read accessor ---------------------------------


def test_reference_no_active_view_raises() -> None:
    with pytest.raises(ReferenceError, match="no active reference view"):
        reference("anything")


def test_reference_resolves_get_and_missing_key() -> None:
    view = {"provider_npi": {"MED1": "111", "MED2": "222"}}
    with activated(view):
        rs = reference("provider_npi")
        assert isinstance(rs, ReferenceSet)
        assert rs.get("MED1") == "111"
        assert rs["MED2"] == "222"
        assert rs.get("nope") is None  # missing key -> default (sparse external data)
        assert rs.get("nope", "d") == "d"
        assert "MED1" in rs and len(rs) == 2
        with pytest.raises(KeyError, match="provider_npi"):
            _ = rs["nope"]  # subscript miss names the set


def test_reference_missing_set_raises() -> None:
    with activated({"a": {}}), pytest.raises(ReferenceError, match="no such reference set 'b'"):
        reference("b")


def test_activated_restores_prior_view() -> None:
    assert set_active is not None
    token = set_active({"x": {"k": "v"}})
    try:
        assert reference("x").get("k") == "v"
    finally:
        reset(token)
    with pytest.raises(ReferenceError):
        reference("x")  # view restored to None


def test_referenceset_is_read_only() -> None:
    rs = ReferenceSet("s", {"k": "v"})
    with pytest.raises(TypeError):
        rs["k2"] = "x"  # type: ignore[index]


# --- store: snapshot write / view / reload / encryption ---------------------


async def test_write_snapshot_and_view(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    await store.write_reference_snapshot(name="codes", version="v1", rows={"A": "1", "B": "2"})
    view = store.reference_view()
    assert view["codes"]["A"] == "1" and view["codes"]["B"] == "2"
    assert isinstance(view, MappingProxyType)
    await store.close()


async def test_snapshot_atomic_replace(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    await store.write_reference_snapshot(name="codes", version="v1", rows={"A": "1", "OLD": "x"})
    await store.write_reference_snapshot(name="codes", version="v2", rows={"A": "9"})
    view = store.reference_view()
    assert view["codes"] == {"A": "9"}  # whole set replaced; OLD key gone
    # only the active version's rows remain in the table
    rows = await (await store._db.execute("SELECT DISTINCT version FROM reference")).fetchall()
    assert [r["version"] for r in rows] == ["v2"]
    await store.close()


async def test_multiple_sets_coexist(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    await store.write_reference_snapshot(name="a", version="v1", rows={"k": "1"})
    await store.write_reference_snapshot(name="b", version="v1", rows={"k": "2"})
    assert store.reference_view()["a"]["k"] == "1"
    assert store.reference_view()["b"]["k"] == "2"
    await store.close()


async def test_snapshot_survives_reopen(tmp_path: Path) -> None:
    db = tmp_path / "r.db"
    store = await MessageStore.open(db)
    await store.write_reference_snapshot(name="codes", version="v1", rows={"A": "1"})
    await store.close()
    reopened = await MessageStore.open(db)
    assert reopened.reference_view()["codes"]["A"] == "1"  # loaded from the table at open
    await reopened.close()


async def test_empty_snapshot_present_after_reopen(tmp_path: Path) -> None:
    # A source that yields 0 rows is a valid synced (empty) set — present as {} both before and after a
    # reopen (the cache load drives from reference_version, so an empty snapshot isn't lost).
    db = tmp_path / "r.db"
    store = await MessageStore.open(db)
    await store.write_reference_snapshot(name="codes", version="v1", rows={})
    assert store.reference_view()["codes"] == {}
    await store.close()
    reopened = await MessageStore.open(db)
    assert reopened.reference_view()["codes"] == {}  # still present, not absent
    await reopened.close()


async def test_snapshot_value_types_round_trip(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    # dict + scalar values (the code-set multi-column shape) round-trip through JSON
    await store.write_reference_snapshot(
        name="t", version="v1", rows={"k": {"npi": "999", "active": True}, "s": "x"}
    )
    assert store.reference_view()["t"]["k"] == {"npi": "999", "active": True}
    assert store.reference_view()["t"]["s"] == "x"
    await store.close()


async def test_snapshot_encrypted_at_rest(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    cipher = make_cipher(generate_key())
    store = await MessageStore.open(db, cipher=cipher)
    await store.write_reference_snapshot(name="codes", version="v1", rows={"MRN": "SECRET999"})
    assert store.reference_view()["codes"]["MRN"] == "SECRET999"  # cache is plaintext
    await store.close()
    # the value column on disk is ciphertext (no PHI visible)
    con = sqlite3.connect(db)
    try:
        at_rest = str(con.execute("SELECT value FROM reference").fetchone()[0])
    finally:
        con.close()
    assert "SECRET999" not in at_rest
    # reopening with the same cipher decrypts back into the cache
    reopened = await MessageStore.open(db, cipher=cipher)
    assert reopened.reference_view()["codes"]["MRN"] == "SECRET999"
    await reopened.close()


async def test_reference_rows_rotate_on_reencrypt_to_active(tmp_path: Path) -> None:
    """Key rotation (reencrypt_to_active) must rotate reference.value too (BACKLOG #235) — without
    the reference pass, a later retired-key drop silently loses every synced snapshot."""
    db = tmp_path / "rot.db"
    k1, k2 = generate_key(), generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(k1))
    await store.write_reference_snapshot(
        name="codes", version="v1", rows={"P1": {"mrn": "M-SECRET-1"}, "P2": "plain"}
    )
    await store.close()

    c2 = make_cipher(k2, [k1])
    assert isinstance(c2, AesGcmCipher)
    rotated = await MessageStore.open(db, cipher=c2)
    assert await rotated.reencrypt_to_active() == 2  # exactly the two reference rows
    cur = await rotated._db.execute("SELECT value FROM reference")
    rows = list(await cur.fetchall())
    assert len(rows) == 2
    for r in rows:
        # under the ACTIVE key now (mfenc:v1:<k2-fingerprint>:...), with no plaintext PHI visible
        assert str(r["value"]).startswith(c2.active_marker_prefix)
        assert "M-SECRET-1" not in str(r["value"])
    assert rotated.reference_view()["codes"]["P1"] == {"mrn": "M-SECRET-1"}  # still decrypts
    assert await rotated.reencrypt_to_active() == 0  # idempotent
    await rotated.close()

    # Proof the rows were actually rewritten: a handle with ONLY k2 (retired key dropped) reads them.
    reopened = await MessageStore.open(db, cipher=make_cipher(k2))
    assert reopened.reference_view()["codes"] == {"P1": {"mrn": "M-SECRET-1"}, "P2": "plain"}
    await reopened.close()


# --- ReferenceSyncRunner + FileReferenceSource ------------------------------


def _spec(name: str, path: Path, refresh: float = 3600.0) -> ReferenceSpec:
    return ReferenceSpec(name=name, source=FileRef(path=str(path)), refresh_seconds=refresh)


async def test_file_sync_materializes(tmp_path: Path) -> None:
    csv = _csv(tmp_path / "codes.csv", "key,value\nA,1\nB,2\n")
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(store, lambda: [_spec("codes", csv)], REF)
    result = await runner.sync_all()
    assert result.synced == 1 and result.failed == 0
    assert store.reference_view()["codes"] == {"A": "1", "B": "2"}
    await store.close()


async def test_sync_respects_cadence(tmp_path: Path) -> None:
    csv = _csv(tmp_path / "codes.csv", "key,value\nA,1\n")
    store = await MessageStore.open(tmp_path / "r.db")
    clock = {"t": 1000.0}
    runner = ReferenceSyncRunner(
        store, lambda: [_spec("codes", csv, refresh=100.0)], REF, clock=lambda: clock["t"]
    )
    assert (await runner.run_once()).synced == 1  # never-synced -> due
    clock["t"] += 50  # within refresh window
    assert (await runner.run_once()).synced == 0  # not due yet
    clock["t"] += 60  # now past 100s since last sync
    assert (await runner.run_once()).synced == 1
    await store.close()


async def test_sync_source_failure_keeps_last_good(tmp_path: Path) -> None:
    csv = _csv(tmp_path / "codes.csv", "key,value\nA,1\n")
    store = await MessageStore.open(tmp_path / "r.db")
    specs = [_spec("codes", csv, refresh=0.0)]
    runner = ReferenceSyncRunner(store, lambda: specs, REF)
    await runner.sync_all()
    assert store.reference_view()["codes"] == {"A": "1"}
    csv.unlink()  # source disappears
    result = await runner.sync_all()
    assert result.failed == 1  # isolated failure
    assert store.reference_view()["codes"] == {"A": "1"}  # last-good snapshot kept
    await store.close()


async def test_sync_isolates_one_bad_among_many(tmp_path: Path) -> None:
    good = _csv(tmp_path / "good.csv", "key,value\nA,1\n")
    store = await MessageStore.open(tmp_path / "r.db")
    specs = [_spec("good", good), _spec("missing", tmp_path / "nope.csv")]
    runner = ReferenceSyncRunner(store, lambda: specs, REF)
    result = await runner.sync_all()
    assert result.synced == 1 and result.failed == 1
    assert store.reference_view()["good"] == {"A": "1"}  # the healthy set still synced
    await store.close()


async def test_sync_env_path_resolution(tmp_path: Path) -> None:
    csv = _csv(tmp_path / "codes.csv", "key,value\nA,1\n")
    store = await MessageStore.open(tmp_path / "r.db")
    spec = ReferenceSpec(name="codes", source=FileRef(path=env("npi_csv")))
    runner = ReferenceSyncRunner(store, lambda: [spec], REF, env_values={"npi_csv": str(csv)})
    assert (await runner.sync_all()).synced == 1
    assert store.reference_view()["codes"] == {"A": "1"}
    await store.close()


async def test_runner_enabled_false_when_no_specs(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(store, lambda: [], REF)
    assert runner.enabled is False
    runner.start()  # no-op; spawns no task
    assert runner._task is None
    await runner.stop()
    await store.close()


# --- DatabaseRef source (ADR 0006 increment 2; faked aioodbc) ---------------


class _RefCursor:
    def __init__(self, columns: list[str], rows: list[tuple[Any, ...]]) -> None:
        self.description = [(c,) for c in columns]
        self._rows = rows

    async def execute(self, sql: str, params: Any = None) -> None:
        pass

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _RefConn:
    def __init__(self, cur: _RefCursor) -> None:
        self._cur = cur

    async def cursor(self) -> _RefCursor:
        return self._cur


class _RefPool:
    def __init__(self, conn: _RefConn) -> None:
        self._conn = conn
        self.closed = False

    async def acquire(self) -> _RefConn:
        return self._conn

    async def release(self, conn: _RefConn) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


def _patch_pool(
    monkeypatch: pytest.MonkeyPatch, columns: list[str], rows: list[tuple[Any, ...]]
) -> _RefPool:
    pool = _RefPool(_RefConn(_RefCursor(columns, rows)))

    async def fake_make_pool(dsn: str, pool_max: int, *, autocommit: bool) -> _RefPool:
        return pool

    import messagefoundry.transports.database as db

    monkeypatch.setattr(db, "_make_pool", fake_make_pool)
    return pool


def _db_spec(**over: Any) -> ReferenceSpec:
    base: dict[str, Any] = dict(  # noqa: C408
        server="sql.example.com",
        database="Clarity",
        statement="SELECT provider_id, npi FROM providers",
        key_column="provider_id",
        value_column="npi",
    )
    base.update(over)
    return ReferenceSpec(name="provider_npi", source=DatabaseRef(**base))


async def test_database_source_materializes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = _patch_pool(monkeypatch, ["provider_id", "npi"], [("MED1", 999), ("MED2", 888)])
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(store, lambda: [_db_spec()], REF)
    assert (await runner.sync_all()).synced == 1
    assert store.reference_view()["provider_npi"] == {"MED1": 999, "MED2": 888}
    assert pool.closed is True  # the sync pool is closed after the read
    await store.close()


async def test_database_source_whole_row_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_pool(monkeypatch, ["id", "npi", "flag"], [("A", "9", "Y")])
    store = await MessageStore.open(tmp_path / "r.db")
    spec = _db_spec(key_column="id", value_column=None, statement="SELECT id, npi, flag FROM p")
    runner = ReferenceSyncRunner(store, lambda: [spec], REF)
    await runner.sync_all()
    assert store.reference_view()["provider_npi"]["A"] == {"npi": "9", "flag": "Y"}
    await store.close()


async def test_database_source_egress_denied_keeps_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_pool(monkeypatch, ["provider_id", "npi"], [("MED1", 999)])
    store = await MessageStore.open(tmp_path / "r.db")
    egress = EgressSettings(allowed_db=["allowed.host"])  # the spec server is not on it
    runner = ReferenceSyncRunner(store, lambda: [_db_spec()], REF, egress=egress)
    result = await runner.sync_all()
    assert result.failed == 1  # dial refused before connecting
    assert "provider_npi" not in store.reference_view()
    await store.close()


async def test_database_source_deny_by_default_refuses_empty_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Parity with the DATABASE source / db_lookup gates: under deny-by-default an empty allowed_db
    # refuses the reference dial-out outright (the one dial-out path that previously ignored the flag).
    _patch_pool(monkeypatch, ["provider_id", "npi"], [("MED1", 999)])
    store = await MessageStore.open(tmp_path / "r.db")
    egress = EgressSettings(deny_by_default=True)  # no allowed_db -> deny all DB dial-outs
    runner = ReferenceSyncRunner(store, lambda: [_db_spec()], REF, egress=egress)
    result = await runner.sync_all()
    assert result.failed == 1  # refused before connecting
    assert "provider_npi" not in store.reference_view()
    await store.close()


def test_databaseref_factory_shape() -> None:
    spec = DatabaseRef(server="s", database="d", statement="SELECT a, b FROM t", key_column="a")
    assert spec.kind == "database"
    assert spec.settings["statement"] == "SELECT a, b FROM t" and spec.settings["key_column"] == "a"


# --- wiring declaration + end-to-end dryrun ---------------------------------


class _CapturingAlerts:
    """Minimal AlertSink that records connection_stopped details (for the PHI-in-alert check)."""

    def __init__(self) -> None:
        self.details: list[str] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.details.append(detail)

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        pass

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        pass


async def test_sync_failure_does_not_log_or_alert_the_key(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A source error can embed a reference KEY (a CSV duplicate-key), which may be PHI. The runner must
    # log/alert the set name + error CLASS only — never the key (CLAUDE.md §9 / PHI.md §7).
    bad = _csv(tmp_path / "pts.csv", "key,value\nMRN999SECRET,a\nMRN999SECRET,b\n")  # duplicate key
    store = await MessageStore.open(tmp_path / "r.db")
    alerts = _CapturingAlerts()
    runner = ReferenceSyncRunner(store, lambda: [_spec("pts", bad)], REF, alert_sink=alerts)
    with caplog.at_level("WARNING"):
        result = await runner.sync_all()
    assert result.failed == 1
    assert alerts.details and all("MRN999SECRET" not in d for d in alerts.details)
    assert "MRN999SECRET" not in caplog.text  # the key never reaches the general log
    await store.close()


# --- engine lifecycle: reload re-arms the reference sync (review findings) ---


def _write_reference_config(
    cfg: Path, inbox: Path, outdir: Path, csv: Path, with_ref: bool
) -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    ref_line = (
        f"Reference('codes', source=FileRef(path={str(csv)!r}), refresh_seconds=3600)\n"
        if with_ref
        else ""
    )
    body = (
        "from messagefoundry import inbound, outbound, router, handler, Send, File, Reference, FileRef\n"
        f"inbound('IB_T', File(directory={str(inbox)!r}, pattern='*.hl7', poll_seconds=0.05), router='r')\n"
        f"outbound('FILE-OUT_T', File(directory={str(outdir)!r}, filename='{{MSH-10}}.hl7'))\n"
        f"{ref_line}"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T', msg)\n"
    )
    (cfg / "cfg.py").write_text(body, encoding="utf-8")


async def test_reload_arms_reference_added_by_reload(tmp_path: Path) -> None:
    # Start with a graph that declares NO reference set (loop not running), then reload to one that
    # adds the first Reference(...). The reload must start the loop AND materialize the set immediately.
    from messagefoundry.pipeline import Engine

    csv = _csv(tmp_path / "codes.csv", "key,value\nA,1\n")
    no_ref, with_ref = tmp_path / "a", tmp_path / "b"
    _write_reference_config(no_ref, tmp_path / "in", tmp_path / "out", csv, with_ref=False)
    _write_reference_config(with_ref, tmp_path / "in", tmp_path / "out", csv, with_ref=True)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.05)
    try:
        await eng.reload(no_ref)  # graph with zero reference sets
        assert "codes" not in eng.store.reference_view()
        await eng.reload(with_ref)  # adds the first reference set
        assert eng.store.reference_view()["codes"] == {"A": "1"}  # materialized immediately
    finally:
        await eng.stop()


async def test_empty_start_then_reload_syncs_reference(tmp_path: Path) -> None:
    # Engine started without a graph, then loaded via reload — the reference set must still sync.
    from messagefoundry.pipeline import Engine

    csv = _csv(tmp_path / "codes.csv", "key,value\nA,1\n")
    cfg = tmp_path / "cfg"
    _write_reference_config(cfg, tmp_path / "in", tmp_path / "out", csv, with_ref=True)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.05)
    try:
        await eng.start()  # no graph
        await eng.reload(cfg)
        assert eng.store.reference_view()["codes"] == {"A": "1"}
    finally:
        await eng.stop()


def test_reference_declaration_registers() -> None:
    from messagefoundry.config import wiring

    reg = Registry()
    token = wiring._active
    wiring._active = reg
    try:
        Reference("provider_npi", source=FileRef(path="x.csv"), refresh_seconds=600)
    finally:
        wiring._active = token
    assert "provider_npi" in reg.references
    assert reg.references["provider_npi"].refresh_seconds == 600


def test_dryrun_resolves_file_reference(tmp_path: Path) -> None:
    # A handler that enriches via reference(...) resolves in a dry-run from the file-backed declaration.
    csv = _csv(tmp_path / "npi.csv", "key,value\nMED1,9991\n")
    reg = Registry()
    reg.references["provider_npi"] = ReferenceSpec(
        name="provider_npi", source=FileRef(path=str(csv))
    )

    def route(msg: Message) -> list[str]:
        return ["enrich"]

    def enrich(msg: Message) -> Send:
        npi = reference("provider_npi").get(msg["PV1-7.1"] or "")
        if npi:
            msg.set("PV1-7.13", npi)
        return Send("OUT", msg)

    from messagefoundry.config.models import ConnectorType, Validation
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        InboundConnection,
        OutboundConnection,
    )

    reg.add_inbound(
        InboundConnection(
            "IN",
            ConnectionSpec(ConnectorType.MLLP, {"port": 2575}),
            router="r",
            validation=Validation(strict=False, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("OUT", ConnectionSpec(ConnectorType.FILE, {"directory": "."}))
    )
    reg.add_router("r", route)
    reg.add_handler("enrich", enrich)

    raw = (
        "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|M1|P|2.5.1\r"
        "PID|1||100^^^H^MR||DOE^JANE\r"
        "PV1|1|I|||||MED1\r"
    )
    outcome = route_message(reg, reg.inbound["IN"], raw)
    assert len(outcome.deliveries) == 1
    assert "9991" in outcome.deliveries[0].payload  # the looked-up NPI was stamped


# --- backend capability gate (ADR 0006 "Backend support") --------------------
#
# The snapshot store ships on all three backends (SQLite reference impl, Postgres port, SQL Server port
# — BACKLOG #235). The engine still ALLOW-LISTS reference sets to a backend whose
# supports_reference_sets is True and REFUSES a graph declaring one anywhere else — at start, at
# reload/promote, and at `messagefoundry check` — so on a future backend that never ports the snapshot
# store a Handler's reference(...) read can never raise per message, post-ACK, forever. Refusal (not an
# ADR-0031 lane degrade) because a set is registry-GLOBAL: the read is a runtime-only reference(name)
# call with no sound static handler->refset edge, so there is no lane to scope a degrade to. These fake
# the capability on a real SQLite store (no server stood up).


def _ref_graph(csv: Path, *, with_reference: bool = True) -> Registry:
    """A FILE-connector graph (no socket binds), optionally declaring one reference set."""
    from messagefoundry.config.models import ConnectorType, Validation
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        InboundConnection,
        OutboundConnection,
    )

    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_REF",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(csv.parent), "pattern": "*.hl7"}),
            router="r",
            validation=Validation(strict=False, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("OB_REF", ConnectionSpec(ConnectorType.FILE, {"directory": "."}))
    )
    reg.add_router("r", lambda _m: ["h"])
    reg.add_handler("h", lambda m: [Send("OB_REF", m)])
    if with_reference:
        reg.add_reference(ReferenceSpec(name="provider_npi", source=FileRef(path=str(csv))))
    return reg


def test_supports_reference_sets_flags_per_backend() -> None:
    # The capability manifest, read off the CLASSES (offline — no server, no driver: the store modules
    # import driver-free because every backend defers aioodbc/asyncpg to .open()).
    from messagefoundry.store.base import QueueStore
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    assert MessageStore.supports_reference_sets is True  # the reference implementation
    assert PostgresStore.supports_reference_sets is True  # ported, not stubbed
    assert SqlServerStore.supports_reference_sets is True  # ported at parity (BACKLOG #235)
    # ALLOW-LIST: the protocol default is False, so a FUTURE backend that never ports the snapshot store
    # is caught by the same gate rather than failing open.
    assert QueueStore.supports_reference_sets is False


def test_backend_supports_reference_sets_matches_the_class_flags() -> None:
    # THE DRIFT GUARD. `check` gates on the DECLARED backend (it has no live store); the engine gates on
    # the LIVE store. That is only sound because both resolve the SAME class flag — pin it.
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store.base import backend_supports_reference_sets
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    for backend, cls in (
        (StoreBackend.SQLITE, MessageStore),
        (StoreBackend.POSTGRES, PostgresStore),
        (StoreBackend.SQLSERVER, SqlServerStore),
    ):
        assert backend_supports_reference_sets(backend) is bool(cls.supports_reference_sets)


async def test_reference_backend_gate_refuses_declared_sets_on_unsupporting_backend(
    tmp_path: Path,
) -> None:
    # A declared Reference(...) on a backend with no snapshot store is REFUSED, naming the set and the
    # backend. (Fake the capability on a real SQLite store — no SQL Server required.)
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.config.wiring import WiringError
    from messagefoundry.pipeline.wiring_runner import check_reference_backend_supported

    csv = _csv(tmp_path / "npi.csv", "key,value\nMED1,9991\n")
    store = await MessageStore.open(tmp_path / "gate.db")
    store.backend = StoreBackend.SQLSERVER  # type: ignore[assignment]
    store.supports_reference_sets = False  # type: ignore[assignment]
    try:
        with pytest.raises(WiringError) as exc:
            check_reference_backend_supported(_ref_graph(csv), store)
        msg = str(exc.value)
        assert "'provider_npi'" in msg  # names the offending set
        assert "sqlserver" in msg  # ...and the backend
    finally:
        await store.close()


async def test_reference_backend_gate_is_a_noop_without_declared_sets(tmp_path: Path) -> None:
    # The non-regression half of the allow-list: a graph declaring NO reference set passes on an
    # unsupporting backend, so every existing SQL Server deployment that doesn't use them is untouched.
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.pipeline.wiring_runner import check_reference_backend_supported

    csv = _csv(tmp_path / "npi.csv", "key,value\nMED1,9991\n")
    store = await MessageStore.open(tmp_path / "gate.db")
    store.backend = StoreBackend.SQLSERVER  # type: ignore[assignment]
    store.supports_reference_sets = False  # type: ignore[assignment]
    try:
        check_reference_backend_supported(_ref_graph(csv, with_reference=False), store)  # no raise
    finally:
        await store.close()


async def test_engine_start_refuses_graph_with_reference_set_on_unsupporting_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Engine.start() REFUSES before _start_graph runs. The ordering is load-bearing: _start_graph ->
    # _reconcile_reference_sync(startup=True) -> sync_all() -> write_reference_snapshot is the exact call
    # chain that detonates today, so pin that sync_all was never even reached.
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.config.wiring import WiringError
    from messagefoundry.pipeline.engine import Engine

    reached: list[str] = []

    async def spy_sync_all(self: ReferenceSyncRunner, now: float | None = None) -> Any:
        reached.append("sync_all")
        raise AssertionError("sync_all must not be reached on a refused graph")

    monkeypatch.setattr(ReferenceSyncRunner, "sync_all", spy_sync_all)

    csv = _csv(tmp_path / "npi.csv", "key,value\nMED1,9991\n")
    store = await MessageStore.open(tmp_path / "start.db")
    store.backend = StoreBackend.SQLSERVER  # type: ignore[assignment]
    store.supports_reference_sets = False  # type: ignore[assignment]
    engine = Engine(store)
    engine.add_registry(_ref_graph(csv))
    try:
        with pytest.raises(WiringError) as exc:
            await engine.start()
        assert "'provider_npi'" in str(exc.value)
        assert reached == []  # refused BEFORE the startup sync — nothing tried to write a snapshot
    finally:
        await engine.stop()
        await store.close()


async def test_reload_refuses_adding_a_reference_set_on_unsupporting_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The property that makes the gate safe for a LIVE engine, and the reason it lives in build_check and
    # not only in Engine.start: a graph with no reference set starts clean on an unsupporting backend, and
    # a reload that ADDS the first Reference(...) is rejected (WiringError -> 422) BEFORE the swap — the
    # already-running graph is left untouched.
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.config.wiring import WiringError
    from messagefoundry.pipeline.engine import Engine

    csv = _csv(tmp_path / "npi.csv", "key,value\nMED1,9991\n")
    store = await MessageStore.open(tmp_path / "reload.db")
    store.backend = StoreBackend.SQLSERVER  # type: ignore[assignment]
    store.supports_reference_sets = False  # type: ignore[assignment]
    engine = Engine(store)
    engine.add_registry(_ref_graph(csv, with_reference=False))
    try:
        await engine.start()  # no reference set -> starts clean on an unsupporting backend
        assert engine.registry_runner is not None and engine.registry_runner.running
        assert not engine.registry_runner.registry.references

        monkeypatch.setattr(
            "messagefoundry.pipeline.engine.load_config",
            lambda _path: _ref_graph(csv),
            raising=True,
        )
        with pytest.raises(WiringError) as exc:
            await engine.reload(tmp_path)
        assert "'provider_npi'" in str(exc.value)

        # UNTOUCHED: still running, still no reference set (the new graph never went live).
        assert engine.registry_runner.running
        assert not engine.registry_runner.registry.references
    finally:
        await engine.stop()
        await store.close()


# --- sync: a permanent backend incapability is not a flaky source ------------


async def test_sync_does_not_retry_a_backend_that_cannot_materialize(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A store that can NEVER materialize a snapshot (write_reference_snapshot raises NotImplementedError)
    # must be reported ONCE, at ERROR, and never retried. Previously this was swallowed by the generic
    # source-failure handler, which logged "sync failed (keeping last-good): NotImplementedError" every
    # interval, forever — a line that lies twice: the source is fine, and there is no last-good (there
    # never was one and there never can be one).
    csv = _csv(tmp_path / "npi.csv", "key,value\nMED1,9991\n")
    store = await MessageStore.open(tmp_path / "unsupported.db")

    attempts: list[str] = []

    async def raising_write(*, name: str, version: str, rows: Any) -> None:
        attempts.append(name)
        raise NotImplementedError("this backend has no reference tables")

    store.write_reference_snapshot = raising_write  # type: ignore[assignment,method-assign]
    alerts = _CapturingAlerts()
    runner = ReferenceSyncRunner(
        store, lambda: [_spec("provider_npi", csv)], REF, alert_sink=alerts
    )
    try:
        with caplog.at_level("WARNING"):
            first = await runner.sync_all()
            second = (
                await runner.sync_all()
            )  # forced — yet the set must be SKIPPED, not re-attempted
        assert first.failed == 1 and first.synced == 0
        assert second.failed == 0 and second.synced == 0  # not re-attempted at all
        assert attempts == ["provider_npi"]  # the write was tried exactly ONCE
        assert len(alerts.details) == 1  # alerted once, not every pass
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1  # logged once, loudly
        # ...and it must not repeat the two lies of the old transient-source path.
        assert "keeping last-good" not in caplog.text
        assert "source sync failed" not in caplog.text
    finally:
        await store.close()


async def test_genuine_source_failure_still_retries_and_keeps_last_good(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The regression guard on the split: a GENUINE source failure (a missing CSV) is still treated as
    # TRANSIENT — counted failed, last-good kept, retried next pass — and still logged with the PHI-safe
    # class-name-only discipline. The NotImplementedError arm must not have hardened or swallowed this.
    missing = tmp_path / "gone.csv"  # never written
    store = await MessageStore.open(tmp_path / "flaky.db")
    alerts = _CapturingAlerts()
    runner = ReferenceSyncRunner(
        store, lambda: [_spec("provider_npi", missing)], REF, alert_sink=alerts
    )
    try:
        with caplog.at_level("WARNING"):
            first = await runner.sync_all()
            second = await runner.sync_all()  # RE-ATTEMPTED: a source can come back
        assert first.failed == 1 and second.failed == 1
        assert len(alerts.details) == 2  # alerted on both passes (still transient)
        assert "keeping last-good" in caplog.text
        assert not [r for r in caplog.records if r.levelname == "ERROR"]  # WARNING, not ERROR
    finally:
        await store.close()


# --- ASVS 14.2.7: purge_reference_snapshots (orphan-scoped) ------------------
#
# `reference.value` is PL-2 (PHI.md §2) and until 14.2.7 had NO purge path at all: a set dropped from
# config kept its decryptable rows forever, because the only thing that ever replaced a snapshot was
# the next sync's build-new-then-flip — which never comes for a set nobody declares.


async def _seed(store: MessageStore, name: str, *, synced_at: float, rows: dict[str, Any]) -> None:
    """Write a snapshot and backdate its active-version pointer, so age is controllable."""
    await store.write_reference_snapshot(name=name, version="v1", rows=rows)
    await store._db.execute(
        "UPDATE reference_version SET synced_at = ? WHERE name = ?", (synced_at, name)
    )
    await store._commit()


async def test_purge_deletes_only_undeclared_sets(tmp_path: Path) -> None:
    """The keep-set is `declared`; age alone is never sufficient.

    Mutation: drop the `r[0] not in declared` filter — reds, because the still-wired set loses its rows.
    """
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "wired", synced_at=0.0, rows={"A": "1"})  # ancient BUT still declared
        await _seed(store, "orphan", synced_at=0.0, rows={"B": "2"})
        deleted = await store.purge_reference_snapshots(older_than=1000.0, declared={"wired"})
        assert deleted == 1
        view = store.reference_view()
        assert view["wired"] == {"A": "1"}, "a DECLARED set must survive however old it is"
        assert view.get("orphan") in (None, {}), "the orphan's rows must be gone"
    finally:
        await store.close()


async def test_purge_leaves_a_recent_orphan_alone(tmp_path: Path) -> None:
    """Undeclared but NEWER than the cutoff — the window still applies to orphans.

    Without this, `declared` alone would drive deletion and the age window would be decorative.
    """
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "orphan", synced_at=5000.0, rows={"B": "2"})
        deleted = await store.purge_reference_snapshots(older_than=1000.0, declared={"other"})
        assert deleted == 0
        assert store.reference_view()["orphan"] == {"B": "2"}
    finally:
        await store.close()


async def test_purge_refuses_an_empty_declared_set(tmp_path: Path) -> None:
    """An empty keep-set reads as "every set is abandoned" and would wipe the store.

    `registry is None` does not cover it: a registry that LOADS FINE while declaring zero reference
    sets — a subset --config, a per-team split, a harness redirect aimed at the real DB — yields
    `references == {}`. Absence-based guards fail open, so this one is positive-signal.

    Mutation: replace the raise with `return 0` — this reds, and so does the row-count assertion.
    """
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "a", synced_at=0.0, rows={"k": "1"})
        with pytest.raises(ValueError, match="non-empty"):
            await store.purge_reference_snapshots(older_than=1000.0, declared=frozenset())
        assert store.reference_view()["a"] == {"k": "1"}, (
            "nothing may be deleted on the refusal path"
        )
    finally:
        await store.close()


async def test_purge_bumps_the_version_so_a_follower_converges(tmp_path: Path) -> None:
    """The pointer row SURVIVES but its version CHANGES — and that is what carries the deletion.

    `converge_reference_cache` only reloads a set whose active version DIFFERS from the one a handle
    reflects. Leave the version alone and every cluster follower keeps serving the purged PHI out of
    RAM until restart; delete the pointer instead and converge never notices, because it only
    adds/updates names present in a fresh read. Bumping routes the deletion through the mechanism that
    already exists.

    Mutation: drop the UPDATE — `version` stays 'v1' and this reds. That is the single-handle proxy for
    the cluster bug; the real two-handle proof lives in the Postgres/SQL Server suites, because SQLite
    is single-node and its converge is legitimately a no-op.
    """
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "orphan", synced_at=0.0, rows={"B": "2"})
        await store.purge_reference_snapshots(older_than=1000.0, declared={"keep"})
        row = await (
            await store._db.execute(
                "SELECT version, row_count FROM reference_version WHERE name = 'orphan'"
            )
        ).fetchone()
        assert row is not None, (
            "the pointer row must SURVIVE — deleting it is invisible to converge"
        )
        assert row["version"] == "purged:v1", "the version must change or a follower never reloads"
        assert row["row_count"] == 0
    finally:
        await store.close()


async def test_purge_is_idempotent_and_does_not_double_prefix(tmp_path: Path) -> None:
    """A second pass over an already-purged set must be a no-op, not a churn of 'purged:purged:v1'."""
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "orphan", synced_at=0.0, rows={"B": "2"})
        first = await store.purge_reference_snapshots(older_than=1000.0, declared={"keep"})
        second = await store.purge_reference_snapshots(older_than=1000.0, declared={"keep"})
        assert (first, second) == (1, 0)
        row = await (
            await store._db.execute("SELECT version FROM reference_version WHERE name = 'orphan'")
        ).fetchone()
        assert row["version"] == "purged:v1"
    finally:
        await store.close()


async def test_a_concurrent_resync_between_decision_and_delete_is_not_destroyed(
    tmp_path: Path,
) -> None:
    """The TOCTOU the eligibility re-assert exists for — the race landed WHERE IT ACTUALLY IS.

    `declared` is computed by the RUNNER outside any store lock, and inside the store the eligibility
    SELECT and the DELETE are separate statements. The dangerous window is BETWEEN them: a config
    reload commits a fresh patient-keyed snapshot after the set has been judged eligible but before its
    rows are removed.

    THE FIRST VERSION OF THIS TEST WAS WORTHLESS and is worth recording. It re-synced *before* calling
    the purge, so the internal SELECT already filtered the set out and the DELETE never ran — removing
    the `EXISTS` re-assert changed nothing and the mutation SURVIVED. A test that exercises the
    candidate filter cannot prove the re-assert. So the re-sync is injected mid-method here, which is
    the only place the race exists.

    Mutation: drop `AND EXISTS (... synced_at < ?)` from the DELETE — the fresh rows are destroyed and
    this reds. Verified killed.
    """
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "orphan", synced_at=0.0, rows={"OLD": "x"})

        real_execute = store._db.execute
        fired = False

        async def racing_execute(sql: str, params: Any = None):  # type: ignore[no-untyped-def]
            nonlocal fired
            if not fired and sql.lstrip().upper().startswith("DELETE FROM REFERENCE"):
                # The reload lands HERE: after eligibility was decided, before the rows are removed.
                fired = True
                await real_execute(
                    "UPDATE reference_version SET synced_at = ? WHERE name = ?", (9999.0, "orphan")
                )
            return (
                await real_execute(sql, params) if params is not None else await real_execute(sql)
            )

        store._db.execute = racing_execute  # type: ignore[method-assign]
        try:
            deleted = await store.purge_reference_snapshots(older_than=1000.0, declared={"keep"})
        finally:
            store._db.execute = real_execute  # type: ignore[method-assign]

        assert fired, "the race never fired — the test proved nothing about the re-assert"
        assert deleted == 0, "a set re-synced mid-purge must survive the DELETE"
        rows = await (
            await store._db.execute("SELECT key FROM reference WHERE name = 'orphan'")
        ).fetchall()
        assert [r["key"] for r in rows] == ["OLD"], "the freshly-eligible rows were destroyed"
    finally:
        await store.close()
