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
    Registry,
    ReferenceSpec,
    Send,
    env,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import route_message
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.store.crypto import generate_key, make_cipher
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
    with activated({"a": {}}):
        with pytest.raises(ReferenceError, match="no such reference set 'b'"):
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
    base: dict[str, Any] = dict(
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
