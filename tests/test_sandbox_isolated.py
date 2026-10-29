# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[sandbox].mode = "isolated"`` (ADR 0147, vault BACKLOG #3131).

Two properties, each pinned per pipeline phase and per mode:

1. **Where the code runs.** Every check that means "runs in a sandbox worker" reads ``is not OFF``,
   so the isolated mode takes the worker branch of the Router, the ``accepts=`` predicate and the
   Handler, exactly as ``subprocess`` does. Before the conversion those checks read ``is
   SUBPROCESS``, and an isolated session ran each phase in the engine process.
2. **The brokered lookups.** In the isolated mode a Handler's ``db_lookup``/``fhir_lookup`` is
   asked of the parent over the closed-tag codec, and the parent answers it with the runner the
   in-process path uses. The parent refuses a request outside the Handler phase, and refuses one
   whose ``[egress]`` list is empty, whatever ``[security].block_unlisted_outbound`` says (owner
   ruling of 2026-10-27, made under delegation). ``subprocess`` still refuses both lookups in the
   worker, and ``off`` runs them in-process.

Synthetic HL7 only."""

from __future__ import annotations

import asyncio
import os
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import db_lookup as db_lookup_mod
from messagefoundry.config import fhir_lookup as fhir_lookup_mod
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.settings import EgressSettings, SandboxSettings
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.fhirsearch import FhirRaw, FhirToken
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    policy_from_settings,
)
from messagefoundry.store import MessageStatus

RAW = "MSH|^~\\&|SEND|F|RECV|F|20240101120000||ADT^A01|MSG00001|P|2.3\rPID|1||900001||DOE^JANE\r"

_GRAPH = """
import os
from collections.abc import Mapping

from messagefoundry import (
    inbound, outbound, router, handler, MLLP, Send, db_lookup, fhir_lookup, FhirToken, FhirRaw,
)
from messagefoundry.config.db_lookup import DbLookupError

PARENT = __PARENT__

inbound("IB_I", MLLP(port=19411), router="r_where")
inbound("IB_RL", MLLP(port=19413), router="r_lookup")
outbound("OB_I", MLLP(host="127.0.0.1", port=19412))


def _where():
    return "parent" if os.getpid() == PARENT else "child"


@router("r_where")
def r_where(msg):
    # Names the handler for the process it ran in, so the routing decision says where it ran.
    return "h_" + _where()


@router("r_lookup")
def r_lookup(msg):
    db_lookup("LK", "SELECT 1 AS v", {})  # unavailable on a Router, in every mode
    return "h_child"


def _in_child(msg):
    return _where() == "child"


@handler("h_child", accepts=_in_child)
def h_child(msg):
    return Send("OB_I", _where())


@handler("h_parent")
def h_parent(msg):
    return Send("OB_I", _where())


@handler("h_db")
def h_db(msg):
    rows = db_lookup("LK", "SELECT v, d FROM t WHERE k = :k", {"k": msg.field("PID-3"), "n": 7})
    return Send("OB_I", f"{rows[0]['v']}|{type(rows[0]['d']).__name__}|{rows[0]['d']}")


@handler("h_db_caught")
def h_db_caught(msg):
    try:
        db_lookup("LK", "SELECT 1 AS v", {})
    except DbLookupError as exc:
        return Send("OB_I", "caught:" + str(exc))
    return Send("OB_I", "not refused")


class _LazyParams(Mapping):
    # A Mapping whose values come from another lookup, read while the outer call describes it.
    def __iter__(self):
        return iter(["k"])

    def __len__(self):
        return 1

    def __getitem__(self, key):
        return db_lookup("LK", "SELECT inner", {})[0]["v"]


@handler("h_db_nested")
def h_db_nested(msg):
    rows = db_lookup("LK", "SELECT outer", _LazyParams())
    return Send("OB_I", rows[0]["v"])


@handler("h_fhir_badkind")
def h_fhir_badkind(msg):
    from messagefoundry.config.fhir_lookup import FhirLookupError

    try:
        fhir_lookup("FH", "Patient", {"_count": 10, "x": ["ok", 2.5]})
    except FhirLookupError as exc:
        return Send("OB_I", str(exc))
    return Send("OB_I", "not refused")


@handler("h_fhir")
def h_fhir(msg):
    bundle = fhir_lookup(
        "FH", "Patient", {"identifier": FhirToken("MRN", "900001"), "_sort": [FhirRaw("-date"), "x"]}
    )
    return Send("OB_I", bundle["id"])
"""


@pytest.fixture
def graph(tmp_path: Path) -> tuple[Registry, str]:
    (tmp_path / "graph.py").write_text(
        _GRAPH.replace("__PARENT__", str(os.getpid())), encoding="utf-8"
    )
    return load_config(tmp_path), str(tmp_path)


def _session(
    config_dir: str,
    mode: SandboxMode,
    *,
    allowed_db: tuple[str, ...] = ("db.example",),
    allowed_http: tuple[str, ...] = ("fhir.example",),
) -> SandboxSession:
    return SandboxSession(
        SandboxPolicy(
            mode=mode,
            wall_seconds=30.0,
            lookup_allowed_db=allowed_db,
            lookup_allowed_http=allowed_http,
        ),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )


def _bodies(registry: Registry, hname: str, session: SandboxSession | None) -> list[str]:
    deliveries, _, _, _ = transform_one(
        registry, hname, RAW, sandbox=session, run_context=RunContext()
    )
    return [str(d.payload) for d in deliveries]


# --- 1. where each phase runs, per mode ----------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "where"),
    [
        (SandboxMode.OFF, "parent"),
        (SandboxMode.SUBPROCESS, "child"),
        (SandboxMode.ISOLATED, "child"),
    ],
)
def test_router_accepts_and_handler_run_where_the_mode_says(
    graph: tuple[Registry, str], mode: SandboxMode, where: str
) -> None:
    registry, config_dir = graph
    session = _session(config_dir, mode)
    try:
        # The Router names the handler for the process it ran in. h_child's accepts= predicate
        # declines anywhere but a worker, so a Router run in a worker beside a predicate run in the
        # engine routes nowhere: each of the two phases is pinned on its own.
        names = route_only(
            registry, registry.inbound["IB_I"], RAW, sandbox=session, run_context=RunContext()
        )
        assert names == ["h_" + where]
        # The Handler reports the process it ran in.
        assert _bodies(registry, "h_parent", session) == [where]
    finally:
        session.close()


# --- 2. the brokered lookups, per mode -----------------------------------------------------------


class _Runners:
    """Stand-ins for the engine's lookup runners, published the way the transform worker publishes
    the real ones: on the thread that runs ``transform_one``, which is where the broker answers."""

    def __init__(self) -> None:
        self.db_calls: list[tuple[str, str, Any]] = []
        self.fhir_calls: list[tuple[str, str, Any]] = []

    def db(self, connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        self.db_calls.append((connection, statement, params))
        return [{"v": "VAL", "d": Decimal("12.50")}]

    def fhir(self, connection: str, query: str, params: Any) -> dict[str, Any]:
        self.fhir_calls.append((connection, query, params))
        return {"resourceType": "Bundle", "id": "BUNDLE-1", "total": 1}


@pytest.fixture
def runners() -> Any:
    r = _Runners()
    with db_lookup_mod.activated(r.db), fhir_lookup_mod.activated(r.fhir):
        yield r


def test_isolated_brokers_db_lookup_through_the_parent(
    graph: tuple[Registry, str], runners: _Runners
) -> None:
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED)
    try:
        bodies = _bodies(registry, "h_db", session)
    finally:
        session.close()
    # The row the parent's runner returned reached the Handler, a Decimal still a Decimal.
    assert bodies == ["VAL|Decimal|12.50"]
    assert runners.db_calls == [("LK", "SELECT v, d FROM t WHERE k = :k", {"k": "900001", "n": 7})]


def test_isolated_brokers_fhir_lookup_with_its_search_kinds(
    graph: tuple[Registry, str], runners: _Runners
) -> None:
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED)
    try:
        bodies = _bodies(registry, "h_fhir", session)
    finally:
        session.close()
    assert bodies == ["BUNDLE-1"]
    # Each value arrives as the kind the Handler wrote, so the parent's executor screens it as it
    # would in-process: a FhirToken's code half, never a FhirRaw.
    assert runners.fhir_calls == [
        (
            "FH",
            "Patient",
            {"identifier": FhirToken("MRN", "900001"), "_sort": [FhirRaw("-date"), "x"]},
        )
    ]


def test_mode_off_runs_the_lookup_in_process(
    graph: tuple[Registry, str], runners: _Runners
) -> None:
    registry, _ = graph
    assert _bodies(registry, "h_db", None) == ["VAL|Decimal|12.50"]
    assert len(runners.db_calls) == 1


def test_subprocess_still_refuses_both_lookups_in_the_worker(
    graph: tuple[Registry, str], runners: _Runners
) -> None:
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.SUBPROCESS)
    try:
        for hname in ("h_db", "h_fhir"):
            with pytest.raises(SandboxError, match="db_lookup/fhir_lookup is forbidden"):
                _bodies(registry, hname, session)
    finally:
        session.close()
    assert runners.db_calls == [] and runners.fhir_calls == []


@pytest.mark.parametrize(
    ("hname", "empty", "key"),
    [
        ("h_db", {"allowed_db": ()}, "allowed_db"),
        ("h_fhir", {"allowed_http": ()}, "allowed_http"),
    ],
)
def test_isolated_refuses_a_lookup_whose_egress_list_is_empty(
    graph: tuple[Registry, str],
    runners: _Runners,
    caplog: pytest.LogCaptureFixture,
    hname: str,
    empty: dict[str, tuple[str, ...]],
    key: str,
) -> None:
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED, **empty)
    try:
        with caplog.at_level("WARNING", logger="messagefoundry.pipeline.sandbox"):
            for _ in range(2):
                with pytest.raises(SandboxError, match=rf"\[egress\]\.{key} is empty"):
                    _bodies(registry, hname, session)
    finally:
        session.close()
    # Refused in the parent, before any runner ran: the published runner saw nothing.
    assert runners.db_calls == [] and runners.fhir_calls == []
    # Logged once for the session, not once per message.
    refusals = [r for r in caplog.records if "was refused" in r.getMessage()]
    assert len(refusals) == 1 and key in refusals[0].getMessage()


def test_a_refusal_reaches_the_handler_as_its_lookup_error(
    graph: tuple[Registry, str], runners: _Runners
) -> None:
    # A Handler that catches DbLookupError sees the parent's refusal as that error, as at mode=off.
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED, allowed_db=())
    try:
        (body,) = _bodies(registry, "h_db_caught", session)
    finally:
        session.close()
    assert body.startswith("caught:db_lookup('LK') refused: [egress].allowed_db is empty")


def test_a_lookup_with_no_runner_in_the_parent_fails_as_at_mode_off(
    graph: tuple[Registry, str],
) -> None:
    # No runner published: a dry run, the inline fast path, or a graph with no lookup connection.
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED)
    try:
        with pytest.raises(SandboxError, match="unavailable here"):
            _bodies(registry, "h_db", session)
    finally:
        session.close()


@pytest.mark.parametrize("mode", [SandboxMode.SUBPROCESS, SandboxMode.ISOLATED])
def test_a_router_lookup_is_refused_in_every_worker_mode(
    graph: tuple[Registry, str], runners: _Runners, mode: SandboxMode
) -> None:
    registry, config_dir = graph
    session = _session(config_dir, mode)
    try:
        with pytest.raises(SandboxError):
            route_only(
                registry, registry.inbound["IB_RL"], RAW, sandbox=session, run_context=RunContext()
            )
    finally:
        session.close()
    assert runners.db_calls == []


def test_the_parent_refuses_a_lookup_bound_to_a_router_dispatch(tmp_path: Path) -> None:
    # The worker has no runner on a Router, so it never asks; the parent refuses one anyway.
    session = _session(str(tmp_path), SandboxMode.ISOLATED)
    lookup = codec.LookupRequest(
        seq=1, kind=codec.LOOKUP_DB, connection="LK", target="SELECT 1", params=None
    )
    for phase in ("router", "accepts"):
        refusal = session._lookup_refusal(phase, lookup)
        assert refusal is not None and "only for a Handler" in refusal
    assert session._lookup_refusal("transform", lookup) is None


def test_a_lookup_frame_drops_a_subprocess_worker() -> None:
    # Only an isolated session decodes a lookup frame; any other refuses it as a protocol violation.
    frame = codec.encode_lookup(
        request_id="r1",
        phase="transform",
        name="h",
        seq=1,
        kind=codec.LOOKUP_DB,
        connection="LK",
        target="SELECT 1",
        params=None,
    )
    with pytest.raises(codec.SandboxCodecError, match="unexpected sandbox frame type 'lookup'"):
        codec.decode_response(frame, request_id="r1", phase="transform", name="h")
    answer = codec.decode_answer(frame, request_id="r1", phase="transform", name="h")
    assert isinstance(answer, codec.LookupRequest) and answer.target == "SELECT 1"
    # Bound to the dispatch in flight (ADR 0147 AC-6): another dispatch's id is refused.
    with pytest.raises(codec.SandboxCodecError, match="correlation mismatch"):
        codec.decode_answer(frame, request_id="r2", phase="transform", name="h")


def test_a_lookup_reply_is_bound_to_its_sequence() -> None:
    reply = codec.encode_lookup_ok(
        request_id="r1", phase="transform", name="h", seq=2, result=[{"a": Decimal("1")}]
    )
    assert codec.decode_lookup_reply(
        reply, request_id="r1", phase="transform", name="h", seq=2
    ) == (True, [{"a": Decimal("1")}], "")
    with pytest.raises(codec.SandboxCodecError, match="out of sequence"):
        codec.decode_lookup_reply(reply, request_id="r1", phase="transform", name="h", seq=1)


# --- 3. the mode setting fails closed --------------------------------------------------------------


def test_policy_reads_the_egress_lists_for_the_broker() -> None:
    policy = policy_from_settings(
        SandboxSettings(mode="isolated"),
        EgressSettings(deny_by_default=False, allowed_db=["db.example"], allowed_http=[]),
    )
    assert policy.mode is SandboxMode.ISOLATED
    assert policy.lookup_allowed_db == ("db.example",) and policy.lookup_allowed_http == ()


def test_an_unknown_mode_refuses() -> None:
    with pytest.raises(ValueError, match="mode"):
        SandboxSettings(mode="isolate")  # type: ignore[arg-type]
    # Past the model's own check too: the engine's rendering refuses rather than guess a mode.
    smuggled = SandboxSettings.model_construct(mode="bogus")
    with pytest.raises(ValueError, match="bogus"):
        policy_from_settings(smuggled, EgressSettings())


# --- 4. the running engine: the split transform worker, per mode ----------------------------------

_RUNNER_GRAPH = """
from messagefoundry import inbound, outbound, router, handler, File, Send, DatabaseLookup, db_lookup

inbound("IB_L", File(directory={inbox!r}, poll_seconds=0.05), router="r")
inbound("IB_W", File(directory={inbox_w!r}, poll_seconds=0.05), router="r_w")
outbound("OB_L", File(directory={outbox!r}))
DatabaseLookup("LK", server="db.example", database="D")


@router("r")
def r(msg):
    return "h"


@router("r_w")
def r_w(msg):
    return "h_write"


@handler("h")
def h(msg):
    rows = db_lookup("LK", "SELECT v FROM t WHERE k = :k", {{"k": msg.field("PID-3")}})
    return Send("OB_L", rows[0]["v"])


@handler("h_write")
def h_write(msg):
    db_lookup("LK", "INSERT INTO t (k) VALUES (:k)", {{"k": "1"}})
    return Send("OB_L", "wrote")
"""


def _runner_dirs(tmp_path: Path) -> dict[str, str]:
    dirs = {key: tmp_path / key for key in ("inbox", "inbox_w", "outbox", "cfg")}
    for path in dirs.values():
        path.mkdir()
    return {key: str(path) for key, path in dirs.items()}


async def _run_one_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    egress: EgressSettings,
    *,
    inbound_name: str = "IB_L",
) -> tuple[str, list[str], Any]:
    """Start a runner on the graph, push one message through ``inbound_name``, and return its final
    status, what was delivered, and the fake pool, whose cursor records any statement that ran."""
    from messagefoundry.pipeline.wiring_runner import RegistryRunner
    from messagefoundry.store import MessageStore, Stage
    from tests.test_db_lookup import _patch_pool

    pool = _patch_pool(monkeypatch, rows=[("FROM-DB",)], columns=["v"])
    dirs = _runner_dirs(tmp_path)
    (Path(dirs["cfg"]) / "graph.py").write_text(_RUNNER_GRAPH.format(**dirs), encoding="utf-8")
    egress = egress.model_copy(update={"allowed_file_dirs": [dirs["outbox"]]})
    store = await MessageStore.open(tmp_path / "isolated.db")
    runner = RegistryRunner(
        load_config(dirs["cfg"]),
        store,
        sandbox_policy=policy_from_settings(
            SandboxSettings.model_validate({"mode": mode, "wall_seconds": 60.0}), egress
        ),
        sandbox_config_source=(dirs["cfg"], None),
        egress=egress,
    )
    await runner.start()
    try:
        mid = await store.enqueue_ingress(
            channel_id=inbound_name, raw=RAW, control_id="MSG00001", message_type="ADT^A01"
        )
        runner._wake_lane(Stage.INGRESS, inbound_name)
        terminal = {MessageStatus.PROCESSED.value, MessageStatus.ERROR.value}
        status = ""
        for _ in range(1200):
            msg = await store.get_message(mid)
            assert msg is not None
            status = str(msg["status"])
            if status in terminal:
                break
            await asyncio.sleep(0.05)
    finally:
        await runner.stop()
        await store.close()
    delivered = [p.read_text(encoding="utf-8") for p in Path(dirs["outbox"]).iterdir()]
    return status, delivered, pool


_LISTED = EgressSettings(allowed_db=["db.example"])
_PROCESSED = MessageStatus.PROCESSED.value
_ERROR = MessageStatus.ERROR.value


@pytest.mark.parametrize(
    ("mode", "expect", "ran"),
    [("off", _PROCESSED, True), ("subprocess", _ERROR, False), ("isolated", _PROCESSED, True)],
)
async def test_the_transform_worker_runs_a_lookup_per_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, expect: str, ran: bool
) -> None:
    status, delivered, pool = await _run_one_message(tmp_path, monkeypatch, mode, _LISTED)
    assert status == expect
    assert delivered == (["FROM-DB"] if ran else [])
    assert (pool.cursor_obj.executed is not None) is ran


async def test_isolated_refuses_an_empty_allowed_db_under_the_audited_opt_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # block_unlisted_outbound = false makes an empty allowed_db unrestricted: the executor builds and
    # mode=off would dial. The broker refuses anyway (owner ruling 2026-10-27, under delegation).
    opt_out = EgressSettings(deny_by_default=False)
    status, delivered, pool = await _run_one_message(tmp_path, monkeypatch, "isolated", opt_out)
    assert (status, delivered) == (_ERROR, [])
    assert pool.cursor_obj.executed is None


async def test_a_brokered_write_is_refused_by_the_executors_read_only_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The broker answers through the same executor as mode=off, so its statement test applies.
    status, delivered, pool = await _run_one_message(
        tmp_path, monkeypatch, "isolated", _LISTED, inbound_name="IB_W"
    )
    assert (status, delivered) == (_ERROR, [])
    assert pool.cursor_obj.executed is None


def test_isolated_with_no_config_dir_refuses_rather_than_run_in_process(tmp_path: Path) -> None:
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    def runner_for(mode: SandboxMode) -> RegistryRunner:
        return RegistryRunner(
            Registry(),  # a graph built in code: no source_dir, no snapshot
            object(),  # type: ignore[arg-type]
            sandbox_policy=SandboxPolicy(mode=mode),
            sandbox_config_source=(None, None),
            egress=EgressSettings(deny_by_default=False),
        )

    # Refused at construction, before anything is received.
    with pytest.raises(ValueError, match="never runs a Router or Handler in the engine"):
        runner_for(SandboxMode.ISOLATED)
    # mode=subprocess keeps its documented degradation to in-process for such a graph.
    runner = runner_for(SandboxMode.SUBPROCESS)
    assert runner._sandbox_for("IB_ANY") is None
    # And the per-message backstop, for a policy that reaches the runner by another route.
    runner._sandbox_policy = SandboxPolicy(mode=SandboxMode.ISOLATED)
    with pytest.raises(SandboxError, match="never runs a Router or Handler in the engine"):
        runner._sandbox_for("IB_ANY")


@pytest.mark.parametrize("mode", [SandboxMode.SUBPROCESS, SandboxMode.ISOLATED])
async def test_fusion_is_disabled_in_every_worker_mode(
    mode: SandboxMode, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    runner = RegistryRunner(
        Registry(),
        object(),  # type: ignore[arg-type]
        sandbox_policy=SandboxPolicy(mode=mode),
        sandbox_config_source=(str(tmp_path), None),
        egress=EgressSettings(deny_by_default=False),
    )
    runner._fuse_thread_hops = True
    with caplog.at_level("WARNING"):
        assert await runner._activate_fusion() is False
    assert any(f"[sandbox].mode={mode.value}" in r.getMessage() for r in caplog.records)


# --- 5. round-one review fixes ---------------------------------------------------------------------


@pytest.mark.parametrize("kind", [codec.LOOKUP_DB, codec.LOOKUP_FHIR])
def test_a_lookup_with_long_arguments_round_trips(kind: str) -> None:
    # Every slot past the inline threshold rides a segment, and segments must be numbered in the
    # order the decoder reads them: connection, target, then params.
    long = "x" * 5000
    params: Any = {"k": long} if kind == codec.LOOKUP_DB else {"identifier": FhirToken("S", long)}
    frame = codec.encode_lookup(
        request_id="r1",
        phase="transform",
        name="h",
        seq=1,
        kind=kind,
        connection="C" * 5000,
        target="SELECT " + long if kind == codec.LOOKUP_DB else "Patient" + long,
        params=params,
    )
    answer = codec.decode_answer(frame, request_id="r1", phase="transform", name="h")
    assert isinstance(answer, codec.LookupRequest)
    assert answer.connection == "C" * 5000 and answer.params == params


def _worker_broker() -> Any:
    """The worker's ``_Broker``. Importing the worker installs a stderr root handler, which is right
    in its child process and wrong here, so the root logger is restored after the import, as the
    ``sandbox_run_one`` fixture in tests/test_db_lookup.py does."""
    import logging

    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        from messagefoundry.pipeline import _sandbox_worker
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)
        for h in handlers:
            root.addHandler(h)
        root.setLevel(level)
    return _sandbox_worker._Broker


def test_a_runner_serves_only_the_dispatch_it_was_published_for() -> None:
    import io
    from types import SimpleNamespace

    from messagefoundry.config.db_lookup import DbLookupError

    broker_cls = _worker_broker()
    out = io.BytesIO()
    broker = broker_cls(io.BytesIO(), out)
    first = SimpleNamespace(request_id="a", phase="transform", name="h")
    second = SimpleNamespace(request_id="b", phase="transform", name="h")
    broker.begin(first)
    stale_db, _ = broker.runners(first)
    broker.end()
    broker.begin(second)
    # A thread left over from the first message still holds its runner: refused, nothing written.
    with pytest.raises(DbLookupError, match="outside the Handler dispatch"):
        stale_db("LK", "SELECT 1", None)
    assert out.getvalue() == b""
    assert not broker.broken


def test_an_oversized_lookup_fails_the_call_and_keeps_the_pipe_in_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io
    from types import SimpleNamespace

    from messagefoundry.config.db_lookup import DbLookupError

    monkeypatch.setattr(codec, "MAX_FRAME", 1024)
    broker_cls = _worker_broker()
    out = io.BytesIO()
    broker = broker_cls(io.BytesIO(), out)
    req = SimpleNamespace(request_id="a", phase="transform", name="h")
    broker.begin(req)
    db, _ = broker.runners(req)
    with pytest.raises(DbLookupError, match="too large for the sandbox"):
        db("LK", "SELECT 1", {"k": "x" * 4096})
    assert out.getvalue() == b"" and not broker.broken


def test_a_worker_that_stops_reading_cannot_hold_the_dispatch_past_the_cap(
    graph: tuple[Registry, str],
) -> None:
    # A Handler forges a lookup whose reply is far larger than the pipe buffer, then sleeps instead
    # of reading it. Unbounded, the parent's write of the reply blocks with the session lock held,
    # and the wall cap never fires. The cap must still end the dispatch.
    def big(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        return [{"v": "x" * 2_000_000}]

    _, config_dir = graph
    source = (Path(config_dir) / "graph.py").read_text(encoding="utf-8") + _FORGER
    (Path(config_dir) / "graph.py").write_text(source, encoding="utf-8")
    registry = load_config(config_dir)
    session = SandboxSession(
        SandboxPolicy(
            mode=SandboxMode.ISOLATED, wall_seconds=3.0, lookup_allowed_db=("db.example",)
        ),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        started = time.monotonic()
        with db_lookup_mod.activated(big), pytest.raises(SandboxError, match="wall cap"):
            _bodies(registry, "h_forge_lookup", session)
        assert time.monotonic() - started < 30
    finally:
        session.close()


_FORGER = """

@handler("h_forge_lookup")
def h_forge_lookup(msg):
    import os, sys, time

    from messagefoundry.pipeline import _sandbox_codec as codec

    # The dispatch's request object is a local of the worker's main loop.
    frame = sys._getframe()
    while frame is not None and "req" not in frame.f_locals:
        frame = frame.f_back
    req = frame.f_locals["req"]
    body = codec.encode_lookup(
        request_id=req.request_id, phase=req.phase, name=req.name, seq=1, kind="db",
        connection="LK", target="SELECT 1", params=None,
    )
    os.write(1, len(body).to_bytes(4, "big") + body)
    time.sleep(60)  # never reads the reply
    return Send("OB_I", "unreachable")
"""


# --- 6. round-two review fixes ---------------------------------------------------------------------


def test_a_lookup_with_no_runner_is_not_told_to_edit_egress(
    graph: tuple[Registry, str], caplog: pytest.LogCaptureFixture
) -> None:
    # No runner and an empty list, as a site with no database has: the mode=off error, no WARNING.
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED, allowed_db=())
    try:
        with (
            caplog.at_level("WARNING", logger="messagefoundry.pipeline.sandbox"),
            pytest.raises(SandboxError, match="unavailable here") as raised,
        ):
            _bodies(registry, "h_db", session)
    finally:
        session.close()
    assert "allowed_db" not in str(raised.value)
    assert not [r for r in caplog.records if "was refused" in r.getMessage()]


def test_a_slow_lookup_is_cut_off_by_the_wall_cap(graph: tuple[Registry, str]) -> None:
    def slow(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        time.sleep(20)
        return [{"v": "late", "d": Decimal(0)}]

    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.ISOLATED, wall_seconds=2.0, lookup_allowed_db=("db",)),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        # Warm the worker first, so the timing below measures the cap rather than a cold start.
        _bodies(registry, "h_parent", session)
        started = time.monotonic()
        with db_lookup_mod.activated(slow), pytest.raises(SandboxError, match="wall cap"):
            _bodies(registry, "h_db", session)
        assert time.monotonic() - started < 15
    finally:
        session.close()


def test_a_lookup_made_while_describing_another_does_not_deadlock(
    graph: tuple[Registry, str],
) -> None:
    calls: list[str] = []

    def runner(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        calls.append(statement)
        return [{"v": "INNER" if statement == "SELECT inner" else f"OUTER:{params['k']}"}]

    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED)
    try:
        with db_lookup_mod.activated(runner):
            assert _bodies(registry, "h_db_nested", session) == ["OUTER:INNER"]
    finally:
        session.close()
    assert calls == ["SELECT inner", "SELECT outer"]


def test_a_short_write_is_completed() -> None:
    from messagefoundry.pipeline.sandbox import _write_frame

    class Trickle:
        def __init__(self) -> None:
            self.data = bytearray()

        def write(self, chunk: Any) -> int:
            self.data.extend(bytes(chunk)[:3])
            return min(3, len(chunk))

        def flush(self) -> None:
            pass

    out = Trickle()
    _write_frame(out, b"0123456789")
    assert bytes(out.data) == (10).to_bytes(4, "big") + b"0123456789"


# --- 7. the Lander's covering review of 415353d7 (round-472dd562) ----------------------------------


def test_a_lookup_the_cap_cut_off_is_the_only_one_outstanding(
    graph: tuple[Registry, str], runners: _Runners
) -> None:
    # A hung backend: every lookup blocks until the test releases it. Each dispatch hits the cap.
    # Unbounded, each later dispatch starts another lookup beside the abandoned ones.
    release = threading.Event()
    lock = threading.Lock()
    state = {"calls": 0, "in_flight": 0, "peak": 0}

    def hung(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        with lock:
            state["calls"] += 1
            state["in_flight"] += 1
            state["peak"] = max(state["peak"], state["in_flight"])
        try:
            release.wait(60)
            return [{"v": "late", "d": Decimal(0)}]
        finally:
            with lock:
                state["in_flight"] -= 1

    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(
            mode=SandboxMode.ISOLATED,
            wall_seconds=4.0,
            lookup_allowed_db=("db",),
            lookup_allowed_http=("fhir",),
        ),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        with db_lookup_mod.activated(hung):
            with pytest.raises(SandboxError, match="wall cap"):
                _bodies(registry, "h_db", session)
            # The next dispatch waits for the stalled lookup, then is refused its own rather than
            # start a second one beside it.
            started = time.monotonic()
            with pytest.raises(SandboxError, match="still running"):
                _bodies(registry, "h_db", session)
            assert time.monotonic() - started < 15
            # Another connection is not held up by the stalled one.
            with fhir_lookup_mod.activated(runners.fhir):
                assert _bodies(registry, "h_fhir", session) == ["BUNDLE-1"]
        assert (state["calls"], state["peak"]) == (1, 1)
        # Once the abandoned lookup ends, the session serves lookups on it again: the next one waits
        # for the stale lookup's completion rather than poll the runner's own counter.
        release.set()
        with db_lookup_mod.activated(hung):
            assert _bodies(registry, "h_db", session)[0].startswith("late|")
    finally:
        release.set()
        session.close()


def test_a_codec_refusal_while_framing_is_the_lookups_own_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io
    from types import SimpleNamespace

    from messagefoundry.config.db_lookup import DbLookupError

    # Framing refuses here: one long param is one segment, over a cap of none.
    monkeypatch.setattr(codec, "_MAX_BLOBS", 0)
    broker = _worker_broker()(io.BytesIO(), io.BytesIO())
    req = SimpleNamespace(request_id="a", phase="transform", name="h")
    broker.begin(req)
    db, _ = broker.runners(req)
    with pytest.raises(DbLookupError, match="cannot cross the sandbox"):
        db("LK", "SELECT 1", {"k": "x" * 5000})
    assert not broker.broken


def _executor_like(connection: str, query: str, params: Any) -> dict[str, Any]:
    """The FHIR executor's screening, as mode=off meets it (transports/fhir.py ``read``)."""
    from messagefoundry.config.fhir_lookup import FhirLookupError
    from messagefoundry.fhirsearch import resolve_search_pairs

    try:
        resolve_search_pairs(params or {})
    except ValueError as exc:
        raise FhirLookupError(f"fhir_lookup on {connection!r}: {exc}") from exc
    return {"resourceType": "Bundle", "id": "B"}


def test_a_wrong_kind_search_value_fails_as_at_mode_off(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    session = _session(config_dir, SandboxMode.ISOLATED)
    try:
        with fhir_lookup_mod.activated(_executor_like):
            off = _bodies(registry, "h_fhir_badkind", None)
            isolated = _bodies(registry, "h_fhir_badkind", session)
        # No runner: the "unavailable here" error, in both modes, before any value is judged.
        off_bare = _bodies(registry, "h_fhir_badkind", None)
        isolated_bare = _bodies(registry, "h_fhir_badkind", session)
    finally:
        session.close()
    assert "got int" in off[0]
    assert isolated == off
    assert "unavailable here" in off_bare[0]
    assert isolated_bare == off_bare


def test_an_unexpected_engine_fault_fails_the_dispatch_promptly(
    graph: tuple[Registry, str],
    runners: _Runners,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def explode(self: Any, *args: Any) -> bytes:
        raise RuntimeError("FAULT-SENTINEL-7f3a")

    monkeypatch.setattr(SandboxSession, "_lookup_reply", explode)
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.ISOLATED, wall_seconds=20.0, lookup_allowed_db=("db",)),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        _bodies(registry, "h_parent", session)  # warm the worker
        started = time.monotonic()
        with (
            caplog.at_level("DEBUG"),
            pytest.raises(SandboxError, match="failed while serving") as raised,
        ):
            _bodies(registry, "h_db", session)
        assert time.monotonic() - started < 10
    finally:
        session.close()
    assert "FAULT-SENTINEL-7f3a" not in str(raised.value)
    assert not [r for r in caplog.records if "FAULT-SENTINEL-7f3a" in r.getMessage()]
    assert any("RuntimeError" in r.getMessage() for r in caplog.records)


def test_a_cut_off_waiter_does_not_replace_the_hung_lookups_record(
    graph: tuple[Registry, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Dispatch B's helper is still building its refusal when B's cap fires. Its record must not
    # replace the hung lookup's, or dispatch C would start a second call on the hung connection.
    release = threading.Event()
    calls: list[str] = []

    def hung(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        calls.append(statement)
        release.wait(60)
        return [{"v": "late", "d": Decimal(0)}]

    real_refusal = SandboxSession._busy_refusal

    def slow_refusal(lookup: codec.LookupRequest) -> str:
        time.sleep(2.0)  # past the 1 s margin at wall_seconds=4
        return real_refusal(lookup)

    monkeypatch.setattr(SandboxSession, "_busy_refusal", staticmethod(slow_refusal))
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.ISOLATED, wall_seconds=4.0, lookup_allowed_db=("db",)),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        with db_lookup_mod.activated(hung):
            for _ in range(3):  # A hangs; B and C each find the connection busy
                with pytest.raises(SandboxError, match="wall cap|still running"):
                    _bodies(registry, "h_db", session)
        assert len(calls) == 1
    finally:
        release.set()
        session.close()


def test_a_helper_past_its_deadline_never_calls_the_runner(
    graph: tuple[Registry, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Dispatch B's helper starts so late that B's cap has already ended, and by then the hung lookup
    # A has finished. It must not call the runner: nobody waits for that call and nothing records it,
    # so the next dispatch would start another beside it.
    release_a, release_all = threading.Event(), threading.Event()
    lock = threading.Lock()
    state = {"calls": 0, "in_flight": 0, "peak": 0}

    def hung(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        with lock:
            state["calls"] += 1
            first = state["calls"] == 1
            state["in_flight"] += 1
            state["peak"] = max(state["peak"], state["in_flight"])
        try:
            (release_a if first else release_all).wait(60)
            return [{"v": "late", "d": Decimal(0)}]
        finally:
            with lock:
                state["in_flight"] -= 1

    go = threading.Event()
    go.set()
    real = SandboxSession._lookup_refusal

    def gated(self: SandboxSession, phase: str, lookup: codec.LookupRequest) -> str | None:
        go.wait(30)  # stands in for a helper thread scheduled late, past its dispatch's cap
        return real(self, phase, lookup)

    monkeypatch.setattr(SandboxSession, "_lookup_refusal", gated)
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.ISOLATED, wall_seconds=2.0, lookup_allowed_db=("db",)),
        inbound="IB_I",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        with db_lookup_mod.activated(hung):
            with pytest.raises(SandboxError, match="wall cap"):
                _bodies(registry, "h_db", session)  # A: hangs, cut off
            go.clear()
            with pytest.raises(SandboxError, match="wall cap"):
                _bodies(registry, "h_db", session)  # B: its helper is held before the runner
            release_a.set()
            deadline = time.monotonic() + 10
            while state["in_flight"] and time.monotonic() < deadline:
                time.sleep(0.05)
            go.set()  # B's helper goes on, past B's deadline, and finds A finished
            time.sleep(0.5)
            release_all.set()
            assert _bodies(registry, "h_db", session)[0].startswith("late|")  # C
        assert (state["calls"], state["peak"]) == (2, 1)  # A and C; never B
    finally:
        release_a.set()
        release_all.set()
        go.set()
        session.close()
