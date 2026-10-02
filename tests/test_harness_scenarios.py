# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The headless scenario runner sends traffic and asserts the engine's disposition via the API.

Qt-free: serves the REAL ``harness/config`` graph in-process (engine + API) on ephemeral ports and
temporary directories, then runs every registered scenario end to end through its driver and, where
it names one, its sink. Also covers the driver/sink/endpoint/registry plumbing and the CLI
(``--list-scenarios``, ``--coverage``, an unknown name) without a server.
"""

from __future__ import annotations

import importlib
import threading
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn

from harness import drivers, endpoints, scenarios, sinks
from harness.__main__ import main
from harness.coverage import coverage_rows, format_report, registered_kinds
from harness.drivers import Driver, Injection
from harness.drivers.file import FileDriver
from harness.drivers.mllp import MLLPDriver
from harness.endpoints import Endpoints
from harness.scenarios import (
    SCENARIOS,
    BaseScenario,
    Scenario,
    _verify_dead_letter,
    _verify_disposition,
    run_scenario,
)
from harness.scenarios._core import _verify_sink, control_id_of
from harness.sinks import Record, Sink
from harness.sinks.file import FileSink
from harness.sinks.mllp import MLLPSink
from messagefoundry.apiclient import EngineClient
from messagefoundry.config.wiring import EnvRef, load_config
from messagefoundry.parsing.message import Message
from tests._harness_engine import HARNESS_CONFIG, ephemeral_overrides, serve_harness_config


def _as_client(fake: object) -> EngineClient:
    """Hand a scenario verifier a fake client. Each fake answers the calls its test makes, which is
    all the verifier asks of an EngineClient; that is the whole of the claim this return type makes."""
    return fake  # type: ignore[return-value]


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    """The real harness/config graph, served on ephemeral endpoints."""
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path)) as served:
        yield served


# The five scenarios the single-module runner shipped with, kept by name: a port that dropped one
# would otherwise pass every test below by parametrizing over fewer scenarios.
_ORIGINAL_FIVE = ("processed", "filtered", "unrouted", "error", "dead_letter")


def test_the_registry_still_holds_the_original_five_scenarios() -> None:
    assert set(_ORIGINAL_FIVE) <= set(SCENARIOS)


# A scenario whose graph lives in a harness/config SUBDIRECTORY (BaseScenario.graph) runs in its
# family's own test, which serves that graph and provides what it needs; the rest run here.
@pytest.mark.parametrize("name", sorted(n for n, s in SCENARIOS.items() if not s.graph))
def test_every_registered_scenario_passes_against_the_real_graph(
    server: tuple[str, Endpoints], name: str
) -> None:
    reason = SCENARIOS[name].unavailable()
    if reason:
        pytest.skip(reason)  # a missing optional extra is reported, never passed
    api_url, eps = server
    with EngineClient(api_url) as client:
        # Generous: dead_letter rides the real graph's retry policy (3 attempts, 1s and 2s backoff),
        # and a refused loopback connect costs about 2s per attempt on Windows.
        result = run_scenario(SCENARIOS[name], client, timeout=60.0, endpoints=eps)
    if result.skipped:
        # A family whose precondition (an external server, an extra) is absent here: a skip, not a pass.
        pytest.skip(result.detail)
    assert result.ok, result.detail


def test_a_scenario_expecting_the_wrong_disposition_fails(server: tuple[str, Endpoints]) -> None:
    """Negative control for the test above: the runner can say no."""
    api_url, eps = server
    wrong = Scenario("wrong", "", "ADT", "A02", count=2, expect="processed")
    with EngineClient(api_url) as client:
        result = run_scenario(wrong, client, timeout=3.0, endpoints=eps)
    assert not result.ok
    assert "statuses seen: ['filtered']" in result.detail


def test_a_sink_scenario_fails_when_nothing_reaches_the_sink(server: tuple[str, Endpoints]) -> None:
    """ADT^A05 is archived to the file outbound only, so an MLLP sink on the echo port receives
    nothing: the disposition passes and the sink assertion must still fail the scenario."""
    api_url, eps = server
    scenario = Scenario(
        "no_echo", "", "ADT", "A05", 2, "processed", sink="mllp", sink_endpoint="mllp_echo"
    )
    with EngineClient(api_url) as client:
        result = run_scenario(scenario, client, timeout=8.0, endpoints=eps)
    assert not result.ok
    assert "0/2 delivered to the mllp sink" in result.detail


def test_verify_dead_letter_ignores_preexisting_rows() -> None:
    # M-32: a long-lived DB already holding dead letters for the destination must NOT false-PASS;
    # only THIS run's control ids count.
    scenario = Scenario(
        "dl", "", "ADT", "A01", count=2, expect="dead_letter", dead_letter_destination="echo"
    )

    class FakeClient:
        def __init__(self, control_ids: list[str]) -> None:
            self._rows = [SimpleNamespace(control_id=c) for c in control_ids]

        def list_dead_letters(self, **kwargs: object) -> object:
            return SimpleNamespace(dead_letters=self._rows, total=len(self._rows))

    stale = FakeClient(["OTHER1", "OTHER2"])  # two pre-existing dead letters, foreign control ids
    assert not _verify_dead_letter(scenario, _as_client(stale), ["MINE1", "MINE2"], 0.05, []).ok
    mine = FakeClient(["MINE1", "MINE2", "OTHER1"])
    assert _verify_dead_letter(scenario, _as_client(mine), ["MINE1", "MINE2"], 5.0, []).ok


def test_verify_disposition_queries_per_control_id_and_surfaces_send_errors() -> None:
    # low-23: query per control id (resilient to concurrent traffic pushing rows off a page) and
    # surface partial send errors in the detail.
    scenario = Scenario("p", "", "ADT", "A05", count=2, expect="processed")
    queried: list[str | None] = []

    class FakeClient:
        def list_messages(self, *, control_id: str | None = None, limit: int = 50, **k: object):
            queried.append(control_id)
            return SimpleNamespace(
                messages=[SimpleNamespace(control_id=control_id, status="processed")]
            )

    result = _verify_disposition(
        scenario, _as_client(FakeClient()), ["A", "B"], 5.0, ["connection refused"]
    )
    assert result.ok
    assert set(queried) >= {"A", "B"}  # per-control-id, not one blanket page
    assert "send error" in result.detail


def test_cli_lists_scenarios(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-scenarios"]) == 0
    out = capsys.readouterr().out
    assert "processed" in out and "dead_letter" in out


def test_cli_rejects_unknown_scenario(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--scenario", "does-not-exist"]) == 2
    assert "unknown scenario" in capsys.readouterr().err


@pytest.mark.parametrize("expect", ["processed", "dead_letter"])
def test_repeated_scenario_cannot_pass_with_previous_run_rows(
    monkeypatch: pytest.MonkeyPatch, expect: str
) -> None:
    stored: set[str | None] = set()
    runs: list[set[str | None]] = []

    class Recorder(Driver):
        kind = "mllp"

        def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
            ids = {Message.parse(raw.decode())["MSH-10"] for raw in payloads}
            runs.append(ids)
            if len(runs) == 1:
                stored.update(ids)
            return [Injection() for _ in payloads]

    class Client:
        def list_messages(self, *, control_id: str, **kwargs: object) -> object:
            rows = [SimpleNamespace(status="processed")] if control_id in stored else []
            return SimpleNamespace(messages=rows)

        def list_dead_letters(self, **kwargs: object) -> object:
            return SimpleNamespace(dead_letters=[SimpleNamespace(control_id=c) for c in stored])

    monkeypatch.setattr(drivers, "build", lambda kind, eps, key: Recorder())
    scenario = Scenario(
        "repeat", "", "ADT", "A05", count=3, expect=expect, dead_letter_destination="echo"
    )
    client = _as_client(Client())
    assert run_scenario(scenario, client, timeout=0.01).ok
    assert not run_scenario(scenario, client, timeout=0.01).ok
    assert len(runs[0]) == len(runs[1]) == 3
    assert runs[0].isdisjoint(runs[1])


@pytest.mark.parametrize("fixture_module", ["test_harness_scenarios", "test_harness_monitor"])
@pytest.mark.parametrize("mode", ["slow", "dead", "dead_ready", "timeout"])
def test_server_readiness_uses_one_budget_and_always_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, fixture_module: str
) -> None:
    clock = [0.0]
    servers: list[Server] = []
    joins: list[float | None] = []

    class Server:
        def __init__(self, config: object) -> None:
            self.should_exit = False
            servers.append(self)

        @property
        def started(self) -> bool:
            return mode == "dead_ready" or (mode == "slow" and clock[0] >= 11)

        def run(self) -> None:
            pass

    class Thread:
        def __init__(self, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def is_alive(self) -> bool:
            return mode not in {"dead", "dead_ready"}

        def join(self, timeout: float | None = None) -> None:
            joins.append(timeout)

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr(uvicorn, "Server", Server)
    monkeypatch.setattr(threading, "Thread", Thread)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "time", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    module = importlib.import_module(fixture_module)
    fixture = module.server.__wrapped__(tmp_path)
    if mode == "slow":
        next(fixture)
        fixture.close()
        assert 11 <= clock[0] < 12
    else:
        with pytest.raises(
            RuntimeError, match="exited" if mode.startswith("dead") else "timed out"
        ):
            next(fixture)
        assert clock[0] == 0 if mode.startswith("dead") else 40 <= clock[0] < 41
    assert len(servers) == 1
    assert servers[0].should_exit
    assert joins == [10]


# --- the coverage report (vault BACKLOG #2672) ------------------------------------------------------


def test_coverage_pins_the_mllp_and_file_rows(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--coverage"]) == 0
    lines = capsys.readouterr().out.splitlines()

    def row(direction: str, kind: str) -> str:
        hits = [ln for ln in lines if ln.split()[:2] == [direction, kind]]
        assert len(hits) == 1, (direction, kind, lines)
        return hits[0]

    def names(direction: str, kind: str) -> set[str]:
        return set(row(direction, kind).split(None, 2)[2].split(", "))

    # At least these: a later family may add its own scenarios to a row, never remove these.
    assert names("inbound", "mllp") >= {
        "dead_letter",
        "error",
        "filtered",
        "mllp_echo_delivered",
        "processed",
        "unrouted",
    }
    assert names("outbound", "mllp") >= {"mllp_echo_delivered"}
    assert names("inbound", "file") >= {"file_roundtrip"}
    assert names("outbound", "file") >= {"file_roundtrip"}


def test_coverage_reads_the_live_registries_not_a_list() -> None:
    """Every registered pair gets exactly one row, and the registries are the engine's own."""
    from messagefoundry.transports import base

    live = registered_kinds()
    assert live["inbound"] == {k.value for k in base._SOURCES}
    assert live["outbound"] == {k.value for k in base._DESTINATIONS}
    rows = coverage_rows(live, SCENARIOS.values())
    registered = [(r.kind, r.direction) for r in rows if r.registered]
    assert len(registered) == len(set(registered)) == len(live["inbound"]) + len(live["outbound"])


def test_coverage_reports_an_uncovered_kind_and_a_stale_claim() -> None:
    """Controls: a kind no scenario covers reads NONE, and a claim on an unregistered kind is
    flagged rather than counted."""

    class Claims(BaseScenario):
        name = "claims_kafka"
        description = ""

        @property
        def covers(self) -> frozenset[tuple[str, str]]:
            return frozenset({("kafka", "inbound")})

        def run(self, ctx: scenarios.ScenarioContext) -> scenarios.ScenarioResult:
            raise AssertionError("never run")

    rows = coverage_rows(
        {"inbound": frozenset({"mllp", "smoke"}), "outbound": frozenset()}, [Claims()]
    )
    report = format_report(rows)
    assert "inbound  smoke       NONE" in report
    assert "NOT REGISTERED, claimed by claims_kafka" in report
    assert report.endswith("0 of 2 registered (kind, direction) pairs have a scenario")


def test_a_scenario_claims_an_outbound_only_through_a_sink() -> None:
    plain = Scenario("p", "", "ADT", "A05")
    sunk = Scenario(
        "s",
        "",
        "ADT",
        "A05",
        driver="file",
        inbound="file_in",
        sink="file",
        sink_endpoint="file_out",
    )
    assert plain.covers == {("mllp", "inbound")}
    assert sunk.covers == {("file", "inbound"), ("file", "outbound")}
    with pytest.raises(ValueError, match="sink and sink_endpoint together"):
        Scenario("x", "", "ADT", "A05", sink="mllp")
    with pytest.raises(ValueError, match="names no destination"):
        Scenario("x", "", "ADT", "A05", expect="dead_letter")


# --- endpoints and discovery -----------------------------------------------------------------------


def test_endpoint_resolution_order_is_override_then_environment_then_default() -> None:
    env = {"MEFOR_VALUE_HARNESS_MLLP_IN": "3575"}
    assert Endpoints(environ={}).port("mllp_in") == 2575
    assert Endpoints(environ=env).port("mllp_in") == 3575
    assert Endpoints({"mllp_in": "4575"}, environ=env).port("mllp_in") == 4575
    with pytest.raises(KeyError, match="unknown harness endpoint"):
        Endpoints({"no_such": "1"})
    with pytest.raises(ValueError, match="must be a port number"):
        Endpoints({"mllp_in": "x"}).port("mllp_in")
    with pytest.raises(ValueError, match="out of the port range"):
        Endpoints({"mllp_in": "70000"}).port("mllp_in")


def test_the_cli_refuses_a_malformed_endpoint(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--scenario", "processed", "--endpoint", "mllp_in"]) == 2
    assert "bad endpoint" in capsys.readouterr().err
    assert main(["--scenario", "processed", "--endpoint", "nope=1"]) == 2


def test_every_family_registry_discovers_its_modules() -> None:
    assert {"mllp", "file"} <= set(drivers.registry())
    assert {"mllp", "file"} <= set(sinks.registry())
    assert {"host", "mllp_in", "mllp_echo", "mllp_strict", "file_in", "file_out"} <= set(
        endpoints.registry()
    )


def test_a_duplicate_scenario_name_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two family modules claiming one name must not silently shadow each other."""
    from harness._discover import family_modules

    real = list(family_modules("harness.scenarios"))
    twin = SimpleNamespace(
        __name__="harness.scenarios.twin", SCENARIOS=(Scenario("processed", "", "ADT", "A05"),)
    )
    monkeypatch.setattr(scenarios, "family_modules", lambda package: iter([*real, twin]))
    scenarios.registry.cache_clear()
    try:
        with pytest.raises(ValueError, match="'processed' is declared twice"):
            scenarios.registry()
    finally:
        monkeypatch.undo()
        scenarios.registry.cache_clear()
    assert "processed" in scenarios.registry()


# --- drivers and sinks, paired against each other ----------------------------------------------------


def _hl7(control_id: str) -> bytes:
    raw = "MSH|^~\\&|A|B|C|D|20260101000000||ADT^A01|" + control_id + "|P|2.5.1\rPID|1||X\r"
    return raw.encode()


def test_the_mllp_driver_and_sink_round_trip_and_ack() -> None:
    with MLLPSink() as sink:
        out = MLLPDriver("127.0.0.1", sink.port, timeout=5.0).inject([_hl7("C1"), _hl7("C2")])
        assert [o.error for o in out] == ["", ""]
        assert all(o.reply is not None and b"MSA|AA|" in o.reply for o in out)
        records = sink.wait_for(lambda rs: len(rs) == 2, 5.0)
    assert [control_id_of(r.payload) for r in records] == ["C1", "C2"]
    assert records[0].payload == _hl7("C1")  # byte for byte, framing stripped


def test_an_mllp_sink_can_refuse_and_a_driver_reports_an_unreachable_port() -> None:
    with MLLPSink(reply="AR") as sink:
        (out,) = MLLPDriver("127.0.0.1", sink.port, timeout=5.0).inject([_hl7("C3")])
    assert out.reply is not None and b"MSA|AR|" in out.reply
    closed = sink.port  # the sink has stopped; nothing listens there now
    (gone,) = MLLPDriver("127.0.0.1", closed, timeout=2.0).inject([_hl7("C4")])
    assert gone.error


def test_the_file_driver_publishes_atomically_and_the_sink_ignores_old_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "old.hl7").write_bytes(_hl7("OLD"))
    with FileSink(tmp_path) as sink:
        assert FileDriver(tmp_path).inject([_hl7("N1")]) == [Injection()]
        (tmp_path / "tmpabc.part").write_bytes(b"half")  # an engine temp mid-write
        records = sink.wait_for(lambda rs: bool(rs), 2.0)
    assert [control_id_of(r.payload) for r in records] == ["N1"]
    assert records[0].meta["inside"] == "true"
    assert not list(tmp_path.glob(".*.part"))  # the driver's own temp was renamed away


def test_verify_sink_names_what_did_not_arrive() -> None:
    scenario = Scenario("s", "", "ADT", "A04", 2, sink="mllp", sink_endpoint="mllp_echo")

    class Fake(Sink):
        kind = "mllp"

    fake = Fake()
    fake._add(Record(_hl7("A")))
    fake._add(Record(_hl7("OTHER")))
    result = _verify_sink(scenario, fake, ["A", "B"], 0.2, "2/2 reached 'processed'")
    assert not result.ok
    assert result.detail.endswith("1/2 delivered to the mllp sink")
    fake._add(Record(_hl7("B")))
    assert _verify_sink(scenario, fake, ["A", "B"], 0.2, "").ok


def test_the_cli_names_a_malformed_endpoint_value_as_setup(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bad VALUE, not only a bad key, is exit 2 before any traffic -- from --endpoint or from the
    environment, and for an endpoint the scenario does not even use."""
    assert main(["--scenario", "processed", "--endpoint", "mllp_in=abc"]) == 2
    assert "must be a port number" in capsys.readouterr().err
    monkeypatch.setenv("MEFOR_VALUE_HARNESS_MLLP_ECHO", "99999")
    assert main(["--scenario", "processed"]) == 2
    assert "out of the port range" in capsys.readouterr().err


def test_the_cli_reports_a_busy_sink_port_as_setup(capsys: pytest.CaptureFixture[str]) -> None:
    """The documented GUI setup listens on the echo port; a sink that cannot bind is exit 2, not a
    traceback (and never a silent shared port)."""
    with MLLPSink() as holder:
        rc = main(
            [
                "--scenario",
                "mllp_echo_delivered",
                "--engine",
                "http://127.0.0.1:9",
                "--endpoint",
                f"mllp_echo={holder.port}",
            ]
        )
    assert rc == 2
    assert capsys.readouterr().err.startswith("SETUP mllp_echo_delivered:")


def test_every_sink_binds_loopback_whatever_the_host_endpoint_says() -> None:
    eps = Endpoints({"host": "0.0.0.0"}, environ={})  # noqa: S104  (the point of the test)
    for kind in ("mllp",):
        sink = sinks.build(kind, eps, "mllp_echo")
        assert isinstance(sink, MLLPSink)
        assert sink._server.host == sinks.LOOPBACK


def test_every_registered_scenario_names_real_drivers_sinks_and_endpoints() -> None:
    """A scenario that cannot run must not count as coverage: every kind it claims has a harness
    driver or sink, and every endpoint it names is declared."""
    declared = set(endpoints.registry())
    for name, scenario in SCENARIOS.items():
        if not isinstance(scenario, Scenario):
            continue
        assert scenario.driver in drivers.registry(), name
        assert scenario.inbound in declared, name
        if scenario.sink is not None:
            assert scenario.sink in sinks.registry(), name
            assert scenario.sink_endpoint in declared, name


def _graph_dirs() -> list[Path]:
    """``harness/config`` itself, plus each family subdirectory: one named after an endpoints family
    (``harness/config/database/``), and one a registered scenario names as its ``graph``. A family's
    graph lives in a subdirectory when it needs an external server or material, so that serving
    ``harness/config`` without it stays clean."""
    from harness._discover import family_modules

    families = {m.__name__.rpartition(".")[2] for m in family_modules("harness.endpoints")}
    families |= {s.graph for s in SCENARIOS.values() if s.graph}
    subdirs = sorted(HARNESS_CONFIG / f for f in families if (HARNESS_CONFIG / f).is_dir())
    return [HARNESS_CONFIG, *subdirs]


def _graph_env_refs() -> list[EnvRef]:
    """Every ``env("harness_<key>", ...)`` the harness graphs make, one per reference, so two graphs
    reading one key are each checked."""
    found: list[EnvRef] = []
    for directory in _graph_dirs():
        registry = load_config(str(directory))
        specs = [c.spec for c in registry.inbound.values()]
        specs += [c.spec for c in registry.outbound.values()]
        for spec in specs:
            for value in spec.settings.values():
                if isinstance(value, EnvRef) and value.key.startswith("harness_"):
                    found.append(value)
    return found


def test_each_graph_default_equals_its_endpoint_default() -> None:
    """The graph reads its ports through the engine's env() and the harness reads harness/endpoints;
    the two defaults are two spellings of one table, so they are held equal here, both ways.

    A key an endpoints family lists in ``ENVIRONMENT_ONLY`` (a credential) is the one exception: it
    is not an endpoint, and the graph must read it with NO default, so it never sits in source."""
    from harness._discover import family_modules
    from messagefoundry.config.wiring import env

    no_default = env("x").default
    environment_only = {
        key
        for module in family_modules("harness.endpoints")
        for key in getattr(module, "ENVIRONMENT_ONLY", ())
    }
    refs = _graph_env_refs()
    declared = endpoints.registry()
    assert refs, "the walk found no harness env() reference -- it is not looking at the graph"
    for ref in refs:
        key, default = ref.key.removeprefix("harness_"), ref.default
        if key in environment_only:
            assert default is no_default, f"harness_{key} is environment-only; drop its default"
            continue
        assert default is not no_default, (
            f"graph reads harness_{key} with no default, and no endpoints family lists it in "
            "ENVIRONMENT_ONLY"
        )
        assert key in declared, (
            f"graph reads harness_{key}, which harness/endpoints does not declare"
        )
        # The engine casts an environment value but never a default, so a graph that casts a
        # declared PORT into a whole URL (harness/config/http.py) carries that cast of the declared
        # default instead: the value it would read if the variable held the declared default.
        cast = ref.cast
        assert str(default) == declared[key].default or (
            cast is not None
            and type(cast(declared[key].default)) is type(default)
            and cast(declared[key].default) == default
        ), key
    unread = sorted(
        (set(declared) | environment_only) - {r.key.removeprefix("harness_") for r in refs}
    )
    assert not unread, f"declared endpoints no graph reads: {unread}"


def test_the_coverage_graph_imports_nothing_from_the_harness() -> None:
    """An engine serving harness/config from its own install need not have the harness importable,
    and `messagefoundry check` refuses an unvetted import (review of vault BACKLOG #2672)."""
    import ast

    for path in sorted(p for directory in _graph_dirs() for p in directory.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            assert not any(n == "harness" or n.startswith("harness.") for n in names), path.name
