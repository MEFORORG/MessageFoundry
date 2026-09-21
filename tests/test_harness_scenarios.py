# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The headless scenario runner sends traffic and asserts the engine's disposition via the API.

Qt-free: starts a real managed app (engine + API) with an MLLP inbound + file outbound, then runs
scenarios end-to-end. Also smoke-tests the CLI dispatch (list / unknown name) without a server.
"""

from __future__ import annotations

import importlib
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn

from harness import scenarios
from harness.__main__ import main
from harness.scenarios import Scenario, _verify_dead_letter, _verify_disposition, run_scenario
from messagefoundry.api import create_managed_app
from messagefoundry.apiclient import EngineClient
from messagefoundry.parsing.message import Message


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _write_config(config_dir: Path, mllp_port: int, outdir: Path, dead_port: int) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    module = f'''\
from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy

inbound("in", MLLP(port={mllp_port}), router="r")
outbound("file", File(directory="{outdir.as_posix()}", filename="{{MSH-10}}.hl7"))
# Points at a closed port with no retries, so A01's echo delivery dead-letters immediately.
outbound(
    "echo",
    MLLP(host="127.0.0.1", port={dead_port}, connect_timeout=1.0, timeout_seconds=1.0),
    retry=RetryPolicy(max_attempts=1),
)


@router("r")
def route(msg):
    return [] if msg["MSH-9.1"] != "ADT" else ["h"]


@handler("h")
def handle(msg):
    trigger = msg["MSH-9.2"]
    if trigger == "A03":
        raise RuntimeError("boom")
    if trigger == "A02":
        return None
    if trigger == "A01":  # fan-out: echo (will dead-letter) + file (succeeds)
        return [Send("echo", msg), Send("file", msg)]
    return Send("file", msg)
'''
    (config_dir / "cfg.py").write_text(module, encoding="utf-8")


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, int]]:
    mllp_port = _free_port()
    dead_port = _free_port()  # nothing listens here: echo delivery dead-letters
    _write_config(tmp_path / "config", mllp_port, tmp_path / "out", dead_port)
    app = create_managed_app(
        db_path=tmp_path / "scenarios.db",
        config_dir=tmp_path / "config",
        poll_interval=0.05,
    )
    api_port = _free_port()
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    # Keep the former four ten-second attempts' total readiness allowance, but let one
    # live startup finish. Restarting a slow startup every ten seconds cannot help it.
    deadline = time.monotonic() + 40.0
    try:
        while True:
            if not thread.is_alive():
                raise RuntimeError(
                    f"server exited during startup (api_port={api_port}, mllp_port={mllp_port})"
                )
            if uv.started:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    f"server startup timed out after 40s (api_port={api_port}, mllp_port={mllp_port})"
                )
            time.sleep(min(0.05, remaining))
        yield f"http://127.0.0.1:{api_port}", mllp_port
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


@pytest.mark.parametrize(
    ("code", "trigger", "expect"),
    [
        ("ADT", "A05", "processed"),  # archived to file
        ("ADT", "A02", "filtered"),  # handler returns None
        ("ORU", "R01", "unrouted"),  # router returns []
        ("ADT", "A03", "error"),  # handler raises
    ],
)
def test_scenario_reaches_expected_disposition(
    server: tuple[str, int], code: str, trigger: str, expect: str
) -> None:
    api_url, mllp_port = server
    scenario = Scenario(expect, "", code, trigger, count=3, expect=expect, inbound_port=mllp_port)
    with EngineClient(api_url) as client:
        result = run_scenario(scenario, client, timeout=15.0)
    assert result.ok, result.detail


def test_dead_letter_scenario(server: tuple[str, int]) -> None:
    api_url, mllp_port = server
    scenario = Scenario(
        "dl",
        "",
        "ADT",
        "A01",
        count=2,
        expect="dead_letter",
        dead_letter_destination="echo",
        inbound_port=mllp_port,
    )
    with EngineClient(api_url) as client:
        result = run_scenario(scenario, client, timeout=20.0)
    assert result.ok, result.detail


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
    assert not _verify_dead_letter(scenario, stale, ["MINE1", "MINE2"], 0.05, []).ok
    mine = FakeClient(["MINE1", "MINE2", "OTHER1"])
    assert _verify_dead_letter(scenario, mine, ["MINE1", "MINE2"], 5.0, []).ok


def test_verify_disposition_queries_per_control_id_and_surfaces_send_errors() -> None:
    # low-23: query per control id (resilient to concurrent traffic pushing rows off a page) and
    # surface partial send errors in the detail.
    scenario = Scenario("p", "", "ADT", "A05", count=2, expect="processed")
    queried: list[str | None] = []

    class FakeClient:
        def list_messages(self, *, control_id: str | None = None, limit: int = 50, **k: object):  # type: ignore[no-untyped-def]
            queried.append(control_id)
            return SimpleNamespace(
                messages=[SimpleNamespace(control_id=control_id, status="processed")]
            )

    result = _verify_disposition(scenario, FakeClient(), ["A", "B"], 5.0, ["connection refused"])
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
    stored: set[str] = set()
    runs: list[set[str]] = []

    def send(host: str, port: int, payloads: list[str]) -> list[str]:
        ids = {Message.parse(raw)["MSH-10"] for raw in payloads}
        runs.append(ids)
        if len(runs) == 1:
            stored.update(ids)
        return [""] * len(payloads)

    class Client:
        def list_messages(self, *, control_id: str, **kwargs: object) -> object:
            rows = [SimpleNamespace(status="processed")] if control_id in stored else []
            return SimpleNamespace(messages=rows)

        def list_dead_letters(self, **kwargs: object) -> object:
            return SimpleNamespace(dead_letters=[SimpleNamespace(control_id=c) for c in stored])

    monkeypatch.setattr(scenarios, "_send_mllp", send)
    scenario = Scenario(
        "repeat", "", "ADT", "A05", count=3, expect=expect, dead_letter_destination="echo"
    )
    client = Client()
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
