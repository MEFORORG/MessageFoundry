"""End-to-end load run against a real engine on a temp SQLite DB.

Serves ``harness/config/load`` (small fan-out, cheap transform, free ports) via the managed app, then
runs a tiny profile through :func:`run_load` and asserts the engine received and delivered everything
with no loss — the full send → ACK → fan-out → sink → reconcile path. Also covers the preflight
failure and the CLI dispatch. Marked implicitly slow (a few seconds); Qt-free.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest
import uvicorn

from harness.__main__ import main
from harness.load.profile import load_profile_text
from harness.load.runner import PreflightError, run_load

_LOAD_CONFIG = Path("harness/config/load")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, int, int]]:
    """Serve the load config with small fan-out + free ports. Yields (api_url, adt_port, sink_port)."""
    adt_port, results_port, other_port = _free_port(), _free_port(), _free_port()
    sink_port = _free_port()
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "2")
    monkeypatch.setenv("MEFOR_LOAD_RESULTS_FANOUT", "1")
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "cheap")
    monkeypatch.setenv("MEFOR_LOAD_ADT_PORT", str(adt_port))
    monkeypatch.setenv("MEFOR_LOAD_RESULTS_PORT", str(results_port))
    monkeypatch.setenv("MEFOR_LOAD_OTHER_PORT", str(other_port))
    monkeypatch.setenv("MEFOR_LOAD_SINK_PORT", str(sink_port))

    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=tmp_path / "load.db", config_dir=_LOAD_CONFIG, poll_interval=0.05
    )
    api_port = _free_port()
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not uv.started:
        time.sleep(0.05)
        if time.time() > deadline:
            raise RuntimeError("engine did not start")
    try:
        yield f"http://127.0.0.1:{api_port}", adt_port, sink_port
    finally:
        uv.should_exit = True
        thread.join(timeout=15)


def _profile(adt_port: int) -> object:
    return load_profile_text(f"""
[load]
name = "it"
corpus_count_per_trigger = 5
pool_size = 4
poll_interval_s = 0.25
drain_timeout_s = 20.0
[[load.target]]
name = "adt_hub"
host = "127.0.0.1"
port = {adt_port}
types = ["ADT"]
[load.mix]
"ADT^A05" = 1.0
[load.slo]
zero_loss = true
max_error_rate = 0.05
max_drain_seconds = 15.0
[[load.phase]]
name = "steady"
kind = "sustained"
loop = "open"
rate_start = 60.0
duration_s = 1.5
""")


def test_run_load_end_to_end_no_loss(engine: tuple[str, int, int]) -> None:
    api_url, adt_port, sink_port = engine
    profile = _profile(adt_port)
    report = asyncio.run(
        run_load(
            profile,  # type: ignore[arg-type]
            engine_url=api_url,
            id_prefix="LIT01",
            sink_port=sink_port,
            db_backend="sqlite",
        )
    )
    assert report.counters.sent > 0
    assert report.counters.acked == report.counters.sent  # engine ACKs every received message
    assert report.no_loss.ok, report.no_loss.detail
    # Fan-out 2 → every sent message arrives at the sink twice and is timed each time.
    assert report.no_loss.sink_received == report.no_loss.engine_written
    assert report.no_loss.sink_received >= report.counters.sent
    assert report.result_ok and report.exit_code == 0
    assert report.engine.drain_seconds is not None  # backlog drained within the timeout


def test_run_load_preflight_fails_on_wrong_port() -> None:
    # No engine on this port → preflight raises rather than running a doomed load.
    profile = _profile(_free_port())
    with pytest.raises(PreflightError):
        asyncio.run(
            run_load(
                profile,  # type: ignore[arg-type]
                engine_url="http://127.0.0.1:1",  # nothing listening
                id_prefix="LIT02",
                sink_port=_free_port(),
            )
        )


def test_cli_lists_profiles(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-profiles"]) == 0
    assert "fanout-baseline" in capsys.readouterr().out


def test_cli_rejects_load_and_scenario_together(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--load", "smoke", "--scenario", "processed"]) == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_cli_engine_setup_failure_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A bad token / unreachable engine surfaces as ApiError (the client validates via /auth/me before
    # preflight). That's a setup failure → exit 2 with a message, not exit 1 + a traceback.
    from messagefoundry.console.client import ApiError
    from harness.load import runner

    async def _boom(*_args: object, **_kwargs: object) -> object:
        raise ApiError("401 Unauthorized")

    monkeypatch.setattr(runner, "run_load", _boom)
    assert main(["--load", "smoke", "--engine", "http://127.0.0.1:9", "--token", "bad"]) == 2
    assert "engine setup failed" in capsys.readouterr().err
