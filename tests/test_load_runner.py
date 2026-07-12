# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

# A genuine failure burns the full budgets back-to-back (5s stop grace + 30s await_drain + up to 30s
# settle-poll + the 1.5s phase + fixture startup) — past the global 60s watchdog, which would kill the
# run with a stack dump INSTEAD of failing the assert with report.no_loss.detail. Match the sibling
# connscale/multishard smokes' 120s so a real failure stays diagnosable.
pytestmark = pytest.mark.timeout(120)

_LOAD_CONFIG = Path("harness/config/load")


def _reserve_port() -> socket.socket:
    """Reserve a free loopback port by binding a socket to port 0 and KEEPING IT OPEN.

    Returns the still-bound socket; read its port via ``.getsockname()[1]``. Closing a socket just to
    learn its port (the old ``_free_port``) opens a TOCTOU window where the OS reassigns that freed
    ephemeral port to another process before the real server binds it — surfacing under contended CI
    as ``[Errno 98] address already in use``. Holding the socket open removes that race: the API
    socket is handed straight to uvicorn (never closed), and the MLLP sockets are released only
    immediately before the engine binds them. ``SO_REUSEADDR`` lets the port be re-bound the instant
    the reservation socket closes."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    return s


def _free_port() -> int:
    """A likely-free loopback port (the reservation socket is closed immediately). Use only where the
    code under test must itself bind the port (e.g. the load runner's own results sink) or merely
    needs nothing listening — NOT for a port this fixture binds, which uses :func:`_reserve_port` to
    hold the socket open and avoid the close→rebind race."""
    s = _reserve_port()
    try:
        return int(s.getsockname()[1])
    finally:
        s.close()


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, int, int]]:
    """Serve the load config with small fan-out + free ports. Yields (api_url, adt_port, sink_port)."""
    # Reserve every port up front while all sockets are held open, so the OS hands out mutually
    # distinct ports (and none can be re-handed to a sibling reservation). The MLLP ports are released
    # just before the engine binds them; the API socket is never closed — it is handed straight to
    # uvicorn, so there is no close→rebind gap to race on.
    adt_sock, results_sock, other_sock, sink_sock, api_sock = (
        _reserve_port(),
        _reserve_port(),
        _reserve_port(),
        _reserve_port(),
        _reserve_port(),
    )
    adt_port = adt_sock.getsockname()[1]
    sink_port = sink_sock.getsockname()[1]
    api_port = api_sock.getsockname()[1]
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "2")
    monkeypatch.setenv("MEFOR_LOAD_RESULTS_FANOUT", "1")
    monkeypatch.setenv("MEFOR_LOAD_TRANSFORM", "cheap")
    monkeypatch.setenv("MEFOR_LOAD_ADT_PORT", str(adt_port))
    monkeypatch.setenv("MEFOR_LOAD_RESULTS_PORT", str(results_sock.getsockname()[1]))
    monkeypatch.setenv("MEFOR_LOAD_OTHER_PORT", str(other_sock.getsockname()[1]))
    monkeypatch.setenv("MEFOR_LOAD_SINK_PORT", str(sink_port))

    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=tmp_path / "load.db", config_dir=_LOAD_CONFIG, poll_interval=0.05
    )
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning"))
    # Release the MLLP ports at the last moment (SO_REUSEADDR + never-listened sockets → immediately
    # re-bindable) so the engine's listeners can claim them on startup; hand the still-bound API socket
    # to uvicorn directly.
    for s in (adt_sock, results_sock, other_sock, sink_sock):
        s.close()
    thread = threading.Thread(target=lambda: uv.run(sockets=[api_sock]), daemon=True)
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
        api_sock.close()  # idempotent; uvicorn closes it on clean shutdown, this covers a failed start


def _profile(adt_port: int) -> object:
    return load_profile_text(f"""
[load]
name = "it"
corpus_count_per_trigger = 5
pool_size = 4
poll_interval_s = 0.25
drain_timeout_s = 30.0
[[load.target]]
name = "adt_hub"
host = "127.0.0.1"
port = {adt_port}
types = ["ADT"]
[load.mix]
"ADT^A05" = 1.0
[load.slo]
zero_loss = true
# No max_error_rate: over this profile's ~90-message phase a single transport blip (one reconnect's
# failed open under CI contention — client-side noise, not loss) exceeds any sane rate threshold, so
# the SLO would gate on runner weather, flipping result_ok while every correctness check passes (the
# windows-2025 flake). Correctness is fully carried by zero_loss + the reconcile + the resolution
# asserts below; report._phase_slos also floors rate SLOs at _RATE_SLO_MIN_SENT, so a threshold on a
# phase this small would not be evaluated anyway.
#
# Align the drain SLO with drain_timeout_s above — this is a no-loss CORRECTNESS test, not a
# throughput benchmark, so the only meaningful bound is "did the backlog drain within the timeout".
# A contended CI runner can take >15s to drain a perfectly lossless backlog (observed 16.14s on the
# windows-2025 leg — hence 30, not 20); a tighter threshold just opens a flake window between
# "drained fine" and "SLO failed". A real timeout already fails the no-loss check (backlog != 0) and
# the drain_seconds assertion below, so this stays a true bound without the timing flake.
max_drain_seconds = 30.0
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
    # Every send resolves to exactly one of acked / nak / timeout (the sender's _fail_inflight
    # reclassifies anything in-flight at a connection close as a timeout). A timeout is a client-side
    # unconfirmed ACK — a frame the engine received (and, per no_loss below, delivered) but whose ACK
    # hadn't landed within the stop grace when the connection tore down under CI contention. It is not
    # an engine failure; the reconcile accounts for it as unconfirmed, never as loss (no_loss below is
    # the correctness authority). This is NOT a tight timing bound: a slow runner (windows-2025) can
    # strand a large share of in-flight frames at teardown — observed ~half (timeouts=46/sent=90) with
    # zero loss — so a fixed small cap flakes. What this MUST still catch is a systemic ACK-path
    # regression: an engine that receives-but-never-ACKs strands the WHOLE run (acked~0, timeouts~sent)
    # yet still passes no_loss (internal delivery is fine, only the client-facing ACK never returns).
    # nak==0 + the identity alone would pass that, so require that a real fraction of sends were
    # ACKed — proof the client-facing ACK path works — which acked~0 fails while teardown weather does
    # not.
    assert report.counters.nak == 0
    assert report.counters.acked >= report.counters.sent // 4, report.counters
    assert report.counters.acked + report.counters.timeouts == report.counters.sent
    assert report.no_loss.ok, report.no_loss.detail
    # Fan-out 2 → every ACKed message (ACK == durable ingress commit) MUST reach the sink twice; the
    # drain wait + no_loss.ok guarantee both deliveries resolved. `>= acked` alone would also pass an
    # ACKed-then-dead-lettered message (dead rows leave backlog at 0 and are excluded from written).
    assert report.no_loss.sink_received == report.no_loss.engine_written
    assert report.no_loss.sink_received >= 2 * report.counters.acked
    # Name the violated SLO(s) on failure — a bare `assert False` here cost a CI-triage round trip.
    assert report.result_ok and report.exit_code == 0, [c for c in report.slos if not c.ok]
    assert report.engine.drain_seconds is not None  # backlog drained within the timeout


def test_run_load_preflight_fails_on_wrong_port() -> None:
    # No engine on this port → preflight raises rather than running a doomed load. (Free ports here:
    # the runner binds its own sink to sink_port, and the adt target just needs nothing listening.)
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
