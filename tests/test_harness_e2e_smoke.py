# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``python -m harness.e2e_smoke`` against a real engine, with negative controls.

Each test starts a real ``serve`` subprocess, so each costs an engine start (about 10 to 20 s).

The configs here are written per test with a free MLLP port, so parallel workers and other
checkouts on the same box never contend for the sample's fixed 2575. The sample config itself is
what ``.claude/skills/verify/SKILL.md`` runs; its graph is the one mirrored below.

The controls prove the script can fail, and that it names the step that did:

* an inbound bound to a router nothing registers: the engine refuses the graph, so ``serve`` fails;
* a router that selects no handler: the message is ACKed and ends UNROUTED, so ``disposition``
  fails. This is the control for the claim that the script reads the final disposition and does
  not stop at the ACK.

The tests after those drive single steps against stand-ins, without an engine.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import messagefoundry
from harness import e2e_smoke
from harness.load import rigadmin
from messagefoundry.apiclient import ApiError
from tests._harness_engine import free_port

#: Above the subprocess cap below, so a hung engine fails as that timeout, with its output.
pytestmark = pytest.mark.timeout(300)

_REPO = Path(__file__).resolve().parents[1]

_ARCHIVE_GRAPH = """\
from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router

inbound("IB_E2E_ADT", MLLP(port={port}), router="e2e_router")
outbound("FILE-OUT_E2E_ADT", File(directory="./out/adt", filename="{{MSH-10}}.hl7"))


@router("e2e_router")
def route(msg):  # type: ignore[no-untyped-def]
    return {handlers}


@handler("archive")
def archive(msg):  # type: ignore[no-untyped-def]
    return Send("FILE-OUT_E2E_ADT", msg)
"""

_DANGLING_ROUTER = """\
from messagefoundry import MLLP, inbound

inbound("IB_E2E_ADT", MLLP(port={port}), router="no_such_router")
"""


def _smoke(config: Path, port: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "harness.e2e_smoke",
            "--config",
            str(config),
            "--inbound",
            "IB_E2E_ADT",
            "--mllp-port",
            str(port),
            "--api-port",
            str(free_port()),
        ],
        cwd=_REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
        check=False,
    )


def _config(tmp_path: Path, template: str, **values: object) -> tuple[Path, int]:
    port = free_port()
    config = tmp_path / "config"
    config.mkdir()
    (config / "e2e_graph.py").write_text(template.format(port=port, **values), encoding="utf-8")
    return config, port


def test_a_routed_message_ends_processed(tmp_path: Path) -> None:
    config, port = _config(tmp_path, _ARCHIVE_GRAPH, handlers='["archive"]')
    done = _smoke(config, port)
    assert done.returncode == 0, done.stderr + done.stdout
    assert "step disposition: PROCESSED" in done.stdout
    assert "PASS e2e smoke" in done.stdout


def test_an_unrouted_message_fails_the_disposition_step(tmp_path: Path) -> None:
    config, port = _config(tmp_path, _ARCHIVE_GRAPH, handlers="[]")
    done = _smoke(config, port)
    assert done.returncode == 1, done.stderr + done.stdout
    # The ACK passed, so the failure is the disposition the API reported, not an earlier step.
    assert "step mllp: AA" in done.stdout
    assert "FAIL disposition:" in done.stderr
    assert "UNROUTED, expected PROCESSED" in done.stderr


def test_a_router_nothing_registers_fails_the_serve_step(tmp_path: Path) -> None:
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    done = _smoke(config, port)
    assert done.returncode == 1, done.stderr + done.stdout
    assert "FAIL serve:" in done.stderr
    assert "step mllp" not in done.stdout


def test_a_taken_mllp_port_fails_before_any_engine_starts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", port))
        holder.listen()
        code = e2e_smoke.main(["--config", str(config), "--mllp-port", str(port)])
    out = capsys.readouterr()
    assert code == 1, out.err + out.out
    assert f"FAIL ports: MLLP port {port} is in use" in out.err
    assert "step serve" not in out.out


def test_the_command_line_parses(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        e2e_smoke.main(["--help"])
    assert exited.value.code == 0
    assert "--mllp-port" in capsys.readouterr().out


def test_the_mllp_timeout_is_a_parameter(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        e2e_smoke.main(["--help"])
    assert "--mllp-timeout" in capsys.readouterr().out


class _Proc:
    """A stand-in engine process: running until ``returncode`` is set."""

    pid = 424242

    def __init__(self, returncode: int | None = None) -> None:
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("engine", timeout or 0)


def test_health_failures_name_the_last_api_error() -> None:
    def refuse() -> None:
        raise ApiError("TLS handshake refused")

    client: Any = SimpleNamespace(health=refuse)
    with pytest.raises(e2e_smoke.StepFailed) as failed:
        e2e_smoke._wait_api(client, _Proc(), time.monotonic() + 0.3)  # type: ignore[arg-type]
    assert failed.value.step == "serve"
    assert "TLS handshake refused" in str(failed.value)


def _rows(*rows: tuple[str, str, int]) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(role="source", channel_id=name, status=status, port=port)
        for name, status, port in rows
    ]


def _wait_inbound(rows: Any) -> tuple[e2e_smoke.StepFailed, float]:
    client: Any = SimpleNamespace(connections=rows)
    started = time.monotonic()
    with pytest.raises(e2e_smoke.StepFailed) as failed:
        e2e_smoke._wait_inbound(
            client,
            _Proc(),  # type: ignore[arg-type]
            inbound="IB_E2E_ADT",
            mllp_port=2575,
            deadline=started + 30,
        )
    return failed.value, time.monotonic() - started


def test_a_connections_api_error_is_a_ready_failure() -> None:
    def refuse() -> None:
        raise ApiError("429 Too Many Requests", status=429)

    failed, _ = _wait_inbound(refuse)
    assert failed.step == "ready"
    assert "GET /connections failed: 429 Too Many Requests" in str(failed)


def test_a_not_deployed_inbound_fails_at_once() -> None:
    failed, took = _wait_inbound(lambda: _rows(("IB_E2E_ADT", "not_deployed", 2575)))
    assert failed.step == "ready"
    assert "not_deployed" in str(failed)
    assert took < 5


def test_an_inbound_missing_from_the_graph_fails_at_once() -> None:
    failed, took = _wait_inbound(lambda: _rows(("IB_OTHER", "running", 2576)))
    assert failed.step == "ready"
    assert "IB_E2E_ADT is not in the engine's graph" in str(failed)
    assert took < 5


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [(0, "kill_reaped_leader_group"), (None, "kill_process_group")],
    ids=["reaped", "unreaped"],
)
def test_stop_signals_a_reaped_leaders_group_only_reuse_safely(
    monkeypatch: pytest.MonkeyPatch, returncode: int | None, expected: str
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(e2e_smoke, "ADOPT_NEW_SESSION", True)
    monkeypatch.setattr(
        e2e_smoke, "kill_process_group", lambda *a, **k: calls.append("kill_process_group")
    )
    monkeypatch.setattr(
        e2e_smoke,
        "kill_reaped_leader_group",
        lambda *a, **k: calls.append("kill_reaped_leader_group"),
    )
    e2e_smoke._stop(_Proc(returncode), None)  # type: ignore[arg-type]
    assert calls == [expected]


def test_checkout_refuses_an_engine_that_imports_another_package(tmp_path: Path) -> None:
    fake = tmp_path / "elsewhere" / "messagefoundry"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(fake.parent)}
    with pytest.raises(e2e_smoke.StepFailed) as failed:
        e2e_smoke._check_checkout(env, tmp_path)
    assert failed.value.step == "checkout"
    assert "elsewhere" in str(failed.value)


def test_checkout_accepts_this_checkout(tmp_path: Path) -> None:
    env = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
    package = e2e_smoke._check_checkout(env, tmp_path)
    assert package == Path(messagefoundry.__file__ or "").resolve().parent


@pytest.mark.skipif(
    threading.current_thread() is not threading.main_thread(),
    reason="signal handlers are installed only from the main thread",
)
def test_a_signal_during_teardown_is_held_until_it_finishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The control: without the hold, the SIGINT aborts _remove before it deletes anything."""
    removed: list[Path] = []
    before = signal.getsignal(signal.SIGINT)
    real_remove = e2e_smoke._remove

    def refuse_provision(**_: object) -> bool:
        raise rigadmin.RigAdminError("refused for the test")

    def interrupted_remove(path: Path) -> None:
        signal.raise_signal(signal.SIGINT)
        real_remove(path)
        removed.append(path)

    monkeypatch.setattr(e2e_smoke, "_check_checkout", lambda env, work: work)
    monkeypatch.setattr(rigadmin, "provision", refuse_provision)
    monkeypatch.setattr(e2e_smoke, "_remove", interrupted_remove)
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    with pytest.raises(SystemExit) as exited:
        e2e_smoke.run(
            config=config,
            message_file=e2e_smoke._DEFAULT_MESSAGE,
            inbound="IB_E2E_ADT",
            mllp_port=port,
            expect="processed",
            timeout=5,
        )
    assert exited.value.code == 128 + signal.SIGINT
    assert len(removed) == 1
    assert not removed[0].exists()
    assert signal.getsignal(signal.SIGINT) is before
