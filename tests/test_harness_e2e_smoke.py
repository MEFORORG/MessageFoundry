# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``python -m harness.e2e_smoke`` against a real engine, with negative controls.

Each test starts a real ``serve`` subprocess, so each costs an engine start (about 10 to 20 s).

The configs here are written per test with a free MLLP port, so parallel workers and other
checkouts on the same box never contend for the sample's fixed 2575. The sample config itself is
what ``.claude/skills/e2e-smoke/SKILL.md`` runs; its graph is the one mirrored below.

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

#: Above the subprocess cap and its grace below, so a hung engine fails as that timeout, with
#: its output.
pytestmark = pytest.mark.timeout(360)

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
    argv = [
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
    ]
    with subprocess.Popen(  # noqa: S603 -- our own interpreter and fixed arguments
        argv,
        cwd=_REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    ) as proc:
        try:
            out, err = proc.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            # On POSIX, SIGTERM first, as subprocess.run's timeout does not: the smoke's teardown
            # runs on it, and a SIGKILL would skip it and orphan the engine with its ports held. On
            # Windows terminate() is a hard kill; the engine dies with the smoke's job, and its temp
            # directory stays.
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=50)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
            pytest.fail(f"the smoke hung past 240 s\n{err}{out}")
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


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


def test_the_mllp_timeout_reaches_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(e2e_smoke, "run", lambda **kwargs: seen.update(kwargs))
    assert e2e_smoke.main(["--mllp-timeout", "3.5"]) == 0
    assert seen["mllp_timeout"] == 3.5


@pytest.mark.parametrize("value", ["0", "-1", "inf", "nan"])
def test_a_timeout_that_is_not_a_finite_positive_number_is_refused(value: str) -> None:
    with pytest.raises(SystemExit) as exited:
        e2e_smoke.main(["--mllp-timeout", value])
    assert exited.value.code == 2


def test_a_taken_api_port_fails_before_any_engine_starts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        api_port = int(holder.getsockname()[1])
        code = e2e_smoke.main(
            ["--config", str(config), "--mllp-port", str(port), "--api-port", str(api_port)]
        )
    out = capsys.readouterr()
    assert code == 1, out.err + out.out
    assert f"FAIL ports: API port {api_port} is in use" in out.err


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
        SimpleNamespace(role="source", channel_id=name, status=status, port=port, method="MLLP")
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


@pytest.mark.parametrize(
    ("status", "port"),
    [("not_deployed", 2575), ("failed", 2575), ("filtered", 2575), ("running", 2600)],
)
def test_an_inbound_that_waiting_cannot_change_fails_at_once(status: str, port: int) -> None:
    failed, took = _wait_inbound(lambda: _rows(("IB_E2E_ADT", status, port)))
    assert failed.step == "ready"
    assert f"status {status}, port {port}, expected port 2575" in str(failed)
    assert took < 5


def test_an_inbound_missing_from_the_graph_fails_at_once() -> None:
    failed, took = _wait_inbound(lambda: _rows(("IB_OTHER", "running", 2576)))
    assert failed.step == "ready"
    assert "IB_E2E_ADT is not in the engine's graph" in str(failed)
    assert took < 5


def test_a_connection_closed_before_the_ack_says_so() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(30)  # a send that never connects fails the test, not hangs it
        port = int(server.getsockname()[1])

        def close_at_once() -> None:
            conn, _ = server.accept()
            with conn:  # read the whole frame first, so the close is a FIN and not a reset
                received = b""
                while not received.endswith(b"\x1c\r") and (chunk := conn.recv(4096)):
                    received += chunk

        closer = threading.Thread(target=close_at_once)
        closer.start()
        message = e2e_smoke._DEFAULT_MESSAGE.read_text(encoding="utf-8")
        with pytest.raises(e2e_smoke.StepFailed) as failed:
            e2e_smoke._send(port, message, timeout=10.0)
        closer.join()
    assert failed.value.step == "mllp"
    assert "closed the connection before an ACK" in str(failed.value)


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


def test_stop_warns_when_the_group_could_not_be_signalled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(e2e_smoke, "ADOPT_NEW_SESSION", True)
    monkeypatch.setattr(e2e_smoke, "kill_reaped_leader_group", lambda pid: None)
    e2e_smoke._stop(_Proc(0), None)  # type: ignore[arg-type]
    assert "could not be signalled" in capsys.readouterr().err


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


def test_a_held_signal_waits_for_the_block_then_ends_the_run() -> None:
    state = e2e_smoke._SignalState()
    finished: list[str] = []
    with pytest.raises(SystemExit) as exited, state.held():
        state.handle(signal.SIGTERM, None)
        state.handle(signal.SIGINT, None)  # a second one neither aborts nor replaces the first
        finished.append("teardown")
    assert finished == ["teardown"]
    assert exited.value.code == 128 + signal.SIGTERM
    with pytest.raises(KeyboardInterrupt):
        state.handle(signal.SIGINT, None)  # outside the block, at once


def test_a_ctrl_c_during_teardown_is_held_until_it_finishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end through main()'s handler: without the hold, the SIGINT aborts _remove before it
    deletes anything."""
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("signal handlers are installed only from the main thread")
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
    code = e2e_smoke.main(["--config", str(config), "--mllp-port", str(port)])
    assert code == 128 + signal.SIGINT
    assert len(removed) == 1
    assert not removed[0].exists()
    assert signal.getsignal(signal.SIGINT) is before


def test_a_running_inbound_that_reports_no_port_is_ready_on_its_name() -> None:
    """An inbound whose port comes from ``env()`` reports none; its name and status are the word."""
    client: Any = SimpleNamespace(
        connections=lambda: [
            SimpleNamespace(
                role="source", channel_id="IB_E2E_ADT", status="running", port=None, method="MLLP"
            )
        ]
    )
    reported = e2e_smoke._wait_inbound(
        client,
        _Proc(),  # type: ignore[arg-type]
        inbound="IB_E2E_ADT",
        mllp_port=2575,
        deadline=time.monotonic() + 30,
    )
    assert reported is None


def test_an_inbound_that_is_not_mllp_fails_at_once() -> None:
    """/connections reports no port for a non-MLLP inbound, so a None port must not pass it."""
    rows = [
        SimpleNamespace(
            role="source", channel_id="IB_E2E_ADT", status="running", port=None, method="X12"
        )
    ]
    failed, took = _wait_inbound(lambda: rows)
    assert failed.step == "ready"
    assert "IB_E2E_ADT is X12, not MLLP" in str(failed)
    assert took < 5


def test_an_engine_left_running_fails_a_run_whose_steps_passed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_start(argv: object, **_: object) -> tuple[_Proc, None]:
        return _Proc(), None

    class _Client:
        base_url = "https://127.0.0.1:1"

        def __init__(self, *_: object, **__: object) -> None: ...
        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *_: object) -> None: ...
        def set_token(self, token: str) -> None: ...

    monkeypatch.setattr(e2e_smoke, "_check_checkout", lambda env, work: work)
    monkeypatch.setattr(rigadmin, "provision", lambda **_: True)
    monkeypatch.setattr(rigadmin, "sign_in", lambda *a, **k: "token")
    monkeypatch.setattr(e2e_smoke, "EngineClient", _Client)
    monkeypatch.setattr(e2e_smoke, "_start", fake_start)
    monkeypatch.setattr(e2e_smoke, "_wait_api", lambda *a: None)
    monkeypatch.setattr(e2e_smoke, "_wait_inbound", lambda *a, **k: 2575)
    monkeypatch.setattr(e2e_smoke, "_send", lambda *a, **k: "AA")
    monkeypatch.setattr(e2e_smoke, "_poll_disposition", lambda *a, **k: "processed")
    monkeypatch.setattr(e2e_smoke, "_stop", lambda proc, job: False)
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    with pytest.raises(e2e_smoke.StepFailed) as failed:
        e2e_smoke.run(
            config=config,
            message_file=e2e_smoke._DEFAULT_MESSAGE,
            inbound="IB_E2E_ADT",
            mllp_port=port,
            expect="processed",
            timeout=1.0,
        )
    assert failed.value.step == "teardown"


def test_a_signal_held_by_a_block_that_raises_still_ends_the_run() -> None:
    state = e2e_smoke._SignalState()
    with pytest.raises(SystemExit) as exited, state.held():
        state.handle(signal.SIGTERM, None)
        raise RuntimeError("the block failed")
    assert exited.value.code == 128 + signal.SIGTERM
    assert state.pending is None
    assert not state.holding


def test_stop_warns_when_the_engine_outlives_its_kill(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(e2e_smoke, "ADOPT_NEW_SESSION", False)

    class _Refusing(_Proc):
        def terminate(self) -> None:
            raise PermissionError("refused")

        def kill(self) -> None:
            raise PermissionError("refused")

    e2e_smoke._stop(_Refusing(), None)  # type: ignore[arg-type]
    assert "WARNING the engine (pid 424242) did not stop" in capsys.readouterr().err


@pytest.mark.parametrize("error", [RuntimeError("not an OSError"), KeyboardInterrupt()])
def test_a_resume_that_fails_with_another_error_stops_the_engine_and_re_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: BaseException
) -> None:
    """A non-OSError from ``resume_into_job`` would leave the suspended engine outside its job.

    RED when: ``_start`` catches only OSError, so ``_stop`` never runs for this error."""
    proc = _Proc()
    stopped: list[tuple[object, object, bool]] = []

    def fake_stop(p: object, job: object, *, never_ran: bool = False) -> bool:
        stopped.append((p, job, never_ran))
        return True

    def failing_resume(pid: int, *, who: str) -> int | None:
        raise error

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(e2e_smoke, "resume_into_job", failing_resume)
    monkeypatch.setattr(e2e_smoke, "_stop", fake_stop)
    with pytest.raises(type(error)) as raised:
        e2e_smoke._start(["engine"], work=tmp_path, env={}, log=tmp_path / "engine.log")
    assert raised.value is error
    assert stopped == [(proc, None, True)]


def test_a_failing_stop_still_removes_the_temp_directory_and_keeps_the_step_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    removed: list[Path] = []
    real_remove = e2e_smoke._remove

    def remove(path: Path) -> bool:
        removed.append(path)
        return real_remove(path)

    def fail_stop(proc: object, job: object) -> None:
        raise OSError("stop failed")

    def fake_start(argv: object, **_: object) -> tuple[_Proc, None]:
        return _Proc(), None

    def refuse_api(*_: object) -> None:
        raise e2e_smoke.StepFailed("serve", "planted")

    monkeypatch.setattr(e2e_smoke, "_check_checkout", lambda env, work: work)
    monkeypatch.setattr(rigadmin, "provision", lambda **_: True)
    monkeypatch.setattr(e2e_smoke, "_start", fake_start)
    monkeypatch.setattr(e2e_smoke, "_wait_api", refuse_api)
    monkeypatch.setattr(e2e_smoke, "_stop", fail_stop)
    monkeypatch.setattr(e2e_smoke, "_remove", remove)
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    with pytest.raises(e2e_smoke.StepFailed) as failed:
        e2e_smoke.run(
            config=config,
            message_file=e2e_smoke._DEFAULT_MESSAGE,
            inbound="IB_E2E_ADT",
            mllp_port=port,
            expect="processed",
            timeout=1.0,
        )
    assert failed.value.step == "serve"
    assert "planted" in str(failed.value)
    assert "WARNING the teardown failed too: OSError: stop failed" in capsys.readouterr().err
    assert len(removed) == 1
    assert not removed[0].exists()


def test_an_unforeseen_error_ends_in_a_fail_line_naming_the_step(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def broken_check(env: object, work: object) -> Path:
        raise ValueError("bad\x1b[2Jvalue")

    monkeypatch.setattr(e2e_smoke, "_check_checkout", broken_check)
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    code = e2e_smoke.main(["--config", str(config), "--mllp-port", str(port)])
    err = capsys.readouterr().err
    assert code == 1
    assert "FAIL checkout: ValueError: bad" in err
    assert "\x1b" not in err


def test_an_installed_harness_names_the_missing_defaults(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Installed, the repo-relative defaults point into site-packages, where samples/ is not."""
    site = tmp_path / "site-packages"
    monkeypatch.setattr(e2e_smoke, "_REPO", site)
    monkeypatch.setattr(e2e_smoke, "_DEFAULT_CONFIG", site / "samples" / "config")
    monkeypatch.setattr(e2e_smoke, "_DEFAULT_MESSAGE", site / "samples" / "messages" / "a.hl7")
    monkeypatch.setattr(e2e_smoke, "_DEFAULT_ENVIRONMENTS", site / "environments")
    monkeypatch.setattr(e2e_smoke, "run", lambda **_: pytest.fail("ran without a checkout"))
    code = e2e_smoke.main([])
    err = capsys.readouterr().err
    assert code == 1
    assert err.startswith("FAIL message: not found for the default --config")
    assert "--message" in err
    assert "--project-root" in err
    assert "run from a MessageFoundry checkout" in err


def test_a_reply_that_does_not_parse_says_so() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(30)  # a send that never connects fails the test, not hangs it
        port = int(server.getsockname()[1])

        def answer_garbage() -> None:
            conn, _ = server.accept()
            with conn:
                received = b""
                while not received.endswith(b"\x1c\r") and (chunk := conn.recv(4096)):
                    received += chunk
                conn.sendall(b"\x0bnot an ACK\x1c\r")

        answerer = threading.Thread(target=answer_garbage)
        answerer.start()
        message = e2e_smoke._DEFAULT_MESSAGE.read_text(encoding="utf-8")
        with pytest.raises(e2e_smoke.StepFailed) as failed:
            e2e_smoke._send(port, message, timeout=10.0)
        answerer.join()
    assert failed.value.step == "mllp"
    assert "did not parse: HL7PeekError" in str(failed.value)


def test_main_leaves_an_ignored_signal_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("signal handlers are installed only from the main thread")
    seen: dict[str, object] = {}
    monkeypatch.setattr(
        e2e_smoke, "run", lambda **_: seen.update(handler=signal.getsignal(signal.SIGTERM))
    )
    before = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        assert e2e_smoke.main([]) == 0
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGTERM, before)
    assert seen["handler"] == signal.SIG_IGN
