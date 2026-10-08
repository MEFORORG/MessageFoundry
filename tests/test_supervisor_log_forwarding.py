# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The supervisor process forwards its own log lines off-box (BACKLOG #2356).

``supervise`` used to call ``configure_logging("INFO")`` and nothing else, so the process that
restarts engine shards kept its lines on the host. It now goes through the helper ``serve`` uses,
so it passes the same forwarding gates and prints the same refusals.

No test here opens a socket or resolves a name: ``configure_logging`` is replaced by a recorder,
and the network calls a forwarder would make raise.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.logging_setup import SyslogForward
from tests._phi_gate_provisions import (
    PHI_GATE_PROVISIONS_TOML,
    VERIFIED_LOG_FORWARDING_HOST,
    make_syslog_ca_and_crl,
    setenv_retention_windows,
    setenv_verified_log_forwarding,
)

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

#: A collector on another host, by a reserved name that never resolves.
_REMOTE = "siem.invalid"


class _Recorder:
    """Stands in for ``configure_logging`` and for the fleet the supervisor would spawn."""

    def __init__(self) -> None:
        self.logging_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.spawned = 0

    def configure_logging(self, *args: Any, **kwargs: Any) -> bool:
        self.logging_calls.append((args, kwargs))
        return kwargs.get("forward") is not None

    async def supervise(self, *args: Any, **kwargs: Any) -> int:
        self.spawned += 1
        return 0

    @property
    def forwards(self) -> list[SyslogForward]:
        return [kw["forward"] for _, kw in self.logging_calls if kw.get("forward") is not None]


def _no_network(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("a start gate or the supervisor touched the network")


def _run(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str = "",
    *,
    verified_forwarding: bool = False,
) -> tuple[int, _Recorder]:
    """Run ``serve`` or ``supervise`` as a prod instance with every OTHER gate pre-cleared."""
    from messagefoundry.__main__ import main

    recorder = _Recorder()
    monkeypatch.chdir(tmp_path)
    setenv_retention_windows(monkeypatch)
    if verified_forwarding:
        setenv_verified_log_forwarding(monkeypatch, make_syslog_ca_and_crl(tmp_path))
    (tmp_path / "messagefoundry.toml").write_text(PHI_GATE_PROVISIONS_TOML + toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.__main__.configure_logging", recorder.configure_logging)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", recorder.supervise)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)
    rc = main([command, "--config", str(_SAMPLES_CONFIG), "--env", "prod"])
    return rc, recorder


def _errors(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("error:")]


# --- forwarding configured ----------------------------------------------------------------------


def test_the_supervisor_installs_the_forwarder_when_forwarding_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, recorder = _run("supervise", tmp_path, monkeypatch, verified_forwarding=True)
    assert rc == 0 and recorder.spawned == 1
    assert len(recorder.forwards) == 1, recorder.logging_calls
    forward = recorder.forwards[0]
    assert (forward.host, forward.protocol) == (VERIFIED_LOG_FORWARDING_HOST, "tls")
    assert forward.tls_verify is True and forward.tls_crl_file
    # The bare call the supervisor made before this change, plus the forwarder and nothing else.
    assert recorder.logging_calls == [(("INFO",), {}), (("INFO",), {"forward": forward})]


def test_the_supervisor_spool_is_its_own_directory_beside_the_shards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spool locks its directory, so the supervisor must not share one with a shard."""
    rc, recorder = _run("supervise", tmp_path, monkeypatch, verified_forwarding=True)
    assert rc == 0
    spool = Path(recorder.forwards[0].spool_dir or "")
    assert spool == (tmp_path / "log-spool" / "supervisor").resolve()


def test_no_shard_can_be_given_the_supervisor_spool_directory(tmp_path: Path) -> None:
    from messagefoundry.__main__ import _forward_spool_dir, _supervisor_forward_spool_dir
    from messagefoundry.config.settings import ServiceSettings

    db = str(tmp_path / "messagefoundry.db")
    for spool_dir in (None, str(tmp_path / "spool")):
        settings = ServiceSettings(store={"path": db}, logging={"forward_spool_dir": spool_dir})
        own = _supervisor_forward_spool_dir(settings, db)
        shards = {_forward_spool_dir(settings, shard) for shard in (None, "supervisor", "a")}
        assert own not in shards and len(shards) == 3
        # Same parent, so the supervisor's directory sits beside its shards'.
        assert {Path(own).parent} == {Path(shard).parent for shard in shards}


# --- the same gates, the same refusals ----------------------------------------------------------

_PLAINTEXT_HOP = f'[logging]\nforward_host = "{_REMOTE}"\n'
_ATTESTED_PLAINTEXT_HOP = (
    _PLAINTEXT_HOP + 'forward_hop_attested = true\nforward_hop_attested_reason = "IPsec tunnel"\n'
)


@pytest.mark.parametrize(
    ("toml", "needles"),
    [
        pytest.param(_PLAINTEXT_HOP, ("off-box forwarding", "forward_hop_attested"), id="hop-gate"),
        pytest.param("", ("ASVS 16.4.3", "no off-box collector"), id="forwarding-gate-no-host"),
        pytest.param(
            _ATTESTED_PLAINTEXT_HOP, ("ASVS 16.4.3", "not 'tls'"), id="forwarding-gate-plaintext"
        ),
    ],
)
def test_the_supervisor_is_refused_by_each_gate_exactly_as_serve_is(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    toml: str,
    needles: tuple[str, ...],
) -> None:
    rc, _ = _run("serve", tmp_path, monkeypatch, toml)
    serve_errors = _errors(capsys.readouterr().err)
    assert rc == 2 and len(serve_errors) == 1, serve_errors
    assert all(needle in serve_errors[0] for needle in needles), serve_errors

    rc, recorder = _run("supervise", tmp_path, monkeypatch, toml)
    assert rc == 2
    assert _errors(capsys.readouterr().err) == serve_errors
    assert recorder.spawned == 0, "the supervisor spawned shards past a refused gate"
    assert recorder.forwards == [], "the supervisor installed a forwarder past a refused gate"


def test_the_gates_under_test_can_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the refusals above: the same fixture, with verified forwarding, starts."""
    rc, recorder = _run("supervise", tmp_path, monkeypatch, verified_forwarding=True)
    assert rc == 0 and recorder.spawned == 1


# --- forwarding not configured ------------------------------------------------------------------


def test_with_no_collector_the_supervisor_logs_as_it_did(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Under ``enforcement = warn`` the forwarding gate warns and the start goes on, so this is the
    one posture where a supervisor runs with no collector. It then installs no forwarder."""
    rc, recorder = _run("supervise", tmp_path, monkeypatch, 'security.enforcement = "warn"\n')
    assert rc == 0 and recorder.spawned == 1
    assert recorder.forwards == []
    assert recorder.logging_calls == [(("INFO",), {}), (("INFO",), {"forward": None})]
    assert "does not forward its logs off-box over verified TLS" in capsys.readouterr().err
