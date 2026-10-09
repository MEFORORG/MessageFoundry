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

import logging
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


#: ``_run``'s default for ``allowed_syslog``: keep what the forwarding provision set.
_PROVISIONED = "<provisioned>"


def _no_network(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("a start gate or the supervisor touched the network")


def _run(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str = "",
    *,
    verified_forwarding: bool = False,
    allowed_syslog: str | None = _PROVISIONED,
    provisions: str = PHI_GATE_PROVISIONS_TOML,
    recorder: _Recorder | None = None,
) -> tuple[int, _Recorder]:
    """Run ``serve`` or ``supervise`` as a prod instance with every OTHER gate pre-cleared.

    ``allowed_syslog`` overrides the ``[egress].allowed_syslog`` value the forwarding provision
    sets, which lists its own collector; ``None`` leaves the list unset. ``recorder`` is the
    caller's own, for a test that watches it while the command runs."""
    from messagefoundry.__main__ import main

    recorder = recorder or _Recorder()
    monkeypatch.chdir(tmp_path)
    setenv_retention_windows(monkeypatch)
    if verified_forwarding:
        setenv_verified_log_forwarding(monkeypatch, make_syslog_ca_and_crl(tmp_path))
        if allowed_syslog is None:
            monkeypatch.delenv("MEFOR_EGRESS_ALLOWED_SYSLOG")
        elif allowed_syslog is not _PROVISIONED:
            monkeypatch.setenv("MEFOR_EGRESS_ALLOWED_SYSLOG", allowed_syslog)
    (tmp_path / "messagefoundry.toml").write_text(provisions + toml, encoding="utf-8")
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
    """The spool locks its directory, so the supervisor must not share one with an engine
    shard."""
    rc, recorder = _run("supervise", tmp_path, monkeypatch, verified_forwarding=True)
    assert rc == 0
    spool = Path(recorder.forwards[0].spool_dir or "")
    assert spool == (tmp_path / "log-spool" / "supervisor").resolve()


def test_no_shard_can_be_given_the_supervisor_spool_directory(tmp_path: Path) -> None:
    from messagefoundry.__main__ import _forward_spool_dir, _supervisor_forward_spool_dir
    from messagefoundry.config.settings import LoggingSettings, ServiceSettings, StoreSettings

    db = str(tmp_path / "messagefoundry.db")
    for spool_dir in (None, str(tmp_path / "spool")):
        settings = ServiceSettings(
            store=StoreSettings(path=db), logging=LoggingSettings(forward_spool_dir=spool_dir)
        )
        own = _supervisor_forward_spool_dir(settings, db)
        shards = {_forward_spool_dir(settings, shard) for shard in (None, "supervisor", "a")}
        assert own not in shards and len(shards) == 3
        # Same parent, so the supervisor's directory sits beside its engine shards'.
        assert {Path(own).parent} == {Path(shard).parent for shard in shards}


def test_the_supervisor_spool_follows_a_base_dir_set_in_the_settings(tmp_path: Path) -> None:
    """``--db`` is anchored only by ``--project-root`` in the supervisor. A base_dir from the file
    or the environment moves each engine shard's store, so it must move the supervisor's spool
    too."""
    from messagefoundry.__main__ import _forward_spool_dir, _supervisor_forward_spool_dir
    from messagefoundry.config.settings import (
        EnvironmentsSettings,
        ServiceSettings,
        StoreSettings,
    )

    data = tmp_path / "data"
    settings = ServiceSettings(environments=EnvironmentsSettings(base_dir=str(data)))
    own = Path(_supervisor_forward_spool_dir(settings, "mefor.db"))
    assert own == (data / "log-spool" / "supervisor").resolve()
    # What an engine shard's `serve` computes once it has anchored its own relative --db under
    # base_dir.
    shard = ServiceSettings(store=StoreSettings(path=str(data / "mefor_a.db")))
    assert Path(_forward_spool_dir(shard, "a")).parent == own.parent
    # An absolute --db stays put, as it does for the engine shard.
    absolute = Path(_supervisor_forward_spool_dir(settings, str(tmp_path / "x" / "mefor.db")))
    assert absolute == (tmp_path / "x" / "log-spool" / "supervisor").resolve()


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
    assert recorder.spawned == 0, "the supervisor spawned engine shards past a refused gate"
    assert recorder.forwards == [], "the supervisor installed a forwarder past a refused gate"


# --- the own-host refusal and its fail-open notes (vault BACKLOG #2375) --------------------------
#
# Both came to `serve` after the gates moved into the shared helper. The tests below fail if the
# helper loses either. They cover at least: the refusal, the note on stderr before logging is
# configured, and the note in the log after it. The own-host rule itself is pinned in
# tests/test_forwarding_gate.py.


def test_a_collector_that_is_this_host_is_refused_for_the_supervisor_exactly_as_for_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verified TLS to a collector named as this host: no separate system, so no start. The OS
    name is stubbed and every resolver call raises, so the answer rests on no runner state."""
    monkeypatch.setattr(socket, "gethostname", lambda: VERIFIED_LOG_FORWARDING_HOST.upper() + ".")

    rc, _ = _run("serve", tmp_path, monkeypatch, verified_forwarding=True)
    serve_errors = _errors(capsys.readouterr().err)
    assert rc == 2 and len(serve_errors) == 1, serve_errors
    assert "own name or one of its own addresses" in serve_errors[0], serve_errors

    rc, recorder = _run("supervise", tmp_path, monkeypatch, verified_forwarding=True)
    assert rc == 2
    assert _errors(capsys.readouterr().err) == serve_errors
    assert recorder.spawned == 0, "the supervisor spawned engine shards past the refusal"
    assert recorder.forwards == [], "the supervisor installed a forwarder to its own host"


_NO_NAME_NOTE = "the OS gave no host name"


class _NoteWatch(_Recorder):
    """A recorder that notes what stderr and the log held when the forwarding
    ``configure_logging`` call was made. With ``live`` false it reports that no forwarder was
    installed, as ``configure_logging`` does for a collector it skipped."""

    def __init__(
        self,
        capsys: pytest.CaptureFixture[str],
        caplog: pytest.LogCaptureFixture,
        *,
        live: bool = True,
    ) -> None:
        super().__init__()
        self._capsys = capsys
        self._caplog = caplog
        self._live = live
        self.stderr_before_configure = ""
        self.logged_before_configure = 0

    def configure_logging(self, *args: Any, **kwargs: Any) -> bool:
        if "forward" in kwargs:
            self.stderr_before_configure += self._capsys.readouterr().err
            self.logged_before_configure = len(_note_records(self._caplog))
        return super().configure_logging(*args, **kwargs) and self._live


def _note_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if _NO_NAME_NOTE in r.getMessage()]


def _no_host_name() -> str:
    raise OSError("no host name")


@pytest.mark.parametrize("live", [True, False], ids=["forwarder-up", "forwarder-down"])
@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_a_fail_open_note_is_printed_before_logging_and_logged_after_it_is_configured(
    command: str,
    live: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The own-host check fails open when the OS gives no name, and its note is the record of
    that pass. It goes to stderr at the gate, once and before ``configure_logging``. It is logged
    once that call has returned, whether or not a forwarder came up: stdout and the log file are
    handlers too."""
    monkeypatch.setattr(socket, "gethostname", _no_host_name)
    recorder = _NoteWatch(capsys, caplog, live=live)
    with caplog.at_level("WARNING"):
        rc, _ = _run(command, tmp_path, monkeypatch, verified_forwarding=True, recorder=recorder)
    assert rc == 0 and len(recorder.forwards) == 1
    assert recorder.stderr_before_configure.count(f"warning: {_NO_NAME_NOTE}") == 1
    assert _NO_NAME_NOTE not in capsys.readouterr().err, "printed again after configure_logging"
    # Logged once, by the start code and not by the gate itself, and only once configured.
    assert recorder.logged_before_configure == 0
    assert [r.name for r in _note_records(caplog)] == ["messagefoundry.__main__"]


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_a_fail_open_note_still_reaches_stderr_when_the_next_gate_refuses_the_start(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Why the stderr copy is printed at the gate and not beside the log copy: a start the
    allow-list refuses next never configures logging, so stderr holds the only record that the
    forwarding gate passed without its own-host check."""
    monkeypatch.setattr(socket, "gethostname", _no_host_name)
    recorder = _NoteWatch(capsys, caplog)
    with caplog.at_level("WARNING"):
        rc, _ = _run(
            command,
            tmp_path,
            monkeypatch,
            verified_forwarding=True,
            allowed_syslog="other.example.org",
            recorder=recorder,
        )
    err = capsys.readouterr().err
    assert rc == 2 and recorder.forwards == [] and recorder.spawned == 0
    assert err.count(f"warning: {_NO_NAME_NOTE}") == 1
    assert len(_errors(err)) == 1 and "allowed_syslog" in _errors(err)[0]
    assert _note_records(caplog) == [], "logged for a start that never configured logging"


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


# --- the readings logged before the forwarder exists --------------------------------------------


@pytest.mark.parametrize("verified_forwarding", [True, False])
def test_an_early_security_reading_is_logged_again_only_once_a_forwarder_is_installed(
    verified_forwarding: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The supervisor reports its remote-debugging reading before it has read any settings, so
    before a forwarder can exist. With one installed the line is logged a second time, so the
    off-box copy has it. With none it is logged once, as before."""
    monkeypatch.setattr(
        "messagefoundry.__main__.remote_debug_loosening", lambda posture: ("probe_key", "a probe")
    )
    toml = "" if verified_forwarding else 'security.enforcement = "warn"\n'
    with caplog.at_level("WARNING", logger="messagefoundry.__main__"):
        rc, recorder = _run(
            "supervise", tmp_path, monkeypatch, toml, verified_forwarding=verified_forwarding
        )
    assert rc == 0 and len(recorder.forwards) == int(verified_forwarding)
    lines = [r.getMessage() for r in caplog.records if "probe_key" in r.getMessage()]
    assert len(lines) == (2 if verified_forwarding else 1), lines
    assert all(line.startswith("[security] probe_key: a probe.") for line in lines)
