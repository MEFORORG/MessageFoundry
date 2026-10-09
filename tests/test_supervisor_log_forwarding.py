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
    client_cert: bool = True,
    env: str | None = "prod",
) -> tuple[int, _Recorder]:
    """Run ``serve`` or ``supervise`` as a prod instance with every OTHER gate pre-cleared.

    ``allowed_syslog`` overrides the ``[egress].allowed_syslog`` value the forwarding provision
    sets, which lists its own collector; ``None`` leaves the list unset. ``recorder`` is the
    caller's own, for a test that watches it while the command runs. ``client_cert=False`` drops
    the client certificate the forwarding provision sets. ``env`` is the ``--env`` value, and
    ``None`` passes no flag."""
    assert client_cert or verified_forwarding, "client_cert=False needs verified_forwarding=True"
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
        if not client_cert:
            monkeypatch.delenv("MEFOR_LOGGING_FORWARD_TLS_CLIENT_CERT")
    (tmp_path / "messagefoundry.toml").write_text(provisions + toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.__main__.configure_logging", recorder.configure_logging)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", recorder.supervise)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)
    argv = [command, "--config", str(_SAMPLES_CONFIG)]
    rc = main(argv if env is None else [*argv, "--env", env])
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
        line: str = _NO_NAME_NOTE,
    ) -> None:
        super().__init__()
        self._capsys = capsys
        self._caplog = caplog
        self._live = live
        self._line = line
        self.stderr_before_configure = ""
        self.logged_before_configure = 0

    def configure_logging(self, *args: Any, **kwargs: Any) -> bool:
        if "forward" in kwargs:
            self.stderr_before_configure += self._capsys.readouterr().err
            self.logged_before_configure = len(_note_records(self._caplog, self._line))
        return super().configure_logging(*args, **kwargs) and self._live


def _note_records(
    caplog: pytest.LogCaptureFixture, line: str = _NO_NAME_NOTE
) -> list[logging.LogRecord]:
    return [r for r in caplog.records if line in r.getMessage()]


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
) -> None:
    """Why the stderr copy is printed at the gate and not beside the log copy: a start the
    allow-list refuses next never configures logging, so stderr holds the only record that the
    forwarding gate passed without its own-host check."""
    monkeypatch.setattr(socket, "gethostname", _no_host_name)
    rc, recorder = _run(
        command,
        tmp_path,
        monkeypatch,
        verified_forwarding=True,
        allowed_syslog="other.example.org",
    )
    err = capsys.readouterr().err
    assert rc == 2 and recorder.forwards == [] and recorder.spawned == 0
    assert err.count(f"warning: {_NO_NAME_NOTE}") == 1
    # The allow-list's own refusal, not the forwarding gate's, whose fix text also names the list.
    assert len(_errors(err)) == 1
    assert "is not in the [egress].allowed_syslog allowlist" in _errors(err)[0]


# --- the other gates `serve` makes ahead of its forwarder ----------------------------------------
#
# Each reads settings only and guards the collector or the store the supervisor itself opens. The
# supervisor runs them through the helpers `serve` calls, so each refusal is serve's own text.

_NONSTATIC = "security.require_nonstatic_credentials = true\n"
_FORWARD_HOP = "settings:logging.forward"
_WARN = 'security.enforcement = "warn"\n'
_SQL_SERVER_STORE = (
    'store.backend = "sqlserver"\n'
    'store.server = "db.invalid"\n'
    'store.database = "mefor"\n'
    'store.auth = "integrated"\n'
)
_OPEN_EGRESS = PHI_GATE_PROVISIONS_TOML.replace(
    "security.block_unlisted_outbound = true\n", "security.block_unlisted_outbound = false\n"
)


def _refused_alike(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    needle: str,
    **run: Any,
) -> str:
    """Run ``serve`` then ``supervise`` the same way. Both must exit 2 on one error line holding
    ``needle``; the supervisor's must start with serve's, and it must have spawned and forwarded
    nothing. Returns what the supervisor's line adds."""
    rc, _ = _run("serve", tmp_path, monkeypatch, **run)
    serve_errors = _errors(capsys.readouterr().err)
    assert rc == 2 and len(serve_errors) == 1 and needle in serve_errors[0], serve_errors

    rc, recorder = _run("supervise", tmp_path, monkeypatch, **run)
    fleet_errors = _errors(capsys.readouterr().err)
    assert rc == 2 and len(fleet_errors) == 1, fleet_errors
    assert fleet_errors[0].startswith(serve_errors[0]), (serve_errors, fleet_errors)
    assert recorder.spawned == 0, "the supervisor spawned engine shards past the refusal"
    assert recorder.forwards == [], "the supervisor installed a forwarder past the refusal"
    return fleet_errors[0][len(serve_errors[0]) :]


def test_the_supervisor_is_refused_by_the_static_credential_gate_exactly_as_serve_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``serve`` runs the settings half of the opt-in static-credential gate ahead of its
    forwarder. A TLS collector with no client certificate is one of its hops, so the supervisor
    must refuse on it too, in the same words, and install no forwarder."""
    added = _refused_alike(
        tmp_path,
        monkeypatch,
        capsys,
        _FORWARD_HOP,
        toml=_NONSTATIC,
        verified_forwarding=True,
        client_cert=False,
    )
    assert added == ""


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_a_collector_with_a_client_certificate_is_not_a_static_credential_hop(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The control for the test above: with the provision's client certificate the same gate
    passes and the start goes on, so the refusal there is the missing certificate's."""
    rc, recorder = _run(command, tmp_path, monkeypatch, _NONSTATIC, verified_forwarding=True)
    assert rc == 0 and len(recorder.forwards) == 1
    assert _errors(capsys.readouterr().err) == []


def test_under_warn_the_supervisor_logs_the_static_credential_refusal_for_its_forwarder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Under ``enforcement = warn`` the gate warns on stderr and the start goes on. The refusal
    is then logged once the forwarder is installed, so the off-box copy has it, as in ``serve``."""
    recorder = _NoteWatch(capsys, caplog, line=_FORWARD_HOP)
    with caplog.at_level("WARNING"):
        rc, _ = _run(
            "supervise",
            tmp_path,
            monkeypatch,
            _NONSTATIC + _WARN,
            verified_forwarding=True,
            client_cert=False,
            recorder=recorder,
        )
    assert rc == 0 and recorder.spawned == 1 and len(recorder.forwards) == 1
    assert f"{_FORWARD_HOP} (" in recorder.stderr_before_configure
    # Not logged before the forwarder was installed, and once after it.
    assert recorder.logged_before_configure == 0
    logged = _note_records(caplog, _FORWARD_HOP)
    assert [r.name for r in logged] == ["messagefoundry.__main__"], logged


def test_the_supervisor_is_refused_by_the_open_egress_gate_exactly_as_serve_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With ``block_unlisted_outbound`` written false and no destination list, ``serve`` refuses
    before its forwarder. That is also the state in which an empty ``allowed_syslog`` allows any
    collector, so the supervisor must not forward past it."""
    assert _OPEN_EGRESS != PHI_GATE_PROVISIONS_TOML
    added = _refused_alike(
        tmp_path,
        monkeypatch,
        capsys,
        "outbound egress is UNRESTRICTED",
        provisions=_OPEN_EGRESS,
        verified_forwarding=True,
        allowed_syslog=None,
    )
    assert added == ""


def test_the_supervisor_is_refused_by_the_managed_identity_gate_exactly_as_serve_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The supervisor opens the store itself when it renews the API pair, so it must not do so
    with a credential ``[store].require_managed_identity`` refuses. The precondition's answer is
    stubbed: a real one needs a server database, and the subject here is who asks."""
    from messagefoundry.config.settings import StoreSettings

    monkeypatch.setattr(
        StoreSettings, "managed_identity_precondition", lambda self: "the store login is static"
    )
    added = _refused_alike(
        tmp_path, monkeypatch, capsys, "the store login is static", verified_forwarding=True
    )
    assert added == ""


def test_the_supervisor_is_refused_a_production_debug_level_exactly_as_serve_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The engine shards read ``[logging].level`` from the settings the supervisor reads, and
    each refuses DEBUG on a production instance. The supervisor's own level is fixed, so this
    refusal is for the fleet."""
    added = _refused_alike(
        tmp_path,
        monkeypatch,
        capsys,
        "DEBUG",
        toml='logging.level = "DEBUG"\n',
        verified_forwarding=True,
    )
    assert added == ""


def test_the_supervisor_is_refused_a_missing_sql_server_driver_exactly_as_serve_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``serve`` refuses the SQL Server backend without its driver before it reads the
    environment, so no ``--env`` is passed here. The driver is stubbed away, and no database is
    dialled: both commands refuse before they open the store."""
    import importlib.util

    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: None if name == "aioodbc" else real_find_spec(name, *a, **k),
    )
    monkeypatch.delenv("MEFOR_AI_ENVIRONMENT", raising=False)
    added = _refused_alike(
        tmp_path,
        monkeypatch,
        capsys,
        "'sqlserver' extra",
        toml=_SQL_SERVER_STORE,
        verified_forwarding=True,
        env=None,
    )
    assert added == ""


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_the_egress_opt_out_is_audited_by_the_process_that_forwards_under_it(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With ``block_unlisted_outbound`` written false and another list declared, the open-egress
    gate passes and an empty ``allowed_syslog`` allows any collector. The AUDIT line is the
    record of that state, so the supervisor writes it too before it forwards."""
    with caplog.at_level("WARNING"):
        rc, recorder = _run(
            command,
            tmp_path,
            monkeypatch,
            'egress.allowed_mllp = ["mllp.invalid:2575"]\n',
            provisions=_OPEN_EGRESS,
            verified_forwarding=True,
            allowed_syslog=None,
        )
    assert rc == 0 and len(recorder.forwards) == 1
    assert "warning: [security].block_unlisted_outbound=false" in capsys.readouterr().err
    audit = [
        r
        for r in caplog.records
        if "AUDIT: [security].block_unlisted_outbound=false" in r.getMessage()
    ]
    assert len(audit) == 1, audit


_FLEET = " Every engine shard would refuse to start; refusing to start the fleet."


@pytest.mark.parametrize(
    ("env", "needle"),
    [
        pytest.param(None, "no active environment set", id="no-environment"),
        pytest.param("qa", "no built-in security posture", id="no-production-tier"),
        pytest.param("", "environment", id="empty-name"),
    ],
)
def test_the_supervisor_refuses_an_environment_serve_refuses_in_serves_words(
    env: str | None,
    needle: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``serve`` refuses a start with no environment, with a custom name that has no production
    tier, and with a name its settings refuse at load. Every engine shard would, so the
    supervisor refuses the fleet. It used to go on, and print ``(None)`` in its own refusals."""
    monkeypatch.delenv("MEFOR_AI_ENVIRONMENT", raising=False)
    added = _refused_alike(tmp_path, monkeypatch, capsys, needle, verified_forwarding=True, env=env)
    # A name the settings refuse at load is one error for both. The gate adds why the fleet
    # stops, as a sentence of its own: serve's tier refusal ends with no full stop.
    assert added == {None: _FLEET, "qa": "." + _FLEET, "": ""}[env]


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
