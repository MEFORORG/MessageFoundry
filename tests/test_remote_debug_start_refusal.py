# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``serve`` and ``supervise`` refuse to start under ``enforce`` when the interpreter's remote
debugging is enabled in their process (vault BACKLOG #2700, owner ruling 2026-10-16).

The escape is the named acceptance ``[security].allow_remote_debugging``, not
``enforcement = warn``. Each refusal arm has a control: the same start with the interface off, or
accepted, gets past this gate. The last arms start a real interpreter both ways, because the
reading is the interpreter's own.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.config.settings import SecuritySettings
from messagefoundry.remotedebug import (
    REMOTE_DEBUG_ACCEPTANCE,
    RemoteDebugPosture,
    remote_debug_refusal,
)
from messagefoundry.startupcode import InterpreterLaunch, StartupPosture
from tests.test_isolated_launch import _needs_install

# The suite stands this gate down for every other test (tests/conftest.py); these test it.
pytestmark = pytest.mark.usefixtures("remote_debug_start_gate")

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
#: Only the refusal says this; the loosening entries share its first half.
_REFUSAL = "enabled in this process, so a process the operating system lets attach"
_ON = RemoteDebugPosture(interpreter_enabled=True, guard_installed=True)
_OFF = RemoteDebugPosture(interpreter_enabled=False, guard_installed=False)


def _environment(monkeypatch: pytest.MonkeyPatch, *, warn: bool, accept: bool) -> None:
    # The start-up code check runs just before this gate and reads the real process, so it is
    # pinned to a clean reading, as tests/test_startup_code_inventory.py pins it.
    hardened = StartupPosture(
        launch=InterpreterLaunch(
            isolated=True, safe_path=True, ignore_environment=True, no_user_site=True
        )
    )
    monkeypatch.setattr("messagefoundry.startupcode.startup_posture", lambda: hardened)
    if warn:
        monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    else:
        monkeypatch.delenv("MEFOR_SECURITY_ENFORCEMENT", raising=False)
    if accept:
        monkeypatch.setenv("MEFOR_SECURITY_ALLOW_REMOTE_DEBUGGING", "true")
    else:
        monkeypatch.delenv("MEFOR_SECURITY_ALLOW_REMOTE_DEBUGGING", raising=False)


def _serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    posture: RemoteDebugPosture,
    *,
    warn: bool = False,
    accept: bool = False,
) -> int:
    """``serve`` with the reading pinned. No store key is set, so a start that gets past this
    gate stops at a later one before it binds anything."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    _environment(monkeypatch, warn=warn, accept=accept)
    monkeypatch.setattr(cli, "remote_debug_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return cli.main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev"])


def test_the_refusal_follows_the_interpreter_reading_only() -> None:
    assert remote_debug_refusal(_OFF) is None
    for guard_installed in (True, False):
        refused = remote_debug_refusal(
            RemoteDebugPosture(interpreter_enabled=True, guard_installed=guard_installed)
        )
        assert refused is not None and _REFUSAL in refused


def test_the_refusal_names_the_launch_that_fixes_it_and_the_acceptance() -> None:
    refused = remote_debug_refusal(_ON)
    assert refused is not None
    assert "python -P -X disable-remote-debug -m messagefoundry" in refused
    assert "PYTHON_DISABLE_REMOTE_DEBUG=1" in refused
    assert f"{REMOTE_DEBUG_ACCEPTANCE} = true" in refused
    assert REMOTE_DEBUG_ACCEPTANCE.removeprefix("[security].") in SecuritySettings.model_fields


def test_serve_refuses_under_enforce_with_remote_debugging_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _serve(tmp_path, monkeypatch, _ON) == 2
    err = capsys.readouterr().err
    assert "refusing to start: the interpreter's remote debugging" in err and _REFUSAL in err
    # This gate, and not the at-rest gate after it, stopped the start, before any side effect.
    assert "no MEFOR_STORE_ENCRYPTION_KEY" not in err
    assert not any(tmp_path.iterdir()), sorted(p.name for p in tmp_path.iterdir())


@pytest.mark.parametrize(
    ("posture", "warn", "accept"),
    [(_OFF, False, False), (_ON, False, True), (_ON, True, False)],
    ids=["interface-off", "accepted", "enforcement-warn"],
)
def test_serve_does_not_stop_at_this_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    posture: RemoteDebugPosture,
    warn: bool,
    accept: bool,
) -> None:
    """The controls: the interface off, the acceptance set, and ``warn``. Each may stop at a later
    gate; none may stop at this one."""
    assert _serve(tmp_path, monkeypatch, posture, warn=warn, accept=accept) == 2
    err = capsys.readouterr().err
    assert _REFUSAL not in err
    # The start went on to the at-rest gate after this one, so this gate let it through.
    assert "no MEFOR_STORE_ENCRYPTION_KEY" in err, err[-2000:]


def _audit_lines(caplog: pytest.LogCaptureFixture, what: str) -> list[str]:
    """The AUDIT lines the gate wrote where the acceptance lifted its refusal to ``what``."""
    prefix = f"AUDIT: permitted to {what} under enforcement"
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == cli.__name__ and r.getMessage().startswith(prefix)
    ]


@pytest.mark.parametrize(
    ("posture", "warn", "audited"),
    [(_ON, False, True), (_OFF, False, False), (_ON, True, False)],
    ids=["lifts-a-refusal", "interface-off", "enforcement-warn"],
)
def test_the_acceptance_writes_an_audit_line_only_where_it_lifts_a_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    posture: RemoteDebugPosture,
    warn: bool,
    audited: bool,
) -> None:
    """As the sibling acceptances do (allow_single_factor_admin_when_exposed,
    allow_over_granted_store_principal): a WARNING-level ``AUDIT:`` line where the acceptance
    lifts a refusal that would fire, and none where there was nothing to lift."""
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        _serve(tmp_path, monkeypatch, posture, warn=warn, accept=True)
    lines = _audit_lines(caplog, "start")
    assert bool(lines) is audited, lines  # a start that gets as far as logging writes it twice
    assert all(REMOTE_DEBUG_ACCEPTANCE in line for line in lines)


class _PastTheReLog(Exception):
    """Raised by the first call a start makes after the remote-debugging AUDIT re-log."""


def _stop_past_the_re_log(*args: object, **kwargs: object) -> NoReturn:
    raise _PastTheReLog


def _stand_down_the_gates_before_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    """The store-key and forwarder gates that would stop a test start before logging."""
    monkeypatch.setattr(cli, "_store_key_file_gate", lambda settings, **kw: True)
    monkeypatch.setattr(cli, "_forwarder_posture_refused", lambda settings, **kw: False)


@pytest.mark.parametrize(
    ("posture", "warn", "audited"),
    [(_ON, False, True), (_OFF, False, False), (_ON, True, False)],
    ids=["lifts-a-refusal", "interface-off", "enforcement-warn"],
)
def test_serve_logs_the_audit_line_again_once_logging_reaches_its_handlers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    posture: RemoteDebugPosture,
    warn: bool,
    audited: bool,
) -> None:
    """The first AUDIT line is written before ``configure_logging`` installs the operator's
    handlers and forwarder, so ``serve`` writes it again after ``_start_logging``, and neither
    where nothing was lifted. The gates in between are stood down and the start is stopped by the
    first call after the re-log."""
    marker = "TEST MARKER: logging has reached its handlers"

    def started(*args: object, **kwargs: object) -> None:
        logging.getLogger(cli.__name__).warning(marker)

    _stand_down_the_gates_before_logging(monkeypatch)
    monkeypatch.setattr(cli, "_store_key_configured", lambda settings: True)
    monkeypatch.setattr(cli, "_start_logging", started)
    monkeypatch.setattr("messagefoundry.config.settings.unread_env_warnings", _stop_past_the_re_log)
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        # main's last-resort handler turns the stop into a non-zero exit.
        assert _serve(tmp_path, monkeypatch, posture, warn=warn, accept=True) != 0
    assert any("_PastTheReLog" in r.getMessage() for r in caplog.records), (
        "the start stopped before the re-log, so this arm proves nothing"
    )
    messages = [r.getMessage() for r in caplog.records if r.name == cli.__name__]
    audits = _audit_lines(caplog, "start")
    if not audited:
        assert not audits and marker in messages, messages
        return
    assert len(audits) == 2, messages
    # One as the gate ran, and one after the handlers exist.
    started_at = messages.index(marker)
    assert audits[0] in messages[:started_at] and audits[0] in messages[started_at + 1 :], messages


def test_the_acceptance_is_named_as_a_loosening() -> None:
    from tests.test_security_posture_defaults import _names

    assert "allow_remote_debugging" in _names(sec=SecuritySettings(allow_remote_debugging=True))
    assert "allow_remote_debugging" not in _names()


def _supervise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    posture: RemoteDebugPosture,
    *,
    accept: bool = False,
) -> tuple[int, list[str]]:
    """``_supervise`` with the fleet stubbed out, as tests/test_startup_code_inventory.py does."""
    spawned: list[str] = []

    async def fake_supervise(config: str, **kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    _environment(monkeypatch, warn=False, accept=accept)
    monkeypatch.setattr(cli, "remote_debug_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    args = argparse.Namespace(
        config=str(_SAMPLES_CONFIG),
        db=str(tmp_path / "mefor.db"),
        base_port=8765,
        env="dev",
        service_config=None,
        project_root=str(tmp_path),
    )
    return cli._supervise(args), spawned


def test_supervise_refuses_under_enforce_before_it_starts_an_engine_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, spawned = _supervise(tmp_path, monkeypatch, _ON)
    err = capsys.readouterr().err
    assert rc == 2 and not spawned
    assert (
        "refusing to start the fleet: the interpreter's remote debugging" in err and _REFUSAL in err
    )
    assert "no MEFOR_STORE_ENCRYPTION_KEY" not in err


@pytest.mark.parametrize(
    ("posture", "accept"), [(_OFF, False), (_ON, True)], ids=["off", "accepted"]
)
def test_supervise_does_not_stop_at_this_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    posture: RemoteDebugPosture,
    accept: bool,
) -> None:
    rc, spawned = _supervise(tmp_path, monkeypatch, posture, accept=accept)
    err = capsys.readouterr().err
    assert _REFUSAL not in err
    # The fleet went on to the store-key gate after this one, so this gate let it through.
    assert rc == 2 and not spawned and "no store key is set" in err, err[-2000:]


def test_supervise_writes_the_audit_line_where_the_acceptance_lifts_its_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        # It may stop at a later gate (no store key is set); the line comes before those.
        _supervise(tmp_path, monkeypatch, _ON, accept=True)
    lines = _audit_lines(caplog, "start the fleet")
    assert len(lines) == 1 and REMOTE_DEBUG_ACCEPTANCE in lines[0], lines


@pytest.mark.parametrize("forwarder", [True, False], ids=["forwarder", "no-forwarder"])
def test_supervise_logs_the_audit_line_again_for_the_forwarder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    forwarder: bool,
) -> None:
    """With a forwarder installed, ``supervise`` writes the AUDIT line once more so the off-box
    copy has it, and only then. The gates in between are stood down; the renewal after the re-log
    stops it."""

    def started(*args: object, configure: Callable[[None], object], **kwargs: object) -> None:
        # _supervise below stubs configure_logging out; its return says whether one installed.
        monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: forwarder)
        configure(None)

    _stand_down_the_gates_before_logging(monkeypatch)
    monkeypatch.setattr(cli, "_keyless_store_gate", lambda settings: None)
    monkeypatch.setattr(cli, "_start_logging", started)
    monkeypatch.setattr(cli, "_renew_api_tls_before_spawning", _stop_past_the_re_log)
    with caplog.at_level(logging.WARNING, logger=cli.__name__), pytest.raises(_PastTheReLog):
        _supervise(tmp_path, monkeypatch, _ON, accept=True)
    lines = _audit_lines(caplog, "start the fleet")
    relogged = "(Logged again for the off-box forwarder.)"
    assert not lines[0].endswith(relogged), lines
    assert [line.endswith(relogged) for line in lines[1:]] == ([True] if forwarder else []), lines


# --- a real interpreter, started both ways ---------------------------------------------------------


def _child_env() -> dict[str, str]:
    """The parent's environment less what would decide the reading or the import for the child:
    the engine's own variables, the variable that turns the interface off, and PYTHONPATH, so the
    installed package answers and not a path the parent happened to carry."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("MEFOR_")
        and k.upper() not in {"PYTHON_DISABLE_REMOTE_DEBUG", "PYTHONPATH"}
    }


def _real_serve(tmp_path: Path, *options: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *options, "-m", "messagefoundry", "serve"]
        + ["--config", str(_SAMPLES_CONFIG), "--env", "dev"],
        cwd=tmp_path,
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=45,  # with the probe's 10 s, under the suite's 60 s pytest-timeout
        check=False,
    )


_PROBE = (
    "import sys, messagefoundry; print(sys.is_remote_debug_enabled()); "
    "print(messagefoundry.__file__)"
)


def _child_interface_on(tmp_path: Path) -> bool:
    """Whether a child started as :func:`_real_serve` starts one has the interface on. Read from
    the child, not this process: a parent run with PYTHON_DISABLE_REMOTE_DEBUG=1 or -X
    disable-remote-debug has it off itself, and the child, started without either, has it on.
    Skips where the child would import an engine other than this checkout's, since neither arm
    would then test the code under review."""
    probe = subprocess.run(
        [sys.executable, "-P", "-c", _PROBE],
        cwd=tmp_path,
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    enabled, package = probe.stdout.strip().splitlines()[-2:]
    assert enabled in {"True", "False"}, probe.stdout
    here = Path(cli.__file__).resolve().parent
    if Path(package).resolve().parent != here:
        pytest.skip(f"SKIP (nothing run): the installed engine is {package}, not this checkout")
    return enabled == "True"


@_needs_install
def test_a_real_start_with_the_interface_on_refuses(tmp_path: Path) -> None:
    if not _child_interface_on(tmp_path):
        pytest.skip("SKIP (nothing run): this interpreter build has remote debugging off")
    proc = _real_serve(tmp_path)
    assert proc.returncode == 2, proc.stderr[-2000:]
    assert _REFUSAL in proc.stderr


@_needs_install
def test_a_real_start_with_disable_remote_debug_gets_past_this_gate(tmp_path: Path) -> None:
    """The control for the arm above: the launch the refusal names. It stops at a later gate, the
    missing store key, which shows it ran on past this one."""
    _child_interface_on(tmp_path)  # for its skip: the child must import this checkout
    proc = _real_serve(tmp_path, "-P", "-X", "disable-remote-debug")  # as the refusal names
    assert _REFUSAL not in proc.stderr
    assert proc.returncode == 2, proc.stderr[-2000:]
    assert "no MEFOR_STORE_ENCRYPTION_KEY" in proc.stderr, proc.stderr[-2000:]
