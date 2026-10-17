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
import os
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.config.settings import SecuritySettings
from messagefoundry.remotedebug import (
    REMOTE_DEBUG_ACCEPTANCE,
    RemoteDebugPosture,
    remote_debug_refusal,
)
from messagefoundry.startupcode import InterpreterLaunch, StartupPosture

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
    assert "python -X disable-remote-debug -m messagefoundry" in refused
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
    _serve(tmp_path, monkeypatch, posture, warn=warn, accept=accept)
    assert _REFUSAL not in capsys.readouterr().err


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
    _supervise(tmp_path, monkeypatch, posture, accept=accept)
    assert _REFUSAL not in capsys.readouterr().err


# --- a real interpreter, started both ways ---------------------------------------------------------


def _real_serve(tmp_path: Path, *options: str) -> subprocess.CompletedProcess[str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("MEFOR_") and k != "PYTHON_DISABLE_REMOTE_DEBUG"
    }
    return subprocess.run(
        [sys.executable, *options, "-m", "messagefoundry", "serve"]
        + ["--config", str(_SAMPLES_CONFIG), "--env", "dev"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.skipif(
    not sys.is_remote_debug_enabled(), reason="this interpreter has remote debugging off"
)
def test_a_real_start_with_the_interface_on_refuses(tmp_path: Path) -> None:
    proc = _real_serve(tmp_path)
    assert proc.returncode == 2, proc.stderr[-2000:]
    assert _REFUSAL in proc.stderr


def test_a_real_start_with_disable_remote_debug_gets_past_this_gate(tmp_path: Path) -> None:
    """The control for the arm above: the launch the refusal names. It stops at a later gate, the
    missing store key, which shows it ran on past this one."""
    proc = _real_serve(tmp_path, "-X", "disable-remote-debug")
    assert _REFUSAL not in proc.stderr
    assert proc.returncode == 2, proc.stderr[-2000:]
    assert "no MEFOR_STORE_ENCRYPTION_KEY" in proc.stderr, proc.stderr[-2000:]
