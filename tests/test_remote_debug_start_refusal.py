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
    REMOTE_DEBUG_ACCEPTANCE_KEY,
    RemoteDebugPosture,
    remote_debug_refusal,
)
from messagefoundry.startupcode import InterpreterLaunch, StartupPosture
from tests.test_isolated_launch import _needs_install

# The suite pins this gate's reading off for every in-process start (tests/conftest.py). Each
# in-process start here, through `_serve` or `_supervise`, pins the reading it tests instead.

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


def _cli_lines(caplog: pytest.LogCaptureFixture, prefix: str) -> list[str]:
    """The lines the command line logged that start with ``prefix``."""
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == cli.__name__ and r.getMessage().startswith(prefix)
    ]


def _audit_lines(caplog: pytest.LogCaptureFixture, what: str) -> list[str]:
    """The AUDIT lines the gate wrote where the acceptance lifted its refusal to ``what``."""
    return _cli_lines(caplog, f"AUDIT: permitted to {what} under enforcement")


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
    warn: bool = False,
    accept: bool = False,
) -> tuple[int, list[str]]:
    """``_supervise`` with the fleet stubbed out, as tests/test_startup_code_inventory.py does."""
    spawned: list[str] = []

    async def fake_supervise(config: str, **kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    _environment(monkeypatch, warn=warn, accept=accept)
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
    # In the off-box copy the remote-debugging lines keep the first pass's order: the AUDIT line,
    # then the residual and the acceptance (vault BACKLOG #3795). Other readings, such as the
    # unpinned service-environment one, may follow them.
    logged = _cli_lines(caplog, "")
    assert len(logged) >= 2, logged
    again = [m for m in logged if m.endswith(relogged)]
    if not forwarder:
        assert not again, again
        return
    assert again[0].startswith("AUDIT: "), again
    assert [m.split(":", 1)[0] for m in again[1:3]] == [
        "[security] remote_debug_enabled",
        f"[security] {REMOTE_DEBUG_ACCEPTANCE_KEY}",
    ], again


def _residual_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The ``[security]`` start-up lines ``supervise`` writes for its own interface reading."""
    return _cli_lines(caplog, "[security] remote_debug_")


def test_supervise_refuses_before_it_reports_the_reading_as_a_residual(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #3795 item 8: under ``enforce`` the refusal comes first, so a refused fleet
    does not first log the reading as a residual it then refuses on."""
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        rc, spawned = _supervise(tmp_path, monkeypatch, _ON)
        # The control in the same capture: a WARNING on this logger is recorded here.
        logging.getLogger(cli.__name__).warning("[security] remote_debug_ control")
    assert rc == 2 and not spawned and _REFUSAL in capsys.readouterr().err
    assert _residual_lines(caplog) == ["[security] remote_debug_ control"]


@pytest.mark.parametrize(
    ("warn", "accept"), [(True, False), (False, True)], ids=["warn", "accepted"]
)
def test_supervise_reports_the_residual_once_past_this_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    warn: bool,
    accept: bool,
) -> None:
    """The controls: where this gate lets the fleet through, the residual is still logged, once,
    and after anything the gate wrote. It may stop at a later gate (no store key is set)."""
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        _supervise(tmp_path, monkeypatch, _ON, warn=warn, accept=accept)
    residual = _residual_lines(caplog)
    assert len(residual) == 1 and residual[0].startswith("[security] remote_debug_enabled: ")
    messages = [r.getMessage() for r in caplog.records if r.name == cli.__name__]
    audits = _audit_lines(caplog, "start the fleet")
    assert len(audits) == int(accept), messages
    assert all(messages.index(a) < messages.index(residual[0]) for a in audits), messages
    # The first pass's order, which the forwarder's re-log repeats: the residual, then the acceptance.
    accepted = _cli_lines(caplog, f"[security] {REMOTE_DEBUG_ACCEPTANCE_KEY}:")
    assert len(accepted) == int(accept), messages
    assert all(messages.index(residual[0]) < messages.index(a) for a in accepted), messages


def test_supervise_reports_no_residual_with_the_interface_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        rc, spawned = _supervise(tmp_path, monkeypatch, _OFF, warn=True)
        # The control in the same capture: a WARNING on this logger is recorded here.
        logging.getLogger(cli.__name__).warning("[security] remote_debug_ control")
    # The fleet went on past the residual to the store-key gate, so the residual's place ran.
    err = capsys.readouterr().err
    assert rc == 2 and not spawned and "no store key is set" in err, err[-2000:]
    assert _residual_lines(caplog) == ["[security] remote_debug_ control"]


def test_supervise_refused_at_an_earlier_gate_reports_no_residual(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #3795: the start-up code gate runs before this one, and a fleet it refuses
    logs neither the residual nor the AUDIT line, though the acceptance would lift this gate."""
    monkeypatch.setattr("messagefoundry.startupcode.startup_refusal", lambda posture: "probe")
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        rc, spawned = _supervise(tmp_path, monkeypatch, _ON, accept=True)
        logging.getLogger(cli.__name__).warning("[security] remote_debug_ control")
    assert rc == 2 and not spawned and "error: probe." in capsys.readouterr().err
    assert _residual_lines(caplog) == ["[security] remote_debug_ control"]
    assert not _audit_lines(caplog, "start the fleet")


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_a_refusal_still_reports_a_hook_that_did_not_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    command: str,
) -> None:
    """Vault BACKLOG #3795: the refusal's relaunch turns the interface off, which says nothing of
    what stopped the engine's hook, so a refused start still logs ``remote_debug_unguarded``. With
    the hook in (``_ON``), :func:`test_supervise_refuses_before_it_reports_the_reading_as_a_residual`
    is the control."""
    unguarded = RemoteDebugPosture(interpreter_enabled=True, guard_installed=False)
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        if command == "serve":
            rc = _serve(tmp_path, monkeypatch, unguarded)
        else:
            rc, _ = _supervise(tmp_path, monkeypatch, unguarded)
    assert rc == 2 and _REFUSAL in capsys.readouterr().err
    residual = _residual_lines(caplog)
    assert len(residual) == 1 and residual[0].startswith("[security] remote_debug_unguarded: ")


def test_a_serve_refusal_with_the_hook_in_logs_no_unguarded_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #3795 item 13: the unguarded line is for a hook that did not answer, so a
    refused ``serve`` whose hook is in (``_ON``) does not write it.
    :func:`test_a_refusal_still_reports_a_hook_that_did_not_answer` is the control that it would."""
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        rc = _serve(tmp_path, monkeypatch, _ON)
        # The control in the same capture: a WARNING on this logger is recorded here.
        logging.getLogger(cli.__name__).warning("[security] remote_debug_ control")
    assert rc == 2 and _REFUSAL in capsys.readouterr().err
    assert _residual_lines(caplog) == ["[security] remote_debug_ control"]


def test_an_accepted_fleet_with_the_hook_missing_logs_the_unguarded_line_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #3795 item 13: where the acceptance lifts the refusal, the fleet goes on, and
    a hook that did not answer is still reported, once: the refusal's own copy of the line is not
    written as well as the residual's. It may stop at a later gate (no store key is set).

    ``supervise`` only. ``serve`` writes the line in its loosening list, which comes after the
    store-key gate this harness stops at, so the serve half is not read here."""
    unguarded = RemoteDebugPosture(interpreter_enabled=True, guard_installed=False)
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        _supervise(tmp_path, monkeypatch, unguarded, accept=True)
    lines = _cli_lines(caplog, "[security] remote_debug_unguarded: ")
    assert len(lines) == 1, [r.getMessage() for r in caplog.records]


def test_the_pin_replaces_the_command_lines_name_and_not_the_reading() -> None:
    """Vault BACKLOG #3795 item 16. tests/conftest.py pins the command line's name for the reading,
    so no in-process start runs the real one. This runs it here: it reads this interpreter's own
    switch. And the name the pin replaces is the one ``__main__`` binds from
    ``messagefoundry.remotedebug``, so the gate reads that function wherever it is not pinned."""
    import ast as pyast

    from messagefoundry import remotedebug

    real = remotedebug.remote_debug_posture()
    assert real.interpreter_enabled is sys.is_remote_debug_enabled()
    pinned = vars(cli)["remote_debug_posture"]
    assert pinned is not remotedebug.remote_debug_posture, "the pin is not in"
    assert pinned().interpreter_enabled is False
    tree = pyast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    name = "remote_debug_posture"

    def binds(node: pyast.stmt) -> bool:
        """Whether a MODULE-level statement binds the global name the pin replaces."""
        if isinstance(node, (pyast.Import, pyast.ImportFrom)):
            return any((alias.asname or alias.name) == name for alias in node.names)
        if isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef, pyast.ClassDef)):
            return node.name == name
        if isinstance(node, (pyast.Assign, pyast.AnnAssign, pyast.AugAssign)):
            targets = node.targets if isinstance(node, pyast.Assign) else [node.target]
            return any(isinstance(t, pyast.Name) and t.id == name for t in targets)
        return False

    module_level = [node for node in tree.body if binds(node)]
    last = module_level[-1] if module_level else None
    assert (
        isinstance(last, pyast.ImportFrom)
        and last.module == "messagefoundry.remotedebug"
        and any(a.name == name and a.asname is None for a in last.names)
    ), f"__main__'s last module-level binding of {name} is not the import from remotedebug"


def test_the_acceptance_key_is_the_settings_field_and_its_variable() -> None:
    """Vault BACKLOG #3795 item 7: the one key the qualified name and the loosening name derive
    from is the field the settings load, under its ``MEFOR_SECURITY_`` variable."""
    from messagefoundry.config.settings import load_settings

    variable = f"MEFOR_SECURITY_{REMOTE_DEBUG_ACCEPTANCE_KEY.upper()}"
    for text, accepted in (("true", True), ("false", False)):
        settings = load_settings(environ={variable: text}, default_file=False)
        assert getattr(settings.security, REMOTE_DEBUG_ACCEPTANCE_KEY) is accepted


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


#: ``serve`` in a real interpreter with the start-up code gate, which runs just before this one,
#: pinned to a clean reading, as :func:`_environment` pins it in process. Unpinned, start-up code
#: this environment happens to carry would refuse first, and the arms below would read that gate.
#: ``__main__`` is IMPORTED and ``main`` called, not run through ``-m``: its module-level guard
#: still goes in, and the remote-debugging reading stays the interpreter's own, but runpy's
#: ``-m`` path and the ``if __name__ == "__main__"`` line are not exercised by these arms.
_PINNED_SERVE = """\
import sys
import messagefoundry.startupcode as startupcode
from messagefoundry.startupcode import InterpreterLaunch, StartupPosture
hardened = StartupPosture(launch=InterpreterLaunch(
    isolated=True, safe_path=True, ignore_environment=True, no_user_site=True))
startupcode.startup_posture = lambda: hardened
from messagefoundry.__main__ import main
sys.exit(main(sys.argv[1:]))
"""


def _real_serve(tmp_path: Path, *options: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *options, "-c", _PINNED_SERVE, "serve"]
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
    # The interpreter flags the refusal names; the entry is _PINNED_SERVE's, not `-m messagefoundry`.
    proc = _real_serve(tmp_path, "-P", "-X", "disable-remote-debug")
    assert _REFUSAL not in proc.stderr
    assert proc.returncode == 2, proc.stderr[-2000:]
    assert "no MEFOR_STORE_ENCRYPTION_KEY" in proc.stderr, proc.stderr[-2000:]


def test_serve_lists_a_reading_taken_after_its_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3795 item 15, kept as designed: ``serve`` reads the posture again for its
    loosening list, because the refused-script count is a snapshot, and a refusal after the gate
    must still be counted there. The gates in between are stood down and the start is stopped
    at the list's build.

    Mutation: pass the gate's reading to the list; the list then shows the older count."""
    readings: list[RemoteDebugPosture] = []
    listed: list[object] = []

    def reading() -> RemoteDebugPosture:
        posture = RemoteDebugPosture(
            interpreter_enabled=False, guard_installed=True, refused_scripts=len(readings)
        )
        readings.append(posture)
        return posture

    def stop_at_the_list(*_args: object, **kwargs: object) -> NoReturn:
        listed.append(kwargs["remote_debug"])
        raise _PastTheReLog

    monkeypatch.chdir(tmp_path)
    _environment(monkeypatch, warn=False, accept=False)
    _stand_down_the_gates_before_logging(monkeypatch)
    monkeypatch.setattr(cli, "_store_key_configured", lambda settings: True)
    monkeypatch.setattr(cli, "_start_logging", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "remote_debug_posture", reading)
    monkeypatch.setattr("messagefoundry.config.settings.security_loosenings", stop_at_the_list)
    with caplog.at_level(logging.WARNING, logger=cli.__name__):
        # main's last-resort handler turns the stop into a non-zero exit.
        assert cli.main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev"]) != 0
    assert listed, "the start stopped before the loosening list, so this arm proves nothing"
    assert len(readings) == 2 and listed == readings[1:], (readings, listed)


#: ``supervise`` in a real interpreter, with the start-up code gate pinned clean as
#: :data:`_PINNED_SERVE` pins it, and the remote-debugging reading pinned on with the hook not
#: answering, so the remote-debugging gate refuses and logs ``remote_debug_unguarded``.
_PINNED_UNGUARDED_SUPERVISE = """\
import sys
import messagefoundry.startupcode as startupcode
from messagefoundry.startupcode import InterpreterLaunch, StartupPosture
hardened = StartupPosture(launch=InterpreterLaunch(
    isolated=True, safe_path=True, ignore_environment=True, no_user_site=True))
startupcode.startup_posture = lambda: hardened
from messagefoundry import __main__ as cli
from messagefoundry.remotedebug import RemoteDebugPosture
unguarded = RemoteDebugPosture(interpreter_enabled=True, guard_installed=False)
cli.remote_debug_posture = lambda: unguarded
sys.exit(cli.main(sys.argv[1:]))
"""

_UNGUARDED_LINE = "[security] remote_debug_unguarded: "


def _real_unguarded_supervise(tmp_path: Path, *, merged: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _PINNED_UNGUARDED_SUPERVISE, "supervise"]
        + ["--config", str(_SAMPLES_CONFIG), "--env", "dev"],
        cwd=tmp_path,
        env=_child_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merged else subprocess.PIPE,
        text=True,
        timeout=45,
        check=False,
    )


@_needs_install
def test_supervise_logs_the_unguarded_line_to_stdout_and_refuses_on_stderr(
    tmp_path: Path,
) -> None:
    """Vault BACKLOG #3795 item 12: the stream each goes to, as SECURITY-LOOSENING.md states it."""
    _child_interface_on(tmp_path)  # for its skip: the child must import this checkout
    proc = _real_unguarded_supervise(tmp_path, merged=False)
    assert proc.returncode == 2, proc.stderr[-2000:]
    assert _UNGUARDED_LINE in proc.stdout and _UNGUARDED_LINE not in proc.stderr, proc.stdout
    assert _REFUSAL in proc.stderr and _REFUSAL not in proc.stdout, proc.stderr[-2000:]


@_needs_install
def test_supervise_logs_the_unguarded_line_before_it_refuses(tmp_path: Path) -> None:
    """Vault BACKLOG #3795 item 12: the order, read with both streams on one pipe."""
    _child_interface_on(tmp_path)  # for its skip: the child must import this checkout
    proc = _real_unguarded_supervise(tmp_path, merged=True)
    assert proc.returncode == 2, proc.stdout[-2000:]
    assert _UNGUARDED_LINE in proc.stdout and _REFUSAL in proc.stdout, proc.stdout[-2000:]
    assert proc.stdout.index(_UNGUARDED_LINE) < proc.stdout.index(_REFUSAL), proc.stdout
