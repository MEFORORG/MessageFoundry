# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Windows service-control helpers: state parsing + a real missing-service query.

The body moved to :mod:`messagefoundry.service` (ADR 0088); this exercises it there so the
``sys``/``subprocess`` monkeypatches land where ``service_state`` resolves them (the
``messagefoundry.console.service_control`` shim just re-exports these)."""

from __future__ import annotations

import messagefoundry.service as service_control
from messagefoundry.service import (
    install_script_path,
    parse_service_state,
    service_state,
)


def test_parse_service_state() -> None:
    assert parse_service_state("        STATE              : 4  RUNNING") == "running"
    assert parse_service_state("        STATE              : 1  STOPPED") == "stopped"
    assert parse_service_state("nonsense") == "unknown"


def test_service_state_for_missing_service() -> None:
    # Windows -> 'not installed'; other platforms / no `sc` -> 'unavailable'. Either is fine.
    assert service_state("MessageFoundryNoSuchService_zzz") in {"not installed", "unavailable"}


def test_service_state_query_suppresses_console_window(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Regression: ``sc query`` must run with CREATE_NO_WINDOW so the windowless GUI process doesn't
    flash a console window on every Status-page poll. Fake win32 + capture the kwargs so the guard
    holds on any host OS (``_NO_WINDOW`` is 0 off Windows, so we assert the flag is *passed*)."""

    class _Result:
        returncode = 0
        stdout = "STATE : 4  RUNNING"

    captured: dict[str, object] = {}

    def _fake_run(*args: object, **kwargs: object) -> _Result:
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(service_control.sys, "platform", "win32")
    monkeypatch.setattr(service_control.subprocess, "run", _fake_run)

    assert service_state("MessageFoundry") == "running"
    assert "creationflags" in captured  # the flag must be passed (no console-window flash)
    assert captured["creationflags"] == service_control._NO_WINDOW


def test_install_script_path_is_found() -> None:
    path = install_script_path()
    assert path is not None
    assert path.name == "install-service.ps1"
    assert path.exists()
