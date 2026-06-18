# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Console Windows service-control helpers: state parsing + a real missing-service query."""

from __future__ import annotations

from messagefoundry.console.service_control import (
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


def test_install_script_path_is_found() -> None:
    path = install_script_path()
    assert path is not None
    assert path.name == "install-service.ps1"
    assert path.exists()
