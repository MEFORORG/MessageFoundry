# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine reads the IDE's provision-admin argv as the IDE means it (BACKLOG #5566, #8243 item 36).

The IDE status bar runs provision-admin, and its probe, with ``--service-config=<file>`` bound by
``=``, so the store they open is the one the Start fork guard judged. The argv comes from
``ide/src/test/fixtures/provision-admin-argv.json``, which
``ide/src/test/suite/provision-admin-argv.test.ts`` pins against the IDE's builders; here the
engine's own parser reads it, after the interpreter options and ``-m messagefoundry``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import _build_parser

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1] / "ide/src/test/fixtures/provision-admin-argv.json"
    ).read_text(encoding="utf-8")
)
SC: str = FIXTURE["serviceConfig"]
# The IDE runs `python -P -X disable-remote-debug -m messagefoundry <command> ...`.
PREFIX = ["-P", "-X", "disable-remote-debug", "-m", "messagefoundry"]


def _cli_args(argv: list[str]) -> list[str]:
    assert argv[: len(PREFIX)] == PREFIX, argv
    return argv[len(PREFIX) :]


@pytest.mark.parametrize("which", ["provision", "probe"])
def test_the_ide_argv_names_the_service_config_to_provision_admin(which: str) -> None:
    parser, dispatch = _build_parser()
    ns = parser.parse_args(_cli_args(FIXTURE[which]))
    assert ns.command == "provision-admin"
    assert "provision-admin" in dispatch
    assert ns.service_config == SC
    # No store override rides along: the store is the one the service TOML names.
    assert ns.db is None
    assert ns.json is (which == "probe")


def test_the_ide_default_probe_argv_names_no_service_config() -> None:
    """``probeDefault`` is the probe with ``messagefoundry.serviceConfig`` at its default: the
    engine reads it as provision-admin with no service-config file and no store override."""
    parser, _ = _build_parser()
    ns = parser.parse_args(_cli_args(FIXTURE["probeDefault"]))
    assert ns.command == "provision-admin"
    assert ns.service_config is None
    assert ns.db is None
    assert ns.json is True


def test_control_without_the_flag_the_engine_falls_back_to_its_default() -> None:
    parser, _ = _build_parser()
    args = [a for a in _cli_args(FIXTURE["provision"]) if not a.startswith("--service-config")]
    assert parser.parse_args(args).service_config is None


def test_a_dash_leading_path_stays_the_service_config_value() -> None:
    parser, _ = _build_parser()
    args = [a for a in _cli_args(FIXTURE["provision"]) if not a.startswith("--service-config")]
    assert parser.parse_args([*args, "--service-config=-odd.toml"]).service_config == "-odd.toml"
