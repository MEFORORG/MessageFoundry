# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine reads the IDE's provision-admin argv as the IDE means it (BACKLOG #5566, #8243 item 36).

The IDE status bar runs provision-admin, and its probe, with ``--service-config=<file>`` bound by
``=``, so the store they open is the one the Start fork guard judged. These are the argv literals
``ide/src/test/suite/provision-admin-argv.test.ts`` pins against the IDE's builders, after the
interpreter options and ``-m messagefoundry``; change one and change the other. Here the engine's
own parser reads them.
"""

from __future__ import annotations

import pytest

from messagefoundry.__main__ import _build_parser

SC = "deploy/prod/messagefoundry.toml"

PROVISION_ARGV = [
    "provision-admin",
    "--username=alice",
    "--email=alice@example.test",
    f"--service-config={SC}",
]
PROBE_ARGV = [
    "provision-admin",
    "--username=probe",
    "--email=probe@example.invalid",
    f"--service-config={SC}",
    "--json",
]


@pytest.mark.parametrize("argv", [PROVISION_ARGV, PROBE_ARGV], ids=["provision", "probe"])
def test_the_ide_argv_names_the_service_config_to_provision_admin(argv: list[str]) -> None:
    parser, dispatch = _build_parser()
    ns = parser.parse_args(argv)
    assert ns.command == "provision-admin"
    assert "provision-admin" in dispatch
    assert ns.service_config == SC
    # No store override rides along: the store is the one the service TOML names.
    assert ns.db is None
    assert ns.json is (argv is PROBE_ARGV)


def test_control_without_the_flag_the_engine_falls_back_to_its_default() -> None:
    parser, _ = _build_parser()
    ns = parser.parse_args([a for a in PROVISION_ARGV if not a.startswith("--service-config")])
    assert ns.service_config is None


def test_a_dash_leading_path_stays_the_service_config_value() -> None:
    parser, _ = _build_parser()
    ns = parser.parse_args([*PROVISION_ARGV[:3], "--service-config=-odd.toml"])
    assert ns.service_config == "-odd.toml"
