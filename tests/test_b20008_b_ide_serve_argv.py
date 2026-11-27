# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine reads the IDE's serve argv as the IDE means it (BACKLOG #5566, #5939).

The IDE status bar starts serve with ``--service-config=<file>`` bound by ``=``, so the store serve
opens is the one the Start fork guard judged. The argv comes from
``ide/src/test/fixtures/b20008-b-serve-argv.json``, which
``ide/src/test/suite/b20008-b-serve-argv.test.ts`` pins against the IDE's builder and
``b20008-b-start-wiring.test.ts`` pins against the argv the real Start launches; here the engine's
own parser reads it, after the interpreter options and ``-m messagefoundry``.
``tests/test_ide_provision_admin_argv.py`` does the same for provision-admin and its probe.
"""

from __future__ import annotations

import json
from pathlib import Path

from messagefoundry.__main__ import _build_parser

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1] / "ide/src/test/fixtures/b20008-b-serve-argv.json"
    ).read_text(encoding="utf-8")
)
SC: str = FIXTURE["serviceConfig"]
# The IDE runs `python -P -X disable-remote-debug -m messagefoundry <command> ...`.
PREFIX = ["-P", "-X", "disable-remote-debug", "-m", "messagefoundry"]


def _cli_args(argv: list[str]) -> list[str]:
    assert argv[: len(PREFIX)] == PREFIX, argv
    return argv[len(PREFIX) :]


def test_the_ide_serve_argv_names_the_service_config() -> None:
    parser, dispatch = _build_parser()
    ns = parser.parse_args(_cli_args(FIXTURE["serve"]))
    assert ns.command == "serve"
    assert "serve" in dispatch
    assert ns.service_config == SC
    assert ns.config == FIXTURE["configDir"]
    # No override rides along: the service TOML is the authority on store, environment and port.
    assert ns.db is None
    assert ns.env is None
    assert ns.port is None


def test_the_ide_default_serve_argv_names_no_service_config() -> None:
    """``serveDefault`` is serve with ``messagefoundry.serviceConfig`` at its default: the engine
    reads it as serve with no service-config file, so it falls back to ./messagefoundry.toml."""
    parser, _ = _build_parser()
    ns = parser.parse_args(_cli_args(FIXTURE["serveDefault"]))
    assert ns.command == "serve"
    assert ns.service_config is None
    assert ns.config == FIXTURE["configDir"]
    assert ns.db is None


def test_the_copied_start_command_is_the_serve_argv() -> None:
    assert FIXTURE["copyLine"].split(" ") == ["python", *FIXTURE["serve"]]


def test_control_the_flag_is_what_names_the_file() -> None:
    """Drop the one element and the parser no longer names the file, so the first test reads the
    flag the IDE passes and not a default."""
    parser, _ = _build_parser()
    args = [a for a in _cli_args(FIXTURE["serve"]) if not a.startswith("--service-config")]
    assert parser.parse_args(args).service_config is None


def test_control_the_config_pair_is_what_names_the_directory() -> None:
    """The fixture's config directory is not serve's default, so drop the pair and the parser
    answers something else: the ``ns.config`` checks above read the argv, not a fallback."""
    parser, _ = _build_parser()
    args = _cli_args(FIXTURE["serve"])
    at = args.index("--config")
    without = args[:at] + args[at + 2 :]
    assert parser.parse_args(without).config != FIXTURE["configDir"]
