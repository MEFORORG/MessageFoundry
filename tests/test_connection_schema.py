# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`connection schema --json` — the engine-derived connection catalogue the VS Code editor renders.

The editor used to enumerate transports and settings by hand in TypeScript: 9 of 11 transports, and
per-transport field hints for 6, against the ~200 keyword-only parameters the factories accept. A
setting added to the engine simply never appeared in the GUI, and nothing failed.

The anti-rot guarantee is `test_every_factory_parameter_is_emitted`: every keyword-only parameter of
every registered transport factory must reach the schema. Add a setting to `wiring.py` and it shows
up in the form; miss one and this test fails rather than the field quietly not existing."""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
from typing import Any

import pytest

from messagefoundry.config.connection_schema import SCHEMA_VERSION, build_schema
from messagefoundry.config.connections_file import _INBOUND_KEYS, _OUTBOUND_KEYS, _TRANSPORTS
from messagefoundry.config.wiring import _is_secret_setting


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return build_schema()


def test_schema_version_is_reported(schema: dict[str, Any]) -> None:
    assert schema["schemaVersion"] == SCHEMA_VERSION


def test_every_registered_transport_is_described(schema: dict[str, Any]) -> None:
    assert set(schema["transports"]) == set(_TRANSPORTS)


def test_every_factory_parameter_is_emitted(schema: dict[str, Any]) -> None:
    """THE anti-rot gate: a setting the engine accepts but the schema omits is invisible in the GUI."""
    for name, factory in _TRANSPORTS.items():
        expected = {
            param
            for param, spec in inspect.signature(factory).parameters.items()
            if spec.kind is inspect.Parameter.KEYWORD_ONLY
        }
        emitted = set(schema["transports"][name]["params"])
        assert emitted == expected, f"{name}: schema/factory drift {expected ^ emitted}"


def test_direction_key_sets_mirror_the_loader(schema: dict[str, Any]) -> None:
    assert set(schema["directionKeys"]["inbound"]) == set(_INBOUND_KEYS)
    assert set(schema["directionKeys"]["outbound"]) == set(_OUTBOUND_KEYS)


def test_secret_flag_matches_the_engine_predicate(schema: dict[str, Any]) -> None:
    """The GUI must never offer a plaintext value box for a credential, so this flag is load-bearing."""
    for transport in schema["transports"].values():
        for param, spec in transport["params"].items():
            assert spec["secret"] == _is_secret_setting(param), param


def test_known_credentials_are_flagged_secret(schema: dict[str, Any]) -> None:
    params = schema["transports"]
    assert params["soap"]["params"]["ws_password"]["secret"] is True
    assert params["sftp"]["params"]["private_key"]["secret"] is True
    assert params["mllp"]["params"]["tls_key_password"]["secret"] is True
    assert params["mllp"]["params"]["host"]["secret"] is False


def test_annotations_resolve_to_types_not_strings(schema: dict[str, Any]) -> None:
    """wiring.py uses `from __future__ import annotations`; without eval_str every type is unknown."""
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["port"]["type"] == "int"
    assert mllp["tls"]["type"] == "bool"
    assert mllp["host"]["type"] == "str"
    assert mllp["connect_timeout"]["type"] == "float"


def test_env_capability_is_detected(schema: dict[str, Any]) -> None:
    """`host` accepts env(); `tls` does not. The form only offers an env-ref control where legal."""
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["host"]["env"] is True
    assert mllp["port"]["env"] is True
    assert mllp["tls"]["env"] is False


def test_multiline_parameter_comment_is_captured(schema: dict[str, Any]) -> None:
    """`tls_key_password`'s declaration spans three lines with the comment on the LAST one.

    A first-physical-line scrape loses exactly these — which are disproportionately the TLS and
    credential parameters — so the span-based attribution is pinned here."""
    help_text = schema["transports"]["mllp"]["params"]["tls_key_password"]["help"]
    assert "passphrase" in help_text.lower()
    assert "env()" in help_text


def test_direction_markers_are_parsed(schema: dict[str, Any]) -> None:
    """`# OUTBOUND: ...` on a parameter means the form should only offer it in that direction."""
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["host"]["direction"] == "outbound"
    assert mllp["tls_verify"]["direction"] == "outbound"
    assert mllp["encoding"]["direction"] is None  # applies to both


def test_required_is_true_only_without_a_default(schema: dict[str, Any]) -> None:
    mllp = schema["transports"]["mllp"]["params"]
    assert mllp["port"]["required"] is True  # no default -> the factory raises without it
    assert mllp["host"]["required"] is False  # defaults to None (mandatory outbound via the hint)
    assert mllp["host"]["requiredHint"] is True


def test_defaults_are_json_safe(schema: dict[str, Any]) -> None:
    json.dumps(schema)  # raises TypeError if any default leaked a non-JSON object


def test_cli_emits_schema_without_a_config_dir(tmp_path: Any) -> None:
    """`connection schema` describes the ENGINE: it must not need (or read) a config directory.

    Run from an empty cwd with no --config, so a workspace whose modules do not import — or which
    would trip the Windows config-source trust check (ADR 0036) — can still draw the form."""
    proc = subprocess.run(
        [sys.executable, "-m", "messagefoundry", "connection", "schema", "--json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schemaVersion"] == SCHEMA_VERSION
    assert set(payload["transports"]) == set(_TRANSPORTS)
