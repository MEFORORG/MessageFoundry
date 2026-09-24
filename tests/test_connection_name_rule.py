# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The config loader refuses a connection name the operator API would refuse (BACKLOG #1107).

Why the loader must hold the API's rule is in :mod:`messagefoundry.connection_names`. These tests
pin the refusal on both authoring surfaces, and pin the two layers to ONE pattern.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry import connection_names
from messagefoundry.api import validation
from messagefoundry.config import wiring
from messagefoundry.config.connections_edit import upsert_connection
from messagefoundry.config.impact import plan_rename
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry.corepoint_import import import_corepoint
from tests.test_api_input_validation import _accepts
from tests.test_connections_file import LOGIC_PY, _config

#: Names the rule must refuse. Each one names the reason it is here.
_BAD_NAMES = (
    "A/B",  # the defect: splits across two decoded path parameters
    "IB\n",  # Python's `$` would admit this; pydantic's does not, and neither may the loader
    "IB.ADT",  # reads as a path or a dotted name
    "IB\\ADT",  # a Windows path separator
    "IB ADT",  # whitespace forges log and CSV fields
    "IB%2FADT",  # a pre-encoded slash
    "_IB",  # no leading letter
    "1IB",  # no leading letter
    "",  # empty
    "A" * 257,  # one past the ceiling
)

#: Names the rule must admit, including the hyphenated shape four shipped connections use.
_GOOD_NAMES = ("IB_ACME_ADT", "FILE-OUT_EXAMPLE_ADT", "a", "A" * 256)

_Builder = Callable[[Path, str, str], Path]


def _code_first(tmp_path: Path, inbound_name: str, outbound_name: str) -> Path:
    body = LOGIC_PY + textwrap.dedent(
        f"""
        from messagefoundry import File, MLLP, inbound, outbound
        inbound({inbound_name!r}, MLLP(port=2600), router="r")
        outbound({outbound_name!r}, File(directory="./out"))
        """
    )
    (tmp_path / "logic.py").write_text(body, encoding="utf-8")
    return tmp_path


def _toml(tmp_path: Path, inbound_name: str, outbound_name: str) -> Path:
    # json.dumps yields a TOML basic string for any of these names, escapes included.
    return _config(
        tmp_path,
        f"""
        [[inbound]]
        name = {json.dumps(inbound_name)}
        transport = "mllp"
        router = "r"
          [inbound.settings]
          port = 2600

        [[outbound]]
        name = {json.dumps(outbound_name)}
        transport = "file"
          [outbound.settings]
          directory = "./out"
        """,
    )


_BUILDERS = pytest.mark.parametrize("builder", [_code_first, _toml], ids=["code", "toml"])


def test_one_pattern_object_serves_both_layers() -> None:
    # Identity, not equality: a second copy with the same text today is the drift this item closes.
    assert validation.CONNECTION_NAME_PATTERN is connection_names.CONNECTION_NAME_PATTERN
    assert wiring.CONNECTION_NAME_PATTERN is connection_names.CONNECTION_NAME_PATTERN
    # The ceiling the importer budgets against is the one written in the pattern.
    assert f"{{0,{connection_names.CONNECTION_NAME_MAX_LENGTH - 1}}}" in (
        connection_names.CONNECTION_NAME_PATTERN
    )
    # And the pydantic type the API routes use is built from that same string.
    constraint = validation.ConnectionName.__metadata__[0]
    assert constraint.pattern is connection_names.CONNECTION_NAME_PATTERN


@pytest.mark.parametrize("name", _BAD_NAMES + _GOOD_NAMES)
def test_loader_predicate_agrees_with_the_api_type(name: str) -> None:
    # The two regex engines differ on anchoring, so a shared string is not enough on its own: this
    # pins the loader's Python match to pydantic's verdict, name by name.
    api_accepts = _accepts(validation.ConnectionName, name)
    assert connection_names.is_connection_name(name) is api_accepts
    assert api_accepts is (name in _GOOD_NAMES)


def test_non_string_is_not_a_connection_name() -> None:
    assert connection_names.is_connection_name(None) is False
    assert connection_names.is_connection_name(b"IB") is False


@_BUILDERS
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
@pytest.mark.parametrize("bad", ["A/B", "IB\n", "IB.ADT", "1IB"])
def test_a_bad_connection_name_is_refused_at_load(
    tmp_path: Path, builder: _Builder, direction: str, bad: str
) -> None:
    names = (bad, "OB") if direction == "inbound" else ("IB", bad)
    with pytest.raises(WiringError, match=f"invalid {direction} connection name") as info:
        load_config(builder(tmp_path, *names))
    assert repr(bad) in str(info.value)
    assert connection_names.CONNECTION_NAME_PATTERN in str(info.value)


@_BUILDERS
def test_good_names_still_load(tmp_path: Path, builder: _Builder) -> None:
    # The control for every refusal above: the same builder with legal, hyphenated names loads, so a
    # refusal is attributable to the name and not to a broken fixture.
    registry = load_config(builder(tmp_path, "IB-ACME_ADT", "FILE-OUT_ACME"))
    assert set(registry.inbound) == {"IB-ACME_ADT"}
    assert set(registry.outbound) == {"FILE-OUT_ACME"}


def test_upsert_refuses_a_bad_name_before_writing(tmp_path: Path) -> None:
    # The editor's own check, so the file is never written; the loader would only roll it back.
    def must_not_run(_config_dir: Path) -> None:
        raise AssertionError("the config was validated, so the file was written first")

    obj = {"direction": "inbound", "name": "A/B", "transport": "mllp", "router": "r"}
    with pytest.raises(WiringError, match="connection 'name' 'A/B' must match"):
        upsert_connection(tmp_path, obj, validate=must_not_run)
    assert not (tmp_path / "connections.toml").exists()


@pytest.mark.parametrize("kind", ["inbound", "outbound"])
def test_a_rename_to_a_bad_connection_name_is_refused_at_plan_time(
    tmp_path: Path, kind: str
) -> None:
    cfg = _code_first(tmp_path, "IB", "OB")
    registry = load_config(cfg)
    old = "IB" if kind == "inbound" else "OB"
    with pytest.raises(WiringError, match="is not a valid connection name"):
        plan_rename(registry, cfg, kind, old, "A/B")
    # The control: a legal new name plans cleanly, so the refusal above is the name's.
    plan_rename(registry, cfg, kind, old, "RENAMED-OK")


def test_a_corepoint_import_with_messy_names_still_loads(tmp_path: Path) -> None:
    # The importer generates connection names from export text. A space, a dot, a non-ASCII letter
    # or an over-long name must be folded to fit the rule, or the generated config cannot load.
    long_name = "D" * 300
    export = {
        "format": "corepoint-actionlist",
        "version": 1,
        "channels": [
            {
                "name": "ACME ADT",
                "inbound": {"connector": "mllp", "name": "R\u00e9sultats ADT", "port": 2600},
                "destinations": [
                    {"name": "Epic ADT Out", "connector": "mllp", "host": "10.0.0.1", "port": 6000},
                    {"name": "LAB.RESULTS", "connector": "mllp", "host": "10.0.0.2", "port": 6001},
                    {"name": long_name, "connector": "mllp", "host": "10.0.0.3", "port": 6002},
                ],
                "handlers": [
                    {"name": "h", "actions": [], "destinations": ["Epic ADT Out", "LAB.RESULTS"]}
                ],
            }
        ],
    }
    src = tmp_path / "export.json"
    src.write_text(json.dumps(export), encoding="utf-8")
    out = tmp_path / "out"
    import_corepoint(src, out)
    registry = load_config(out)
    names = set(registry.inbound) | set(registry.outbound)
    assert names == {"R_sultats_ADT", "Epic_ADT_Out", "LAB_RESULTS", "D" * 240}
    assert all(connection_names.is_connection_name(n) for n in names)


def test_a_corepoint_import_keeps_legal_names_and_non_ascii_handlers(tmp_path: Path) -> None:
    # The fold applies to connection names only, and only to names that fail the rule: a legal
    # hyphenated name is kept, so it cannot collide with its underscore twin, and non-ASCII handler
    # names stay distinct. Long channel names must not collapse unnamed destinations onto one name.
    export = {
        "format": "corepoint-actionlist",
        "version": 1,
        "channels": [
            {
                "name": "ACME",
                "inbound": {"connector": "mllp", "name": "IB-ACME", "port": 2600},
                "destinations": [
                    {"name": "OB-ACME", "connector": "mllp", "host": "10.0.0.1", "port": 6000},
                    {"name": "OB_ACME", "connector": "mllp", "host": "10.0.0.2", "port": 6001},
                ],
                "handlers": [
                    {"name": "\u5909\u63db", "actions": []},
                    {"name": "\u691c\u8a3c", "actions": []},
                ],
            },
            {
                "name": "X" * 300,
                "inbound": {"connector": "mllp", "port": 2601},
                "destinations": [
                    {"connector": "mllp", "host": "10.0.0.3", "port": 6002},
                    {"connector": "mllp", "host": "10.0.0.4", "port": 6003},
                ],
                "handlers": [{"name": "h", "actions": []}],
            },
        ],
    }
    src = tmp_path / "export.json"
    src.write_text(json.dumps(export), encoding="utf-8")
    out = tmp_path / "out"
    import_corepoint(src, out)
    registry = load_config(out)
    # The inbound name is also the file stem, so it keeps its identifier fold, as it did before.
    assert "IB_ACME" in registry.inbound
    assert {"OB-ACME", "OB_ACME"} <= set(registry.outbound)
    assert len(registry.outbound) == 4
    assert all(connection_names.is_connection_name(n) for n in registry.outbound)
    assert all(connection_names.is_connection_name(n) for n in registry.inbound)


def test_a_corepoint_xml_package_with_a_long_name_still_loads(tmp_path: Path) -> None:
    from messagefoundry.corepoint_import import parse_package

    xml = '<Package Name="' + "P" * 300 + '"><ActionList Name="t"></ActionList></Package>'
    channels = parse_package(xml)
    assert channels
    for ch in channels:
        assert connection_names.is_connection_name(ch.module_name)
