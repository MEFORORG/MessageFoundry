# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The config loader refuses a connection name the operator API would refuse (BACKLOG #1107).

Why the loader must hold the API's rule is in :mod:`messagefoundry.connection_names`. These tests
pin the refusal on both authoring surfaces, and pin the two layers to ONE pattern.
"""

from __future__ import annotations

import json
import re
import textwrap
import typing
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry import connection_names
from messagefoundry.api import validation
from messagefoundry.config import impact, wiring
from messagefoundry.config.connections_edit import upsert_connection
from messagefoundry.config.impact import RENAMEABLE_KINDS, plan_rename
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry_toolkit.corepoint_import import import_corepoint
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
    # vars(): wiring imports the name rather than re-exporting it, which strict mypy refuses.
    assert vars(wiring)["CONNECTION_NAME_PATTERN"] is connection_names.CONNECTION_NAME_PATTERN
    # The ceiling the importer budgets against is the one written in the pattern.
    assert f"{{0,{connection_names.CONNECTION_NAME_MAX_LENGTH - 1}}}" in (
        connection_names.CONNECTION_NAME_PATTERN
    )
    # And the pydantic type the API routes use is built from that same string.
    constraint = typing.get_args(validation.ConnectionName)[1]  # Annotated[str, <constraint>]
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


def test_an_inbound_record_name_reads_back() -> None:
    record = connection_names.inbound_record_name("IB_A")
    assert connection_names.inbound_name_of(record) == "IB_A"
    assert connection_names.inbound_name_of("IB_A") is None
    assert connection_names.inbound_name_of(connection_names.fhir_lookup_record_name("F")) is None


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
    from messagefoundry_toolkit.corepoint_import import parse_package

    xml = '<Package Name="' + "P" * 300 + '"><ActionList Name="t"></ActionList></Package>'
    channels = parse_package(xml)
    assert channels
    for ch in channels:
        assert connection_names.is_connection_name(ch.module_name)


def _two_inbounds(tmp_path: Path, first: str, second: str, outbound_name: str = "OB") -> Path:
    body = LOGIC_PY + textwrap.dedent(
        f"""
        from messagefoundry import File, MLLP, inbound, outbound
        inbound({first!r}, MLLP(port=2600), router="r")
        inbound({second!r}, MLLP(port=2601), router="r")
        outbound({outbound_name!r}, File(directory="./out"))
        """
    )
    (tmp_path / "logic.py").write_text(body, encoding="utf-8")
    return tmp_path


def test_names_differing_only_in_case_are_refused_at_load(tmp_path: Path) -> None:
    # BACKLOG #5392: a case-insensitive SQL Server collation would give the two one set of rows.
    with pytest.raises(WiringError, match="differs only in case") as info:
        load_config(_two_inbounds(tmp_path, "IB_ACME_ADT", "ib_acme_adt"))
    assert "'ib_acme_adt'" in str(info.value)
    assert "'IB_ACME_ADT'" in str(info.value)


def test_distinct_names_and_a_case_twin_in_another_table_still_load(tmp_path: Path) -> None:
    # The control: two names that differ by more than case load, and the check is per table, as the
    # exact-duplicate check is, so an outbound may share an inbound's name up to case.
    registry = load_config(_two_inbounds(tmp_path, "IB_ACME_ADT", "IB_ACME_ORU", "ib_acme_adt"))
    assert set(registry.inbound) == {"IB_ACME_ADT", "IB_ACME_ORU"}
    assert set(registry.outbound) == {"ib_acme_adt"}


def test_every_record_namespace_has_one_helper() -> None:
    assert connection_names.db_lookup_record_name("L") == "db_lookup:L"
    assert connection_names.reference_record_name("R") == "reference:R"
    # No engine module hand-spells a namespace prefix the helpers own (BACKLOG #5392).
    root = Path(connection_names.__file__).parent
    # A string literal, either quote, f-string or not, that opens with a prefix and goes on to a
    # placeholder or ends there to be concatenated. An error message such as "db_lookup: no ..." is
    # prose, not a record name.
    spelled_re = re.compile(
        r"""(?<!\w)[rRbBuU]?[fF]?[rR]?(["'])(?:db_lookup|reference|inbound|fhir_lookup):(?:\{|\1)"""
    )
    # The positive controls: the pattern finds a hand-spelled prefix in each quote and f-string
    # form, and passes the prose an error message carries.
    assert spelled_re.search('f"db_lookup:{x}"')
    assert spelled_re.search("'reference:' + name")
    assert not spelled_re.search('"db_lookup: no such connection"')
    # The walk must see the engine package, or a moved root would pass on nothing. The package held
    # 337 modules besides connection_names.py when this floor was set.
    files = [path for path in root.rglob("*.py") if path.name != "connection_names.py"]
    assert len(files) >= 300
    spelled = [
        f"{path.relative_to(root)}: {match.group(0)}"
        for path in files
        for match in spelled_re.finditer(path.read_text(encoding="utf-8"))
    ]
    assert spelled == []


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_a_case_twin_across_toml_and_code_is_refused(tmp_path: Path, direction: str) -> None:
    config = _toml(tmp_path, "IB_ACME", "OB_ACME")
    call = (
        'inbound("ib_acme", MLLP(port=2700), router="r")'
        if direction == "inbound"
        else 'outbound("ob_acme", File(directory="./out2"))'
    )
    (config / "twin.py").write_text(
        f"from messagefoundry import File, MLLP, inbound, outbound\n{call}\n", encoding="utf-8"
    )
    with pytest.raises(WiringError, match=f"duplicate {direction} connection name.*differs only"):
        load_config(config)


def test_a_rename_onto_a_case_twin_is_refused_at_plan_time(tmp_path: Path) -> None:
    config = _two_inbounds(tmp_path, "IB_ACME_ADT", "IB_ACME_ORU")
    registry = load_config(config)
    with pytest.raises(WiringError, match="differs only in case"):
        plan_rename(registry, config, "inbound", "IB_ACME_ORU", "ib_acme_adt")
    # The control: a rename to its own case variant is not a twin of another connection.
    plan_rename(registry, config, "inbound", "IB_ACME_ORU", "ib_acme_oru")


_REFERENCE_CALL = (
    'Reference("{name}", source=DatabaseRef(server="db.example.org", database="d", '
    'statement="SELECT code FROM t", key_column="code"))'
)
_LOOKUP_CALL = 'DatabaseLookup("{name}", server="db.example.org", database="d")'
_FHIR_CALL = 'FhirLookup("{name}", url="https://fhir.example.org/fhir")'


def _lookups(tmp_path: Path, *names: str, module: str = "lookups.py") -> Path:
    """A config declaring a FhirLookup, a DatabaseLookup and a reference set under each name."""
    lines = ["from messagefoundry import DatabaseLookup, DatabaseRef, FhirLookup, Reference"]
    for name in names:
        lines += [call.format(name=name) for call in (_FHIR_CALL, _LOOKUP_CALL, _REFERENCE_CALL)]
    (tmp_path / module).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("call", "kind"),
    [
        (_FHIR_CALL, "fhir lookup"),
        (_LOOKUP_CALL, "database lookup"),
        (_REFERENCE_CALL, "reference set"),
    ],
    ids=["fhir_lookup", "lookup", "reference"],
)
def test_a_lookup_or_reference_case_twin_is_refused_at_load(
    tmp_path: Path, call: str, kind: str
) -> None:
    # BACKLOG #5392: the twin check covered only inbound, outbound and FHIR lookup names.
    _lookups(tmp_path, "EPIC")
    (tmp_path / "twin.py").write_text(
        "from messagefoundry import DatabaseLookup, DatabaseRef, FhirLookup, Reference\n"
        + call.format(name="epic")
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match=f"duplicate {kind} name: 'epic' differs only in case"):
        load_config(tmp_path, allow_empty=True)


def test_one_name_in_each_lookup_kind_still_loads(tmp_path: Path) -> None:
    # The control: the check is per table, so one name may be a FHIR lookup, a database lookup and
    # a reference set at once, and two names differing by more than case load.
    registry = load_config(_lookups(tmp_path, "EPIC", "EPIC2"), allow_empty=True)
    assert set(registry.fhir_lookups) == set(registry.lookups) == set(registry.references)
    assert set(registry.lookups) == {"EPIC", "EPIC2"}


@pytest.mark.parametrize("kind", ["fhir_lookup", "lookup", "reference"])
def test_a_lookup_rename_onto_a_case_twin_is_refused_at_plan_time(
    tmp_path: Path, kind: str
) -> None:
    # BACKLOG #5392: plan_rename refused a twin only for inbound and outbound names.
    config = _lookups(tmp_path, "EPIC", "CLAR")
    registry = load_config(config, allow_empty=True)
    with pytest.raises(WiringError, match="differs only in case"):
        plan_rename(registry, config, kind, "CLAR", "epic")
    # The control: a rename to its own case variant is not a twin of another name.
    plan_rename(registry, config, kind, "CLAR", "clar")


def test_every_twin_table_pairs_a_rename_kind_with_its_own_registry_table() -> None:
    registry = wiring.Registry()
    for rename_kind, attribute, _label in wiring.CASE_TWIN_TABLES:
        assert rename_kind in RENAMEABLE_KINDS
        # The table plan_rename checks is the one graph_problems checks, not merely a table.
        assert getattr(registry, attribute) is impact._table(registry, rename_kind)


@pytest.mark.parametrize(
    ("first", "second"),
    [("EPIC", "EPIC "), ("EPIC", "\uff25\uff30\uff29\uff23")],  # a trailing space; full width
    ids=["trailing_space", "full_width"],
)
def test_a_reference_twin_by_width_or_trailing_space_is_refused(
    tmp_path: Path, first: str, second: str
) -> None:
    # A reference set name is not bound by the name rule, and SQL Server's `=` ignores a trailing
    # space and a _CI_AS collation ignores width, so casefold alone would let these load.
    (tmp_path / "refs.py").write_text(
        "from messagefoundry import DatabaseRef, Reference\n"
        + "\n".join(_REFERENCE_CALL.format(name=name) for name in (first, second))
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="duplicate reference set name: .*differs only in case"):
        load_config(tmp_path, allow_empty=True)


def test_the_twin_fold_keeps_a_no_break_space_and_a_superscript_apart(tmp_path: Path) -> None:
    # The fold adds width and trailing U+0020 to casefold, and no more: a no-break space and a
    # superscript are compared as written, as SQL Server's `=` compares them. This test does not
    # show the fold keeps apart everything SQL Server keeps apart. casefold folds further than a
    # SQL Server collation may, at least the long s, the Kelvin sign and the sharp s (to s, k and
    # ss), so a name beside such a twin can be refused that the store would keep apart. That
    # over-refusal fails closed.
    names = ("EPIC", "EPIC\u00a0", "x2", "x\u00b2")
    (tmp_path / "refs.py").write_text(
        "from messagefoundry import DatabaseRef, Reference\n"
        + "\n".join(_REFERENCE_CALL.format(name=name) for name in names)
        + "\n",
        encoding="utf-8",
    )
    assert set(load_config(tmp_path, allow_empty=True).references) == set(names)


def test_a_name_that_is_not_a_string_does_not_crash_the_twin_check() -> None:
    assert list(wiring.case_twins([123, "123", "A", "a"])) == [("A", "a")]  # type: ignore[list-item]
