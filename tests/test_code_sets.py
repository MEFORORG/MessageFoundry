# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Code sets: managed, hot-reloadable reference lookup tables for the message graph.

Covers the loaders (CSV scalar/dict, TOML flat/nested, duplicate/missing/malformed), the frozen
:class:`CodeSet`, and end-to-end resolution through ``load_config`` (module-import time) and
``dry_run`` (call time inside a handler), plus a reload swapping to an edited table.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.code_sets import (
    CodeSet,
    CodeSetError,
    activated,
    code_set,
    load_code_set,
    load_code_sets,
)
from messagefoundry.config.wiring import WiringError, load_config, validate_config
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.store import MessageStatus

_MSG = "MSH|^~\\&|SND|ACME|RCV|DST|20260101||ADT^A01|MSG1|P|2.5.1\rEVN|A01|20260101\r"


# --- loaders -----------------------------------------------------------------


def test_csv_two_columns_maps_to_scalar(tmp_path: Path) -> None:
    p = tmp_path / "diet.csv"
    p.write_text("code,value\nA,Apple\nB,Banana\n", encoding="utf-8")
    cs = load_code_set(p)
    assert cs.name == "diet"
    assert cs["A"] == "Apple" and cs["B"] == "Banana"
    assert dict(cs) == {"A": "Apple", "B": "Banana"}


def test_csv_multi_columns_maps_to_dict(tmp_path: Path) -> None:
    p = tmp_path / "facility.csv"
    p.write_text("code,name,mnemonic\nACME,Acme Hospital,ACMEHOSP\n", encoding="utf-8")
    cs = load_code_set(p)
    assert cs["ACME"] == {"name": "Acme Hospital", "mnemonic": "ACMEHOSP"}


def test_csv_duplicate_key_is_error(tmp_path: Path) -> None:
    p = tmp_path / "dup.csv"
    p.write_text("code,value\nA,1\nA,2\n", encoding="utf-8")
    with pytest.raises(CodeSetError, match="duplicate key 'A'"):
        load_code_set(p)


def test_csv_needs_value_column(tmp_path: Path) -> None:
    p = tmp_path / "keyonly.csv"
    p.write_text("code\nA\nB\n", encoding="utf-8")
    with pytest.raises(CodeSetError, match="value column"):
        load_code_set(p)


def test_toml_flat_table(tmp_path: Path) -> None:
    p = tmp_path / "fac.toml"
    p.write_text('ACME = "ACMEHOSP"\nZGEN = "GENERAL"\n', encoding="utf-8")
    cs = load_code_set(p)
    assert cs["ACME"] == "ACMEHOSP" and cs["ZGEN"] == "GENERAL"


def test_toml_nested_table(tmp_path: Path) -> None:
    p = tmp_path / "nested.toml"
    p.write_text('[ACME]\nname = "Acme"\nmnemonic = "ACMEHOSP"\n', encoding="utf-8")
    cs = load_code_set(p)
    assert cs["ACME"] == {"name": "Acme", "mnemonic": "ACMEHOSP"}


def test_malformed_toml_is_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.toml"
    p.write_text("this is = = not toml\n", encoding="utf-8")
    with pytest.raises(CodeSetError, match="bad.toml"):
        load_code_set(p)


def test_unknown_extension_is_error(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(CodeSetError, match="unsupported extension"):
        load_code_set(p)


def test_load_code_sets_missing_dir_is_empty(tmp_path: Path) -> None:
    assert load_code_sets(tmp_path / "nope") == {}


def test_load_code_sets_name_clash_across_extensions(tmp_path: Path) -> None:
    d = tmp_path / "codesets"
    d.mkdir()
    (d / "diet.csv").write_text("code,value\nA,1\n", encoding="utf-8")
    (d / "diet.toml").write_text('A = "1"\n', encoding="utf-8")
    with pytest.raises(CodeSetError, match="duplicate code set name 'diet'"):
        load_code_sets(d)


def test_load_code_sets_ignores_other_files(tmp_path: Path) -> None:
    d = tmp_path / "codesets"
    d.mkdir()
    (d / "diet.csv").write_text("code,value\nA,1\n", encoding="utf-8")
    (d / "README.md").write_text("not a code set\n", encoding="utf-8")
    sets = load_code_sets(d)
    assert set(sets) == {"diet"}


# --- frozen CodeSet ----------------------------------------------------------


def test_codeset_is_frozen() -> None:
    cs = CodeSet("t", {"A": "1"})
    with pytest.raises(TypeError):
        cs["B"] = "2"  # type: ignore[index]


def test_codeset_get_and_missing_key() -> None:
    cs = CodeSet("epic_diets", {"A": "1"})
    assert cs.get("A") == "1"
    assert cs.get("Z", "default") == "default"
    assert "A" in cs and "Z" not in cs
    assert len(cs) == 1
    with pytest.raises(KeyError, match="epic_diets"):
        _ = cs["Z"]


# --- accessor + active-set holder --------------------------------------------


def test_code_set_no_active_set_is_error() -> None:
    with pytest.raises(CodeSetError, match="no active code sets"):
        code_set("anything")


def test_activated_publishes_and_restores() -> None:
    cs = CodeSet("t", {"A": "1"})
    with activated({"t": cs}):
        assert code_set("t") is cs
    # restored: outside the block there is no active set again
    with pytest.raises(CodeSetError):
        code_set("t")


def test_code_set_missing_name_lists_available() -> None:
    with activated({"a": CodeSet("a", {}), "b": CodeSet("b", {})}):
        with pytest.raises(CodeSetError, match="available: a, b"):
            code_set("c")


# --- end-to-end through load_config ------------------------------------------


def _cfg(tmp_path: Path, body: str) -> Path:
    (tmp_path / "cfg.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


def test_import_time_resolution_through_load_config(tmp_path: Path) -> None:
    cs_dir = tmp_path / "codesets"
    cs_dir.mkdir()
    (cs_dir / "events.csv").write_text("code,value\nA01,admit\n", encoding="utf-8")
    _cfg(
        tmp_path,
        """
        from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, code_set

        EVENTS = code_set("events")  # resolved at module import time

        inbound("in", MLLP(port=2575), router="r")
        outbound("out", File(directory="./out"))

        @router("r")
        def route(msg):
            return ["h"]

        @handler("h")
        def handle(msg):
            return Send("out", msg)
        """,
    )
    reg = load_config(tmp_path)
    assert set(reg.code_sets) == {"events"}
    assert reg.code_sets["events"]["A01"] == "admit"


def test_missing_code_set_at_import_is_wiringerror(tmp_path: Path) -> None:
    _cfg(
        tmp_path,
        """
        from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, code_set
        MISSING = code_set("nope")
        inbound("in", MLLP(port=2575), router="r")
        outbound("out", File(directory="./out"))

        @router("r")
        def route(msg):
            return []
        """,
    )
    with pytest.raises(WiringError, match="no such code set 'nope'"):
        load_config(tmp_path)


def test_malformed_code_set_blocks_load(tmp_path: Path) -> None:
    cs_dir = tmp_path / "codesets"
    cs_dir.mkdir()
    (cs_dir / "bad.csv").write_text("code,value\nA,1\nA,2\n", encoding="utf-8")  # dup key
    _cfg(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("in", MLLP(port=2575), router="r")
        @router("r")
        def route(msg):
            return []
        """,
    )
    with pytest.raises(WiringError, match="duplicate key"):
        load_config(tmp_path)


def test_validate_config_reports_bad_code_set(tmp_path: Path) -> None:
    cs_dir = tmp_path / "codesets"
    cs_dir.mkdir()
    (cs_dir / "bad.csv").write_text("code,value\nA,1\nA,2\n", encoding="utf-8")
    _cfg(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("in", MLLP(port=2575), router="r")
        @router("r")
        def route(msg):
            return []
        """,
    )
    diags = validate_config(tmp_path)
    assert any("duplicate key" in d.message for d in diags)


def test_call_time_resolution_in_dry_run(tmp_path: Path) -> None:
    cs_dir = tmp_path / "codesets"
    cs_dir.mkdir()
    (cs_dir / "fac.toml").write_text('ACME = "ACMEHOSP"\n', encoding="utf-8")
    _cfg(
        tmp_path,
        """
        from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, code_set

        inbound("in", MLLP(port=2575), router="r")
        outbound("out", File(directory="./out"))

        @router("r")
        def route(msg):
            return ["h"]

        @handler("h")
        def handle(msg):
            # call-time lookup (not captured at import) — must resolve during the dry-run
            msg["MSH-4"] = code_set("fac").get(msg["MSH-4"], msg["MSH-4"])
            return Send("out", msg)
        """,
    )
    reg = load_config(tmp_path)
    result = dry_run(reg, _MSG, inbound="in")
    assert result.disposition == MessageStatus.RECEIVED
    assert result.deliveries and "ACMEHOSP" in result.deliveries[0].payload


def test_reload_swaps_to_edited_code_set(tmp_path: Path) -> None:
    cs_dir = tmp_path / "codesets"
    cs_dir.mkdir()
    table = cs_dir / "fac.toml"
    table.write_text('ACME = "FIRST"\n', encoding="utf-8")
    _cfg(
        tmp_path,
        """
        from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, code_set

        inbound("in", MLLP(port=2575), router="r")
        outbound("out", File(directory="./out"))

        @router("r")
        def route(msg):
            return ["h"]

        @handler("h")
        def handle(msg):
            msg["MSH-4"] = code_set("fac").get(msg["MSH-4"], msg["MSH-4"])
            return Send("out", msg)
        """,
    )
    reg1 = load_config(tmp_path)
    assert "FIRST" in dry_run(reg1, _MSG, inbound="in").deliveries[0].payload

    # Edit the table and reload (a fresh load_config = the reload's loader path).
    table.write_text('ACME = "SECOND"\n', encoding="utf-8")
    reg2 = load_config(tmp_path)
    out2 = dry_run(reg2, _MSG, inbound="in").deliveries[0].payload
    assert "SECOND" in out2 and "FIRST" not in out2
