# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Transform-vocabulary parameter schema (drives the Steps-view input widgets, ADR 0076 §5).

Derivation (op -> params with kind/choices/required/keyword_only) from the action + diagnostic
signatures, plus the ``lens schema`` CLI smoke test."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.lens_schema import op_param_schema

# The IDE renderer tests consume a CANNED dump of this schema (the CI ide job has no Python, so those
# tests never shell the CLI). It must stay faithful to the live derivation, or a signature change would
# silently outdate the fixture and the IDE tests would validate against a stale contract.
_IDE_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "ide"
    / "src"
    / "test"
    / "fixtures"
    / "lens-schema"
    / "op-schema.json"
)


def _param(op: str, name: str) -> dict:
    params = {p["name"]: p for p in op_param_schema()[op]}
    return params[name]


def test_msg_is_dropped() -> None:
    # The leading `msg` the Handler threads through is never an editable input — it is dropped, so
    # set_field surfaces exactly its two editable string params in signature order.
    assert op_param_schema()["set_field"] == [
        {"name": "path", "kind": "str", "required": True, "keyword_only": False},
        {"name": "value", "kind": "str", "required": True, "keyword_only": False},
    ]
    names = [p["name"] for op in op_param_schema().values() for p in op]
    assert "msg" not in names


def test_int_and_default_optionality() -> None:
    # substring_field(msg, path, start, end=None): start is a required int; end is an int slot that is
    # nullable + optional because it carries a default (None).
    start = _param("substring_field", "start")
    assert start["kind"] == "int" and start["required"] is True

    end = _param("substring_field", "end")
    assert end["kind"] == "int"
    assert end["required"] is False  # has a default -> optional
    assert end.get("nullable") is True


def test_keyword_only_flagged() -> None:
    # pad_field(msg, path, width, *, fill="0", side="left"): fill/side are keyword-only optionals;
    # width is a required positional.
    fill = _param("pad_field", "fill")
    side = _param("pad_field", "side")
    width = _param("pad_field", "width")
    assert fill["keyword_only"] is True and fill["required"] is False
    assert side["keyword_only"] is True and side["required"] is False
    assert width["keyword_only"] is False and width["required"] is True


def test_diagnostics_covered() -> None:
    # The diagnostic ops (log_note/checkpoint) ride the SAME schema so their Steps forms are
    # schema-driven too (not a separate hand-rolled table). log_note's positional-only `template` is a
    # str param; its `*values` varargs are recognized-only and never surface as an editable input.
    schema = op_param_schema()
    assert schema["log_note"] == [
        {"name": "template", "kind": "str", "required": True, "keyword_only": False},
    ]
    label = _param("checkpoint", "label")
    assert label["kind"] == "str" and label["required"] is False
    assert label.get("default") == ""


def test_non_json_default_omitted() -> None:
    # code_lookup(msg, path, table, *, default=_UNSET): `default`'s sentinel is a bare object and
    # `table` is a mapping — neither is a JSON scalar, so no `default` key is emitted and json.dumps of
    # the whole schema never raises. `table` maps to the code-set hint.
    default = _param("code_lookup", "default")
    assert "default" not in default
    assert _param("code_lookup", "table")["kind"] == "codeset"
    json.dumps(op_param_schema())  # must not raise on any sentinel default


def test_cli_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lens", "schema", "--json"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert "set_field" in schema
    assert schema["set_field"][0]["name"] == "path"


def test_ide_fixture_in_sync() -> None:
    # The committed IDE test fixture must equal the live derivation (structure only — formatting is
    # irrelevant since both are compared as parsed JSON). A signature change that outdates it fails here
    # instead of silently narrowing the IDE renderer tests. To fix a failure, regenerate:
    #   python -m messagefoundry lens schema > ide/src/test/fixtures/lens-schema/op-schema.json
    committed = json.loads(_IDE_FIXTURE.read_text(encoding="utf-8"))
    assert committed == op_param_schema(), (
        "ide/src/test/fixtures/lens-schema/op-schema.json is stale — regenerate: "
        "python -m messagefoundry lens schema > ide/src/test/fixtures/lens-schema/op-schema.json"
    )


def test_closed_set_param_becomes_enum() -> None:
    # OQ1: the four closed-set args are typed Literal[...], so the schema emits kind 'enum' with the
    # choice list -- the IDE renders a dropdown, not a text input (the item's headline widget). The
    # runtime ValueError guards still stand for a dynamically-supplied bad value (two-layer, actions.py).
    assert _param("convert_case", "mode") == {
        "name": "mode",
        "kind": "enum",
        "required": True,
        "keyword_only": False,
        "choices": ["upper", "lower", "title"],
    }
    assert _param("arith_field", "op")["choices"] == ["+", "-", "*", "/"]
    unit = _param("date_diff_field", "unit")
    assert unit["kind"] == "enum" and unit["choices"] == ["days", "years", "hours", "minutes"]
    assert unit["default"] == "days" and unit["required"] is False
    assert _param("pad_field", "side")["choices"] == ["left", "right"]
