# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A row a code set hands out cannot alter the shared table (BACKLOG #5897).

One ``CodeSet`` instance serves every message until reload, so a Handler that mutated a multi-column
CSV row or a nested TOML table returned by ``translate``/``[]``/``get`` used to change the answer for
every later message, breaking re-run determinism. Rows are now frozen at construction. Synthetic
data only."""

from __future__ import annotations

import copy
import json
import pickle
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.code_sets import CodeSet, parse_code_set

_CSV = b"code,display,system\nM,Male,HL7\nF,Female,HL7\n"
_TOML = b'[A]\nlabel = "Alpha"\ntags = ["x", "y"]\n[A.inner]\nlevel = 1\n'


def _csv_set() -> CodeSet:
    return parse_code_set("sex.csv", _CSV)


def _toml_set() -> CodeSet:
    return parse_code_set("nested.toml", _TOML)


_DICT_MUTATIONS: list[Callable[[Any], object]] = [
    lambda row: row.__setitem__("display", "Changed"),
    lambda row: row.__delitem__("display"),
    lambda row: row.update(display="Changed"),
    lambda row: row.pop("display"),
    lambda row: row.popitem(),
    lambda row: row.setdefault("extra", "v"),
    lambda row: row.clear(),
    lambda row: row.__ior__({"display": "Changed"}),
]


@pytest.mark.parametrize("mutate", _DICT_MUTATIONS)
@pytest.mark.parametrize("lookup", ["translate", "getitem", "get"])
def test_a_csv_row_refuses_mutation_and_the_table_is_unchanged(
    lookup: str, mutate: Callable[[Any], object]
) -> None:
    cs = _csv_set()
    row = {"translate": cs.translate, "getitem": cs.__getitem__, "get": cs.get}[lookup]("M")
    with pytest.raises(TypeError, match="read-only"):
        mutate(row)
    assert cs["M"] == {"display": "Male", "system": "HL7"}


def test_nested_toml_tables_and_arrays_refuse_mutation() -> None:
    cs = _toml_set()
    with pytest.raises(TypeError):
        cs["A"]["inner"]["level"] = 2
    for mutate in (
        lambda tags: tags.append("z"),
        lambda tags: tags.__setitem__(0, "z"),
        lambda tags: tags.extend(["z"]),
        lambda tags: tags.__iadd__(["z"]),
        lambda tags: tags.sort(),
        lambda tags: tags.clear(),
    ):
        with pytest.raises(TypeError):
            mutate(cs["A"]["tags"])
    assert cs["A"] == {"label": "Alpha", "tags": ["x", "y"], "inner": {"level": 1}}


def test_a_frozen_row_still_reads_like_the_plain_value() -> None:
    cs = _toml_set()
    row = cs["A"]
    assert isinstance(row, dict) and isinstance(row["tags"], list)
    assert json.loads(json.dumps(row)) == {
        "label": "Alpha",
        "tags": ["x", "y"],
        "inner": {"level": 1},
    }


@pytest.mark.parametrize(
    "make_copy",
    [dict, lambda r: r.copy(), copy.copy, copy.deepcopy, lambda r: pickle.loads(pickle.dumps(r))],
)
def test_a_copy_of_a_row_is_mutable_and_leaves_the_table_alone(
    make_copy: Callable[[Any], Any],
) -> None:
    cs = _csv_set()
    mine = make_copy(cs["F"])
    mine["display"] = "Changed"
    assert cs["F"]["display"] == "Female"


def test_a_deep_copy_unfreezes_nested_values() -> None:
    mine = copy.deepcopy(_toml_set()["A"])
    mine["tags"].append("z")
    mine["inner"]["level"] = 2
    assert mine["tags"] == ["x", "y", "z"]


def test_the_caller_mapping_passed_to_the_constructor_is_not_shared() -> None:
    source = {"K": {"a": "1"}}
    cs = CodeSet("direct", source)
    source["K"]["a"] = "2"
    assert cs["K"] == {"a": "1"}
