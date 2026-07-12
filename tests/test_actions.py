# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The typed action vocabulary (ADR 0076 phase 1): behavior + purity (gate 5)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

import messagefoundry.actions as actions_mod
import messagefoundry.lens as lens_mod
from messagefoundry import (
    append_to_field,
    code_lookup,
    convert_case,
    copy_field,
    copy_segment,
    delete_segment,
    format_date,
    set_field,
    split_field,
)
from messagefoundry.config.code_sets import CodeSet
from messagefoundry.parsing.message import Message

ADT = (
    "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101120000||ADT^A01^ADT_A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^HOSP^MR||doe^jane^q||19800101|F\r"
    "NK1|1|SMITH^JOHN\r"
)


def _msg() -> Message:
    return Message.parse(ADT)


# --- behavior ----------------------------------------------------------------


def test_copy_field_copies_value() -> None:
    m = _msg()
    copy_field(m, "PID-5.1", "NK1-2.1")
    assert m["NK1-2.1"] == "doe"
    assert m["NK1-2.2"] == "JOHN"  # sibling component preserved


def test_copy_field_absent_source_clears_dest() -> None:
    m = _msg()
    copy_field(m, "PID-99.1", "NK1-2.1")  # PID-99 absent
    assert m["NK1-2.1"] is None


def test_set_field() -> None:
    m = _msg()
    set_field(m, "PID-3.1", "999")
    assert m["PID-3.1"] == "999"


def test_append_to_field() -> None:
    m = _msg()
    append_to_field(m, "PID-5.1", "-JR")
    assert m["PID-5.1"] == "doe-JR"


def test_append_to_absent_field_is_just_suffix() -> None:
    m = _msg()
    append_to_field(m, "NK1-3.1", "X")
    assert m["NK1-3.1"] == "X"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("upper", "DOE"), ("lower", "doe"), ("title", "Doe")],
)
def test_convert_case(mode: str, expected: str) -> None:
    m = _msg()
    convert_case(m, "PID-5.1", mode)
    assert m["PID-5.1"] == expected


def test_convert_case_absent_is_noop() -> None:
    m = _msg()
    convert_case(m, "NK1-9.1", "upper")  # absent -> no-op, no raise
    assert m["NK1-9.1"] is None


def test_convert_case_unknown_mode_raises() -> None:
    m = _msg()
    with pytest.raises(ValueError, match="convert_case mode"):
        convert_case(m, "PID-5.1", "sentence")


def test_format_date_hl7_default() -> None:
    m = _msg()
    format_date(m, "PID-7", "%Y-%m-%d")  # 19800101 (HL7 TS) -> reformatted
    assert m["PID-7"] == "1980-01-01"


def test_format_date_with_input_format() -> None:
    m = _msg()
    set_field(m, "PID-6", "01/15/2026")
    format_date(m, "PID-6", "%Y%m%d", in_fmt="%m/%d/%Y")
    assert m["PID-6"] == "20260115"


def test_format_date_absent_is_noop() -> None:
    m = _msg()
    format_date(m, "NK1-4", "%Y")
    assert m["NK1-4"] is None


def test_format_date_malformed_raises() -> None:
    m = _msg()
    set_field(m, "PID-6", "not-a-date")
    with pytest.raises(ValueError):
        format_date(m, "PID-6", "%Y")


def test_split_field() -> None:
    m = _msg()
    set_field(m, "PID-2", "AAA_BBB")
    split_field(m, "PID-2", "_", ["PID-2", "PID-4"])
    assert m["PID-2"] == "AAA"
    assert m["PID-4"] == "BBB"


def test_split_field_fewer_parts_clears_trailing() -> None:
    m = _msg()
    set_field(m, "PID-2", "ONLYONE")
    split_field(m, "PID-2", "_", ["PID-2", "PID-4"])
    assert m["PID-2"] == "ONLYONE"
    assert m["PID-4"] is None  # trailing dest cleared


def test_code_lookup_hit_with_dict() -> None:
    m = _msg()
    code_lookup(m, "PID-8", {"F": "Female", "M": "Male"})
    assert m["PID-8"] == "Female"


def test_code_lookup_hit_with_codeset() -> None:
    m = _msg()
    table = CodeSet("gender", {"F": "Female", "M": "Male"})  # a CodeSet is a Mapping — stays pure
    code_lookup(m, "PID-8", table)
    assert m["PID-8"] == "Female"


def test_code_lookup_miss_with_default() -> None:
    m = _msg()
    code_lookup(m, "PID-8", {"M": "Male"}, default="Unknown")
    assert m["PID-8"] == "Unknown"


def test_code_lookup_miss_no_default_leaves_unchanged() -> None:
    m = _msg()
    code_lookup(m, "PID-8", {"M": "Male"})
    assert m["PID-8"] == "F"  # untouched


def test_copy_segment_appends_duplicate() -> None:
    m = _msg()
    assert m.count_segments("NK1") == 1
    copy_segment(m, "NK1")
    assert m.count_segments("NK1") == 2
    assert m.field("NK1-2.1", occurrence=2) == "SMITH"  # the copy carries the same content


def test_copy_segment_at_index() -> None:
    m = _msg()
    copy_segment(m, "NK1", index=1)  # insert just after MSH
    assert m.segments() == ["MSH", "NK1", "EVN", "PID", "NK1"]


def test_copy_segment_absent_raises() -> None:
    m = _msg()
    with pytest.raises(KeyError, match="ZZZ"):
        copy_segment(m, "ZZZ")


def test_delete_segment_returns_count() -> None:
    m = _msg()
    copy_segment(m, "NK1")  # now two
    removed = delete_segment(m, "NK1")
    assert removed == 2
    assert m.count_segments("NK1") == 0


def test_vocabulary_mutates_in_place_and_reencodes() -> None:
    m = _msg()
    set_field(m, "PID-3.1", "555")
    again = Message.parse(m.encode())
    assert again["PID-3.1"] == "555"  # the edit survives a round-trip


# --- purity + no-new-dependency (ADR 0076 §6 gate 5) -------------------------


def _top_level_imports(path: str) -> set[str]:
    """The top-level package name of every import in a module's source (AST — no execution)."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    return mods


# I/O-capable modules the pure vocabulary must never import (proves helpers do no I/O).
_IO_MODULES = frozenset(
    {
        "os",
        "io",
        "socket",
        "subprocess",
        "http",
        "urllib",
        "sqlite3",
        "asyncio",
        "selectors",
        "shutil",
        "tempfile",
        "requests",
        "aiohttp",
        "aiosqlite",
        "pyodbc",
        "aioodbc",
        "ssl",
        "smtplib",
        "ftplib",
    }
)


def test_actions_imports_nothing_doing_io() -> None:
    imports = _top_level_imports(actions_mod.__file__)
    offenders = imports & _IO_MODULES
    assert not offenders, f"actions.py must do no I/O; forbidden imports: {sorted(offenders)}"


def test_actions_and_lens_add_no_runtime_dependency() -> None:
    # Every import must be stdlib or first-party — no new third-party dependency (stdlib `ast` only).
    for mod in (actions_mod, lens_mod):
        for top in _top_level_imports(mod.__file__):
            assert top in sys.stdlib_module_names or top == "messagefoundry", (
                f"{Path(mod.__file__).name} imports non-stdlib, non-first-party {top!r} "
                "(would add a runtime dependency)"
            )
