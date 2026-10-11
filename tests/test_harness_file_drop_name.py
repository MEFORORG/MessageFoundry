# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness file drop builds its name from untrusted input, and must never write outside its
directory (ASVS 5.3.2).

The Compose tab and the File tab's drop worker name each drop after the message's own MSH-10. That
value is whatever the operator pasted, and ``Peek`` returns it raw, so ``../../tmp/x`` once became a
path joined onto the drop directory unreduced. :func:`drop_name` reduces it, as the engine's File
destination reduces a rendered name, and :func:`drop_atomic` refuses any name that is not one file
name inside the directory. Qt-free, so it runs where PySide6 cannot.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from harness.drivers import file as file_driver
from harness.drivers.file import (
    FALLBACK_STEM,
    MAX_DROP_NAME_BYTES,
    drop_atomic,
    drop_name,
)
from messagefoundry.parsing import Peek
from messagefoundry.transports import file as engine_file


def _only_child(directory: Path) -> Path:
    children = list(directory.iterdir())
    assert len(children) == 1, children
    return children[0]


def test_the_reduction_matches_the_engine_file_destination() -> None:
    # Duplicated because a harness module may not import transports/; pinned here so the copies
    # cannot drift apart.
    assert file_driver._UNSAFE.pattern == engine_file._UNSAFE.pattern
    assert MAX_DROP_NAME_BYTES == engine_file.FILENAME_MAX_BYTES


@pytest.mark.parametrize(
    ("stem", "expected"),
    [
        ("MEFORADTA0100001", "MEFORADTA0100001.hl7"),
        ("../x", "_x.hl7"),
        ("../../tmp/x", "_.._tmp_x.hl7"),
        ("/etc/passwd", "_etc_passwd.hl7"),
        ("C:\\Windows\\x", "C__Windows_x.hl7"),
        ("..\\..\\x", "_.._x.hl7"),
        ("a\x00b", "a_b.hl7"),
        ("", f"{FALLBACK_STEM}.hl7"),
        (".", f"{FALLBACK_STEM}.hl7"),
        ("..", f"{FALLBACK_STEM}.hl7"),
        ("...", f"{FALLBACK_STEM}.hl7"),
        (" . ", f"{FALLBACK_STEM}.hl7"),
        (".hidden", "hidden.hl7"),
        ("NUL", f"{FALLBACK_STEM}.hl7"),
        ("con", f"{FALLBACK_STEM}.hl7"),
        ("x" * 300, f"{FALLBACK_STEM}.hl7"),
    ],
)
def test_drop_name_is_one_safe_component(stem: str, expected: str) -> None:
    name = drop_name(stem)
    assert name == expected
    assert os.sep not in name and "/" not in name and "\\" not in name and "\x00" not in name
    assert len(name.encode("utf-8")) <= MAX_DROP_NAME_BYTES


def test_drop_name_keeps_a_name_exactly_at_the_byte_cap() -> None:
    stem = "x" * (MAX_DROP_NAME_BYTES - len(".hl7"))
    assert drop_name(stem) == stem + ".hl7"
    assert drop_name(stem + "x") == f"{FALLBACK_STEM}.hl7"


@pytest.mark.parametrize(
    "name",
    [
        "../escaped.hl7",
        "../../tmp/x.hl7",
        "sub/x.hl7",
        "..\\x.hl7",
        "",
        ".",
        "..",
        "a\x00b.hl7",
        ".. ",
        "...",
        "x.",
        # Windows device and stream names, refused even when the caller skipped drop_name.
        "CON",
        "con.hl7",
        "COM1.hl7",
        "NUL .hl7",
        "CONIN$",
        "x.hl7:stream",
        "C:x.hl7",
        "x*.hl7",
    ],
)
def test_drop_atomic_refuses_a_name_that_is_not_one_file_name(tmp_path: Path, name: str) -> None:
    inner = tmp_path / "inner"
    inner.mkdir()
    with pytest.raises(OSError, match="not a single file name"):
        drop_atomic(inner, name, b"data")
    # Nothing written anywhere: not in the directory (no stray temp either), not beside it.
    assert list(inner.iterdir()) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["inner"]


def test_drop_atomic_refuses_an_absolute_path(tmp_path: Path) -> None:
    inner = tmp_path / "inner"
    inner.mkdir()
    outside = tmp_path / "outside.hl7"
    with pytest.raises(OSError, match="not a single file name"):
        drop_atomic(inner, str(outside), b"data")
    assert not outside.exists()
    assert list(inner.iterdir()) == []


def test_the_traversal_that_used_to_escape_now_lands_inside(tmp_path: Path) -> None:
    # The reported defect: drop_atomic(<dir>/inner, "../escaped.hl7", ...) wrote beside <dir>/inner.
    inner = tmp_path / "inner"
    inner.mkdir()
    target = drop_atomic(inner, drop_name("../escaped"), b"data")
    assert target.parent == inner
    assert target.read_bytes() == b"data"
    assert not (tmp_path / "escaped.hl7").exists()


def test_a_compose_message_with_a_traversal_msh10_drops_inside_the_directory(
    tmp_path: Path,
) -> None:
    # The Compose path end to end, short of Qt: Peek returns MSH-10 raw, the drop worker names the
    # file with drop_name, and drop_atomic writes it.
    raw = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|../../tmp/x|P|2.5.1\rEVN|A01|20260101\r"
    control_id = Peek.parse(raw).control_id
    assert control_id == "../../tmp/x"  # the raw, untrusted value the defect joined unreduced
    inner = tmp_path / "drop" / "inner"
    inner.mkdir(parents=True)
    target = drop_atomic(inner, drop_name(control_id or ""), raw.encode("utf-8"))
    assert _only_child(inner) == target
    assert target.name == "_.._tmp_x.hl7"
    assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == ["_.._tmp_x.hl7"]


def test_a_second_drop_of_the_same_reduced_name_does_not_clobber(tmp_path: Path) -> None:
    first = drop_atomic(tmp_path, drop_name("../x"), b"1")
    second = drop_atomic(tmp_path, drop_name("../x"), b"2")
    assert first != second and first.parent == second.parent == tmp_path
    assert (first.read_bytes(), second.read_bytes()) == (b"1", b"2")


@pytest.mark.parametrize(
    "name",
    ["CONSOLE.hl7", "COM10.hl7", "nul-x.hl7", "AUXILIARY.hl7", "file with spaces.hl7", "a.b.hl7"],
)
def test_drop_atomic_accepts_an_ordinary_name_beside_a_reserved_one(
    tmp_path: Path, name: str
) -> None:
    # The device and stream refusal must not refuse everything: names that only look like a device,
    # or carry spaces and inner dots, are ordinary file names and land in the directory.
    target = drop_atomic(tmp_path, name, b"data")
    assert target == tmp_path / name
    assert target.read_bytes() == b"data"
