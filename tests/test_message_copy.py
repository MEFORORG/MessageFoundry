# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``Message.copy()`` / ``RawMessage.copy()`` — the ADR 0104 structural-clone primitive.

Verifies AC-2 (``copy().encode() == source.encode()`` over an escaping / repetition /
custom-separator / trailing-whitespace / Z-segment corpus, including a tree that holds a blank
segment) and AC-3 (the structural clone is **not** ``parse(encode())``).
"""

from __future__ import annotations

import pytest

import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
from messagefoundry.parsing.message import Message, RawMessage, snapshot_payload

_STD = (
    "MSH|^~\\&|SENDA|SENDF|RECV|RFAC|20200101||ADT^A01^ADT_A01|MSG1|P|2.5\r"
    "PID|1||123^^^A~456^^^B||DOE^JANE\r"
    "OBX|1|ST|X^Y||some text\r"
)


def _std() -> Message:
    return Message.parse(_STD)


def _trailing_ws_terminal() -> Message:
    m = Message.parse(_STD)
    m.set("OBX-5", "trailing value ")  # trailing space in the terminal field
    return m


def _appended_ws_segment() -> Message:
    m = Message.parse(_STD)
    m.add_segment("ZAL|note with trailing space ")
    return m


def _custom_separators() -> Message:
    # MSH-2 uses '@' as the component separator (not '^'); copy must not assume the defaults.
    return Message.parse(
        "MSH|@~\\&|A|B|C|D|20200101||ADT@A01@ADT_A01|MSG1|P|2.5\rPID|1||9@@@AUTH\r"
    )


def _escaped_component() -> Message:
    m = Message.parse(_STD)
    m.set(
        "PID-5.1", "O^BRIEN"
    )  # a caret in a component is escaped (\S\) — must round-trip on clone
    return m


def _z_segment() -> Message:
    m = Message.parse(_STD)
    m.add_segment("ZAL|1|custom^data")
    return m


_CORPUS = {
    "std": _std,
    "trailing_ws_terminal": _trailing_ws_terminal,
    "appended_ws_segment": _appended_ws_segment,
    "custom_separators": _custom_separators,
    "escaped_component": _escaped_component,
    "z_segment": _z_segment,
}


@pytest.mark.parametrize("name", list(_CORPUS))
def test_structural_clone_encode_parity(name: str) -> None:
    """AC-2: the clone encodes byte-identically to the source, and mutating the clone
    leaves the source's bytes unchanged (true independence)."""
    src = _CORPUS[name]()
    clone = src.copy()
    assert clone.encode() == src.encode(), f"{name}: clone lost bytes"
    before = src.encode()
    clone.set("MSH-3", "MUTATED")
    assert src.encode() == before, f"{name}: mutating the clone changed the source"
    assert clone.field("MSH-3") == "MUTATED"


def test_copy_is_not_parse_encode(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-3: ``copy()`` is a structural clone, not ``Message.parse(self.encode())`` — it must succeed
    even if ``Message.parse`` would raise."""
    src = _std()

    def _boom(cls, raw):
        raise AssertionError("copy() must not call Message.parse")

    monkeypatch.setattr(Message, "parse", classmethod(_boom))
    clone = src.copy()
    assert clone.encode() == src.encode()


def test_tree_held_blank_segment_clones_faithfully() -> None:
    """AC-2/AC-3: a tree built without :meth:`Message.parse` keeps a blank segment line, which
    ``parse(encode())`` would drop. The structural clone keeps it.

    This replaced a test of a python-hl7 fallback-parsed source, the other case ``parse(encode())``
    got wrong; the fallback retired with python-hl7 (ADR 0054 amendment)."""
    src = Message(_builtin_hl7.parse(_STD.replace("\rOBX", "\r\rOBX")))
    clone = src.copy()
    assert "\r\r" in src.encode()
    assert clone.encode() == src.encode()
    assert "\r\r" not in Message.parse(src.encode()).encode()


def test_rawmessage_copy_recaptures() -> None:
    """A ``RawMessage`` snapshot re-captures its ``raw`` into a fresh instance; the original is unaffected
    by a later mutation of the snapshot's source attribute."""
    rm = RawMessage("original", "json")
    snap = rm.copy()
    assert snap is not rm and snap.raw == "original" and snap.content_type == "json"
    rm.raw = "mutated"
    assert snap.raw == "original"


def test_snapshot_payload_dispatch() -> None:
    """``snapshot_payload`` clones a Message/RawMessage but returns a ``str`` unchanged (by identity)."""
    m = _std()
    assert snapshot_payload(m) is not m and isinstance(snapshot_payload(m), Message)
    rm = RawMessage("x", "text")
    assert snapshot_payload(rm) is not rm and isinstance(snapshot_payload(rm), RawMessage)
    s = "literal"
    assert snapshot_payload(s) is s
