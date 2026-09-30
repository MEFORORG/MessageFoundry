# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Byte-PARITY suite for the built-in HL7 parser (ADR 0054), against a frozen python-hl7 oracle.

The built-in parser replaced python-hl7 as a behaviour-identical drop-in. This suite used to run both
backends side by side. python-hl7 has since been retired, so its answers were recorded once, over the
same corpus, into ``tests/golden/python_hl7_oracle.json``. The suite now holds the built-in parser to
that record. The corpus covers every ``samples/messages/**/*.hl7`` message, synthetic ADT/ORU/ORM from
:mod:`messagefoundry.generators`, and hand-built adversarial messages. For each it checks:

* every :class:`~messagefoundry.parsing.peek.Peek` routing property + ``routing()`` + ``segments()``;
* :meth:`Peek.field` and :meth:`Message.field` over a fixed battery of paths (whole-field, component,
  subcomponent, out-of-range, MSH-1/MSH-2, repetition fields);
* :meth:`Message.repetitions`, a plain ``encode()``, and ``encode()`` after each named mutation.

The record carries its own inputs, so a changed sample file or generator cannot silently re-aim it.
Nothing can regenerate it, by design: the ADR 0054 amendment explains why and what that costs. A
value ``{"raises": T}`` in the record means python-hl7 raised an exception of type ``T``; the built-in
must raise the same type.

It also carries the named AC tests from ADR 0054 that do not need an oracle.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
from messagefoundry.generators import _core, all_types  # noqa: F401 — registers the generators
from messagefoundry.parsing import HL7PeekError, normalize, validate
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import Peek

ORACLE = Path(__file__).resolve().parent / "golden" / "python_hl7_oracle.json"

# ---------------------------------------------------------------------------
# The battery the oracle was recorded over. The record also stores these lists, and
# test_battery_matches_the_record pins the two together, so a path added here without an oracle
# answer fails loudly instead of being skipped.
# ---------------------------------------------------------------------------

_PROBE_PATHS: list[str] = [
    # MSH offset + routing
    "MSH-1",
    "MSH-2",
    "MSH-1.1",
    "MSH-2.1",
    "MSH-2.2",  # invalid-depth on the encoding-chars leaf
    "MSH-3",
    "MSH-3.1",
    "MSH-4",
    "MSH-5",
    "MSH-6",
    "MSH-7",
    "MSH-9",
    "MSH-9.1",
    "MSH-9.2",
    "MSH-9.3",
    "MSH-9.4",  # over-index component
    "MSH-10",
    "MSH-12",
    "MSH-99",  # absent field
    "MSH-9.1.1",
    "MSH-9.1.2",  # subcomponent on a leaf
    # PID — repetitions, components, subcomponents
    "PID-1",
    "PID-3",
    "PID-3.1",
    "PID-3.1.1",
    "PID-3.4",
    "PID-3.5",
    "PID-5",
    "PID-5.1",
    "PID-5.2",
    "PID-5.3",
    "PID-5.1.1",
    "PID-5.99",  # over-index component
    "PID-5.1.99",  # over-index subcomponent
    "PID-7",
    "PID-8",
    "PID-11",
    "PID-11.1",
    "PID-11.3",
    "PID-13",
    "PID-18",
    "PID-99",
    # EVN / PV1
    "EVN-1",
    "EVN-2",
    "PV1-1",
    "PV1-2",
    "PV1-3",
    "PV1-3.1",
    "PV1-3.2",
    "PV1-7",
    "PV1-7.1",
    "PV1-7.2",
    "PV1-44",
    # order/observation
    "ORC-1",
    "ORC-2",
    "ORC-2.1",
    "ORC-3",
    "OBR-1",
    "OBR-4",
    "OBR-4.1",
    "OBR-4.2",
    "OBX-1",
    "OBX-2",
    "OBX-3",
    "OBX-3.1",
    "OBX-3.2",
    "OBX-5",
    "OBX-6",
    # other shared segments
    "NK1-2",
    "NK1-2.1",
    "AL1-3",
    "AL1-3.1",
    "DG1-3",
    "DG1-3.1",
    "IN1-3",
    "IN1-3.1",
    "IN1-4",
    # a segment that isn't there
    "ZZZ-1",
    "ZZZ-1.1",
]

REPETITION_PATHS: tuple[str, ...] = ("PID-3", "PID-3.1", "PID-5", "OBX-3", "IN1-3")

_PEEK_PROPERTIES: tuple[str, ...] = (
    "message_code",
    "trigger_event",
    "message_structure",
    "message_type",
    "control_id",
    "version",
    "sending_app",
    "sending_facility",
    "receiving_app",
    "receiving_facility",
    "timestamp",
)

#: AC-4's non-standard encoding characters: field ``#``, component ``@``, repetition ``$``,
#: subcomponent ``%``, escape ``^``.
AC4_MESSAGE = normalize(
    "MSH#@$%^#APP#FAC#RCV#RFAC#20260101##ADT@A01#C9#P#2.5.1\r"
    "PID#1##333@@@A$444@@@B##O^S^Brien@Sean#@#19800101#F\r"
)
AC4_PATHS: tuple[str, ...] = (
    "MSH-1",
    "MSH-2",
    "MSH-9",
    "MSH-9.1",
    "MSH-9.2",
    "MSH-10",
    "PID-3",
    "PID-3.1",
    "PID-5",
    "PID-5.1",
    "PID-5.2",
    "PID-8",
)

#: Odd segment lines held in a parse tree, for the whole-field-set blank-segment case (BACKLOG #1594).
BLANK_SEGMENT_LINES: tuple[tuple[str, str], ...] = (
    ("empty-line", ""),
    ("leading-field-sep", "|stray"),
    ("space", " "),
)


def _ignore(_value: object) -> None:
    return None


def _group_ops(m: Message) -> None:
    """Exercise SegmentGroup: append within the first OBR group, then rebuild its body."""
    groups = m.groups("OBR")
    if not groups:
        return  # no order groups in this message: the op is a no-op, as it was for the oracle
    g = groups[0]
    g.append_segment("NTE|1|group-note")
    g.rebuild(["OBX|1|NM|GLU^Glucose^LN|1|99|mg/dL", "NTE|1|rebuilt"])


def _mutation_ops() -> list[tuple[str, Callable[[Message], None]]]:
    """Named mutations applied to a fresh ``Message``; a missing target raises, and that is recorded."""
    return [
        ("set-whole-field", lambda m: m.set("MSH-3", "NEWAPP")),
        ("set-component", lambda m: m.set("PID-5.1", "O'Brien")),
        ("set-component-escaping", lambda m: m.set("PID-5.1", "A^B&C|D")),
        ("set-subcomponent", lambda m: m.set("PID-3.1.1", "XYZ")),
        ("set-occurrence", lambda m: m.set("OBX-5", "EDITED", occurrence=1)),
        ("set-msh10", lambda m: m.set("MSH-10", "NEWCTRL")),
        ("add-repetition", lambda m: m.add_repetition("PID-3", "999^^^Z")),
        ("add-segment-append", lambda m: m.add_segment("ZAL|1|extra^data")),
        ("add-segment-index", lambda m: m.add_segment("NTE|1|note", index=1)),
        ("delete-segments", lambda m: _ignore(m.delete_segments("OBX"))),
        ("delete-evn", lambda m: _ignore(m.delete_segments("EVN"))),
        ("group-ops", _group_ops),
    ]


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------


@cache
def _oracle() -> dict[str, Any]:
    record: dict[str, Any] = json.loads(ORACLE.read_text(encoding="utf-8"))
    return record


def _cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = _oracle()["cases"]
    return cases


def _got(fn: Callable[[], Any]) -> Any:
    """``fn``'s result, with a raised exception reduced to the record's ``{"raises": type}`` shape."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — the raise path is part of the contract
        return {"raises": type(exc).__name__}


#: Where the built-in parser deliberately answers differently from the frozen python-hl7 record,
#: keyed by (case label, accessor) and mapped to (the record's answer, the answer now required).
#: Upstream python-hl7 issue 84: its ``unescape`` dropped an escape no second escape character
#: closed, so ``SMITH\`` read as ``SMITH``. The built-in parser keeps it as data (``_builtin_hl7.
#: unescape``). The record is left as python-hl7 answered; each divergence is named here instead, and
#: the old answer is checked too, so a regenerated or edited record cannot move under this table.
DELIBERATE_DIVERGENCES: dict[tuple[str, str], tuple[Any, Any]] = {
    ("adv:trailing-escape", f"{surface}.field({path!r})"): (old, new)
    for surface in ("Peek", "Message")
    for path, old, new in (
        ("PID-5.1", "SMITH", "SMITH\\"),
        ("PID-5.1.1", "SMITH", "SMITH\\"),
        ("PID-5.2", "JO", "JO\\E"),
    )
}


def _check(
    failures: list[str], label: str, accessor: str, want: Any, fn: Callable[[], Any]
) -> None:
    divergence = DELIBERATE_DIVERGENCES.get((label, accessor))
    if divergence is not None:
        recorded, want = divergence
        assert _oracle_has(label, accessor, recorded), f"[{label}] {accessor}: record moved"
    got = _got(fn)
    if got != want:
        failures.append(f"[{label}] {accessor}: expected={want!r} builtins={got!r}")


def _oracle_has(label: str, accessor: str, value: Any) -> bool:
    """Whether the frozen record answers ``accessor`` on case ``label`` with ``value``."""
    case = next(c for c in _cases() if c["label"] == label)
    surface, _, rest = accessor.partition(".field(")
    path = rest.rstrip(")").strip("'")
    key = "peek_field" if surface == "Peek" else "message_field"
    return bool(case[key][path] == value)


def test_every_deliberate_divergence_is_exercised() -> None:
    """A divergence entry that names no real case and accessor would silently excuse nothing."""
    for label, accessor in DELIBERATE_DIVERGENCES:
        recorded, _new = DELIBERATE_DIVERGENCES[(label, accessor)]
        assert _oracle_has(label, accessor, recorded), (label, accessor)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("SMITH\\", "SMITH\\"),  # a lone trailing escape character is data (issue 84)
        ("JO\\E", "JO\\E"),  # an unterminated run is kept whole
        ("A\\.in5", "A\\.in5"),  # an unterminated counted escape expands nothing
        ("O\\S\\Brien", "O^Brien"),  # a terminated escape still unescapes
        ("x\\E\\", "x\\"),  # an escaped escape character still reads as one
        ("a\\Z9\\b", "ab"),  # an unmappable, terminated sequence is still dropped
    ],
)
def test_unterminated_escape_is_kept_as_data(value: str, expected: str) -> None:
    assert _builtin_hl7.unescape(value, ("|", "^", "~", "&", "\\")) == expected


def _peek_field(msg: str, path: str) -> Callable[[], Any]:
    return lambda: Peek.parse(msg).field(path)


def _msg_field(msg: str, path: str) -> Callable[[], Any]:
    return lambda: Message.parse(msg).field(path)


def _msg_reps(msg: str, path: str) -> Callable[[], Any]:
    return lambda: Message.parse(msg).repetitions(path)


def _peek_prop(msg: str, prop: str) -> Callable[[], Any]:
    return lambda: getattr(Peek.parse(msg), prop)


def _encode_after(msg: str, op: Callable[[Message], None]) -> Callable[[], str]:
    def run() -> str:
        m = Message.parse(msg)
        op(m)
        return m.encode()

    return run


# ---------------------------------------------------------------------------
# The record is whole and aimed at this battery
# ---------------------------------------------------------------------------


def test_battery_matches_the_record() -> None:
    """The paths and ops evaluated here are exactly the ones the oracle answered."""
    record = _oracle()
    assert record["probe_paths"] == _PROBE_PATHS
    assert record["repetition_paths"] == list(REPETITION_PATHS)
    assert record["mutation_ops"] == [name for name, _ in _mutation_ops()]
    for case in _cases():
        assert set(case["peek_props"]) == set(_PEEK_PROPERTIES), case["label"]
        assert list(case["peek_field"]) == _PROBE_PATHS, case["label"]
        assert list(case["message_field"]) == _PROBE_PATHS, case["label"]
        assert list(case["repetitions"]) == list(REPETITION_PATHS), case["label"]
        assert list(case["mutations"]) == record["mutation_ops"], case["label"]


def test_corpus_is_populated() -> None:
    """Guards an empty parametrization passing vacuously, and names the three corpus families."""
    labels = [case["label"] for case in _cases()]
    assert len(labels) >= 15, f"parity corpus unexpectedly small: {len(labels)}"
    joined = " ".join(labels)
    assert "samples/messages" in joined
    assert "gen:" in joined
    assert "adv:" in joined
    assert len(set(labels)) == len(labels), "duplicate corpus labels"


def test_the_oracle_is_not_all_one_answer() -> None:
    """A record of nothing but ``None`` would pass every comparison against a broken parser."""
    values = [v for case in _cases() for v in case["peek_field"].values()]
    assert sum(isinstance(v, str) for v in values) > 500
    assert sum(v is None for v in values) > 100
    assert any(isinstance(v, dict) for case in _cases() for v in case["mutations"].values())


# ---------------------------------------------------------------------------
# AC-1 / AC-5 — Peek, Message and mutate→encode parity over the corpus
# ---------------------------------------------------------------------------


def _case_ids() -> list[str]:
    return [case["label"] for case in _cases()]


@pytest.mark.parametrize("index", range(len(_cases())), ids=_case_ids())
def test_builtin_parity_over_corpus(index: int) -> None:
    """AC-1 — every Peek property + ``Peek.field``/``Message.field`` path matches the oracle."""
    case = _cases()[index]
    label, msg = case["label"], case["input"]
    failures: list[str] = []
    for prop, want in case["peek_props"].items():
        _check(failures, label, f"Peek.{prop}", want, _peek_prop(msg, prop))
    _check(failures, label, "Peek.routing()", case["routing"], lambda: Peek.parse(msg).routing())
    _check(failures, label, "Peek.segments()", case["segments"], lambda: Peek.parse(msg).segments())
    for path, want in case["peek_field"].items():
        _check(failures, label, f"Peek.field({path!r})", want, _peek_field(msg, path))
    for path, want in case["message_field"].items():
        _check(failures, label, f"Message.field({path!r})", want, _msg_field(msg, path))
    for path, want in case["repetitions"].items():
        _check(failures, label, f"Message.repetitions({path!r})", want, _msg_reps(msg, path))
    _check(failures, label, "Message.encode()", case["encode"], lambda: Message.parse(msg).encode())
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("index", range(len(_cases())), ids=_case_ids())
def test_encode_roundtrip_parity(index: int) -> None:
    """AC-5 — read → mutate (set/add_repetition/add_segment/delete/group) → encode matches the oracle."""
    case = _cases()[index]
    ops = dict(_mutation_ops())
    failures: list[str] = []
    for name, want in case["mutations"].items():
        _check(failures, case["label"], f"op={name}", want, _encode_after(case["input"], ops[name]))
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# AC-2 — whole-field vs component semantics + whole-value-no-component
# ---------------------------------------------------------------------------


def test_whole_field_vs_component_semantics() -> None:
    """AC-2 — whole-field returns structural text; a component on a separator-less field is the whole value."""
    msg = normalize(
        "MSH|^~\\&|A|B|C|D|20260604||ADT^A01|M|P|2.5.1\r"
        "ORC|RE|PLACER123\r"
        "PID|1||111^^^A~222^^^B||DOE^JANE^Q\r"
    )
    cases = [
        ("ORC-2", "PLACER123"),  # whole field, no component sep
        ("ORC-2.1", "PLACER123"),  # whole-value-no-component rule (not "P")
        ("ORC-2.2", None),  # no 2nd component
        ("PID-3", "111^^^A~222^^^B"),  # whole field keeps repetition delimiters
        ("PID-3.1", "111"),  # first repetition's first component
        ("PID-5.1", "DOE"),
        ("PID-5.2", "JANE"),
    ]
    peek = Peek.parse(msg)
    failures = [
        f"Peek.field({path!r}): got={peek.field(path)!r} expected-doc={want!r}"
        for path, want in cases
        if peek.field(path) != want
    ]
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# AC-3 — tolerant parse + no-MSH/empty error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "\r\r",
        "PID|1|no msh here\r",
        "not an hl7 message at all",
    ],
    ids=["empty", "blank", "blank-cr", "no-msh", "garbage"],
)
def test_tolerant_and_no_msh(bad: str) -> None:
    """AC-3 — empty/no-MSH/unparseable raises ``HL7PeekError``; odd-but-parseable parses."""
    with pytest.raises(HL7PeekError):
        Peek.parse(bad)

    # Odd-but-structurally-parseable: inconsistent field counts, extra separators, missing CR.
    odd = normalize("MSH|^~\\&|A|B||||ADT^A01|M|P|2.5.1\rPID|1|||||extra|||sep||||~~~\rOBX|1|NM")
    peek = Peek.parse(odd)
    assert peek.message_type == "M"  # MSH-8 holds ADT^A01 here: the sender skipped a field
    assert peek.segments() == ["MSH", "PID", "OBX"]


@pytest.mark.parametrize(
    ("label", "line"), BLANK_SEGMENT_LINES, ids=[x for x, _ in BLANK_SEGMENT_LINES]
)
@pytest.mark.parametrize("touch_first", [False, True], ids=["lazy", "split"])
def test_whole_field_set_over_a_tree_held_blank_segment(
    label: str, line: str, touch_first: bool
) -> None:
    """The built-in's blank-segment raise still matches python-hl7 exactly (BACKLOG #1594).

    ``Message.parse`` and ``Peek.parse`` drop empty lines, so the corpus no longer reaches
    ``raise_if_blank_segment_scan`` with one. A ``Message`` built straight from a parse tree still
    can. Only a truly empty line raises on a whole-field set; a line that merely starts with the field
    separator does not. ``touch_first`` splits the odd segment first, so the scan takes its post-split
    branch rather than the lazy one.
    """
    text = f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|C6|P|2.5.1\r{line}\rPID|1||444\r"

    def run() -> str:
        msg = Message(_builtin_hl7.parse(text))
        if touch_first:
            msg.field("PID-3", occurrence=1)
            msg.repetitions("MSH-9")
            _builtin_hl7._ensure_split(msg._m, 1)
        msg.set("MSH-10", "EDITED")
        return msg.encode()

    key = f"{label}/{'split' if touch_first else 'lazy'}"
    want = _oracle()["blank_segment_set"][key]
    assert _got(run) == want, f"[{key}] python-hl7={want!r}"
    assert (want == {"raises": "IndexError"}) is (label == "empty-line")


# ---------------------------------------------------------------------------
# AC-4 — custom encoding characters read from MSH-1/MSH-2
# ---------------------------------------------------------------------------


def test_custom_encoding_chars() -> None:
    """AC-4 — separators are read from MSH-1/MSH-2 (non-standard ``#@$%^``), never hardcoded."""
    record = _oracle()["custom_encoding_chars"]
    assert record["input"] == AC4_MESSAGE
    failures: list[str] = []
    for path in AC4_PATHS:
        _check(
            failures,
            "ac4",
            f"Peek.field({path!r})",
            record["peek_field"][path],
            _peek_field(AC4_MESSAGE, path),
        )
        _check(
            failures,
            "ac4",
            f"Message.field({path!r})",
            record["message_field"][path],
            _msg_field(AC4_MESSAGE, path),
        )
    assert Peek.parse(AC4_MESSAGE).field("MSH-1") == "#"
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# AC-7 — strict path unchanged (hl7apy)
# ---------------------------------------------------------------------------


def test_strict_path_unchanged() -> None:
    """AC-7 — ``validate()`` builds an hl7apy tree, independent of the tolerant tier."""
    msg = _core.generate_message("ADT", "A01", 1)
    result = validate(msg, expected_version="2.5.1")
    assert result.ok, f"strict validation failed: {result.errors}"
    assert bool(result) == result.ok  # frozen ValidationResult.__bool__ == ok
    assert result.version == "2.5.1"
    mismatch = validate(msg, expected_version="2.3")
    assert not mismatch.ok
    assert mismatch.errors


# ---------------------------------------------------------------------------
# AC-6 — free-threaded scaling (cp314t) — stub, skipped off a free-threaded build
# ---------------------------------------------------------------------------


def _is_freethreaded() -> bool:
    getter = getattr(sys, "_is_gil_enabled", None)
    if getter is None:
        return False
    try:
        return not getter()
    except Exception:  # noqa: BLE001 — be conservative if the probe misbehaves
        return False


@pytest.mark.skipif(
    not _is_freethreaded(),
    reason="AC-6 scaling re-measure runs only on a free-threaded (cp314t) build (ADR 0054)",
)
def test_freethread_scaling() -> None:  # pragma: no cover - cp314t-only stub
    """AC-6 — ≥6× multi-core / ~14× single-thread on cp314t (WS3/ADR 0052 harness).

    A placeholder gate: the authoritative scaling re-measure is the ADR 0053 spike harness on the
    bench box. Here we only assert the build is genuinely free-threaded.
    """
    assert _is_freethreaded()
