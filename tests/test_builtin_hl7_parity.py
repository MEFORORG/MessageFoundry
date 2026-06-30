# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Byte-PARITY suite for the built-ins HL7 parser (ADR 0054).

This is the parity guarantee that makes ``_builtin_hl7`` a safe drop-in for ``python-hl7`` on the
tolerant peek tier. For a broad corpus (every ``samples/messages/**/*.hl7`` plus synthetic ADT/ORU/ORM
output from :mod:`messagefoundry.generators`) it asserts the **built-ins backend** and the
**python-hl7 backend** return *byte-identical* results for:

* every :class:`~messagefoundry.parsing.peek.Peek` routing property + ``routing()`` + ``segments()``;
* :meth:`Peek.field` over a generated set of field paths (whole-field, component, subcomponent,
  out-of-range, MSH-1/MSH-2, repetition fields);
* :class:`~messagefoundry.parsing.message.Message` read → mutate
  (``set`` / ``add_repetition`` / ``add_segment`` / ``delete_segments`` / group ops) → ``encode()``
  round-trips.

The two backends are toggled with :func:`messagefoundry.parsing._backend.backend` (read per-parse, so a
single process drives both). The suite **measures** parity — it does **not** fix the parser; a divergence
is reported as a failure carrying ``(input, accessor, expected-python-hl7, got-builtins)``.

It also carries the named AC-1..AC-7 tests from ADR 0054 (``test_builtin_parity_over_corpus``,
``test_whole_field_vs_component_semantics``, ``test_tolerant_and_no_msh``, ``test_custom_encoding_chars``,
``test_encode_roundtrip_parity``, ``test_strict_path_unchanged``, plus the AC-6 cp314t scaling stub).
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.parsing._backend as _backend
from messagefoundry.generators import _core, all_types  # noqa: F401 — registers the generators
from messagefoundry.parsing import HL7PeekError, normalize, validate
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import Peek

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "messages"


# ---------------------------------------------------------------------------
# Backend toggling
# ---------------------------------------------------------------------------


def _under_backend(builtin: bool, fn: Callable[[], Any]) -> Any:
    """Run ``fn`` with the parser backend forced to built-ins (``True``) or python-hl7 (``False``)."""
    with _backend.backend(builtin=builtin):
        return fn()


def _both(fn: Callable[[], Any]) -> tuple[Any, Any]:
    """Run ``fn`` under each backend, capturing a raised exception as a value for comparison.

    Returns ``(python_hl7_result, builtins_result)``; an exception is returned (not raised) so the
    caller can assert both backends agree on *raising* (same type) as well as on values. The result
    is typed ``Any``; the call sites build their thunks via the ``_peek_field``/``_msg_field``/… closure
    factories (rather than default-arg lambdas) so mypy can type them.
    """

    def _capture(builtin: bool) -> Any:
        try:
            return _under_backend(builtin, fn)
        except Exception as exc:  # noqa: BLE001 — parity over the raise path too
            return exc

    return _capture(False), _capture(True)


def _eq(expected: Any, got: Any) -> bool:
    """Parity equality: values compare ``==``; exceptions compare by **type** (message text differs)."""
    if isinstance(expected, Exception) or isinstance(got, Exception):
        return type(expected) is type(got)
    return bool(expected == got)


def _peek_field(msg: str, path: str) -> Callable[[], Any]:
    """A no-arg thunk reading ``Peek.parse(msg).field(path)`` — avoids default-arg lambdas (mypy)."""
    return lambda: Peek.parse(msg).field(path)


def _msg_field(msg: str, path: str) -> Callable[[], Any]:
    return lambda: Message.parse(msg).field(path)


def _msg_reps(msg: str, path: str) -> Callable[[], Any]:
    return lambda: Message.parse(msg).repetitions(path)


def _peek_prop(msg: str, prop: str) -> Callable[[], Any]:
    return lambda: getattr(Peek.parse(msg), prop)


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


def _split_messages(raw: str) -> list[str]:
    """Split a (possibly batch) HL7 file into individual ``\\r``-delimited messages on MSH boundaries."""
    norm = normalize(raw)
    lines = norm.split("\r")
    messages: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.startswith("MSH") and current:
            messages.append("\r".join(current) + "\r")
            current = [line]
        else:
            current.append(line)
    tail = [ln for ln in current if ln.strip()]
    if tail:
        messages.append("\r".join(tail) + "\r")
    return [m for m in messages if m.strip()]


def _sample_corpus() -> list[tuple[str, str]]:
    """``(label, message)`` for every individual message under ``samples/messages/**/*.hl7``.

    Batch files (multiple MSH) are split into their constituent messages so each parity unit is one
    message; the whole-file form is also kept (label ``…[file]``) to exercise the multi-MSH parse.
    """
    out: list[tuple[str, str]] = []
    for path in sorted(SAMPLES.rglob("*.hl7")):
        raw = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        parts = _split_messages(raw)
        if len(parts) > 1:
            out.append((f"{rel}[file]", normalize(raw)))
            for i, msg in enumerate(parts, start=1):
                out.append((f"{rel}[msg{i}]", msg))
        elif parts:
            out.append((rel, parts[0]))
    return out


# Synthetic generator coverage: ADT/ORU/ORM across several triggers — repetitions (PID-3 lists,
# repeating OBX/IN1/DG1), components, subcomponents, escapes, empty fields, multi-segment groups.
_SYNTH_PLAN: list[tuple[str, str, int]] = [
    ("ADT", "A01", 1),  # full PID/PV1/NK1/AL1/DG1/IN1 — repetitions + components
    ("ADT", "A01", 2),
    ("ADT", "A02", 1),
    ("ADT", "A03", 1),
    ("ADT", "A04", 1),
    ("ADT", "A08", 1),
    ("ADT", "A40", 1),  # merge — extra PID block
    ("ORU", "R01", 1),  # OBR/OBX observation groups
    ("ORU", "R01", 2),
    ("ORU", "R30", 1),
    ("ORM", "O01", 1),  # ORC/OBR order groups
    ("ORM", "O01", 2),
]


def _synthetic_corpus() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for code, trigger, index in _SYNTH_PLAN:
        if code not in _core.message_codes():
            continue
        if trigger not in _core.triggers_for(code):
            continue
        msg = _core.generate_message(code, trigger, index)
        out.append((f"gen:{code}^{trigger}#{index}", normalize(msg)))
    return out


# Hand-built adversarial messages: escapes, custom encoding chars, empty fields/segments, missing CR.
_ESCAPED = (
    "MSH|^~\\&|APP|FAC|RCV|RFAC|20260101||ADT^A01^ADT_A01|C1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||111^^^A~222^^^B||O\\S\\Brien^Se\\T\\an^\\F\\mid||19700101|M|||"
    "1\\X0A\\Main^^City^ST^00000\r"
    "PV1|1|I\r"
)
_CUSTOM_SEPS = (
    "MSH#@$%^|APP#FAC#RCV#RFAC#20260101##ADT@A01#C2#P#2.5.1\r"
    "PID#1##333@@@A||O$S$Brien@Sean#@#19800101#F\r"
)
_EMPTY_FIELDS = (
    "MSH|^~\\&|||||20260101||ADT^A01|C3|P|2.5.1\r"
    "EVN\r"
    "PID|1||||||\r"
    "\r"  # blank segment
    "PV1|1\r"
)
_NO_TRAILING_CR = (
    "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|C4|P|2.5.1\rOBR|1\rOBX|1|NM|GLU^Glucose^LN|1|99|mg/dL"
)

_ADVERSARIAL: list[tuple[str, str]] = [
    ("adv:escapes", normalize(_ESCAPED)),
    ("adv:custom-seps", normalize(_CUSTOM_SEPS)),
    ("adv:empty-fields", normalize(_EMPTY_FIELDS)),
    ("adv:no-trailing-cr", normalize(_NO_TRAILING_CR)),
]


def _corpus() -> list[tuple[str, str]]:
    return _sample_corpus() + _synthetic_corpus() + _ADVERSARIAL


CORPUS = _corpus()
CORPUS_IDS = [label for label, _ in CORPUS]


# ---------------------------------------------------------------------------
# Field-path generation
# ---------------------------------------------------------------------------

# A fixed battery of paths that exercise whole-field / component / subcomponent / out-of-range /
# MSH-offset / repetition access across the segment ids the corpus actually uses.
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


# ---------------------------------------------------------------------------
# AC-1 — Peek/field parity over the corpus
# ---------------------------------------------------------------------------


def _peek_property_names() -> list[str]:
    return [
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
    ]


def _peek_divergences(label: str, msg: str) -> list[str]:
    """Every (accessor, expected, got) divergence between the two backends for one message."""
    failures: list[str] = []

    # Routing properties.
    for prop in _peek_property_names():
        expected, got = _both(_peek_prop(msg, prop))
        if not _eq(expected, got):
            failures.append(f"[{label}] Peek.{prop}: python-hl7={expected!r} builtins={got!r}")

    # routing() dict + segments() list.
    exp_routing, got_routing = _both(lambda: Peek.parse(msg).routing())
    if not _eq(exp_routing, got_routing):
        failures.append(
            f"[{label}] Peek.routing(): python-hl7={exp_routing!r} builtins={got_routing!r}"
        )
    exp_segs, got_segs = _both(lambda: Peek.parse(msg).segments())
    if not _eq(exp_segs, got_segs):
        failures.append(f"[{label}] Peek.segments(): python-hl7={exp_segs!r} builtins={got_segs!r}")

    # Peek.field over the probe battery.
    for path in _PROBE_PATHS:
        expected, got = _both(_peek_field(msg, path))
        if not _eq(expected, got):
            failures.append(
                f"[{label}] Peek.field({path!r}): python-hl7={expected!r} builtins={got!r}"
            )

    # Message.field parity (it has its own extract path distinct from Peek's).
    for path in _PROBE_PATHS:
        expected, got = _both(_msg_field(msg, path))
        if not _eq(expected, got):
            failures.append(
                f"[{label}] Message.field({path!r}): python-hl7={expected!r} builtins={got!r}"
            )

    # Message.repetitions parity for the repeating fields.
    for path in ("PID-3", "PID-3.1", "PID-5", "OBX-3", "IN1-3"):
        expected, got = _both(_msg_reps(msg, path))
        if not _eq(expected, got):
            failures.append(
                f"[{label}] Message.repetitions({path!r}): python-hl7={expected!r} builtins={got!r}"
            )

    # encode() round-trip (no mutation) parity.
    expected, got = _both(lambda: Message.parse(msg).encode())
    if not _eq(expected, got):
        failures.append(f"[{label}] Message.encode(): python-hl7={expected!r} builtins={got!r}")

    return failures


@pytest.mark.parametrize(("label", "msg"), CORPUS, ids=CORPUS_IDS)
def test_builtin_parity_over_corpus(label: str, msg: str) -> None:
    """AC-1 — every Peek property + ``Peek.field``/``Message.field`` path is bit-identical across backends."""
    failures = _peek_divergences(label, msg)
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
    failures: list[str] = []
    for path, want in cases:
        expected, got = _both(_peek_field(msg, path))
        # both backends must agree AND match the documented value
        if not _eq(expected, got):
            failures.append(f"Peek.field({path!r}): python-hl7={expected!r} builtins={got!r}")
        if got != want:
            failures.append(f"Peek.field({path!r}): builtins={got!r} expected-doc={want!r}")
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# AC-3 — tolerant parse + no-MSH/empty error parity
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
    """AC-3 — empty/no-MSH/unparseable raises ``HL7PeekError`` on both backends; odd-but-parseable parses."""
    exp, got = _both(lambda: Peek.parse(bad))
    assert isinstance(exp, HL7PeekError), f"python-hl7 should raise HL7PeekError, got {exp!r}"
    assert isinstance(got, HL7PeekError), f"builtins should raise HL7PeekError, got {got!r}"

    # Odd-but-structurally-parseable: inconsistent field counts, extra separators, missing CR — both parse.
    odd = normalize("MSH|^~\\&|A|B||||ADT^A01|M|P|2.5.1\rPID|1|||||extra|||sep||||~~~\rOBX|1|NM")
    exp_ok, got_ok = _both(lambda: Peek.parse(odd).message_type)
    assert not isinstance(exp_ok, Exception), f"python-hl7 raised on odd-but-parseable: {exp_ok!r}"
    assert not isinstance(got_ok, Exception), f"builtins raised on odd-but-parseable: {got_ok!r}"
    assert _eq(exp_ok, got_ok), f"odd message_type: python-hl7={exp_ok!r} builtins={got_ok!r}"


# ---------------------------------------------------------------------------
# AC-4 — custom encoding characters read from MSH-1/MSH-2
# ---------------------------------------------------------------------------


def test_custom_encoding_chars() -> None:
    """AC-4 — separators are read from MSH-1/MSH-2 (non-standard ``#@$%^``), never hardcoded; parity holds."""
    # field=#, component=@, repetition=$, subcomponent=%, escape=^
    msg = normalize(
        "MSH#@$%^#APP#FAC#RCV#RFAC#20260101##ADT@A01#C9#P#2.5.1\r"
        "PID#1##333@@@A$444@@@B##O^S^Brien@Sean#@#19800101#F\r"
    )
    paths = [
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
    ]
    failures: list[str] = []
    for path in paths:
        expected, got = _both(_peek_field(msg, path))
        if not _eq(expected, got):
            failures.append(f"Peek.field({path!r}): python-hl7={expected!r} builtins={got!r}")
        expected_m, got_m = _both(_msg_field(msg, path))
        if not _eq(expected_m, got_m):
            failures.append(
                f"Message.field({path!r}): python-hl7={expected_m!r} builtins={got_m!r}"
            )
    # Sanity: the custom separators actually parsed (MSH-1 is '#', MSH-2 is the enc chars).
    f_sep, _ = _both(lambda: Peek.parse(msg).field("MSH-1"))
    assert f_sep == "#", f"custom field separator not read from MSH-1: {f_sep!r}"
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# AC-5 — mutate → encode round-trip parity
# ---------------------------------------------------------------------------


def _mutation_ops() -> list[tuple[str, Callable[[Message], None]]]:
    """Named mutations applied identically to a fresh ``Message`` on each backend (defensive: a missing
    target segment raises identically on both, captured by ``_both``)."""
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


def _ignore(_value: object) -> None:
    return None


def _group_ops(m: Message) -> None:
    """Exercise SegmentGroup: append within the first OBR group, then rebuild its body."""
    groups = m.groups("OBR")
    if not groups:
        # No order groups in this message — make the op a no-op (parity must still hold: both skip).
        return
    g = groups[0]
    g.append_segment("NTE|1|group-note")
    g.rebuild(["OBX|1|NM|GLU^Glucose^LN|1|99|mg/dL", "NTE|1|rebuilt"])


def _encode_after(msg: str, op: Callable[[Message], None], builtin: bool) -> str | Exception:
    def run() -> str:
        m = Message.parse(msg)
        op(m)
        return m.encode()

    try:
        result: str = _under_backend(builtin, run)
        return result
    except Exception as exc:  # noqa: BLE001 — capture raise-path for parity
        return exc


# A focused corpus for the (heavier) mutate→encode matrix: the samples + the synthetic set.
_MUTATE_CORPUS = _sample_corpus() + _synthetic_corpus() + _ADVERSARIAL
_MUTATE_IDS = [label for label, _ in _MUTATE_CORPUS]


@pytest.mark.parametrize(("label", "msg"), _MUTATE_CORPUS, ids=_MUTATE_IDS)
def test_encode_roundtrip_parity(label: str, msg: str) -> None:
    """AC-5 — read → mutate (set/add_repetition/add_segment/delete/group) → encode is byte-identical."""
    failures: list[str] = []
    for op_name, op in _mutation_ops():
        expected = _encode_after(msg, op, builtin=False)
        got = _encode_after(msg, op, builtin=True)
        if not _eq(expected, got):
            failures.append(f"[{label}] op={op_name}: python-hl7={expected!r} builtins={got!r}")
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# AC-7 — strict path unchanged (hl7apy, backend-independent)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("builtin", [False, True], ids=["python-hl7", "builtins"])
def test_strict_path_unchanged(builtin: bool) -> None:
    """AC-7 — ``validate()`` builds an hl7apy tree and is unaffected by the tolerant-tier backend flag."""
    msg = _core.generate_message("ADT", "A01", 1)
    with _backend.backend(builtin=builtin):
        result = validate(msg, expected_version="2.5.1")
    assert result.ok, f"strict validation failed under builtin={builtin}: {result.errors}"
    assert bool(result) == result.ok  # frozen ValidationResult.__bool__ == ok
    assert result.version == "2.5.1"
    # A version mismatch is still reported (cross-check unaffected by the flag).
    with _backend.backend(builtin=builtin):
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

    This is a placeholder gate: the authoritative scaling re-measure is the ADR 0053 spike harness on
    the 265KF box (``…\\Temp\\mefor-ft``). Here we only assert the build is genuinely free-threaded so a
    future run can hang the throughput numbers off this node; the full benchmark lives outside the unit
    suite (``tests/test_benchmark_parser.py`` per the ADR).
    """
    assert _is_freethreaded()


# ---------------------------------------------------------------------------
# Sanity: the corpus is non-trivial (guards an empty parametrization passing vacuously)
# ---------------------------------------------------------------------------


def test_corpus_is_populated() -> None:
    assert len(CORPUS) >= 15, f"parity corpus unexpectedly small: {len(CORPUS)}"
    # at least one sample, one synthetic, one adversarial
    labels = " ".join(CORPUS_IDS)
    assert "samples/messages" in labels
    assert "gen:" in labels
    assert "adv:" in labels
