# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Freeze python-hl7's answers over the ADR 0054 parity corpus into a golden file.

The parity suite compared the built-in parser against python-hl7 at run time. python-hl7 is being
retired, so its answers are recorded once, here, and the suite compares against the record instead.

This script runs ONLY while the engine still carries its python-hl7 backend (``parsing._backend``).
It is committed so the pull request that retires the dependency shows how the record was made, and
that pull request deletes it. The record is then a frozen oracle: nothing can regenerate it.

    python scripts/dev/freeze_python_hl7_oracle.py
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

import hl7  # noqa: E402

import messagefoundry.parsing._backend as _backend  # noqa: E402
from messagefoundry.generators import (  # noqa: E402, F401 — registers the generators
    _core,
    all_types,
)
from messagefoundry.parsing import normalize  # noqa: E402
from messagefoundry.parsing.message import Message  # noqa: E402
from messagefoundry.parsing.peek import Peek  # noqa: E402
from tests import test_builtin_hl7_parity as parity  # noqa: E402

OUT = REPO / "tests" / "golden" / "python_hl7_oracle.json"
SAMPLES = REPO / "samples" / "messages"

# --- the corpus, exactly as the side-by-side suite built it ---------------------------------------


def _split_messages(raw: str) -> list[str]:
    """Split a (possibly batch) HL7 file into individual ``\\r``-delimited messages on MSH boundaries."""
    lines = normalize(raw).split("\r")
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
    out: list[tuple[str, str]] = []
    for path in sorted(SAMPLES.rglob("*.hl7")):
        raw = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO).as_posix()
        parts = _split_messages(raw)
        if len(parts) > 1:
            out.append((f"{rel}[file]", normalize(raw)))
            for i, msg in enumerate(parts, start=1):
                out.append((f"{rel}[msg{i}]", msg))
        elif parts:
            out.append((rel, parts[0]))
    return out


_SYNTH_PLAN: list[tuple[str, str, int]] = [
    ("ADT", "A01", 1),
    ("ADT", "A01", 2),
    ("ADT", "A02", 1),
    ("ADT", "A03", 1),
    ("ADT", "A04", 1),
    ("ADT", "A08", 1),
    ("ADT", "A40", 1),
    ("ORU", "R01", 1),
    ("ORU", "R01", 2),
    # ORU^R30 #1 is left out: its generated ORC-2 trips the forbidden-content gate as a site code.
    ("ORM", "O01", 1),
    ("ORM", "O01", 2),
]


def _synthetic_corpus() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for code, trigger, index in _SYNTH_PLAN:
        if code in _core.message_codes() and trigger in _core.triggers_for(code):
            msg = _core.generate_message(code, trigger, index)
            out.append((f"gen:{code}^{trigger}#{index}", normalize(msg)))
    return out


_ADVERSARIAL: list[tuple[str, str]] = [
    (
        "adv:escapes",
        "MSH|^~\\&|APP|FAC|RCV|RFAC|20260101||ADT^A01^ADT_A01|C1|P|2.5.1\r"
        "EVN|A01|20260101\r"
        "PID|1||111^^^A~222^^^B||O\\S\\Brien^Se\\T\\an^\\F\\mid||19700101|M|||"
        "1\\X0A\\Main^^City^ST^00000\r"
        "PV1|1|I\r",
    ),
    (
        "adv:custom-seps",
        "MSH#@$%^|APP#FAC#RCV#RFAC#20260101##ADT@A01#C2#P#2.5.1\r"
        "PID#1##333@@@A||O$S$Brien@Sean#@#19800101#F\r",
    ),
    (
        "adv:empty-fields",
        "MSH|^~\\&|||||20260101||ADT^A01|C3|P|2.5.1\rEVN\rPID|1||||||\r\rPV1|1\r",
    ),
    (
        "adv:leading-field-sep",
        "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|C5|P|2.5.1\r|stray\rPID|1||444^^^A||DOE^JO\rPV1|1|I\r",
    ),
    (
        "adv:no-trailing-cr",
        "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|C4|P|2.5.1\rOBR|1\rOBX|1|NM|GLU^Glucose^LN|1|99|mg/dL",
    ),
    # Upstream python-hl7 issue 84: unescape drops a trailing, unterminated escape character. The
    # built-in reproduces it; recording it here pins that behaviour until someone decides otherwise.
    (
        "adv:trailing-escape",
        "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|C7|P|2.5.1\rPID|1||555^^^A||SMITH\\^JO\\E\r",
    ),
]


def _corpus() -> list[tuple[str, str]]:
    return _sample_corpus() + _synthetic_corpus() + [(k, normalize(v)) for k, v in _ADVERSARIAL]


# --- recording -----------------------------------------------------------------------------------


def _run(fn: Callable[[], Any]) -> Any:
    """``fn``'s result under python-hl7, with a raised exception recorded by its type name."""
    with _backend.backend(builtin=False):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - the raise path is part of the oracle
            return {"raises": type(exc).__name__}


def _case(label: str, msg: str) -> dict[str, Any]:
    ops = parity._mutation_ops()
    return {
        "label": label,
        "input": msg,
        "peek_props": {p: _run(parity._peek_prop(msg, p)) for p in parity._PEEK_PROPERTIES},
        "routing": _run(lambda: Peek.parse(msg).routing()),
        "segments": _run(lambda: Peek.parse(msg).segments()),
        "peek_field": {p: _run(parity._peek_field(msg, p)) for p in parity._PROBE_PATHS},
        "message_field": {p: _run(parity._msg_field(msg, p)) for p in parity._PROBE_PATHS},
        "repetitions": {p: _run(parity._msg_reps(msg, p)) for p in parity.REPETITION_PATHS},
        "encode": _run(lambda: Message.parse(msg).encode()),
        "mutations": {name: _run(parity._encode_after(msg, op)) for name, op in ops},
    }


def _blank_segment_set(line: str, touch_first: bool) -> Any:
    """The tree-held blank-segment case: a ``Message`` built straight from python-hl7's parse tree."""

    def run() -> str:
        text = f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|C6|P|2.5.1\r{line}\rPID|1||444\r"
        msg = Message(hl7.parse(text))
        if touch_first:
            msg.field("PID-3", occurrence=1)
            msg.repetitions("MSH-9")
        msg.set("MSH-10", "EDITED")
        return msg.encode()

    return _run(run)


def main() -> None:
    cases = [_case(label, msg) for label, msg in _corpus()]
    custom = parity.AC4_MESSAGE
    record = {
        "provenance": {
            "oracle": f"python-hl7 {version('hl7')}",
            "made_by": "scripts/dev/freeze_python_hl7_oracle.py, deleted with the dependency",
            "note": (
                "Frozen python-hl7 answers through the engine's Peek and Message surfaces. "
                "A value {'raises': T} means the call raised an exception of type T. "
                "Nothing can regenerate this file: see the ADR 0054 amendment."
            ),
        },
        "probe_paths": parity._PROBE_PATHS,
        "repetition_paths": list(parity.REPETITION_PATHS),
        "mutation_ops": [name for name, _ in parity._mutation_ops()],
        "cases": cases,
        "custom_encoding_chars": {
            "input": custom,
            "peek_field": {p: _run(parity._peek_field(custom, p)) for p in parity.AC4_PATHS},
            "message_field": {p: _run(parity._msg_field(custom, p)) for p in parity.AC4_PATHS},
        },
        "blank_segment_set": {
            f"{label}/{'split' if touch else 'lazy'}": _blank_segment_set(line, touch)
            for label, line in parity.BLANK_SEGMENT_LINES
            for touch in (False, True)
        },
    }
    OUT.write_text(json.dumps(record, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)}: {len(cases)} cases")


if __name__ == "__main__":
    main()
