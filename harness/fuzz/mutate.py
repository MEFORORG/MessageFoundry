# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Seeded mutation of synthetic HL7: one :class:`Case` per ``(seed, iteration)``.

Determinism is the contract here. Each case draws from its own ``random.Random`` seeded with a
string built from the campaign seed and the iteration, never from the clock, the process hash seed
or set iteration order, so the same pair yields the same bytes in any process on any platform. A
time budget that stops a campaign early therefore cannot change the bytes of the cases it did run.

Layers:

``none``  the generated message, unmutated -- the positive control: a clean message must be ACKed.
``byte``  raw byte edits on the encoded payload (flip, overwrite with a structural byte, insert,
          delete, duplicate, truncate, swap line endings).
``field`` an edit through the parsed :class:`~messagefoundry.parsing.message.Message`: emptied,
          oversized, delimiter-laden or non-ASCII values, extra repetitions, dropped or added
          segments, odd header values. Never raw slicing.
``frame`` MLLP framing edits on the wire bytes (missing start or end block, junk before the start
          block, two frames, an end block without its CR, a frame split in two). Only a transport
          that sends wire bytes can carry this layer.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache

from harness.scenarios._core import control_id_of
from messagefoundry.generators import (
    _core,
    all_types,  # noqa: F401  (registers the built-in message types)
)
from messagefoundry.mllpcodec import CR, EB, SB, MLLPDecoder, MLLPFrameError, frame
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import PEEK_READ_FAULTS

NONE = "none"
BYTE = "byte"
FIELD = "field"
FRAME = "frame"
LAYERS = (NONE, BYTE, FIELD, FRAME)

#: Relative weight of each layer. The clean control stays rare but present.
_WEIGHTS = {NONE: 1, BYTE: 3, FIELD: 3, FRAME: 2}

#: Bytes that mean something to HL7 or MLLP, plus a NUL, a bare high byte and a UTF-8 lead byte.
_STRUCTURAL = (0x00, 0x0A, 0x0B, 0x0D, 0x1C, 0x26, 0x5C, 0x5E, 0x7C, 0x7E, 0x80, 0xC3, 0xFF)

#: Non-ASCII code points for field values, spelled as numbers so the source stays plain ASCII:
#: Latin-1, Greek, CJK, a right-to-left mark, a BOM, a non-BMP code point, and NUL.
_CODE_POINTS = (0x00E9, 0x00DF, 0x03A9, 0x4E2D, 0x200F, 0xFEFF, 0x1F600, 0x0000)

#: The largest single inserted value. Well under the engine's 16 MiB default message ceiling, so an
#: oversized field tests field handling rather than the size guard every case would then hit.
_MAX_LONG_VALUE = 64 * 1024


@dataclass(frozen=True)
class Case:
    """One fuzz case: ``data`` is exactly what the transport sends (the payload, or the framed wire
    bytes for a wire transport). ``control_id`` is MSH-10 as the tolerant parser reads it from the
    first frame the engine would decode (the payload, for a payload transport), or None when there
    is none; it is a prediction, the ACK's MSA-2 is the truth."""

    seed: int
    iteration: int
    message: str  # e.g. "ADT^A01": the generated type, never content
    layer: str
    mutation: str
    data: bytes
    control_id: str | None


@cache
def message_types() -> tuple[tuple[str, str], ...]:
    """Every (code, trigger) the generators register, sorted so a choice over it is stable."""
    return tuple(
        sorted(
            (code, trigger)
            for code in _core.message_codes()
            for trigger in _core.triggers_for(code)
        )
    )


def case_control_id(seed: int, iteration: int) -> str:
    """The MSH-10 a case starts from: unique per (seed, iteration) and within HL7's 20 characters."""
    return f"FZ{seed % 10**9:09d}{iteration:09d}"


def make_case(seed: int, iteration: int, *, wire: bool = True) -> Case:
    """Build case ``iteration`` of campaign ``seed``. ``wire`` says the transport sends framed MLLP
    bytes, which both frames every payload and allows the ``frame`` layer."""
    if seed < 0 or iteration < 0:
        raise ValueError("seed and iteration are non-negative")
    rng = random.Random(f"harness-fuzz|{seed}|{iteration}")  # nosec B311 (synthetic, seeded)
    code, trigger = rng.choice(message_types())
    message = Message.parse(
        _core.generate_message(code, trigger, iteration + 1, seed=f"harness-fuzz-{seed}")
    )
    message.set("MSH-10", case_control_id(seed, iteration))

    layers = [layer for layer in LAYERS if wire or layer != FRAME]
    layer = rng.choices(layers, weights=[_WEIGHTS[layer] for layer in layers])[0]
    mutation = NONE
    if layer == FIELD:
        mutation, message = _mutate_field(rng, message)
        if mutation == NONE:  # every field edit was refused: fall back to a byte edit
            layer = BYTE
    payload = str(message).encode("utf-8")
    if layer == BYTE:
        mutation, payload = _mutate_bytes(rng, payload)
    data = frame(payload) if wire else payload
    if layer == FRAME:
        mutation, data = _mutate_frame(rng, payload)
    return Case(
        seed=seed,
        iteration=iteration,
        message=f"{code}^{trigger}",
        layer=layer,
        mutation=mutation,
        data=data,
        control_id=_first_control_id(data) if wire else control_id_of(payload),
    )


def _first_control_id(wire: bytes) -> str | None:
    payload = first_frame(wire)
    return None if payload is None else control_id_of(payload)


def frames(wire: bytes) -> list[bytes]:
    """Every complete MLLP frame in ``wire``, decoded as the engine's listener decodes them (the
    same decoder: bytes outside a frame are dropped, a start block inside one is data)."""
    try:
        return list(MLLPDecoder().feed(wire))
    except MLLPFrameError:
        return []


def first_frame(wire: bytes) -> bytes | None:
    """The first complete MLLP frame in ``wire``, or None when there is none."""
    found = frames(wire)
    return found[0] if found else None


# --- byte layer ----------------------------------------------------------------------------------


def _mutate_bytes(rng: random.Random, payload: bytes) -> tuple[str, bytes]:
    data = bytearray(payload)
    op = rng.choice(("flip", "structural", "insert", "delete", "duplicate", "truncate", "newline"))
    if not data:
        return f"byte.{op}", bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
    if op == "flip":
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
    elif op == "structural":
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.choice(_STRUCTURAL)
    elif op == "insert":
        at = rng.randrange(len(data) + 1)
        data[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    elif op == "delete":
        at = rng.randrange(len(data))
        del data[at : at + rng.randint(1, 64)]
    elif op == "duplicate":
        at = rng.randrange(len(data))
        span = data[at : at + rng.randint(1, 256)]
        data[at:at] = span * rng.randint(1, 8)
    elif op == "truncate":
        del data[rng.randrange(len(data)) :]
    else:  # newline: the segment terminator as LF or CRLF, which the engine normalizes
        data = bytearray(data.replace(b"\r", rng.choice((b"\n", b"\r\n", b"\n\r"))))
    return f"byte.{op}", bytes(data)


# --- field layer ---------------------------------------------------------------------------------


def _target(rng: random.Random, message: Message) -> tuple[str, int, int]:
    """A (segment id, occurrence, field number) to edit. MSH-1 and MSH-2 are the separators
    themselves and the model refuses to treat them as data, so MSH edits start at MSH-3."""
    seg = rng.choice(message.segments())
    occurrence = rng.randint(1, max(1, message.count_segments(seg)))
    low = 3 if seg == "MSH" else 1
    return seg, occurrence, rng.randint(low, 30)


def _value(rng: random.Random) -> str:
    kind = rng.randrange(5)
    if kind == 0:
        return "X" * rng.randint(1_000, _MAX_LONG_VALUE)
    if kind == 1:
        return "".join(chr(rng.choice(_CODE_POINTS)) for _ in range(rng.randint(1, 32)))
    if kind == 2:
        return "".join(rng.choice("|^~\\&") for _ in range(rng.randint(1, 16)))
    if kind == 3:
        return rng.choice(
            ("-1", "0", "99999999999999999999", "1e308", "NaN", "20260230", "\\X00\\")
        )
    return ""


def _field_empty(rng: random.Random, message: Message) -> None:
    seg, occ, fld = _target(rng, message)
    message.set(f"{seg}-{fld}", "", occurrence=occ)


def _field_component(rng: random.Random, message: Message) -> None:
    seg, occ, fld = _target(rng, message)
    message.set(f"{seg}-{fld}.{rng.randint(1, 12)}", _value(rng), occurrence=occ)


def _field_subcomponent(rng: random.Random, message: Message) -> None:
    seg, occ, fld = _target(rng, message)
    path = f"{seg}-{fld}.{rng.randint(1, 6)}.{rng.randint(1, 6)}"
    message.set(path, _value(rng), occurrence=occ)


def _field_repeat(rng: random.Random, message: Message) -> None:
    seg, occ, fld = _target(rng, message)
    for _ in range(rng.randint(1, 50)):
        message.add_repetition(f"{seg}-{fld}", rng.choice(("R", "A^B", "", "1")), occurrence=occ)


def _field_drop_segment(rng: random.Random, message: Message) -> None:
    others = [seg for seg in message.segments() if seg != "MSH"]
    if not others:
        raise KeyError("no segment besides MSH")
    message.delete_segments(rng.choice(others))


def _field_add_segment(rng: random.Random, message: Message) -> None:
    seg_id = rng.choice(("ZFZ", "PID", "OBX", "NTE", "MSA", "EVN"))
    fields = "|".join(rng.choice(("", "1", "A^B~C", "X" * rng.randint(1, 200))) for _ in range(8))
    index = rng.randint(1, len(message.segments()))
    message.add_segment(f"{seg_id}|{fields}", index=index)


def _field_header(rng: random.Random, message: Message) -> None:
    path, choices = rng.choice(
        (
            ("MSH-9.1", ("ADT", "ACK", "ZZZ", "", "adt")),
            ("MSH-9.2", ("A01", "", "Z99", "A0")),
            ("MSH-12", ("2.5.1", "2.3", "9.9", "", "2.5.1.1.1")),
            ("MSH-18", ("UNICODE UTF-8", "8859/1", "ASCII", "NOPE")),
            ("MSH-10", ("", "X" * 200, "FZ-dup", "\\F\\")),
            ("MSH-11", ("P", "T", "D", "")),
        )
    )
    message.set(path, rng.choice(choices))


_FIELD_OPS: tuple[tuple[str, Callable[[random.Random, Message], None]], ...] = (
    ("empty", _field_empty),
    ("component", _field_component),
    ("subcomponent", _field_subcomponent),
    ("repeat", _field_repeat),
    ("drop_segment", _field_drop_segment),
    ("add_segment", _field_add_segment),
    ("header", _field_header),
)


def _mutate_field(rng: random.Random, message: Message) -> tuple[str, Message]:
    """Apply one field edit through the model to a copy and return its name and the copy, or
    ``none`` and the original when the model refused three in a row. It refuses CR/LF and stray
    separators by design, which is not a bug; editing a copy keeps a refused edit from leaving a
    half-applied change behind."""
    for _ in range(3):
        name, op = rng.choice(_FIELD_OPS)
        trial = message.copy()
        try:
            op(rng, trial)
        except PEEK_READ_FAULTS:  # LookupError, TypeError, ValueError: a refusal, not a bug
            continue
        return f"field.{name}", trial
    return NONE, message


# --- frame layer ---------------------------------------------------------------------------------


def _mutate_frame(rng: random.Random, payload: bytes) -> tuple[str, bytes]:
    end = bytes((EB, CR))
    start = bytes((SB,))
    op = rng.choice(
        ("no_end", "no_start", "junk_prefix", "double", "fs_no_cr", "split", "empty", "inner_sb")
    )
    if op == "no_end":
        wire = start + payload
    elif op == "no_start":
        wire = payload + end
    elif op == "junk_prefix":
        wire = bytes(rng.randrange(256) for _ in range(rng.randint(1, 32))) + frame(payload)
    elif op == "double":
        wire = frame(payload) + frame(payload)
    elif op == "fs_no_cr":
        wire = start + payload + bytes((EB,))
    elif op == "split":
        at = rng.randrange(len(payload) + 1)
        wire = start + payload[:at] + end + start + payload[at:] + end
    elif op == "empty":
        wire = start + end
    else:  # inner_sb: a start block inside the payload
        at = rng.randrange(len(payload) + 1)
        wire = start + payload[:at] + start + payload[at:] + end
    return f"frame.{op}", wire
