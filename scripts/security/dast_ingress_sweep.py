#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DAST increment 2, the unauthenticated ingress plane: hostile bytes at live MLLP, raw-TCP and X12
listeners in front of a real engine, with the engine's invariants as the oracle (ADR 0155).

WHY "NO CRASH" IS NOT THE ORACLE. Every listener here wraps its per-connection loop in a last-resort
``except Exception``, so a crashing parser never takes the process down; it just drops that one
connection. A pass that asked only "is the engine still up?" would be green over a listener that
silently swallowed every hostile frame. So each case is judged against what CLAUDE.md section 2 says
the ingress path must do, and each judgement is a DETECTOR with a positive control that must fire:

* ``reply`` -- every MLLP frame that reaches decode gets exactly one synchronous reply, an ACK or a
  NAK, never silence and never a spare. The expected frame count comes from running the SAME decoder
  class over the SAME bytes, so framing tolerance is the engine's own, not a guess.
* ``count_and_log`` -- every decoded frame is persisted: an accepted reply matches a new non-ERROR row
  and a NAK matches a new ERROR row. A raw-TCP or X12 frame gets no reply by design, so there the row
  count alone must equal the frame count. An oversize frame closes the connection and must leave a
  ``frame_oversize`` connection event, never nothing.
* ``liveness`` -- after every case a well-formed message on a fresh connection is accepted and
  persisted, so a listener that died or wedged on the previous case is named at that case.
* ``time`` -- every case finishes inside a fixed budget, a stalled or trickling peer is closed by the
  listener inside the stall bound, and a closed peer's connection is released.
* ``resources`` -- heap, OS handles and asyncio tasks, measured across repeated passes of the
  catalogue after a warm-up pass, stay under a fixed growth bound. Instruments: ``tracemalloc``
  traced bytes, ``psutil`` handle (Windows) or descriptor (POSIX) count, ``len(asyncio.all_tasks())``.
* ``log_body`` -- no log record at INFO or above carries message content. Every catalogue body
  carries a per-run sentinel in PID-5, and a record whose rendered text contains it is a finding.
  This is a CALL-SITE check: the receipt also says whether the shipped redaction filters would have
  removed the hit, but a hit is a finding either way, because section 9 binds the call site.

EXIT CODES, as increment 1: 0 clean and above every floor; 1 findings; 2 could not measure. A canary
run exits 1 only when ITS detector fired at or above its floor, and 2 otherwise.

PHI. Every message is synthetic, built here or taken from the committed samples ADR 0191 seeds from.
The receipt records case names, counts, codes and timings, never a body. The scope boundary for this
tier is stated once, in ADR 0155's Scope boundary section; this file carries a pointer only.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import gc
import json
import logging
import random
import sys
import time
import tracemalloc
from collections.abc import Callable, Iterator, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, NamedTuple

import psutil

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fuzz.targets import TARGETS  # noqa: E402
from messagefoundry.logging_setup import _install_phi_filters  # noqa: E402
from messagefoundry.mllpcodec import MLLPDecoder, MLLPFrameError, frame  # noqa: E402
from messagefoundry.parsing.peek import Peek, normalize  # noqa: E402
from messagefoundry.parsing.x12.errors import X12FrameError  # noqa: E402
from messagefoundry.parsing.x12.interchange import X12FrameReader  # noqa: E402
from messagefoundry.store import MessageStatus  # noqa: E402
from messagefoundry.transports.framing import STX_ETX_CODEC, FrameDecoder, FrameError  # noqa: E402
from scripts.security.dast_auth_sweep import _run, annotation_level  # noqa: E402
from scripts.security.dast_ingress_target import (  # noqa: E402
    CANARY_DETECTOR,
    PLANES,
    IngressTarget,
    IngressTargetUnusable,
    ingress_target,
)

DEFAULT_POLICY = Path(__file__).with_name("dast-ingress-policy.json")
_PREFIX = "dast-ingress"
DETECTORS = ("reply", "count_and_log", "liveness", "time", "resources", "log_body")

VT, FS, CR = b"\x0b", b"\x1c", b"\r"
STX, ETX = b"\x02", b"\x03"

#: The seeds ADR 0191 fuzzes the parsers with in-process, reused here over a socket, and the one
#: finding that harness has recorded, replayed at a live listener.
_HL7_SEEDS = next(t for t in TARGETS if t.name == "hl7_peek").seeds
#: A COMPLETE interchange. `next` raises at import when the committed sample is missing, which is
#: loud; falling back to the fuzz target's truncated literal would make every raw-TCP and X12
#: liveness probe report a false engine finding.
_X12_SEED = next(s for s in next(t for t in TARGETS if t.name == "x12_peek").seeds if b"IEA" in s)
_ISA_LEN = 106  # the fixed-width ISA segment, terminator included
_IEA_AT = _X12_SEED.rindex(b"IEA")  # the closing IEA segment, which frames the interchange


class PolicyError(ValueError):
    """The policy file is missing, unreadable or incomplete. Exit 2."""


# =====================================================================================================
# Cases
# =====================================================================================================


@dataclass(frozen=True)
class Case:
    """One hostile input. ``payload`` is written first, the replies to its complete frames are read,
    then ``tail`` is written. ``stall`` cases never half-close: the LISTENER must close them."""

    name: str
    plane: str
    payload: bytes
    split: int = 0  # write in chunks of this many bytes; 0 = one write
    tail: bytes = b""  # an incomplete frame, written after the replies are read
    abort: bool = False  # reset the connection after the tail
    stall: bool = False  # the listener must close this connection within the stall bound
    trickle: bytes = b""  # stall only: one byte of this every trickle_delay seconds
    origin: str = "catalogue"


def hl7(
    control_id: str, sentinel: str, *, fs: str = "|", enc: str = "^~\\&", extra: str = ""
) -> str:
    """A synthetic ADT^A01. The sentinel sits in PID-5 so a logged body is recognisable."""
    return (
        f"MSH{fs}{enc}{fs}DAST{fs}DASTFAC{fs}MEFOR{fs}MEFORFAC{fs}20260101000000{fs}{fs}ADT^A01"
        f"{fs}{control_id}{fs}P{fs}2.5.1\r"
        "EVN|A01|20260101000000\r"
        f"PID|1||DAST0001^^^DAST^MR||{sentinel}^CASE\r{extra}"
    )


def _b(text: str) -> bytes:
    return text.encode("utf-8")


def mllp_catalogue(sentinel: str, cap: int) -> list[Case]:
    """The fixed MLLP cases: broken framing first, then hostile HL7 inside a well-formed frame."""

    def msg(cid: str, **kw: str) -> bytes:
        return _b(hl7(cid, sentinel, **kw))

    good = msg("DAST-OK")
    pad = cap - len(msg("DAST-CAP")) - len("NTE|1||\r")
    exact = _b(hl7("DAST-CAP", sentinel, extra="NTE|1||" + "X" * pad + "\r"))
    cases = [
        Case("well-formed", "mllp", frame(good)),
        Case("missing-start-vt", "mllp", good + FS + CR),
        Case("missing-end-fs", "mllp", VT + good, stall=True),
        Case("missing-trailer-cr", "mllp", VT + good + FS),
        Case("extra-trailers", "mllp", frame(good) + CR * 8),
        Case("double-start", "mllp", VT + frame(good)),
        Case("empty-frame", "mllp", VT + FS + CR),
        Case("start-byte-mid-body", "mllp", frame(good[:40] + VT + good[40:])),
        Case("end-byte-mid-body", "mllp", frame(good[:40] + FS + good[40:])),
        Case("pipelined-three", "mllp", frame(msg("P1")) + frame(msg("P2")) + frame(msg("P3"))),
        Case("split-seven-bytes", "mllp", frame(msg("SPLIT")), split=7),
        Case("noise-then-frame", "mllp", b"\x00\xffGARBAGE\r\n" * 16 + frame(good)),
        Case("binary-garbage-frame", "mllp", frame(bytes(range(32, 256)) * 4)),
        Case("idle-after-connect", "mllp", b"", stall=True),
        Case("slowloris-in-frame", "mllp", VT, stall=True, trickle=good * 8),
        Case("frame-then-truncated-drop", "mllp", frame(good), tail=VT + good[:30], abort=True),
        Case("drop-mid-frame", "mllp", b"", tail=VT + good[:30], abort=True),
        Case("oversize-frame", "mllp", VT + b"A" * (cap + 1)),
        Case("frame-then-oversize", "mllp", frame(good) + VT + b"A" * (cap + 1)),
        Case("exactly-at-cap", "mllp", frame(exact)),
        # Hostile HL7 inside a well-formed frame.
        Case("letter-field-separator", "mllp", frame(msg("SEP1", fs="A"))),
        Case("separator-collision", "mllp", frame(msg("SEP2", enc="||||"))),
        Case("short-encoding-chars", "mllp", frame(msg("SEP3", enc="^"))),
        Case("truncation-char-27", "mllp", frame(msg("SEP4", enc="^~\\&#"))),
        Case("missing-msh", "mllp", frame(_b(f"PID|1||X||{sentinel}^CASE\r"))),
        Case("msh-only", "mllp", frame(b"MSH|^~\\&|")),
        # ADR 0191's recorded finding (an empty segment), rebuilt here around the sentinel.
        Case("blank-segment", "mllp", frame(msg("BLANK", extra="\rPV1|1|I\r"))),
        Case(
            "blank-segment-invalid-utf8",
            "mllp",
            frame(msg("BLANK", extra="\rPV1|1|I\r").replace(b"CASE", b"CA\xc0E")),
        ),
        Case("huge-repeat-count", "mllp", frame(msg("REP", extra="ZRP|" + "~" * 20000 + "\r"))),
        Case("deep-components", "mllp", frame(msg("DEEP", extra="ZDP|" + "^&" * 10000 + "\r"))),
        Case("many-segments", "mllp", frame(msg("SEGS", extra="NTE|1|\r" * 3000))),
        Case(
            "escape-abuse", "mllp", frame(msg("ESC", extra="NTE|1||" + "\\X0\\\\E\\" * 3000 + "\r"))
        ),
        Case("lf-only-segments", "mllp", frame(good.replace(b"\r", b"\n"))),
        Case("bom-prefixed", "mllp", frame(b"\xef\xbb\xbf" + good)),
        Case("latin1-not-utf8", "mllp", frame(good.replace(b"CASE", b"CAS\xe9"))),
        Case("overlong-utf8", "mllp", frame(good.replace(b"CASE", b"CA\xc0\xafE"))),
        Case("lone-surrogate-utf8", "mllp", frame(good.replace(b"CASE", b"CA\xed\xa0\x80E"))),
        Case("nul-in-body", "mllp", frame(good.replace(b"CASE", b"CA\x00E"))),
        Case("control-chars", "mllp", frame(good.replace(b"CASE", bytes(range(1, 11)) + b"E"))),
        Case("huge-single-field", "mllp", frame(msg("BIG", extra="NTE|1||" + "Z" * 60000 + "\r"))),
    ]
    return cases


def tcp_catalogue(cap: int) -> list[Case]:
    x12 = _X12_SEED
    return [
        Case("well-formed", "tcp", STX + x12 + ETX),
        Case("missing-stx", "tcp", x12 + ETX),
        Case("missing-etx", "tcp", STX + x12, stall=True),
        Case("pipelined-three", "tcp", (STX + x12 + ETX) * 3),
        Case("empty-frame", "tcp", STX + ETX),
        Case("invalid-utf8", "tcp", STX + x12.replace(b"ZZ", b"\xc0\xaf", 1) + ETX),
        Case("nul-in-body", "tcp", STX + x12.replace(b"ZZ", b"\x00\x00", 1) + ETX),
        Case("oversize-frame", "tcp", STX + b"A" * (cap + 1)),
        Case("drop-mid-frame", "tcp", b"", tail=STX + x12[:40], abort=True),
    ]


def x12_catalogue(cap: int) -> list[Case]:
    x12 = _X12_SEED
    return [
        Case("well-formed", "x12", x12),
        Case("noise-then-interchange", "x12", b"\x00\xffNOISE" * 32 + x12),
        Case("pipelined-three", "x12", x12 * 3),
        Case("short-isa", "x12", x12[:60]),
        Case("isa-without-iea", "x12", x12.replace(b"IEA", b"XEA")),
        Case("invalid-utf8", "x12", x12.replace(b"ZZ", b"\xc0\xaf", 1)),
        Case("oversize-interchange", "x12", b"ISA" + b"*" * (cap + 1)),
        Case("idle-after-connect", "x12", b"", stall=True),
        Case("drop-mid-interchange", "x12", b"", tail=x12[:120], abort=True),
    ]


_INTERESTING = (
    b"|", b"^", b"~", b"\\", b"&", b"\r", b"\n", VT, FS, b"\x00", b"\xff",
    b"\xc0\xaf", b"\xed\xa0\x80", b"MSH|^~\\&|", b"\x1c\r\x0b",
)  # fmt: skip


def mutate(rng: random.Random, seed: bytes, limit: int) -> bytes:
    """One to four byte-level mutations of ``seed``, never longer than ``limit`` bytes.

    Atheris supplies ADR 0191's mutator in-process; it cannot drive a socket, so these are the small
    set of structure-aware edits that matter at a listener: delimiter bytes, framing bytes, encodings
    and repetition. Deterministic for a given ``rng`` state.
    """
    data = bytearray(seed)
    for _ in range(rng.randint(1, 4)):
        pos = rng.randint(0, len(data)) if data else 0
        op = rng.randrange(6)
        if op == 0 and data:
            idx = min(pos, len(data) - 1)
            data[idx] ^= 1 << rng.randrange(8)
        elif op == 1:
            data[pos:pos] = rng.choice(_INTERESTING)
        elif op == 2 and data:
            end = min(len(data), pos + rng.randint(1, 64))
            del data[pos:end]
        elif op == 3 and data:
            end = min(len(data), pos + rng.randint(1, 64))
            data[pos:pos] = data[pos:end] * rng.randint(1, 40)
        elif op == 4:
            data[pos:pos] = rng.choice((b"|", b"^", b"~", b"&", b"\r")) * rng.randint(100, 4000)
        else:
            del data[pos:]
    return bytes(data[:limit])


def mutation_cases(seed: int, count: int, cap: int, sentinel: str) -> list[Case]:
    """``count`` seeded mutations. HL7 seeds include one carrying the sentinel, so the log_body
    detector can see a mutated body. X12 mutations edit only what lies between the fixed-width ISA
    and the closing IEA: an edit inside the ISA moves the terminator and a lost IEA never closes the
    interchange, and either way the X12 ingress path would go unreached."""
    rng = random.Random(seed)
    limit = cap // 2
    hl7_seeds = (*_HL7_SEEDS, _b(hl7("MUTATE", sentinel)))
    cases = []
    for index in range(count):
        if index % 4 == 3:
            body = mutate(rng, _X12_SEED[_ISA_LEN:_IEA_AT], limit - len(_X12_SEED))
            plane, payload = "x12", _X12_SEED[:_ISA_LEN] + body + _X12_SEED[_IEA_AT:]
        else:
            plane, payload = "mllp", frame(mutate(rng, rng.choice(hl7_seeds), limit))
        cases.append(Case(f"mutation-{index}", plane, payload, origin=f"mutation:{seed}:{index}"))
    return cases


# =====================================================================================================
# The oracle: how many frames the engine's own decoder takes out of these bytes
# =====================================================================================================


def reference_frames(plane: str, data: bytes, cap: int) -> tuple[list[bytes], bool]:
    """``(complete frame payloads, overflowed)`` for ``data`` under ``plane``'s own decoder and cap."""
    decoder: Any
    errors: tuple[type[Exception], ...]
    if plane == "mllp":
        decoder, errors = MLLPDecoder(max_frame_bytes=cap), (MLLPFrameError,)
    elif plane == "tcp":
        decoder, errors = FrameDecoder(STX_ETX_CODEC, max_frame_bytes=cap), (FrameError,)
    else:
        decoder, errors = X12FrameReader(max_interchange_bytes=cap), (X12FrameError,)
    frames: list[bytes] = []
    try:
        frames.extend(decoder.feed(data))
    except errors:
        return frames, True
    return frames, False


def _blank_segment(payload: bytes) -> bool:
    """ADR 0191's known finding, recognised by its own narrow discriminator: the frame parses and
    carries a segment whose id is the empty string.

    Decoded with REPLACEMENT, not strictly, because the defect has two faces. A frame that decodes
    cleanly raises before its ingress row, so no row and no reply. A frame that fails UTF-8 decode is
    recorded ERROR first, and then the NAK builder re-parses the bytes leniently and raises, so there
    is a row and still no reply. Both are this one defect, and a strict decode would miss the second.
    """
    try:
        peek = Peek.parse(normalize(payload, encoding="utf-8", errors="replace"))
        return any(not segment for segment in peek.segments())
    except ValueError:  # HL7PeekError is a ValueError
        return False


def _alphanumeric_field_separator(payload: bytes) -> bool:
    return payload[:3] == b"MSH" and payload[3:4].isalnum()


#: Known engine defects, each recognised by a NARROW structural condition on the frames a case sent,
#: never by an exception type or a case name alone (a mutation can reproduce one by chance). Which of
#: these a run tolerates is the policy's ``known_defects`` list; tests/test_dast_ingress_sweep.py holds
#: a strict xfail per entry, so the day a defect is fixed its entry has to come out.
KNOWN_DEFECT_DISCRIMINATORS: dict[str, Callable[[bytes], bool]] = {
    "blank-segment": _blank_segment,
    "alphanumeric-field-separator": _alphanumeric_field_separator,
}
#: The only detectors a known defect may silence. A liveness, time, resource or log finding on the
#: same case is never tolerated: those would be a SECOND defect riding on the known one.
KNOWN_DEFECT_DETECTORS = frozenset({"reply", "count_and_log"})
#: Known defects whose failure closes the connection, measured: the listener's last-resort handler
#: breaks out of the read loop, so pipelined frames after the defective one are never decoded.
CONNECTION_DROPPING_DEFECTS = frozenset({"blank-segment"})


def classify_replies(data: bytes) -> tuple[int, int, int]:
    """``(accepted, rejected, unreadable)`` MLLP replies in ``data``, read off each reply's MSA-1."""
    accepted = rejected = unreadable = 0
    for payload in MLLPDecoder(max_frame_bytes=None).feed(data):
        text = payload.decode("utf-8", errors="replace")
        msa = next((s for s in text.replace("\n", "\r").split("\r") if s.startswith("MSA")), "")
        code = msa.split(msa[3])[1] if len(msa) > 4 else ""
        if code in ("AA", "CA"):
            accepted += 1
        elif code in ("AE", "AR", "CE", "CR"):
            rejected += 1
        else:
            unreadable += 1
    return accepted, rejected, unreadable


# =====================================================================================================
# Driving a case
# =====================================================================================================


def finding(
    detector: str, plane: str, case: str, detail: str, known_defect: str = ""
) -> dict[str, str]:
    """The one shape every finding takes, in the receipt and in the evaluator."""
    return {
        "detector": detector,
        "plane": plane,
        "case": case,
        "detail": detail,
        "known_defect": known_defect,
    }


@dataclass
class CaseResult:
    name: str
    plane: str
    origin: str
    frames: int
    overflow: bool
    known_defect: str = ""
    accepted: int = 0
    rejected: int = 0
    unreadable: int = 0
    rows: int = 0
    error_rows: int = 0
    oversize_events: int = 0
    seconds: float = 0.0
    findings: list[dict[str, str]] = field(default_factory=list)

    def find(self, detector: str, detail: str) -> None:
        self.findings.append(finding(detector, self.plane, self.name, detail, self.known_defect))


def _chunks(data: bytes, size: int) -> Iterator[bytes]:
    if size <= 0:
        yield data
        return
    for start in range(0, len(data), size):
        yield data[start : start + size]


async def _read_until_close(reader: asyncio.StreamReader, seconds: float) -> tuple[bytes, bool]:
    """Everything the peer sends until it closes, or ``seconds`` pass. A reset counts as a close."""
    got = b""
    deadline = time.monotonic() + seconds
    try:
        while (left := deadline - time.monotonic()) > 0:
            chunk = await asyncio.wait_for(reader.read(65536), left)
            if not chunk:
                return got, True
            got += chunk
    except TimeoutError:
        return got, False
    except (ConnectionError, OSError):
        return got, True
    return got, False


async def _read_replies(reader: asyncio.StreamReader, count: int, seconds: float) -> bytes:
    got = b""
    deadline = time.monotonic() + seconds
    with suppress(TimeoutError, ConnectionError, OSError):
        while sum(classify_replies(got)) < count and (left := deadline - time.monotonic()) > 0:
            chunk = await asyncio.wait_for(reader.read(65536), left)
            if not chunk:
                break
            got += chunk
    return got


async def _trickle(writer: asyncio.StreamWriter, data: bytes, delay: float) -> None:
    with suppress(ConnectionError, OSError):  # the listener closing on us is the expected end
        for index in range(len(data)):
            writer.write(data[index : index + 1])
            await writer.drain()
            await asyncio.sleep(delay)


@dataclass
class Budget:
    case_seconds: float
    stall_close_seconds: float
    trickle_delay: float
    settle_seconds: float
    cap: int
    connect_seconds: float = 1.0

    @classmethod
    def from_policy(cls, policy: dict[str, Any], *, canary: str | None = None) -> Budget:
        b = policy["budget"]
        return cls(
            case_seconds=float(
                policy["canary"]["case_seconds"] if canary == "stall" else b["case_seconds"]
            ),
            stall_close_seconds=float(b["stall_close_seconds"]),
            trickle_delay=float(b["trickle_delay"]),
            settle_seconds=float(b["settle_seconds"]),
            cap=int(policy["posture"]["max_frame_bytes"]),
            connect_seconds=float(b["connect_seconds"]),
        )


async def _connect(
    target: IngressTarget, plane: str, budget: Budget
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a loopback connection, bounded. A loopback connect takes milliseconds; Windows retries a
    REFUSED one for about two seconds before failing, so without a bound a dead listener costs two
    seconds per probe. A timeout here is reported as the refusal it is."""
    try:
        return await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", target.ports[plane]), budget.connect_seconds
        )
    except TimeoutError as exc:
        raise ConnectionRefusedError(f"no connection within {budget.connect_seconds}s") from exc


async def _drive(target: IngressTarget, case: Case, result: CaseResult, budget: Budget) -> bytes:
    """Send ``case`` and return every byte the listener sent back."""
    reader, writer = await _connect(target, case.plane, budget)
    trickler: asyncio.Task[None] | None = None
    # A write can fail because the listener already closed (an oversize frame does that). What it sent
    # before closing is still read below, so a failed write is noted and never ends the case early.
    wrote = True
    try:
        try:
            for chunk in _chunks(case.payload, case.split):
                writer.write(chunk)
                await writer.drain()
        except (ConnectionError, OSError):
            wrote = False
        if case.stall:
            opened = time.monotonic()
            if case.trickle and wrote:
                trickler = asyncio.create_task(_trickle(writer, case.trickle, budget.trickle_delay))
            got, closed = await _read_until_close(reader, budget.stall_close_seconds)
            if not closed:
                result.find(
                    "time",
                    f"the listener held a stalled connection past {budget.stall_close_seconds}s",
                )
            result.seconds = time.monotonic() - opened
            return got
        got = b""
        if case.tail and wrote:
            if case.plane == "mllp" and result.frames:
                got = await _read_replies(reader, result.frames, budget.case_seconds)
            with suppress(ConnectionError, OSError):
                writer.write(case.tail)
                await writer.drain()
            if case.abort:
                writer.transport.abort()
                return got
        if wrote and writer.can_write_eof():
            with suppress(ConnectionError, OSError):
                writer.write_eof()
        rest, closed = await _read_until_close(reader, budget.case_seconds)
        if not closed:
            result.find("time", "the listener did not close after the peer half-closed")
        return got + rest
    finally:
        if trickler is not None:
            trickler.cancel()
            with suppress(asyncio.CancelledError):
                await trickler
        writer.close()
        with suppress(ConnectionError, OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 2.0)


class Counts(NamedTuple):
    rows: int
    errors: int


async def _counts(target: IngressTarget, plane: str) -> Counts:
    store, name = target.engine.store, PLANES[plane]
    return Counts(
        await store.count_messages(channel_id=name),
        await store.count_messages(channel_id=name, status=MessageStatus.ERROR.value),
    )


async def _oversize_events(target: IngressTarget, plane: str) -> int:
    """Read only for a case that overflows: most cases never need it."""
    events = await target.engine.store.list_connection_events(
        connection=PLANES[plane], kinds=["frame_oversize"], limit=1000
    )
    return len(events)


async def _settle(target: IngressTarget, plane: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while target.active_connections(plane) > 0:
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.01)
    return True


async def run_case(target: IngressTarget, case: Case, budget: Budget) -> CaseResult:
    payloads, overflow = reference_frames(case.plane, case.payload, budget.cap)
    known, known_frames = "", 0
    for name, hit in KNOWN_DEFECT_DISCRIMINATORS.items():
        matches = [i for i, payload in enumerate(payloads) if hit(payload)]
        if matches:
            # A defect that drops the connection also loses every later frame on it, so those
            # count as explained; any other defect explains only the frames it matched.
            dropping = name in CONNECTION_DROPPING_DEFECTS
            known = name
            known_frames = len(payloads) - matches[0] if dropping else len(matches)
            break
    result = CaseResult(case.name, case.plane, case.origin, len(payloads), overflow, known)
    before = await _counts(target, case.plane)
    events_before = await _oversize_events(target, case.plane) if overflow else 0
    started = time.monotonic()
    try:
        got = await asyncio.wait_for(_drive(target, case, result, budget), budget.case_seconds * 2)
    except TimeoutError:
        result.find("time", f"the case did not finish inside {budget.case_seconds * 2}s")
        got = b""
    except OSError as exc:
        # The connect itself failed: the listener is gone. Nothing was sent, so there is nothing for
        # the reply or row oracle to judge, and judging it anyway would triple-count one fault.
        result.find(
            "liveness", f"the listener refused the case's connection ({type(exc).__name__})"
        )
        return result
    if not case.stall:
        result.seconds = time.monotonic() - started
    if not await _settle(target, case.plane, budget.settle_seconds):
        result.find(
            "time", f"the listener did not release the connection in {budget.settle_seconds}s"
        )
    if overflow:
        # The event is written off the listener's path, so it may land a moment after the close.
        deadline = time.monotonic() + budget.settle_seconds
        while (events := await _oversize_events(target, case.plane)) <= events_before:
            if time.monotonic() > deadline:
                break
            await asyncio.sleep(0.02)
        result.oversize_events = events - events_before
    after = await _counts(target, case.plane)
    result.rows, result.error_rows = after.rows - before.rows, after.errors - before.errors
    _judge(result, got)
    if known and not _explained(result, known_frames):
        # A multi-frame case where the known frames cannot account for the whole shortfall: the
        # rest is a SECOND defect riding on the known one, so nothing on this case is tolerated.
        for f in result.findings:
            f["known_defect"] = ""
    return result


def _explained(result: CaseResult, known_frames: int) -> bool:
    """Whether ``known_frames`` defective frames can account for every reply and row mismatch."""
    replies = result.accepted + result.rejected + result.unreadable
    nonerror = result.rows - result.error_rows
    gaps = (
        result.frames - replies,
        result.frames - result.rows,
        abs(result.accepted - nonerror),
        abs(result.rejected - result.error_rows),
        result.unreadable,
    )
    return all(0 <= gap <= known_frames for gap in gaps[:2]) and all(
        gap <= known_frames for gap in gaps[2:]
    )


def _judge(result: CaseResult, got: bytes) -> None:
    frames = result.frames
    if result.plane == "mllp":
        result.accepted, result.rejected, result.unreadable = classify_replies(got)
        replies = result.accepted + result.rejected + result.unreadable
        if replies < frames:
            result.find(
                "reply", f"{frames} frame(s) reached decode, {replies} reply(ies) came back"
            )
        elif replies > frames:
            result.find("reply", f"{replies} replies for {frames} decoded frame(s)")
        if result.unreadable:
            result.find("reply", f"{result.unreadable} reply(ies) carried no readable MSA-1")
        if result.accepted != result.rows - result.error_rows:
            result.find(
                "count_and_log",
                f"{result.accepted} accepted reply(ies) against "
                f"{result.rows - result.error_rows} new non-ERROR row(s)",
            )
        if result.rejected != result.error_rows:
            result.find(
                "count_and_log",
                f"{result.rejected} NAK(s) against {result.error_rows} new ERROR row(s)",
            )
    elif got:
        result.find("reply", f"{len(got)} byte(s) came back from a listener that never replies")
    if result.rows != frames:
        result.find("count_and_log", f"{frames} decoded frame(s) left {result.rows} new row(s)")
    if result.overflow and result.oversize_events < 1:
        result.find("count_and_log", "an oversize frame was dropped with no frame_oversize event")


async def probe_liveness(
    target: IngressTarget, plane: str, index: int, budget: Budget
) -> str | None:
    """A well-formed message on a fresh connection must be accepted and persisted. ``None`` = alive."""
    if plane == "mllp":
        payload = frame(_b(hl7(f"LIVE{index}", "LIVENESS")))
    elif plane == "tcp":
        payload = STX + _X12_SEED + ETX
    else:
        payload = _X12_SEED
    before = await _counts(target, plane)
    try:
        reader, writer = await _connect(target, plane, budget)
    except OSError as exc:
        return f"the listener refused a connection ({type(exc).__name__})"
    try:
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        got, _closed = await _read_until_close(reader, budget.case_seconds)
    except (ConnectionError, OSError) as exc:
        return f"the listener dropped a well-formed message ({type(exc).__name__})"
    finally:
        writer.close()
        with suppress(ConnectionError, OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 2.0)
    await _settle(target, plane, budget.settle_seconds)
    after = await _counts(target, plane)
    accepted = (after.rows - before.rows) - (after.errors - before.errors)
    if plane == "mllp" and classify_replies(got)[0] != 1:
        return "a well-formed message got no AA"
    if accepted != 1:
        return f"a well-formed message left {accepted} accepted row(s), expected 1"
    return None


# =====================================================================================================
# Detectors that span the run: log bodies and resource growth
# =====================================================================================================


class LogWatch(logging.Handler):
    """Counts INFO+ records and records every one whose rendered text carries the sentinel."""

    def __init__(self, sentinel: str) -> None:
        super().__init__(level=logging.INFO)
        self.sentinel = sentinel
        self.seen = 0
        self.hits: list[dict[str, str]] = []
        self._shipped = logging.Handler()
        _install_phi_filters(self._shipped)

    @staticmethod
    def _render(record: logging.LogRecord) -> str:
        text = record.getMessage()
        if record.exc_info and not record.exc_text:
            text += logging.Formatter().formatException(record.exc_info)
        return text + (record.exc_text or "")

    def emit(self, record: logging.LogRecord) -> None:
        self.seen += 1
        if self.sentinel not in self._render(record):
            return
        shipped = copy.copy(record)
        redacted = bool(self._shipped.filter(shipped)) and self.sentinel not in self._render(
            shipped
        )
        self.hits.append(
            {
                "logger": record.name,
                "level": record.levelname,
                "shipped_filters_would_redact": "yes" if redacted else "no",
            }
        )


def _handles() -> int:
    proc = psutil.Process()
    return int(proc.num_handles()) if hasattr(proc, "num_handles") else int(proc.num_fds())


@dataclass
class Resources:
    passes: int = 0
    heap_growth_bytes: int = 0
    handle_growth: int = 0
    task_growth: int = 0
    instruments: str = (
        "tracemalloc traced bytes; psutil num_handles (Windows) or num_fds (POSIX); "
        "len(asyncio.all_tasks())"
    )


async def _quiesce(target: IngressTarget, budget: Budget) -> None:
    for plane in PLANES:
        await _settle(target, plane, budget.settle_seconds)
    await asyncio.sleep(0.05)
    gc.collect()


async def measure_resources(
    target: IngressTarget, cases: Sequence[Case], passes: int, budget: Budget
) -> tuple[Resources, list[dict[str, str]]]:
    """Warm up with one pass, then measure growth across ``passes`` more. Every repeat is still
    judged, and a liveness probe closes each pass, so a defect that shows only on a repeat or a
    listener wedged by one is reported rather than discarded."""
    findings: list[dict[str, str]] = []

    async def one_pass(label: str) -> None:
        for case in cases:
            findings.extend(
                (
                    await run_case(target, replace(case, name=f"{label}:{case.name}"), budget)
                ).findings
            )
        for plane in PLANES:
            if (failure := await probe_liveness(target, plane, 0, budget)) is not None:
                findings.append(finding("liveness", plane, label, failure))

    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    try:
        await one_pass("resource-warmup")
        await _quiesce(target, budget)
        heap0, handles0, tasks0 = (
            tracemalloc.get_traced_memory()[0],
            _handles(),
            len(asyncio.all_tasks()),
        )
        for number in range(passes):
            await one_pass(f"resource-pass-{number + 1}")
        await _quiesce(target, budget)
        return Resources(
            passes=passes,
            heap_growth_bytes=tracemalloc.get_traced_memory()[0] - heap0,
            handle_growth=_handles() - handles0,
            task_growth=len(asyncio.all_tasks()) - tasks0,
        ), findings
    finally:
        if started_here:
            tracemalloc.stop()


# =====================================================================================================
# The run
# =====================================================================================================


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"cannot read the policy at {path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicyError(f"the policy at {path} is not a JSON object")
    for key in ("posture", "budget", "floors", "resource_bounds", "canary", "seed", "mutations"):
        if key not in policy:
            raise PolicyError(f"the policy at {path} has no {key!r} section")
    return policy


def catalogue(sentinel: str, cap: int) -> list[Case]:
    return mllp_catalogue(sentinel, cap) + tcp_catalogue(cap) + x12_catalogue(cap)


async def run_sweep(
    policy: dict[str, Any],
    *,
    canary: str | None = None,
    seed: int | None = None,
    mutations: int | None = None,
    mutation_seconds: float = 0.0,
) -> dict[str, Any]:
    posture = policy["posture"]
    budget = Budget.from_policy(policy, canary=canary)
    cap = budget.cap
    seed = int(policy["seed"]) if seed is None else seed
    sentinel = f"ZZDASTSENTINEL{seed:08X}"
    fixed = catalogue(sentinel, cap)
    cases = list(fixed)
    if canary is not None:
        wanted = policy["canary"].get("cases_by_canary", {}).get(canary, policy["canary"]["cases"])
        cases = [c for c in cases if f"{c.plane}:{c.name}" in wanted]
    else:
        cases += mutation_cases(
            seed, int(policy["mutations"] if mutations is None else mutations), cap, sentinel
        )

    # The watch hangs on the ENGINE's logger, not the root: a host that stops `messagefoundry` from
    # propagating (the test suite's teardown quiescing does exactly that) would otherwise hide every
    # engine record from it. The level is forced to INFO, the shipped service level, for the run, and
    # the `records_seen` floor is what proves the watch was actually fed.
    watch = LogWatch(sentinel)
    engine_logger = logging.getLogger("messagefoundry")
    saved_level = engine_logger.level
    engine_logger.addHandler(watch)
    engine_logger.setLevel(logging.INFO)
    results: list[CaseResult] = []
    liveness: list[dict[str, str]] = []
    resource_findings: list[dict[str, str]] = []
    probes = 0
    resources = Resources()
    started = time.monotonic()
    try:
        settings = dict(posture, canary_stall_seconds=policy["canary"]["stall_seconds"])
        async with ingress_target(settings, canary=canary) as target:

            async def one(case: Case) -> None:
                nonlocal probes
                index = len(results)
                results.append(await run_case(target, case, budget))
                await target.after_case(index)
                failure = await probe_liveness(target, case.plane, index, budget)
                probes += 1
                if failure is not None:
                    liveness.append(finding("liveness", case.plane, case.name, failure))

            for case in cases:
                await one(case)
            if canary is None and mutation_seconds > 0:
                rng_seed, extra = seed + 1, 0
                deadline = time.monotonic() + mutation_seconds
                while time.monotonic() < deadline:
                    for case in mutation_cases(rng_seed, 16, cap, sentinel):
                        if time.monotonic() >= deadline:
                            break
                        # origin is `mutation:<seed>:<index in its batch of 16>`, so
                        # `--seed <seed> --mutations 16` regenerates it.
                        await one(replace(case, name=f"timed-{extra}"))
                        extra += 1
                    rng_seed += 1
            if canary in (None, "leak"):
                wanted_r = policy["canary"]["resource_cases"] if canary else None
                resource_cases = [
                    c
                    for c in fixed
                    if not c.stall and (wanted_r is None or f"{c.plane}:{c.name}" in wanted_r)
                ]
                passes = int(policy["resource_bounds"]["passes"])
                resources, resource_findings = await measure_resources(
                    target, resource_cases, passes, budget
                )
            posture_out = target.posture
    finally:
        engine_logger.removeHandler(watch)
        engine_logger.setLevel(saved_level)

    findings = [f for r in results for f in r.findings] + liveness + resource_findings
    bounds = policy["resource_bounds"]
    for label, observed, bound in (
        ("heap", resources.heap_growth_bytes, bounds["max_heap_growth_bytes"]),
        ("handles", resources.handle_growth, bounds["max_handle_growth"]),
        ("tasks", resources.task_growth, bounds["max_task_growth"]),
    ):
        if observed > bound:
            detail = f"{label} grew by {observed} across {resources.passes} passes (bound {bound})"
            findings.append(finding("resources", "all", label, detail))
    findings += [finding("log_body", "all", hit["logger"], json.dumps(hit)) for hit in watch.hits]
    return {
        "tool": "scripts/security/dast_ingress_sweep.py",
        "scope": "see docs/adr/0155-dast-dynamic-security-testing-of-the-running-engine.md, Scope boundary",
        "seed": seed,
        "canary": canary,
        "posture": posture_out,
        "wall_seconds": round(time.monotonic() - started, 2),
        "planes": _plane_totals(results, liveness),
        "liveness_probes": probes,
        "mutation_cases": sum(1 for r in results if r.origin.startswith("mutation")),
        "log": {"records_seen": watch.seen, "sentinel_hits": len(watch.hits)},
        "resources": asdict(resources),
        "findings": findings,
        "cases": [
            {k: v for k, v in asdict(r).items() if k != "findings"} | {"findings": len(r.findings)}
            for r in results
        ],
    }


def _plane_totals(
    results: Sequence[CaseResult], liveness: Sequence[dict[str, str]]
) -> dict[str, Any]:
    totals: dict[str, Any] = {}
    for plane in PLANES:
        mine = [r for r in results if r.plane == plane]
        totals[plane] = {
            "cases": len(mine),
            "frames_decoded": sum(r.frames for r in mine),
            "accepted_replies": sum(r.accepted for r in mine),
            "rejected_replies": sum(r.rejected for r in mine),
            "rows": sum(r.rows for r in mine),
            "error_rows": sum(r.error_rows for r in mine),
            "liveness_failures": sum(1 for f in liveness if f["plane"] == plane),
        }
    return totals


def evaluate(receipt: dict[str, Any], policy: dict[str, Any]) -> tuple[int, list[str]]:
    """``(exit code, messages)``. A canary is judged on its own detector; a real run on floors first."""
    tolerated_ids = set(policy.get("known_defects", {}))
    tolerated = [
        f
        for f in receipt["findings"]
        if f.get("known_defect") in tolerated_ids and f["detector"] in KNOWN_DEFECT_DETECTORS
    ]
    findings = [f for f in receipt["findings"] if f not in tolerated]
    receipt["known_defect_findings"] = tolerated
    messages = [f"[{f['detector']}] {f['plane']}:{f['case']}: {f['detail']}" for f in findings]
    canary = receipt["canary"]
    if canary is not None:
        detector = CANARY_DETECTOR[canary]
        floor = int(policy["canary"]["floors"][canary])
        if canary == "leak":
            # Heap and handles are floored SEPARATELY: one combined count would let a blind handle
            # instrument be certified by the heap instrument beside it.
            fired = [f for f in findings if f["detector"] == "resources"]
            kinds = {f["case"] for f in fired}
            ok = {"heap", "handles"} <= kinds
        else:
            ok = sum(1 for f in findings if f["detector"] == detector) >= floor
        if ok:
            return 1, messages
        return 2, [
            f"canary {canary!r} did not trip the {detector!r} detector at its floor of {floor}: the "
            "detector is blind, so this run measured nothing",
            *messages,
        ]
    floors = policy["floors"]
    unmet: list[str] = []
    for plane, plane_floor in floors["cases_per_plane"].items():
        if receipt["planes"][plane]["cases"] < plane_floor:
            unmet.append(f"{plane} cases {receipt['planes'][plane]['cases']} < floor {plane_floor}")
    for plane, plane_floor in floors["min_frames_decoded"].items():
        if receipt["planes"][plane]["frames_decoded"] < plane_floor:
            decoded = receipt["planes"][plane]["frames_decoded"]
            unmet.append(f"{plane} frames decoded {decoded} < floor {plane_floor}")
    mllp_totals = receipt["planes"]["mllp"]
    for key in ("frames_decoded", "accepted_replies", "rejected_replies"):
        if mllp_totals[key] < floors[f"min_mllp_{key}"]:
            unmet.append(f"mllp {key} {mllp_totals[key]} < floor {floors[f'min_mllp_{key}']}")
    if receipt["liveness_probes"] < floors["min_liveness_probes"]:
        unmet.append(
            f"liveness probes {receipt['liveness_probes']} < floor {floors['min_liveness_probes']}"
        )
    if receipt["log"]["records_seen"] < floors["min_log_records_seen"]:
        unmet.append("the log watch saw no INFO record, so the log_body detector was blind")
    if receipt["resources"]["passes"] < 1:
        unmet.append("the resource phase did not run")
    if unmet:
        return 2, [f"floor unmet: {u}" for u in unmet] + messages
    return (1 if findings else 0), messages


def receipt_lines(receipt: dict[str, Any], verdict: str) -> list[str]:
    lines = [
        f"## DAST ingress plane: {verdict}",
        "",
        f"Seed {receipt['seed']}, canary {receipt['canary'] or 'none'}, {receipt['wall_seconds']}s. "
        f"Scope: {receipt['scope']}.",
        "",
        "| plane | cases | frames decoded | accepted | rejected | rows | ERROR rows |",
        "|---|---|---|---|---|---|---|",
    ]
    for plane, t in receipt["planes"].items():
        lines.append(
            f"| {plane} | {t['cases']} | {t['frames_decoded']} | {t['accepted_replies']} | "
            f"{t['rejected_replies']} | {t['rows']} | {t['error_rows']} |"
        )
    r = receipt["resources"]
    lines += [
        "",
        f"Liveness probes: {receipt['liveness_probes']}. Log records watched: "
        f"{receipt['log']['records_seen']}, sentinel hits {receipt['log']['sentinel_hits']}.",
        f"Resources over {r['passes']} passes: heap +{r['heap_growth_bytes']} B, handles "
        f"+{r['handle_growth']}, tasks +{r['task_growth']} ({r['instruments']}).",
        "",
        "Scanned posture (NOT the shipped default):",
        *(f"- {k}: {v}" for k, v in receipt["posture"].items()),
        "",
        f"Findings: {len(receipt['findings']) - len(receipt.get('known_defect_findings', []))}. "
        f"Tolerated as known engine defects (named in the policy, each pinned by a strict xfail): "
        f"{len(receipt.get('known_defect_findings', []))}.",
    ]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Hostile-input pass over the live ingress listeners."
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--receipt", type=Path, default=None)
    parser.add_argument("--summary", type=Path, default=None)
    parser.add_argument("--canary", choices=sorted(CANARY_DETECTOR), default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--mutations", type=int, default=None)
    parser.add_argument(
        "--mutation-seconds", type=float, default=0.0, help="extra randomized budget (nightly)"
    )
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        receipt = _run(
            run_sweep(
                policy,
                canary=args.canary,
                seed=args.seed,
                mutations=args.mutations,
                mutation_seconds=args.mutation_seconds,
            )
        )
    except (PolicyError, IngressTargetUnusable) as exc:
        print(f"::error::{_PREFIX}: {exc} (fail closed)", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - every could-not-measure path must be 2, never 1
        print(
            f"::error::{_PREFIX}: the sweep did not run to completion ({type(exc).__name__}: {exc}). "
            "Refusing to report a result (fail closed).",
            file=sys.stderr,
        )
        return 2
    try:
        code, messages = evaluate(receipt, policy)
        verdict = {0: "PASS", 1: "FINDINGS", 2: "COULD NOT MEASURE (fail closed)"}[code]
        receipt["verdict"] = verdict
        lines = receipt_lines(receipt, verdict)
    except (KeyError, TypeError, ValueError) as exc:
        # A policy missing a nested key must not escape as a traceback: that exits 1, the FINDINGS
        # code, and the CI canary loop would read it as a detection.
        print(
            f"::error::{_PREFIX}: cannot evaluate the run: {exc!r} (fail closed)", file=sys.stderr
        )
        return 2
    print("\n".join(lines))
    if args.summary is not None:
        try:
            with args.summary.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as exc:
            print(f"::warning::{_PREFIX}: could not write the step summary: {exc}", file=sys.stderr)
    level = annotation_level(canary=args.canary, code=code)
    for message in messages:
        print(f"::{level}::{_PREFIX}: {message}", file=sys.stderr)
    if args.receipt is not None:
        try:
            args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"::error::{_PREFIX}: could not write {args.receipt}: {exc}", file=sys.stderr)
            return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
