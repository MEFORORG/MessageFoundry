# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fuzz targets for the tolerant HL7 v2 / X12 / DICOM parsers (ADR 0191), and for the decoders a
body passes through before it reaches them (vault BACKLOG #2683; see the section that adds them).

This module is deliberately **Atheris-free**, so it imports and runs on every platform the engine
supports -- including Windows, where Atheris has no wheel at all. ``fuzz/fuzz_parsers.py`` is the
only Atheris entrypoint and it imports this registry; ``tests/test_fuzz_targets.py`` drives the same
targets under plain pytest, so the harness itself is regression-tested on every CI leg rather than
only on the one advisory job that fuzzes.

**The invariant every target asserts.** Each codec writes its contract down in its own error module:
a malformed or hostile body raises that codec's :class:`ValueError` subclass -- ``HL7PeekError``,
``X12Error``, ``DicomError`` -- so a Router or Handler that already routes ``ValueError`` to the
error/dead-letter path catches it without special-casing the format, and the count-and-log invariant
holds for free. A **missing optional extra** raises ``RuntimeError`` instead, deliberately, so a
deploy/config error is not swallowed as a data error.

A target therefore feeds a parser arbitrary bytes and lets **every other exception propagate**. An
escaping ``IndexError``, ``KeyError``, ``AttributeError`` or ``RecursionError`` is a finding: the
parser accepted a body and then broke its own contract on a path a Router already relies on.

**Parse is not the whole surface, and that is the point.** A Router does not stop at ``parse``; it
reads routing fields off the result. So each target parses *and then* sweeps the accessor tier.
Fuzzing ``parse`` alone would have missed the one finding this harness has produced (an empty
segment, fixed under BACKLOG #1594; see :data:`KNOWN_FINDINGS`).

**What that sweep is, stated accurately, because the first draft justified it wrongly.** It claimed
these are "the accessors the inbound path actually touches". They are not, in both directions, and a
later reader pruning the list by that reason would prune the wrong entries. Measured 2026-09-22
against ``pipeline/wiring_runner.py``, ``transports/`` and ``api/``:

* ``Peek.routing()`` and ``Peek.segments()`` are read **nowhere in the message path** -- zero hits
  across ``pipeline/``, ``transports/`` and ``api/``, against 13 for ``control_id`` on the same
  instrument. (``segments()`` does have one caller elsewhere, ``generators/adt.py``, which is a test
  generator and not the inbound path; the scope of the claim is the three packages named.) The
  sweep drives them anyway, and that is defensible: they are public surface on a pure library, so a
  contract break there is a finding whether or not today's pipeline calls it.
* The pre-ACK path reads **more** than the eleven named properties: ``control_id``,
  ``message_type`` and ``summarize(peek)`` at the ingress commit, then ``build_ack``
  (``transports/mllp.py``) reads eight further accessors before the ACK frame goes out.
* ``Peek.field()`` is the widest input-dependent surface of all -- ``summarize`` alone calls it up
  to seven times, for ``PID-3.1``, ``PID-5.1``, ``PID-5.2`` and, on an ORM/ORU only, ``ORC-2.1``,
  ``OBR-2.1``, ``OBR-3.1`` and ``ORC-3.1`` -- and **no target calls it directly.** The named
  properties reach it internally, which is how that finding surfaced at all; a direct
  ``field()`` target is the obvious next addition and is deliberately not in this change.

**PHI (CLAUDE.md section 9).** Seeds are the repository's committed synthetic samples plus small
inline literals -- no new message-shaped files, and never real PHI. No target prints a body, and the
runner keeps its corpus and crash artifacts **outside the work tree** (see :func:`work_root`), so a
fuzzer-minimised input cannot be staged even by ``git add -A``. That last clause is only true because
:func:`work_root` **refuses** an override resolving inside the repository; it was false for the
override path until the fence landed, and the docstring there records what went wrong.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import functools
import importlib.util
import os
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.framing import STX_ETX_CODEC, FrameDecoder
from messagefoundry.mllpcodec import MLLPDecoder
from messagefoundry.mllpcodec import frame as mllp_frame
from messagefoundry.parsing import HL7PeekError, Peek, TreeNode, parse_tree
from messagefoundry.parsing.binary import MARKER as CARRIAGE_MARKER
from messagefoundry.parsing.binary import (
    BinaryCarriageError,
    DocRefError,
    extract_obx_document,
    is_doc_ref,
    iter_obx_documents,
    parse_doc_ref,
    strip_documents,
)
from messagefoundry.parsing.binary import decode as carriage_decode
from messagefoundry.parsing.compression import (
    CompressionError,
    deflate_compress,
    deflate_decompress,
    deflate_decompress_with_tail,
    gzip_compress,
    gzip_decompress,
    zip_compress,
    zip_decompress,
)
from messagefoundry.parsing.dicom import DicomError, DicomPeek
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.x12 import (
    X12Error,
    X12FrameError,
    X12FrameReader,
    X12Peek,
    X12PeekError,
)
from messagefoundry.parsing.x12 import check_integrity as x12_check_integrity
from messagefoundry.parsing.x12 import split as x12_split
from messagefoundry.transports.http_listener import DEFAULT_MAX_BODY_BYTES as HTTP_MAX_BODY_BYTES
from messagefoundry.transports.http_listener import (
    DEFAULT_MAX_HEADER_BYTES as HTTP_MAX_HEADER_BYTES,
)
from messagefoundry.transports.http_listener import HttpRequestError
from messagefoundry.transports.http_listener import _read_request as read_http_request

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES = _REPO_ROOT / "samples" / "messages"

#: Override to keep a persistent corpus somewhere of your own choosing. Refused if it resolves inside
#: the repository -- see :func:`work_root`.
WORK_DIR_ENV = "MEFOR_FUZZ_WORK_DIR"

#: Process exit code for a harness REFUSAL: a misconfiguration that stopped the run before any input
#: was fuzzed. Distinct from 1 because ``.github/workflows/fuzz.yml`` reads every other non-zero exit
#: as "this parser broke its exception contract", so a refusal exiting 1 publishes a parser finding
#: that never happened. It cannot collide with a libFuzzer exit code: every refusal is raised before
#: ``atheris.Setup``, so libFuzzer has not started and will never choose this process's status.
REFUSAL_EXIT = 3


class HarnessRefusal(ValueError):
    """The harness refused to run because its configuration would do something unsafe or vacuous.

    A ``ValueError`` because it reports a bad *value* in the environment, and a distinct class so the
    entrypoint can map it to :data:`REFUSAL_EXIT` without also catching a parser's contract error.
    """


#: Inputs longer than this are not interesting here: a parse bug reachable at all is reachable in a
#: few kilobytes, and libFuzzer spends its budget on shape rather than on length.
#:
#: **The rationale this comment used to give was backwards.** It said each parser enforces a size
#: ceiling "well below" 8192, making a larger ``max_len`` redundant. Measured 2026-09-22, the
#: ceilings are 16 MiB -- ``DEFAULT_MAX_MESSAGE_BYTES`` (``parsing/peek.py``),
#: ``DEFAULT_MAX_INTERCHANGE_BYTES`` (``parsing/x12/delimiters.py``) and, bounding the *inflated*
#: stream rather than the input, ``DEFAULT_MAX_INFLATED_BYTES`` (``parsing/dicom/_inflate.py``).
#: That is 2048x **above** this value, not below it, so those guards are **unreachable** at this
#: ``max_len``, not redundant. The choice stands on the budget argument alone; nothing here fuzzes a
#: size ceiling, and a run that should exercise one has to raise ``-max_len`` past 16 MiB.
DEFAULT_MAX_LEN = 8192


def _sample(name: str) -> tuple[bytes, ...]:
    """The committed synthetic sample ``name`` as a one-tuple, or empty if it is not present.

    Reusing ``samples/messages/`` keeps the seed corpus synthetic and commits no new
    message-shaped file. Absence is tolerated rather than fatal so a sparse checkout still fuzzes.
    """
    path = _SAMPLES / name
    return (path.read_bytes(),) if path.is_file() else ()


# A bare MSH, an ISA fragment that stops mid-header, and the Part-10 magic with nothing after it.
# Each sits on a different early branch (accepted / truncated envelope / magic-only), which is where
# a mutator gets the most leverage from a tiny seed.
#
# MEASURED for the DICOM one, in CI run 35761703252: from these 132 bytes and nothing else, the
# mutator produced a real contract violation at execution unit 8,326, through pydicom's file-meta
# reader, inside a 60-second budget. A magic-only seed reaching a tier that can report was an open
# question when these were chosen; it is no longer one, so do not shrink this seed on the theory
# that it cannot get anywhere.
#
# An earlier draft also pinned "reached the file-meta reader" to exec #4495. That pairs the wrong
# two facts: #4495's coverage jump follows a warning from `filereader.py:487`, which is the
# end-of-file handler inside `read_dataset`, while the finding's own traceback enters
# `_read_file_meta_info` at `filereader.py:686`. The tier attribution is right and the exec number
# belonged to a different event, so the number is dropped rather than re-pointed.
_MINIMAL_HL7 = b"MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\r"
#: The reproducer of the one finding this harness produced (BACKLOG #1594), kept as a seed so a
#: regression is found from the first input rather than rediscovered by mutation.
BLANK_SEGMENT_HL7 = b"MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\r\rPV1|1|I\r"
_TRUNCATED_X12 = b"ISA*00*          *00*"
_MAGIC_ONLY_DICOM = b"\x00" * 128 + b"DICM"

#: The HL7 routing properties this harness sweeps off a ``Peek``.
#:
#: **Not "every one is on the pre-ACK path", which is what this comment used to claim.** Measured
#: 2026-09-22: six are read pre-ACK by ``build_ack`` (``sending_app``, ``sending_facility``,
#: ``receiving_app``, ``receiving_facility``, ``version``, ``control_id``), ``message_type`` is read
#: at the ingress commit, and ``message_code`` is reached pre-ACK inside ``summarize`` (it selects
#: the ORM/ORU branch). That leaves ``trigger_event``, ``message_structure`` and ``timestamp`` with
#: no pre-ACK reader found.
#:
#: **"Unique to this sweep" is a separate question from "pre-ACK", and the two must not be read as
#: one.** ``Peek.routing()`` independently reads eight of the eleven, so a fault injected on any of
#: those eight is still caught with this loop deleted; only the three MSH-9 components --
#: ``message_code``, ``trigger_event``, ``message_structure`` -- are reachable *solely* through this
#: loop, which is what makes the loop earn its place and what the pinning test keys on. See the
#: module docstring for the full accounting, including what the pre-ACK path reads that is NOT
#: listed here.
_HL7_ROUTING_PROPERTIES = (
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

#: The X12 interchange-identity properties, read by fixed ISA offset.
_X12_ISA_PROPERTIES = (
    "sender_qual",
    "sender_id",
    "receiver_qual",
    "receiver_id",
    "date",
    "time",
    "version",
    "control_number",
    "usage",
    "is_test",
)


@dataclass(frozen=True)
class KnownFinding:
    """A contract violation this harness has already produced, filed rather than fixed here.

    Registered for one reason: an advisory job that is red the day it lands gets ignored, and an
    ignored fuzzer is indistinguishable from no fuzzer. So a found-but-unfixed defect is recorded
    with a **narrow** discriminator -- one named structural condition, never a bare exception type --
    and ``tests/test_fuzz_targets.py`` asserts both halves: that ``reproducer`` still provokes the
    violation through the raw parser, and that the target recognises it. The day the underlying
    defect is fixed, that test fails and this entry comes out. It cannot rot silently into a
    suppression that hides its successors.
    """

    target: str
    #: What the parser does, in the conditional -- there are no deployments (CLAUDE.md section 0).
    summary: str
    #: The narrow structural condition the target matches on, in words.
    discriminator: str
    reproducer: bytes


#: The harness's first finding -- an empty segment (a ``\r\r`` run) parsed, then every named routing
#: property raised ``IndexError`` -- was fixed under BACKLOG #1594, and its entry and the carve-out in
#: :func:`_hl7_peek` came out with it. Its reproducer stays on as the :data:`BLANK_SEGMENT_HL7` seed,
#: and ``tests/test_fuzz_targets.py`` drives it, so the fix cannot quietly regress.
#:
#: The entry below was produced by the ``binary_carriage`` target within its first 299 executions,
#: on the run that introduced it (vault BACKLOG #2683). It is not filed under a number of its own
#: here: a ledger number is allocated in the maintainer-internal repository, not cited before it is.
KNOWN_FINDINGS: tuple[KnownFinding, ...] = (
    KnownFinding(
        target="binary_carriage",
        summary=(
            "strip_documents, iter_obx_documents and extract_obx_document raise a bare ValueError "
            "('cannot determine HL7 separators') on an HL7 body whose MSH-2 carries fewer than four "
            "encoding characters. Peek.parse and Message.parse both accept such a body, and build_ack "
            "answers it AA; Message.field then raises on the first read. The store "
            "backends' retention document-strip pass calls strip_documents with no try, so one such "
            "stored body would abort that pass on every run, and the over-threshold ingress detach "
            "in pipeline/wiring_runner.py does not list ValueError among the errors it records."
        ),
        discriminator=(
            "Message.parse accepts the text and Message._encoding_chars() raises ValueError on the "
            "parsed message"
        ),
        reproducer=(
            b"MSH|^~|A|B|C|D|20260101||ORU^R01|X1|P|2.5\r"
            b"OBX|1|ED|X||^Application^pdf^Base64^JVBERi0=\r"
        ),
    ),
)


def _hl7_peek(data: bytes) -> None:
    """``Peek.parse`` plus a sweep of the accessor tier (see the module docstring for which).

    There is no carve-out: every exception other than the contracted ``HL7PeekError`` escapes, and
    ``tests/test_fuzz_targets.py`` pins that with injected faults.
    """
    try:
        peek = Peek.parse(data)
    except HL7PeekError:
        return  # The contract: these bytes are not an HL7 message at all.
    for name in _HL7_ROUTING_PROPERTIES:
        getattr(peek, name)
    peek.routing()
    peek.segments()


def _walk_tree(node: TreeNode) -> None:
    """Touch every label and value in a parsed tree.

    HL7 nesting is bounded at segment/field/repetition/component/subcomponent, so a plain recursive
    walk cannot run away on a mutated input.
    """
    _ = (node.label, node.value)
    for child in node.children:
        _walk_tree(child)


def _hl7_tree(data: bytes) -> None:
    """``parse_tree`` -- the tolerant structural view the harness's parse-tree pane renders."""
    try:
        nodes = parse_tree(data)
    except HL7PeekError:
        return
    for node in nodes:
        _walk_tree(node)


def _x12_peek(data: bytes) -> None:
    """``X12Peek.parse`` plus the ISA identity properties and the segment/group walk."""
    try:
        peek = X12Peek.parse(data)
    except X12Error:
        return
    for name in _X12_ISA_PROPERTIES:
        getattr(peek, name)
    peek.groups()
    peek.transaction_ids()
    peek.segment_ids()


def _dicom_peek(data: bytes) -> None:
    """``DicomPeek.parse``.

    The result is a frozen dataclass of already-materialised strings, so there is no accessor tier
    to exercise -- unlike HL7 and X12, ``parse`` really is the whole surface here. The property
    under test is whether the ``except parse_error_types()`` wrap in ``dicom/peek.py`` covers what
    ``pydicom`` throws at it. It does not cover everything by construction: the tuple is a list of
    the classes found so far, and this target found one it missed (BACKLOG #1893). A gap surfaces
    as a non-``DicomError`` escaping here.
    """
    try:
        DicomPeek.parse(data)
    except DicomError:
        return


# --- The decoders IN FRONT of the parsers (vault BACKLOG #2683) -------------------------------------
#
# The four targets above start at a complete message. Every byte an attacker sends reaches them only
# after one of the decoders below has run on it: a stream reassembler (MLLP, raw TCP, X12-over-TCP),
# the HTTP intake head parser, a decompressor on a file feed, or the binary-carriage helpers. All of
# them are pure over bytes (or over a str decoded from bytes), so they fuzz in-process exactly like the
# parsers. The surfaces checked and ruled out are listed in `fuzz/README.md`, with the reason for each.
#
# Three of these targets assert more than "no undocumented exception escapes", and the extra assertion
# is always a property the decoder's own docstring states. A violation raises AssertionError, which
# is not any codec's contract error, so libFuzzer records it like any other escape.

#: The cap the capped stream-decoder runs use. Small on purpose: the shipped default is 16 MiB, which
#: no input of DEFAULT_MAX_LEN bytes can reach, so a run at the real default never touches the cap
#: path at all. A few hundred bytes puts the cap inside what the mutator generates.
_STREAM_CAP = 256
#: The X12 equivalent. It must exceed one 106-byte ISA header, or the cap can only fire before an
#: interchange could ever complete -- see `X12FrameReader._check_cap`.
_X12_STREAM_CAP = 512
#: The decompressed-size ceiling for the compression target. Far below any real deployment's value and
#: far above anything a valid seed inflates to, so a mutated stream reaches the bomb refusal quickly
#: without each execution spending time inflating megabytes.
_INFLATE_CEILING = 64 * 1024


def _chunks(stream: bytes, step: int) -> list[bytes]:
    """``stream`` cut into reads of ``step`` bytes, the way a socket may deliver it."""
    return [stream[i : i + step] for i in range(0, len(stream), step)]


def _new_frame_decoder(selector: int, cap: int | None) -> FrameDecoder:
    """The MLLP listener's decoder for an even ``selector``, the raw-TCP STX/ETX one for an odd one.

    Both are the same :class:`FrameDecoder` loop; what differs is the delimiters and the error class.
    ``MLLPDecoder`` raises ``MLLPFrameError``, and ``transports/mllp.py`` catches that name, so the
    error class is part of what is under test rather than a detail.
    """
    if selector & 1:
        return STX_ETX_CODEC.decoder(max_frame_bytes=cap)
    return MLLPDecoder(max_frame_bytes=cap)


def _drain(
    feed: Callable[[bytes], Iterable[bytes]],
    refusal: type[Exception],
    reads: Sequence[bytes],
) -> tuple[list[bytes], bool]:
    """Feed ``reads`` in order through a stream decoder: ``(completed, refused_over_cap)``.

    Only ``refusal`` is caught; anything else escapes, which is the point of the target.
    """
    completed: list[bytes] = []
    try:
        for read in reads:
            for item in feed(read):
                completed.append(item)
    except refusal:
        return completed, True
    return completed, False


def _drain_frames(decoder: FrameDecoder, reads: Sequence[bytes]) -> tuple[list[bytes], bool, bool]:
    """:func:`_drain` for a frame decoder, plus whether a frame is still open at the end.

    Only ``decoder.error_class`` counts as a refusal. A plain ``FrameError`` out of an MLLP decoder
    would slip past the ``except MLLPFrameError`` the listener relies on, so it must escape here.
    """
    payloads, refused = _drain(decoder.feed, decoder.error_class, reads)
    return payloads, refused, decoder.in_frame


def _stream_frames(data: bytes) -> None:
    """MLLP / raw-TCP frame reassembly (``framing.FrameDecoder``), split-invariance and the cap.

    The first byte is a control byte, not stream content: its low bit picks the codec and the rest
    picks a read size of 1 to 32 bytes. Three runs over the remaining bytes:

    * **One read versus many.** The decoder's documented job is that "a real peer may split a message
      across reads or pack several into one", so the payloads, and whether a frame is still open at
      the end, must not depend on where the reads were cut. A difference raises AssertionError.
    * **Capped.** With a small ``max_frame_bytes`` the only allowed exception is the decoder's own
      ``error_class``, and no yielded payload may exceed the cap: an over-cap frame must raise, never
      be delivered.
    """
    if not data:
        return
    selector, stream = data[0], data[1:]
    reads = _chunks(stream, (selector >> 1) % 32 + 1)
    whole = _drain_frames(_new_frame_decoder(selector, None), [stream])
    split = _drain_frames(_new_frame_decoder(selector, None), reads)
    if whole != split:
        raise AssertionError("frame decoder output depends on how the stream was split into reads")
    payloads, _refused, _open = _drain_frames(_new_frame_decoder(selector, _STREAM_CAP), reads)
    if any(len(payload) > _STREAM_CAP for payload in payloads):
        raise AssertionError("frame decoder delivered a payload larger than max_frame_bytes")


def _drain_x12(reader: X12FrameReader, reads: Sequence[bytes]) -> tuple[list[bytes], bool]:
    """:func:`_drain` for an X12 frame reader, whose one refusal is ``X12FrameError``."""
    return _drain(reader.feed, X12FrameError, reads)


def _x12_frames(data: bytes) -> None:
    """X12-over-TCP interchange reassembly (``X12FrameReader``), plus ``split`` and ``check_integrity``.

    The first byte picks a read size of 1 to 64 bytes, which is enough to cut a 106-byte ISA header,
    and the CR+LF terminator the reader has to wait for, across reads. Asserted:

    * **One read versus many** must yield the same interchanges, for the reason given on
      :func:`_stream_frames`.
    * Every yielded interchange starts with ``ISA``: the reader drops inter-interchange noise, and a
      frame that kept some would hand a non-X12 body to the parser as if it were one.
    * **Capped**, only ``X12FrameError`` may escape and no yielded interchange may exceed the cap.

    Then the str-level :func:`split` over the same bytes, and :func:`check_integrity` over each
    interchange, both of which document ``X12PeekError`` as their only refusal.
    """
    if not data:
        return
    selector, stream = data[0], data[1:]
    reads = _chunks(stream, selector % 64 + 1)
    whole, _ = _drain_x12(X12FrameReader(), [stream])
    split, _ = _drain_x12(X12FrameReader(), reads)
    if whole != split:
        raise AssertionError(
            "X12 frame reader output depends on how the stream was split into reads"
        )
    if any(not frame.startswith(b"ISA") for frame in whole):
        raise AssertionError("X12 frame reader yielded an interchange that does not start with ISA")
    capped, _refused = _drain_x12(X12FrameReader(max_interchange_bytes=_X12_STREAM_CAP), reads)
    if any(len(frame) > _X12_STREAM_CAP for frame in capped):
        raise AssertionError("X12 frame reader delivered an interchange over max_interchange_bytes")
    # latin-1 maps every byte, so this decode cannot fail and every input reaches the str surfaces.
    with contextlib.suppress(X12PeekError):
        x12_split(stream.decode("latin-1"))
    for frame in whole:
        with contextlib.suppress(X12PeekError):
            x12_check_integrity(frame.decode("latin-1"))


@functools.cache
def _event_loop() -> asyncio.AbstractEventLoop:
    """One private loop for the HTTP target, reused across executions.

    A fresh ``asyncio.run`` per input costs more than the parse it wraps, and libFuzzer's throughput is
    the budget. The loop is never the running loop of anything else: it only ever runs one
    ``run_until_complete`` at a time, from a synchronous caller.
    """
    loop = asyncio.new_event_loop()
    atexit.register(loop.close)
    return loop


async def _read_every_request(data: bytes) -> None:
    """Read pipelined requests from ``data`` until EOF or the first refusal, as one connection would.

    The reader is fed the whole input and EOF before the first read, so no await ever suspends: a
    short body or head raises ``IncompleteReadError`` inside the listener, which maps it to its own
    refusal. The reader's limit is asyncio's default, which is what ``asyncio.start_server`` gives
    the listener's connections.
    """
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    while not reader.at_eof():
        try:
            request = await read_http_request(
                reader,
                max_header_bytes=HTTP_MAX_HEADER_BYTES,
                max_body_bytes=HTTP_MAX_BODY_BYTES,
            )
        except HttpRequestError:
            return  # the contract: refused before any ingress row, answered with its status
        _ = (request.method, request.target, request.headers, request.body, request.repeated)


def _http_request(data: bytes) -> None:
    """The HTTP intake listener's request reader (``transports/http_listener.py``), pre-ingress.

    This is the unauthenticated half of the HTTP source: the head is parsed before any credential is
    examined, so every byte here is attacker-chosen. ``HttpRequestError`` is the documented refusal,
    and it is NOT a ``ValueError`` -- the listener catches it by name and answers with its status.
    Anything else escaping is a request that would reach the listener's last-resort handler instead.

    It drives a private function, ``_read_request``, deliberately: that is the exact composition the
    listener runs (head, then body, with the header and body caps), and the public surface is a socket
    server, which needs a live endpoint and is out of scope here (ADR 0191).
    """
    _event_loop().run_until_complete(_read_every_request(data))


def _compression(data: bytes) -> None:
    """Every decompressor in ``parsing/compression.py``, on the same bytes, with a ceiling.

    ``gzip_decompress`` is what the File connector runs on a ``decompress="gzip"`` feed, before the
    content sniff and the batch split; the rest are Handler-facing. Each documents exactly one error
    type, ``CompressionError``, for every corrupt, truncated, over-ceiling or unsupported input, and
    each documents that a bomb is refused after producing at most the ceiling. So an accepted result
    larger than the ceiling is a finding as well, raised as AssertionError.

    ``zip_decompress`` also runs the archive-member admission checks in ``parsing/sniff.py`` on every
    member it accepts, so those are exercised here rather than by a target of their own.
    """
    for decompress in (gzip_decompress, deflate_decompress):
        try:
            out = decompress(data, max_output_bytes=_INFLATE_CEILING)
        except CompressionError:
            continue
        if len(out) > _INFLATE_CEILING:
            raise AssertionError(f"{decompress.__name__} returned more than its ceiling")
    try:
        body, tail = deflate_decompress_with_tail(data, max_output_bytes=_INFLATE_CEILING)
    except CompressionError:
        pass
    else:
        if len(body) > _INFLATE_CEILING:
            raise AssertionError("deflate_decompress_with_tail returned more than its ceiling")
        if not data.endswith(tail):
            raise AssertionError(
                "deflate_decompress_with_tail returned a tail that is not the input's"
            )
    try:
        members = zip_decompress(data, max_output_bytes=_INFLATE_CEILING)
    except CompressionError:
        return
    if sum(len(member) for member in members.values()) > _INFLATE_CEILING:
        raise AssertionError("zip_decompress returned more than its ceiling in total")


def _binary_carriage(data: bytes) -> None:
    """The binary-carriage and embedded-document helpers in ``parsing/binary.py`` (ADR 0028, 0042, 0105).

    The bytes are decoded the way the inbound path decodes a body (UTF-8, ``replace``), then:

    * ``decode`` of a carriage string built from them -- ``BinaryCarriageError`` is its refusal;
    * ``parse_doc_ref`` when the text claims to be a handle -- ``DocRefError`` is its refusal;
    * ``strip_documents``, bare and as a carriage value, with **no** exception allowed at all. The
      retention pass in each store backend calls it on every stored body with no ``try``, so a raise
      here would abort the whole pass, not just skip one row. Its docstring promises that a body it
      does not strip comes back unchanged;
    * after ``Message.parse`` (``HL7PeekError`` is its refusal), ``iter_obx_documents`` -- the ingress
      document-detach scan, which documents no refusal -- and ``extract_obx_document`` on every OBX,
      whose refusal is ``BinaryCarriageError``.

    The HL7 half carries the one carve-out in this file, for the registered known finding: see
    :data:`KNOWN_FINDINGS` and :func:`_separators_undeterminable`.
    """
    text = data.decode("utf-8", "replace")
    with contextlib.suppress(BinaryCarriageError):
        carriage_decode(CARRIAGE_MARKER + text)
    if is_doc_ref(text):
        with contextlib.suppress(DocRefError):
            parse_doc_ref(text)
    # A carriage value never reaches the HL7 path, so this call needs no carve-out.
    strip_documents(CARRIAGE_MARKER + text, pruned_at=0.0)
    try:
        _strip_and_scan_hl7(text)
    except ValueError:
        if not _separators_undeterminable(text):
            raise
        # The registered known finding. Narrow on purpose: any other ValueError escapes.


def _strip_and_scan_hl7(text: str) -> None:
    """The HL7 half of :func:`_binary_carriage`: the retention strip, the detach scan, the extract."""
    strip_documents(text, pruned_at=0.0)
    try:
        message = Message.parse(text)
    except HL7PeekError:
        return
    list(iter_obx_documents(message))
    for occurrence in range(1, message.count_segments("OBX") + 1):
        with contextlib.suppress(BinaryCarriageError):
            extract_obx_document(message, occurrence=occurrence)


def _separators_undeterminable(text: str) -> bool:
    """The :data:`KNOWN_FINDINGS` discriminator: ``Message.parse`` accepts ``text``, and the parsed
    message's own separators cannot be read back.

    That is exactly the condition under which ``Message._encoding_chars`` raises the bare
    ``ValueError`` behind the finding, so the check calls it rather than restating its rule: MSH-1 must
    be one character and MSH-2 at least four. A private method, deliberately -- a copy of the rule here
    would drift from the engine's and widen or narrow the carve-out without anyone noticing.
    """
    try:
        message = Message.parse(text)
    except HL7PeekError:
        return False
    try:
        message._encoding_chars()
    except ValueError:
        return True
    return False


@dataclass(frozen=True)
class FuzzTarget:
    """One named fuzz target: a callable over arbitrary bytes, plus its seeds.

    ``run`` returns normally when the parser behaved to contract -- whether it accepted the input or
    rejected it with its own ``ValueError`` subclass -- and raises otherwise. libFuzzer needs no
    more than that: a raised exception is the crash it records and minimises.
    """

    name: str
    summary: str
    run: Callable[[bytes], None]
    seeds: tuple[bytes, ...]
    #: The optional extra this target's parser needs, if any. A target whose extra is absent is
    #: **refused**, never silently skipped -- see :meth:`available`.
    requires_module: str | None = None

    def available(self) -> bool:
        """Whether this target's optional dependency is importable.

        The runner refuses to fuzz an unavailable target rather than passing over it, because a
        target that silently does nothing is the failure this whole harness exists to avoid: a
        clean run and a run that never executed look identical from the outside.
        """
        if self.requires_module is None:
            return True
        return importlib.util.find_spec(self.requires_module) is not None


def _x12_stream_seeds() -> tuple[bytes, ...]:
    """The committed X12 sample as a stream: once whole, once twice over with noise in front.

    The leading control byte picks the read size (see :func:`_x12_frames`): 0 is one-byte reads, 37 is
    38-byte reads, which cut the ISA header mid-element.
    """
    seeds: list[bytes] = [b"\x00" + _TRUNCATED_X12]
    for sample in _sample("x12_270_eligibility.edi"):
        seeds += [b"\x00" + sample, b"\x25" + b"\r\nnoise" + sample + sample]
    return tuple(seeds)


#: Stream seeds for `_stream_frames`. The leading byte is the control byte: even is MLLP, odd STX/ETX.
_FRAME_SEEDS = (
    b"\x00" + mllp_frame(_MINIMAL_HL7) + mllp_frame(BLANK_SEGMENT_HL7),
    b"\x0e" + b"\r\n" + mllp_frame(_MINIMAL_HL7) + b"\x0b" + _MINIMAL_HL7[:20],
    b"\x01" + b"\x02" + _TRUNCATED_X12 + b"\x03" + b"\x02ISA",
)

#: HTTP intake seeds: one POST carrying an HL7 body, a health probe, and two pipelined requests.
_HTTP_POST = (
    b"POST /hl7 HTTP/1.1\r\nHost: localhost\r\nContent-Type: x-application/hl7-v2+er7\r\n"
    + f"Content-Length: {len(_MINIMAL_HL7)}\r\n\r\n".encode("ascii")
    + _MINIMAL_HL7
)
_HTTP_SEEDS = (
    _HTTP_POST,
    b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    _HTTP_POST + b"HEAD / HTTP/1.0\r\nContent-Length: 0\r\n\r\n",
)

#: Compression seeds: one valid stream per codec, plus a deflate stream with a trailing CR+LF -- the
#: PDF FlateDecode shape `deflate_decompress_with_tail` exists for. Built by the engine's own
#: compressors, which are deterministic (fixed gzip mtime and zip dates), so the seeds are stable.
_COMPRESSION_SEEDS = (
    gzip_compress(_MINIMAL_HL7),
    deflate_compress(_MINIMAL_HL7),
    deflate_compress(_MINIMAL_HL7) + b"\r\n",
    zip_compress({"adt.hl7": _MINIMAL_HL7, "sub/notes.txt": b"synthetic"}),
)

#: Binary-carriage seeds: an HL7 message with one OBX-5 ED Base64 document (a PDF header, synthetic),
#: a bare base64 value, and a live document handle with a 64-hex content address.
_BINARY_SEEDS = (
    _MINIMAL_HL7 + b"OBX|1|ED|DOC^Document||^Application^pdf^Base64^JVBERi0xLjQKJQ==\r",
    b"JVBERi0xLjQKJQ==",
    b"mfdoc:v1:ref:" + b"0" * 64 + b":application/pdf",
)


TARGETS: tuple[FuzzTarget, ...] = (
    FuzzTarget(
        name="hl7_peek",
        summary="tolerant HL7 v2 peek (the built-in parser) plus the pre-ACK routing accessors",
        run=_hl7_peek,
        seeds=_sample("adt_a01.hl7") + _sample("adt_batch.hl7") + (_MINIMAL_HL7, BLANK_SEGMENT_HL7),
    ),
    FuzzTarget(
        name="hl7_tree",
        summary="tolerant HL7 v2 structural tree (parsing/tree.py)",
        run=_hl7_tree,
        seeds=_sample("adt_a01.hl7") + (_MINIMAL_HL7,),
    ),
    FuzzTarget(
        name="x12_peek",
        summary="tolerant X12 interchange peek plus the ISA identity and segment walk",
        run=_x12_peek,
        seeds=_sample("x12_270_eligibility.edi") + (_TRUNCATED_X12,),
    ),
    FuzzTarget(
        name="dicom_peek",
        summary="tolerant DICOM Part-10 peek (needs the [dicom] extra)",
        run=_dicom_peek,
        seeds=(_MAGIC_ONLY_DICOM,),
        requires_module="pydicom",
    ),
    FuzzTarget(
        name="stream_frames",
        summary="MLLP and raw-TCP frame reassembly: exception contract, split-invariance and the cap",
        run=_stream_frames,
        seeds=_FRAME_SEEDS,
    ),
    FuzzTarget(
        name="x12_frames",
        summary="X12-over-TCP interchange reassembly plus split and check_integrity",
        run=_x12_frames,
        seeds=_x12_stream_seeds(),
    ),
    FuzzTarget(
        name="http_request",
        summary="HTTP intake listener request head and body reader, before authentication",
        run=_http_request,
        seeds=_HTTP_SEEDS,
    ),
    FuzzTarget(
        name="compression",
        summary="gzip, deflate and zip decompression with a ceiling (parsing/compression.py)",
        run=_compression,
        seeds=_COMPRESSION_SEEDS,
    ),
    FuzzTarget(
        name="binary_carriage",
        summary="binary carriage, document handles, and the OBX-5 ED detach, extract and strip",
        run=_binary_carriage,
        seeds=_BINARY_SEEDS,
    ),
)

TARGETS_BY_NAME = {target.name: target for target in TARGETS}


def write_seed_corpus(target: FuzzTarget, directory: Path) -> int:
    """Materialise ``target``'s seeds into ``directory`` and return how many were written.

    libFuzzer takes a corpus as a directory of files, and the seeds live in this module as literals
    and committed-sample reads, so somebody has to put them on disk. Each file is named by index
    rather than by content, so a re-run overwrites in place instead of growing the directory.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for index, seed in enumerate(target.seeds):
        (directory / f"seed_{index:03d}").write_bytes(seed)
    return len(target.seeds)


def work_root() -> Path:
    """Base directory for seed corpora and crash artifacts, from :data:`WORK_DIR_ENV` or a temp dir.

    **Outside the repository, and that is the control rather than a convenience.** Every file the
    fuzzer writes here is message-shaped -- a minimised HL7, X12 or DICOM body -- and a corpus grows
    without bound as the fuzzer finds branches, so an overnight run leaves thousands of generated
    message files. Ignoring them would rely on a pattern staying correct; keeping them outside the
    work tree means ``git add -A`` cannot reach them at all, which is how the PHI rule (CLAUDE.md
    section 9) holds by construction instead of by a reviewer noticing.

    **The override is fenced, and "by construction" was false without the fence.** This function
    previously returned ``Path(override)`` unexamined, so the guarantee above held for the default
    and for an absolute path pointing elsewhere -- but a **relative** override resolves against the
    working directory, and ``fuzz/README.md`` tells the operator to run the module from the
    repository root. So ``MEFOR_FUZZ_WORK_DIR=corpus`` put fuzzer-minimised message bodies inside
    the work tree, reachable by ``git add -A``, while this docstring said that could not happen.

    A leading ``~`` is the same fault wearing a disguise, and it is the one the README hands out.
    ``Path("~/mefor-fuzz")`` is *relative*: measured 2026-09-22, it resolves to
    ``<repo root>/~/mefor-fuzz``. A POSIX shell expands the tilde before the value is ever set, so
    the README's recipe is safe on an interactive bash line -- but the expansion belongs to the
    shell, not to the value, and every mechanism that sets an environment variable **without** a
    shell passes the tilde through intact: a quoted assignment, a Dockerfile ``ENV``, a systemd
    unit, a CI ``env:`` block, or a non-POSIX shell such as PowerShell.

    Both halves are fixed: ``expanduser`` first, so the tilde means the same thing however the value
    arrived, then a refusal if the result still lands inside :data:`_REPO_ROOT`. Refusing loudly
    beats writing there quietly. Three reviews checked this function and all three passed an
    absolute path, which is the one shape that cannot show either fault.

    That is also why sharing a seed by committing it is the wrong move: a seed belongs in this
    module, as a committed synthetic sample path or a small inline literal.

    :raises HarnessRefusal: if the override resolves to the repository root or anywhere beneath it.
    """
    override = os.environ.get(WORK_DIR_ENV)
    if override:
        resolved = Path(override).expanduser().resolve()
        if resolved == _REPO_ROOT or _REPO_ROOT in resolved.parents:
            raise HarnessRefusal(
                f"{WORK_DIR_ENV}={override!r} resolves to {resolved}, which is inside the "
                f"repository at {_REPO_ROOT}. The fuzzer writes minimised message bodies there and "
                f"`git add -A` would stage them (CLAUDE.md section 9). Point it outside the work "
                f"tree; note that PowerShell does not expand a leading `~` the way bash does, so "
                f"give an absolute path or use $HOME/mefor-fuzz."
            )
        return resolved
    return Path(tempfile.gettempdir()) / "messagefoundry-fuzz"


def work_paths(target: FuzzTarget) -> tuple[Path, Path]:
    """``(corpus, artifacts)`` for ``target``, both under :func:`work_root`."""
    base = work_root() / target.name
    return base / "corpus", base / "artifacts"


def libfuzzer_argv(argv: Sequence[str], corpus: Path, artifacts: Path) -> list[str]:
    """``argv`` with this harness's defaults appended, never overriding what a caller passed.

    Kept here, beside the targets, rather than in the Atheris entrypoint: that entrypoint cannot be
    imported off Linux, so logic living there would be untestable on most of the CI matrix. The
    defaulting is load-bearing enough to want a test -- if ``-artifact_prefix`` goes missing,
    libFuzzer writes a minimised, message-shaped crash input into the current working directory,
    which is how such a file ends up staged (CLAUDE.md section 9).

    Each default is supplied **only when absent**, because libFuzzer takes the last occurrence of a
    repeated flag: appending unconditionally would silently clobber a caller's own choice.
    """
    result = list(argv)
    supplied = result[1:]
    if not any(arg.startswith("-artifact_prefix=") for arg in supplied):
        # The trailing separator is required -- libFuzzer concatenates prefix and filename.
        result.append(f"-artifact_prefix={artifacts}{os.sep}")
    if not any(arg.startswith("-max_len=") for arg in supplied):
        result.append(f"-max_len={DEFAULT_MAX_LEN}")
    if all(arg.startswith("-") for arg in supplied):
        # libFuzzer's one positional is the corpus directory it reads and grows.
        result.append(str(corpus))
    return result
