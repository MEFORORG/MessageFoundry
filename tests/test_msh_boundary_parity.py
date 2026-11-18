# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3759 items 3.1 and 3.2: the ``MSH``-boundary readings in ``parsing/split.py``.

The four readings (the split, the ingress guard's, the delivery's and the whole-file byte scan)
spelled the boundary each its own way, and a clean outbound payload paid two scans. They now find
it through one predicate, ``split._next_boundary`` (BACKLOG #4972), and one scan settles a clean
payload. Those were refactors, so every decision must
be the one the code made before it: each reading is checked against a copy of its body as it
stood before, over every string of up to four tokens drawn from the shapes the readings tell
apart, and a seeded sample of longer ones.

The copies are the oracle for that refactor. A later change that means to alter a reading edits
its copy in the same commit, and says so; never edit one only to make a failure go away. The
split's copy calls the live ``normalize`` and ``_LEADING_WS_STR``, so it pins the boundary, not
those. That the delivery reading agrees with the ingress one is AC-7's test, in
``tests/test_one_frame_one_message.py``, not this file's. Synthetic data only.

BACKLOG #5918 widened three readings on purpose, and edited their copies here to match: the
split, the ingress guard and the byte scan now take a later ``MSH`` line that byte order marks
lead as a boundary, as the delivery reading already did, and the split cuts past those marks.
Each edited line says what it read at a0a5e4f5a4.

BACKLOG #5806 changed the split on purpose, and only by dropping lines: an ``MSH``-led message no
longer ends with the run of envelope trailer lines (``BTS``, ``FTS``, ``BHS`` or ``FHS``, then that
message's own MSH-1) that followed it. The split's copy is left as it stood, so it is the oracle
for every other cut: the live split must give the copy's messages less those trailer lines, and
nothing else (:func:`_less_the_trailer`). The byte scan and its copy are unchanged. The whole-file
split is held to a copy of origin/main's, on that scan: each message it re-encodes must come back
less the same lines. A file it hands over as its bytes must come back, under a codec that writes
ASCII as itself, as its decoded text less the same trailer lines, line ends and leading whitespace
kept, re-encoded (:func:`_old_bytes_less_the_trailer`), and under any other codec as its bytes,
unchanged. The corpus gained trailer tokens and the shapes a review of that change named.
"""

from __future__ import annotations

import codecs
import itertools
import random
import re
from collections.abc import Callable
from typing import Any, SupportsIndex

import pytest

from messagefoundry.parsing import normalize, split
from messagefoundry.parsing.sniff import _LEADING_WS_STR

BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"

# --- the readings as they stood at engine origin/main a0a5e4f5a4, verbatim but for names and ---
# --- the lines marked BACKLOG #5918, which widen the boundary ------------------------------------

# BACKLOG #5918: was r"(?=\rMSH)"; byte order marks may now sit between the CR and the MSH.
_OLD_MSH_BOUNDARY = re.compile(r"(?=\r" + BOM + r"*MSH)")
_OLD_FIRST_KEPT = re.compile(r"\S")
_OLD_LEADS_WITH_MSH_PAST_BOM = re.compile(r"[\s" + BOM + r"]*MSH")
_OLD_LATER_MSH_PAST_BOM = re.compile(r"[\r\n]" + BOM + r"+MSH")
_OLD_LEADING_BOM = re.compile(rb"\s*\xef\xbb\xbf")
#: BACKLOG #5918: the later MSH lines the ingress guard and the byte scan now read, marks and all.
_OLD_LATER_MSH_CR = re.compile(r"\r" + BOM + r"*MSH")
#: The byte scan reads any run of the mark's three bytes, a superset that only costs a decode.
_OLD_LATER_MSH_BYTES_PAST_BOM = re.compile(rb"[\r\n][\xef\xbb\xbf]+MSH")


def _old_holds_more_than_one_message(text: str) -> bool:
    first = _OLD_FIRST_KEPT.search(text)
    if first is None:
        return False
    start = first.start()
    later = len(_OLD_LATER_MSH_CR.findall(text, start))  # BACKLOG #5918: was text.count("\rMSH")
    return later > 1 or (later == 1 and text.startswith("MSH", start))


def _old_sends_more_than_one_message(payload: str) -> bool:
    lead = _OLD_LEADS_WITH_MSH_PAST_BOM.match(payload)
    if lead is None:
        return False
    start = lead.end()
    if payload.find("\rMSH", start) >= 0 or payload.find("\nMSH", start) >= 0:
        return True
    return BOM in payload and _OLD_LATER_MSH_PAST_BOM.search(payload, start) is not None


def _old_writes_ascii_as_itself(encoding: str) -> bool:
    """The codec test ``_old_needs_a_decode`` opens with, named for BACKLOG #5806's use of it."""
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        return False
    return name in {"utf-8", "ascii"} or name.startswith(("iso8859-", "cp125"))


def _old_needs_a_decode(raw: bytes, encoding: str) -> bool:
    if not _old_writes_ascii_as_itself(encoding):
        return True
    name = codecs.lookup(encoding).name
    if name == "utf-8" and _OLD_LEADING_BOM.match(raw):
        return True
    if b"\rMSH" in raw or b"\nMSH" in raw:
        return True
    # BACKLOG #5918: a later MSH that UTF-8 byte order marks lead now needs a decode too.
    return _OLD_LATER_MSH_BYTES_PAST_BOM.search(raw) is not None


def _old_split_batch(raw: str | bytes) -> list[str]:
    text = normalize(raw)
    first, *rest = _OLD_MSH_BOUNDARY.split(text)
    messages = [chunk[1:].lstrip(BOM) for chunk in rest]  # BACKLOG #5918: was chunk[1:]
    head = first.lstrip(_LEADING_WS_STR)
    while head.startswith(("FHS", "BHS")):
        head = head.partition("\r")[2].lstrip(_LEADING_WS_STR)
    if head.strip():
        messages.insert(0, head)
    return messages or [text]


_OLD_LEADS_WITH_MSH = re.compile(r"\s*MSH")


def _old_split_batch_bytes(raw: bytes, encoding: str) -> list[bytes]:
    """``split_batch_bytes`` and ``one_message_bytes`` as they stood, on the copies above."""
    if not _old_needs_a_decode(raw, encoding):
        return [raw]
    try:
        text = raw.decode(encoding)
    except (UnicodeError, LookupError):
        return [raw]
    messages = _old_split_batch(text)
    if len(messages) == 1:
        if _OLD_LEADS_WITH_MSH.match(text) or not messages[0].startswith("MSH"):
            return [raw]
        return [messages[0].encode(encoding)]
    return [message.encode(encoding) for message in messages]


#: BACKLOG #5806: the ids a trailer line opens with.
_TRAILER_IDS = ("BTS", "FTS", "BHS", "FHS")


def _less_the_trailer(message: str) -> str:
    """BACKLOG #5806, written over lines rather than as the live scan from the end: an ``MSH``-led
    message less the run of lines that ends it, past one final CR, each of which opens with a
    trailer id and then the message's own MSH-1, when that is ASCII. The CR before the run
    stays."""
    if not message.startswith("MSH") or len(message) < 4 or message[3] == "\r":
        return message
    if not message[3].isascii():
        return message
    separator = message[3]
    lines = message.split("\r")
    last = len(lines) - 1 if lines[-1] == "" else len(lines)
    first = last
    while first > 1 and lines[first - 1][:3] in _TRAILER_IDS and lines[first - 1][3:4] == separator:
        first -= 1
    if first == last:
        return message
    return "\r".join(lines[:first]) + "\r"


def _only_trailer_lines_gone(new: list[str], old: list[str]) -> bool:
    """Whether each of ``new`` is its ``old`` message, or that message less a suffix of whole
    lines each opening with a trailer id and the message's own MSH-1: a check of the shape of any
    difference, independent of :func:`_less_the_trailer`."""
    if len(new) != len(old):
        return False
    for kept, was in zip(new, old, strict=True):
        if kept == was:
            continue
        if not (was.startswith(kept) and kept.startswith("MSH") and kept.endswith("\r")):
            return False
        separator = kept[3]
        dropped = was[len(kept) :].removesuffix("\r").split("\r")
        if not all(line[:3] in _TRAILER_IDS and line[3:4] == separator for line in dropped):
            return False
    return True


#: After each line break, a CR LF counting as one: the file's own lines, ends kept.
_AFTER_A_LINE_BREAK = re.compile(r"(?<=\n)|(?<=\r)(?!\n)")


def _old_bytes_less_the_trailer(raw: bytes, encoding: str) -> bytes:
    """BACKLOG #5806, over a file the copy hands over as its bytes: its decoded text less its own
    last lines, as many as :func:`_less_the_trailer` drops from the copy's one message, re-encoded
    with ``encoding``. Line ends and leading whitespace stay in the text."""
    try:
        text = raw.decode(encoding)
    except (UnicodeError, LookupError):
        return raw
    (message,) = _old_split_batch(text)
    kept = _less_the_trailer(message)
    if kept == message:
        return raw
    dropped = message[len(kept) :].removesuffix("\r").count("\r") + 1
    lines = [line for line in _AFTER_A_LINE_BREAK.split(text) if line]
    return "".join(lines[:-dropped]).encode(encoding)


# --- the corpus ---------------------------------------------------------------------------------

#: Tokens for each shape the readings tell apart: both line ends, a whole and a broken ``MSH``,
#: the byte order mark, other leading whitespace and a vertical tab, a field separator, the batch
#: envelope headers, another segment, and a non-Latin-1 character (a wider string kind).
#: BACKLOG #5806 added a file separator, trailers under ``|`` and under ``^``, and a bare id.
TOKENS = (
    "\r",
    "\n",
    "MSH",
    "MS",
    "H",
    BOM,
    " ",
    "\x0b",
    "\x1c",
    "|",
    "FHS|",
    "BHS|",
    "BTS|",
    "FTS^",
    "BTS",
    "PID|",
    "王",
)
#: Every string of up to this many tokens, then a seeded sample of longer ones, which is where a
#: marked second boundary or two boundaries behind an envelope header first fit.
EXHAUSTIVE_TOKENS = 4
SAMPLED = 40_000
SAMPLED_TOKENS = (5, 9)


#: BACKLOG #5806: the shapes a review of that change found the split treating unlike origin/main,
#: and data lines that only begin like a trailer, each also with a trailer after it.
_SHAPES = (
    "MSH|a\r MSH|b\r",
    "MSH|a\r\x0bMSH|b\r",
    "MSH|a\r\x1cMSH|b\r",
    "\x1c\rFHS|x\rMSH|a\rPID|1\r",
    "FHS^x\rMSH|a\rPID|1\r",
    "FHSX\rMSH|a\rPID|1\r",
    "FHS|x\rBHS|x\rBTS|0\rBHS|x\rMSH|a\rPID|1\r",
    "MSH|a\rOBX|1|TX|||note\rFHS: 140 bpm\rFHS\rBTS^1\r",
    "MSH^a\rPID^1\rBTS|1\rBTS^1\rFTS^1\r",
    "MSH|a\rBTS|1\r\rFTS|1\r",
    "MSH|a\rBTS|1\r" + BOM + "FTS|1\r",
    # Round four: header lines after a line break sent this file to the decode, which read it
    # past them where origin/main handed it over as its bytes.
    "FHS|x\rBHS|y\r MSH|a\rPID|1\r",
    " \r\nMSH|a\r\nPID|1\r\n",
)
REVIEW_SHAPES = [*_SHAPES, *(shape + "BTS|2\rFTS|1\r" for shape in _SHAPES)]


def _corpus() -> list[str]:
    rng = random.Random(3759)
    exhaustive = [
        "".join(parts)
        for n in range(EXHAUSTIVE_TOKENS + 1)
        for parts in itertools.product(TOKENS, repeat=n)
    ]
    sampled = ["".join(rng.choices(TOKENS, k=rng.randint(*SAMPLED_TOKENS))) for _ in range(SAMPLED)]
    return exhaustive + sampled + REVIEW_SHAPES


CORPUS = _corpus()
#: The corpus as the bytes of a received file, encoded once for every test that reads bytes.
BODIES = [text.encode("utf-8") for text in CORPUS]


def _disagreements(
    new: Callable[[str], object], old: Callable[[str], object], inputs: list[str]
) -> list[str]:
    return [text for text in inputs if new(text) != old(text)]


def test_the_corpus_reaches_every_answer() -> None:
    # A corpus on which a reading always answers one way proves nothing about it.
    for reading in (_old_holds_more_than_one_message, _old_sends_more_than_one_message):
        assert {reading(text) for text in CORPUS} == {True, False}
    assert {_old_needs_a_decode(body, "utf-8") for body in BODIES} == {True, False}
    assert {len(_old_split_batch(text)) for text in CORPUS} >= {1, 2, 3}


def test_the_ingress_reading_matches_its_copy() -> None:
    # check_decoded hands it normalized text; the raw strings are read too, so a change that only
    # shows on an LF the guard is never given would still fail here.
    normalized = [normalize(text) for text in CORPUS]
    for inputs in (CORPUS, normalized):
        assert (
            _disagreements(
                split._holds_more_than_one_message, _old_holds_more_than_one_message, inputs
            )
            == []
        )


def test_the_delivery_reading_matches_its_copy() -> None:
    assert (
        _disagreements(split._sends_more_than_one_message, _old_sends_more_than_one_message, CORPUS)
        == []
    )


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "cp1252", "ascii", "utf-16", "nope"])
def test_the_whole_file_byte_scan_matches_its_copy(encoding: str) -> None:
    assert [
        body
        for body in BODIES
        if split._needs_a_decode(body, encoding) != _old_needs_a_decode(body, encoding)
    ] == []


def test_the_batch_split_is_its_copy_less_the_trailer_lines() -> None:
    # BACKLOG #5806: every input splits as it did, and each message differs only by trailer lines.
    for inputs in (CORPUS, BODIES):
        wrong = []
        for text in inputs:
            new, old = split.split_batch(text), _old_split_batch(text)
            if new != [_less_the_trailer(m) for m in old] or not _only_trailer_lines_gone(new, old):
                wrong.append(text)
        assert wrong == []


def test_the_corpus_drops_a_trailer_and_keeps_one() -> None:
    # A corpus on which the split never drops a line, or always does, proves nothing about it.
    dropped = {text for text in CORPUS if split.split_batch(text) != _old_split_batch(text)}
    assert dropped
    assert any("BTS" in text and text not in dropped for text in CORPUS)
    for kept in ("FHS: 140 bpm", "\rFHS\r", "BTS^1"):
        assert any(kept in text and text not in dropped for text in REVIEW_SHAPES)


def _old_whole_file_less_the_trailer(raw: bytes, encoding: str) -> list[bytes]:
    """What origin/main's whole-file split hands over for ``raw``, less the trailer lines. A file
    it hands over as its bytes keeps them under a codec that does not write ASCII as itself."""
    old = _old_split_batch_bytes(raw, encoding)
    if old == [raw]:
        if not _old_writes_ascii_as_itself(encoding):
            return [raw]
        return [_old_bytes_less_the_trailer(raw, encoding)]
    return [_less_the_trailer(part.decode(encoding)).encode(encoding) for part in old]


#: Each line ending, and the leading whitespace before an ``MSH`` the parser reads past.
_SPELLINGS = (("\r", "\r"), ("\r", "\n"), ("\r", "\r\n"), ("", " \t"), ("", "\r\n"))


@pytest.mark.parametrize(
    "encoding", ["utf-8", "latin-1", "cp1252", "utf-16", "utf-16-le", "utf-8-sig", "nope"]
)
def test_the_whole_file_split_is_origin_mains_less_the_trailer_lines(encoding: str) -> None:
    # BACKLOG #5806: what a whole-file source hands over is what origin/main's whole-file split
    # hands over, part by part, less the trailer lines and nothing else: a re-encoded message less
    # its trailer lines, and a file handed over as its bytes less their bytes where the codec
    # writes ASCII as itself, and unchanged where it does not.
    codec = encoding if encoding.startswith(("utf-16", "utf-8-sig")) else "utf-8"
    respelled = [shape.replace(cr, brk) for shape in REVIEW_SHAPES for cr, brk in _SPELLINGS if cr]
    led = [lead + shape for shape in REVIEW_SHAPES for cr, lead in _SPELLINGS if not cr]
    wrong = []
    for text in [*CORPUS, *respelled, *led]:
        raw = text.encode(codec)
        if split.split_batch_bytes(raw, encoding) != _old_whole_file_less_the_trailer(
            raw, encoding
        ):
            wrong.append(text)
    assert wrong == []


#: One message ending in trailer lines, which origin/main handed over as the file's bytes.
_ONE_WITH_A_TRAILER = "MSH|^~\\&|A|B\r\nPID|1||123\r\nBTS|1\r\nFTS|1\r\n"


@pytest.mark.parametrize(
    ("encoding", "raw"),
    [
        ("utf-16", codecs.BOM_UTF16_BE + _ONE_WITH_A_TRAILER.encode("utf-16-be")),
        ("utf-16-le", _ONE_WITH_A_TRAILER.encode("utf-16-le")),
        ("utf-8-sig", _ONE_WITH_A_TRAILER.encode("utf-8-sig")),
        ("cp932", "MSH|^~\\&|A|B\rPID|1||王\rBTS|1\rFTS|1\r".encode("cp932")),
    ],
    ids=["utf-16be-bom", "utf-16le-no-bom", "utf-8-sig", "cp932"],
)
def test_a_codec_that_does_not_write_ascii_as_itself_keeps_the_file_whole(
    encoding: str, raw: bytes
) -> None:
    # BACKLOG #5806, round 6: no byte cut is exact under these codecs, so a one-message file goes
    # over as origin/main handed it over, its own bytes with the trailer lines, on both whole-file
    # paths: the remote source's split_batch_bytes and the File source's one_message_bytes.
    assert _old_split_batch_bytes(raw, encoding) == [raw]
    assert split.split_batch_bytes(raw, encoding) == [raw]
    text = raw.decode(encoding)
    (message,) = split.split_batch(text)
    assert not message.rstrip("\r").endswith("FTS|1")  # the split itself still drops them
    assert split.one_message_bytes(raw, text, message, encoding) == raw


def test_the_whole_file_corpus_cuts_bytes_the_byte_scan_hands_over() -> None:
    # A corpus in which no file the byte scan hands over as its bytes loses a trailer line, or
    # every such file does, proves nothing about that path.
    scanned = [body for body in BODIES if not _old_needs_a_decode(body, "utf-8")]
    cut = [body for body in scanned if split.split_batch_bytes(body, "utf-8") != [body]]
    assert cut
    assert len(cut) < len(scanned)
    assert b"FHS|x\rBHS|y\r MSH|a\rPID|1\r" in scanned
    assert b"FHS|x\rBHS|y\r MSH|a\rPID|1\r" not in cut


#: The earliest boundary each ``_Boundary`` names, written out again here as a plain regex.
_EARLIEST_OUTBOUND = re.compile(r"[\r\n]" + BOM + r"*MSH")
_EARLIEST_NORMALIZED = re.compile(r"\r" + BOM + r"*MSH")
_EARLIEST_RAW_BYTES = re.compile(rb"[\r\n][\xef\xbb\xbf]*MSH")


def _earliest(pattern: re.Pattern[Any], text: Any, start: int) -> int:
    found = pattern.search(text, start)
    return -1 if found is None else found.start()


@pytest.mark.parametrize("start", [0, 1, 3])
def test_the_predicate_returns_the_earliest_boundary(start: int) -> None:
    # The boolean readings throw the index away, so the parity tests above would not see a search
    # return a later boundary (BACKLOG #4972). Each answer is held to a plain regex for the same
    # boundary, for each kind of text.
    assert [
        text
        for text in CORPUS
        if split._next_boundary(text, start, split._OUTBOUND)
        != _earliest(_EARLIEST_OUTBOUND, text, start)
    ] == []
    assert [
        text
        for text in CORPUS
        if split._next_boundary(text, start, split._NORMALIZED)
        != _earliest(_EARLIEST_NORMALIZED, text, start)
    ] == []
    assert [
        body
        for body in BODIES
        if split._next_boundary(body, start, split._RAW_BYTES)
        != _earliest(_EARLIEST_RAW_BYTES, body, start)
    ] == []


def test_a_clean_outbound_payload_pays_one_scan() -> None:
    # Item 3.2. A str subclass counts the substring scans the delivery reading makes through find,
    # count and `in`; a payload with no MSH after its lead must stop at the first, and one holding
    # a second message still answers. A regex search is not counted: the lead match reads only the
    # lead, and the boundary pattern is searched only once this scan has found an MSH.
    class Counted(str):
        scans = 0

        def find(
            self,
            sub: str,
            start: SupportsIndex | None = None,
            end: SupportsIndex | None = None,
            /,
        ) -> int:
            type(self).scans += 1
            return super().find(sub, start, end)

        def count(
            self,
            sub: str,
            start: SupportsIndex | None = None,
            end: SupportsIndex | None = None,
            /,
        ) -> int:
            type(self).scans += 1
            return super().count(sub, start, end)

        def __contains__(self, key: object) -> bool:
            assert isinstance(key, str)
            type(self).scans += 1
            return super().__contains__(key)

    clean = Counted("MSH|^~\\&|A|B\rPID|1||1\r")
    assert split._sends_more_than_one_message(clean) is False
    assert Counted.scans == 1
    assert split._sends_more_than_one_message(Counted("MSH|a\rPID|1\nMSH|b\r")) is True


@pytest.mark.parametrize("lead", ["", BOM, BOM * 3])
def test_walking_a_batch_reads_the_text_a_bounded_number_of_times(lead: str) -> None:
    # BACKLOG #5918 review: with only marked boundaries, a search that scanned on for a plain
    # boundary read to the end of the text on every call, so a split was quadratic. Walking every
    # boundary of an N-message batch, as split_batch does, must read the text a bounded number of
    # times in all. A str subclass totals the characters each find reads, which is the MSH
    # prescan; the boundary pattern opens with a line break no mark holds, so its own search is
    # linear, and the regex is not counted here.
    class Counted(str):
        read = 0

        def find(
            self,
            sub: str,
            start: SupportsIndex | None = None,
            end: SupportsIndex | None = None,
            /,
        ) -> int:
            first = 0 if start is None else int(start)
            last = len(self) if end is None else int(end)
            hit = super().find(sub, start, end)
            type(self).read += (last if hit < 0 else hit + len(sub)) - first
            return hit

    count = 200
    text = Counted(("MSH|a\rOBX|1|MSH x\r" + lead) * count)
    found = []
    at = split._next_boundary(text, 0, split._NORMALIZED)
    while at >= 0:
        found.append(at)
        at = split._next_boundary(text, at + 1, split._NORMALIZED)
    assert len(found) == count - 1
    assert Counted.read <= 3 * len(text)
