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

BACKLOG #5806 changed the split and the byte scan on purpose too, and their copies with them: an
``MSH``-led message no longer ends with the batch envelope lines that followed it in the file, the
first chunk is read past trailer lines as well as header lines, and an envelope segment id
anywhere in a file needs a decode. The corpus gained a ``BTS|`` token for it.
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


def _old_needs_a_decode(raw: bytes, encoding: str) -> bool:
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        return True
    if name not in {"utf-8", "ascii"} and not name.startswith(("iso8859-", "cp125")):
        return True
    if name == "utf-8" and _OLD_LEADING_BOM.match(raw):
        return True
    if b"\rMSH" in raw or b"\nMSH" in raw:
        return True
    # BACKLOG #5806: an envelope segment id anywhere now needs a decode too.
    if any(segment in raw for segment in (b"FHS", b"BHS", b"BTS", b"FTS")):
        return True
    # BACKLOG #5918: a later MSH that UTF-8 byte order marks lead now needs a decode too.
    return _OLD_LATER_MSH_BYTES_PAST_BOM.search(raw) is not None


def _old_split_batch(raw: str | bytes) -> list[str]:
    text = normalize(raw)
    first, *rest = _OLD_MSH_BOUNDARY.split(text)
    messages = [chunk[1:].lstrip(BOM) for chunk in rest]  # BACKLOG #5918: was chunk[1:]
    head = first.lstrip(_LEADING_WS_STR)
    # BACKLOG #5806: was head.startswith(("FHS", "BHS")).
    while _old_envelope(head.partition("\r")[0]):
        head = head.partition("\r")[2].lstrip(_LEADING_WS_STR)
    if head.strip():
        messages.insert(0, head)
    messages = [_old_drop_trailer(m) for m in messages]  # BACKLOG #5806: was not there
    return messages or [text]


#: BACKLOG #5806: the envelope segment ids, dropped before the first message and at a message's end.
_OLD_ENVELOPE_LINES = ("FHS", "BHS", "BTS", "FTS")
#: BACKLOG #5806: the noise around a message's closing envelope lines, whitespace and the mark.
_OLD_TRAILING_NOISE = "".join(chr(c) for c in range(0x3001) if chr(c).isspace()) + BOM


def _old_envelope(line: str) -> bool:
    """BACKLOG #5806: noise, an envelope id, then the line's end or a character that is neither a
    word character nor whitespace."""
    rest = line.lstrip(_OLD_TRAILING_NOISE)
    if not rest.startswith(_OLD_ENVELOPE_LINES):
        return False
    return len(rest) == 3 or not (rest[3].isalnum() or rest[3] == "_" or rest[3].isspace())


def _old_drop_trailer(message: str) -> str:
    """BACKLOG #5806, written as lines rather than as the live code's scan from the end: an
    ``MSH``-led message loses the trailing run of noise-only and envelope lines from its first
    envelope line on, keeping the CR before it; one whose run holds no envelope line is
    unchanged."""
    if not message.startswith("MSH"):
        return message

    def noise(line: str) -> bool:
        return line.strip(_OLD_TRAILING_NOISE) == ""

    envelope = _old_envelope
    lines = message.split("\r")
    run = len(lines)
    while run > 1 and (noise(lines[run - 1]) or envelope(lines[run - 1])):
        run -= 1
    first = next((i for i in range(run, len(lines)) if envelope(lines[i])), None)
    if first is None:
        return message
    return "\r".join(lines[:first]) + "\r"


# --- the corpus ---------------------------------------------------------------------------------

#: Tokens for each shape the readings tell apart: both line ends, a whole and a broken ``MSH``,
#: the byte order mark, other leading whitespace and a vertical tab, a field separator, the batch
#: envelope headers and a trailer (BACKLOG #5806), another segment, and a non-Latin-1 character (a
#: wider string kind).
TOKENS = ("\r", "\n", "MSH", "MS", "H", BOM, " ", "\x0b", "|", "FHS|", "BHS|", "BTS|", "PID|", "王")
#: Every string of up to this many tokens, then a seeded sample of longer ones, which is where a
#: marked second boundary or two boundaries behind an envelope header first fit.
EXHAUSTIVE_TOKENS = 4
SAMPLED = 40_000
SAMPLED_TOKENS = (5, 9)


def _corpus() -> list[str]:
    rng = random.Random(3759)
    exhaustive = [
        "".join(parts)
        for n in range(EXHAUSTIVE_TOKENS + 1)
        for parts in itertools.product(TOKENS, repeat=n)
    ]
    sampled = ["".join(rng.choices(TOKENS, k=rng.randint(*SAMPLED_TOKENS))) for _ in range(SAMPLED)]
    return exhaustive + sampled


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


def test_the_batch_split_matches_its_copy() -> None:
    assert [text for text in CORPUS if split.split_batch(text) != _old_split_batch(text)] == []
    assert [body for body in BODIES if split.split_batch(body) != _old_split_batch(body)] == []


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
