# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3759 items 3.1 and 3.2: the ``MSH``-boundary readings in ``parsing/split.py``.

The four readings (the split, the ingress guard's, the delivery's and the whole-file byte scan)
spelled the boundary each its own way, and a clean outbound payload paid two scans. They now share
their literals, and one scan settles a clean payload. That was a refactor, so every decision must
be the one the code made before it: each reading is checked against a copy of its body as it
stood before, over every string of up to four tokens drawn from the shapes the readings tell
apart, and a seeded sample of longer ones.

The copies are the oracle for that refactor. A later change that means to alter a reading edits
its copy in the same commit, and says so; never edit one only to make a failure go away. The
split's copy calls the live ``normalize`` and ``_LEADING_WS_STR``, so it pins the boundary, not
those. That the delivery reading agrees with the ingress one is AC-7's test, in
``tests/test_one_frame_one_message.py``, not this file's. Synthetic data only.
"""

from __future__ import annotations

import codecs
import itertools
import random
import re
from collections.abc import Callable
from typing import SupportsIndex

import pytest

from messagefoundry.parsing import normalize, split
from messagefoundry.parsing.sniff import _LEADING_WS_STR

BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"

# --- the readings as they stood at engine origin/main a0a5e4f5a4, verbatim but for names --------

_OLD_MSH_BOUNDARY = re.compile(r"(?=\rMSH)")
_OLD_FIRST_KEPT = re.compile(r"\S")
_OLD_LEADS_WITH_MSH_PAST_BOM = re.compile(r"[\s" + BOM + r"]*MSH")
_OLD_LATER_MSH_PAST_BOM = re.compile(r"[\r\n]" + BOM + r"+MSH")
_OLD_LEADING_BOM = re.compile(rb"\s*\xef\xbb\xbf")


def _old_holds_more_than_one_message(text: str) -> bool:
    first = _OLD_FIRST_KEPT.search(text)
    if first is None:
        return False
    start = first.start()
    later = text.count("\rMSH", start)
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
    return b"\rMSH" in raw or b"\nMSH" in raw


def _old_split_batch(raw: str | bytes) -> list[str]:
    text = normalize(raw)
    first, *rest = _OLD_MSH_BOUNDARY.split(text)
    messages = [chunk[1:] for chunk in rest]
    head = first.lstrip(_LEADING_WS_STR)
    while head.startswith(("FHS", "BHS")):
        head = head.partition("\r")[2].lstrip(_LEADING_WS_STR)
    if head.strip():
        messages.insert(0, head)
    return messages or [text]


# --- the corpus ---------------------------------------------------------------------------------

#: Tokens for each shape the readings tell apart: both line ends, a whole and a broken ``MSH``,
#: the byte order mark, other leading whitespace and a vertical tab, a field separator, the batch
#: envelope headers, another segment, and a non-Latin-1 character (a wider string kind).
TOKENS = ("\r", "\n", "MSH", "MS", "H", BOM, " ", "\x0b", "|", "FHS|", "BHS|", "PID|", "王")
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


def test_the_ingress_reading_is_unchanged() -> None:
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


def test_the_delivery_reading_is_unchanged() -> None:
    assert (
        _disagreements(split._sends_more_than_one_message, _old_sends_more_than_one_message, CORPUS)
        == []
    )


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "cp1252", "ascii", "utf-16", "nope"])
def test_the_whole_file_byte_scan_is_unchanged(encoding: str) -> None:
    assert [
        body
        for body in BODIES
        if split._needs_a_decode(body, encoding) != _old_needs_a_decode(body, encoding)
    ] == []


def test_the_batch_split_is_unchanged() -> None:
    assert [text for text in CORPUS if split.split_batch(text) != _old_split_batch(text)] == []
    assert [body for body in BODIES if split.split_batch(body) != _old_split_batch(body)] == []


def test_the_split_boundary_literal_spells_the_shared_cr_msh() -> None:
    # The split's lookahead is a literal so the static ReDoS scanner can read it, which means it no
    # longer follows _CR_MSH on its own: hold it to the pure lookahead over that one literal.
    body = split._MSH_BOUNDARY.pattern.removeprefix("(?=").removesuffix(")")
    assert split._MSH_BOUNDARY.pattern == "(?=" + body + ")"
    assert body == split._CR_MSH.replace("\r", r"\r")
    assert re.fullmatch(body, split._CR_MSH) is not None


def test_a_clean_outbound_payload_pays_one_scan() -> None:
    # Item 3.2. A str subclass counts the substring scans the delivery reading makes through find,
    # count and `in`; a payload with no MSH after its lead must stop at the first, and one holding
    # a second message still answers. A regex search is not counted: the lead match reads only the
    # lead, and the marked-boundary search runs only past this scan.
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
