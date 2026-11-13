# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pure X12 codec (messagefoundry.parsing.x12) — delimiters, peek, interchange framing, message,
integrity, and the console-carve-out import-purity guard (ADR 0012)."""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from messagefoundry.parsing.x12 import (
    X12FrameError,
    X12FrameReader,
    X12Message,
    X12Peek,
    X12PeekError,
    check_integrity,
    discover_delimiters,
    find_isa_start,
    split,
)
from messagefoundry_toolkit.lens import CONTRACT_V2, parse_source, rewrite_source


def isa(
    *,
    el: str = "*",
    comp: str = ":",
    term: str = "~",
    rep: str = "^",
    version: str = "00501",
    sender: str = "SENDERID",
    receiver: str = "RECEIVERID",
    control: str = "000000001",
    usage: str = "P",
) -> str:
    """A fixed-length (106-char) ISA header with configurable delimiters/version."""
    seg = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + sender.ljust(15)
        + el
        + "ZZ"
        + el
        + receiver.ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + rep
        + el
        + version
        + el
        + control
        + el
        + "0"
        + el
        + usage
        + el
        + comp
    )
    assert len(seg) == 105, f"ISA pre-terminator length {len(seg)} (want 105)"
    return seg + term


def interchange(
    *,
    el: str = "*",
    comp: str = ":",
    term: str = "~",
    rep: str = "^",
    version: str = "00501",
    control: str = "000000001",
    usage: str = "P",
    sender: str = "SENDERID",
    receiver: str = "RECEIVERID",
    groups: list[tuple[str, str, list[str]]] | None = None,
) -> str:
    """A complete interchange. ``groups`` = list of (GS01 functional id, GS08 version, [ST01 ids])."""
    if groups is None:
        groups = [("HS", "005010X279A1", ["270"])]
    head = isa(
        el=el,
        comp=comp,
        term=term,
        rep=rep,
        version=version,
        control=control,
        usage=usage,
        sender=sender,
        receiver=receiver,
    )
    body = ""
    for gi, (fid, gver, txs) in enumerate(groups, 1):
        body += el.join(["GS", fid, "SAPP", "RAPP", "20240101", "1200", str(gi), "X", gver]) + term
        for ti, tx in enumerate(txs, 1):
            body += el.join(["ST", tx, f"{ti:04d}"]) + term
            body += el.join(["SE", "2", f"{ti:04d}"]) + term  # ST + SE = 2 segments
        body += el.join(["GE", str(len(txs)), str(gi)]) + term
    body += el.join(["IEA", str(len(groups)), control]) + term
    return head + body


# --- delimiter discovery -----------------------------------------------------


def test_discover_default_delimiters() -> None:
    d = discover_delimiters(interchange())
    assert (d.element, d.component, d.segment, d.repetition) == ("*", ":", "~", "^")


def test_discover_non_default_delimiters() -> None:
    d = discover_delimiters(interchange(el="|", comp="^", term="'", rep="~"))
    assert (d.element, d.component, d.segment, d.repetition) == ("|", "^", "'", "~")


def test_repetition_separator_gated_on_version() -> None:
    # 00501+ : ISA11 is the repetition separator.
    assert discover_delimiters(interchange(version="00501", rep="^")).repetition == "^"
    # 00401 and earlier : ISA11 is the literal "U", NOT a delimiter.
    assert discover_delimiters(interchange(version="00401", rep="U")).repetition is None


def test_crlf_segment_terminator() -> None:
    d = discover_delimiters(interchange(term="\r\n"))
    assert d.segment == "\r\n"


def test_leading_whitespace_and_bom_tolerated() -> None:
    raw = "" + chr(65279) + "  \r\n" + interchange()
    assert find_isa_start(raw) == 5  # BOM(1) + 2 spaces + CR + LF = 5 chars before "ISA"
    assert X12Peek.parse(raw).sender_id == "SENDERID"


def test_truncated_isa_raises() -> None:
    with pytest.raises(X12PeekError, match="truncated"):
        discover_delimiters(isa()[:60])


def test_non_distinct_delimiters_raise() -> None:
    with pytest.raises(X12PeekError, match="not mutually distinct"):
        discover_delimiters(interchange(comp="*"))  # component == element


def test_sanity_gate_catches_misplaced_separator() -> None:
    raw = list(interchange())
    raw[6] = "X"  # corrupt a fixed element-separator position
    with pytest.raises(X12PeekError, match="malformed"):
        discover_delimiters("".join(raw))


def test_non_x12_input_raises() -> None:
    with pytest.raises(X12PeekError, match="does not begin with an ISA"):
        find_isa_start("MSH|^~\\&|not x12")


# --- peek --------------------------------------------------------------------


def test_peek_interchange_identity() -> None:
    p = X12Peek.parse(interchange(usage="T"))
    assert p.sender_id == "SENDERID" and p.sender_qual == "ZZ"
    assert p.receiver_id == "RECEIVERID" and p.receiver_qual == "ZZ"
    assert p.version == "00501" and p.control_number == "000000001"
    assert p.usage == "T" and p.is_test is True


def test_peek_groups_multi_gs_multi_st_with_gs08() -> None:
    raw = interchange(
        groups=[
            ("HC", "005010X222A1", ["837"]),
            ("HB", "005010X279A1", ["270", "271"]),
        ]
    )
    groups = X12Peek.parse(raw).groups()
    assert len(groups) == 2
    assert groups[0].functional_id == "HC" and groups[0].version == "005010X222A1"
    assert groups[0].transactions == ("837",)
    assert groups[1].functional_id == "HB" and groups[1].version == "005010X279A1"
    assert groups[1].transactions == ("270", "271")
    assert X12Peek.parse(raw).transaction_ids() == ["837", "270", "271"]


def test_peek_segment_ids() -> None:
    ids = X12Peek.parse(interchange()).segment_ids()
    assert ids[0] == "ISA" and ids[-1] == "IEA" and "GS" in ids and "ST" in ids


def test_peek_accepts_bytes() -> None:
    assert X12Peek.parse(interchange().encode("utf-8")).version == "00501"


# --- interchange splitting ---------------------------------------------------


def test_split_single() -> None:
    one = interchange()
    assert split(one) == [one]


def test_split_two_concatenated() -> None:
    a = interchange(control="000000001")
    b = interchange(control="000000002")
    assert split(a + b) == [a, b]


def test_split_skips_inter_interchange_noise() -> None:
    a, b = interchange(), interchange(control="000000002")
    assert split(a + "\r\n\r\n" + b) == [a, b]


def test_split_surfaces_unterminated_remainder() -> None:
    a = interchange()
    partial = isa(control="000000009") + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~"  # no IEA
    out = split(a + partial)
    assert out[0] == a and out[1] == partial


def test_split_tolerates_cosmetic_newlines_after_terminator() -> None:
    pretty = interchange().replace("~", "~\n")
    parts = split(pretty)
    assert len(parts) == 1 and parts[0].lstrip().startswith("ISA") and "IEA" in parts[0]


# --- non-ISA noise and false ISA trigrams (BACKLOG #5921) --------------------
# split used to stop at the first run of non-ISA data and drop it and everything after it. The frame
# reader took any "ISA" trigram in noise as an interchange start, so a real interchange behind it was
# swallowed into a false frame. Both now check the ISA's fixed element-separator positions, and both
# surface what fails the check rather than drop it.


@pytest.mark.parametrize(
    ("raw_parts", "expected"),
    [
        pytest.param(["A", "\r\nGARBAGE line\r\n", "B"], ["A", "GARBAGE line", "B"], id="between"),
        pytest.param(["A", "trailing junk\r\n"], ["A", "trailing junk"], id="trailing"),
        pytest.param(["leading junk ", "A"], ["leading junk", "A"], id="leading"),
        pytest.param(
            ["A", "noise ISAAC here ", "B"], ["A", "noise ISAAC here", "B"], id="false-isa"
        ),
        pytest.param(["A", "\r\n"], ["A"], id="trailing-crlf-is-skipped"),
    ],
)
def test_split_surfaces_non_isa_junk_as_its_own_element(
    raw_parts: list[str], expected: list[str]
) -> None:
    a, b = interchange(), interchange(control="000000002")
    parts = {"A": a, "B": b}
    out = split("".join(parts.get(p, p) for p in raw_parts))
    assert out == [parts.get(p, p) for p in expected]


def test_split_of_a_buffer_with_no_isa() -> None:
    assert split("not x12 at all\r\n") == ["not x12 at all"]
    assert split("\ufeff \r\n") == [] and split("") == []


def _corrupt(raw: str) -> str:
    return raw[:6] + "X" + raw[7:]  # clobber a fixed element-separator position


@pytest.mark.parametrize(
    ("raw_parts", "expected"),
    [
        pytest.param(["A", "\r\nPaid by VISA\r\n"], ["A", "Paid by VISA"], id="trailing-visa"),
        pytest.param(["A", "\r\nISAAC\r\n"], ["A", "ISAAC"], id="short-trailing-isa"),
        pytest.param(
            ["A", "\r\nISA segment missing\r\n", "B"],
            ["A", "ISA segment missing", "B"],
            id="junk-opening-with-isa",
        ),
        pytest.param(["BAD", "BAD", "B"], ["BAD", "BAD", "B"], id="two-corrupted-then-good"),
        pytest.param(
            ["BAD", "\r\nGARBAGE\r\n", "B"], ["BAD", "GARBAGE", "B"], id="corrupted-noise"
        ),
    ],
)
def test_split_bounds_a_malformed_isa_and_never_raises_on_one(
    raw_parts: list[str], expected: list[str]
) -> None:
    a, b = interchange(), interchange(control="000000002")
    parts = {"A": a, "B": b, "BAD": _corrupt(interchange(control="000000003"))}
    out = split("".join(parts.get(p, p) for p in raw_parts))
    assert out == [parts.get(p, p) for p in expected]


def _frames_of(data: bytes, chunk: int) -> list[bytes]:
    reader = X12FrameReader()
    frames: list[bytes] = []
    for i in range(0, len(data), chunk):
        frames.extend(reader.feed(data[i : i + chunk]))
    assert not reader.in_frame
    return frames


@pytest.mark.parametrize(
    "noise",
    [
        pytest.param(b"xxISA junk ", id="short"),
        pytest.param(b"ISA long noise line " * 12, id="longer-than-an-isa"),
        pytest.param(b"ISAISAISA ", id="repeated"),
    ],
)
@pytest.mark.parametrize("chunk", [4096, 1])
def test_frame_reader_frames_a_false_isa_in_noise_apart_from_the_real_one(
    noise: bytes, chunk: int
) -> None:
    real = interchange().encode("utf-8")
    frames = _frames_of(noise + real, chunk)
    # The false ISA's run is framed on its own, so the parse refuses it, and the real one is whole.
    assert frames == [noise[noise.index(b"ISA") :], real]
    with pytest.raises(X12PeekError):
        X12Message.parse(frames[0])


@pytest.mark.parametrize(
    "parts",
    [
        pytest.param(["BAD"], id="alone"),
        pytest.param(["BAD", "GOOD"], id="before-good"),
        pytest.param(["BAD", "\r\n", "GOOD"], id="crlf-between"),
        pytest.param(["BAD", "\r\nGARBAGE\r\n", "GOOD"], id="noise-between"),
        pytest.param(["BAD", "BAD", "BAD", "GOOD"], id="three-corrupted"),
        pytest.param(["GOOD", "BAD", "GOOD"], id="between-goods"),
    ],
)
@pytest.mark.parametrize("chunk", [4096, 7, 1])
def test_frame_reader_frames_each_corrupted_isa_through_its_own_iea(
    parts: list[str], chunk: int
) -> None:
    # A real interchange whose header fails the structural check is not noise to discard, and its
    # frame does not depend on how the stream was split into reads.
    good = interchange(control="000000002").encode("utf-8")
    bad = _corrupt(interchange()).encode("utf-8")
    pieces = {"BAD": bad, "GOOD": good}
    data = b"".join(pieces.get(p, p.encode()) for p in parts)
    assert _frames_of(data, chunk) == [pieces[p] for p in parts if p in pieces]


def test_frame_reader_does_not_cut_a_suspect_inside_the_next_isa_in_small_reads() -> None:
    # A suspect whose +105 terminator is "S" could close an IEA segment on the "S" of the next real
    # ISA while only "IS" of it had arrived, losing that interchange in small reads only.
    head = bytearray(b"ISA" + b"x" * 102 + b"S")
    head[6:7] = b"y"  # fails the structural check
    suspect = bytes(head) + b"IEA*1*000000001~"
    real = interchange().encode("utf-8")
    for chunk in (4096, 1):
        assert _frames_of(suspect + real, chunk) == [suspect, real]


def test_split_keeps_a_malformed_interchanges_whitespace_terminator() -> None:
    bad = _corrupt(interchange(term="\n"))
    assert split(bad + interchange(control="000000002")) == [bad, interchange(control="000000002")]


def test_split_and_reader_stay_linear_over_many_malformed_interchanges() -> None:
    # Each malformed interchange used to restart the search for the next passing ISA, so k of them
    # in one buffer cost about k * k structural checks. Count the checks rather than time the run.
    from messagefoundry.parsing.x12 import delimiters

    bad = _corrupt(interchange())
    calls = 0
    original = delimiters.isa_separators_line_up

    def counting(buf: Any, isa_at: int) -> bool:
        nonlocal calls
        calls += 1
        return original(buf, isa_at)

    import messagefoundry.parsing.x12.interchange as interchange_mod

    for k in (50, 200):
        calls = 0
        mp = pytest.MonkeyPatch()
        mp.setattr(interchange_mod, "isa_separators_line_up", counting)
        try:
            assert len(split(bad * k)) == k
            assert len(list(X12FrameReader().feed((bad * k).encode()))) == k
        finally:
            mp.undo()
        assert calls < 10 * k, (k, calls)


def test_frame_reader_clear_resets_the_trailer_allowance() -> None:
    reader = X12FrameReader()
    assert list(reader.feed(interchange().encode("utf-8"))) != []
    assert reader._tail_left == 2
    reader._clear()
    assert reader._tail_left == 0
    list(reader.feed(b"\r\n"))
    assert not reader.trailer_only


# A run of one character after "ISA" lines up at every separator position, so the separator check
# alone passed padded text ("Paid by VISA" then spaces, a row of "=" or "0"). The reader then walked it
# without bound and split refused the whole buffer. The check also requires distinct delimiters now.
_PADDED_NOISE = [
    pytest.param("\r\nPaid by VISA" + " " * 110 + "\r\n", id="spaces"),
    pytest.param("\r\nVISA" + "0" * 110 + "\r\n", id="zeros"),
    pytest.param("\r\n====VISA" + "=" * 120 + "\r\n", id="banner"),
]


@pytest.mark.parametrize("fill", [" ", "0", "="])
def test_isa_followed_by_one_repeated_character_fails_the_check(fill: str) -> None:
    from messagefoundry.parsing.x12.delimiters import isa_separators_line_up

    run = "ISA" + fill * 103
    assert not isa_separators_line_up(run, 0)
    assert not isa_separators_line_up(run.encode(), 0)
    assert not isa_separators_line_up(bytearray(run.encode()), 0)
    # Positive controls: a real header passes, and so does one too short to tell yet.
    assert isa_separators_line_up(isa(), 0) and isa_separators_line_up(isa().encode()[:40], 0)


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"comp": "*"}, id="component-is-element"),
        pytest.param({"term": "*"}, id="terminator-is-element"),
        pytest.param({"comp": "~"}, id="component-is-terminator"),
        pytest.param({"rep": ":"}, id="repetition-is-component"),
    ],
)
def test_the_check_refuses_delimiters_that_are_not_distinct(kwargs: dict[str, Any]) -> None:
    from messagefoundry.parsing.x12.delimiters import isa_separators_line_up

    assert not isa_separators_line_up(isa(**kwargs), 0)
    # Before 00501 ISA11 is data, so a value equal to a delimiter is not a repetition clash.
    assert isa_separators_line_up(isa(version="00401", rep=":"), 0)


@pytest.mark.parametrize("noise", _PADDED_NOISE)
def test_split_surfaces_padded_isa_noise_and_keeps_both_interchanges(noise: str) -> None:
    a, b = interchange(), interchange(control="000000002")
    assert split(a + noise + b) == [a, noise.strip(), b]


@pytest.mark.parametrize("noise", _PADDED_NOISE)
@pytest.mark.parametrize("chunk", [4096, 1])
def test_frame_reader_bounds_padded_isa_noise_at_the_next_interchange(
    noise: str, chunk: int
) -> None:
    a = interchange().encode()
    b = interchange(control="000000002").encode()
    run = noise.encode()
    frames = _frames_of(a + run + b, chunk)
    assert frames == [a, run[run.index(b"ISA") :], b]


@pytest.mark.parametrize("sender", ["SEND~X", "SEND*X"])
def test_split_returns_an_isa_the_parse_refuses_as_its_own_element(sender: str) -> None:
    # The ISA passes the structural check, but a delimiter in ISA06 makes the parse refuse it. split
    # used to raise for the whole buffer, losing both good interchanges; the reader framed all three.
    a, b = interchange(), interchange(control="000000002")
    c = interchange(control="000000003", sender=sender)
    assert split(a + c + b) == [a, c, b]
    assert _frames_of((a + c + b).encode(), 4096) == [a.encode(), c.encode(), b.encode()]
    # The forged delimiter still cannot make it parse as valid (BACKLOG #5536).
    with pytest.raises(X12PeekError, match="ISA-06 holds a delimiter character"):
        X12Message.parse(c)


def _without_iea(raw: str) -> str:
    return raw[: raw.index("IEA*")]


_BIG_CUT = _without_iea(interchange(groups=[("HS", "005010X279A1", ["270", "270", "270"])]))


@pytest.mark.parametrize(
    ("first", "cap"),
    [
        # A suspect's frame ends at the next ISA that passes.
        pytest.param(b"ISA long noise line " * 9, 220, id="suspect"),
        # A passing interchange with no IEA ends at the next one too.
        pytest.param(_without_iea(interchange()).encode(), 232, id="passing-no-iea"),
        # At the cap exactly, and one over: the next ISA's first bytes are not charged.
        pytest.param(_BIG_CUT.encode(), len(_BIG_CUT), id="passing-at-cap"),
        pytest.param(_BIG_CUT.encode(), len(_BIG_CUT) + 1, id="passing-cap-plus-one"),
    ],
)
def test_frame_reader_cap_does_not_depend_on_read_size(first: bytes, cap: int) -> None:
    # Bytes of the next ISA already received belong to it, not to the open frame, so they must not
    # count against the open frame's cap: they did, and 1- or 64-byte reads raised frame_oversize
    # where one read framed both.
    good = interchange(control="000000002").encode()
    assert len(first) <= cap and len(good) <= cap < len(first) + len(good)
    data = first + good
    for chunk in (len(data), 4096, 150, 64, 7, 1):
        reader = X12FrameReader(max_interchange_bytes=cap)
        frames: list[bytes] = []
        for i in range(0, len(data), chunk):
            frames.extend(reader.feed(data[i : i + chunk]))
        assert frames == [first, good], chunk
        assert not reader.in_frame


@pytest.mark.parametrize("chunk", [4096, 1])
def test_frame_reader_cap_holds_over_whitespace_after_a_segment(chunk: int) -> None:
    # Whitespace after a terminator may open the next ISA, which would cut the frame before it, so
    # the reader waits to see what follows. It is still charged, or a peer could grow the buffer
    # with it without bound.
    data = _without_iea(interchange()).encode() + b" " * 400
    reader = X12FrameReader(max_interchange_bytes=300)
    with pytest.raises(X12FrameError):
        for i in range(0, len(data), chunk):
            list(reader.feed(data[i : i + chunk]))


@pytest.mark.parametrize("between", ["", "\r\n"])
@pytest.mark.parametrize("next_term", ["~", "\n"])
def test_an_interchange_with_no_iea_ends_at_the_next_interchange(
    between: str, next_term: str
) -> None:
    # A passing ISA with no IEA was walked to the end of the buffer, swallowing the interchange
    # after it. Its walk now ends at the next ISA that opens a segment, whatever that interchange's
    # own terminator. Both surfaces keep the frame verbatim through its last terminator; the
    # whitespace before the next ISA is between interchanges, so neither frame holds it.
    a = _without_iea(interchange())
    b = interchange(control="000000002", term=next_term)
    assert split(a + between + b) == [a, b]
    for chunk in (4096, 7, 1):
        assert _frames_of((a + between + b).encode(), chunk) == [a.encode(), b.encode()]
    # The cut frame still parses, so check_integrity is what reports it.
    assert check_integrity(a) == ["no IEA segment"]


def test_check_integrity_reports_every_trailer_left_open() -> None:
    raw = interchange()
    cut = raw[: raw.index("SE*")]
    assert check_integrity(cut) == [
        "ST02 '0001' has no SE",
        "GS06 '1' has no GE",
        "no IEA segment",
    ]


@pytest.mark.parametrize(
    ("dropped", "groups", "expected"),
    [
        pytest.param(
            "GE*1*1~",
            [("HS", "005010X279A1", ["270"]), ("HB", "005010X279A1", ["271"])],
            ["GS06 '1' has no GE"],
            id="group-opened-over",
        ),
        pytest.param(
            "SE*2*0001~",
            [("HS", "005010X279A1", ["270", "270"])],
            ["ST02 '0001' has no SE"],
            id="set-opened-over",
        ),
    ],
)
def test_check_integrity_reports_a_trailer_a_new_header_opens_over(
    dropped: str, groups: list[tuple[str, str, list[str]]], expected: list[str]
) -> None:
    raw = interchange(groups=groups).replace(dropped, "", 1)
    assert check_integrity(raw) == expected


class _CountingStr(str):
    """A ``str`` that totals how far its ``find`` calls scan."""

    scanned = 0

    def find(self, sub: Any, start: Any = 0, end: Any = None) -> int:
        stop = len(self) if end is None else end
        idx = super().find(sub, start, stop)
        type(self).scanned += max(0, (stop if idx == -1 else idx + len(sub)) - start)
        return idx


def test_split_walks_a_chain_of_interchanges_with_no_iea_linearly() -> None:
    # Each walk used to run to the end of the buffer before looking for the next ISA, so a run of
    # interchanges with no IEA cost about N * N.
    cut = _without_iea(interchange())
    for k in (50, 400):
        _CountingStr.scanned = 0
        raw = _CountingStr(cut * k)
        assert len(split(raw)) == k
        assert _CountingStr.scanned < 4 * len(raw), (k, _CountingStr.scanned)


@pytest.mark.parametrize(
    "between",
    [
        pytest.param("﻿", id="bom"),
        pytest.param("junk", id="junk"),
        pytest.param("\x1c\r\x0b", id="mllp-envelope"),
    ],
)
def test_split_and_reader_stay_linear_when_noise_precedes_each_isa(between: str) -> None:
    # A passing walk used to search ahead for a later ISA that opens a segment before walking. With
    # anything but terminator and whitespace before each next ISA, none opens one, so each of k
    # interchanges searched to the end of the buffer: about k * k. Count what find scans.
    one = interchange() + between
    for k in (50, 400):
        _CountingStr.scanned = 0
        raw = _CountingStr(one * k)
        assert len([p for p in split(raw) if p.startswith("ISA")]) == k
        assert _CountingStr.scanned < 4 * len(raw), (k, _CountingStr.scanned)
        data = (one * k).encode()
        frames, scanned = _drip(data, len(data))
        assert len(frames) == k
        assert scanned < 4 * len(data), (k, scanned)


def test_a_failing_isa_that_opens_a_segment_ends_a_passing_walk() -> None:
    # Any literal ISA that opens a segment ends the walk, passing or not, so an interchange with no
    # IEA does not swallow a corrupted one after it. That one is its own malformed element.
    a = _without_iea(interchange())
    bad = _corrupt(interchange(control="000000002"))
    good = interchange(control="000000003")
    for between in ("", "\r\n"):
        raw = a + between + bad + good
        assert split(raw) == [a, bad, good]
        for chunk in (4096, 7, 1):
            assert _frames_of(raw.encode(), chunk) == [a.encode(), bad.encode(), good.encode()]


def test_split_takes_a_lowercase_isa_as_data_as_the_reader_does() -> None:
    # The separator check never reads the literal. split took a lowercase "isa" header as an
    # interchange and walked it past a passing ISA in its element data; the reader only starts a
    # frame at a literal "ISA", so the two framed the same bytes differently.
    body_isa = isa(control="000000009")
    raw = interchange().replace("GS*HS*", "GS*HS" + body_isa + "*", 1)
    lower = "isa" + raw[3:]
    cut = lower.index(body_isa)
    assert split(lower) == [lower[:cut], lower[cut:]]
    assert split(raw) == [raw]  # the control: with a literal ISA it is one interchange


def test_split_checks_a_chain_of_interchanges_with_no_iea_once_each() -> None:
    import messagefoundry.parsing.x12.interchange as interchange_mod
    from messagefoundry.parsing.x12 import delimiters

    calls = 0
    original = delimiters.isa_separators_line_up

    def counting(buf: Any, isa_at: int) -> bool:
        nonlocal calls
        calls += 1
        return original(buf, isa_at)

    cut = _without_iea(interchange())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(interchange_mod, "isa_separators_line_up", counting)
        assert split(cut * 50) == [cut] * 50
    assert calls <= 50, calls


@pytest.mark.parametrize("segment", ["ISA~", "ISAX*1~", "ISA*00*~"])
@pytest.mark.parametrize("chunk", [4096, 1])
def test_a_short_segment_opening_with_isa_does_not_hold_a_complete_interchange(
    segment: str, chunk: int
) -> None:
    # A body segment that only starts like an ISA must not make the reader wait for a whole header
    # once the interchange's IEA has arrived: a sender waiting for an acknowledgment would stall.
    # Any literal "ISA" that opens a segment ends a passing walk, whether or not it passes, so the
    # interchange is cut there at once and the rest is its own malformed element, both whole.
    raw = interchange().replace("GE*", segment + "GE*", 1)
    cut = raw.index(segment)
    assert split(raw) == [raw[:cut], raw[cut:]]
    reader = X12FrameReader()
    data = raw.encode()
    frames: list[bytes] = []
    for i in range(0, len(data), chunk):
        frames.extend(reader.feed(data[i : i + chunk]))
    assert frames == [raw[:cut].encode()]
    # The reader frames the short rest once the next interchange bounds it, as any short suspect;
    # until then it is an open frame, which the listener's frame deadline covers.
    nxt = interchange(control="000000002").encode()
    assert list(reader.feed(nxt)) == [raw[cut:].encode(), nxt]
    assert not reader.in_frame


@pytest.mark.parametrize("chunk", [4096, 1])
def test_an_isa_in_element_data_does_not_end_an_interchange(chunk: int) -> None:
    # Only an ISA that opens a segment ends the walk: one inside element data is data, even one
    # whose own header passes the check.
    body_isa = isa(control="000000009", term="!")
    raw = interchange().replace("GS*HS*", "GS*HS" + body_isa + "*", 1)
    from messagefoundry.parsing.x12.delimiters import isa_separators_line_up

    assert isa_separators_line_up(raw, raw.index(body_isa))
    assert split(raw) == [raw]
    assert _frames_of(raw.encode(), chunk) == [raw.encode()]


def test_split_checks_each_passing_interchange_once() -> None:
    import messagefoundry.parsing.x12.interchange as interchange_mod
    from messagefoundry.parsing.x12 import delimiters

    calls = 0
    original = delimiters.isa_separators_line_up

    def counting(buf: Any, isa_at: int) -> bool:
        nonlocal calls
        calls += 1
        return original(buf, isa_at)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(interchange_mod, "isa_separators_line_up", counting)
        assert len(split(interchange() * 100)) == 100
    assert calls <= 100, calls


# --- streaming byte frame reader ---------------------------------------------


def test_frame_reader_byte_at_a_time() -> None:
    data = interchange().encode("utf-8")
    reader = X12FrameReader()
    out: list[bytes] = []
    for i in range(len(data)):
        out.extend(reader.feed(data[i : i + 1]))
    assert out == [data]


def test_iea_segment_whitespace_matches_the_shared_set() -> None:
    """The frame reader's IEA pattern skips exactly the whitespace the codec strips before a segment.

    _IEA_SEGMENT spells its class as a literal so the static ReDoS scan can read it; this keeps that
    literal equal to _SEGMENT_WHITESPACE, byte for byte, so the two cannot drift apart.
    """
    from messagefoundry.parsing.x12.delimiters import _SEGMENT_WHITESPACE
    from messagefoundry.parsing.x12.interchange import (
        _IEA_SEGMENT,
        _SEGMENT_WS_RUN,
        _SEGMENT_WS_RUN_STR,
    )

    skipped = {chr(b) for b in range(256) if _IEA_SEGMENT.fullmatch(bytes([b, b, *b"IEA"]))}
    assert skipped == set(_SEGMENT_WHITESPACE)
    assert {chr(b) for b in range(256) if _SEGMENT_WS_RUN.fullmatch(bytes([b]))} == skipped
    assert {chr(c) for c in range(0x10000) if _SEGMENT_WS_RUN_STR.fullmatch(chr(c))} == skipped


def test_frame_reader_two_in_one_feed() -> None:
    a = interchange(control="000000001").encode("utf-8")
    b = interchange(control="000000002").encode("utf-8")
    assert list(X12FrameReader().feed(a + b)) == [a, b]


def test_frame_reader_crlf_terminator() -> None:
    data = interchange(term="\r\n").encode("utf-8")
    assert list(X12FrameReader().feed(data)) == [data]


def test_frame_reader_iea_in_data_does_not_truncate() -> None:
    raw = (
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~REF*XX*IEADATA~SE*3*0001~GE*1*1~IEA*1*000000001~"
    )
    data = raw.encode("utf-8")
    assert list(X12FrameReader().feed(data)) == [data]


# --- a delimiter inside ISA element data (BACKLOG #5536) ---------------------
# The ISA is fixed-width, but every tokenizer used to split it on the delimiters, so a terminator in
# ISA06 could forge an ST, GS or IEA ahead of the real body and an element separator could shift every
# ISA element after it. The str surfaces now refuse such an ISA. split and the frame reader frame it
# whole, so the real body is not dropped, and the parse after them refuses (BACKLOG #5921).


def _split_then_parse(raw: str) -> None:
    """split frames the interchange whole, never at a forged segment, and the parse of that frame
    refuses it where the delimiters are spoofed."""
    try:
        parts = split(raw)
    except X12PeekError as exc:  # split must frame it, not refuse it for the whole buffer
        pytest.fail(f"split raised: {exc}")
    assert parts == [raw]
    X12Message.parse(parts[0])


_REFUSE_STR_SURFACES = [
    pytest.param(discover_delimiters, id="discover_delimiters"),
    pytest.param(X12Peek.parse, id="X12Peek"),
    pytest.param(X12Message.parse, id="X12Message"),
    pytest.param(_split_then_parse, id="split"),
    pytest.param(check_integrity, id="check_integrity"),
]


@pytest.mark.parametrize("surface", _REFUSE_STR_SURFACES)
@pytest.mark.parametrize(
    ("element", "kwargs"),
    [
        pytest.param("ISA-06", {"sender": "A~ST*270~IEA"}, id="ISA06-forged-ST-and-IEA"),
        pytest.param("ISA-06", {"sender": "A~GS*HC~ST*999"}, id="ISA06-forged-GS"),
        pytest.param("ISA-06", {"sender": "A~IEA*1"}, id="ISA06-forged-IEA"),
        pytest.param("ISA-08", {"receiver": "B*SHIFT"}, id="ISA08-element-separator"),
        pytest.param("ISA-06", {"sender": "A\nB", "term": "\r\n"}, id="ISA06-LF-of-CRLF"),
        pytest.param("ISA-08", {"receiver": "B\rC", "term": "\r\n"}, id="ISA08-CR-of-CRLF"),
    ],
)
def test_a_delimiter_in_isa_element_data_is_refused(
    surface: Any, element: str, kwargs: dict[str, Any]
) -> None:
    with pytest.raises(X12PeekError, match=f"{element} holds a delimiter character") as caught:
        surface(interchange(**kwargs))
    # The refusal names the element, never its value.
    value = kwargs.get("sender") or kwargs["receiver"]
    assert value not in str(caught.value) and "IEA" not in str(caught.value)


@pytest.mark.parametrize("surface", _REFUSE_STR_SURFACES)
def test_isa11_is_data_before_00501_so_a_delimiter_there_is_refused(surface: Any) -> None:
    # Before 00501 ISA11 is the standards identifier ("U"), not the repetition separator, so a
    # terminator there is data that would end the ISA at +82.
    with pytest.raises(X12PeekError, match="ISA-11 holds a delimiter character"):
        surface(interchange(version="00401", rep="~"))


@pytest.mark.parametrize("surface", _REFUSE_STR_SURFACES)
@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"receiver": "B:C"}, id="ISA08-component-separator"),
        pytest.param({"sender": "A^B"}, id="ISA06-repetition-separator"),
        pytest.param({"rep": "U", "sender": "UHC"}, id="00501-legacy-ISA11-U"),
    ],
)
def test_the_component_and_repetition_separators_are_not_refused_in_isa_data(
    surface: Any, kwargs: dict[str, Any]
) -> None:
    # Nothing splits the ISA on these two, so they cannot forge a segment or shift an element, and a
    # 00501 header still carrying ISA11 "U" must not refuse every id that holds a U.
    raw = interchange(**kwargs)
    surface(raw)
    assert X12Peek.parse(raw).transaction_ids() == ["270"]
    msg = X12Message.parse(raw)
    assert msg["ISA-13"] == "000000001" and msg["ISA-16"] == ":"


def test_a_clean_isa_still_parses_on_every_surface() -> None:
    # Positive control: space padding and non-delimiter punctuation are ordinary ISA data.
    raw = interchange(sender="ACME-CLAIMS.01", receiver="PAYER #7")
    peek = X12Peek.parse(raw)
    assert peek.sender_id == "ACME-CLAIMS.01" and peek.receiver_id == "PAYER #7"
    assert peek.segment_ids() == ["ISA", "GS", "ST", "SE", "GE", "IEA"]
    assert peek.transaction_ids() == ["270"]
    msg = X12Message.parse(raw)
    assert msg["ISA-08"] == "PAYER #7       " and msg.segment_ids() == peek.segment_ids()
    assert split(raw) == [raw] and check_integrity(raw) == []
    old = interchange(version="00401", rep="U")
    assert X12Peek.parse(old).transaction_ids() == ["270"] and check_integrity(old) == []


@pytest.mark.parametrize(
    ("sender", "term"),
    [("A~IEA*1", "~"), ("A~ST*270~IEA", "~"), ("A\r\nIEA*1", "\r\n")],
)
@pytest.mark.parametrize("chunk", [4096, 1])
def test_frame_reader_frames_a_forged_iea_in_the_isa_whole(
    sender: str, term: str, chunk: int
) -> None:
    # The reader cut the frame at the forged IEA, then dropped the real body as noise. It now frames
    # through the real IEA, and the parse after it refuses, so the interchange reaches the error path.
    data = interchange(sender=sender, term=term).encode("utf-8")
    reader = X12FrameReader()
    frames: list[bytes] = []
    for i in range(0, len(data), chunk):
        frames.extend(reader.feed(data[i : i + chunk]))
    assert frames == [data] and not reader.in_frame
    with pytest.raises(X12PeekError, match="ISA-06 holds a delimiter character"):
        X12Message.parse(frames[0])


# --- streaming byte frame reader: the two oversize caps ----------------------
# ``max_interchange_bytes`` is enforced by two independent guards, so each needs its own test. Every
# test here matches on the message text, because a bare ``pytest.raises(X12FrameError)`` passes just
# as happily via the other guard.


def test_frame_reader_oversize_raises() -> None:
    # Guard one: an interchange that arrived whole and is still too big.
    reader = X12FrameReader(max_interchange_bytes=64)
    with pytest.raises(X12FrameError, match="exceeds the 64-byte cap"):
        list(reader.feed(interchange().encode("utf-8")))


def test_frame_reader_cap_holds_when_no_iea_ever_arrives() -> None:
    # Guard two: a peer that opened an ISA and streamed on without ever closing it would grow the
    # buffer without bound. Guard one cannot reach this case, because no IEA arrives to complete a
    # frame.
    _assert_open_interchange_refused_at_cap(b"REF*XX*PADDING~")


def test_frame_reader_cap_holds_when_iea_appears_in_element_data() -> None:
    # Guard two again, with "IEA" inside element data. The reader used to skip its segment walk until
    # "IEA" appeared anywhere, so this input once took a different path from the one above. The walk
    # now always runs, but the case stays pinned: a false IEA must not let the buffer outgrow the cap.
    _assert_open_interchange_refused_at_cap(b"REF*XX*IEADATA~")


def _assert_open_interchange_refused_at_cap(chunk: bytes) -> None:
    """Stream ``chunk`` after an ISA, never sending an IEA, and require the refusal on the read that
    carries the buffer past the cap.

    Asserting the byte count is the point. A guard that refused only after buffering far past the cap
    would satisfy a bare ``pytest.raises`` and still be the unbounded-growth defect; so would one that
    tripped on the ISA alone, never reaching the across-feeds behaviour under test. The surplus chunks
    are the room a late guard would have used.
    """
    cap = 256
    header = isa().encode("utf-8")
    reader = X12FrameReader(max_interchange_bytes=cap)
    list(reader.feed(header))  # 106 bytes: opening the interchange must not trip the cap by itself
    fed = len(header)
    with pytest.raises(X12FrameError, match="before the IEA segment"):
        for _ in range(40):
            fed += len(chunk)
            list(reader.feed(chunk))
    crossing = -(-(cap + 1 - len(header)) // len(chunk))  # first chunk to carry the buffer past cap
    assert fed == len(header) + crossing * len(chunk) == 271


# --- streaming byte frame reader: scan work stays linear (BACKLOG #1595) -----
# The feed size is the sender's choice, so a reader that rescans its whole buffer on every feed turns a
# slow-drip sender into quadratic CPU. These tests count the bytes ``find`` examines rather than timing
# the run, because wall time flakes on hosted runners and a byte count does not. The count sees only
# ``find``, which is how the reader searches today; a rescan written some other way (a copy of the
# buffer, ``in``, a regex over the whole buffer) would slip past it.


class _CountingBuffer(bytearray):
    """A bytearray that tallies how many bytes each ``find`` call examines."""

    scanned = 0

    def find(self, sub: object, start: object = 0, end: object = None) -> int:
        assert isinstance(sub, bytes) and isinstance(start, int)
        assert end is None or isinstance(end, int)
        stop = len(self) if end is None else end
        idx = super().find(sub, start, stop)
        self.scanned += max(0, (stop if idx == -1 else idx + len(sub)) - start)
        return idx


def _drip(data: bytes, chunk: int) -> tuple[list[bytes], int]:
    """Feed ``data`` ``chunk`` bytes at a time; return the frames and the bytes ``find`` examined."""
    reader = X12FrameReader()
    counter = _CountingBuffer()
    reader._buf = counter  # the seam: every scan the reader does goes through this buffer
    frames: list[bytes] = []
    for i in range(0, len(data), chunk):
        frames.extend(reader.feed(data[i : i + chunk]))
    return frames, counter.scanned


def _big_interchange(term: str, *, segments: int, long_segment: int) -> str:
    """One interchange of many short segments, one very long segment, and ``IEA`` inside element data,
    so the drip exercises the segment walk, a segment that spans many feeds, and a false ``IEA``."""
    body = "".join(f"REF*XX*{i:08d}{term}" for i in range(segments))
    body += "REF*XX*IEADATA" + "P" * long_segment + term
    return isa(term=term) + body + f"IEA*1*000000001{term}"


@pytest.mark.parametrize("term", ["~", "\r\n"])
@pytest.mark.parametrize("chunk", [16, 7])
def test_frame_reader_drip_feed_scan_work_is_linear(term: str, chunk: int) -> None:
    raw = _big_interchange(term, segments=4096, long_segment=64 * 1024)
    noise = b"\r\n  "
    first = raw.encode("utf-8")
    second = raw.replace("000000001", "000000002").encode("utf-8")
    stream = noise + first + noise + second
    frames, scanned = _drip(stream, chunk)
    # The control: dripping changes nothing about what is framed.
    assert frames == [first, second]
    # Each feed pays a few bytes of fixed cost: the ISA check at the front, and a terminator byte that
    # could straddle two feeds. So the bound is a small multiple of the input, and it assumes chunks
    # of several bytes; at one byte per feed a linear reader examines four or five bytes per input
    # byte. A rescan from the buffer front would examine about len(stream) ** 2 / (2 * chunk) bytes,
    # thousands of times this bound at this size.
    assert scanned <= 3 * len(stream), (scanned, len(stream))


def test_frame_reader_scan_work_grows_linearly_with_input() -> None:
    # Doubling the input must roughly double the work, not quadruple it.
    small = _big_interchange("~", segments=2048, long_segment=32 * 1024).encode("utf-8")
    large = _big_interchange("~", segments=4096, long_segment=64 * 1024).encode("utf-8")
    _, small_work = _drip(small, 16)
    _, large_work = _drip(large, 16)
    assert large_work <= 2.5 * small_work, (small_work, large_work)


# --- integrity ---------------------------------------------------------------


def test_integrity_clean_interchange_ties_out() -> None:
    assert check_integrity(interchange()) == []


def test_integrity_flags_control_number_and_count_mismatches() -> None:
    bad = interchange().replace("IEA*1*000000001~", "IEA*9*999999999~")
    problems = check_integrity(bad)
    assert any("IEA02" in p for p in problems)
    assert any("IEA01" in p for p in problems)


# --- mutable message ---------------------------------------------------------


def test_message_round_trip_clean() -> None:
    raw = interchange()
    assert X12Message.parse(raw).encode() == raw


def test_message_round_trip_custom_delimiters() -> None:
    raw = interchange(el="|", comp="^", term="'", rep="~")
    assert X12Message.parse(raw).encode() == raw


def test_message_get_set_element_and_component() -> None:
    msg = X12Message.parse(interchange())
    assert msg["BHT-03"] is None  # no BHT in the minimal interchange
    msg = X12Message.parse(
        isa() + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~"
        "NM1*IL*1*DOE*JANE~SE*3*0001~GE*1*1~IEA*1*000000001~"
    )
    assert msg["NM1-03"] == "DOE"
    msg["NM1-03"] = "SMITH"
    assert msg["NM1-03"] == "SMITH"
    msg.set("NM1-04", "JOHN")
    assert msg["NM1-04"] == "JOHN"
    assert "NM1*IL*1*SMITH*JOHN" in msg.encode()


def test_message_occurrence_selects_segment() -> None:
    msg = X12Message.parse(
        isa() + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~"
        "HL*1**20*1~HL*2*1*21*1~SE*3*0001~GE*1*1~IEA*1*000000001~"
    )
    assert msg.get("HL-01", occurrence=1) == "1"
    assert msg.get("HL-01", occurrence=2) == "2"
    assert msg.count_segments("HL") == 2


def test_message_add_and_delete_segments() -> None:
    msg = X12Message.parse(
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    msg.add_segment("REF*EI*123456789", index=msg.segment_ids().index("SE"))
    assert "REF*EI*123456789" in msg.encode()
    assert msg.delete_segments("REF") == 1
    assert "REF*EI" not in msg.encode()


def test_message_set_rejects_delimiter_injection() -> None:
    msg = X12Message.parse(
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~NM1*IL*1*DOE~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    with pytest.raises(ValueError, match="delimiter"):
        msg.set("NM1-03", "BAD*VALUE")  # element separator would inject a field
    with pytest.raises(ValueError, match="delimiter"):
        msg.set("NM1-03", "BAD~VALUE")  # segment terminator would inject a segment


def test_an_isa_write_keeps_the_fixed_width_and_re_peeks() -> None:
    # vault BACKLOG #2785: a short ISA-06 used to shrink the 106-char header, and X12Peek refused it.
    msg = X12Message.parse(interchange())
    msg["ISA-06"] = "NEWSENDER"
    msg.set_data("ISA-08", "PARTNER")
    msg["ISA-13"] = "42"  # numeric control number: zero-padded, not space-padded
    msg["IEA-02"] = "000000042"  # the trailer is the caller's to keep in step
    out = msg.encode()
    assert out.index("~") == 105  # the ISA keeps its fixed length
    peek = X12Peek.parse(out)
    assert peek.sender_id == "NEWSENDER"
    assert peek.receiver_id == "PARTNER"
    assert peek.control_number == "000000042"
    assert msg["ISA-06"] == "NEWSENDER".ljust(15)
    assert check_integrity(out) == []
    assert len(list(X12FrameReader().feed(out.encode()))) == 1  # the byte-offset reader frames it
    # ADR 0012 names ISA-09 as settable; a full-width date still writes and re-peeks.
    msg["ISA-09"] = "251231"
    assert X12Message.parse(msg.encode())["ISA-09"] == "251231"


def test_an_isa_write_that_cannot_keep_the_layout_is_refused() -> None:
    msg = X12Message.parse(interchange())
    before = msg.encode()
    refused = [
        ("ISA-06", "X" * 16, "fixed at 15"),  # over-length
        ("ISA-09", "2512", "exactly 6"),  # a date is never padded
        ("ISA-13", "ABCDEFGHI", "digits only"),  # numeric at any length
        ("ISA-05", "Z", "exactly 2"),  # a qualifier is a code, never padded
        ("ISA-15", "", "exactly 1"),
        ("ISA-06", "\u00c9" * 15, "printable ASCII only"),  # 15 characters, 30 bytes
        ("ISA-06", "A\tB", "printable ASCII only"),  # a control character
        ("ISA-09", "ABCDEF", "digits only"),  # full width, still not a date
        ("ISA-06", "AB:CD", "delimiter"),  # the component separator in a simple element
        ("ISA-11", "!", "delimiter"),  # the repetition separator
        ("ISA-16", ">", "delimiter"),  # the component separator
        ("ISA-12", "00401", "repetition separator"),  # would turn ISA-11 back into data
        ("ISA-06.1", "X", "no components"),
        ("ISA-17", "X", "does not exist"),
    ]
    for path, value, why in refused:
        with pytest.raises(ValueError, match=why):
            msg.set(path, value)
    assert msg.encode() == before  # a refused write changes nothing
    # The same version gate holds from the other side: a pre-00501 header stays pre-00501.
    old = X12Message.parse(interchange(rep="U", version="00401"))
    old["ISA-12"] = "00402"
    old["ISA-11"] = "U"  # before 00501 ISA-11 is data, not a delimiter
    with pytest.raises(ValueError, match="repetition separator"):
        old["ISA-12"] = "00501"
    assert X12Peek.parse(old.encode()).delimiters.repetition is None


def test_set_data_is_set_on_an_x12_message_and_keeps_one_component() -> None:
    # The Steps view writes msg.set_data for a template reading a component (ADR 0206).
    body = (
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~NM1*IL*1*DOE~SE*2*0001~"
        + "GE*1*1~IEA*1*000000001~"
    )
    a, b = X12Message.parse(body), X12Message.parse(body)
    a.set_data("NM1-03", "SMITH")
    a.set_data("NM1-04.2", "J")
    b.set("NM1-03", "SMITH")
    b.set("NM1-04.2", "J")
    assert a.encode() == b.encode()
    with pytest.raises(ValueError, match="delimiter"):
        a.set_data("NM1-03", "BAD*VALUE")
    with pytest.raises(KeyError):
        a.set_data("REF-02", "X")
    # set takes a component separator in a whole element as structure; set_data refuses it.
    b.set("NM1-03", "O:BRIEN")
    assert b["NM1-03.2"] == "BRIEN"
    with pytest.raises(ValueError, match="delimiter"):
        a.set_data("NM1-03", "O:BRIEN")
    assert a["NM1-03"] == "SMITH"
    # A bad path fails as set fails it, before the value is read.
    with pytest.raises(X12PeekError):
        a.set_data("bad path", "O:BRIEN")


_CLAIM = (
    "GS*HC*A*B*20240101*1200*1*X*005010X222A1~ST*837*0001~CLM*1*100***11{c}B{c}1~"
    "NM1*IL*1*DOE~SE*3*0001~GE*1*1~IEA*1*000000001~"
)

_LENS_HANDLER = """from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    set_field(msg, "NM1-03", "X")
"""


def _claim(comp: str = ":") -> X12Message:
    return X12Message.parse(isa(comp=comp) + _CLAIM.format(c=comp))


def _lens_row(source: str) -> dict[str, Any]:
    row: dict[str, Any] = parse_source(source, contract=CONTRACT_V2)[0]["rows"][-1]
    return row


def _lens_insert_set_field(path: str, expr: str) -> str:
    """The source the Steps view writes when it inserts a Set Field of ``path`` to ``expr``."""
    anchor = parse_source(_LENS_HANDLER)[0]["rows"][0]
    out: str = rewrite_source(
        _LENS_HANDLER,
        {
            "op": "insert_row",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            "position": "after",
            "action": "set_field",
            "params": {"path": path, "value": {"expr": expr}},
        },
    )
    return out


def _lens_edit(source: str, params: dict[str, Any]) -> str:
    """The source the Steps view writes when it edits the last row's ``params``."""
    row = _lens_row(source)
    out: str = rewrite_source(
        source,
        {
            "op": "set_params",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "params": params,
        },
        contract=CONTRACT_V2,
    )
    return out


def _run_last_line(source: str, msg: X12Message) -> None:
    """Run the last line the lens wrote, the write itself, against ``msg``."""
    line = source.splitlines()[-1].strip()
    assert line.startswith("msg.set")
    exec(line, {"msg": msg})  # the lens's own output, run as the handler body would run it


def test_the_lens_set_field_template_line_runs_on_an_x12_message() -> None:
    out = _lens_insert_set_field("NM1-03", "f\"{msg['CLM-05.1'] or ''}\"")
    assert 'msg.set_data("NM1-03"' in out  # a leaf read into a whole element is data
    msg = _claim()
    _run_last_line(out, msg)
    assert msg["NM1-03"] == "11"


@pytest.mark.parametrize("comp", [":", ">"])
def test_a_lens_template_whose_text_holds_the_component_separator_raises_on_x12(comp: str) -> None:
    # Vault #2861: the lens holds no X12 separator, so it writes set_data, and on X12 that refuses
    # the component separator in a whole element. It raises rather than split the value.
    expr = f"f\"{{msg['CLM-05.1'] or ''}}{comp}B{comp}1\""
    inserted = _lens_insert_set_field("NM1-03", expr)
    edited = _lens_edit(
        _LENS_HANDLER.replace('set_field(msg, "NM1-03", "X")', 'msg.set("NM1-03", "X")'),
        {"value": {"parts": [{"path": "CLM-05.1"}, {"text": f"{comp}B{comp}1"}]}},
    )
    for out in (inserted, edited):
        assert 'msg.set_data("NM1-03"' in out
        assert _lens_row(out)["action"] == "set_field"
        msg = _claim(comp)
        with pytest.raises(ValueError, match="delimiter"):
            _run_last_line(out, msg)
        assert msg["NM1-03"] == "DOE"
    # Structure is still the author's to write by hand: a hand-written set keeps the separator.
    msg = _claim(comp)
    msg.set("NM1-03", f"{msg['CLM-05.1'] or ''}{comp}B{comp}1")
    assert msg["NM1-03"] == f"11{comp}B{comp}1"
    assert msg["NM1-03.2"] == "B"


def test_a_path_edit_writes_set_data_for_a_template_holding_the_component_separator() -> None:
    # The hand-written line from the review, its path edited to a whole element in the Steps view.
    # Vault #2861: the edit re-picks set_data, which raises on X12 rather than split the value.
    line = "msg.set(\"NM1-03\", f\"{msg['CLM-05.1'] or ''}:C:2\")"
    source = _LENS_HANDLER.replace('set_field(msg, "NM1-03", "X")', line)
    out = _lens_edit(source, {"path": "CLM-05"})
    assert out.splitlines()[-1] == "    msg.set_data(\"CLM-05\", f\"{msg['CLM-05.1'] or ''}:C:2\")"
    msg = _claim()
    with pytest.raises(ValueError, match="delimiter"):
        _run_last_line(out, msg)
    assert msg.encode() == _claim().encode()  # nothing written: CLM-05 is still 11:B:1
    # The hand-written line, left unedited, still writes its separators as structure.
    msg = _claim()
    _run_last_line(source, msg)
    assert msg["NM1-03"] == "11:C:2"
    assert msg["NM1-03.2"] == "C"


def test_message_refuses_envelope_segment_edits() -> None:
    msg = X12Message.parse(interchange())
    with pytest.raises(ValueError, match="envelope"):
        msg.add_segment("ISA*00*x")
    with pytest.raises(ValueError, match="envelope"):
        msg.delete_segments("IEA")


# --- review follow-ups: additional edge-case coverage ------------------------


def test_peek_orphan_st_without_gs() -> None:
    # An ST with no enclosing GS is malformed, but the peek must not lose it: it surfaces as a group
    # with None envelope fields carrying the transaction (count-and-log: nothing silently dropped).
    raw = isa() + "ST*270*0001~SE*2*0001~IEA*1*000000001~"
    groups = X12Peek.parse(raw).groups()
    assert len(groups) == 1
    assert groups[0].functional_id is None and groups[0].version is None
    assert groups[0].control_number is None and groups[0].transactions == ("270",)


def test_frame_reader_crlf_terminator_byte_at_a_time() -> None:
    # A 2-byte CR+LF terminator split across single-byte socket reads must still frame verbatim.
    data = interchange(term="\r\n").encode("utf-8")
    reader = X12FrameReader()
    out: list[bytes] = []
    for i in range(len(data)):
        out.extend(reader.feed(data[i : i + 1]))
    assert out == [data]


def test_frame_reader_marks_only_an_interchanges_own_line_ends_as_trailer_only() -> None:
    # vault BACKLOG #2938: up to two CR/LF bytes after a completed interchange are its ending, so a
    # listener's frame deadline must not start on them. Mirrors the FrameDecoder test in
    # tests/test_listener_admission.py.
    data = interchange().encode("utf-8")
    reader = X12FrameReader()
    assert list(reader.feed(data)) == [data]
    assert not reader.trailer_only, "a read that completed an interchange is not trailer-only"
    assert list(reader.feed(b"\r")) == []
    assert reader.trailer_only, "the CR after the IEA terminator"
    assert list(reader.feed(b"\n")) == []
    assert reader.trailer_only, "the LF of a CR LF ending"
    # CONTROL: a third line-end byte is past the allowance, so it is noise like any other byte.
    assert list(reader.feed(b"\r")) == []
    assert not reader.trailer_only
    # CONTROL: a byte that is not a line end ends the allowance for what follows it too.
    assert list(reader.feed(data)) == [data]
    assert list(reader.feed(b"Z")) == []
    assert not reader.trailer_only
    assert list(reader.feed(b"\n")) == []
    assert not reader.trailer_only
    # A line end that arrived with the interchange uses up part of the allowance.
    assert list(reader.feed(data + b"\r")) == [data]
    assert list(reader.feed(b"\n")) == []
    assert reader.trailer_only
    assert list(reader.feed(b"\n")) == []
    assert not reader.trailer_only
    # Both line ends in one read of their own.
    assert list(reader.feed(data)) == [data]
    assert list(reader.feed(b"\r\n")) == []
    assert reader.trailer_only
    # An empty read is not trailer-only, and holds no byte to end the allowance with.
    assert list(reader.feed(data)) == [data]
    assert list(reader.feed(b"")) == []
    assert not reader.trailer_only
    assert list(reader.feed(b"\r")) == []
    assert reader.trailer_only
    # CONTROL: three in one read are past the allowance.
    assert list(reader.feed(data)) == [data]
    assert list(reader.feed(b"\r\n\r")) == []
    assert not reader.trailer_only
    # Decided when feed() is called, before its generator runs, so it never describes a past read.
    assert list(reader.feed(data)) == [data]
    reader.feed(b"Z")  # not iterated
    assert not reader.trailer_only
    # Before any interchange there is nothing for a line end to end.
    fresh = X12FrameReader()
    assert list(fresh.feed(b"\r\n")) == []
    assert not fresh.trailer_only
    # A CR+LF segment terminator is the interchange's own, so the allowance starts after it.
    crlf = interchange(term="\r\n").encode("utf-8")
    assert list(fresh.feed(crlf)) == [crlf]
    assert list(fresh.feed(b"\r\n")) == []
    assert fresh.trailer_only


def test_frame_reader_trailer_bytes_still_reach_the_noise_buffer() -> None:
    # The flag only observes. The line ends still sit in the 2-byte noise tail, so the leftover
    # reading the reuse path takes from the buffer, and the next interchange's framing, are unchanged.
    data = interchange().encode("utf-8")
    reader = X12FrameReader()
    assert list(reader.feed(data + b"\r\n")) == [data]
    assert reader._buf == b"\r\n"
    assert list(reader.feed(data)) == [data]
    assert not reader.in_frame


def test_integrity_group_and_transaction_mismatches() -> None:
    # GS06/GE02 control-number mismatch.
    assert any("GE02" in p for p in check_integrity(interchange().replace("GE*1*1~", "GE*1*9~")))
    # ST02/SE02 control-number mismatch.
    assert any(
        "SE02" in p for p in check_integrity(interchange().replace("SE*2*0001~", "SE*2*9999~"))
    )
    # SE01 segment-count mismatch.
    assert any(
        "SE01" in p for p in check_integrity(interchange().replace("SE*2*0001~", "SE*9*0001~"))
    )


@pytest.mark.parametrize(
    "path", ["NM1-0", "NM1-00.1", "NM1-03.0", "NM1", "nm1-03", "NM1_03", "NM1-3.x"]
)
def test_message_invalid_paths_rejected(path: str) -> None:
    msg = X12Message.parse(
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~NM1*IL*1*DOE~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    with pytest.raises(X12PeekError):
        msg.get(path)


def test_message_add_segment_at_boundaries() -> None:
    base = (
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    inserted = X12Message.parse(base)
    inserted.add_segment("REF*EI*1", index=1)  # right after ISA
    assert inserted.segment_ids()[1] == "REF"
    appended = X12Message.parse(base)
    appended.add_segment("REF*EI*2")  # default → appended last
    assert appended.segment_ids()[-1] == "REF"
    count = len(X12Message.parse(base).segment_ids())
    for bad_index in (0, -1, count + 1):
        with pytest.raises(ValueError):
            X12Message.parse(base).add_segment("REF*EI*9", index=bad_index)


def test_message_large_interchange_round_trip() -> None:
    raw = interchange(groups=[("HS", "005010X279A1", ["270"] * 50)])
    msg = X12Message.parse(raw)
    assert msg.encode() == raw  # byte-identical round-trip at scale
    assert msg.count_segments("ST") == 50
    assert check_integrity(raw) == []
    assert X12Peek.parse(raw).transaction_ids() == ["270"] * 50


# --- console carve-out: import purity ---------------------------------------


def test_parsing_x12_pulls_no_heavy_engine_or_gui_modules() -> None:
    """Importing parsing.x12 must NOT pull in the engine internals or the GUI (ADR 0012 + CLAUDE.md §4
    carve-out): no pipeline/store/transports/api/console. (``config`` is excluded here because the root
    ``messagefoundry/__init__`` imports config *models* unconditionally — a baseline shared by all of
    parsing/; that x12's own sources don't import config is enforced by the static test below.)"""
    code = (
        "import sys, messagefoundry.parsing.x12 as _;"
        "heavy=('messagefoundry.pipeline','messagefoundry.store','messagefoundry.transports',"
        "'messagefoundry.api','messagefoundry.console');"
        "bad=sorted(m for m in sys.modules if m.startswith(heavy));"
        "print('\\n'.join(bad));"
        "sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"parsing.x12 pulled heavy engine/GUI modules:\n{result.stdout}"


def test_parsing_x12_sources_import_no_engine_packages() -> None:
    """Every parsing.x12 module must import zero engine packages — config included (the ADR's
    'refer to the content type by the literal "x12"' rule) — so the codec stays pure."""
    import pathlib

    import messagefoundry.parsing.x12 as pkg

    forbidden = (
        "messagefoundry.config",
        "messagefoundry.transports",
        "messagefoundry.pipeline",
        "messagefoundry.store",
        "messagefoundry.api",
        "messagefoundry.console",
    )
    offenders: list[str] = []
    for module_file in sorted(pathlib.Path(pkg.__file__).parent.glob("*.py")):
        for line in module_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for pkg_name in forbidden:
                if stripped.startswith((f"import {pkg_name}", f"from {pkg_name}")):
                    offenders.append(f"{module_file.name}: {stripped}")
    assert not offenders, "parsing.x12 sources import engine packages:\n" + "\n".join(offenders)
