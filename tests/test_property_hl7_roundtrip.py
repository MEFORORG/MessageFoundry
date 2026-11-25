# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Property tests: the built-in tolerant HL7 parser round-trips what it is given (ADR 0054).

The parity suite (``tests/test_builtin_hl7_parity.py``) holds the parser to a fixed corpus. These
tests generate the corpus instead, so the inputs do not share the corpus author's blind spots. What
they generate is at least: separator sets drawn from 17 ASCII punctuation characters, three-character
segment ids from a fixed grid, empty fields, repetitions, components, subcomponents, spaces anywhere
in a leaf, escape sequences, and non-ASCII data. Not generated, at least: separators that are
letters, digits, control or non-ASCII characters, a short MSH-2, and BHS or FHS headers.

The normalization the parser intends, and the only one asserted here, comes from three places.
:meth:`Message.parse`'s docstring: every line ending (``\\r``, ``\\n``, ``\\r\\n``) becomes ``\\r``.
:func:`~messagefoundry.parsing.peek.drop_blank_segments`: exactly-empty lines are dropped.
:func:`messagefoundry.parsing._builtin_hl7.parse`'s docstring: whitespace around the whole message
is stripped. ``encode()`` ends with a single ``\\r``. Everything inside a segment line is kept byte
for byte.

Every message is synthetic: random tokens from a fixed alphabet, never PHI.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import given
from hypothesis import strategies as st

from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing.message import Message, reencode_with_separators
from tests._hypothesis_settings import property_settings

_SETTINGS = property_settings(max_examples=100)

# Separator candidates: ASCII punctuation. The ones a message does not use are data in its leaves.
_SEPARATOR_POOL = "|^~\\&#!$%*+:;=?@_"
# Data characters: letters, digits and two non-ASCII letters. Spaces are drawn as their own token.
_DATA_ALPHABET = "ABCXYZabcxyz0189éü"

Seps = tuple[str, str, str, str, str]  # (field, component, repetition, subcomponent, escape)


@dataclass(frozen=True)
class Generated:
    """A generated message: its separators, its canonical form, and the raw text a sender sent."""

    seps: Seps
    canonical: str  # what encode() must return: "\r"-joined segment lines plus one trailing "\r"
    raw: str  # the same lines with mixed line endings, blank lines and surrounding whitespace


separator_sets: st.SearchStrategy[Seps] = st.lists(
    st.sampled_from(_SEPARATOR_POOL), min_size=5, max_size=5, unique=True
).map(lambda c: (c[0], c[1], c[2], c[3], c[4]))


def _leaf(seps: Seps) -> st.SearchStrategy[str]:
    """A leaf value: data words, spaces, escape sequences; never a raw source separator."""
    esc = seps[4]
    escape_seq = st.sampled_from(["F", "S", "R", "T", "E", "H", "N", "X41", ".br"]).map(
        lambda body: f"{esc}{body}{esc}"
    )
    # Other separator-pool characters are plain data here, and a rewrite to another set may have to
    # escape them, which is what the cross-set test exercises.
    alphabet = _DATA_ALPHABET + "".join(c for c in _SEPARATOR_POOL if c not in seps)
    word = st.text(alphabet=alphabet, min_size=1, max_size=4)
    return st.lists(st.one_of(word, escape_seq, st.just(" ")), max_size=3).map("".join)


def _field(seps: Seps) -> st.SearchStrategy[str]:
    comp, rep, sub = seps[1:4]
    component = st.lists(_leaf(seps), min_size=1, max_size=3).map(sub.join)
    repetition = st.lists(component, min_size=1, max_size=3).map(comp.join)
    return st.lists(repetition, min_size=1, max_size=3).map(rep.join)


_SEGMENT_ID = st.tuples(
    st.sampled_from("APORZ"), st.sampled_from("IVBXT1"), st.sampled_from("DSX12")
).map("".join)  # no tuple spells MSH, BHS or FHS

_TERMINATOR = st.lists(st.sampled_from(["\r", "\n", "\r\n"]), min_size=1, max_size=3).map("".join)


@st.composite
def messages(draw: st.DrawFn) -> Generated:
    seps = draw(separator_sets)
    field_sep, comp, rep, sub, esc = seps
    # Empty fields are drawn on purpose, not left to chance, because trailing empty fields
    # (``PID|1||``) are common HL7 and a rebuild that trims them is a plausible defect.
    field = st.one_of(st.just(""), _field(seps))
    msh_fields = draw(st.lists(field, max_size=10))
    lines = [field_sep.join([f"MSH{field_sep}{comp}{rep}{esc}{sub}", *msh_fields])]
    for _ in range(draw(st.integers(min_value=0, max_value=5))):
        lines.append(field_sep.join([draw(_SEGMENT_ID), *draw(st.lists(field, max_size=6))]))
    # The parser strips whitespace around the whole message, so trailing spaces on the LAST line are
    # the one place a byte-identical round trip is not owed. Every other leaf keeps its edge spaces.
    lines[-1] = lines[-1].rstrip(" ")
    canonical = "\r".join(lines) + "\r"

    # The sender's framing: any mix of line endings, blank lines between segments, and whitespace
    # around the whole message. None of it may survive into encode().
    raw = draw(st.sampled_from(["", " ", "\n", "\r\n "]))
    for line in lines:
        raw += line + draw(_TERMINATOR)
    raw += draw(st.sampled_from(["", " ", "\r\n", "\n \n"]))
    return Generated(seps=seps, canonical=canonical, raw=raw)


@_SETTINGS
@given(messages())
def test_parse_and_rebuild_preserve_every_byte(gen: Generated) -> None:
    """Three properties of one message, asserted together so the generation is paid for once.

    1. ``Message.parse(raw).encode()`` is the canonical text: only the documented framing goes.
    2. The separators are read from MSH-1 and MSH-2, whatever set the sender chose.
    3. A full rebuild loses no byte, and each field's cached repetition, component and subcomponent
       split joins back to its text. A clean ``encode()`` returns the cached text, so property 1
       never exercises the rebuild a mutation triggers; this one splits every segment,
       componentizes every data field, drops the cache and rebuilds. It is not the mixed path of a
       real edit, where untouched segments stay lazy and are written back verbatim.
    """
    assert Message.parse(gen.raw).encode() == gen.canonical, "parse then encode"

    parsed = _builtin_hl7.parse(gen.canonical)
    assert _builtin_hl7.separators(parsed) == gen.seps, "separators from MSH"

    _field_sep, comp, rep, sub, _esc = seps = parsed["seps"]
    for index, seg in enumerate(parsed["segments"]):
        _builtin_hl7._ensure_split(parsed, index)
        first_data = 3 if seg["id"] in _builtin_hl7.HEADER_IDS else 1
        for fld in range(first_data, len(seg["fields"])):
            entry = _builtin_hl7._componentize(parsed, index, fld, seps)
            joined = rep.join(comp.join(sub.join(c) for c in r) for r in entry["reps"])
            assert joined == entry["text"], "componentized split"
    parsed["raw"] = None
    assert _builtin_hl7.encode(parsed) == gen.canonical, "full rebuild"


@_SETTINGS
@given(messages(), separator_sets)
def test_reencode_to_another_set_and_back_is_identity(gen: Generated, target: Seps) -> None:
    """A rewrite to any other separator set and back restores the original bytes (ADR 0206 rule 4).

    A leaf never holds a source separator, but it may hold a TARGET delimiter as data, which the
    first rewrite must escape and the second must turn back into the literal character. A separator
    escape is decoded against one set and re-escaped against the other, so its letter may change on
    the way out; only the round trip is asserted, not how each leaf reads under the target set.
    """
    there = reencode_with_separators(gen.canonical, target)
    assert _builtin_hl7.separators(_builtin_hl7.parse(there)) == target
    assert reencode_with_separators(there, gen.seps) == gen.canonical
