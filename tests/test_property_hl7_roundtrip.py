# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Property tests: the built-in tolerant HL7 parser round-trips what it is given (ADR 0054).

The parity suite (``tests/test_builtin_hl7_parity.py``) holds the parser to a fixed corpus. These
tests generate the corpus instead, so the inputs do not share the corpus author's blind spots: any
separator set, any segment ids, empty fields, repetitions, components, subcomponents, escape
sequences and non-ASCII data.

The normalization the parser intends, and the only one asserted here, is :meth:`Message.parse`'s
own docstring and :func:`~messagefoundry.parsing.peek.drop_blank_segments`: every line ending
(``\\r``, ``\\n``, ``\\r\\n``) becomes ``\\r``, exactly-empty lines are dropped, whitespace around
the whole message is dropped, and ``encode()`` ends with a single ``\\r``. Everything inside a
segment line is kept byte for byte.

Every message is synthetic: random tokens from a fixed alphabet, never PHI.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing.message import Message, reencode_with_separators

# Deterministic in CI and locally: derandomize fixes the example sequence, and no example database
# is written into the checkout. The deadline is per example; the cap keeps each test well under 10 s.
_SETTINGS = settings(
    derandomize=True,
    database=None,
    max_examples=100,
    deadline=500,
    suppress_health_check=[HealthCheck.too_slow],
)

# Separator candidates: ASCII punctuation. The ones a message does not use are data in its leaves.
_SEPARATOR_POOL = "|^~\\&#!$%*+:;=?@_"
# Data characters: letters, digits and two non-ASCII letters. A space goes only between tokens.
_DATA_ALPHABET = "ABCXYZabcxyz0189\u00e9\u00fc"
_HEADER_IDS = {"MSH", "BHS", "FHS"}

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
    """A leaf value: data words, an inner space, escape sequences; never a raw source separator.

    No leading or trailing space: the parser strips whitespace around the whole message, so a final
    field ending in a space would be the one place a byte-identical round trip is not owed.
    """
    esc = seps[4]
    escape_seq = st.sampled_from(["F", "S", "R", "T", "E", "H", "N", "X41", ".br"]).map(
        lambda body: f"{esc}{body}{esc}"
    )
    # Other separator-pool characters are plain data here, and a rewrite to another set may have to
    # escape them, which is what the cross-set test exercises.
    alphabet = _DATA_ALPHABET + "".join(c for c in _SEPARATOR_POOL if c not in seps)
    word = st.text(alphabet=alphabet, min_size=1, max_size=4)
    token = st.one_of(word, escape_seq)
    spaced = st.tuples(token, st.sampled_from(["", " "]))
    return st.lists(spaced, max_size=3).map(
        lambda pairs: "".join(t + g for t, g in pairs).rstrip(" ")
    )


def _field(seps: Seps) -> st.SearchStrategy[str]:
    comp, rep, sub = seps[1:4]
    component = st.lists(_leaf(seps), min_size=1, max_size=3).map(sub.join)
    repetition = st.lists(component, min_size=1, max_size=3).map(comp.join)
    return st.lists(repetition, min_size=1, max_size=3).map(rep.join)


_SEGMENT_ID = st.tuples(
    st.sampled_from("APORZ"), st.sampled_from("IVBXT1"), st.sampled_from("DSX12")
).map("".join)  # no tuple spells MSH, BHS or FHS


@st.composite
def messages(draw: st.DrawFn) -> Generated:
    seps = draw(separator_sets)
    field_sep, comp, rep, sub, esc = seps
    field = _field(seps)
    msh_fields = draw(st.lists(field, max_size=10))
    msh = field_sep.join([f"MSH{field_sep}{comp}{rep}{esc}{sub}", *msh_fields])
    lines = [msh]
    for _ in range(draw(st.integers(min_value=0, max_value=5))):
        seg_id = draw(_SEGMENT_ID)
        fields = draw(st.lists(field, max_size=6))
        lines.append(field_sep.join([seg_id, *fields]))
    canonical = "\r".join(lines) + "\r"

    # The sender's framing: any mix of line endings, blank lines between segments, and whitespace
    # around the whole message. None of it may survive into encode().
    terminator = st.lists(st.sampled_from(["\r", "\n", "\r\n"]), min_size=1, max_size=3).map(
        "".join
    )
    raw = draw(st.sampled_from(["", " ", "\n", "\r\n "]))
    for line in lines:
        raw += line + draw(terminator)
    raw += draw(st.sampled_from(["", " ", "\r\n", "\n \n"]))
    return Generated(seps=seps, canonical=canonical, raw=raw)


@_SETTINGS
@given(messages())
def test_parse_then_encode_is_the_canonical_text(gen: Generated) -> None:
    """``Message.parse(raw).encode()`` is the canonical text: only the documented framing goes."""
    assert Message.parse(gen.raw).encode() == gen.canonical


@_SETTINGS
@given(messages())
def test_parse_reads_the_separators_from_msh(gen: Generated) -> None:
    """The parser takes its separators from MSH-1 and MSH-2, whatever set the sender chose."""
    assert _builtin_hl7.separators(_builtin_hl7.parse(gen.canonical)) == gen.seps


@_SETTINGS
@given(messages())
def test_rebuilt_encode_is_byte_identical(gen: Generated) -> None:
    """Forcing every segment and field through the split model and rebuilding loses no byte.

    A clean ``encode()`` returns the cached text, so the first test never exercises the rebuild that
    any mutation triggers. This one splits every segment, componentizes every data field, drops the
    cache and rebuilds, which is the path a Handler's edit takes for every segment it did not touch.
    """
    parsed = _builtin_hl7.parse(gen.canonical)
    seps = parsed["seps"]
    for index, seg in enumerate(parsed["segments"]):
        _builtin_hl7._ensure_split(parsed, index)
        first_data = 3 if seg["id"] in _HEADER_IDS else 1
        for fld in range(first_data, len(seg["fields"])):
            _builtin_hl7._componentize(parsed, index, fld, seps)
    parsed["raw"] = None
    assert _builtin_hl7.encode(parsed) == gen.canonical


@_SETTINGS
@given(messages())
def test_reencode_with_own_separators_is_identity(gen: Generated) -> None:
    """Re-serializing with the message's own separator set changes nothing."""
    assert reencode_with_separators(gen.canonical, gen.seps) == gen.canonical


@_SETTINGS
@given(messages(), separator_sets)
def test_reencode_to_another_set_and_back_is_identity(gen: Generated, target: Seps) -> None:
    """A rewrite to any other separator set and back restores the original bytes (ADR 0206 rule 4).

    No data character here is a separator of either set, so every leaf has one spelling under each
    set and the rewrite owes an exact return. The escape sequences, the separator escapes included,
    keep their letters across both rewrites.
    """
    there = reencode_with_separators(gen.canonical, target)
    assert _builtin_hl7.separators(_builtin_hl7.parse(there)) == target
    assert reencode_with_separators(there, gen.seps) == gen.canonical
