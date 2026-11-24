# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A braced credential value with text glued after its closer (BACKLOG #2966 steps 1 and 2).

Synthetic values only. Each shape is read through both surfaces: the write-time
``scrub_credentials`` and the support bundle's ``redact_log_line``, whose first layer is the
``support/redact.py`` copy of the patterns and whose PHI pass runs after it."""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable

import pytest

from messagefoundry import redaction
from messagefoundry import secretscrub as scrub_mod
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support import redact as redact_mod
from messagefoundry.support.redact import REDACTION_PLACEHOLDER, redact_log_line

_Surface = tuple[str, Callable[[str], str], str]
_SURFACES: tuple[_Surface, ...] = (
    ("scrub_credentials", scrub_credentials, CREDENTIAL_PLACEHOLDER),
    ("redact_log_line", redact_log_line, REDACTION_PLACEHOLDER),
)
_SURFACE_IDS = [s[0] for s in _SURFACES]

#: (line, what each surface writes, with ``P`` for its placeholder). Each printed the braced value's
#: tail on ``origin/main`` before this change: " ww}x rest", " ww},rest" and so on.
_GLUED_SHAPES = (
    ("MEFOR_X={pp ww}x rest", "MEFOR_X=P rest"),
    ("MEFOR_X={pp ww}x", "MEFOR_X=P"),
    ("MEFOR_X={pp ww};rest", "MEFOR_X=P"),
    ("MEFOR_X={pp ww},rest", "MEFOR_X=P"),
    ("MEFOR_X={pp ww}x&rest tail", "MEFOR_X=P tail"),
    ("private_key={pp ww}x rest", "private_key=P rest"),
    ("private_key={pp ww},rest", "private_key=P"),
    ("private_key={pp ww}x;rest", "private_key=P;rest"),
)


@pytest.mark.parametrize(("line", "expected"), _GLUED_SHAPES, ids=[s[0] for s in _GLUED_SHAPES])
@pytest.mark.parametrize("surface", _SURFACES, ids=_SURFACE_IDS)
def test_a_braced_value_with_glued_text_is_taken_whole(
    line: str, expected: str, surface: _Surface
) -> None:
    _name, apply, placeholder = surface
    out = apply(line)
    assert out == expected.replace("P", placeholder, 1), out
    assert "ww" not in out


def _without_glued_branch(monkeypatch: pytest.MonkeyPatch, replacement: str = "(?!)") -> None:
    """Both copies of ``_MEFOR_SECRET`` and ``_KEY_MATERIAL`` with the glued branch replaced, by
    default with one refusing all."""
    for module in (scrub_mod, redact_mod):
        for name in ("_MEFOR_SECRET", "_KEY_MATERIAL"):
            pattern: re.Pattern[str] = getattr(module, name)
            source = pattern.pattern
            for branch in (scrub_mod._MEFOR_GLUED_BRANCH, scrub_mod._KEY_GLUED_BRANCH):
                source = source.replace(branch, replacement)
            assert source != pattern.pattern, f"{module.__name__}.{name} holds no glued branch"
            monkeypatch.setattr(module, name, re.compile(source, pattern.flags))


#: Shapes the branch refuses, each for a reason stated on ``_SPACED_GUARDED_BRACED``: a capital, a
#: digit, punctuation, a scheme word or a label after the glued text, ";" in the braces, a PHI-pass
#: anchor in the braces or the glued text, a line separator, a word a later pass reads.
_REFUSED_GLUED_SHAPES = (
    "MEFOR_X={pp ww}Xx rest",
    "MEFOR_X={pp ww}x1 rest",
    "MEFOR_X={pp ww}x.y rest",
    "MEFOR_X={pp ww}x-y rest",
    "MEFOR_X={pp ww}x:y rest",
    "MEFOR_X={pp ww};bearer tokenvalue",
    "MEFOR_X={pp ww}password = vq9",
    "MEFOR_X={pp;q ww}x rest",
    "MEFOR_X={pp PID|x}x rest vq9",
    "MEFOR_X={pp ww}mrn 12345",
    "MEFOR_X={pp ww};mrn 12345",
    "MEFOR_X={pp\u2028ww}x rest",
    "MEFOR_X={pp name}x rest",
    "private_key={pp ww}Xx rest",
    "private_key={pp ww}mrn 12345",
    "MEFOR_X={pp ww}nonnumeric port: 'vq7@db.example'",
    "private_key={pp ww}xnonnumeric port: 'vq7@db.example'",
)


@pytest.mark.parametrize("line", _REFUSED_GLUED_SHAPES)
def test_refused_glued_text_reads_as_it_did_without_the_branch(
    line: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly the reading without the branch, which is the reading ``origin/main`` gave."""
    shipped = [apply(line) for _name, apply, _p in _SURFACES]
    _without_glued_branch(monkeypatch)
    before = [apply(line) for _name, apply, _p in _SURFACES]
    assert shipped == before


def test_a_label_after_refused_glued_text_still_hides_its_value() -> None:
    """``password = vq9`` after the glued text stays readable to ``_CREDENTIAL_KV``."""
    for name, apply, _placeholder in _SURFACES:
        out = apply("MEFOR_X={pp ww}password = vq9")
        assert "vq9" not in out, f"{name}: {out!r}"


# --- the differential: both surfaces with and without the glued branch ---------------------------

_ATOM = re.compile(r"vq\d+(?!\d)|9\d{4}|Smith|Jones")
_GLUED_LABELS = ("MEFOR_A", "MEFOR_B_PW", "private_key", "encryption_keys_retired")
_BRACED_TAILS = (
    *("zz", "zz zz", "PID|vq1", "mrn vq1", "(0010,0010) vq1", "PatientName=vq1"),
    *("Smith Jones", "name", "zz;pwd=vq1 zz"),
)
_GLUED_TEXTS = (
    *("zz", ";zz", ",zz", "&zz", "mrn", ";mrn", "zzbearer", "Zz", "zz;pwd=vq2", ""),
    *("nonnumeric", "xnonnumeric"),
)
_AFTER = (
    *("", " vq3", " 91234", " = vq3", " Bearer vq3abcd", " Smith Jones", ";PWD=vq3 zz"),
    *('"vq3"', " port: 'vq3@db.example'"),
)


def _glued_corpus() -> list[str]:
    return [
        f"{label}={{vq0 {tail}}}{glued}{after}"
        for label, tail, glued, after in itertools.product(
            _GLUED_LABELS, _BRACED_TAILS, _GLUED_TEXTS, _AFTER
        )
    ]


def _newly_printed(
    shipped: list[list[str]], before: list[list[str]], corpus: list[str]
) -> list[str]:
    newly = []
    for (name, _apply, _p), now, then in zip(_SURFACES, shipped, before, strict=True):
        for line, after, old in zip(corpus, now, then, strict=True):
            for atom in set(_ATOM.findall(line)):
                if atom in after and atom not in old:
                    newly.append(f"{name}: {atom} in {line!r} -> {after!r}")
    return newly


def _readings(corpus: list[str]) -> list[list[str]]:
    return [[apply(line) for line in corpus] for _name, apply, _p in _SURFACES]


def test_the_glued_branch_prints_nothing_the_reading_without_it_hid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Over every combination of label, braced tail, glued text and what follows, on both surfaces,
    the bundle's PHI pass included: no atom the reading without the branch hid prints with it, and
    the two readings differ somewhere, or nothing was compared. A sample, not a proof."""
    corpus = _glued_corpus()
    shipped = _readings(corpus)
    _without_glued_branch(monkeypatch)
    before = _readings(corpus)
    newly = _newly_printed(shipped, before, corpus)
    assert not newly, f"{len(newly)} atoms newly printed, first: {newly[:3]}"
    assert shipped != before, "the branch changed nothing, so nothing was compared"


def test_the_glued_differential_sees_a_widened_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL. A branch taking any braced value and any glued text up to white space,
    the first form this change tried, must make the differential above find a newly printed atom."""
    corpus = _glued_corpus()
    with monkeypatch.context() as patch:
        _without_glued_branch(patch)
        before = _readings(corpus)
    _without_glued_branch(monkeypatch, r"\{[^}'\"\r\n]* [^}'\"\r\n]*\}(?!\})[^\s'\"]+")
    widened = _readings(corpus)
    assert _newly_printed(widened, before, corpus), "the corpus cannot see a widened branch"


def _words_later_passes_read() -> set[str]:
    """The lower case letter words the sources ``_GLUED_REFUSED_WORDS`` names hold."""
    words = {word.lower() for word in scrub_mod._MEMBER_KEEP_WORDS}
    for source in (
        redaction._DICOM_PHI_LABEL.pattern,
        redaction._CREDENTIAL_AHEAD.pattern,
        redaction._MSH_DELIMITERS.pattern,
        redaction._USERINFO_OPENER,
        redaction._MRN_LABELLED.pattern,
        " ".join(redaction._JSON_LITERALS),
        " ".join(redaction._UNBOUNDED_WORDS),
    ):
        words.update(re.findall(r"[a-z]{2,}", source.lower()))
    return {word for word in words if re.fullmatch("[a-z]+", word)}


def test_the_glued_refused_words_cover_the_words_later_passes_read() -> None:
    """Every such word is refused, and every refused word is one of them."""
    refused = re.compile(scrub_mod._GLUED_REFUSED_WORDS)
    words = _words_later_passes_read()
    assert "nonnumeric" in words and "mrn" in words, "the sources lost a word this test relies on"
    assert all(refused.search(word) for word in words), sorted(
        word for word in words if not refused.search(word)
    )
    listed = scrub_mod._GLUED_REFUSED_WORDS.removeprefix("(?:").removesuffix(")").split("|")
    assert set(listed) <= words, set(listed) - words


def test_the_glued_initials_gate_holds_every_refused_word() -> None:
    """The one-character gate in front of the alternation names each refused word's first letter."""
    gate = re.search(r"\(\?!\[([a-z]+)\]\)", scrub_mod._GLUED_LOWER)
    assert gate is not None, scrub_mod._GLUED_LOWER
    listed = scrub_mod._GLUED_REFUSED_WORDS.removeprefix("(?:").removesuffix(")").split("|")
    assert {word[0] for word in listed} == set(gate.group(1))
