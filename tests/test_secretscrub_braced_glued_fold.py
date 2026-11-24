# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A braced credential value with text glued after its closer (BACKLOG #2966 steps 1 and 2), and a
keyword spelled with a fold character after a plain value (BACKLOG #3114 step 4).

Synthetic values only. Each shape is read through both surfaces: the write-time
``scrub_credentials`` and the support bundle's ``redact_log_line``, whose first layer is the
``support/redact.py`` copy of the patterns."""

from __future__ import annotations

import pytest

from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support.redact import REDACTION_PLACEHOLDER, redact_log_line

#: The fold characters a keyword head can be spelled with: U+017F folds to "s", U+212A to "k".
_LONG_S = "ſ"

_SURFACES = (
    ("scrub_credentials", scrub_credentials, CREDENTIAL_PLACEHOLDER),
    ("redact_log_line", redact_log_line, REDACTION_PLACEHOLDER),
)

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
@pytest.mark.parametrize("surface", _SURFACES, ids=[s[0] for s in _SURFACES])
def test_a_braced_value_with_glued_text_is_taken_whole(
    line: str, expected: str, surface: tuple[str, object, str]
) -> None:
    _name, apply, placeholder = surface
    assert callable(apply)
    out = apply(line)
    assert out == expected.replace("P", placeholder, 1), out
    assert "ww" not in out


#: Glued text the narrow form refuses, each for a reason stated on ``_SPACED_GUARDED_BRACED``. Each
#: prints exactly what it printed before: the shape is pinned so a widening is a deliberate edit.
_REFUSED_GLUED_SHAPES = (
    "MEFOR_X={pp ww}Xx rest",
    "MEFOR_X={pp ww}x1 rest",
    "MEFOR_X={pp ww}x.y rest",
    "MEFOR_X={pp ww}x-y rest",
    "MEFOR_X={pp ww}x:y rest",
    "MEFOR_X={pp ww};bearer tokenvalue",
    "MEFOR_X={pp ww}password = vq9",
    "MEFOR_X={pp;q ww}x rest",
)


@pytest.mark.parametrize("line", _REFUSED_GLUED_SHAPES)
def test_refused_glued_text_falls_back_to_the_plain_class(line: str) -> None:
    """The braced head up to its first space is still hidden, and the rest is left to later passes."""
    for name, apply, placeholder in _SURFACES:
        out = apply(line)
        assert out.startswith(f"MEFOR_X={placeholder}"), f"{name}: {out!r}"
        assert "pp" not in out, f"{name}: {out!r}"


def test_a_label_after_refused_glued_text_still_hides_its_value() -> None:
    """``password = vq9`` after the glued text stays readable to ``_CREDENTIAL_KV``."""
    for name, apply, _placeholder in _SURFACES:
        out = apply("MEFOR_X={pp ww}password = vq9")
        assert "vq9" not in out, f"{name}: {out!r}"


#: (line, what each surface writes). A keyword spelled with U+017F for its first letter, after a
#: plain value, before a braced value. On ``origin/main`` the ``MEFOR_`` line printed " ww}" on both
#: surfaces and the ``token=`` line printed it on the bundle's.
_FOLD_SHAPES = (
    (f"MEFOR_X=a;{_LONG_S}ecret={{pp ww}}", "MEFOR_X=P xx}"),
    (f"token=a;{_LONG_S}ecret={{pp ww}}", "token=P xx}"),
    (f"MEFOR_X=a;{_LONG_S}ecret={{pp ww ww}}", "MEFOR_X=P xx xx}"),
)


@pytest.mark.parametrize(("line", "expected"), _FOLD_SHAPES, ids=("mefor", "token", "two-words"))
@pytest.mark.parametrize("surface", _SURFACES, ids=[s[0] for s in _SURFACES])
def test_a_fold_character_keyword_reads_as_its_ascii_spelling(
    line: str, expected: str, surface: tuple[str, object, str]
) -> None:
    _name, apply, placeholder = surface
    assert callable(apply)
    out = apply(line)
    assert out == expected.replace("P", placeholder, 1), out
    ascii_line = line.replace(_LONG_S, "s")
    assert apply(ascii_line) == out, "the ASCII spelling reads differently"


def test_a_fold_character_keyword_before_a_quoted_value_stops_the_plain_value() -> None:
    """The same stop before a quoted value: ``"v w"`` is hidden, as the ASCII spelling hides it."""
    line = f'MEFOR_X=a;{_LONG_S}ecret="vqa vqb"'
    for name, apply, _placeholder in _SURFACES:
        out = apply(line)
        assert "vqa" not in out and "vqb" not in out, f"{name}: {out!r}"
