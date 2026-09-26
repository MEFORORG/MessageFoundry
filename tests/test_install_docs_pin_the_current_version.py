# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The install guides name the version this tree ships.

``docs/INSTALL-GUIDE.md`` and ``docs/EARLY-ADOPTER-GUIDE.md`` open their verify blocks with
``$V = "<version>"``, and the guides carry ``pip install "messagefoundry==<version>"`` commands. The
0.4.0 release bumped ``messagefoundry.__version__`` and left the verify blocks and the early-adopter
install command at ``0.1.0``, so a pasted block verified and installed a release three versions old.
Pinning those literals to ``__version__`` makes the release commit that bumps the version fail until
the guides move with it.

BACKLOG #1749 widened it in three ways. The web console wheel is versioned on its own line, so its
``messagefoundry-webconsole==`` pins are held to ``messagefoundry_webconsole.__version__``. An
``engine X.Y.Z`` literal in prose is held to the engine version, because INSTALL-GUIDE's promotion
diagram said ``engine 0.1.0 wheel`` three times after both pin forms had moved on. And the sweep
covers all six documents ``docs/README.md`` sequences for a new operator, read from the index.
INSTALL-GUIDE's engine pins are now in scope: the illustrative upgrade that kept them out
(``messagefoundry==0.2.0``) reads ``messagefoundry==<new>``, the placeholder EARLY-ADOPTER-GUIDE
already used, and a placeholder is not a digit so no pattern here reads it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from _sequenced_docs import sequenced_documents

from messagefoundry import __version__
from messagefoundry_webconsole import __version__ as _CONSOLE_VERSION

_ROOT = Path(__file__).resolve().parents[1]
_VERIFY_ASSIGN = re.compile(r'^\$V = "([^"]+)"', re.MULTILINE)
# The engine pin in a pip command or its inline prose. The webconsole wheel has its own version, so
# `messagefoundry-webconsole==` must not match; `$V` pins are not literals, so they must not either.
_ENGINE_PIN = re.compile(r'(?<![\w-])messagefoundry(?:\[[\w,]+\])?==(\d[^"`\s]*)')
_CONSOLE_PIN = re.compile(r'(?<![\w-])messagefoundry-webconsole==(\d[^"`\s]*)')
# "the console built for engine 0.4.0", "engine 0.1.0 wheel". A placeholder (`X.Y.Z`, `<new>`) is
# not digits, so an illustrative line stays out of it by construction.
_ENGINE_PROSE = re.compile(r"\bengine (\d+\.\d+\.\d+)\b")

#: Each pattern with the version it must name. The sweep and the planted control share this, so the
#: control exercises exactly the table the sweep reads.
_PINS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("engine pin", _ENGINE_PIN, __version__),
    ("web console pin", _CONSOLE_PIN, _CONSOLE_VERSION),
    ("engine version in prose", _ENGINE_PROSE, __version__),
)


def _stale_pins(text: str) -> list[str]:
    """Every pin in ``text`` that names something other than the version its pattern demands."""
    return [
        f"{label} {found} (the tree ships {expected})"
        for label, pattern, expected in _PINS
        for found in pattern.findall(text)
        if found != expected
    ]


@pytest.mark.parametrize(
    ("doc", "pattern", "expected"),
    [
        ("docs/INSTALL-GUIDE.md", _VERIFY_ASSIGN, __version__),
        ("docs/EARLY-ADOPTER-GUIDE.md", _VERIFY_ASSIGN, __version__),
        ("docs/EARLY-ADOPTER-GUIDE.md", _ENGINE_PIN, __version__),
        ("docs/USER-GUIDE.md", _ENGINE_PIN, __version__),
        ("docs/INSTALL-GUIDE.md", _ENGINE_PIN, __version__),
        ("docs/INSTALL-GUIDE.md", _CONSOLE_PIN, _CONSOLE_VERSION),
        ("docs/USER-GUIDE.md", _CONSOLE_PIN, _CONSOLE_VERSION),
    ],
)
def test_every_pin_names_the_shipped_version(
    doc: str, pattern: re.Pattern[str], expected: str
) -> None:
    found = pattern.findall((_ROOT / doc).read_text(encoding="utf-8"))
    # Armed: a guide that drops or reshapes the line must fail here, not pass on zero matches.
    assert found, f"{doc}: {pattern.pattern!r} matched nothing; it no longer fits the guide"
    assert set(found) == {expected}, f"{doc}: pins {found}, the tree ships {expected}"


def test_the_sequenced_documents_pin_only_the_shipped_versions() -> None:
    """Every pin in all six sequenced documents, not only the lines the cases above name.

    The armed cases above prove each pattern still fits its guide. This sweep carries no such arm
    per document, because SYSTEM-REQUIREMENTS, DEPLOYMENT and VERIFY pin nothing today; it is
    armed across the set instead, so a sweep that stopped reading anything cannot pass.
    """
    stale: dict[str, list[str]] = {}
    matched = 0
    for rel in sequenced_documents():
        text = (_ROOT / rel).read_text(encoding="utf-8")
        matched += sum(len(pattern.findall(text)) for _, pattern, _ in _PINS)
        if bad := _stale_pins(text):
            stale[rel] = bad
    assert matched, "no pin of any kind matched across the sequenced documents"
    assert not stale, f"stale pins in the sequenced documents: {stale}"


@pytest.mark.parametrize(
    "planted",
    [
        'pip install "messagefoundry==0.1.0"',
        'pip install "messagefoundry[harness]==0.1.0"',
        'pip install "messagefoundry-webconsole==0.0.1"',
        "       engine 0.1.0 wheel  engine 0.1.0 wheel  (pinned, identical)",
    ],
)
def test_a_planted_stale_pin_is_caught(planted: str) -> None:
    """POSITIVE CONTROL for the sweep: each shape it exists for is reported when stale.

    Paired with the live versions, which must read clean, so a pattern that matched nothing would
    fail the first half rather than pass both.
    """
    assert _stale_pins(planted), f"the sweep did not report {planted!r}"
    current = planted.replace("0.1.0", __version__).replace("0.0.1", _CONSOLE_VERSION)
    assert _stale_pins(current) == [], f"the sweep reported the shipped version in {current!r}"
