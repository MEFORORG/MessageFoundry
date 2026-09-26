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
``messagefoundry-webconsole==`` pins are held to ``messagefoundry_webconsole.__version__``. Two
pin-shaped prose forms, ``for engine X.Y.Z`` and ``engine X.Y.Z wheel``, are held to the engine
version, because INSTALL-GUIDE's promotion diagram said ``engine 0.1.0 wheel`` three times after
both pin forms had moved on. And the sweep
covers all six documents ``docs/README.md`` sequences for a new operator, read from the index.
INSTALL-GUIDE's engine pins are now in scope: the illustrative upgrade that kept them out
(``messagefoundry==0.2.0``) reads ``messagefoundry==<new>``, the placeholder EARLY-ADOPTER-GUIDE
already used, and a placeholder is not a digit so no pattern here reads it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from messagefoundry import __version__
from tests._sequenced_docs import sequenced_documents

_ROOT = Path(__file__).resolve().parents[1]

# Read from the file the console's build reads it from (packaging/messagefoundry-webconsole's
# `[tool.hatch.version] path`), not imported. This module runs in the docs-only CI lane, which
# installs the engine and nothing else.
_CONSOLE_INIT = _ROOT / "messagefoundry_webconsole" / "__init__.py"
_CONSOLE_MATCH = re.search(
    r'^__version__ = "([^"]+)"$', _CONSOLE_INIT.read_text(encoding="utf-8"), re.MULTILINE
)
assert _CONSOLE_MATCH is not None, f"no __version__ assignment in {_CONSOLE_INIT}"
_CONSOLE_VERSION = _CONSOLE_MATCH[1]

_VERIFY_ASSIGN = re.compile(r'^\$V = "([^"]+)"', re.MULTILINE)
# A PEP 440 release with its pre, post and dev parts, and nothing after it: a trailing quote, period
# or comma is punctuation, not version. Truncating `0.4.0.post1` to `0.4.0` would read it as current.
_V = r"(\d+(?:\.\d+)+(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?)(?![\w+])"
# The engine pin in a pip command or its inline prose, in any spelling pip accepts: any case, space
# around `==`, spaced or hyphenated extras. The webconsole wheel has its own version, so
# `messagefoundry-webconsole==` must not match; `$V` pins are not literals, so they must not either.
_ENGINE_PIN = re.compile(rf"(?<![\w-])messagefoundry(?:\[[\w,\s-]+\])?\s*==\s*{_V}", re.IGNORECASE)
_CONSOLE_PIN = re.compile(rf"(?<![\w-])messagefoundry[-_]webconsole\s*==\s*{_V}", re.IGNORECASE)
# Two pin-shaped prose forms: "the web console FOR engine 0.4.0" / "BUILT FOR engine 0.4.0", and a
# diagram's "engine 0.1.0 WHEEL". Narrower than any "engine X.Y.Z" on purpose: "added in engine
# 0.2.0" and "works with engine 0.2.0 and later" stay true forever and must not go red on the next
# release. A placeholder (`X.Y.Z`, `<new>`) is not digits, so an illustrative line stays out.
_ENGINE_FOR = re.compile(rf"\b(?:console|built)\s+for\s+engine\s+`?v?{_V}", re.IGNORECASE)
_ENGINE_WHEEL = re.compile(rf"\bengine\s+`?v?{_V}`?\s+wheel\b", re.IGNORECASE)

#: Each pattern with the version it must name. The sweep and the planted control share this, so the
#: control exercises exactly the table the sweep reads.
_PINS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("engine pin", _ENGINE_PIN, __version__),
    ("web console pin", _CONSOLE_PIN, _CONSOLE_VERSION),
    ("console-for-engine note", _ENGINE_FOR, __version__),
    ("engine wheel in prose", _ENGINE_WHEEL, __version__),
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


# Each shape as `{e}`/`{c}` templates: filled with a stale version it must be reported, and filled
# with the shipped one it must read clean.
_SHAPES = (
    'pip install "messagefoundry=={e}"',
    "pip install 'messagefoundry=={e}'",
    "Install messagefoundry=={e}.",
    'pip install "messagefoundry[harness]=={e}"',
    'pip install "messagefoundry[harness, postgres]=={e}"',
    "pip install MessageFoundry == {e}",
    'pip install "messagefoundry-webconsole=={c}"',
    "messagefoundry-webconsole=={c}, the console",
    "pip install messagefoundry_webconsole=={c}",
    "the /ui web console for engine {e}, into the same venv",
    "the console built for engine {e}.",
    "       engine {e} wheel  engine {e} wheel  (pinned, identical)",
    "       Engine {e} wheel",
    "       engine v{e} wheel",
    "       engine `{e}` wheel",
)


@pytest.mark.parametrize("shape", _SHAPES)
@pytest.mark.parametrize(
    ("stale_e", "stale_c"),
    [
        ("0.1.0", "0.0.1"),
        ("0.1.0rc1", "0.0.1rc1"),
        # The shipped version plus a suffix: a capture that truncated it would read it as current.
        (f"{__version__}.post1", f"{_CONSOLE_VERSION}.dev1"),
    ],
)
def test_a_planted_stale_pin_is_caught(shape: str, stale_e: str, stale_c: str) -> None:
    """POSITIVE CONTROL for the sweep: each shape it exists for is reported when stale.

    Paired with the shipped versions, which must read clean, so a pattern that matched nothing would
    fail the first half rather than pass both, and one that read punctuation as part of the version
    would fail the second.
    """
    planted = shape.format(e=stale_e, c=stale_c)
    assert _stale_pins(planted), f"the sweep did not report {planted!r}"
    current = shape.format(e=__version__, c=_CONSOLE_VERSION)
    assert _stale_pins(current) == [], f"the sweep reported the shipped version in {current!r}"


@pytest.mark.parametrize(
    "history",
    [
        "The retry cap was added in engine 0.2.0.",
        "Engine 0.1.0 shipped the first MLLP listener.",
        "The DICOM connector works with engine 0.2.0 and later.",
        "The replay bug was fixed for engine 0.2.0.",
    ],
)
def test_a_version_named_as_history_is_not_a_pin(history: str) -> None:
    """NEGATIVE CONTROL: a true statement about an old release must survive the next release."""
    assert _stale_pins(history) == [], history
