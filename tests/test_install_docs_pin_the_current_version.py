# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The install guides name the version this tree ships.

``docs/INSTALL-GUIDE.md`` and ``docs/EARLY-ADOPTER-GUIDE.md`` open their verify blocks with
``$V = "<version>"``, and the guides carry ``pip install "messagefoundry==<version>"`` commands. The
0.4.0 release bumped ``messagefoundry.__version__`` and left the verify blocks and the early-adopter
install command at ``0.1.0``, so a pasted block verified and installed a release three versions old.
Pinning those literals to ``__version__`` makes the release commit that bumps the version fail until
the guides move with it. INSTALL-GUIDE's engine pins are left out on purpose: it also shows an
illustrative upgrade to another version (``messagefoundry==0.2.0``), which is not a stale pin.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from messagefoundry import __version__

_ROOT = Path(__file__).resolve().parents[1]
_VERIFY_ASSIGN = re.compile(r'^\$V = "([^"]+)"', re.MULTILINE)
# The engine pin in a pip command or its inline prose. The webconsole wheel has its own version, so
# `messagefoundry-webconsole==` must not match; `$V` pins are not literals, so they must not either.
_ENGINE_PIN = re.compile(r'(?<![\w-])messagefoundry(?:\[[\w,]+\])?==(\d[^"`\s]*)')


@pytest.mark.parametrize(
    ("doc", "pattern"),
    [
        ("docs/INSTALL-GUIDE.md", _VERIFY_ASSIGN),
        ("docs/EARLY-ADOPTER-GUIDE.md", _VERIFY_ASSIGN),
        ("docs/EARLY-ADOPTER-GUIDE.md", _ENGINE_PIN),
        ("docs/USER-GUIDE.md", _ENGINE_PIN),
    ],
)
def test_every_pin_names_the_shipped_version(doc: str, pattern: re.Pattern[str]) -> None:
    found = pattern.findall((_ROOT / doc).read_text(encoding="utf-8"))
    # Armed: a guide that drops or reshapes the line must fail here, not pass on zero matches.
    assert found, f"{doc}: {pattern.pattern!r} matched nothing; it no longer fits the guide"
    assert set(found) == {__version__}, f"{doc}: pins {found}, the tree ships {__version__}"
