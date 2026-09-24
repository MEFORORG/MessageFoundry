# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The verify-before-install blocks name the version this tree ships.

``docs/INSTALL-GUIDE.md`` and ``docs/EARLY-ADOPTER-GUIDE.md`` open their verify blocks with
``$V = "<version>"``, the release an operator downloads, attests and installs. The 0.4.0 release bumped
``messagefoundry.__version__`` and left both guides at ``"0.1.0"``, so a pasted block verified and
installed a release three versions old. Pinning the literal to ``__version__`` makes the release commit
that bumps the version fail until the guides move with it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from messagefoundry import __version__

_ROOT = Path(__file__).resolve().parents[1]
_ASSIGN = re.compile(r'^\$V = "([^"]+)"', re.MULTILINE)


@pytest.mark.parametrize("doc", ["docs/INSTALL-GUIDE.md", "docs/EARLY-ADOPTER-GUIDE.md"])
def test_every_version_assignment_names_the_shipped_version(doc: str) -> None:
    found = _ASSIGN.findall((_ROOT / doc).read_text(encoding="utf-8"))
    # Armed: a guide that drops or renames the assignment must fail here, not pass on zero matches.
    assert found, f'{doc}: no `$V = "..."` line found; the pattern no longer matches the guide'
    assert set(found) == {__version__}, f"{doc}: $V is {found}, the tree ships {__version__}"
