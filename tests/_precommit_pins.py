# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read each remote hook repository's pin out of ``.pre-commit-config.yaml``: its commit and its tag.

vault BACKLOG #2631, limb 4. Every remote ``rev:`` is a 40-character commit, with the tag it was
pinned from beside it as ``# frozen: <tag>``, the form ``pre-commit autoupdate --freeze`` writes.
A YAML parser drops comments, so the tag is read from the raw lines here, once, for every test that
compares a hook's VERSION with something else. Comparing the commit itself with a version would
compare a hash with a number.
"""

from __future__ import annotations

import re
from pathlib import Path

PRECOMMIT = Path(__file__).resolve().parents[1] / ".pre-commit-config.yaml"

_REPO = re.compile(r"^\s*-\s*repo:\s*(\S+)\s*$")
_REV = re.compile(r"^\s*rev:\s*(\S+)\s*(?:#\s*frozen:\s*(\S+))?\s*$")
COMMIT = re.compile(r"[0-9a-f]{40}")


def pins(text: str | None = None) -> dict[str, tuple[str, str | None]]:
    """``{repo url: (rev, frozen tag or None)}`` for every repository that declares a ``rev:``."""
    found: dict[str, tuple[str, str | None]] = {}
    repo: str | None = None
    for line in (PRECOMMIT.read_text(encoding="utf-8") if text is None else text).splitlines():
        if m := _REPO.match(line):
            repo = m.group(1)
        elif (m := _REV.match(line)) and repo is not None:
            found[repo] = (m.group(1), m.group(2))
            repo = None
    return found


def frozen_tag(repo_url: str) -> str:
    """The tag ``repo_url``'s commit was pinned from. Fails loudly when there is none."""
    entry = pins().get(repo_url)
    assert entry is not None, f"no `rev:` found for {repo_url!r} in {PRECOMMIT.name}"
    rev, tag = entry
    assert COMMIT.fullmatch(rev) and tag, (
        f"{repo_url} is pinned as `rev: {rev}` with frozen tag {tag!r}. A remote hook repository "
        "is pinned by a 40-character commit with its tag beside it as `# frozen: <tag>` (vault "
        "BACKLOG #2631); move it with `pre-commit autoupdate --freeze --repo <url>`."
    )
    return tag
