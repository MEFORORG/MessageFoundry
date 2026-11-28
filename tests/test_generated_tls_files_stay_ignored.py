# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The repository root `.gitignore` ignores at least the TLS key and certificate files the engine
writes beside a dev store.

The engine writes its generated TLS pair beside the store, and the dev command in CLAUDE.md
section 7 puts the store at the repository root. A re-mint caused only by a trailing dot in the
bind keeps the old private key at ``api-generated-key.pem.replaced``, and a replacement stages the
old certificate at ``api-generated-cert.pem.prior`` (BACKLOG #5973). A replacement also stages the
new pair at ``*.pem.renewing``; a kill or a failed rollback can leave it there. ``*.pem`` matches
none of these names, so without their own rules a ``git add -A`` in a dev checkout would stage a
private key.

The probes are pinned here, not read from `.gitignore`, as in ``test_private_paths_stay_ignored``:
a guard that reads the file it guards moves with it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

_PROBES = [
    "api-generated-key.pem",
    "api-generated-cert.pem",
    "api-generated-key.pem.replaced",
    "api-generated-cert.pem.replaced",
    "api-generated-cert.pem.prior",
    "api-generated-key.pem.renewing",
    "api-generated-cert.pem.renewing",
]

#: A name no ignore line matches, so the probe above can answer non-zero here.
_CONTROL = "api-generated-key.pem.unignored-control"


@pytest.mark.parametrize("probe", _PROBES)
def test_a_generated_pair_sibling_at_the_repo_root_is_ignored(probe: str) -> None:
    result = subprocess.run(  # nosec B603 B607 -- fixed git argv, no shell
        ["git", "check-ignore", "-q", "--no-index", probe],
        cwd=_ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, f"{probe} at the repo root is not ignored by .gitignore"


def test_a_name_no_ignore_line_matches_is_not_ignored() -> None:
    """The control: the same probe answers 1 for a sibling no rule matches, so a pass above is the
    rules' doing, not a probe that always answers 0."""
    result = subprocess.run(  # nosec B603 B607 -- fixed git argv, no shell
        ["git", "check-ignore", "-q", "--no-index", _CONTROL],
        cwd=_ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1, result.stderr
