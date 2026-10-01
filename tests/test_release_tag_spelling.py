# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/tag_spelling.py``: which engine tags may release, and that the release runs it.

BACKLOG #2534. A verifier rebuilds the tag from the wheel's version for ``--source-ref``, so the
release refuses every tag spelling that rebuild cannot reproduce. tests/test_scaffold.py runs the
rebuild itself over the tags this module accepts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.release.tag_spelling import allowed, main

_REPO = Path(__file__).resolve().parents[1]

#: Spellings the release accepts. tests/test_scaffold.py runs the wheel-to-tag rebuild over the
#: same shapes, each checked against ``allowed``.
ALLOWED_TAGS = (
    "v0.4.0",
    "v1.0.0",
    "v0.10.12",
    "v0.5.0-a1",
    "v0.5.0-b2",
    "v0.5.0-rc1",
    "v2.0.0-rc10",
)


@pytest.mark.parametrize("tag", ALLOWED_TAGS)
def test_the_two_spellings_pass(tag: str) -> None:
    """POSITIVE CONTROL: every refusal below is evidence only while these pass."""
    assert allowed(tag)
    assert main([tag]) == 0


@pytest.mark.parametrize(
    "tag",
    [
        "v0.5.0-rc.1",  # PEP 440 reads it as 0.5.0rc1, so the rebuilt tag would be v0.5.0-rc1
        "v0.5.0-alpha1",
        "v0.5.0-post1",
        "v0.5.0-dev1",
        "v0.5.0rc1",  # the wheel's spelling; the trigger never fires on it, refused anyway
        "v01.2.3",  # a leading zero PEP 440 drops
        "v0.5.0-rc01",
        "v0.5",
        "0.5.0",
        "webconsole-v0.3.0",
        "v0.5.0-rc1\n",
    ],
)
def test_every_other_spelling_is_refused(tag: str) -> None:
    assert not allowed(tag)
    assert main([tag]) == 1


def test_a_missing_argument_is_a_usage_error() -> None:
    assert main([]) == 2


def _release_steps() -> list[dict[str, Any]]:
    data = yaml.safe_load(
        (_REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    return [s for s in data["jobs"]["release"]["steps"] if isinstance(s, dict)]


def test_the_release_job_checks_the_tag_before_it_runs_anything_else() -> None:
    """The guard must run on every tag push and before the first step that runs a command.

    The release-harness job needs this job, so the guard covers the harness too. The web console
    has its own tag namespace and no verifier rebuilds its tags, so it needs no guard.
    """
    steps = _release_steps()
    call = 'python scripts/release/tag_spelling.py "$GITHUB_REF_NAME"'
    run_steps = [s for s in steps if "run" in s]
    assert len(run_steps) > 5, f"the release job parse found only {len(run_steps)} run steps"
    first = run_steps[0]
    assert first["run"].strip() == call, f"the first run step is not the tag guard: {first}"
    assert first.get("if") == (
        "${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/') }}"
    ), first.get("if")
