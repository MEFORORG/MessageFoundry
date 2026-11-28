# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/tag_spelling.py``: which engine and console tags may release, and that the
release runs it.

BACKLOG #2534. A verifier rebuilds the tag from the wheel's version for ``--source-ref``, so the
release refuses every tag spelling that rebuild cannot reproduce. tests/test_scaffold.py runs the
rebuild itself over the tags this module accepts. The web console's tags are ``webconsole-``
followed by an engine spelling, checked with ``--prefix``, which requires the prefix: the console
ships at the engine's version and never as a ``.postN`` (docs/WEBCONSOLE-PACKAGE.md).
"""

from __future__ import annotations

from typing import Any

import pytest

from scripts.release.tag_spelling import allowed, main
from tests._workflow_contexts import jobs_of

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


#: The console job's ``--prefix``, as release.yml passes it.
_CONSOLE_PREFIX = "webconsole-"


def _console(tag: str) -> int:
    return main(["--prefix", _CONSOLE_PREFIX, tag])


@pytest.mark.parametrize("tag", [f"{_CONSOLE_PREFIX}{t}" for t in ALLOWED_TAGS])
def test_a_console_tag_with_an_engine_spelling_passes(tag: str) -> None:
    """POSITIVE CONTROL for the console refusals below."""
    assert allowed(tag, _CONSOLE_PREFIX)
    assert _console(tag) == 0


@pytest.mark.parametrize(
    "tag",
    [
        "webconsole-v0.5.3-post1",  # the .postN release the version rule forbids
        "webconsole-v0.5.3-rc.1",
        "webconsole-v0.5.3-dev1",
        "webconsole-v0.5.3rc1",
        "webconsole-v05.3.0",
        "webconsole-0.5.3",  # no `v` after the prefix
        "webconsole-webconsole-v0.5.3",  # the prefix is taken once, never twice
        "v0.5.3",  # an engine tag: the prefix is required, never optional
        "",
    ],
)
def test_every_other_console_spelling_is_refused(tag: str) -> None:
    assert not allowed(tag, _CONSOLE_PREFIX)
    assert _console(tag) == 1


def test_a_console_refusal_names_the_whole_tag_and_the_console_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The message is what the maintainer acts on, so it must name the tag they pushed and the
    console spelling to push instead, not the stripped tail and an engine spelling."""
    assert _console("webconsole-v0.5.3-post1") == 1
    out = capsys.readouterr().out
    assert "'webconsole-v0.5.3-post1'" in out, out
    assert "webconsole-vX.Y.Z or webconsole-vX.Y.Z-(a|b|rc)N" in out, out
    assert "--source-ref" not in out, out


@pytest.mark.parametrize("argv", [["--prefix", "webconsole-"], ["--prefix", "", "v0.5.3"], []])
def test_a_malformed_prefix_call_is_a_usage_error(argv: list[str]) -> None:
    assert main(argv) == 2


def _job_steps(job: str) -> list[dict[str, Any]]:
    return [s for s in jobs_of("release.yml")[job].get("steps") or [] if isinstance(s, dict)]


_TAG_PUSH_ONLY = "${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/') }}"


@pytest.mark.parametrize(
    ("job", "call"),
    [
        ("release", 'python scripts/release/tag_spelling.py "$GITHUB_REF_NAME"'),
        (
            "release-webconsole",
            'python scripts/release/tag_spelling.py --prefix webconsole- "$GITHUB_REF_NAME"',
        ),
    ],
)
def test_each_release_job_checks_the_tag_before_it_runs_anything_else(job: str, call: str) -> None:
    """The guard must run on every tag push and before the first step that runs a command.

    The release-harness job needs the engine's ``release`` job, so that guard covers the harness
    too. The console fires on its own ``webconsole-v*`` tag and needs no engine job, so it runs the
    guard itself, with the prefix required.
    """
    run_steps = [s for s in _job_steps(job) if "run" in s]
    # Per job, so the console's shorter job does not lower the engine's floor.
    floor = {"release": 5, "release-webconsole": 3}[job]
    assert len(run_steps) > floor, f"the {job} job parse found only {len(run_steps)} run steps"
    first = run_steps[0]
    assert first["run"].strip() == call, f"the first {job} run step is not the tag guard: {first}"
    assert first.get("if") == _TAG_PUSH_ONLY, first.get("if")
