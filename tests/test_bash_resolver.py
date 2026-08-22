# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shared bash resolver must reject a wrong interpreter and name a harness fault (BACKLOG #1216).

These are the properties three test modules were missing when they guarded on
``shutil.which("bash") is None``. The defect is not reproducible on a box whose PATH happens to order
Git Bash first -- which is most of them, and is why it survived a full day -- so every test here
CONSTRUCTS the failing condition rather than waiting to encounter it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from _bash_resolver import (
    BASH_HARNESS_FAILURE,
    BASH_SYNTAX_ERROR,
    bash_candidates,
    bash_sees,
    explain_returncode,
    require_bash,
)


def test_a_real_bash_is_found_and_can_read_this_process_files(tmp_path: Path) -> None:
    """POSITIVE CONTROL for every negative below: on this box the resolver succeeds.

    Without this, a resolver that rejected EVERYTHING would satisfy the negative tests perfectly.
    """
    resolved = require_bash(tmp_path)
    assert resolved, "no bash resolved"
    assert bash_sees(Path(resolved), tmp_path), (
        "the resolved bash cannot read the probe it just wrote"
    )


def test_candidates_put_git_derived_paths_before_whatever_path_ordered_first() -> None:
    """The ordering IS the fix: PATH order decides which OS answers, so PATH is consulted LAST."""
    candidates = bash_candidates()
    assert candidates, "no candidates at all -- the probe below would be vacuous"
    from shutil import which

    on_path = which("bash")
    if on_path is None or len(candidates) == 1:
        pytest.skip("nothing on PATH to order against; the git-derived arm is covered above")
    # The PATH entry is appended last, so anything git-derived precedes it.
    assert str(candidates[-1]) == str(Path(on_path)), (
        f"the PATH bash must be tried LAST, got order: {[str(c) for c in candidates]}"
    )


def test_an_interpreter_that_cannot_read_the_probe_is_rejected(tmp_path: Path) -> None:
    """``bash_sees`` is a LIVE namespace probe, not a pattern match on a path spelling.

    Rejecting ``system32`` by name would pass a WSL bash installed elsewhere and fail a legitimate one
    that happened to live there. The Python interpreter stands in for "a real executable that is not a
    bash": it exists, it runs, and it cannot read the probe back.
    """
    assert not bash_sees(Path(sys.executable), tmp_path), (
        "the probe accepted an interpreter that cannot read the file it just wrote"
    )


def test_require_bash_fails_loudly_rather_than_skipping_when_nothing_can_see(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No usable bash must RAISE, never skip -- and the message must name what was tried.

    ci.yml sets ``defaults.run.shell: bash`` on every OS, so a leg without a usable bash cannot run
    the gates these helpers serve. A skip there is a green that proves nothing, which is worse than a
    red because a red gets investigated.
    """
    import _bash_resolver

    monkeypatch.setattr(_bash_resolver, "bash_candidates", lambda: [Path(sys.executable)])
    with pytest.raises(RuntimeError) as ei:
        require_bash(tmp_path)
    message = str(ei.value)
    assert "read a file this process just wrote" in message
    assert Path(sys.executable).name in message, "the failure must name the interpreter it tried"


def test_a_harness_failure_is_never_reported_as_a_syntax_error() -> None:
    """127 and 2 are different worlds, and conflating them sends a reader to edit innocent content.

    A shell that cannot find its interpreter exits 127. A shell that read a broken script exits 2.
    Only the second is a finding about the thing under test.
    """
    harness = explain_returncode(BASH_HARNESS_FAILURE, "a workflow block")
    syntax = explain_returncode(BASH_SYNTAX_ERROR, "a workflow block")
    assert "HARNESS" in harness
    assert "NOT a syntax error" in harness
    assert "syntax error" in syntax and "HARNESS" not in syntax
    # And an unknown code is described rather than silently classified as either.
    other = explain_returncode(3, "a workflow block")
    assert "HARNESS" not in other and "3" in other
