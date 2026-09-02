# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shared bash resolver must reject a wrong interpreter and name a harness fault (BACKLOG #1216).

These are the properties three test modules were missing when they guarded on
``shutil.which("bash") is None``. The defect is not reproducible on a box whose PATH happens to order
Git Bash first -- which is most of them, and is why it survived a full day -- so every test here
CONSTRUCTS the failing condition rather than waiting to encounter it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from _bash_resolver import (
    BASH_CANNOT_EXECUTE,
    BASH_HARNESS_FAILURE,
    BASH_SYNTAX_ERROR,
    CANNOT_RUN_CODES,
    bash_candidates,
    bash_preserves_path_order,
    bash_sees,
    explain_returncode,
    require_bash,
)


def test_a_real_bash_is_found_and_can_read_this_process_files(tmp_path: Path) -> None:
    """POSITIVE CONTROL for every negative below: on this box the resolver succeeds.

    Without this, a resolver that rejected EVERYTHING would satisfy the negative tests perfectly.

    THE SECOND ASSERTION IS DELIBERATELY NOT ``bash_sees(resolved)``, and that is the whole point.
    ``require_bash`` returns only a candidate ``bash_sees`` has already approved, so re-asserting it
    is an IDENTITY -- true by construction, incapable of failing. MEASURED: with ``bash_sees``
    mutated to ``return True``, the two negative tests below both went red and this one stayed
    GREEN, certifying a resolver whose probe was broken wide open. A live first assertion masked a
    dead second one.

    So the check below is INDEPENDENT of the selection predicate: it runs the resolved interpreter
    directly, with a different token, a different file name and a shell builtin rather than ``cat``.
    If the probe is broken open this fails, because a WSL bash genuinely cannot read the file.
    """
    resolved = require_bash(tmp_path)
    assert resolved, "no bash resolved"
    marker = tmp_path / "independent_check.txt"
    marker.write_text("INDEPENDENT-OK\n", encoding="utf-8")
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [resolved, "-c", 'read -r line < independent_check.txt; printf "%s" "$line"'],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0 and b"INDEPENDENT-OK" in proc.stdout, (
        f"the resolved bash ({resolved}) could not read a file this process wrote: "
        f"rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
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


def test_a_cannot_run_exit_is_named_a_harness_fault_and_a_real_finding_is_not(
    tmp_path: Path,
) -> None:
    """126 is the OTHER "cannot run" code, and it was reading as a finding about the content.

    bash exits 127 when it could not FIND the thing and 126 when it found it and COULD NOT EXECUTE it
    -- a directory, a bad shebang, a file with no execute bit. Both are facts about the harness. Only
    2 is a fact about the content under test, so a neutral message on 126 lets a broken invocation
    reach a reader as a syntax error and send them to edit a workflow that was never wrong.

    The 126 is MANUFACTURED LIVE rather than asserted from the table, which keeps this measuring bash
    rather than measuring my own constant. The negative arm is the load-bearing half: widening the
    harness set must not swallow a real syntax error, so 0, 1 and 2 are pinned as NOT harness faults.
    """
    resolved = require_bash(tmp_path)
    (tmp_path / "adir").mkdir()
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [resolved, "-c", "./adir"],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == BASH_CANNOT_EXECUTE, (
        f"asking {resolved} to execute a DIRECTORY returned {proc.returncode}, not "
        f"{BASH_CANNOT_EXECUTE}. This control is meant to measure bash; if the code moved, the "
        f"constant is what needs revisiting, not the message text. stderr={proc.stderr!r}"
    )

    cannot_execute = explain_returncode(BASH_CANNOT_EXECUTE, "a workflow block")
    assert "HARNESS" in cannot_execute and "126" in cannot_execute, (
        f"exit {BASH_CANNOT_EXECUTE} is described neutrally: {cannot_execute!r}. A reader takes that "
        "as a finding about the content, which is the impersonation 127 already has a branch for."
    )
    for real in (0, 1, BASH_SYNTAX_ERROR):
        assert "HARNESS" not in explain_returncode(real, "a workflow block"), (
            f"exit {real} is now labelled a HARNESS fault. Widening the cannot-run set must not "
            "swallow a real finding -- a predicate that says HARNESS to everything says nothing."
        )


def test_the_cannot_run_set_is_exactly_the_two_codes_bash_uses_for_it() -> None:
    """One definition of "cannot run", so a caller cannot hold a second that disagrees.

    ``test_merge_gate_controls`` carried its own ``(126, 127)`` tuple. Two copies of a rule are free
    to drift, and the copy that drifts is the one still reading a broken invocation as a verdict.
    Pinned as an EXACT set: a later widening that quietly admitted 1 or 2 would turn a real finding
    into a harness excuse, which is the direction this whole item guards.
    """
    assert sorted(CANNOT_RUN_CODES) == [BASH_CANNOT_EXECUTE, BASH_HARNESS_FAILURE]
    assert sorted(CANNOT_RUN_CODES) == [126, 127], (
        f"the cannot-run set is {sorted(CANNOT_RUN_CODES)}; callers assert `returncode not in` it to "
        "tell a broken invocation from a verdict"
    )
    assert BASH_SYNTAX_ERROR not in CANNOT_RUN_CODES, (
        "a syntax error is a finding about the CONTENT and must never be excused as a harness fault"
    )


def test_the_resolved_bash_keeps_a_prepended_path_entry_first(tmp_path: Path) -> None:
    """A test that shadows a binary with a stub gets the stub, not the real one.

    Git for Windows' `bin/bash.exe` is the MINGW64 wrapper: it REWRITES the inherited PATH so
    `/mingw64/bin` leads. Git ships `curl.exe` there, so a prepended curl stub is silently bypassed and
    the step reaches the live network. MEASURED: that is how a release-age check passed off pypi.org
    rather than off its fixture, and it broke exactly the rows whose stub Git also ships -- `gh` and
    `jq` stubs kept winning, which is why it read as flakiness rather than as one defect.
    """
    resolved = Path(require_bash(tmp_path))
    assert bash_preserves_path_order(resolved, tmp_path), (
        f"the resolved bash ({resolved}) rewrote PATH, so a stub a test prepends is bypassed"
    )


def test_the_mingw_wrapper_passes_the_namespace_probe_and_fails_the_path_probe(
    tmp_path: Path,
) -> None:
    """THE DISCRIMINATING CASE, and the reason two controls exist rather than one.

    `bash_sees` asks whether the interpreter shares this process's FILESYSTEM NAMESPACE. The wrapper
    does, perfectly. The failure is entirely in PATH ORDER, an orthogonal dimension, so that control
    could not fail in the direction this was failing -- which is why the defect shipped under a probe
    written specifically to catch a wrong interpreter.

    Skips only when the wrapper is genuinely absent, and asserts BOTH halves so a wrapper that stopped
    rewriting PATH would surface here rather than silently weakening the test.
    """
    wrapper = next(
        (
            c
            for c in bash_candidates()
            # `.exe` IS THE PLATFORM TEST, deliberately not sys.platform. The wrapper is
            # `bin/bash.exe` by construction, so the suffix identifies it without a second
            # condition the docstring does not name. MEASURED: without the suffix this matches
            # /bin/bash AND /usr/local/bin/bash on Linux -- parent `bin`, grandparent not
            # `usr` -- so the skip never fired and the test asserted that an ordinary Linux
            # bash rewrites PATH. The assertion was right and the SUBJECT was wrong.
            if (
                c.is_file()
                and c.suffix == ".exe"
                and c.parent.name == "bin"
                and c.parent.parent.name != "usr"
            )
        ),
        None,
    )
    if wrapper is None:
        pytest.skip("no Git-for-Windows bin/bash.exe wrapper on this box to discriminate against")
    assert bash_sees(wrapper, tmp_path), (
        "the wrapper should pass the NAMESPACE probe -- if it does not, this test is no longer "
        "demonstrating that the two controls are orthogonal"
    )
    assert not bash_preserves_path_order(wrapper, tmp_path), (
        "the wrapper no longer rewrites PATH; if Git changed this, the ordering fix in "
        "bash_candidates may be unnecessary -- verify before removing it"
    )


def test_candidates_prefer_usr_bin_over_the_bin_wrapper() -> None:
    """The ordering IS the fix, pinned so a future edit cannot quietly reverse it."""
    names = [str(c).replace("\\", "/") for c in bash_candidates()]
    usr = next((i for i, n in enumerate(names) if n.endswith("usr/bin/bash.exe")), None)
    wrapper = next(
        (i for i, n in enumerate(names) if n.endswith("/bin/bash.exe") and "usr/bin" not in n),
        None,
    )
    if usr is None or wrapper is None:
        pytest.skip("this box does not produce both candidate shapes")
    assert usr < wrapper, f"usr/bin must be tried before the bin wrapper, got {names}"
