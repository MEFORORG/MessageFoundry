# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
r"""Resolve a bash that can see THIS process's files (BACKLOG #1216).

``shutil.which("bash")`` is a fact about PATH, and on Windows PATH order decides WHICH OPERATING
SYSTEM answers: ``C:\Windows\System32\bash.exe`` is the WSL launcher, whose filesystem namespace is
not the one this process just wrote a fixture into. It strips the backslashes out of a Windows path
and cannot open the file.

**So a ``skipif(shutil.which("bash") is None)`` guard asks the wrong question.** It asks whether A
bash EXISTS, not whether the one it found CAN DO THE JOB -- the wrong interpreter is FOUND rather than
absent, the skip never fires, and every block the test checks fails for a reason that has nothing to
do with its content. Measured on one box, one commit, one session, PATH order the only variable: WSL
bash reported 154 of 154 shell blocks failing; Git Bash reported 47 passed and 7 skipped. **A 100
percent failure rate is an instrument fault, not 154 content faults.**

**LOUD FAILURE, NEVER A SKIP.** ``ci.yml`` sets ``defaults.run.shell: bash`` on every OS, so a leg
without a usable bash cannot run the gate at all -- a skip there is a green that proves nothing (the
silent-control shape ADR 0158 names), and it is worse than a red because a red gets investigated.
Candidates are git-derived first, so the loud failure fires only when no bash on the machine can read
a file the process just wrote, at which point the box cannot run the suite meaningfully anyway.

This module is the SINGLE SOURCE. It was written and proven in ``test_merge_gate_controls.py`` on
2026-08-10; three other modules kept their own ``shutil.which`` guards and so kept the defect. Two
copies of a resolver are free to disagree, and the copy that disagrees is the one still manufacturing
failures.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

#: ``bash`` exits **127** when it cannot FIND the thing it was asked to run and **126** when it found
#: it and could not EXECUTE it (a directory, a bad shebang, no execute bit); it exits **2** on a
#: syntax error in the script. Those are different worlds: 2 is a finding about the CONTENT under
#: test, 126 and 127 are findings about the HARNESS. Conflating them lets a broken harness
#: impersonate a syntax error -- a red that sends a reader to edit a workflow that was never wrong.
BASH_HARNESS_FAILURE = 127
BASH_CANNOT_EXECUTE = 126
BASH_SYNTAX_ERROR = 2

#: The full "bash could not run this at all" set, so a caller asking `returncode not in ...` states
#: the rule ONCE. ``BASH_HARNESS_FAILURE`` is kept beside it because existing callers name it.
CANNOT_RUN_CODES = frozenset({BASH_CANNOT_EXECUTE, BASH_HARNESS_FAILURE})

_PROBE_NAME = "mf_bash_probe.txt"
_PROBE_TOKEN = "MFPROBE-OK"
_TIMEOUT = 120


def bash_candidates() -> list[Path]:
    """Every plausible bash, GIT-DERIVED FIRST.

    Git for Windows always ships bash beside git, so git -- which the callers already require -- is
    the deterministic anchor. Whatever PATH happens to order first is tried LAST, not first.
    """
    found: list[Path] = []
    git = shutil.which("git")
    if git:
        # `<root>/cmd/git.exe`, `<root>/bin/git.exe` and `<root>/mingw64/bin/git.exe` are all shipped
        # layouts, so walk up and try both bash homes from each level.
        #
        # `usr/bin/bash.exe` BEFORE `bin/bash.exe`, AND THE ORDER IS THE WHOLE FIX. Git for Windows'
        # `<root>/bin/bash.exe` is the MINGW64 WRAPPER: it REWRITES the inherited PATH, putting
        # `/mingw64/bin` at the head ahead of anything the caller prepended. `<root>/usr/bin/bash.exe`
        # is the real shell and leaves PATH alone. MEASURED on this box, same command, one variable:
        #
        #     Git/bin/bash.exe      PATH head -> /mingw64/bin   (a prepended stub dir is GONE)
        #     Git/usr/bin/bash.exe  PATH head -> <the prepend>  (preserved)
        #
        # It matters because a test that prepends a stub directory to shadow a real binary is silently
        # bypassed under the wrapper. Git ships `curl.exe` in `mingw64/bin`, so a curl stub loses and
        # the step reaches the LIVE network -- which is how a release-age check passed off pypi.org
        # instead of off its fixture. SELECTIVE, and that is why it looked like flakiness: `gh` and
        # `jq` stubs still win, because Git ships neither there.
        #
        # `bash_sees` CANNOT CATCH THIS and it is not a gap in that probe -- it is a different
        # dimension. It asks whether the interpreter shares this process's FILESYSTEM NAMESPACE, and
        # both binaries do. PATH ORDER is orthogonal, so the control could not fail in the direction
        # this was failing. `bash_preserves_path_order` below is the control for that dimension.
        for parent in Path(git).resolve().parents:
            for rel in ("usr/bin/bash.exe", "bin/bash.exe", "bin/bash"):
                found.append(parent / rel)
    on_path = shutil.which("bash")
    if on_path:
        found.append(Path(on_path))
    return found


def bash_sees(bash: Path, tmp_path: Path, env: dict[str, str] | None = None) -> bool:
    """LIVE POSITIVE CONTROL for the namespace, not a guess from the path string.

    Rejecting ``system32`` by name would be a pattern match on a spelling -- it would pass a WSL bash
    installed anywhere else and fail a legitimate one that happened to live there. This writes a token
    into the directory the fixture will live in and requires the candidate to READ IT BACK. If it
    cannot, it is looking at a different filesystem and every verdict it returns would be about
    nothing.
    """
    probe = tmp_path / _PROBE_NAME
    probe.write_text(_PROBE_TOKEN + "\n", encoding="utf-8")
    try:
        out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
            [str(bash), "-c", f"cat {_PROBE_NAME}"],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except OSError:
        return False
    return out.returncode == 0 and _PROBE_TOKEN.encode() in out.stdout


def bash_preserves_path_order(
    bash: Path, tmp_path: Path, env: dict[str, str] | None = None
) -> bool:
    """LIVE CONTROL for the dimension :func:`bash_sees` cannot see: does a PREPENDED PATH entry stay
    first?

    Git for Windows' `bin/bash.exe` wrapper rewrites PATH so `/mingw64/bin` leads, which silently
    un-shadows any stub a test prepended -- and Git ships `curl.exe` there. `bash_sees` passes on that
    binary because the filesystem namespace is fine; the failure is entirely in PATH order.

    Asserted on the RESOLVED PATH the child reports, not on the string handed in: the wrapper's whole
    behaviour is to rewrite it between here and there, so reading back what the caller set would be
    asking the question in a place where the answer cannot be wrong.
    """
    marker = tmp_path / "mf_path_probe"
    marker.mkdir(exist_ok=True)
    child_env = dict(env) if env is not None else dict(os.environ)
    child_env["PATH"] = str(marker) + os.pathsep + child_env.get("PATH", "")
    try:
        out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
            [str(bash), "-c", "echo $PATH"],
            cwd=str(tmp_path),
            env=child_env,
            capture_output=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except OSError:
        return False
    if out.returncode != 0:
        return False
    head = out.stdout.decode("utf-8", "replace").strip().split(":", 1)[0]
    # The child reports a POSIX-style path, so compare on the leaf rather than the spelling: a
    # tmp_path basename is unique per test, and matching the whole translated path would be an
    # assertion about the translator rather than about ordering.
    return head.rstrip("/").endswith(marker.name)


def require_bash(tmp_path: Path, env: dict[str, str] | None = None) -> str:
    """A bash that can see this process's files, or a loud failure -- NEVER a skip.

    Raises ``RuntimeError`` rather than calling ``pytest.fail`` so this module stays importable
    outside pytest; callers that want a pytest failure let it propagate, which pytest reports as an
    error naming every interpreter tried.
    """
    tried: list[str] = []
    for candidate in bash_candidates():
        if not candidate.is_file():
            continue
        tried.append(str(candidate))
        # BOTH controls, because they answer different questions and a candidate can pass one
        # while failing the other. The MINGW64 wrapper sees the filesystem perfectly and
        # rewrites PATH; a WSL bash preserves PATH order and cannot open the file.
        if bash_sees(candidate, tmp_path, env) and bash_preserves_path_order(
            candidate, tmp_path, env
        ):
            return str(candidate)
    raise RuntimeError(
        "no bash on this machine can read a file this process just wrote. Tried: "
        f"{tried or '(none found)'}. On Windows, `bash` on PATH is often "
        r"C:\Windows\System32\bash.exe -- the WSL launcher, which runs in a different filesystem "
        "namespace, and a control that ran there would be measuring nothing (BACKLOG #1216)."
    )


def explain_returncode(returncode: int, what: str = "the script") -> str:
    """Message text that keeps a HARNESS failure from impersonating a CONTENT failure."""
    if returncode == BASH_HARNESS_FAILURE:
        return (
            f"bash exited {BASH_HARNESS_FAILURE} (command not found) running {what}. That is a "
            "HARNESS fault -- an interpreter or a dependency is missing -- NOT a syntax error in the "
            "content under test. Do not edit the content on the strength of this (BACKLOG #1216)."
        )
    if returncode == BASH_CANNOT_EXECUTE:
        # The VERDICT and the warning-off sentence are word-for-word 127's, because the reader's next
        # action is identical and wording them differently would invite reading one as the milder
        # case. Only the CAUSE clause differs, and it has to: 127 means bash could not find the
        # thing, 126 means it found it and could not run it. Saying "missing" here would be false.
        return (
            f"bash exited {BASH_CANNOT_EXECUTE} (found it, could not execute it) running {what}. "
            "That is a HARNESS fault -- a directory, a bad shebang or a missing execute bit -- NOT "
            "a syntax error in the content under test. Do not edit the content on the strength of "
            "this (BACKLOG #1272)."
        )
    if returncode == BASH_SYNTAX_ERROR:
        return f"bash exited {BASH_SYNTAX_ERROR} (syntax error) in {what} -- a real finding."
    return f"bash exited {returncode} running {what}."
