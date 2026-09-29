# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import atexit
import os
import shlex
import shutil
import subprocess
import tempfile
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
    return _probe(bash, tmp_path, env)[0]


def probe_env(bash: Path, env: dict[str, str] | None = None) -> dict[str, str]:
    """A child environment that can find the ordinary utilities (BACKLOG #1373).

    ***THE UTILITIES SHIP BESIDE BASH, SO THE INTERPRETER'S OWN DIRECTORY IS THE ANSWER.*** On Git
    for Windows ``cat``, ``tr``, ``grep`` and ``sort`` live in the same ``usr/bin`` as ``bash.exe``;
    on Linux they share ``/usr/bin``. Deriving it from the interpreter means no install location is
    spelled out here, and a caller that already supplied a working PATH is unaffected.

    ***APPENDED, NEVER PREPENDED, AND THAT IS LOAD-BEARING.*** ``bash_preserves_path_order`` asserts
    that an entry the CALLER prepended is still first in the child. That control exists because Git
    ships ``curl.exe`` in ``mingw64/bin``, and a stub that lost to it sent a release-age check to the
    live network. Prepending here would shadow the caller's stub and defeat that control silently.
    Appending cannot: it only adds a fallback behind everything the caller already chose.

    ***ONE ADDITION AHEAD OF THE APPEND: A SHIM THAT ANSWERS ONLY ``bash``.*** A bash or POSIX child
    that runs ``bash`` by name, or a ``#!/usr/bin/env bash`` stub, resolves it against this PATH. A
    NATIVE Windows grandchild uses PATHEXT, never sees the extensionless shim, and is not covered. On a Windows
    box with WSL installed, ``C:\\Windows\\System32`` holds the WSL launcher and sits ahead of any
    appended entry, so the grandchild lands in another filesystem namespace. Measured 2026-09-28
    (owner instruction of that date): a ``gh`` stub exited 127 with "No such file or directory", and a
    nested ``bash -c`` ran nothing. So when a DIFFERENT bash sits earlier on PATH, a directory holding
    one file, ``bash``, which execs THIS interpreter, goes immediately before that entry.

    It is a shim and not the interpreter's own directory because that directory holds every GNU
    utility too: moving it would re-rank ``sort``, ``find``, ``curl`` and the rest against everything
    after the insertion point. The shim re-ranks one name. Every entry ahead of the other bash stays
    ahead, so a prepended stub directory still wins -- UNLESS the stub is itself a ``bash``. Nothing
    here can tell a deliberate ``bash`` stub from the WSL launcher, so a caller stubbing ``bash`` must
    build its own PATH rather than call this.
    """
    child = dict(env) if env is not None else dict(os.environ)
    own = str(bash.parent)
    current = child.get("PATH", "")
    entries = current.split(os.pathsep) if current else []
    shadow = _first_other_bash(entries, bash)
    if shadow is not None:
        entries.insert(shadow, str(_bash_shim(bash)))
    entries.append(own)
    child["PATH"] = os.pathsep.join(entries)
    return child


#: One shim directory per interpreter per import of this module, removed at exit. A hard kill that
#: skips atexit leaves one small directory in the temp dir.
_SHIMS: dict[str, Path] = {}
_SHIM_PREFIX = "mf-bash-shim-"


def _bash_shim(bash: Path) -> Path:
    """A directory whose only file is a ``bash`` that execs ``bash``.

    ``/bin/sh`` rather than the interpreter's own path in the shebang, because that path has a space
    in it on Windows (``C:/Program Files/Git``) and a shebang cannot quote one. The exec line can.
    """
    key = str(bash)
    shim = _SHIMS.get(key)
    if shim is None:
        shim = Path(tempfile.mkdtemp(prefix=_SHIM_PREFIX))
        atexit.register(shutil.rmtree, shim, True)
        script = shim / "bash"
        script.write_text(
            f'#!/bin/sh\nexec {shlex.quote(bash.as_posix())} "$@"\n', encoding="utf-8", newline="\n"
        )
        script.chmod(0o755)
        _SHIMS[key] = shim
    return shim


def _first_other_bash(entries: list[str], bash: Path) -> int | None:
    """Index of the first PATH entry that would answer ``bash`` with a DIFFERENT binary, or None.

    Stops where the right bash already wins by PATH order: the interpreter's own directory under any
    spelling, or the shim this module made for THIS interpreter. Skips empty and relative entries,
    which name the CHILD's working directory, not this process's.
    """

    def norm(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    stops = {norm(str(bash.parent))}
    if str(bash) in _SHIMS:
        stops.add(norm(str(_SHIMS[str(bash)])))
    # `bash.exe` answers `bash` only on Windows; a POSIX PATH search never appends an extension.
    names = ("bash.exe", "bash") if os.name == "nt" else ("bash",)
    for index, entry in enumerate(entries):
        if not entry or not os.path.isabs(entry):
            continue
        if norm(entry) in stops:
            return None
        for name in names:
            candidate = os.path.join(entry, name)
            # lexists, NOT is_file: is_file swallows a failed stat and answers False, and an
            # app-execution alias such as WindowsApps\bash.exe is a reparse point that still
            # answers `bash` by name.
            if not os.path.lexists(candidate) or os.path.isdir(candidate):
                continue
            if os.name != "nt" and not os.access(candidate, os.X_OK):
                continue  # bash's own PATH search skips a file it cannot execute
            try:
                if os.path.samefile(candidate, bash):
                    return None  # our own interpreter, under another spelling, already leads
            except OSError:
                pass  # cannot prove it is the same binary, so it may shadow ours
            return index
    return None


def _probe(
    bash: Path, tmp_path: Path, env: dict[str, str] | None = None
) -> tuple[bool, int | None]:
    """Run the read-back probe. Returns (saw the token, the exit code).

    ***THE EXIT CODE IS CARRIED OUT BECAUSE 127 IS NOT A VERDICT ABOUT THE CANDIDATE.*** This module
    already says so at ``BASH_HARNESS_FAILURE``: 127 is a finding about the HARNESS. A caller given
    only a bool cannot tell "this interpreter is in another filesystem namespace" from "the probe
    could not run at all", and those want opposite responses -- reject the candidate, or repair the
    environment. ``None`` means the process never started.
    """
    probe = tmp_path / _PROBE_NAME
    probe.write_text(_PROBE_TOKEN + "\n", encoding="utf-8")
    # OUTSIDE the try: probe_env may write a shim, and a temp-dir failure there is a HARNESS fault.
    # Caught below, it would read as "this interpreter cannot see the file" -- a false namespace verdict.
    child_env = probe_env(bash, env)
    try:
        out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
            [str(bash), "-c", f"cat {_PROBE_NAME}"],
            cwd=str(tmp_path),
            env=child_env,
            capture_output=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except OSError:
        return False, None
    return out.returncode == 0 and _PROBE_TOKEN.encode() in out.stdout, out.returncode


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
    codes: list[int | None] = []
    for candidate in bash_candidates():
        if not candidate.is_file():
            continue
        tried.append(str(candidate))
        # BOTH controls, because they answer different questions and a candidate can pass one
        # while failing the other. The MINGW64 wrapper sees the filesystem perfectly and
        # rewrites PATH; a WSL bash preserves PATH order and cannot open the file.
        saw, code = _probe(candidate, tmp_path, env)
        codes.append(code)
        if saw and bash_preserves_path_order(candidate, tmp_path, env):
            return str(candidate)
    # EVERY CANDIDATE EXITED 127 => THE PROBE NEVER RAN, so nothing observed is a finding about any
    # interpreter's filesystem namespace (BACKLOG #1373). Saying "no bash can read a file this
    # process just wrote" there is FALSE, and it is the expensive kind of false: it names a namespace
    # problem, so a reader goes looking at WSL and interpreter paths instead of at PATH.
    if codes and all(c == BASH_HARNESS_FAILURE for c in codes):
        raise RuntimeError(
            f"{explain_returncode(BASH_HARNESS_FAILURE, 'the bash probe')} Every candidate exited "
            f"{BASH_HARNESS_FAILURE}, so this says NOTHING about any interpreter's filesystem "
            f"namespace -- the probe could not run. Tried: {tried}. The probe needs ordinary "
            "utilities (`cat`); a PATH without them, which is what PowerShell and cmd supply by "
            "default, produces exactly this."
        )
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
