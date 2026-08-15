# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Resolving a bash a test can actually USE, and pinning the child environment it runs in.

**Why this is shared rather than per-module (BACKLOG #1272).** Four test modules resolve bash. One of
them -- ``test_merge_gate_controls`` -- solved this on 2026-08-10 and has carried the fix, its
reasoning and its negative control ever since. The other three kept ``shutil.which("bash")`` and were
measured on 2026-08-14 producing **19 failures that were entirely an artifact of PATH ORDER**: the same
tree, same commit and same interpreter gave 19 failed / 28 passed under the WSL launcher and 47 passed
under Git Bash, with nothing changed but which bash was found first.

**So the defect was never that the problem was unsolved. It was that the solution did not propagate**,
and three seats spent an evening re-deriving a fact already written in a docstring in this directory.
This module exists so there is one copy to find.

**THE QUESTION A GUARD MUST ASK.** ``shutil.which("bash") is None`` asks *is bash PRESENT*. The
question is *is the bash I found USABLE FOR WHAT I AM ABOUT TO DO* -- and on Windows the WSL launcher
is present, passes that guard, and then cannot read any path this process wrote. A guard that answers
the adjacent question returns green and tells you nothing (``docs/Secure_Development_Standards.md``
SDS-3.8).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_TIMEOUT = 300


def child_env(**extra: str) -> dict[str, str]:
    """A minimal, EXPLICIT environment for a child process.

    Measured in wave 2 of this backlog pass: a lane's new test passed in its author's shell and failed
    at integration, because that shell happened to export ``PYTHONIOENCODING=utf-8`` while the test
    pinned only the PARENT's decoding. It would have passed ubuntu and reddened the Windows legs. So
    nothing is inherited here except what a child genuinely cannot run without, and the two variables
    that incident turned on are set EXPLICITLY rather than passed through.

    ``LC_ALL=C`` and the ``GIT_CONFIG_*`` overrides exist for the same reason one level over: a global
    ``core.autocrlf``, a global hooks path, or a locale that reorders ``grep`` output would otherwise
    make the result a fact about this machine.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "GIT_AUTHOR_NAME": "negative control",
        "GIT_AUTHOR_EMAIL": "control@example.invalid",
        "GIT_COMMITTER_NAME": "negative control",
        "GIT_COMMITTER_EMAIL": "control@example.invalid",
        "GIT_TERMINAL_PROMPT": "0",
    }
    # Windows: a child python cannot start without these, and they carry no behaviour of their own.
    for name in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP", "WINDIR", "PATHEXT"):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(extra)
    return env


def run(argv: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    """Run a child and return RAW BYTES.

    Decoding is done by the caller with ``errors="replace"``. A child whose output cannot be decoded
    under the ambient code page must not be able to turn an assertion about an EXIT CODE into a
    ``UnicodeDecodeError`` -- that failure mode is a property of the console, not of the gate.
    """
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        argv, cwd=str(cwd), env=env, capture_output=True, timeout=_TIMEOUT, check=False
    )


def text(proc: subprocess.CompletedProcess[bytes]) -> str:
    return (proc.stdout + proc.stderr).decode("utf-8", errors="replace")


def shell_candidates(name: str) -> list[Path]:
    """Every plausible interpreter called ``name``, GIT-DERIVED FIRST.

    ``shutil.which(name)`` alone is a fact about PATH, and on Windows PATH order decides WHICH
    OPERATING SYSTEM answers: ``C:\\Windows\\System32\\bash.exe`` is the WSL launcher, whose filesystem
    namespace is not the one this process just wrote a fixture into. Git for Windows ships a POSIX
    shell beside git, so git -- which every test here already requires -- is the deterministic anchor.

    **The root cause of the ordering, measured and recorded in BACKLOG #1216:** ``C:\\Program
    Files\\Git\\cmd`` is on PATH and carries ``git.exe`` ONLY, while ``C:\\Program Files\\Git\\bin``,
    which carries the shell, is not -- so PATH offers the WSL launcher and never the Git one.
    """
    found: list[Path] = []
    git = shutil.which("git")
    if git:
        # `<root>/cmd/git.exe`, `<root>/bin/git.exe` and `<root>/mingw64/bin/git.exe` are all shipped
        # layouts, so walk up and try both shell homes from each level.
        for parent in Path(git).resolve().parents:
            for rel in (f"bin/{name}.exe", f"usr/bin/{name}.exe", f"bin/{name}"):
                found.append(parent / rel)
    on_path = shutil.which(name)
    if on_path:
        found.append(Path(on_path))
    return found


def shell_sees(shell: Path, tmp_path: Path) -> bool:
    """LIVE POSITIVE CONTROL for the namespace, not a guess from the path string.

    Rejecting ``system32`` by name would be a pattern match on a spelling. This writes a token into
    the directory the fixture will live in and requires the candidate to read it back -- if it cannot,
    it is looking at a different filesystem and every verdict it returns would be about nothing.
    """
    probe = tmp_path / "mf_bash_probe.txt"
    probe.write_text("MFPROBE-OK\n", encoding="utf-8")
    try:
        out = run([str(shell), "-c", "cat mf_bash_probe.txt"], tmp_path, child_env())
    except OSError:
        return False
    return out.returncode == 0 and b"MFPROBE-OK" in out.stdout


def require_shell(tmp_path: Path, *names: str) -> str:
    """An interpreter that can see this process's files, or a loud failure -- never a skip.

    **PROVE THE INTERPRETER YOU ARE ABOUT TO USE -- not "find a usable bash".** ``names`` are tried in
    the caller's own preference order, and **every one of them is probed**. That distinction is the
    whole contract, and it was Builder 3's correction to a narrower first version of this helper:
    ``test_installed_coord_hooks`` resolves ``shutil.which("sh") or shutil.which("bash")``, trying
    ``sh`` FIRST. A helper that proved only *bash* usable would repair that file **by accident** on a
    box where ``sh`` is absent, and leave it broken wherever an UNUSABLE ``sh`` is on PATH -- because
    ``sh`` would win the ``or`` and never be probed at all.

    **LOUD FAILURE, NOT A SKIP, and the item's own text is the half being corrected here.** ``ci.yml``
    sets ``defaults.run.shell: bash`` on every OS, so a leg without a usable shell could not run the
    gates these controls exercise: a skip there is a green that proves nothing, and a red at least
    gets investigated. A skip is the right answer to *"this environment legitimately cannot run this"*
    and the wrong answer to *"this environment is broken in a way CI would be fatal on"*.

    The cost is near-zero in practice because git-derived candidates are tried first, so a developer
    box with git installed neither skips nor fails. Loud failure fires only when NO candidate can read
    a file this process just wrote -- at which point the suite cannot be measuring anything anyway.
    """
    tried: list[str] = []
    for name in names:
        for candidate in shell_candidates(name):
            if not candidate.is_file():
                continue
            tried.append(str(candidate))
            if shell_sees(candidate, tmp_path):
                return str(candidate)
    pytest.fail(
        f"no {' or '.join(names)} on this machine can read a file this process just wrote. Tried: "
        f"{tried or '(none found)'}. On Windows, a POSIX shell on PATH is often "
        "C:\\Windows\\System32\\bash.exe -- the WSL launcher, which runs in a different filesystem "
        "namespace, and a control that ran there would be measuring nothing."
    )


def require_bash(tmp_path: Path) -> str:
    """``require_shell`` for the common case. Kept so bash callers read as bash callers."""
    return require_shell(tmp_path, "bash")


#: ``bash`` exits 126/127 when it cannot RUN what it was handed -- not found, not executable, or a
#: path its namespace cannot resolve. It exits 2 for a genuine SYNTAX error. A caller that tests only
#: ``returncode != 0`` conflates the two, so a harness failure impersonates a defect in the thing under
#: test -- which is how one unresolvable path presented as 160 syntax errors that did not exist.
#: ``COMMON`` states the general rule: a crashed instrument must not exit the same code as a real
#: failure.
CANNOT_RUN_CODES = frozenset({126, 127})
