# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Do two spellings of the SAME local path compare equal to a governed root?

BACKLOG #1071. ``Get-ComparablePath`` is a LEXICAL comparison -- ``GetFullPath`` never touches the
filesystem -- so it canonicalised the drive-letter spelling and nothing else. An extended-length or
admin-share spelling of a governed root therefore matched no root, and rule 3c allowed a disarm write
through it.

**THE ITEM FILES THE UNC SPELLING AND THAT IS THE CONDITIONAL ONE.** Measured with the consequence read
back from the governed config rather than inferred from a verdict:

===========================  ==========================================================
``\\\\?\\C:\\<governed>``          git rc=0; the write LANDS. No setup of any kind.
``\\\\localhost\\C$\\<governed>``   git rc=128 "dubious ownership" today; rc=0 and the write lands
                             the moment an operator adds one ``safe.directory`` entry.
===========================  ==========================================================

That ordering matters for severity, and it answers the objection recorded against this rule -- that
these spellings "need a SHELL command to set up" and are therefore out of reach. **The extended-length
prefix needs no share, no junction and no configuration.** It is a path spelling.

**WHY THE UNC CASE READS AS "STILL ALLOWED" WITHOUT BEING A FAIL-OPEN.** Rule 3c resolves a candidate by
ASKING GIT for its common dir. While git refuses the path, the rule cannot resolve the target and falls
through -- but the write fails for the same reason, so nothing is exposed. Both components decline
together. The fold below closes the case exactly when git will answer, which is exactly when the write
becomes possible.

**THE FOLD IS ADDITIVE**: it makes more spellings resolve onto a governed root, so every verdict it
changes moves ALLOW to DENY. It sits at the single shared comparison point, so rules 3, 3b, 3c and 3d
inherit it together instead of drifting apart.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_SOURCE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
B = chr(92)

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def _brace_block(src: str, name: str) -> str:
    """The verbatim text of one function, matched by braces.

    TAKEN FROM THE SHIPPED FILE RATHER THAN RESTATED. A second copy of this logic in a test is a second
    definition that drifts, and the drift would be invisible precisely because both sides agree at the
    moment it is written.
    """
    start = src.index("function " + name)
    depth = 0
    i = src.index("{", start)
    while True:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1


def comparable(paths: list[str]) -> list[str]:
    """Run the SHIPPED ``Get-ComparablePath`` over each path and return what it produced."""
    src = GATE_SOURCE.read_text(encoding="utf-8")
    # The host-spellings list lives outside both functions and the fold consults it. An earlier version
    # of this helper omitted it, and every UNC row came back UNFOLDED -- a clean, wrong result that
    # looked exactly like the defect still being open. Extraction that drops a dependency reports the
    # absence of the dependency, not the behaviour of the code.
    #
    # ITS ABSENCE IS TOLERATED SO THE CONTROL ROWS STAY MEANINGFUL ON A GATE WITHOUT THE FOLD. Requiring
    # it made all three rows fail against a pre-fold gate for ONE reason -- the helper crashing -- which
    # is a suite that cannot tell its subject from its scaffolding. The two control rows must PASS on
    # both gates, and they can only do that if the helper runs on both.
    var = ""
    marker = "$script:LocalHostSpellings"
    if marker in src:
        var_start = src.index(marker)
        var = src[var_start : src.index("function Get-ComparablePath", var_start)]
    block = var + "\n".join(_brace_block(src, n) for n in ("Get-FullPathRaw", "Get-ComparablePath"))
    body = "\n".join(f"Get-ComparablePath '{p}'" for p in paths)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", block + "\n" + body],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip().splitlines()


def test_every_local_spelling_of_one_path_compares_equal() -> None:
    """The defect, stated as the property it broke: these are all the same file."""
    repo = "C:" + B + "Repo"
    got = comparable(
        [
            repo,
            B + B + "?" + B + "C:" + B + "Repo",
            B + B + "?" + B + "UNC" + B + "localhost" + B + "C$" + B + "Repo",
            B + B + "localhost" + B + "C$" + B + "Repo",
            B + B + "127.0.0.1" + B + "C$" + B + "Repo",
        ]
    )
    assert got == ["c:/repo"] * 5, got


def test_a_REMOTE_admin_share_is_NOT_folded() -> None:
    """The control that keeps the fold from being a false-deny machine.

    ``\\\\otherbox\\C$`` is a DIFFERENT machine's C: drive. Folding it would let a remote path match a
    local governed root, and the refusal would name a repository the write never touches -- the
    BACKLOG #1085 shape this file has already been fixed for once. The host list is deliberately not
    ``[^/]+``.
    """
    (got,) = comparable([B + B + "otherbox" + B + "C$" + B + "Repo"])
    assert got == "//otherbox/c$/repo"


def test_the_fold_leaves_an_ordinary_path_untouched() -> None:
    """A control against the fold firing on paths it has no business touching -- without this, a rule
    that returned ``c:/repo`` for everything would pass the row above."""
    got = comparable(["C:" + B + "Other", "D:" + B + "Repo"])
    assert got == ["c:/other", "d:/repo"]
