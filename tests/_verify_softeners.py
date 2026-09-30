# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shell shapes that let a step run on past a FAILED ``sha256sum -c`` (BACKLOG #1698).

Shared by two tests that must agree. ``tests/test_ci_venv_pinning.py`` holds the in-repo pin rule
for downloads inside ``id-token: write``. ``tests/test_release_pipeline.py`` holds the owner ruling
of 2026-09-30, that an sbomqs pin failure blocks the release. Both used to pass a verify line
ending ``|| true``: the digest was pinned and bound to the right file, and a mismatch still printed
FAILED and carried on to install the bytes. One definition here, so the two cannot drift apart.

GitHub runs a ``run:`` body under ``bash -e``, so a failing command stops the step. Each shape
below is one bash exempts from that, or one that turns it off. The rule is FAIL-CLOSED: it refuses
some shapes that would in fact stop the step, such as ``sha256sum -c -; true``, because a verify
line the rule cannot read in one pass is one a reviewer cannot either.

STRAIGHT-LINE STEPS ONLY. Reading control flow across lines is where a line-by-line reader goes
blind: ``f() { <check>; }; f || echo warn`` and a multi-line ``if`` whose condition is the check
both suspend errexit, and neither puts anything on the check's own line. So a step that verifies
may hold no compound command, function, brace group or subshell, and no ``trap``, background
``&`` or ``wait``. A ``trap 'exit 0' EXIT`` rewrites a failed check's status to 0, and a
backgrounded check's status is lost to a bare ``wait``.
"""

from __future__ import annotations

import re

_VERIFY = "sha256sum -c"

#: `set +e`, `set +eu`, `set +o errexit`: errexit off for everything after it.
_ERREXIT_OFF = re.compile(r"\bset\b[^;&|\n]*?(?:\+[A-Za-z]*e|\+o\s+errexit\b)")

#: A fallback that turns any failure before it into success, anywhere in the body.
_SWALLOW = re.compile(r"\|\|\s*(?::(?=\s|;|\)|$)|true\b|exit\s+0\b|return\s+0\b)")

#: The verify line opens a condition or a negation, where bash never applies errexit.
_CONDITIONAL_PREFIX = re.compile(r"(?:^\s*|[;&|(]\s*)(?:if|elif|while|until|!)\s")

#: After the verify command: an operator that lets the line continue past a failure, or one that
#: puts the check somewhere other than the end of its pipeline.
_TRAILING_OPERATOR = re.compile(r"[|&;)`]")

#: A compound command, function, brace group or subshell, opened in command position.
_COMPOUND = re.compile(
    r"(?:^\s*|[;&|]\s*)(?:(?:if|then|elif|else|while|until|for|select|case|do|function)\b|[{(])"
    r"|\b[A-Za-z_][\w-]*\s*\(\s*\)"
)

#: `trap` or `wait` in command position.
_TRAP_OR_WAIT = re.compile(r"(?:^\s*|[;&|]\s*)(?:trap|wait)\b")

#: A lone `&`, which backgrounds what precedes it. Not `&&`, `>&` or `&>`.
_BACKGROUND = re.compile(r"(?<![&>])&(?![&>])")


def logical_lines(body: str) -> list[str]:
    """``body`` with backslash continuations joined, so a `\\`-split command reads as one line."""
    out: list[str] = []
    pending = ""
    for line in body.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\") and not stripped.endswith("\\\\"):
            pending += stripped[:-1] + " "
            continue
        out.append(pending + line)
        pending = ""
    if pending:
        out.append(pending)
    return out


def verification_softeners(body: str) -> list[str]:
    """Why a failed ``sha256sum -c`` in ``body`` would NOT stop the step; empty when it would.

    ``body`` is the EXECUTED shell, comment lines already removed.
    """
    reasons: list[str] = []
    lines = logical_lines(body)
    for line in lines:
        if _ERREXIT_OFF.search(line):
            reasons.append(f"turns errexit off ({line.strip()!r})")
        if _SWALLOW.search(line):
            reasons.append(f"swallows a failure with a fallback ({line.strip()!r})")
        if _COMPOUND.search(line):
            reasons.append(
                f"is not straight-line: a compound command, function, group or subshell can "
                f"suspend errexit around the check ({line.strip()!r})"
            )
        if _TRAP_OR_WAIT.search(line):
            reasons.append(
                f"sets a trap or waits, either of which can mask the exit status ({line.strip()!r})"
            )
        if _BACKGROUND.search(line):
            reasons.append(
                f"backgrounds a command, whose failure a later line never sees ({line.strip()!r})"
            )
    for line in lines:
        at = line.find(_VERIFY)
        if at < 0:
            continue
        prefix, suffix = line[:at], line[at + len(_VERIFY) :]
        if _CONDITIONAL_PREFIX.search(prefix):
            reasons.append(f"runs the check as a condition or negation ({line.strip()!r})")
        if _TRAILING_OPERATOR.search(suffix):
            reasons.append(
                f"lets the line continue past the check, or pipes its result on ({line.strip()!r})"
            )
        if "--ignore-missing" in suffix:
            reasons.append(f"skips a missing file instead of failing on it ({line.strip()!r})")
    return reasons
