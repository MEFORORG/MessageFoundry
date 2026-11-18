# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ESCAPED quote must not shift the quote masker of the fs-scan guard (BACKLOG #5451).

Hide-QuotedSpans in scripts/hooks/block-unbounded-fs-scan.ps1 blanks quoted text so prose never
reaches program position. For the Bash tool, BACKLOG #5607 made it read backslash escapes as bash
does, and tests/test_unbounded_fs_scan_guard.py pins that. The PowerShell tool kept only the plain
quote toggle, where a backtick-escaped quote (`"` inside or outside a string) still opened or closed
a span, so the separator and the unbounded walk after it were blanked and allowed.

The same reading blanks a comment and a here-string body, so an apostrophe in either opens no
span. The allow rows that carry a backtick, `#` or `@` are the ones the PowerShell reading runs on;
each would be denied by a reading that escaped inside single quotes, treated an escaped backtick as
escaping the quote after it, or read a backtick in a comment or a single-quoted here-string body.
"""

from __future__ import annotations

import shutil

import pytest

from tests.test_blanket_stage_guard import assert_allowed, bash
from tests.test_unbounded_fs_scan_guard import run_guard
from tests.test_worktree_gate import assert_denied

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

POWERSHELL_DENY = [
    pytest.param('Write-Output "a`"b"; find /proc', id="escaped-quote-inside-a-string"),
    pytest.param('Write-Output `"; find /proc; Write-Output `"', id="escaped-quotes-outside"),
    pytest.param("Write-Output 'it`'; grep -r x /proc", id="backtick-is-literal-in-single-quotes"),
    pytest.param('Write-Output "x``"; grep -r x /proc', id="escaped-backtick-before-the-close"),
    pytest.param("# don't walk\ngrep -r x /proc", id="apostrophe-in-a-line-comment"),
    pytest.param("<# it's #>\ngrep -r x /proc", id="apostrophe-in-a-block-comment"),
    pytest.param("git commit -m @'\ndon't\n'@\ngrep -r x /proc", id="apostrophe-in-a-here-string"),
    pytest.param("$m = 'done'# it's fine\ngrep -r x /proc", id="comment-right-after-a-quote"),
    pytest.param("$x =# it's\ngrep -r x /proc", id="comment-right-after-an-operator"),
]

POWERSHELL_ALLOW = [
    pytest.param('Write-Output "say `"find /proc`" is blocked"', id="escaped-quotes-in-prose"),
    pytest.param("Write-Output 'never find /proc'", id="single-quoted-prose"),
    pytest.param('Write-Output "a ""find /proc"" b"', id="doubled-quotes-in-prose"),
    pytest.param("Write-Output 'x`' '; find /proc'", id="backtick-literal-in-single-quotes"),
    pytest.param('Write-Output "x``" "; find /proc"', id="escaped-backtick-then-a-string"),
    pytest.param(
        "git commit -m @'\nFix the guard's `\"; find /proc` masking\n'@",
        id="backtick-quote-in-a-here-string",
    ),
    pytest.param("Write-Output 'a' # it`'s; grep -r x /proc", id="backtick-in-a-comment"),
    pytest.param('Write-Output "x"# uses `"; find /proc', id="backtick-in-a-comment-after-a-quote"),
    pytest.param("Write-Output x 2>&1# it`'s; grep -r x /proc", id="comment-after-a-redirect"),
]


@pytest.mark.parametrize("command", POWERSHELL_DENY)
def test_an_escaped_quote_does_not_hide_the_walk_after_it(command: str) -> None:
    assert_denied(run_guard(bash(command, tool="PowerShell")))


@pytest.mark.parametrize("command", POWERSHELL_ALLOW)
def test_powershell_prose_naming_a_walk_is_still_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command, tool="PowerShell")))
