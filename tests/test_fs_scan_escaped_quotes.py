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
    # The leading escaped quote throws the toggle off, so each of these two rows is denied only by
    # a reading that keeps the backtick literal in single quotes and lets an escaped backtick end.
    pytest.param(
        "Write-Output `\"x 'it`'; grep -r x /proc", id="backtick-is-literal-in-single-quotes"
    ),
    pytest.param('Write-Output `" "x``"; grep -r x /proc', id="escaped-backtick-before-the-close"),
    pytest.param("# don't walk\ngrep -r x /proc", id="apostrophe-in-a-line-comment"),
    pytest.param("<# it's #>\ngrep -r x /proc", id="apostrophe-in-a-block-comment"),
    pytest.param("git commit -m @'\ndon't\n'@\ngrep -r x /proc", id="apostrophe-in-a-here-string"),
    pytest.param("$m = 'done'# it's fine\ngrep -r x /proc", id="comment-right-after-a-quote"),
    pytest.param("$x =# it's\ngrep -r x /proc", id="comment-right-after-an-operator"),
    pytest.param("$x +=# it's\ngrep -r x /proc", id="comment-right-after-a-compound-operator"),
    pytest.param("$x.Count# it's\ngrep -r x /proc", id="comment-ending-an-expression-first-token"),
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

# A `#` STARTS A COMMENT ONLY AT A TOKEN START. Inside a bareword (`a^#`, `a=#`, `a/#`, `a_#`,
# `a<#`, or a quoted part glued to one, `a'b'#`) it is a literal character, and PowerShell's own
# tokenizer reads each of these as one argument, the quote spanning the lines after it. A reading
# that took the `#` for a comment blanked the opening quote and exposed the walk the quote holds.
# `=` at a token start is an operator only in an expression statement, so among a command's
# arguments (`x =#`), and after `(`, `&` or an escaped statement start, it starts a bareword too.
# `${#x}` is a variable name. The last row is the other direction: a `$x#` comment left unread
# exposed its `;` once the line above was read right.
TOKEN_START_ALLOW = [
    pytest.param("Write-Output a^#'\nfind /proc\n'", id="hash-after-caret"),
    pytest.param("Write-Output a=#'\nfind /proc\n'", id="hash-after-equals-in-a-word"),
    pytest.param("Write-Output a/#'\nfind /proc\n'", id="hash-after-slash"),
    pytest.param("Write-Output a_#'\nfind /proc\n'", id="hash-after-underscore"),
    pytest.param("Write-Output a<#'\nfind /proc\n'", id="hash-after-a-less-than-in-a-word"),
    pytest.param("Write-Output a'b'#'\nfind /proc\n'", id="hash-after-a-quote-glued-to-a-word"),
    pytest.param("Write-Output x =#'\nfind /proc\n'", id="hash-after-equals-in-arguments"),
    pytest.param("Write-Output ($a) =#'\nfind /proc\n'", id="equals-after-a-parenthesis"),
    pytest.param("& $s =#'\nfind /proc\n'", id="equals-after-the-call-operator"),
    pytest.param("$x = 1; `n =#'\nfind /proc\n'", id="equals-after-an-escaped-statement-start"),
    pytest.param("Write-Output ${#x} '\nfind /proc\n'", id="hash-in-a-braced-variable-name"),
    pytest.param("# don't\n$x#; find /proc", id="comment-ending-an-expression-first-token"),
]


@pytest.mark.parametrize("command", POWERSHELL_DENY)
def test_an_escaped_quote_does_not_hide_the_walk_after_it(command: str) -> None:
    assert_denied(run_guard(bash(command, tool="PowerShell")))


@pytest.mark.parametrize("command", POWERSHELL_ALLOW)
def test_powershell_prose_naming_a_walk_is_still_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command, tool="PowerShell")))


@pytest.mark.parametrize("command", TOKEN_START_ALLOW)
def test_a_hash_inside_a_bareword_is_not_a_comment(command: str) -> None:
    assert_allowed(run_guard(bash(command, tool="PowerShell")))


# STILL A FALSE DENY. The reading tells an expression statement from a command by the statement's
# first character only, so after `$null = Write-Output` it still takes `=#` for an operator and a
# comment, where PowerShell reads a bareword. Allowing it means reading the statement grammar;
# dropping the `=` rule instead would lose the comment-right-after-an-operator deny row.
@pytest.mark.xfail(strict=True, reason="expression mode is read from the first character only")
def test_equals_hash_among_arguments_after_an_assignment() -> None:
    command = "$null = Write-Output =#'\nfind /proc\n'"
    assert_allowed(run_guard(bash(command, tool="PowerShell")))
