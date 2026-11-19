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
import time

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
    pytest.param("$x=# it's\ngrep -r x /proc", id="comment-after-a-glued-operator"),
    pytest.param("$m='done'# it's\ngrep -r x /proc", id="comment-after-a-glued-quote"),
    pytest.param("[int]$x =# it's\ngrep -r x /proc", id="comment-in-a-typed-assignment"),
    pytest.param("Get-ChildItem `\n#it's\ngrep -r x /proc", id="comment-after-a-continuation"),
    pytest.param(
        "Get-ChildItem `\r\n#it's\r\ngrep -r x /proc", id="comment-after-a-crlf-continuation"
    ),
    # A command with no backtick, `#` or `@` still takes the PowerShell reading for its `${`.
    pytest.param("Write-Output ${it's}; grep -r x /proc", id="apostrophe-in-a-braced-variable"),
    pytest.param("Write-Output ${a`}'}; grep -r x /proc", id="escaped-brace-in-a-braced-variable"),
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
# arguments (`x =#`), after `(`, `&` or an escaped statement start, and after the command an
# assignment runs (`$x = Get-ChildItem *#`), it starts a bareword too. `${#x}` is a variable name.
# The `$x#` row is the other direction: a comment left unread exposed its `;` once the line above
# was read right.
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
    pytest.param("$x = Get-ChildItem *#'\nfind /proc\n'", id="star-in-a-command-after-assignment"),
    pytest.param("$x = foo /#'\nfind /proc\n'", id="slash-in-a-command-after-assignment"),
    pytest.param(
        "$null = Write-Output =#'\nfind /proc\n'", id="equals-in-a-command-after-assignment"
    ),
    pytest.param(
        "$x = gci *#*.txt; Write-Output 'it''s\nfind /proc'", id="star-hash-glob-after-assignment"
    ),
    pytest.param(
        "Write-Output a `\r\n$b#'\r\nfind /proc\r\n'", id="hash-in-a-word-after-a-crlf-continuation"
    ),
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


# AN EXPRESSION READS `#` AS A COMMENT AFTER ANY OF ITS TOKENS, not only its first: after a
# variable, a number, a member, a closing parenthesis, and a hashtable key's `=`, each checked
# against Parser::ParseInput. A comment left unread there kept its backtick as an escape, so the
# apostrophe after it opened a span the plain toggle closed, and the `;` inside the comment split a
# walk out of it. A parenthesis, `$(`, `@(` and `{` open a statement of their own, so `$b#` at
# their start is a comment too, and the reading after their close is the reading before it.
EXPRESSION_COMMENT_ALLOW = [
    pytest.param("$x = $y# don`'t; find /proc'", id="comment-after-a-variable"),
    pytest.param('$x = 1# use `"; find /proc', id="comment-after-a-number"),
    pytest.param("$h = @{ a =# x`'; find /proc }", id="comment-after-a-hashtable-equals"),
    pytest.param("$x = $y.Foo(1).Bar# it`'s; find /proc'", id="comment-after-a-call-and-member"),
    pytest.param("Write-Output ($b# it`'s; find /proc\n)", id="comment-at-a-parenthesis-start"),
    pytest.param("5# it`'s; find /proc'", id="comment-after-a-number-statement"),
    pytest.param("git status && $x# don`'t; grep -r x /proc", id="expression-after-a-chain"),
    pytest.param("gci | $x# don`'t; grep -r x /proc", id="expression-after-a-pipe"),
    pytest.param("$x = 'a'.Length# don`'t; grep -r x /proc", id="member-of-a-string"),
    pytest.param("return $x# don`'t; grep -r x /proc", id="expression-after-return"),
    pytest.param("-not $x# don`'t; grep -r x /proc", id="expression-led-by-not"),
    pytest.param("Write-Output $x.Name# don`'t; grep -r x /proc", id="member-in-an-argument"),
]

# THE OTHER DIRECTION: a token PowerShell reads as a generic word keeps its `#` literal, so the
# quote after it still spans the lines that follow. `7z` and `1_000` are not numbers, a bareword
# after an operator is a command, and `a@{` in an argument is a word and a script block.
EXPRESSION_GENERIC_ALLOW = [
    pytest.param("$x = 7z -a=#'\nfind /proc\n'", id="digit-led-command-after-assignment"),
    pytest.param("$x = 1_000#'\nfind /proc\n'", id="digit-led-word-is-not-a-number"),
    pytest.param("$x = 7.Foo#'\nfind /proc\n'", id="digit-dot-letter-is-not-a-number"),
    pytest.param("$x = $a -eq b#'\nfind /proc\n'", id="bareword-after-an-operator"),
    pytest.param("Write-Output (gci)a#'\nfind /proc\n'", id="word-glued-after-a-parenthesis"),
    pytest.param("Write-Output a@{ b =#'\nfind /proc\n' }", id="glued-at-brace-is-a-script-block"),
    pytest.param(
        "$h = @{ a =\n Get-Thing *#'\nfind /proc\n'\n}", id="hashtable-value-on-the-next-line"
    ),
    pytest.param("Write-Output $x.Name-foo#'\nfind /proc\n'", id="parameter-glued-to-a-member"),
    pytest.param("Write-Output $x[0]x#'\nfind /proc\n'", id="word-glued-to-an-index"),
    pytest.param("Write-Output $x.Name=#'\nfind /proc\n'", id="equals-glued-to-a-member"),
]

EXPRESSION_COMMENT_DENY = [
    pytest.param("$x = 5# it's\ngrep -r x /proc", id="comment-after-a-number-hides-nothing"),
    pytest.param("$h = @{ a =# it's\n}\ngrep -r x /proc", id="comment-in-a-hashtable"),
    pytest.param("($x =# it's\n)\ngrep -r x /proc", id="comment-in-a-parenthesised-assignment"),
    pytest.param(
        "Write-Output $x.Name#it's\ngrep -r x /proc", id="comment-after-a-member-argument"
    ),
    pytest.param("Write-Output $a[0]#it's\ngrep -r x /proc", id="comment-after-an-index-argument"),
    pytest.param("git status && $x#it's\ngrep -r x /proc", id="comment-after-a-chained-variable"),
    pytest.param("$x = 'a'.Length#it's\ngrep -r x /proc", id="comment-after-a-string-member"),
]


@pytest.mark.parametrize("command", EXPRESSION_COMMENT_ALLOW + EXPRESSION_GENERIC_ALLOW)
def test_an_expression_reads_its_comments_and_words_as_powershell_does(command: str) -> None:
    assert_allowed(run_guard(bash(command, tool="PowerShell")))


@pytest.mark.parametrize("command", EXPRESSION_COMMENT_DENY)
def test_an_apostrophe_in_an_expression_comment_hides_no_walk(command: str) -> None:
    assert_denied(run_guard(bash(command, tool="PowerShell")))


def test_a_run_of_unclosed_braced_variables_is_read_in_linear_time() -> None:
    """Each unclosed `${` once scanned to the end of the command, so a run of them was quadratic.

    Measured on the unfixed reading, 16 KB took about 11 s against 0.55 s on origin/main. 32 KB is
    past 40 s there; the bound is generous so a loaded runner does not flake.
    """
    command = "Write-Output " + "${" * 16000 + " find /proc"
    started = time.perf_counter()
    run_guard(bash(command, tool="PowerShell"))
    assert time.perf_counter() - started < 25


def test_a_long_digit_run_before_a_letter_is_read_in_linear_time() -> None:
    """The number pattern backtracked through a digit run that a letter ends, quadratically.

    Measured on the unfixed pattern, 24000 digits ran the guard past 85 s. The plain toggle allows
    this command, so only the PowerShell reading's own speed is timed here.
    """
    command = "Write-Output find; $x = " + "1" * 24000 + "z # c"
    started = time.perf_counter()
    assert_allowed(run_guard(bash(command, tool="PowerShell")))
    assert time.perf_counter() - started < 25


def test_the_toggle_deny_lands_before_the_powershell_reading_runs() -> None:
    """The toggle's verdict is judged first, so a slow PowerShell reading cannot delay its deny."""
    command = "$x = " + "1" * 24000 + "z # c\nfind /proc"
    started = time.perf_counter()
    assert_denied(run_guard(bash(command, tool="PowerShell")))
    assert time.perf_counter() - started < 25
