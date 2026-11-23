# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
r"""Tests for the unbounded-filesystem-scan PreToolUse guard.

The guard (``scripts/hooks/block-unbounded-fs-scan.ps1``) denies a shell command that would walk
the MSYS root or its synthetic ``/proc``, and passes everything else silently.

WHAT IT IS PROTECTING: Git Bash's ``/proc`` carries three Windows-registry mounts, and walking one
opens a kernel handle per registry key without bound. The 2026-09-20 measurement, its paired arms
and the machine-wide totals live in the guard's own header and are deliberately not copied here --
a re-measurement should have one prose arm to update, not three (CLAUDE.md section 11).

An interrupt cannot stop such a walk, which is why this is a DENY and not a timeout. That half is
stated in ``scripts/coord/reap-orphans.ps1``, the after-the-fact companion.

THE ALLOW SIDE IS WHERE THIS GUARD CAN GO WRONG QUIETLY. A pattern for ``find`` also matches the
word inside ``echo findings``, a Windows path spelled ``C:\find\notes.txt``, and
``git log --find-renames``. Each of those is driven below, because a guard that denies them gets
switched off, and a guard that is switched off protects nothing.

Each test drives the real hook as a subprocess with a real PreToolUse payload on stdin, so the
contract under test is the one Claude Code actually invokes.
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

# THE SHARED HALVES COME FROM THEIR ONE HOME RATHER THAN BEING RE-SPELLED. The deny ENVELOPE is one
# contract across every PreToolUse hook here; so are the allow-side assertion and the stdin payload
# shape. tests/test_blanket_stage_guard.py states that principle for the envelope and this module
# applies it to the other two, so a change to what Claude Code sends reaches every guard's tests at
# once instead of leaving whichever copy nobody remembered.
from tests.test_blanket_stage_guard import assert_allowed, bash
from tests.test_worktree_gate import assert_denied

GUARD = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "block-unbounded-fs-scan.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_guard(payload: dict[str, Any] | str) -> dict[str, Any] | None:
    """Invoke the hook exactly as Claude Code does. Returns the deny object, or None for 'allow'."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(GUARD)],
        input=raw,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Fail-OPEN is the contract: a non-zero exit would be a guardrail wedging every shell call, and
    # an exit code the harness ignores would leave the guard off with nobody the wiser.
    assert proc.returncode == 0, f"guard exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return None
    decision: dict[str, Any] = json.loads(proc.stdout)
    return decision


@pytest.fixture(scope="module")
def find_proc_deny() -> dict[str, Any] | None:
    """One spawn, shared by the three tests that assert different properties of the SAME deny.

    Each hook invocation is a cold pwsh start, and the positive control, the message-content test
    and the encoding test all interrogate the one object `find /proc` produces.
    """
    return run_guard(bash("find /proc"))


@pytest.fixture(scope="module")
def grep_proc_deny() -> dict[str, Any] | None:
    return run_guard(bash("grep -r pattern /proc"))


# ================================================================== THE POSITIVE CONTROL


# EVERY ALLOW ASSERTION IN THIS FILE PASSES VACUOUSLY IF THE MATCHER NEVER FIRES. A hook that
# exited 0 unconditionally -- a typo in the program regex, a `continue` one level too high, a
# rename that left settings.json pointing at nothing -- would turn this module green while the
# control was completely off. This test is the one that cannot pass in that world, so read it as
# the instrument check for every ALLOW below rather than as one more deny row.
def test_positive_control_the_matcher_fires_at_all(find_proc_deny: dict[str, Any] | None) -> None:
    reason = assert_denied(find_proc_deny)
    assert "BLOCKED" in reason


def test_the_deny_message_names_the_measured_cause_and_the_way_out(
    find_proc_deny: dict[str, Any] | None,
) -> None:
    """A denial that only forbids leaves the agent to guess, and the guess is the same command."""
    reason = assert_denied(find_proc_deny)
    # The cause. Naming "one entry per running process" here would be wrong: /proc has 32 entries
    # and only the three registry mounts leak.
    assert "registry" in reason
    assert "/proc/registry32" in reason
    # The three ways forward the guard promises.
    assert "Glob tool" in reason
    assert "-maxdepth" in reason
    assert "-path /proc -prune -o" in reason
    # Pruning one mount was TRIED and the walk fell into the next one, so the message must not
    # leave a reader thinking a single mount is enough.
    assert "WHOLE of /proc" in reason


def test_the_deny_message_is_ascii_so_it_survives_a_cp1252_console(
    find_proc_deny: dict[str, Any] | None, grep_proc_deny: dict[str, Any] | None
) -> None:
    """CLAUDE.md section 11: no glyphs or emoji, in prose or in anything written back to a user.

    A stock Windows console is cp1252 and raises UnicodeEncodeError on a glyph, which would turn
    a refusal into a crash at exactly the moment the operator needs to read it. Both branches are
    driven, because the shared evidence sentence is only half of each message.
    """
    for label, decision in (("find", find_proc_deny), ("grep", grep_proc_deny)):
        reason = assert_denied(decision)
        assert reason.isascii(), f"non-ASCII in the {label} deny message: {reason!r}"


# ================================================================== DENY: find

FIND_DENY = [
    pytest.param("find /", id="root-bare"),
    pytest.param('find "/"', id="root-double-quoted"),
    pytest.param("find '/'", id="root-single-quoted"),
    pytest.param("find /proc", id="proc-bare"),
    pytest.param('find "/proc"', id="proc-double-quoted"),
    pytest.param("find '/proc'", id="proc-single-quoted"),
    # The pump itself, and one level below it. A walk started inside a registry mount is the same
    # leak, just entered lower down.
    pytest.param("find /proc/registry", id="proc-registry"),
    pytest.param("find /proc/registry64 -name '*.dat'", id="proc-registry64-with-expression"),
    # An expression after the root changes nothing: the root is what decides.
    pytest.param("find / -name '*.py'", id="root-with-expression"),
    pytest.param("find / -maxdepth 4 -name '*.py'", id="root-with-maxdepth"),
    # find's own leading global options sit BEFORE the path, so they must not hide it.
    pytest.param("find -L / -name x", id="root-behind-a-follow-symlinks-flag"),
    pytest.param("find -P /proc -type f", id="proc-behind-a-nofollow-flag"),
]


@pytest.mark.parametrize("command", FIND_DENY)
def test_a_find_rooted_at_the_msys_root_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# ================================================================== DENY: grep -r

GREP_DENY = [
    pytest.param("grep -r pattern /", id="short-r-root"),
    pytest.param("grep -R pattern /", id="short-R-root"),
    pytest.param("grep --recursive pattern /", id="long-recursive-root"),
    pytest.param("grep -r pattern /proc", id="short-r-proc"),
    pytest.param("grep -rn pattern /proc", id="clustered-flag-proc"),
    pytest.param("grep -rn pattern /proc/registry", id="clustered-flag-registry"),
    pytest.param("grep --dereference-recursive pattern /proc", id="long-deref-recursive-proc"),
    # `-d recurse` is `-r` spelled long-hand, and its value must be read rather than skipped.
    pytest.param("grep -d recurse pattern /proc", id="directories-action-recurse"),
    pytest.param("grep --directories=recurse pattern /", id="directories-option-recurse"),
    # An option that takes a SEPARATE value must not shift the pattern/target reading.
    pytest.param("grep -r -m 5 pattern /proc", id="value-taking-option-before-the-target"),
    pytest.param("grep -e pattern -r /proc", id="pattern-supplied-by-e-so-proc-is-a-target"),
]


@pytest.mark.parametrize("command", GREP_DENY)
def test_a_recursive_grep_over_the_msys_root_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# ================================================================== DENY: through a wrapper

WRAPPED_DENY = [
    # A leading `cd X &&`. Each shell-separated simple command is judged on its own.
    pytest.param("cd /c/work/repo && find / -name x", id="cd-and-find-root"),
    pytest.param("cd sub; find /proc", id="cd-semicolon-find-proc"),
    pytest.param("cd sub || find /proc/registry", id="cd-or-find-registry"),
    pytest.param("cd sub && grep -r pattern /proc", id="cd-and-recursive-grep"),
    # Through xargs, with and without option values in the way.
    pytest.param("ls | xargs find /proc -name x", id="xargs-find-proc"),
    pytest.param("echo x | xargs -I {} find / -name {}", id="xargs-replace-flag-find-root"),
    pytest.param("cat list | xargs -n 1 grep -r pattern /proc", id="xargs-maxargs-grep-proc"),
    # A newline is a separator too, and it is how a multi-line Bash payload arrives.
    pytest.param("echo starting\nfind /proc", id="newline-separated"),
]


@pytest.mark.parametrize("command", WRAPPED_DENY)
def test_the_walk_is_caught_through_a_leading_cd_or_an_xargs(command: str) -> None:
    assert_denied(run_guard(bash(command)))


def test_the_powershell_tool_is_screened_too() -> None:
    """The matcher wiring this guard selects both shell tools, so the guard must judge both."""
    assert_denied(run_guard(bash("find /proc", tool="PowerShell")))


# ================================================== DENY: the fail-opens a critic measured

# EVERY ROW HERE WAS ALLOWED BY THE COMMITTED GUARD AND IS NOW DENIED. They are kept as a block,
# with their mechanism named, because each one is a shape a reader would call contrived until they
# see that it was found by driving the real hook rather than by reasoning about it.
#
# Rows 1-2: the heredoc opener was matched on the RAW line, so a `<<` inside a quoted pattern, and
#           the second `<` of a `<<<` herestring, each set a terminator word that never appeared
#           again -- blanking every later line, the real walk included.
# Rows 3-5: the segment splitter had no case for command substitution or a subshell, so the walk
#           sat somewhere program position never looked.
# Row 6:    the prune exemption was a substring match with no trailing boundary, so a path that
#           merely STARTS with /proc satisfied it.
# Row 7:    the same substring match read a shell COMMENT. This is the one that matters: the deny
#           message hands the agent the exact text `-path /proc -prune -o`, so pasting the advice
#           into a comment turned the retry into an exemption.
# Row 8:    `-d recurse` was recognised only in its short spelling, so the long option's value was
#           consumed without being read and the walk read as non-recursive.
MEASURED_FAIL_OPENS = [
    pytest.param('grep -rn "x << y" .\nfind /proc', id="quoted-shift-then-walk"),
    pytest.param("bash <<< 'hello'\nfind /proc", id="herestring-then-walk"),
    pytest.param("echo $(find /proc)", id="command-substitution"),
    pytest.param("echo `find /proc`", id="backtick-substitution"),
    pytest.param("(find /proc)", id="subshell"),
    pytest.param("find / -path /procurement -prune -o -print", id="prune-on-a-lookalike-path"),
    pytest.param(
        "find / -name x # use -path /proc -prune -o instead", id="prune-named-only-in-a-comment"
    ),
    pytest.param("grep --directories recurse pattern /proc", id="long-directories-recurse"),
]


@pytest.mark.parametrize("command", MEASURED_FAIL_OPENS)
def test_a_measured_fail_open_is_now_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


def test_a_real_heredoc_is_still_blanked_so_the_fix_did_not_cost_the_allow_side() -> None:
    """The control for rows 1-2 above. Tightening the opener must not stop it finding a real one.

    Without this, the cheapest way to pass those two rows is to disable the heredoc pass entirely,
    which would deny every commit that documents this guard.
    """
    assert_allowed(run_guard(bash("cat >> docs/X.md <<'EOF'\nfind /proc leaks.\nEOF")))
    assert_allowed(run_guard(bash("cat >> docs/X.md <<EOF\nfind /proc leaks.\nEOF")))


# ================================================================== ALLOW: bounded work

# EVERY PATH BELOW IS GENERIC ON PURPOSE. The repository's leak gate
# (scripts/security/scan_forbidden.py) refuses a tracked file carrying an absolute user-home path,
# because an OS account name is a real host string and this repo is public. A test payload spelling
# one out was blocked at commit, which is the gate working; the guard cares about the ROOT of the
# walk and not about whose home directory it is, so nothing is lost by using a placeholder.
BOUNDED_ALLOW = [
    pytest.param("find . -maxdepth 3", id="relative-root-with-depth"),
    pytest.param("find /c/work/repo -maxdepth 4 -name '*.py'", id="real-root-with-depth"),
    pytest.param("find /tmp -name x", id="tmp-root"),
    pytest.param("find /c -maxdepth 1", id="drive-mount-root"),
    pytest.param("find ./src -type f", id="relative-subdirectory"),
    pytest.param("find /procurement -name x", id="a-path-that-merely-starts-with-proc"),
    pytest.param("grep -rn pattern ./src", id="recursive-grep-on-a-real-directory"),
    pytest.param("grep -r pattern /c/work/repo", id="recursive-grep-on-a-real-root"),
    # NOT recursive, so it reads one named file and cannot walk anything.
    pytest.param("grep pattern /proc/version", id="non-recursive-read-of-one-proc-file"),
    pytest.param("grep -n pattern /proc/cpuinfo", id="non-recursive-with-line-numbers"),
]


@pytest.mark.parametrize("command", BOUNDED_ALLOW)
def test_a_bounded_walk_is_not_denied(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# ================================================================== ALLOW: the word, not the program

# THE SHAPE THAT MAKES A GUARD GET DISABLED. `find` is an ordinary English word, a directory name,
# and a flag fragment. The sibling block-api-burn.ps1 records the same trap from the other side:
# a pattern written for a claim also matched the sentence disclaiming it, so `echo "gh run watch
# is banned"` denied itself and would have blocked writing the documentation for its own rule.
MERE_MENTION_ALLOW = [
    pytest.param("echo findings", id="a-word-beginning-with-find"),
    pytest.param("echo 'find /proc is blocked'", id="prose-quoting-the-denied-command"),
    pytest.param('echo "find / -name x"', id="double-quoted-prose"),
    pytest.param(r"cat C:\find\notes.txt", id="a-windows-path-containing-find"),
    pytest.param("git log --find-renames", id="a-flag-fragment"),
    pytest.param("git log --grep find", id="find-as-an-argument-to-something-else"),
    pytest.param("ls /proc", id="a-different-program-reading-proc"),
    pytest.param("cat /proc/version", id="reading-one-proc-file"),
    pytest.param("echo /proc/registry", id="printing-the-path"),
    pytest.param("grep pattern ./notes-about-find.txt", id="a-filename-containing-find"),
]


@pytest.mark.parametrize("command", MERE_MENTION_ALLOW)
def test_merely_containing_the_word_find_is_not_a_walk(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def test_a_heredoc_writing_this_very_rule_is_not_denied() -> None:
    """A heredoc body is data being written to a file, not a command.

    Without the heredoc pass its lines land at the front of a newline-split segment and are read
    there as program position -- which would deny the commit that documents the guard.
    """
    payload = "cat >> docs/X.md <<'EOF'\nfind /proc is blocked by the scan gate.\nEOF"
    assert_allowed(run_guard(bash(payload)))


def test_a_commit_message_quoting_the_denied_command_is_not_denied() -> None:
    assert_allowed(run_guard(bash('git commit -m "block find /proc; it leaks handles"')))


# ================================================================== ALLOW: the prune guard

# THE SANCTIONED ESCAPE, AND IT IS THE ONE THE DENY MESSAGE NAMES. Recognising it SUPPRESSES a
# deny and can never produce one, so a spelling missing here costs a false deny -- noisy, visible,
# self-reporting -- rather than a silent hole.
PRUNED_ALLOW = [
    pytest.param(
        "find / -path /proc -prune -o -name '*.py' -print", id="prune-before-the-expression"
    ),
    pytest.param("find / -path '/proc' -prune -o -type f -print", id="prune-with-a-quoted-path"),
    pytest.param("find /proc -path /proc/registry -prune -o -print", id="prune-inside-proc"),
    pytest.param("find / -wholename /proc -prune -o -name x", id="prune-spelled-wholename"),
]


@pytest.mark.parametrize("command", PRUNED_ALLOW)
def test_an_explicit_prune_guard_is_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def test_a_prune_that_names_only_one_registry_mount_still_allows_and_why() -> None:
    """MEASURED, AND IT IS A KNOWN GAP RATHER THAN A DESIGN CHOICE (2026-09-20).

    Pruning `/proc/registry` alone was tried against the real tree and the walk fell straight into
    `/proc/registry32` and kept leaking. The guard cannot tell that spelling apart from a correct
    one without reasoning about which of the three mounts a pattern covers, and a recognition that
    can turn a deny into an ALLOW is the construct that fails open.

    So this row asserts the CURRENT behaviour and names it a gap. It is pinned rather than left to
    be discovered, because the deny message is what closes it in practice: it tells the reader to
    prune the whole of `/proc`, and says that pruning one mount is not enough.
    """
    assert_allowed(run_guard(bash("find / -path /proc/registry -prune -o -print")))


# ============================================ DENY: the five bypasses that started this

# EACH ROW WAS DRIVEN AGAINST THE COMMITTED GUARD AND CAME BACK ALLOW. They sit in their own list,
# once, so the report that found them has one place to check. Pinning ONLY these five would close
# five holes and leave two families open, which is what the two corpora after this one are for.
MEASURED_BYPASS_DENY = [
    pytest.param("find /. -name x", id="dot-root"),
    pytest.param("find // -name x", id="double-slash"),
    pytest.param("find /./ -name x", id="dot-slash-root"),
    pytest.param("grep -r --regexp=foo /proc", id="long-regexp-equals"),
    pytest.param("grep -rm5 foo /proc", id="bundled-r-with-attached-value"),
]


@pytest.mark.parametrize("command", MEASURED_BYPASS_DENY)
def test_a_measured_bypass_of_the_walk_root_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# ============================================ DENY: a root spelled a way the string test missed

# THE FAMILY, NOT THE FIVE. Every spelling here resolves to the MSYS root or to /proc without being
# the literal string the guard compared, so patching the five above would have left all of it open.
#
# WHAT EACH SPELLING ACTUALLY RESOLVES TO WAS MEASURED, NOT ASSUMED (2026-09-20, `ls` at one level
# rather than a walk, and `printf` for what bash hands the program). The guard's Get-Operand and
# Get-NormalizedPath headers carry the readings; they are not copied here (CLAUDE.md section 11).
# Two are worth naming because they look contrived and are not: `/tmp/..` really is the MSYS root,
# because MSYS resolves `..` lexically rather than through the mount table; and `/pro\c` really is
# `/proc`, because bash deletes an unquoted backslash before find ever sees the word.
NORMALIZED_ROOT_DENY = [
    # Dot segments, anywhere in the path.
    pytest.param("find /./proc -name x", id="dot-before-proc"),
    pytest.param("find /proc/. -name x", id="trailing-dot-segment"),
    pytest.param("find /proc/./registry -name x", id="dot-inside-proc"),
    pytest.param("find /.// -name x", id="dot-then-repeated-separator"),
    # Repeated separators. THREE or more collapse to the MSYS root; exactly two do not, and that
    # case is the network root, asserted separately below.
    pytest.param("find /// -name x", id="triple-slash"),
    pytest.param("find ///// -name x", id="five-slashes"),
    pytest.param("find /proc// -name x", id="repeated-separator-inside-proc"),
    # Parent segments. At a root, `..` is the root.
    pytest.param("find /.. -name x", id="parent-of-the-root"),
    pytest.param("find /tmp/.. -name x", id="parent-of-a-mount"),
    pytest.param("find /proc/registry/.. -name x", id="parent-back-up-into-proc"),
    pytest.param("find /tmp/../proc -name x", id="parent-then-down-into-proc"),
    # A backslash. UNQUOTED it is a shell ESCAPE, so bash deletes it and the program is handed a
    # word with no backslash in it at all -- these three are `/proc` by the time find runs, and all
    # three were measured ALLOWED by a first cut that read the backslash as a separator instead.
    # QUOTED it survives, and MSYS then reads it as a separator once the path has resolved through
    # the POSIX root: `ls '/proc\registry'` returned the six HKEY_* roots.
    pytest.param(r"find /\proc -name x", id="escaped-slash-before-proc"),
    pytest.param(r"find \/proc -name x", id="escaped-leading-slash"),
    pytest.param(r"find /pro\c -name x", id="escape-inside-the-word"),
    pytest.param(r"grep -r foo /\proc", id="escaped-proc-under-a-recursive-grep"),
    pytest.param(r"find '/proc\registry' -name x", id="quoted-backslash-into-the-registry"),
    pytest.param(r"grep -r foo '/proc\registry'", id="quoted-backslash-under-a-recursive-grep"),
    # Quote concatenation. The shell removes quotes throughout a word, so none of these reach the
    # program with a quote in them -- but the guard used to strip only a matched OUTER pair.
    pytest.param("find /'' -name x", id="root-with-an-empty-single-quoted-tail"),
    pytest.param('find /"" -name x', id="root-with-an-empty-double-quoted-tail"),
    pytest.param("find '/'\"\" -name x", id="root-spelled-in-two-quoted-pieces"),
    pytest.param("find /pro'c' -name x", id="proc-spelled-in-two-quoted-pieces"),
    pytest.param("grep -r foo /''", id="quoted-concatenation-under-a-recursive-grep"),
    # The same folding under the grep branch and through the wrappers the guard already handles.
    pytest.param("grep -r foo /.", id="recursive-grep-on-the-dot-root"),
    pytest.param("grep -r foo /./proc", id="recursive-grep-on-a-dotted-proc"),
    pytest.param("ls | xargs find /. -name x", id="folded-root-behind-xargs"),
    pytest.param("cd sub && find /./proc", id="folded-proc-behind-a-cd"),
    pytest.param("echo starting\nfind /..", id="folded-root-after-a-newline"),
    # `--` ends find's options, which the operand scan did not know: `find -- /proc` was ALLOWED
    # until the scan learned it. Measured on this machine's findutils -- `find -- . -maxdepth 0`
    # prints `.` and exits 0 -- so this is a real spelling, not a hypothetical one.
    pytest.param("find -- /proc -name x", id="end-of-options-then-proc"),
    pytest.param("find -- / -name x", id="end-of-options-then-root"),
]


@pytest.mark.parametrize("command", NORMALIZED_ROOT_DENY)
def test_a_root_spelled_another_way_is_still_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# ============================================ DENY: an option grammar the name test missed

# TWO SHAPES, AND THEY FAIL IN OPPOSITE DIRECTIONS. A long option carrying its value with `=` hides
# the option's NAME behind that value, so the name never matches a list and the pattern is never
# marked taken -- which makes the guard read the TARGET as the pattern and find no target at all. A
# short bundle hides `-r` among other letters, and an attached numeric value breaks any test that
# expects the bundle to be all letters. Every row here was ALLOWED by the committed guard.
OPTION_GRAMMAR_DENY = [
    # Long form, value attached with `=`. The plain `grep -r --regexp=foo /proc` is not repeated
    # here: it is one of the five, and sits in MEASURED_BYPASS_DENY above.
    pytest.param("grep --regexp=foo -r /proc", id="regexp-equals-before-r"),
    pytest.param("grep -R --regexp=foo /proc", id="regexp-equals-with-capital-R"),
    pytest.param("grep -r --file=pats.txt /proc", id="file-equals"),
    pytest.param("grep --recursive --regexp=foo /", id="regexp-equals-with-the-long-recursive"),
    # Short bundle, value attached. `grep -rm5 foo /proc` is one of the five and is not repeated.
    pytest.param("grep -rA2 foo /proc", id="bundled-after-context"),
    pytest.param("grep -rB2 foo /proc", id="bundled-before-context"),
    pytest.param("grep -rC3 foo /proc", id="bundled-context"),
    pytest.param("grep -r5 foo /proc", id="bundled-numeric-context-shortcut"),
    pytest.param("grep -drecurse foo /proc", id="directories-action-attached-to-its-letter"),
    # Short bundle, value as the next word: the value must be stepped over, not read as a target.
    pytest.param("grep -rm 5 foo /proc", id="bundled-max-count-with-a-separate-value"),
    pytest.param("grep -rd recurse foo /proc", id="bundled-directories-with-a-separate-value"),
    pytest.param("grep -rf pats.txt /proc", id="bundled-pattern-file"),
]


@pytest.mark.parametrize("command", OPTION_GRAMMAR_DENY)
def test_a_recursive_grep_hidden_in_the_option_grammar_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# ============================================ DENY: the network root, with its OWN reason


# EXACTLY TWO LEADING SLASHES ARE NOT THE MSYS ROOT, and folding them into it would have been the
# easy way to make `find //` deny. Measured 2026-09-20: `ls //` listed the network root, and
# `ls -d //proc` failed outright, so `//proc` is a UNC host named "proc" and not the /proc mount.
# The walk is still unbounded and still uninterruptible, so it is still a deny -- but under a cause
# that is true of it. A deny message asserting the registry mounts for this command would be a
# control resting on a false premise (CLAUDE.md section 11, SDS-3.7), which is why the last
# assertion here is a NEGATIVE one.
@pytest.mark.parametrize(
    "command",
    ["find // -name x", "find //. -name x", "grep -r foo //"],
    ids=["find", "dot", "grep"],
)
def test_the_network_root_denies_under_its_own_cause(command: str) -> None:
    reason = assert_denied(run_guard(bash(command)))
    assert "network root" in reason
    assert "two leading slashes" in reason
    assert "registry" not in reason, (
        "the network root is the UNC namespace, not the registry mounts: this message would "
        f"hand the reader a cause that is false for the command they ran -- {reason!r}"
    )
    assert reason.isascii(), f"non-ASCII in the network deny message: {reason!r}"


# ============================================ the two claims that did NOT reproduce


# THESE TWO WERE REPORTED AS BYPASSES AND WERE ALREADY DENIED. They are pinned rather than dropped,
# because the fix above rewrote both code paths they run through -- the prune exemption now reads a
# LITERAL operand while the walk root is folded, and a later tidy-up that unified the two would
# silently turn the first of these into an exemption.
def test_a_prune_on_a_path_that_matches_nothing_was_already_denied() -> None:
    assert_denied(run_guard(bash("find / -path /nonexistent -prune -o -name x -print")))


def test_a_trailing_separator_on_proc_was_already_denied() -> None:
    assert_denied(run_guard(bash("find /proc/ -name x")))


# ============================================ the prune exemption, from both sides

# ***`-path` IS A GLOB MATCHED AGAINST THE PATH find ITSELF GENERATES, AND find GENERATES IT BY
# APPENDING TO THE LITERAL ROOT YOU GAVE IT.*** Two halves follow from that one sentence, and the
# guard got each of them wrong in turn.
#
# PATTERN HALF: a pattern spelled `-path /./proc` or `-path /..` matches nothing, so the prune is
# inert and the walk must stay a DENY. Folding the pattern -- the obvious symmetry with the
# walk-root side -- would turn it into an exemption instead, and an exemption is the direction that
# goes silent.
#
# ROOT HALF, and this one was MEASURED ALLOWED after the pattern half was fixed. `find /. -path
# /proc -prune -o -name x -print` generates `/./proc`, so that perfectly ordinary prune matches
# nothing either, and the registry walk ran. It is the worst of the four because the guard's own
# deny message hands the agent exactly that text, so an agent denied for `find /.` and following
# the advice verbatim landed here. The exemption is now scoped: the pattern must start with the
# literal root. `find /proc/registry -path /proc -prune` fails that test for the same reason.
PRUNE_INERT_DENY = [
    pytest.param("find / -path /./proc -prune -o -name x -print", id="dotted-prune-pattern"),
    pytest.param(r"find / -path /proc\registry -prune -o -name x", id="backslash-prune-pattern"),
    pytest.param("find / -path /.. -prune -o -name x -print", id="parent-prune-pattern"),
    pytest.param("find / -wholename //proc -prune -o -name x", id="double-slash-prune-pattern"),
    pytest.param("find /. -path /proc -prune -o -name x -print", id="folded-root-with-good-prune"),
    pytest.param("find /proc/. -path /proc -prune -o -print", id="dotted-proc-with-good-prune"),
    pytest.param("find /tmp/.. -path /proc -prune -o -print", id="parent-root-with-good-prune"),
    pytest.param(
        "find /proc/registry -path /proc -prune -o -print", id="prune-above-the-root-it-is-given"
    ),
    # There is no /proc under the UNC namespace, so pruning it bounds nothing there. The network
    # arm is decided before the exemption is even consulted.
    pytest.param("find // -path /proc -prune -o -name x", id="prune-cannot-bound-the-network-root"),
]


@pytest.mark.parametrize("command", PRUNE_INERT_DENY)
def test_a_prune_that_cannot_fire_is_not_an_exemption(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# ============================================ ALLOW: what the folding must NOT catch

# OVER-DENYING IS THE WORSE FAILURE HERE, because a guard that refuses real work gets switched off
# and then protects nothing. THREE ROWS IN THIS LIST WERE MEASURED DENYING mid-change, by a first
# cut that read every `\` as a separator instead of as the shell escape it is: `find . \` (a line
# continuation), `find . \( ... \)` (find's own grouping, which splits at the paren and leaves a
# bare `\` in path position) and `find \proc`. They are kept as rows rather than as a note, because
# the cheapest way to pass the backslash deny rows above is exactly the rule that broke these.
#
# The rest are the resolver's own answers, measured the same day with `ls` and with `printf` for
# what bash hands the program. `//proc`, `/PROC`, `/\proc` and `\proc` do not exist; `/proc/../tmp`
# is `/tmp`; a lone `\` is the current DRIVE root, which is outside this guard's stated subject; and
# `find /proc\registry` unquoted is `/procregistry`, which is why its QUOTED twin is the deny row.
FOLDING_ALLOW = [
    pytest.param("find . \\", id="a-line-continuation-leaves-a-bare-backslash"),
    pytest.param("find . \\( -name a -o -name b \\) -print", id="finds-own-grouping-parens"),
    pytest.param(r"find \proc -name x", id="a-leading-backslash-reaches-no-root"),
    pytest.param(r"find \\proc\registry -name x", id="an-all-backslash-path-reaches-no-root"),
    # THESE TWO ARE THE ONLY ROWS THAT SEPARATE THE LEADING-SLASH ANCHOR FROM AN UNCONDITIONAL
    # CONVERSION, and they were added because a mutation arm proved the anchor untested: breaking
    # it left the whole module green. Every other backslash row loses its backslash to the shell
    # before the fold sees it, so only a QUOTED backslash in leading position can tell the two
    # rules apart. Both were driven at `ls`: `\proc` does not exist, and a lone `\` is the current
    # DRIVE root rather than the MSYS one, which is outside this guard's stated subject.
    pytest.param(r"find '\proc' -name x", id="a-quoted-leading-backslash"),
    pytest.param(r"find '\' -name x", id="a-quoted-lone-backslash-is-the-drive-root"),
    pytest.param(r"find /proc\registry -name x", id="an-unquoted-escape-eaten-by-the-shell"),
    pytest.param(r'find "/\proc" -name x', id="a-quoted-backslash-in-leading-position"),
    pytest.param("find //proc -name x", id="a-unc-host-that-is-not-the-proc-mount"),
    pytest.param(r"find //server\share -maxdepth 2", id="a-real-unc-share"),
    pytest.param("find /PROC -name x", id="the-proc-mount-is-case-sensitive"),
    pytest.param("find /proc/../tmp -name x", id="a-parent-that-leaves-proc-for-a-real-root"),
    pytest.param("find /c/work/../repo -maxdepth 2", id="a-parent-inside-a-real-tree"),
    pytest.param("find ./x/../y -name z", id="a-parent-in-a-relative-path"),
    # A DRIVE path, driven through `find` on purpose. Spelled through `cat` it would exit at the
    # guard's find/grep substring early-out and could not fail, which is what an earlier version of
    # this row did. Written with a placeholder directory because the repository's leak gate refuses
    # a tracked absolute user-home path.
    pytest.param(r"find C:\work -maxdepth 2", id="a-windows-drive-path"),
    # `-er` is `-e` taking `r` as its PATTERN, so this grep is not recursive and cannot walk. The
    # old whole-token regex called it recursive and denied it for the wrong reason; reading the
    # bundle character by character is what gets both directions right.
    pytest.param("grep -er foo /proc", id="an-r-that-is-the-argument-of-e"),
    pytest.param("grep -m5 foo /proc/version", id="a-bundled-value-with-no-recursion"),
    pytest.param("grep --regexp=foo /proc/version", id="long-regexp-equals-with-no-recursion"),
    pytest.param("grep -A2 foo /proc/cpuinfo", id="context-option-with-no-recursion"),
    # GNU getopt_long is case-SENSITIVE, so this is an unrecognised option and grep walks nothing.
    # Denying it would hand the reader the registry cause for a command that never ran.
    pytest.param("grep --RECURSIVE foo /proc", id="a-long-option-in-the-wrong-case"),
]


@pytest.mark.parametrize("command", FOLDING_ALLOW)
def test_the_folding_does_not_reach_a_bounded_command(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# ============================================ DENY: a walk the quote masker blanked (BACKLOG #5607)

# THE QUOTE MASKER USED TO BLANK A WHOLE QUOTED SPAN AND IGNORE BACKSLASHES, and each row below was
# allowed by it. Inside double quotes bash still runs a `$(...)` or backtick substitution, so
# blanking the span hid a real walk from program position. And a backslash-escaped quote opens or
# closes nothing, so treating it as a quote shifted every later span by one: the separator and the
# walk after it fell inside a span that bash never opened. `$'...'` takes backslash escapes too, so
# `$'\''` is one quote character, not the end of a span.
QUOTED_SUBSTITUTION_DENY = [
    pytest.param('echo "$(find /proc)"', id="dollar-substitution-inside-double-quotes"),
    pytest.param('echo "`find /proc`"', id="backtick-substitution-inside-double-quotes"),
    pytest.param('echo "x $(grep -r p /proc) y"', id="recursive-grep-substitution-in-prose"),
    pytest.param('echo "$(echo "inner") $(find /)"', id="second-substitution-after-nested-quotes"),
    pytest.param('echo "$( (find /proc) )"', id="subshell-inside-a-quoted-substitution"),
    pytest.param(r"echo \"; find /proc; echo \"", id="escaped-quotes-outside-any-span"),
    pytest.param(r'echo "a\"b"; find /proc', id="escaped-quote-inside-a-double-quoted-span"),
    pytest.param(r"echo $'\''; find /proc", id="escaped-quote-inside-ansi-c-quotes"),
    # The other side of the same rule: an ESCAPED dollar starts no `$'...'`, so the single quotes
    # after it are plain ones, in which a backslash escapes nothing.
    pytest.param(r"echo \$'\'; find /proc", id="escaped-dollar-before-plain-single-quotes"),
    # `$$` is the PID, so the quote after it is a plain one, not a `$'...'`.
    pytest.param(r"echo $$'\'; find /proc", id="pid-before-plain-single-quotes"),
    # A quote inside a heredoc body is data, in the commit-message form and at the top level.
    pytest.param(
        "git commit -m \"$(cat <<'EOF'\nFix: don't break it\nEOF\n)\" && grep -r foo /proc",
        id="apostrophe-in-a-heredoc-inside-a-quoted-substitution",
    ),
    pytest.param("cat <<EOF\ndon't\nEOF\nfind /proc", id="apostrophe-in-a-top-level-heredoc"),
    # Arithmetic is not a heredoc opener.
    pytest.param('echo "$((1 << n))"\nfind /proc', id="shift-inside-quoted-arithmetic"),
    # Arithmetic still runs a substitution, and a comment's apostrophe opens no span. In each the
    # walk sits inside the double-quoted span, where the plain toggle blanks it too.
    pytest.param(
        'echo "logs: $(( $(find / -name x | wc -l) + 0 ))"', id="substitution-in-quoted-arithmetic"
    ),
    pytest.param(
        'echo "$(echo a # don\'t\n) $(find /proc)"', id="comment-apostrophe-before-a-substitution"
    ),
]


@pytest.mark.parametrize("command", QUOTED_SUBSTITUTION_DENY)
def test_a_walk_the_quote_masker_used_to_blank_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# THE CONTROL FOR THE LIST ABOVE. The cheapest way to pass it is to stop blanking quoted spans at
# all, which would deny every commit message that names this guard. Each row is prose bash never
# runs: an escaped quote, an escaped backtick or dollar, and a substitution inside single quotes.
QUOTED_PROSE_ALLOW = [
    pytest.param(r'git commit -m "say \"find /proc\" is blocked"', id="escaped-quotes-in-prose"),
    pytest.param(r'git commit -m "a \`find /proc\` mention"', id="escaped-backticks-in-prose"),
    pytest.param(r'echo "cost: \$(find /proc)"', id="escaped-dollar-in-prose"),
    pytest.param("echo '$(find /proc)'", id="substitution-inside-single-quotes"),
    pytest.param("echo \"$(echo 'find /proc')\"", id="single-quoted-word-inside-a-substitution"),
    pytest.param(r"echo $'it\'s find /proc'", id="ansi-c-quoted-prose"),
    pytest.param('echo "$(echo a # it\'s a find /proc mention\n)"', id="walk-named-in-a-comment"),
]


@pytest.mark.parametrize("command", QUOTED_PROSE_ALLOW)
def test_quoted_prose_naming_a_walk_is_still_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# THE POWERSHELL TOOL KEEPS THE PLAIN QUOTE TOGGLE, beside its own escape reading (BACKLOG #5451,
# tests/test_fs_scan_escaped_quotes.py), never the bash one. Its escape is the backtick and a backslash is
# literal, so reading these as bash would open a substitution or an escape that never closes and
# blank the walk after it. Each was denied before the bash masker and must stay denied.
POWERSHELL_QUOTE_DENY = [
    pytest.param('Write-Host "done`n"; grep -r x /proc', id="backtick-escape-in-a-string"),
    pytest.param('Get-ChildItem "D:\\Code\\"; grep -r x /proc', id="trailing-backslash-path"),
]


def test_a_payload_without_a_tool_name_is_still_screened() -> None:
    """Strict mode throws on a missing property, and the guard's catch allows."""
    assert_denied(run_guard('{"tool_input": {"command": "find /proc"}}'))


@pytest.mark.parametrize("command", POWERSHELL_QUOTE_DENY)
def test_a_powershell_string_does_not_hide_the_walk_after_it(command: str) -> None:
    assert_denied(run_guard(bash(command, tool="PowerShell")))


# THE BASH READING MUST NEVER ALLOW WHAT THE PLAIN TOGGLE DENIED. Each row was denied by the toggle
# alone, before the bash reading existed, and allowed once the bash reading replaced it: its own
# misreading blanked a walk the toggle left visible. The quote in each row is what sends it through
# the masker at all; a command with none is never masked.
TOGGLE_FLOOR_DENY = [
    # `$((` opens arithmetic, whose body was blanked whole, substitution and all.
    pytest.param(
        "x='a'; echo $(( $(find /proc | wc -l) + 1 ))", id="substitution-inside-arithmetic"
    ),
    # `$((cmd) )` is a subshell in a substitution, not arithmetic: the `) )` never closes `$((`.
    pytest.param("echo 'a'; echo $((find /proc) )", id="subshell-substitution-read-as-arithmetic"),
    # `cat<<` with no space was no heredoc opener, so the apostrophe in its body opened a span.
    pytest.param(
        "git commit -m \"$(cat<<'EOF'\nFix: don't break it\nEOF\n)\" && grep -r foo /proc",
        id="unspaced-heredoc-inside-a-quoted-substitution",
    ),
    # Only the second delimiter was kept, so the first terminator line was blanked as body.
    pytest.param(
        'echo "a"; cat <<A <<B\nx\nA\ny\nB\nfind /proc', id="two-heredocs-opened-on-one-line"
    ),
    # A comment is not quoting, so the apostrophe in it opened a span.
    pytest.param(
        'echo "$(echo a # don\'t\n)" && grep -r x /proc',
        id="apostrophe-in-a-comment-inside-a-quoted-substitution",
    ),
]


# A `#` STARTS A COMMENT ONLY WHERE BASH STARTS A WORD. Each `#` below carries a word on, so blanking
# from it as a comment would hide the walk after it, which sits where the plain toggle blanks it too.
# The last row's comment is real, but it ends at the closing backtick, not the newline.
COMMENT_BOUNDARY_DENY = [
    pytest.param('echo "$(echo $(echo a)#b; find /proc)"', id="hash-after-a-substitution"),
    pytest.param('echo "$(echo $((1+2))#b; find /proc)"', id="hash-after-arithmetic"),
    pytest.param(r'echo "$(echo a\ #b; find /proc)"', id="hash-after-an-escaped-space"),
    pytest.param('echo "$(echo a\\\n#b; find /proc)"', id="hash-after-a-line-continuation"),
    pytest.param('echo "$(echo ${x:- #a}; find /proc)"', id="hash-inside-a-parameter-expansion"),
    pytest.param(r"echo \"`echo a #x`; find /proc #\"", id="comment-ends-at-a-top-level-backtick"),
]


@pytest.mark.parametrize("command", COMMENT_BOUNDARY_DENY)
def test_a_hash_that_carries_a_word_on_hides_no_walk(command: str) -> None:
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", TOGGLE_FLOOR_DENY)
def test_a_walk_the_plain_toggle_denied_is_still_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# THE MISREADINGS THE REFINED VIEW CORRECTS (BACKLOG #5607), each inside a double-quoted span, where
# the plain toggle blanks the walk too, so the floor above cannot catch it. Each row was allowed on
# origin/main: `$((cmd) )` read as arithmetic, also with a quoted or escaped paren in the subshell;
# a glued `cat<<` read as no opener; two heredocs on a line, whose first terminator the bash view
# blanked as body; and a spaced shift in `(( ))` or `$[ ]` read as a heredoc opener.
REFINED_READING_DENY = [
    pytest.param('echo "$((find /proc) )"', id="subshell-substitution-inside-double-quotes"),
    pytest.param('echo "$(echo $((find /proc) ))"', id="subshell-substitution-in-a-substitution"),
    pytest.param(
        "echo \"$(cat<<'EOF'\ndon't\nEOF\n) $(find /proc)\"",
        id="glued-heredoc-with-a-quoted-delimiter",
    ),
    pytest.param(
        'echo "$(cat<<EOF\ndon\'t\nEOF\n) $(find /proc)"', id="glued-heredoc-with-a-bare-delimiter"
    ),
    pytest.param(
        'echo "$(cat <<A <<B\nx\nA\ny\nB\n) $(find /proc)"', id="two-heredocs-on-one-line"
    ),
    pytest.param(
        'echo "$(cat <<A <<B\nx\'\nA\ny\nB\n) $(find /proc)"',
        id="two-heredocs-with-an-apostrophe-in-the-first-body",
    ),
    pytest.param(
        "echo \"$(echo $((grep -r 'foo(' /proc) ))\"", id="quoted-paren-in-a-subshell-substitution"
    ),
    pytest.param(
        r'echo "$((echo \(; find /proc) ))"', id="escaped-paren-in-a-subshell-substitution"
    ),
    # A combining mark after an apostrophe leaves it a quote to bash, and the later `))` must not
    # close the arithmetic reading the first `) ` already refused.
    pytest.param(
        "echo \"$((echo 'a'\u0301; find /proc) )\"; echo ')) '",
        id="combining-mark-after-a-quote-in-a-subshell-substitution",
    ),
    pytest.param('echo "$( (( a << b ))\nfind /proc)"', id="spaced-shift-in-an-arithmetic-command"),
    pytest.param(
        'echo "$(echo $[ a << b ]\nfind /proc)"', id="spaced-shift-in-old-style-arithmetic"
    ),
    # A comment after the walk: its `#` ends the bound, and the walk before it is still read.
    pytest.param('echo "$((find /proc) )" # note', id="subshell-substitution-before-a-comment"),
    # Twenty nested `$(($(...) ) )` levels before the walk. Cutting every later site at each
    # restore spent the budget at about ten levels, so the view gave up and added nothing.
    pytest.param(
        'echo "' + "$(($(" * 20 + "echo a" + ") ) )" * 20 + '"; echo "$((find /proc) )"',
        id="walk-after-nested-subshell-substitutions",
    ),
]


@pytest.mark.parametrize("command", REFINED_READING_DENY)
def test_a_walk_the_refined_view_finds_inside_double_quotes_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# EACH ROW IS DENIED ON origin/main BY THE VIEWS JUDGED BEFORE THE REFINED ONE, so they pin that
# adding it keeps those denies. The first is the long-delimiter row an earlier cut of this change
# allowed: it read the delimiter from a 1024-character slice, in code the bash view runs, so the
# terminator never matched and every later line was blanked.
REFINED_FLOOR_DENY = [
    pytest.param(
        "echo 'it'\\''s'; cat <<" + "L" * 2000 + "\nx\n" + "L" * 2000 + "\nfind /proc",
        id="a-heredoc-delimiter-longer-than-1024-characters",
    ),
    pytest.param('echo "$( (( a<<b ))\nfind /proc)"', id="glued-shift-in-an-arithmetic-command"),
    pytest.param('echo "$(echo $[a<<b]\nfind /proc)"', id="glued-shift-in-old-style-arithmetic"),
]


@pytest.mark.parametrize("command", REFINED_FLOOR_DENY)
def test_a_walk_the_earlier_views_deny_stays_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# THE CONTROLS FOR THE REFINED VIEW: arithmetic that closes with `))` runs nothing, and both bodies
# of two heredocs opened on one line are data. A glued heredoc's body is not a row here: origin/main
# denies `echo "$(cat<<EOF` with `find /proc` in the body, and the refined view only adds denies.
REFINED_CONTROL_ALLOW = [
    pytest.param('echo "$(( find / 2 ))"', id="arithmetic-that-reads-like-a-walk"),
    pytest.param(
        'echo "$(cat <<A <<B\nfind /proc\nA\nfind /proc\nB\n)"', id="both-bodies-of-two-heredocs"
    ),
]


@pytest.mark.parametrize("command", REFINED_CONTROL_ALLOW)
def test_what_the_refined_view_reads_as_data_is_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# EACH ROW IS ALLOWED ON origin/main. Most were false denies of an earlier cut of this change: a
# shared scan budget spent by nested subshells, after which every `$((` read as a subshell; a glued
# `<<` read as a heredoc in an array subscript or in arithmetic glued to a reserved word, whose body
# blanked an opening quote and exposed the prose it holds; and a comment blanked in a command with
# no quote. The last three are controls for the glued opener's line rule.
REFINED_FALSE_DENY_ALLOW = [
    pytest.param(
        "(" * 250 + "true" + ") " * 250 + '; echo "$(( find / 2 ))"',
        id="arithmetic-after-many-nested-subshells",
    ),
    # Shallow enough that the refined view runs to the end rather than giving up on its budget.
    pytest.param(
        "(" * 60 + "true" + ") " * 60 + '; echo "$(( find / 2 ))"',
        id="arithmetic-after-some-nested-subshells",
    ),
    pytest.param('a[x<<y]=1\necho "\ny\nfind /proc\n"', id="glued-shift-in-an-array-subscript"),
    pytest.param(
        'a[ x<<y ]=1\necho "\ny\nfind /proc\n"', id="glued-shift-in-a-spaced-array-subscript"
    ),
    pytest.param(
        'a[(i<<k)]=v\necho "\nk\nfind /proc\n"', id="glued-shift-in-parens-in-a-subscript"
    ),
    pytest.param(
        'for i in 1; do((x<<y)); done\necho "\ny\nfind /proc\n"', id="arithmetic-glued-to-do"
    ),
    pytest.param(
        'if true; then((x<<y)); fi\necho "\ny\nfind /proc\n"', id="arithmetic-glued-to-then"
    ),
    pytest.param(
        'if false; then :; else((x<<y)); fi\necho "\ny\nfind /proc\n"',
        id="arithmetic-glued-to-else",
    ),
    pytest.param("cat <<EOF\nx\nEOF\nfind . # see; ls /proc", id="comment-in-a-quote-free-command"),
    # The refined view exposes a span the bash view blanked; a comment in it must not hand its words
    # to the operand loop, which reads the raw text to the end of a bound.
    pytest.param(
        'echo "$(cat<<EOF\nit\'s\nEOF\n)"; find . # see; ls /proc',
        id="comment-after-a-glued-heredoc",
    ),
    pytest.param(
        'echo "$((echo a) ) x"; find . # note; ls /proc', id="comment-after-a-subshell-substitution"
    ),
    pytest.param('(( x<<y ))\necho "\ny\nfind /proc\n"', id="glued-shift-in-an-arithmetic-command"),
    pytest.param('x=$((a<<b))\necho "\nb\nfind /proc\n"', id="glued-shift-in-arithmetic"),
    pytest.param('((x<<y)\necho "\ny\nfind /proc\n"', id="glued-shift-after-a-subshell-pair"),
]


@pytest.mark.parametrize("command", REFINED_FALSE_DENY_ALLOW)
def test_the_refined_view_adds_no_deny_main_did_not_have(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def _nested_subshell_substitutions(depth: int) -> str:
    """`echo "$(( $(( ... $((find /proc) ) ... ) ) ) )"`, DEPTH sites deep, every one a subshell."""
    inner = "$((find /proc) )"
    for _ in range(depth - 1):
        inner = "$(( " + inner + " ) )"
    return 'echo "' + inner + '"'


# THE ONE-PASS READING (BACKLOG #5607). The refined view used to read a `$((` site as arithmetic,
# and on a `)` that refused it, restore a saved state and read the site again as a subshell. Each
# nested site was read again for each site around it, so past some depth the budget gave up and
# the view added nothing. The rows at depths 50 and 200, and the twenty sites under an unclosed
# `${`, were allowed on 4a0c81c3d96 for that reason; depth 12 was denied there and is the shallow
# end. A `$((cmd) )` nested in arithmetic was never read as a site at all.
ONE_PASS_DENY = [
    pytest.param(_nested_subshell_substitutions(12), id="twelve-nested-subshell-substitutions"),
    pytest.param(_nested_subshell_substitutions(50), id="fifty-nested-subshell-substitutions"),
    pytest.param(
        _nested_subshell_substitutions(200), id="two-hundred-nested-subshell-substitutions"
    ),
    pytest.param(
        'echo "' + "$(( ${a:-$(" * 20 + "echo a" + ")} ) )" * 20 + '"; echo "$((find /proc) )"',
        id="walk-after-nested-sites-under-unclosed-parameter-expansions",
    ),
    pytest.param('echo "$(( $((find /proc) ) + 1 ))"', id="subshell-substitution-in-arithmetic"),
]


@pytest.mark.parametrize("command", ONE_PASS_DENY)
def test_a_walk_in_nested_sites_is_read_in_one_pass(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# WHERE ARITHMETIC AND A SUBSHELL WOULD CONSUME THE TEXT DIFFERENTLY, the view reads the site as a
# subshell, and the raw command is scanned beside it. One row per trigger, each in a site that is
# still undecided: a comment, a heredoc opener whose line ends inside the site, `$'...'`, `$[`, a
# nested frame opened inside `${...}`, and a backtick in a `((` inside a backtick substitution.
# The last three were allowed by an earlier cut that scanned the raw command alone, which splits
# the walk's quoted pattern at its separator, or that left a dropped heredoc opener visible.
FALLBACK_DENY = [
    pytest.param('echo "$(( a #b ))$((find /proc) )"', id="comment-in-a-site"),
    pytest.param(
        'echo "$(( x << y\n ))"; echo "$((find /proc) )"', id="heredoc-line-ends-in-a-site"
    ),
    pytest.param("echo \"$(( $'1' ))$((find /proc) )\"", id="ansi-c-quote-in-a-site"),
    pytest.param('echo "$(( $[1] ))$((find /proc) )"', id="old-style-arithmetic-in-a-site"),
    pytest.param(
        'echo "$(( ${x:-$(echo 1)} ))$((find /proc) )"', id="frame-opened-inside-braces-in-a-site"
    ),
    pytest.param(
        'echo "`(( `echo 1` ))`"; echo "$((find /proc) )"', id="backtick-in-a-site-in-backticks"
    ),
    pytest.param(
        "echo \\\" $((echo # c\n) ); grep -r 'a;b' /proc", id="quoted-separator-after-a-comment"
    ),
    pytest.param(
        'echo \\" $((cd x\necho "y") ); grep -r \'a;b\' /proc',
        id="quoted-separator-after-a-frame-on-a-later-line",
    ),
    pytest.param(
        'echo "q" $((true) ) $(( $((cat <<X) ) + 1 ))\nfind /proc\nX',
        id="heredoc-in-a-subshell-in-arithmetic",
    ),
]

# THE PRICE OF FAILING CLOSED, pinned so the fallback cannot stop running unnoticed: the raw scan
# reads the prose in the second command as a walk. Each was allowed on 4a0c81c3d96.
FALLBACK_FIRES_DENY = [
    pytest.param('echo "$(( a #b ))"; echo "x; find /proc"', id="prose-after-a-comment-in-a-site"),
    pytest.param(
        'echo "$(( x << y\n ))"; echo "x; find /proc"', id="prose-after-a-heredoc-line-in-a-site"
    ),
]

# THE CONTROLS: each holds a trigger's character where both readings agree, so the view runs to
# the end and the prose stays data. A heredoc opener whose site closes on its line is dropped with
# the arithmetic, a `#` glued to a word is no comment, and the rest sit in a nested frame, or
# after the braces closed, or in a `((` outside backticks.
FALLBACK_CONTROL_ALLOW = [
    pytest.param('echo "$(( 2#101 ))"; echo "x; find /proc"', id="base-prefix-in-a-site"),
    pytest.param(
        'echo "$(( x << y ))"; echo "x; find /proc"', id="shift-in-a-site-closed-on-its-line"
    ),
    pytest.param(
        'echo "$(( $(echo $\'1\') ))"; echo "x; find /proc"', id="ansi-c-quote-in-a-nested-frame"
    ),
    pytest.param(
        'echo "$(( $(echo $[1]) ))"; echo "x; find /proc"', id="old-style-arithmetic-in-a-frame"
    ),
    pytest.param(
        'echo "$(( ${#x} + $(echo 1) ))"; echo "x; find /proc"', id="frame-after-closed-braces"
    ),
    pytest.param('(( `echo 1` )); echo "x; find /proc"', id="backtick-in-a-top-level-site"),
]


@pytest.mark.parametrize("command", FALLBACK_DENY + FALLBACK_FIRES_DENY)
def test_a_form_the_refined_view_cannot_read_denies_through_the_raw_command(command: str) -> None:
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", FALLBACK_CONTROL_ALLOW)
def test_a_trigger_both_readings_agree_on_does_not_fall_back(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def _guard_seconds(command: str) -> float:
    started = time.monotonic()
    run_guard(bash(command))
    return time.monotonic() - started


def test_many_arithmetic_commands_are_read_in_linear_time() -> None:
    """Doubling the `(( 1 ))` sites must not quadruple the time.

    Every site takes the refined view's `((` frame, because the quote in `"find"` sends the command
    through the masker. An earlier cut scanned forward from every `((`, and a long run took about
    98 seconds, past the hook timeout, and a timed-out hook lets the command run. The bound allows
    for the fixed cost of starting pwsh, which both runs pay, and is loose because both runs are
    wall-clock timings.
    """
    half = _guard_seconds('echo "find"; ' + "(( 1 )); " * 3000)
    full = _guard_seconds('echo "find"; ' + "(( 1 )); " * 6000)
    assert full < 3 * half + 3


def test_deeply_nested_arithmetic_is_read_in_bounded_time() -> None:
    assert _guard_seconds('echo "find"; x=' + "$((" * 5000 + "1" + "))" * 5000) < 30


def test_nested_subshell_substitutions_are_read_in_linear_time() -> None:
    """Doubling the nested `$(( ... ) )` sites must not quadruple the time.

    Every site is a subshell, which the earlier cut found only by reading the site again, once per
    site around it. The bound allows for pwsh's fixed start cost, as the test above does.
    """
    half = _guard_seconds(_nested_subshell_substitutions(2000))
    full = _guard_seconds(_nested_subshell_substitutions(4000))
    assert full < 3 * half + 3


# ============================================ differentials against origin/main (BACKLOG #5607)

# THE REFINED VIEW MAY ONLY ADD DENIES, AND THE BASH AND PLAIN VIEWS MAY NOT MOVE AT ALL. A row list
# pins the forms someone thought of; these two compare the guard with origin/main's copy over the
# whole corpus and a seeded generated set, so a form nobody listed still has to agree. Both run
# every command inside ONE pwsh process, because a cold start per command would take an hour.
_BASE_REF = "origin/main"

# Runs Hide-QuotedSpans from two copies of the guard, read out of each file's syntax tree so the
# hook body never runs, and prints the index and view of every command whose mask differs.
_MASK_DRIVER = r"""
param([string]$Old, [string]$New, [string]$Commands)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Get-Fn([string]$Path) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $a.Name -eq 'Hide-QuotedSpans' }, $true)
    $params = ($fn.Parameters | ForEach-Object { $_.Extent.Text }) -join ', '
    $body = $fn.Body.Extent.Text
    [scriptblock]::Create("param($params)`n" + $body.Substring(1, $body.Length - 2))
}
$o = Get-Fn $Old
$w = Get-Fn $New
$cmds = @(Get-Content -Raw -Encoding utf8 $Commands | ConvertFrom-Json)
for ($i = 0; $i -lt $cmds.Count; $i++) {
    $c = [string]$cmds[$i]
    if ((& $o $c -Plain) -cne (& $w $c -Plain)) { "$i plain" }
    if ((& $o $c) -cne (& $w $c)) { "$i bash" }
}
"done"
"""

# Runs each copy of the hook once per command with the payload on a redirected stdin, and prints
# one line per copy: a 1 for a deny and a 0 for an allow, per command.
_VERDICT_DRIVER = r"""
param([string]$Scripts, [string]$Commands)
$ErrorActionPreference = 'Stop'
$cmds = @(Get-Content -Raw -Encoding utf8 $Commands | ConvertFrom-Json)
$inner = [Console]::In
$outer = [Console]::Out
foreach ($s in @(Get-Content -Raw $Scripts | ConvertFrom-Json)) {
    $line = [System.Text.StringBuilder]::new()
    foreach ($c in $cmds) {
        $payload = @{ tool_name = 'Bash'; tool_input = @{ command = [string]$c } } | ConvertTo-Json -Compress
        $sink = [System.IO.StringWriter]::new()
        [Console]::SetIn([System.IO.StringReader]::new($payload))
        [Console]::SetOut($sink)
        try { & $s *> $null } finally { [Console]::SetIn($inner); [Console]::SetOut($outer) }
        [void]$line.Append($(if ($sink.ToString().Contains('"deny"')) { '1' } else { '0' }))
    }
    $line.ToString()
}
"""


def _base_guard(tmp_path: Path, ref: str = _BASE_REF) -> Path:
    proc = subprocess.run(
        ["git", "show", f"{ref}:scripts/hooks/block-unbounded-fs-scan.ps1"],
        cwd=GUARD.parents[2],
        capture_output=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"{ref} is not readable here: {proc.stderr.decode(errors='replace').strip()}")
    base = tmp_path / "base-guard.ps1"
    base.write_bytes(proc.stdout)
    return base


def _run_driver(tmp_path: Path, driver: str, *args: str) -> list[str]:
    script = tmp_path / "driver.ps1"
    script.write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    assert proc.returncode == 0, f"driver exited {proc.returncode}: {proc.stderr}"
    return proc.stdout.splitlines()


def _corpus() -> list[str]:
    rows: list[str] = []
    for name in EXPECTED_ROW_COUNTS:
        for row in globals()[name]:
            rows.append(row.values[0] if hasattr(row, "values") else row)
    return rows


# The pieces the generated commands are built from: each opens, closes or changes a context the
# refined view reads, and the walk is what a deny needs.
_ATOMS = [
    "$((", "((", ") )", "))", ")", "(", '"', "'", "\\", "<<X", " <<X ", "\nX\n", "#", " # ",
    "${", "}", "$[", "]", "\n", " find /proc", "; find /proc", "$(", "`", " ", "a", ";", "$'",
    "1", " << ", "<<", "$", "|", "&&", '\\"', "$((cat <<X) )", "$((echo # c\n) )",
]  # fmt: skip
# Walks whose own operands hold a separator in quotes, which only a quote-aware view keeps whole.
_WALKS = [
    " find /proc", "; find /proc", "; grep -r 'a;b' /proc", "; grep -rn 'f(x)' /proc",
    "; find 'a;b' /proc -name x", "; grep -rE 'p|q' /",
]  # fmt: skip
_WRAPPERS = [
    ("$((", ") )"), ("$((", "))"), ("((", "))"), ("((", ") )"), ("$(", ")"), ('"$(', ')"'),
    ("${x:-", "}"), ("$(( ", " ))"), ("(", ")"), ("$[", "]"), ("`", "`"), ("'", "'"),
]  # fmt: skip


def _generated_commands(count: int = 2400, seed: int = 5607) -> list[str]:
    rng = random.Random(seed)
    out: list[str] = []
    while len(out) < count:
        depth = rng.randint(0, 60)
        if rng.random() < 0.5:
            body = "".join(rng.choice(_ATOMS) for _ in range(rng.randint(1, max(1, depth))))
        else:
            body = "".join(rng.choice(_ATOMS) for _ in range(rng.randint(0, 4)))
            for _ in range(depth):
                left, right = rng.choice(_WRAPPERS)
                pad = rng.choice(["", " ", "a ", " find /proc ", "'x' ", '"y" '])
                body = left + pad + body + rng.choice(["", " ", rng.choice(_WALKS)]) + right
        lead = rng.choice(
            ['echo "', "echo '", 'x="a"; ', "", 'echo "$(', "echo 'a'; ", 'echo \\" ']
        )
        tail = rng.choice(
            ['"', "'", ')"', "", '; echo "$((find /proc) )"', "\n" + rng.choice(_WALKS)]
        )
        command = lead + body + tail
        if "find" not in command:
            command += " find /proc"
        if '"' not in command and "'" not in command:
            command = "echo 'q'; " + command
        out.append(command)
    return out


def test_the_bash_and_plain_masks_match_origin_main_byte_for_byte(tmp_path: Path) -> None:
    base = _base_guard(tmp_path)
    commands = tmp_path / "commands.json"
    commands.write_text(json.dumps(_corpus() + _generated_commands()), encoding="utf-8")
    lines = _run_driver(tmp_path, _MASK_DRIVER, str(base), str(GUARD), str(commands))
    assert lines[-1:] == ["done"], lines[-5:]
    assert lines[:-1] == [], f"masks that moved: {lines[:20]}"


_VERDICT_CHUNKS = 8


# Split so the parts run in parallel, each well inside its timeout; together they cover every row.
@pytest.mark.timeout(600)
@pytest.mark.parametrize("chunk", range(_VERDICT_CHUNKS))
def test_every_command_origin_main_denies_is_still_denied(tmp_path: Path, chunk: int) -> None:
    base = _base_guard(tmp_path)
    corpus = (_corpus() + _generated_commands())[chunk::_VERDICT_CHUNKS]
    commands = tmp_path / "commands.json"
    commands.write_text(json.dumps(corpus), encoding="utf-8")
    scripts = tmp_path / "scripts.json"
    scripts.write_text(json.dumps([str(base), str(GUARD)]), encoding="utf-8")
    old, new = _run_driver(tmp_path, _VERDICT_DRIVER, str(scripts), str(commands))[-2:]
    assert len(old) == len(new) == len(corpus)
    # The floor: a run in which both copies failed open would compare nothing.
    assert old.count("1") > len(corpus) // 4, f"origin/main denied only {old.count('1')} commands"
    lost = [corpus[i] for i in range(len(corpus)) if old[i] == "1" and new[i] == "0"]
    assert lost == [], f"{len(lost)} commands origin/main denies are now allowed: {lost[:10]}"


# ============================================ the corpora must not quietly shrink


# A PARAMETRIZED LIST FAILS LOUDLY WHEN A ROW STOPS HOLDING AND SILENTLY WHEN A ROW IS DELETED.
# Deleting one is the cheapest way to make a weakened guard green again, and nothing else in this
# module would report it. So the counts are pinned: add a row and this number moves in the same
# edit, which is a reviewable line in the diff rather than an absence.
#
# EVERY CORPUS IS PINNED, not only the ones a later change added. MEASURED_FAIL_OPENS is the one
# that matters most -- every row in it was a real bypass someone drove -- and it was the list
# sitting unpinned when this test was first written for four others.
EXPECTED_ROW_COUNTS = {
    "FIND_DENY": 12,
    "GREP_DENY": 11,
    "WRAPPED_DENY": 8,
    "MEASURED_FAIL_OPENS": 8,
    "BOUNDED_ALLOW": 10,
    "MERE_MENTION_ALLOW": 10,
    "PRUNED_ALLOW": 4,
    "MEASURED_BYPASS_DENY": 5,
    "NORMALIZED_ROOT_DENY": 29,
    "OPTION_GRAMMAR_DENY": 12,
    "PRUNE_INERT_DENY": 9,
    "FOLDING_ALLOW": 20,
    "QUOTED_SUBSTITUTION_DENY": 15,
    "QUOTED_PROSE_ALLOW": 7,
    "POWERSHELL_QUOTE_DENY": 2,
    "TOGGLE_FLOOR_DENY": 5,
    "COMMENT_BOUNDARY_DENY": 6,
    "REFINED_READING_DENY": 13,
    "REFINED_FLOOR_DENY": 3,
    "REFINED_CONTROL_ALLOW": 2,
    "REFINED_FALSE_DENY_ALLOW": 14,
    "ONE_PASS_DENY": 5,
    "FALLBACK_DENY": 9,
    "FALLBACK_FIRES_DENY": 2,
    "FALLBACK_CONTROL_ALLOW": 6,
}


def test_every_corpus_is_the_size_it_was_measured_at() -> None:
    actual = {name: len(globals()[name]) for name in EXPECTED_ROW_COUNTS}
    assert actual == EXPECTED_ROW_COUNTS


# ================================================================== the guard must stay fail-open


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "not json at all", "{}", '{"tool_input": {}}', '{"tool_input": {"command": ""}}'],
)
def test_a_payload_the_guard_cannot_read_allows(raw: str) -> None:
    """A guardrail must never wedge all shell work. Anything unreadable passes silently."""
    assert_allowed(run_guard(raw))


# ================================================================== the wiring


# WIRING IS A PROPERTY OF settings.json, NOT OF THE SCRIPT, so the script does not claim it and
# this is where the claim can fail. A hook nothing references is a control that reads as enforced
# and is not -- the exact hole tests/test_claude_settings_contract.py was built to close after
# block-blanket-git-stage.ps1 sat wired-nowhere while eight tracked sites described it as live.
def test_the_guard_is_wired_for_the_shell_tools() -> None:
    # THE SETTINGS WALK COMES FROM THE CONTRACT MODULE, not from a second copy here. `_load` and
    # `_matchers_wiring` already flatten `hooks.<event>[].hooks[]`, read the args tokens, and treat
    # an absent `matcher` key as the documented match-all. Re-deriving that shape would mean a
    # settings-schema change gets fixed in one place while the copy here keeps passing over a shape
    # that no longer exists -- the vacuity class that module was built for.
    from tests.test_claude_settings_contract import _load, _matchers_wiring, matcher_selects

    matchers = _matchers_wiring(_load(), GUARD.name)
    assert matchers, f"{GUARD.name} is referenced by no handler in .claude/settings.json"
    for tool in ("Bash", "PowerShell"):
        assert any(matcher_selects(m, tool) for m in matchers), (
            f"no matcher wiring {GUARD.name} selects the {tool} tool, so the guard never runs on it"
        )


# THE ${CLAUDE_PROJECT_DIR} ANCHORING RULE IS NOT RESTATED HERE ON PURPOSE (CLAUDE.md section 11:
# state a load-bearing fact once and link to it). A bare `scripts/hooks/x.ps1` resolves against the
# session's cwd rather than the repo, so in a session started elsewhere the hook never launches and
# nothing reports it -- and
# tests/test_claude_settings_contract.py::test_every_hook_resolves_through_the_project_dir_placeholder
# already asserts the placeholder over EVERY hook reference in the file. This guard is covered the
# moment the matcher above names it. A per-script copy would be a second statement of one rule, kept
# in step with that module's `_PLACEHOLDER` by nothing.
