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
import shutil
import subprocess
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
    "FOLDING_ALLOW": 18,
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
