# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The SIGIL that introduces an interpreter flag, and the two other spelling axes measured beside it.

:mod:`tests.test_worktree_gate_interpreter_flags` replaced a hand-typed list of flag spellings with a
generating rule, and it was right to. It stopped one axis short. The rule it committed reads

    $psFlag = "[-/](?:$psPrefixes|encodedcommand)"

and ``[-/]`` is a HAND-TYPED TWO-MEMBER CLASS sitting inside a fix whose entire purpose was to stop
hand-typing enumerations -- the PREFIX was generated, the SIGIL beside it was not. BACKLOG #1097.

**Everything below was established by EXECUTION against the real binaries on this box** -- pwsh 7.6.4,
Windows PowerShell 5.1.26100.7462, Git Bash 5.2.37, cmd.exe on Windows 10.0.26200 -- never read off
documentation. Three separate gaps, on three different axes:

1. **SIGIL.** ``pwsh --command``, ``pwsh --Com`` and ``pwsh --c`` all run. The double dash is the
   ORDINARY POSIX spelling on the platform this repo targets, and it was not in the class. Neither were
   the three Unicode dashes PowerShell's argument parser accepts as dash-equivalents: U+2013 (en dash),
   U+2014 (em dash) and U+2015 (horizontal bar) all bind the parameter, singly on both hosts and
   DOUBLED on pwsh. So the measured sigil set is five characters and two lengths, not two characters
   and one.
2. **A SECOND PARAMETER, whose name is not a prefix of "command".** ``pwsh -h`` lists
   ``-CommandWithArgs | -cwa``. ``-cwa``, ``-CWA`` and the full ``-CommandWithArgs`` each run arbitrary
   code, and NONE of them is matched by a prefix-of-``command`` rule: ``-Command`` matches only when
   whitespace follows, and ``-CommandWithArgs`` continues with ``W``. A generated prefix family cannot
   generate a parameter it was never told about, which is why this file pins the parameter SET as well
   as the spelling of one member.
3. **SEPARATOR.** cmd.exe does not require whitespace before its argument: ``cmd /c"echo ran"`` and
   ``cmd /cecho ran`` both run. PowerShell and a POSIX shell DO require it (``-Command:x``,
   ``-Command=x``, ``-CommandWrite-Output`` and ``bash -cecho`` were each measured to refuse), so the
   mandatory ``\\s+`` stays on those two branches and is relaxed on cmd's alone.

**The bound is unchanged and is what keeps this from being a widening.** ``-Cm``, ``-Cmd``, ``-Cnd`` and
``-Comd`` are refused by pwsh under EVERY one of the five sigils and both lengths (measured, 20 cases),
so the mandatory whitespace-then-quote after the flag still does the work, and
:func:`test_the_prefix_family_is_bounded_under_every_sigil` pins it. Two further negatives bound the two
new axes: a run of THREE or more sigil characters is refused, as is a MIXED pair (a hyphen then an en dash),
and the ``-cwa`` alias is exact -- ``-cw``, ``-cwar`` and ``-CommandWithArg`` all refuse.

**Measured against the gate with #1097's first commit (545f536b) applied and before this one**: this
file was 96 failed / 71 passed, and 243 passed afterwards alongside
:mod:`tests.test_worktree_gate_interpreter_flags`, whose 76 are unchanged. Every one of the 96 was a
live ALLOW on a command that resets the shared primary's working tree, disarms ``core.hooksPath`` for
every worktree at once, or hijacks another session's checkout -- 49 sigil-by-prefix spellings, 16
``CommandWithArgs`` spellings, 7 single-quoted, 6 cmd separator, 5 case, and 13 spread across the three
rules that ride the same scan. NOT ONE bounded-ness assertion in this file moved in that run: they pass
before AND after, which is what makes them a bound rather than a restatement of the fix.

**What this file does NOT claim.** Not that every spelling is now covered -- at least these, each
established by execution. The residuals are recorded in the gate beside the rule; the one this audit
ADDED to that list is ``powershell "<script>"`` with NO FLAG AT ALL, which Windows PowerShell 5.1 runs
(pwsh 7 does not -- it treats a bare argument as a file). That is not a flag-spelling gap and no flag
matcher closes it: it needs a matcher keyed on the interpreter's NAME, which is a different rule with a
different false-deny profile, so it is stated rather than half-fixed here.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

PAYLOAD = "git reset --hard"

# Written as escapes, not literals, so this file stays pure ASCII: CLAUDE.md section 11 requires every
# added non-ASCII character to survive cp1252, and U+2015 does not encode there at all. The gate's own
# pattern spells them the same way and for the same reason.
EN_DASH = "\u2013"
EM_DASH = "\u2014"
H_BAR = "\u2015"

# The sigils that BIND, generated from the two measured facts rather than typed as a list of seven:
# a dash-family character may be single or DOUBLED (same character both times), a slash may not.
DASHES = ["-", EN_DASH, EM_DASH, H_BAR]
BINDING_SIGILS = [*DASHES, *[d * 2 for d in DASHES], "/"]

# The sigils #1097's first commit already carried. Subtracting them leaves exactly the new coverage, so
# this file cannot quietly re-assert what was already true.
NEW_SIGILS = [s for s in BINDING_SIGILS if s not in ("-", "/")]

COMMAND_PREFIXES = ["Command"[:n] for n in range(1, len("Command") + 1)]


def shell(command: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def nested(primary: Path) -> Path:
    """A first-party worktree, where ``../../..`` IS the primary -- the natural relative spelling."""
    return primary / ".claude" / "worktrees" / "wt-1"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


# ------------------------------------------------------------------------------ axis 1: the sigil


@pytest.mark.parametrize("sigil", NEW_SIGILS)
@pytest.mark.parametrize("prefix", COMMAND_PREFIXES)
def test_every_sigil_that_binds_the_command_parameter_is_recognised(
    primary: Path, repos_file: Path, sigil: str, prefix: str
) -> None:
    """The generated PREFIX family crossed with the generated SIGIL family -- 49 spellings, every one
    measured to run, none of which the previous rule matched.

    This is the same argument the prefix fix made, one axis over. A matcher that generates ``-C``
    through ``-Command`` and then hard-codes ``[-/]`` beside it has not stopped enumerating, it has
    moved the enumeration one token to the left."""
    command = f'pwsh -NoProfile {sigil}{prefix} "{PAYLOAD}"'
    reason = assert_denied(run_gate(shell(command, cwd=primary), repos_file))
    assert "SHARED PRIMARY" in reason


@pytest.mark.parametrize("sigil", NEW_SIGILS)
def test_the_new_sigils_are_recognised_under_either_quote(
    primary: Path, repos_file: Path, sigil: str
) -> None:
    """Single quotes are this repo's house idiom. The old ``/c`` pattern accepted double quotes only,
    so a verdict once turned on the quote character rather than on what ran; a new sigil family must
    not reintroduce that asymmetry on the other side."""
    assert_denied(run_gate(shell(f"pwsh {sigil}Com '{PAYLOAD}'", cwd=primary), repos_file))


@pytest.mark.parametrize("flag", ["--command", "--COMMAND", "--CoMmAnD", "--c", "--COM"])
def test_the_double_dash_is_recognised_whatever_its_case(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """``--`` is the ordinary long-option spelling on this platform, so it is the sigil a model reaches
    for by habit rather than by intent. Case-insensitivity was already fixed for ``-`` and ``/``; it has
    to hold on every member of the class or the fix is one spelling deep."""
    assert_denied(run_gate(shell(f'pwsh -NoProfile {flag} "{PAYLOAD}"', cwd=primary), repos_file))


# -------------------------------------------------------- axis 2: a second command-taking parameter


@pytest.mark.parametrize("word", ["cwa", "CWA", "CommandWithArgs", "commandwithargs"])
@pytest.mark.parametrize("sigil", ["-", "--", "/", EN_DASH])
def test_the_command_with_args_parameter_is_an_interpreter_flag(
    primary: Path, repos_file: Path, sigil: str, word: str
) -> None:
    """``pwsh -h`` lists ``-CommandWithArgs | -cwa`` beside ``-Command | -c``, and all 16 spellings here
    were measured to run arbitrary code.

    A prefix-of-``command`` rule cannot reach any of them, and that is a fact about GENERATION, not
    about this particular parameter: a rule that generates spellings of a name it was told about is
    still blind to a name nobody told it. So the gate now carries the command-taking parameter SET, and
    this test pins membership rather than one spelling of one member."""
    command = f'pwsh -NoProfile {sigil}{word} "{PAYLOAD}"'
    reason = assert_denied(run_gate(shell(command, cwd=primary), repos_file))
    assert "SHARED PRIMARY" in reason


# ------------------------------------------------------------------------- axis 3: the separator


@pytest.mark.parametrize("flag", ["/c", "/C", "/k", "/K", "/Q/C", "/V:ON/C"])
def test_a_cmd_switch_does_not_need_whitespace_before_its_argument(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """``cmd /c"git reset --hard"`` runs. Measured on cmd.exe: ``/c"echo ran"`` and ``/cecho ran`` both
    execute, so the whitespace this gate required was a PowerShell fact applied to a host that does not
    share it.

    The relaxation is scoped to the cmd branch alone. PowerShell and a POSIX shell were each measured to
    REFUSE the attached form -- ``-CommandWrite-Output ran``, ``-Command:x``, ``-Command=x`` and
    ``bash -cecho ran`` all decline -- so their mandatory ``\\s+``, which is what refuses ``-Comd``,
    is untouched. :func:`test_relaxing_the_cmd_separator_does_not_relax_the_prefix_bound` pins the
    separation from the other side."""
    assert_denied(run_gate(shell(f'cmd {flag}"{PAYLOAD}"', cwd=primary), repos_file))


# ------------------------------------------------- the recursion feeds every rule, not just rule 3


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A real governed primary + a linked worktree + a free branch to hijack onto."""
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")

    def git(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
        )

    primary = tmp_path / "Primary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "seed.txt", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    git("branch", "claude/other-branch", cwd=primary)
    wt = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, other="claude/other-branch")


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
@pytest.mark.parametrize("flag", ["--Com", "--command", f"{EN_DASH}Com", "-cwa", "--cwa"])
def test_a_new_spelling_does_not_hide_a_shared_config_disarm(
    repo: SimpleNamespace, flag: str
) -> None:
    """The severe one, and the item's own sentence: whatever a session may not do directly, it could do
    inside a wrapper the matcher does not carry. Rule 3c refuses a ``core.hooksPath`` repoint because it
    turns off the ledger, claim and secret-leak commit gates for EVERY worktree at once -- and each
    spelling here made that refusal skippable by typing one extra dash or three different letters."""
    command = f'pwsh {flag} "git config core.hooksPath /dev/null"'
    reason = assert_denied(run_gate(shell(command, cwd=repo.primary), repo.repos))
    assert "core.hookspath" in reason.lower()


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
@pytest.mark.parametrize("flag", ["--Com", f"{EM_DASH}c", "-cwa"])
def test_a_new_spelling_does_not_hide_a_worktree_hijack(repo: SimpleNamespace, flag: str) -> None:
    """Rule 3b rides the same scan, so an unrecognised wrapper disarmed it too: a session could pull
    another session's worktree onto its branch by spelling the flag with one more dash."""
    command = f'pwsh {flag} "git checkout {repo.other}"'
    reason = assert_denied(run_gate(shell(command, cwd=repo.wt), repo.repos))
    assert "LINKED WORKTREE" in reason


@pytest.mark.parametrize(
    "flag", ["--Com", "--command", f"{EN_DASH}Command", f"{H_BAR}{H_BAR}c", "-cwa", "-Command"]
)
def test_a_new_spelling_does_not_hide_a_relative_cd_to_the_primary(
    nested: Path, repos_file: Path, flag: str
) -> None:
    """The two defects COMPOSE. ``../../..`` from a nested worktree IS the primary -- that is simply how
    a session names the repo root, and BACKLOG #1061 was the work of teaching the resolver to see it.
    Wrapping it in a flag the matcher does not carry puts it straight back out of reach. The last entry
    is ``-Command``, which denied before this change: it is the control, so a green here is a
    subtraction rather than a claim about the harness."""
    command = f'pwsh {flag} "cd ../../.. && git reset --hard"'
    reason = assert_denied(run_gate(shell(command, cwd=nested), repos_file))
    assert "SHARED PRIMARY" in reason


# ------------------------------------------------ the bounds: what a wider matcher must NOT refuse


@pytest.mark.parametrize("sigil", BINDING_SIGILS)
@pytest.mark.parametrize("flag", ["Cm", "Cmd", "Cnd", "Comd"])
def test_the_prefix_family_is_bounded_under_every_sigil(
    primary: Path, repos_file: Path, sigil: str, flag: str
) -> None:
    """The negative that keeps the fix honest, and it must stay ALLOW -- now crossed with the widened
    sigil, because a bound proved under ``-`` says nothing about ``--`` or a doubled en dash.

    Measured on all 36 combinations: pwsh REFUSES every one ("not recognized as the name of a script
    file"), so the command runs nothing and there is nothing to deny. A matcher spelled
    ``<sigil>C[a-z]*`` would deny all of them, read as more thorough, and have stopped describing the
    family. The mandatory whitespace-then-quote after the flag is what refuses them, and widening the
    sigil must not touch it."""
    assert (
        run_gate(shell(f'pwsh -NoProfile {sigil}{flag} "{PAYLOAD}"', cwd=primary), repos_file)
        is None
    )


@pytest.mark.parametrize(
    "sigil",
    [
        "---",
        "----",
        f"{EN_DASH * 3}",
        f"{EM_DASH * 4}",
        # NOTE `//` IS DELIBERATELY ABSENT -- see the docstring. `///` stays because it was measured
        # not to run: `pwsh ///Command "<code>"` through Git Bash does nothing.
        "///",
        f"-{EN_DASH}",
        f"{EN_DASH}-",
        f"{EN_DASH}{EM_DASH}",
        "-/",
        "/-",
    ],
)
def test_the_sigil_run_is_bounded(primary: Path, repos_file: Path, sigil: str) -> None:
    """THE FALSE-DENY DIRECTION FOR THIS CHANGE, and no bypass test can surface it.

    Measured: a run of THREE or more sigil characters is refused by both hosts, and a MIXED pair is
    refused even when both halves are individually binding. So the sigil is "a dash-family character,
    optionally doubled with ITSELF, or one slash" -- which is why the gate spells it with a
    backreference rather than ``{1,2}``.

    Both widenings were RUN, not argued: replacing the backreference with ``{1,2}`` reddens exactly the
    3 dash-family mixed pairs here and nothing else in the suite, and replacing it with ``+`` over a
    class including the slash reddens the remaining rows and nothing else. Each reads as the more
    thorough matcher and each describes a family that does not exist.

    ``//`` WAS REMOVED FROM THIS LIST, and the removal is the point. It was here on the ground that "a
    slash never doubles" -- true of a pwsh spawned FROM a PowerShell parent, and FALSE of the delivery
    path this hook actually governs. A Bash tool call goes through Git Bash, which applies MSYS argument
    conversion before the child ever sees the string. Measured with an argv printer through Git Bash
    5.2.37::

        typed  /c         -> child receives  C:/                          does NOT run
        typed  //c        -> child receives  /c                           RUNS
        typed  /Command   -> child receives  C:/Program Files/Git/Command  does NOT run
        typed  //Command  -> child receives  /Command                     RUNS
        typed  ///Command -> child receives  //Command                    does NOT run

    So the slash sigil is INVERTED for this path: the gate DENIES ``/Command``, which cannot run, and
    ALLOWS ``//Command``, ``//c`` and ``//Com``, which do. Asserting ``//`` as a must-ALLOW made that
    inversion a REQUIREMENT -- a new permit in a security test is a specification change wearing the
    clothes of coverage, and it would have forced a later fix to delete a green test.

    The BYPASS itself is inherited from the previous matcher and is unchanged by this commit, so it is
    disclosed rather than closed here: see the residual list in ``Get-ScannableSegments``. Closing it
    means matching a leading ``//``, which opens a UNC-shaped false-deny surface (``ls //server/share/c
    "..."``) that needs its own measurement -- a separate change with a separate risk profile, not a
    line to slip into this one.

    ``///`` STAYS, because ``pwsh ///Command`` and ``pwsh ////Command`` were both measured on the same
    path NOT to run. That is a statement about PWSH and this row drives pwsh, so the row is right --
    but do not read it as a fact about the sigil, because cmd.exe differs: ``cmd //c`` and
    ``cmd ////c`` RUN while ``cmd /c`` and ``cmd ///c`` do not. Those cmd spellings are ALLOWed here
    and on the matcher this replaces, and they are recorded in the gate's residual list.

    The table assumes DEFAULT MSYS path conversion. Under ``MSYS_NO_PATHCONV=1`` or
    ``MSYS2_ARG_CONV_EXCL='*'`` it inverts back; both were verified unset on this box, and neither
    the removal of ``//`` nor the keeping of ``///`` changes under either configuration.

    Removing the row left NO coverage of ``//`` in either direction, so
    :func:`test_the_double_slash_sigil_is_a_known_open_residual` below replaces it as a tripwire."""
    assert (
        run_gate(shell(f'pwsh -NoProfile {sigil}Command "{PAYLOAD}"', cwd=primary), repos_file)
        is None
    )


@pytest.mark.parametrize("flag", ["-cw", "-cwar", "-cwaa", "-CommandWithArg", "-CommandWithArgss"])
def test_the_command_with_args_alias_is_exact(primary: Path, repos_file: Path, flag: str) -> None:
    """The bound for axis 2, and it must stay ALLOW. ``-cwa`` binds as an exact ALIAS, not as a prefix
    family: measured, ``-cw`` is one character short and refuses, ``-cwar`` is one over and refuses, and
    every prefix of ``CommandWithArgs`` between ``-Command`` and the full name refuses too. Adding the
    parameter to the set must therefore add two literals, never a second generated prefix ladder --
    which would sweep in ``-cw`` and, through it, any two-letter flag starting with c."""
    assert run_gate(shell(f'pwsh -NoProfile {flag} "{PAYLOAD}"', cwd=primary), repos_file) is None


@pytest.mark.parametrize(
    "command",
    [
        'pwsh -NoProfile -Com"git reset --hard"',
        'pwsh -NoProfile -Command"git reset --hard"',
        'pwsh -NoProfile --c"git reset --hard"',
        f'pwsh -NoProfile {EN_DASH}Command"git reset --hard"',
        'pwsh -NoProfile -cwa"git reset --hard"',
        'bash -c"git reset --hard"',
        'bash -xc"git reset --hard"',
    ],
)
def test_the_separator_relaxation_is_scoped_to_cmd(
    primary: Path, repos_file: Path, command: str
) -> None:
    """THE BOUND FOR AXIS 3, and it must stay ALLOW.

    **This is a NEW MUST-ALLOW SET, i.e. a specification change, so here is why permitting it is safe:
    none of these commands RUNS ANYTHING.** Driven through a real shell so the argv is what a shell
    actually produces (the quotes vanish, leaving one token ``<flag><script>``): pwsh exits 64 on every
    spelling above -- "The argument '-ComWrite-Output ran' is not recognized as the name of a script
    file" -- and bash exits 1 with "invalid option". The spaced controls run, and they DENY, and this
    file asserts that separately. So the gate is refusing to act on a command the host refuses to
    execute; there is no reachable behaviour behind these strings to protect.

    **And it is the only probe that catches the over-broad edit.** An earlier version of this bound used
    ``pwsh -Comd"..."`` and was measured to be a NO-OP: relaxing ``\\s+`` to ``\\s*`` across ALL THREE
    branches left the whole suite green, because the quote in ``-Comd"`` does not sit immediately after
    any prefix of ``command``. The attached form above does, so the across-the-board relaxation now
    reddens 7 rows here while the committed per-host split -- ``\\s+`` for PowerShell and a POSIX shell,
    ``\\s*`` for cmd alone -- keeps them all green. A bound that cannot fail is not a bound, and this one
    was replaced rather than kept because it read like one."""
    assert run_gate(shell(command, cwd=primary), repos_file) is None


@pytest.mark.parametrize(
    "command",
    [
        # A REAL long option beginning with 'c'. This is the whole false-deny surface the double-dash
        # sigil could have opened, and the mandatory whitespace-then-quote is what closes it: the
        # matcher gets as far as `--c` and then needs a space, but finds `olor`/`onfig`/`acert`.
        'grep --color "git checkout main" notes.txt',
        'grep --count "git checkout main" notes.txt',
        'docker --config "/tmp/dockercfg" ps',
        'curl --cacert "/etc/ssl/ca.pem" https://example.invalid',
        'cmake --build "." --config "Release"',
        'sort --check "git checkout main"',
        # An en dash inside ordinary prose, which is where a Unicode dash actually turns up.
        f'git commit -m "perf: cut latency 5{EN_DASH}10 ms"',
        f'echo "sprint 3 {EM_DASH} git checkout was discussed"',
        # A POSIX path whose last component is `c`, adjacent to a quoted span WITH NO GIT TOKEN. Kept
        # only as the CONTROL for test_the_relaxed_cmd_separator_costs_a_posix_path_false_deny below --
        # on its own it proves nothing, because a line with no git token cannot deny under any width of
        # $cmdExeFlag. It used to sit here labelled "the shape the relaxed cmd separator has to
        # survive", which is a bound that cannot fail.
        'ls /usr/src/c "some file.txt"',
        # The SAME payload as the pinned false deny below, behind a path that does NOT end in `c`.
        # What varies from that row is the PATH, which is what isolates the trigger to the `/c`
        # ending. (The row above varies the PAYLOAD instead, and on its own is vacuous.)
        'ls /usr/src/lib "git checkout main"',
        # Already-paid-for false positives, re-asserted against the wider matcher.
        'ssh box "git checkout main"',
        'git commit -m "chore: clean up dead code"',
        'tar -C "/tmp/x" -xf archive.tar',
    ],
)
def test_the_widened_matcher_does_not_create_false_denies(
    primary: Path, repos_file: Path, command: str
) -> None:
    """Measured rather than assumed, and every one of these was checked to still ALLOW.

    Recursion only ADDS a scan line, and a line still needs a git token AND a gated verb to deny -- so
    a path or a certificate behind a family-shaped flag changes no verdict. The rows that matter are the
    first six: each is a genuine long option starting with ``c``, i.e. exactly what a hand-typed
    ``[-/]`` was implicitly protecting against, and each is refused by the ``\\s+`` bound instead."""
    assert run_gate(shell(command, cwd=primary), repos_file) is None


@pytest.mark.parametrize("spelling", ["//Command", "//c", "//Com", "//cwa"])
def test_the_double_slash_sigil_is_a_known_open_residual(
    primary: Path, repos_file: Path, spelling: str
) -> None:
    """A TRIPWIRE OVER AN OPEN BYPASS. It asserts ALLOW, and that is NOT an endorsement -- read this
    before you conclude the row blesses the hole, because the distinction is the whole point.

    A must-ALLOW row that asserts a spelling is SAFE is a specification change wearing the clothes of
    coverage; that is why the ``//`` row was deleted from
    :func:`test_the_sigil_run_is_bounded`. But deleting it left ZERO coverage of ``//`` anywhere in
    the repo, in EITHER direction -- proven, not argued: under a minimal ``//?`` sigil closure the
    three gate suites stay entirely green, so the suite can see this bypass neither open nor closed.
    Silence is not disclosure.

    So this row exists to make the residual FAIL-VISIBLE. Each spelling below was measured to EXECUTE
    through Git Bash, because MSYS argument conversion delivers ``//Command`` to the child as
    ``-Command``'s slash form while ``/Command`` arrives as a path and does nothing::

        typed  //c        -> child gets  /c        RUNS
        typed  //Command  -> child gets  /Command  RUNS
        typed  /c         -> child gets  C:/       does NOT run

    The gate ALLOWs all of them today, and so did the matcher this change replaced -- the exposure is
    INHERITED and UNCHANGED, which is why it is disclosed here rather than closed inside a commit
    whose subject is something else.

    WHEN THIS TEST REDS, that is the SUCCESS signal, not a regression: somebody closed the bypass.
    Delete this test and the residual note in ``Get-ScannableSegments``; do not restore the ALLOW.
    The measured cost of closing is narrow -- a bare ``//c``/``//com``/``//command``/``//cwa`` token
    before a quoted span. It is NOT the UNC-shaped surface an earlier version of that note claimed;
    ``ls //server/share/c "..."`` matches under neither sigil, because ``(?:^|\\s)`` anchors before
    the first slash."""
    assert (
        run_gate(shell(f'pwsh -NoProfile {spelling} "{PAYLOAD}"', cwd=primary), repos_file) is None
    ), (
        f"{spelling} now DENIES. If you closed the double-slash sigil deliberately, that is the "
        "intended outcome -- delete this test and the residual note in Get-ScannableSegments. Do "
        "NOT restore the ALLOW to make this pass."
    )


def test_the_cmd_switch_cluster_prefix_costs_a_posix_path_false_deny(
    primary: Path, repos_file: Path
) -> None:
    """A DISCLOSED COST OF THIS CHANGE, pinned so it cannot be lost, and NOT an endorsement.

    THE CAUSE IS THE CLUSTER PREFIX, NOT THE SEPARATOR. This test was first written as
    ``test_the_relaxed_cmd_separator_costs_...`` and that name, and the four places that repeated it,
    were WRONG -- caught by an adversarial re-read of the commit that introduced them. ``$cmdExeFlag``
    is ``(?:/[^/\\s]+)*/[ck]``. The leading ``(?:/[^/\\s]+)*`` was added so cmd's CONCATENATED switch
    runs (``/Q/C``, ``/V:ON/C``) are recognised, and it is that prefix which lets an ordinary POSIX
    path walk into the matcher: ``/usr`` then ``/src`` then ``/c``. Rebuilt the pattern and measured
    the row directly::

        cluster prefix + \\s*   -> MATCH, captures `git checkout main`
        cluster prefix + \\s+   -> MATCH, captures `git checkout main`     <-- separator irrelevant
        no cluster     + \\s*   -> no match
        no cluster     + \\s+   -> no match

    The line has a literal space before the quote, so the ``\\s*`` relaxation was never involved. It
    was blamed because it was the newest thing nearby -- the same mistake as the separator claim this
    lane corrected one commit earlier, made while correcting it.

    A POSIX path whose last component is ``c`` matches that shape, so a quoted span after it is
    recursed into as if it were cmd's command argument. Measured against both gates::

        ls /usr/src/c   "some file.txt"      main ALLOW   this build ALLOW    (no git token: vacuous)
        ls /usr/src/c   "git checkout main"  main ALLOW   this build DENY     <-- the new false deny
        ls /usr/src/lib "git checkout main"  main ALLOW   this build ALLOW    (control: the `/c` ending
                                                                              is the trigger, not the path)

    THIS TEST ASSERTS THE DENY, which is a deliberate and uncomfortable choice, so read why. The row it
    replaced asserted ALLOW on a payload with no git token -- green under any matcher, including one
    widened to match everything. A guard that cannot fail is not a guard, and this file's own
    neighbouring docstring congratulates itself for removing exactly that defect elsewhere.

    So the choice was between deleting the row (losing the record) and pinning the real behaviour. It is
    pinned. A false DENY is a cost, not a hole: it stops legitimate work rather than admitting illegitimate
    work, and the rule-3 direction that matters -- DENY becoming ALLOW -- is unaffected. If someone later
    narrows ``$cmdExeFlag`` so this ALLOWs again, this test reds, and that is the intended signal to come
    and read this docstring rather than a regression to paper over.

    DECIDED, AND THE DECISION REVERSED THE PREMISE. This docstring previously said the narrowing that
    works is "require a cmd-like PROGRAM token before the switch run". That was MEASURED FALSE and is
    corrected here, because it is the sentence a future reader would act on.

    THE CLUSTER PREFIX IS NOT THE SLOPPY PART. cmd.exe itself accepts arbitrary ``/junk`` components
    in a switch run and then executes the quoted payload. Driven against the real binary with a
    payload that COMPUTES its answer (``set /a 111*3`` -> 333, so an echo-back cannot be mistaken for
    a run), with controls in the same batch -- ``cmd /c`` must run, ``cmdd /c`` must not::

        cmd /usr/src/c  "<payload>"   RUNS        cmd /zzz/c      "<payload>"  RUNS  (z is no switch)
        cmd /mnt/c      "<payload>"   RUNS        cmd /usr/lib/k  "<payload>"  RUNS
        cmd /a:/c       "<payload>"   RUNS        cmd /d /usr/src/c "<p>"      RUNS

    ``/usr`` binds as ``/U``, ``/src`` as ``/S``, ``/zzz`` is ignored. So ``(?:/[^/\\s]+)*/[ck]`` is
    very nearly EXACTLY the family cmd accepts, and dropping it would lose real coverage rather than
    trim an over-match.

    SO THIS IS A PROGRAM-IDENTITY PROBLEM, and it is not solvable at this layer. The only thing
    separating ``ls /usr/src/c "..."`` from ``cmd /usr/src/c "..."`` is the program token -- but every
    program-token spelling tried was defeated by something that EXECUTES: ``echo hi;cmd /k`` and
    ``(cmd /mnt/c`` (neither ``;`` nor ``(`` is whitespace, and the outer ``(?:^|\\s)`` anchor sits
    before the whole alternation), an alias, a renamed copy of cmd.exe, and ``cmd /d /Q/C`` where the
    program is not adjacent to the switch run. Five candidates were built and driven as real gate
    mutants; each traded this one disclosed false deny for four or more measured DENY-to-ALLOW
    regressions on shapes that run.

    The false deny is therefore KEPT. At this rule's threat model the two directions are not
    symmetric: a false DENY stops legitimate work loudly and has a workaround, while a false ALLOW
    lets a reset land in the shared primary silently.

    AND ONE NON-REMEDY, RECORDED SO NOBODY REACHES FOR IT: dropping the ``\\s*`` relaxation does NOT
    remove this false deny (see the table above -- it matches under ``\\s+`` too) and it REGRESSES
    ``cmd /c"git checkout main"`` from DENY to ALLOW, because the attached form is exactly what
    ``\\s*`` exists to catch. That advice was printed here in the first version of this docstring. It
    would have cost a real DENY-to-ALLOW and bought nothing."""
    reason = assert_denied(
        run_gate(shell('ls /usr/src/c "git checkout main"', cwd=primary), repos_file)
    )
    # ATTRIBUTE the deny, do not merely count it. Asserting "something denied" would keep this
    # tripwire green if some future unrelated rule denied the same string, and it would then hold
    # green straight through a $cmdExeFlag narrowing -- the tripwire silently measuring nothing.
    # Today the deny is fully attributable: removing the cluster prefix ALLOWs this outright.
    assert "checkout" in reason, (
        "the POSIX-path false deny is still a deny, but no longer for the gated verb -- so this "
        f"tripwire is no longer measuring the cluster-prefix path. Reason was: {reason}"
    )
    # The control: the same payload behind a path NOT ending in `c` must still ALLOW, or the cause is
    # something wider than the cmd branch and this test is measuring the wrong thing.
    assert run_gate(shell('ls /usr/src/lib "git checkout main"', cwd=primary), repos_file) is None


def test_a_context_flag_with_a_count_is_still_not_an_interpreter_flag(
    primary: Path, repos_file: Path
) -> None:
    """``grep -C 3 "git checkout main"`` takes a COUNT before its pattern, so the quoted span is not that
    flag's argument -- and ``--context`` is the same flag spelled long, which the widened sigil now
    reaches. Both stay ALLOW for the same reason ``-Comd`` does: the quote is not adjacent."""
    assert run_gate(shell('grep -C 3 "git checkout main" f', cwd=primary), repos_file) is None
    assert (
        run_gate(shell('grep --context 3 "git checkout main" f', cwd=primary), repos_file) is None
    )
