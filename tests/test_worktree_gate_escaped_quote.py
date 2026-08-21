# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Escape-blind span scanning let a gated git command hide from every rule (BACKLOG #1229 residual).

Two fail-opens, one root cause, and it is the same sentence this gate has already written twice:
**whichever quote opens first owns the span, and nothing that cannot decide ownership may blank text.**

**ONE -- A BACKSLASH-ESCAPED QUOTE IS A SHELL LITERAL, AND THE SCAN READ IT AS AN OPENER.** In sh,
``\\"`` is an ordinary character; the command around it RUNS. ``Remove-QuotedSpans`` resolved quote
OWNERSHIP correctly and ignored ESCAPING entirely, so it paired two escaped quotes across a live
command and deleted the middle. No rule ever saw it.

**IT IS RULE-AGNOSTIC, WHICH IS WHY THE COVERAGE HERE IS WIDER THAN THE ORIGINAL STRADDLE'S.** This is
not a checkout bug -- it is a SCANNER bug that disarms whatever rule sits behind it. Measured on the
shipped hook before the fix: the same shape hid ``checkout`` (rule 3) and ``reset --hard`` (rule 3, DESTRUCTIVE) alike. A suite that
pinned only the checkout case would go green over the destructive one.

**TWO -- THE QUOTED-PROGRAM-PATH COLLAPSE WAS TWO ORDERED REGEXES RUN BEFORE THE SCAN**, double quotes
first, which is the *exact* shape the scan replaced. It could pair a quote with a distant ``/git"``
ACROSS a gated command and rewrite the whole middle to a bare token -- verb and arguments gone. Both
are now decided inside the single left-to-right pass, on spans it already owns.

**PRE-EXISTING, NOT A REGRESSION.** Both shapes ALLOW on the pre-fix blob too. This suite is the first
thing in the repository that can see either: measured across all 13 ``test_worktree_gate*`` modules
before it, ZERO carried a backslash-escaped-quote case (positive control: the token ``escap`` appears
in four of them, every hit unrelated).

**WHY THE PAYLOADS ARE HERE IN A PUBLIC FILE, since that was a real question and not an oversight.**
Owner-ruled 2026-08-20: pin it publicly. A gate that refuses a class needs a real offender to prove it
refuses it -- an anti-vacuity control cannot be written from a description -- and this repo already
ships that shape deliberately (``tests/test_cp1252_console_safety.py`` builds a synthetic offender;
``scan_forbidden.py`` commits one it recognises without it being usable). The non-reusable variant was
designed first and does not reach here: the scanner is a PowerShell function with no importable
surface, and all 13 sibling suites drive the hook end-to-end through this same subprocess harness.
Inventing a second, unprecedented test path for a security gate to avoid a construct the owner already
authorised would be the worse trade.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

# Built by concatenation, matching the sibling straddle suite: a test about quote handling must not
# depend on how this file's own literals nest. The escape is spelled once, here, for the same reason.
DQ = '"'
SQ = "'"
ESC_DQ = "\\" + DQ  # a BACKSLASH then a quote -- one shell literal, not a span opener
ESC_SQ = "\\" + SQ


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


def shell(command: str, cwd: Path) -> dict[str, object]:
    """A Bash tool payload, matching the sibling suites' harness."""
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd)}


# THE VERB SET IS THE POINT OF THIS PARAMETRISATION, not thoroughness for its own sake. The defect is
# in the SCANNER, so it disarms every rule equally; pinning one verb would leave the suite green while
# the destructive arm stayed open.
#
# ***BUT THIS SUITE DOES NOT ACTUALLY COVER MORE THAN ONE RULE, AND AN EARLIER VERSION OF THIS COMMENT
# CLAIMED IT DID. MEASURED, WHICH IS THE ONLY REASON I KNOW:*** both verbs are denied by the SAME rule
# -- each returns "would change the working tree of the SHARED PRIMARY checkout". Two verbs, one rule.
# The defect is rule-AGNOSTIC, so the coverage that would actually pin that property has to exercise
# DIFFERENT RULES, and this file exercises one.
#
# **AND "DENIED" IS A WEAKER CLAIM THAN "DENIED BY THE RULE WE THINK."** A suite that asserts only that
# a deny happened cannot tell a rule-agnostic scanner fix from a lucky overlap in one rule's matching.
# The stronger form -- reading back the rule ids the gate RECORDS and asserting they are distinct --
# was built independently on another lane and is the right home for that coverage; this file should
# not grow a second, thinner version of it. Cross-checked there: 10 of its 11 rows pass against this
# gate unchanged.
#
# Left as-is deliberately rather than widened here, and the over-claim corrected in place rather than
# deleted, because the gap is real and a reader who saw only the fixed comment could not tell this
# suite had ever asserted coverage it does not have.
#
# `worktree add` WAS IN THIS LIST AND WAS REMOVED, WHICH IS WORTH RECORDING RATHER THAN TIDYING AWAY.
# A report reached me claiming the escape hid it, so it went in as a third case and FAILED. The
# discriminating probe is the one that settles it -- run the same command WITH and WITHOUT the escape:
#     git -C <governed> worktree add ../x main                    -> ALLOW
#     echo \" ; git -C <governed> worktree add ../x main ; echo \" -> ALLOW
# It allows either way, so the escape hides nothing there and the case proved nothing about this fix.
# The cause is stated in this file's own rule-3b resolver comment: 3b handles checkout/switch only.
# KEEPING THE FAILING CASE WOULD HAVE PRESSURED THE NEXT READER TO WIDEN A SECURITY GATE UNTIL A TEST
# BUILT ON A FALSE PREMISE WENT GREEN. Whether `worktree add` SHOULD be governed is a real question and
# a separate one; it is not evidence about escape handling and must not be smuggled in as such.
@pytest.mark.parametrize(
    "verb",
    [
        "checkout main",  # rule 3 -- the shape the original straddle used
        "reset --hard",  # rule 3, DESTRUCTIVE
    ],
)
def test_an_escaped_quote_does_not_hide_a_gated_command(
    primary: Path, repos_file: Path, verb: str
) -> None:
    """The gated command sits between two ESCAPED quotes and must still be seen.

    Before the fix both ALLOWed. The escapes are literals to the shell, so the middle command
    really does run -- this is not a theoretical parse difference.
    """
    command = f"echo {ESC_DQ} ; git -C {primary} {verb} ; echo {ESC_DQ}"
    assert_denied(run_gate(shell(command, primary.parent), repos_file))


def test_the_mirrored_escaped_shape_also_denies(primary: Path, repos_file: Path) -> None:
    """The apostrophe arm, so neither quote character is special-cased.

    The ORIGINAL straddle was asymmetric -- the mirrored shape denied by accident of regex ordering,
    which is what hid it from one side. A fix that restored an asymmetry would pass the test above.
    """
    command = f"echo {ESC_SQ} ; git -C {primary} reset --hard ; echo {ESC_SQ}"
    assert_denied(run_gate(shell(command, primary.parent), repos_file))


def test_an_escape_inside_a_real_quoted_span_is_still_blanked(
    primary: Path, repos_file: Path
) -> None:
    """THE OTHER ARM, and without it the fix could be 'never blank anything'.

    Here the backslash sits INSIDE a genuine single-quoted span, where sh gives it no special meaning.
    The span is real, so it must still be blanked and must not supply a verb -- a commit message
    cannot become a command. This is the case that makes the test above evidence rather than an
    assertion that the gate denies everything.
    """
    command = f"git -C {primary} commit -m {SQ}a\\{DQ}b checkout main{SQ}"
    assert run_gate(shell(command, primary.parent), repos_file) is None


def test_a_quoted_program_path_still_keeps_its_git_token(primary: Path, repos_file: Path) -> None:
    """The false-NEGATIVE guard the collapse exists to provide, now decided inside the scan.

    `"C:/Program Files/Git/bin/git.exe" -C <governed> reset --hard` is a real spelling. Blanking the
    span wholesale would drop the verb and ALLOW, so the token has to survive -- and it has to survive
    without a pre-pass that can pair across a live command.
    """
    command = f"{DQ}C:/Program Files/Git/bin/git.exe{DQ} -C {primary} reset --hard"
    assert_denied(run_gate(shell(command, primary.parent), repos_file))


@pytest.mark.parametrize("spelling", ["git", "git.exe", "GIT.EXE", "Git"])
def test_the_program_path_token_survives_every_spelling(
    primary: Path, repos_file: Path, spelling: str
) -> None:
    """Case-folded and backslash-separated spellings, which the naive form of this fix misses.

    PowerShell `-replace` is case-insensitive by DEFAULT, so the old regexes accepted `GIT.EXE` by
    accident rather than by decision. Keeping the token is the fail-CLOSED direction -- it preserves a
    verb for the rules to judge -- so the case-insensitivity is now deliberate and pinned.
    """
    command = f"{DQ}C:\\Program Files\\Git\\bin\\{spelling}{DQ} -C {primary} reset --hard"
    assert_denied(run_gate(shell(command, primary.parent), repos_file))


def test_an_ordinary_command_is_still_allowed(primary: Path, repos_file: Path) -> None:
    """The global negative control. A gate that denies everything passes every test above."""
    assert run_gate(shell("echo hello ; ls -la", primary.parent), repos_file) is None


# VERIFIED STATE OF THIS FAMILY, recorded because TWO OF MY OWN COMMIT MESSAGES SAY OTHERWISE AND
# A COMMIT MESSAGE CANNOT BE AMENDED ONCE PUSHED (BACKLOG #1229 residual).
#
# `4d46a2a0` and `c308cc34` both state that rules 3c and 3d are UNADDRESSED and that I could not
# reproduce them. **THEY ARE CLOSED.** Verified COLD by the seat that found them, on a rig that
# predates my fix and which I did not write: all four PowerShell shapes now DENY where the previous
# fix ALLOWed, including 3c (shared core.hooksPath) and 3d (another session's worktree).
#
# MY NON-REPRODUCTION WAS MY HARNESS, NOT THE GATE. My control allowed on origin/main too, which
# means my shapes never exercised rule 3c at all -- evidence about my construction. Gating the
# escape AT THE SCANNER closed all three rules at once, which is what rule-agnostic cuts both ways
# means: one character disarmed three rules, and one flag re-armed them.
#
# AND THE EXTRACTION FIX CLOSED AN INHERITED DEFECT TOO, which I did not set out to fix and would
# not have claimed without measuring both gates:
#
#     one-level escaped interpreter arg   main ALLOW -> DENY      inherited, now closed
#
#         bash -c "echo \\"x\\"; git -C <governed> reset --hard"
#
#     NAMED HERE DELIBERATELY, under the owner's ruling that a construct is published only ALONGSIDE
#     THE FIX THAT MAKES IT INERT. This one is inert in this commit and travels in the same change,
#     so it cannot be lifted from here and used against this tree. It is named because an unnamed
#     improvement claim is not checkable: 'main ALLOW -> DENY' asks a reader to take the author's
#     word for what was measured, and the whole point of the left column is that it can be re-run.
#     two-level escaped interpreter arg   main DENY  -> DENY      my regression, repaired
#
# THE LEFT COLUMN IS THE POINT. A fix is not only judged against the branch it repairs; measuring
# against main is what distinguishes 'restored' from 'improved', and I would have reported the
# weaker claim.
#
# LEFT OPEN AND NOT CLAIMED: twelve further shapes the same lens reports as INHERITED from main --
# command substitution, backticks, ANSI-C quoting, concatenated quoting, heredocs, bare program
# names, and the per-line split. None is introduced here and none is fixed here. They are with the
# Dispatcher as a disclosure question.


# COVERAGE NOTE, deliberately a comment rather than an assertion, because what it names is a CLASS and
# a class cannot be enumerated by a test (BACKLOG #1229 residual).
#
# What let both fail-opens live for so long was not a missing case -- it was that NOTHING in 13 suites
# could see the class at all, so 13 green suites were evidence about the classes they covered and
# silent about this one. Both defects were pre-existing, and both survived a dedicated pass over this
# exact function.
#
# The scan's contract is: text a rule must judge is never blanked, and text inside a span the SHELL
# would quote always is. Anything that decides span boundaries WITHOUT that ownership rule -- a regex
# pair, a pre-pass, a lookahead -- has been wrong here three times now. If you add one, it belongs
# inside Remove-QuotedSpans' single pass, and it needs a case in this file.


# --- BACKLOG #1229 residual, SECOND ROUND: the escape rule is HOST-SPECIFIC ----------------------
#
# THE FIRST VERSION OF THIS FIX RE-CREATED #1229'S OWN DEFECT ON THE OTHER HOST, and it did so through
# the decision this file argued FOR. Honouring a backslash escape inside a double-quoted span is
# correct POSIX -- but `scripts/hooks/worktree_gate.ps1:999` scans BOTH tool names through ONE matcher
# (`$tool -in @("Bash", "PowerShell")`), and **PowerShell has no backslash escape**; its escape is the
# backtick. So on a PowerShell payload the scan held a span open that PowerShell had already CLOSED,
# straddled the live command, and blanked it.
#
# Found by the seat whose own design row asserted exactly this property -- a row I argued should be
# dropped, and which they dropped agreeing with me. Their commit called it "a deny no shell requires".
# That sentence is true of sh and FALSE OF POWERSHELL, and neither of us checked the second half.
#
# EVERY ROW BELOW IS PINNED TO WHETHER THE COMMAND ACTUALLY EXECUTES ON THAT HOST, measured with an
# inert payload that COMPUTES (`111*3` -> 333) rather than echoes, so an echo-back cannot be mistaken
# for a run. That is the only ground truth here: "should this deny" is a question about the shell, not
# about the gate.
_ODD_BS = 'Write-Output "C:\\Temp\\" ; {gated} ; Write-Output "x"'
# NOT MADE RAW, WHICH IS THE ESCAPE-SEQUENCE GATE'S OWN PRESCRIBED REMEDY (BACKLOG #1229 residual).
# `r'...'` would preserve the `\\\` as TWO backslashes, turning this line's ODD trailing count
# into an EVEN one -- and per the measured table ODD is the ALLOW case under test while EVEN DENIES.
# The remedy would have yielded a GREEN test of the non-regressing case: the regression row neutered,
# with nothing reporting it. Escaping only the INVALID sequence preserves the value exactly (verified
# by comparing ast.literal_eval before and after, not by reading the line).
# Generally: that remedy is unsafe for any literal that ALSO contains a valid backslash escape.
_STRADDLE = 'echo \\" ; {gated} ; echo \\"'


@pytest.mark.parametrize(
    "tool,template,expect_deny,measured",
    [
        # pwsh -NoProfile -Command '...(111*3)...' printed 333 -> the middle statement RAN.
        ("PowerShell", _ODD_BS, True, "333 printed: middle RAN"),
        # bash -c '...' -> "unexpected EOF while looking for matching \"" -> nothing parses, nothing runs.
        ("Bash", _ODD_BS, False, "syntax error: nothing executes"),
        # pwsh printed the line as a literal string, no 333 -> the middle did NOT run.
        ("PowerShell", _STRADDLE, False, "no 333: middle did NOT run"),
        # bash printed 333 -> the middle RAN.
        ("Bash", _STRADDLE, True, "333 printed: middle RAN"),
    ],
)
def test_the_verdict_matches_whether_the_command_RUNS_on_that_host(
    primary: Path, repos_file: Path, tool: str, template: str, expect_deny: bool, measured: str
) -> None:
    """The gate must model each shell's real quoting, not one shell's.

    ``measured`` is not decoration -- it records the observation each row is pinned to, so a future
    reader can tell an assertion grounded in shell behaviour from one grounded in a previous verdict.
    A row that only asserted "deny" would be satisfied by a gate that denies everything.
    """
    command = template.format(gated=f"git -C {primary} reset --hard")
    result = run_gate(
        {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(primary.parent)},
        repos_file,
    )
    if expect_deny:
        assert_denied(result), f"{tool}: {measured} -- the gate must see it"
    else:
        assert result is None, f"{tool}: {measured} -- denying it would be a FALSE DENY"


def test_an_unknown_host_gets_the_CONSERVATIVE_reading() -> None:
    """The default is fail-CLOSED, and the direction is the whole reason it is a default.

    Honouring the escape makes spans LONGER, so it blanks MORE and can hide a command -- fail OPEN.
    Refusing it leaves more text visible to the rules -- fail CLOSED. So `$PosixEscapes` defaults to
    false and only a host known to use backslash escapes opts in.

    Asserted on the SOURCE because the parameter default is the guarantee; a behavioural probe would
    need a third tool name the gate does not currently accept.
    """
    gate = (
        Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "worktree_gate.ps1"
    ).read_text(encoding="utf-8")
    assert "[bool]$PosixEscapes = $false" in gate, (
        "the escape rule must default to OFF: an unrecognised host has to get the reading that blanks "
        "less, or a future tool name silently inherits sh semantics (BACKLOG #1229 residual)"
    )
    assert '($tool -eq "Bash")' in gate, (
        "the opt-in must be keyed on the host, not left unconditional"
    )


def test_an_escaped_quote_in_an_interpreter_ARGUMENT_still_reaches_the_inner_code() -> None:
    """BACKLOG #1229 residual, THIRD round -- and the host flag alone could not close it.

    THE EXTRACTION AND THE BLANKING MUST AGREE ABOUT WHERE THE ARGUMENT ENDS. The interpreter-argument
    regex was ``[^"]*``, which is escape-BLIND and stops at the first quote INCLUDING an escaped one.
    Once the span blanking became escape-AWARE the two disagreed::

        bash -c "bash -c \\"git -C <governed> reset --hard\\""
        extraction got  `bash -c \\`   -- truncated at the escaped quote, no verb in it
        blanking removed the whole span
        so nothing reached any rule -> ALLOW

    MEASURED: origin/main DENY x3, the escape-aware fix ALLOW x3, and the control below DENY on both.
    The inner command really runs -- ``bash -c "bash -c \\"expr 111 \\* 3\\""`` prints 333.

    ON MAIN THE TWO AGREED BY ACCIDENT, both being escape-blind, which left the verb visible OUTSIDE
    the span. Making one side escape-aware removed the accident without replacing it. **A host flag
    cannot fix this**: the failing host is Bash, where the escape is real and honouring it is correct.
    """
    import tempfile

    d = Path(tempfile.mkdtemp())
    primary = d / "Repo"
    rf = d / "repos.txt"
    rf.write_text(f"{primary}\n", encoding="utf-8")
    gated = f"git -C {primary} reset --hard"

    escaped = f"bash -c {DQ}bash -c {ESC_DQ}{gated}{ESC_DQ}{DQ}"
    assert_denied(run_gate(shell(escaped, d), rf))

    # THE DISCRIMINATING CONTROL: identical nesting, no escape. It denies on main and on the fix, so
    # the trigger is the ESCAPE and not the nesting -- without this row the test above would pass
    # against a gate that simply denied anything containing `bash -c`.
    plain = f"bash -c {SQ}bash -c {DQ}{gated}{DQ}{SQ}"
    assert_denied(run_gate(shell(plain, d), rf))


# --- BACKLOG #1229 residual, FOURTH ROUND: the token survives only in PROGRAM position -----------
#
# Keeping the git token of a closed span is the false-NEGATIVE guard the three tests above pin. It was
# UNCONDITIONAL, and position is the whole difference between the two shapes that spelling covers:
#
#     "C:\Program Files\Git\bin\GIT.EXE" -C <governed> reset --hard   a PROGRAM. Must deny.
#     cp -r "/c/backups/Git" restore                                  a PATH. Must not deny.
#
# The second is a backup directory whose leaf happens to be `Git`, followed by an ordinary word that
# happens to be a git verb. Measured across two gate blobs driven over the real hook: at least 15 such
# shapes DENY under the unconditional emit and ALLOW under the blob before it.
#
# AND THE FALSE DENY WAS NOT THE WORST OF IT -- see
# tests/test_worktree_gate_hijack.py::test_a_quoted_git_path_on_an_earlier_line_does_not_shadow_a_hijack,
# where the same emit made rule 3b hand back an ALLOW on a real worktree hijack. A test file that saw
# only the false denies would have scored this change as a pure relaxation of a security control. It is
# not: it closes a fail-OPEN and a fail-CLOSED defect with the same predicate.


# Both ends of every row, so neither arm can pass vacuously: the ARGUMENT spelling must ALLOW and the
# PROGRAM spelling of a quoted git path must DENY. A gate that denied everything reddens the first
# assertion; a gate that blanked every span reddens the second.
@pytest.mark.parametrize(
    "argument_shape",
    [
        "cp -r {q} restore",
        "rsync -a {q} restore",
        "mv {q} clean",
        "ls {q} clean",
        "echo {q} merge",
        "7z a out.7z {q} am",
        "cp -r {q} switch",
        "du -sh {q} restore",
        "head -n 5 {q} clean",
        "docker run --rm -v {q} restore",
        # A REDIRECT TARGET is an argument too, and it is the row that keeps the redirection element in
        # Test-GitProgramPosition honest: `> out.txt "<prog>"` IS program position, `echo hi > "<dir>"`
        # is not, and only the COMPLETED form is transparent.
        "echo hi > {q} clean",
        # Command substitution and a brace expansion left of the span. Both were measured to keep
        # DENYING under a draft predicate whose boundary set admitted the CLOSING bracket; neither
        # shell dispatches a command straight after one, so it is not in the set.
        "cp -r $(pwd) {q} clean",
        "cp -r ${BACKUP} {q} clean",
        # An earlier span this same scan already blanked must not turn the next one into a program.
        'cp -r "/a/Git" {q} clean',
    ],
)
def test_a_quoted_git_path_in_ARGUMENT_position_does_not_deny(
    primary: Path, repos_file: Path, argument_shape: str
) -> None:
    """The false-deny half of the position predicate, with its own discriminating control per row."""
    quoted = f"{DQ}/c/backups/Git{DQ}"
    # `.replace` rather than `.format`: one row carries a literal `${BACKUP}` and str.format would
    # read those braces as a field name and raise -- turning a probe into a collection error.
    shaped = argument_shape.replace("{q}", quoted)
    assert run_gate(shell(shaped, primary.parent), repos_file) is None, (
        "a quoted PATH whose leaf is `Git` is not a git command, and denying it stops legitimate "
        "work over a directory name (BACKLOG #1229 residual, fourth round)"
    )
    # THE DISCRIMINATING CONTROL, and it varies POSITION alone: the identical span at the head of the
    # line is a program and must still deny. Without this row the test above would pass against a
    # scanner that had simply stopped keeping the token -- which is the remedy this fix rejected,
    # because it re-opens the whole GIT.EXE-as-program family.
    program = f"{DQ}C:\\Program Files\\Git\\bin\\GIT.EXE{DQ} -C {primary} reset --hard"
    assert_denied(run_gate(shell(program, primary.parent), repos_file))


# A WRAPPER RUNS THE PROGRAM NAMED AFTER IT, so the span behind one is still in program position. This
# is the half a naive "is the span first on the line" test gets wrong, and it is where a draft
# predicate measured on the same rig leaked 30 of 36 program-position shapes.
@pytest.mark.parametrize(
    "prefix",
    [
        "sudo ",
        "sudo -u root ",  # an option WITH AN OPERAND -- measured to leak without its own element
        'sudo "-u" "root" ',  # the operands pre-blanked by this same scan
        "env FOO=1 ",
        "FOO=1 ",
        "FOO=1 BAR=2 ",
        "X=$(ls) ",
        "time ",
        "nohup ",
        "timeout 5 ",
        "nice -n 10 ",
        "xargs ",
        "/usr/bin/sudo ",
        "> out.txt ",
        "2>&1 ",
        "echo hi ; ",
        "echo hi && ",
        "echo hi | ",
        "echo hi ;",  # no space after the separator
        "& ",
        "( ",
        "if true ; then ",
        "! ",
        "echo x | xargs -I{} ",
        "find . -type f -exec ",
    ],
)
def test_a_wrapper_prefix_does_not_move_a_quoted_git_program_out_of_program_position(
    primary: Path, repos_file: Path, prefix: str
) -> None:
    """The fail-OPEN half. Each prefix really dispatches the word after it."""
    program = f"{DQ}C:\\Program Files\\Git\\bin\\GIT.EXE{DQ} -C {primary} reset --hard"
    assert_denied(run_gate(shell(prefix + program, primary.parent), repos_file))
    # THE DISCRIMINATING CONTROL: a NON-wrapper word in the same slot is not transparent, so the same
    # span becomes an argument and allows. Without it, a predicate that returned true unconditionally
    # -- i.e. the unconditional emit this change replaces -- would pass every row above.
    assert (
        run_gate(shell(f"cp -r {DQ}/c/backups/Git{DQ} restore", primary.parent), repos_file) is None
    )


def test_the_argument_position_ALLOW_is_a_RECORDED_WEAKENING_for_the_lowercase_spelling(
    primary: Path, repos_file: Path
) -> None:
    """OWNER-RULED 2026-08-20, and pinned here so the losing end cannot be quietly dropped.

    ``cp -r "/c/backups/git" restore`` and ``cp -r "./git" restore`` DENIED on origin/main as well as
    under the unconditional emit -- the pre-fix collapse kept a lowercase token whatever its position,
    so these two were false denies of the same family that simply predate the case-folding. Position
    is now the only question asked, so they ALLOW.

    BOTH ENDS, because a one-sided note reads as a pure win:
      GAINED -- the whole argument-position family stops denying, in every case spelling.
      PAID -- this is a deliberate DENY-to-ALLOW move against origin/main, not merely the repair of a
      fresh regression, and it is recorded as such rather than absorbed into the repair.

    The control below is what makes this a test rather than a restatement of current behaviour: the
    SAME lowercase spelling in PROGRAM position must still deny.
    """
    for shape in (f"cp -r {DQ}/c/backups/git{DQ} restore", f"cp -r {DQ}./git{DQ} restore"):
        assert run_gate(shell(shape, primary.parent), repos_file) is None, (
            f"{shape} must allow -- owner ruling of 2026-08-20, recorded in Remove-QuotedSpans"
        )
    assert_denied(
        run_gate(
            shell(f"{DQ}/usr/bin/git{DQ} -C {primary} reset --hard", primary.parent), repos_file
        )
    )


def test_an_UNLISTED_wrapper_word_is_a_known_open_residual(primary: Path, repos_file: Path) -> None:
    """A TRIPWIRE OVER THE COST OF THIS CHANGE. It asserts ALLOW and that is NOT an endorsement.

    ``Test-GitProgramPosition`` reaches a command boundary across an ALLOWLIST of wrapper words. A
    wrapper it does not know is an ordinary bare word, which ends the chain, so the span behind it
    reads as an argument::

        myrunner "/usr/bin/git" -C <governed> reset --hard        ALLOW   (origin/main: DENY)
        setarch x86_64 "/usr/bin/git" -C <governed> reset --hard  ALLOW   (origin/main: DENY)

    Measured on the real hook, both blobs. This is the price of the predicate and it is stated in
    ``Test-GitProgramPosition``'s own docstring: a name listed in error costs only a fail-CLOSED deny,
    so the list may be generously long -- but a name MISSING from it is a fail-OPEN.

    WHEN THIS TEST REDS, that is the success signal: somebody added the word, or replaced the
    allowlist with something that does not need one. Delete the row; do not restore the ALLOW.

    ``ssh box "/usr/bin/git" ...`` is deliberately NOT in this list even though it allows for the same
    mechanical reason. ``ssh`` runs the program on the REMOTE host, so it cannot reach this machine's
    primary, and the gate's own must-allow set already carries ``ssh box "git checkout main"``.
    """
    for shape in (
        f"myrunner {DQ}/usr/bin/git{DQ} -C {primary} reset --hard",
        f"setarch x86_64 {DQ}/usr/bin/git{DQ} -C {primary} reset --hard",
    ):
        assert run_gate(shell(shape, primary.parent), repos_file) is None, (
            f"{shape} now DENIES. If you widened the wrapper vocabulary deliberately, that is the "
            "intended outcome -- delete this test and the residual note in Test-GitProgramPosition. "
            "Do NOT restore the ALLOW to make this pass."
        )
    # THE CONTROL that keeps the tripwire attached to the wrapper vocabulary rather than to the whole
    # predicate: a LISTED wrapper in the identical slot must still deny.
    assert_denied(
        run_gate(
            shell(f"nohup {DQ}/usr/bin/git{DQ} -C {primary} reset --hard", primary.parent),
            repos_file,
        )
    )
