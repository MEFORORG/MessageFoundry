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

from tests.test_worktree_gate import GATE, assert_denied, run_gate  # reuse the subprocess harness

# Built by concatenation, matching the sibling straddle suite: a test about quote handling must not
# depend on how this file's own literals nest. The escape is spelled once, here, for the same reason.
DQ = '"'
SQ = "'"
ESC_DQ = "\\" + DQ  # a BACKSLASH then a quote -- one shell literal, not a span opener
ESC_SQ = "\\" + SQ
BT = "`"  # PowerShell's escape character. Spelled once, for the same reason as the two above.


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


def shell(command: str, cwd: Path, tool: str = "Bash") -> dict[str, object]:
    """A tool payload, matching the sibling suites' harness.

    ``tool`` defaults to Bash because most rows here are sh shapes. It is a PARAMETER rather than a
    second helper: the host is the variable half of this file's fifth round, and spelling the payload
    dict inline at every PowerShell row is how the ``cwd`` convention drifts between neighbours.
    """
    return {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(cwd)}


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


@pytest.mark.parametrize("spelling", ["git", "git.exe"])
def test_the_program_path_token_survives_the_backslash_separated_spelling(
    primary: Path, repos_file: Path, spelling: str
) -> None:
    """The backslash-separated program path, which the naive form of this fix misses.

    ``GIT.EXE`` AND ``Git`` WERE ROWS HERE AND ARE NOT ANY MORE, on a measurement rather than a
    tidy-up. The emit is deliberately case-SENSITIVE (``-cmatch``), so those spellings blank wholesale
    and ALLOW -- and that is NOT a regression, because ``origin/main`` ALLOWs them too. Main's collapse
    regex is case-INSENSITIVE but substitutes ``$1``, preserving the original case, and every rule
    downstream compares case-sensitively; main therefore mints a token nothing recognises and lands on
    the same verdict by a different route. Measured on both blobs::

        "<...>\\Git\\bin\\git.exe" -C <governed> reset --hard   main=DENY   this build=DENY
        "<...>\\Git\\bin\\GIT.EXE" -C <governed> reset --hard   main=ALLOW  this build=ALLOW
        "<...>\\Git\\bin\\Git"     -C <governed> reset --hard   main=ALLOW  this build=ALLOW

    The uppercase hole is disclosed as a tripwire further down this file rather than dropped silently:
    see ``test_the_UPPERCASE_quoted_PROGRAM_spelling_is_a_known_open_residual``.
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
#
# THREE THINGS ABOVE HAVE SINCE MOVED, and none of them deletes the disclosure. (1) The count of
# twelve is UNCONFIRMED -- BACKLOG #1427 re-derived the census and could not reach it, and no
# artifact anywhere lists the twelve individually. Read the list as categories, not as a number.
# (2) The Dispatcher is a RETIRED SEAT (CLAUDE.md section 5), so "with the Dispatcher" routes
# nowhere; the disclosure landed in #1427 instead. (3) "the per-line split" names the mechanism and
# not the hole. The hole needs the gated command on a LINE carrying the closing quote of one
# newline-crossing span AND the opening quote of the next; every neighbour one property away denies.
# That imprecision is what let #1427 and #1429 record opposite results and both be right. The four
# allowing corners are pinned in tests/test_worktree_gate_quote_straddle.py and the neighbours in
# tests/test_worktree_gate_line_split_discriminator.py.


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
        # --- FIFTH ROUND, the BACKTICK. These two are the must-ALLOW half of that round and they
        # --- belong in this table rather than in one of their own: same property, same shape.
        # An ODD trailing backtick escape with nothing to re-close it. pwsh reports "The string is
        # missing the terminator" and runs NOTHING, so a deny would refuse a line that cannot execute.
        # This row is a DENY-to-ALLOW move against the pre-fix gate: a false deny removed, not a hole.
        (
            "PowerShell",
            f"Write-Output {DQ}a{BT}{DQ} ; {{gated}} ; Write-Output {DQ}x{DQ}",
            False,
            "ParserError: the string is missing its terminator",
        ),
        # The backtick straddle's OWN characters under the Bash tool, where a backtick is command
        # substitution rather than an escape. bash reports an unexpected EOF and runs nothing, so the
        # SAME text has opposite right answers on the two hosts -- which is what the convention buys.
        (
            "Bash",
            f"echo {DQ}a{BT}{DQ}b{DQ} ; {{gated}} ; echo {DQ}c{BT}{DQ}d{DQ}",
            False,
            "unexpected EOF while looking for a matching quote",
        ),
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
    result = run_gate(shell(command, primary.parent, tool), repos_file)
    if expect_deny:
        assert_denied(result), f"{tool}: {measured} -- the gate must see it"
    else:
        assert result is None, f"{tool}: {measured} -- denying it would be a FALSE DENY"


def test_an_unknown_host_gets_the_CONSERVATIVE_reading() -> None:
    """An unrecognised tool name must get NO escape rule, because guessing one has cost twice.

    Refusing an escape is not universally fail-closed -- the fifth round below measures the opposite
    -- so the reason for this default is narrower and it is the right one: a host nobody has MEASURED
    gets no rule invented for it. Both regressions in this file's history came from applying one
    host's escape to another host's text.

    Asserted on the SOURCE because the parameter default is the guarantee; a behavioural probe would
    need a third tool name the gate does not currently accept.
    """
    gate = GATE.read_text(encoding="utf-8")
    assert "[string]$Convention = 'none'" in gate, (
        "the escape rule must default to 'none': an unmeasured host has to get no escape rule at "
        "all, or a future tool name silently inherits some other shell's semantics (BACKLOG #1229 "
        "residual)"
    )
    assert "Get-HostConvention $tool" in gate, (
        "the convention must be keyed on the host, not left unconditional"
    )
    assert "default { 'none' }" in gate, (
        "Get-HostConvention must fall through to 'none' for a tool name it does not recognise"
    )


# --- BACKLOG #1229 residual, FIFTH ROUND: refusing the HOST'S OWN escape straddles too ------------
#
# Round 2 gave PowerShell NO escape rule and wrote down why: "Honouring the escape makes spans LONGER,
# so it BLANKS MORE and can hide a command -- fail OPEN. Refusing it makes spans shorter, leaving more
# text visible to the rules -- fail CLOSED."
#
# THAT IS TRUE OF SPAN LENGTH AND FALSE OF SPAN POSITION, and the difference is a live fail-open.
# Refusing an escape the host really honours does not merely shorten the first span, it SHIFTS every
# pairing after it -- and the shifted pair straddles the gated command and blanks it. #1229's own
# mechanism, arriving through the door built to keep it out.
#
# PowerShell's escape is the BACKTICK. Measured on pwsh 7.6.4 with a payload that COMPUTES (`111*3`
# -> 333) rather than echoes, so an echo-back cannot be mistaken for a run:
#
#     Write-Output "a`"b" ; 111*3 ; Write-Output "c`"d"      333 printed: the middle RAN
#     Write-Output "a""b" ; 111*3 ; Write-Output "c""d"      333 printed  (doubled-quote escape)
#     Write-Output "ab"   ; 111*3 ; Write-Output "cd"        333 printed  (no escape at all)
#     Write-Output 'a`'   ; 111*3 ; Write-Output 'b`'        333 printed  (single-quoted: LITERAL)
#     Write-Output "a`"   ; 111*3 ; Write-Output "x"         ParserError: nothing runs
#     the FIRST line's characters under bash                 unexpected EOF: nothing runs
#
# Every row below is pinned to one of those observations, never to a previous verdict. The two
# must-ALLOW rows live in the host matrix above rather than in a table of their own: they have that
# test's exact shape, and splitting the deny half from the allow half of one property into two tables
# is how the two drift.


def _pwsh_backtick_straddle(gated: str) -> str:
    """The straddle: one backtick-escaped quote on each side of the gated command."""
    return f"Write-Output {DQ}a{BT}{DQ}b{DQ} ; {gated} ; Write-Output {DQ}c{BT}{DQ}d{DQ}"


# THE VERB IS ZIPPED INTO THE ROWS, NOT CROSSED WITH THEM. Crossing two verbs over three rows costs
# six `pwsh` launches for three shapes, and this file already measured why that buys nothing: both
# verbs reach the SAME rule. The defect is upstream of any rule anyway -- it is in the blanking -- so
# varying the verb across the rows keeps both spellings present at half the launches.
@pytest.mark.parametrize(
    "tool,wrap,verb",
    [
        # The OUTER line of a PowerShell tool call really is PowerShell.
        ("PowerShell", None, "reset --hard"),
        # ...and an EXTRACTED pwsh payload gets the same convention from Get-FlagOwner, whichever tool
        # typed the outer line. Without this row the fix could have been keyed on the tool name alone.
        ("Bash", "pwsh -Command", "checkout main"),
        ("PowerShell", "pwsh -c", "reset --hard"),
    ],
)
def test_a_powershell_backtick_escaped_quote_does_not_hide_a_gated_command(
    primary: Path, repos_file: Path, tool: str, wrap: str | None, verb: str
) -> None:
    """pwsh printed 333 for this shape, so the middle statement RUNS and the gate must see it."""
    payload = _pwsh_backtick_straddle(f"git -C {primary} {verb}")
    command = payload if wrap is None else f"{wrap} {SQ}{payload}{SQ}"
    assert_denied(run_gate(shell(command, primary.parent, tool), repos_file))


@pytest.mark.parametrize(
    "middle,measured",
    [
        # PowerShell's OTHER escape. Naive pairing already covers the same extent for it, so this row
        # denies before and after the fix -- it is here to show the straddle above is about the
        # BACKTICK and not about escaped quotes in general.
        (f"{DQ}a{DQ}{DQ}b{DQ}", "doubled-quote escape: 333 printed"),
        # No escape at all. Denies on every version of this scanner, so it separates the rows above
        # from a gate that has simply started denying `Write-Output`.
        (f"{DQ}ab{DQ}", "no escape at all: 333 printed"),
    ],
)
def test_the_controls_that_deny_either_way_still_deny(
    primary: Path, repos_file: Path, middle: str, measured: str
) -> None:
    """Same shape, same host, no backtick. Both RUN on pwsh and both must be seen."""
    command = f"Write-Output {middle} ; git -C {primary} reset --hard ; Write-Output {DQ}z{DQ}"
    result = run_gate(shell(command, primary.parent, "PowerShell"), repos_file)
    assert result is not None, f"{measured} -- the gate must see it"
    assert_denied(result)


def test_the_backtick_is_LITERAL_inside_a_SINGLE_quoted_powershell_span(
    primary: Path, repos_file: Path
) -> None:
    """THE ASYMMETRY ARM, and without it the fix could be 'honour the backtick everywhere'.

    A PowerShell single-quoted string is fully literal -- the backtick escapes nothing there, so the
    span really does close at the apostrophe and the middle statement RUNS. Measured: pwsh printed 333
    for ``Write-Output 'a`' ; 111*3 ; Write-Output 'b`'``.

    Applying the escape inside single-quoted spans would hold the first one open past its real closer,
    pair it with the next apostrophe, and blank the gated command -- the same fail-open one span type
    over. This is the PowerShell twin of the sh row that keeps ``'a\\'`` closing at its quote.
    """
    command = (
        f"Write-Output {SQ}a{BT}{SQ} ; git -C {primary} reset --hard ; Write-Output {SQ}b{BT}{SQ}"
    )
    assert_denied(run_gate(shell(command, primary.parent, "PowerShell"), repos_file))


def test_a_backtick_straddle_AROUND_a_cmd_call_is_seen(primary: Path, repos_file: Path) -> None:
    """A fourth fail-open the fifth round closes, found while probing the cmd family.

    The straddling quotes sit on the OUTER PowerShell line and the thing between them happens to be a
    ``cmd /c`` invocation. Nothing about cmd decides this -- the outer line is PowerShell and its
    backtick is what pairs the spans -- but it is pinned because it measured differently from the
    shapes above and a class found by accident is the one that goes unrecorded::

        cmd /c "echo a`"b" & git -C <governed> reset --hard & Write-Output "c`"d"

    MEASURED: origin/main ALLOW, this build DENY. The middle really runs -- pwsh started it as
    background Job3 under ``&`` and printed 333 under ``;``.
    """
    gated = f"git -C {primary} reset --hard"
    command = f"cmd /c {DQ}echo a{BT}{DQ}b{DQ} & {gated} & Write-Output {DQ}c{BT}{DQ}d{DQ}"
    assert_denied(run_gate(shell(command, primary.parent, "PowerShell"), repos_file))


def test_the_cmd_family_keeps_its_NO_ESCAPE_reading() -> None:
    """cmd.exe escapes with ``^``, not with a backtick, and it must not inherit PowerShell's rule.

    ``Get-FlagOwner`` used to answer a single ``win`` for pwsh, powershell, cmd and wsl. That was
    harmless while ``win`` meant "no escapes" and became a hazard the moment PowerShell got a rule, so
    the set is split. Splitting is the NO-CHANGE option: cmd and wsl get exactly the reading they had.

    **THE REASON THIS USED TO GIVE FOR BEING A SOURCE ASSERTION WAS FALSE, AND IT IS REPLACED BY A
    MEASUREMENT.** It said no probe can separate ``cmd`` from PowerShell because the RAW line is
    scanned under the OUTER host's convention and carries the git text, so the outer line reaches a
    verdict before the payload's convention can matter. That holds only while the payload contains an
    unescaped quote. **It fails whenever the payload's quotes are ALL backtick-escaped**: the outer
    pwsh scan then treats the whole argument as ONE span, blanks it, and reaches NO verdict -- so the
    extracted payload's own convention is the only thing left to decide. A justification that told the
    next reader the probe could not exist is a compensating control resting on a false premise, which
    is the same defect this file's #1429 tripwire was written for, so it is corrected in place rather
    than deleted.

    **THE PROBE THAT SEPARATES THEM, built and measured 2026-09-03** against this build and against a
    mutant folding ``cmd`` and ``wsl`` into the PowerShell set, cwd inside the governed repo::

        probe                                       this   cmdfold   separates?
        cmd /c "`"<gated>`""    (PowerShell tool)   ALLOW  DENY      YES
        wsl -c "`"<gated>`""    (PowerShell tool)   ALLOW  DENY      YES
        cmd /c "`"<gated>`""    (Bash tool)         DENY   DENY      no, outer conv is posix
        cmd /c "<gated>"        no backtick         DENY   DENY      no   (control)
        wsl -c "<gated>"        no backtick         DENY   DENY      no   (control)

    The no-backtick controls are what make this a separation rather than a coincidence: only the
    escape varies between a separating row and its own control.

    **THE CONCLUSION IS UNCHANGED AND STILL CORRECT.** ``cmd`` must not inherit a backtick: cmd.exe
    escapes with ``^``, and handing it an escape it does not have lengthens its spans and can hide a
    command inside one. What changed is that the split now rests on a measurement rather than on a
    claim that no probe exists.

    **IT IS NO LONGER A SOURCE ASSERTION ALONE (residual, SIXTH round).** The separating probe above
    used to read ALLOW on this build, so pinning DENY would have pinned a verdict the gate did not
    produce; that ALLOW is closed below and the row now denies either way, which costs the table its
    separating power. A DIFFERENT probe replaces it, and this one is the better instrument because it
    separates the two conventions in the direction that MATTERS -- it shows the fold LOSING a deny the
    gate has today, rather than gaining one::

        cmd /c 'echo "x`" & <gated> & echo "y"'   PowerShell tool   this DENY   cmd-folded ALLOW
        cmd /c 'echo "x"  & <gated> & echo "y"'   the control       this DENY   cmd-folded DENY

    Measured 2026-09-03 against a mutant that folds ``cmd`` and ``wsl`` into ``$pwshSet``, cwd inside
    the governed repo, gate copies hash-verified byte-identical to ``origin/main`` and to this build.
    The middle statement REALLY RUNS: the inert marker ``set /a 111*3`` prints 333 through both rows,
    so neither is a dead probe, and ``&`` is used rather than ``;`` because ``;`` is not a command
    separator in cmd.

    **WHY THE FOLD LOSES IT.** A backtick is an ORDINARY CHARACTER to cmd.exe, so the quote after it
    really closes the span and the gated command is left in plain view. Reading that quote as escaped
    holds the span open ACROSS the gated command and blanks it -- #1229's own straddle, bought by
    handing a host an escape it does not have. The PowerShell single-quoted argument is what carries
    the backtick through to cmd intact, since a pwsh single-quoted string is fully literal.
    """
    gate = GATE.read_text(encoding="utf-8")
    assert "$cmdSet = @('cmd', 'wsl')" in gate, (
        "cmd and wsl must stay in their own set: folding them in with pwsh hands them a backtick "
        "escape neither has (BACKLOG #1229 residual, fifth round)"
    )
    assert "$pwshSet = @('pwsh', 'powershell')" in gate, (
        "only the two PowerShell hosts may carry the backtick convention"
    )
    assert "'pwsh' { [char]0x60 }" in gate, (
        "the backtick must be reachable ONLY from the 'pwsh' arm of Get-EscapeChar"
    )


def test_a_LITERAL_backtick_in_a_cmd_payload_does_not_hide_a_gated_command(
    primary: Path, repos_file: Path
) -> None:
    """The BEHAVIOURAL half of the split above, and the arm the cmd-folded mutant fails.

    See ``test_the_cmd_family_keeps_its_NO_ESCAPE_reading`` for the measurement and the mechanism.
    WHEN THIS REDS, somebody handed ``cmd`` an escape convention it does not have.
    """
    gated = f"git -C {primary} reset --hard"
    probe = f"""cmd /c {SQ}echo {DQ}x{BT}{DQ} & {gated} & echo {DQ}y{DQ}{SQ}"""
    assert_denied(run_gate(shell(probe, primary.parent, "PowerShell"), repos_file))
    # THE CONTROL, and it is what makes the row above a separation rather than a coincidence: the
    # identical shape with the backtick removed. Only the escape varies between the two.
    control = f"""cmd /c {SQ}echo {DQ}x{DQ} & {gated} & echo {DQ}y{DQ}{SQ}"""
    assert_denied(run_gate(shell(control, primary.parent, "PowerShell"), repos_file))
    # THE ANTI-VACUITY ROW. Two DENY assertions go green against a gate that denies everything, and
    # the evidence that they do not -- the cmd-folded mutant ALLOWS the probe -- lives in a scratchpad
    # a reader cannot re-run. So the same shape aimed at a NON-governed tree must still ALLOW.
    ungoverned = f"git -C {primary.parent / 'Elsewhere'} reset --hard"
    benign = f"""cmd /c {SQ}echo {DQ}x{BT}{DQ} & {ungoverned} & echo {DQ}y{DQ}{SQ}"""
    assert run_gate(shell(benign, primary.parent, "PowerShell"), repos_file) is None, (
        "the identical shape aimed at an ungoverned tree must ALLOW -- if it denies, the two rows "
        "above prove nothing about escape handling"
    )


@pytest.mark.parametrize("flag", ["/c", "/k"])
def test_a_fully_ESCAPED_cmd_payload_is_read_in_the_encoding_cmd_RECEIVES(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """BACKLOG #1229 residual, SIXTH round -- a fail-open THE FIFTH ROUND'S OWN FIX INTRODUCED.

    **THIS ROW ASSERTED ALLOW UNTIL THE SIXTH ROUND, AS A DELIBERATE TRIPWIRE OVER A LIVE REGRESSION.**
    The ALLOW is closed; the history stays because the mechanism is the item's own and the next reader
    needs it. Measured 2026-09-03 against gate copies hash-verified byte-identical to ``origin/main``
    and to each build, cwd inside the governed repo, every row pinned to whether the middle statement
    really RUNS (the inert marker ``set /a 111*3`` -> 333, so an echo-back proves nothing)::

        cmd /c "`"git -C <governed> reset --hard`""   main DENY   round 5 ALLOW   here DENY   RUNS
        cmd /k "`"git -C <governed> reset --hard`""   main DENY   round 5 ALLOW   here DENY   RUNS
        cmd /c "git -C <governed> reset --hard"       main DENY   round 5 DENY    here DENY   (control)
        git -C <governed> reset --hard                main DENY   round 5 DENY    here DENY   (POSCTL)

    **THE MECHANISM.** The OUTER line is PowerShell, so the outer scan honours the backticks, sees one
    span, blanks it and reaches NO verdict. Extraction then asks ``Get-FlagOwner``, which answers
    ``cmd``, whose convention is ``none``. But the extracted text STILL CARRIES THE OUTER HOST'S
    BACKTICKS -- pwsh has not run, so nothing has consumed them -- and scanning it with no escape rule
    pairs the two escaped-quote sequences ACROSS the git command and blanks it. Span ownership
    deciding the wrong way, one level in.

    **HOW IT IS CLOSED, AND THE TWO WAYS THAT WERE MEASURED AND REJECTED.** ``Get-ScannableSegments``
    now emits ONE EXTRA SEGMENT for a cmd-owned payload: the same text with the outer host's escaped
    quotes resolved and cmd's own ``/c`` wrapper quotes removed -- the encoding cmd.exe actually
    receives. Both steps are needed and neither is enough alone, measured.

      * FOLDING ``cmd`` INTO THE PowerShell SET denies these rows and LOSES a deny the gate has
        today. See ``test_a_LITERAL_backtick_in_a_cmd_payload_does_not_hide_a_gated_command``.
      * DECODING IN PLACE -- replacing the payload rather than adding a view -- re-opens round 3's
        nested ``bash -c "bash -c \\"<gated>\\""`` (DENY -> ALLOW), because this function recurses ONE
        level and that round-3 deny depends on the escaped text staying visible at this level.

    An EXTRA segment cannot do either: every rule reaches a segment through a continue-or-deny loop,
    so adding one can only ADD a deny.
    """
    gated = f"git -C {primary} reset --hard"
    # Spelled once, locally: the run of quote and backtick placeholders below is the whole subject of
    # this test, and `{DQ}{BT}{DQ}{gated}{BT}{DQ}{DQ}` is unreadable as an unbroken sequence.
    esc_dq = BT + DQ  # PowerShell's escaped quote -- a literal `"` that does NOT close a span
    command = f"cmd {flag} {DQ}{esc_dq}{gated}{esc_dq}{DQ}"
    assert_denied(run_gate(shell(command, primary.parent, "PowerShell"), repos_file))
    # THE CONTROL, and it is what keeps this attached to the ESCAPE rather than to the cmd shape: the
    # identical command with NO backticks DENIES, on origin/main and on every build since. Without it
    # the row above would pass against a gate that had simply stopped recognising `cmd` altogether.
    #
    # BOTH FLAGS KEEP THEIR OWN ROW DELIBERATELY, against this file's own zip-don't-cross rule. That
    # rule is for dimensions that reach the SAME rule and buy nothing; here both `cmd /c` and
    # `cmd /k` were INDEPENDENTLY MEASURED to allow AND to execute (333) before this fix.
    assert_denied(
        run_gate(shell(f"cmd {flag} {DQ}{gated}{DQ}", primary.parent, "PowerShell"), repos_file)
    )


def test_the_extra_cmd_view_is_ADDITIVE_and_cannot_remove_a_deny() -> None:
    """The safety argument of the sixth round, made structural rather than remembered.

    THE FIX IS AN EXTRA SEGMENT, NOT A REPLACED ONE, and that is the whole reason it cannot introduce
    a fail-open. Rewriting the payload in place is the tidier change and it is MEASURED to re-open
    round 3 -- see the test above. So the emission the round-3 pin depends on must stay, and the new
    view must be APPENDED after every existing segment, where rule 3's first-verb-wins bookkeeping
    cannot see it.

    WHEN THIS REDS, somebody turned the extra view into a rewrite. Re-measure round 3 before agreeing
    that is safe.
    """
    gate = GATE.read_text(encoding="utf-8")
    assert "$s = Remove-QuotedSpans $item.Text $item.Conv" in gate, (
        "the ORIGINAL payload view must still be emitted: the round-3 nested-escape deny depends on "
        "the outer-encoded text staying visible at this level (BACKLOG #1229 residual, sixth round)"
    )
    assert (
        "$unwrapped = Remove-CmdWrapperQuotes (Remove-EscapeChars $item.Text $Convention)" in gate
    ), (
        "the extra cmd view must resolve the OUTER host's escaped quotes before applying cmd's own "
        "wrapper rule -- neither step closes the shape alone"
    )
    # The extra view must come after the loop that emits the original, never inside it.
    original = gate.index("$s = Remove-QuotedSpans $item.Text $item.Conv")
    extra = gate.index("$unwrapped = Remove-CmdWrapperQuotes")
    assert original < extra, "the extra view must be APPENDED, so segment order is unchanged"


def test_the_scanner_and_the_extractor_READ_THE_SAME_ESCAPE_TABLE() -> None:
    """The invariant round 3 was a fail-open for, made structural instead of watched.

    THE SCANNER AND THE INTERPRETER-ARGUMENT EXTRACTION MUST NOT DISAGREE ABOUT WHERE A SPAN ENDS.
    They did once, measurably (see the round-3 test below). The fix at the time made the two AGREE
    while leaving the escape character spelled TWICE -- once as a ``[char]`` in ``Remove-QuotedSpans``
    and once inside a hand-written regex in ``Get-ScannableSegments``, some 500 lines apart. A sixth
    host added to one and not the other re-opens the round-3 hole, and a source assertion on each
    spelling separately cannot see that gap, because both would still pass.

    So the duplicate is gone rather than watched. ``Get-EscapeChar`` is the only table and the
    extraction pattern is DERIVED from it through ``[regex]::Escape``, which makes divergence
    unrepresentable rather than merely absent today. Verified byte-identical to the three literals it
    replaced, on all four conventions.

    WHEN THIS TEST REDS, somebody re-introduced a second spelling of the escape character. That is
    the defect; the test is not the thing to fix.
    """
    gate = GATE.read_text(encoding="utf-8")
    assert gate.count("function Get-EscapeChar(") == 1, "the escape table must be defined once"
    assert "$esc = Get-EscapeChar $Convention" in gate, (
        "Remove-QuotedSpans must read the shared table rather than spelling the character itself"
    )
    assert "$extractEsc = Get-EscapeChar $Convention" in gate, (
        "the extraction regex must read the SAME table -- see round 3 in this file's history"
    )
    assert "[regex]::Escape($extractEsc)" in gate, (
        "the extraction pattern must be DERIVED from the shared character, not re-spelled as a "
        "literal: a second literal is what lets the two drift apart silently"
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


# --- BACKLOG #1229 residual, FOURTH ROUND: the emit is CASE-SENSITIVE, and the PROGRAM-POSITION
# --- experiment that briefly stood here was REVERTED (owner ruling, 2026-08-21) -------------------
#
# Keeping the git token of a closed span is the false-NEGATIVE guard the three tests above pin. Two
# further changes were layered on top of it and BOTH ARE GONE. The tests that pinned them went with
# them; this block records the dead end so the next reader does not walk back into it.
#
# WHAT WAS TRIED.
#   (a) The emit was made case-INSENSITIVE and canonicalised to lowercase, so that `GIT.EXE` -- a real
#       Windows spelling the case-SENSITIVE rules downstream otherwise skip -- would still present a
#       verb for those rules to judge. Fail-closed in direction, and sound in isolation.
#   (b) (a) then read `cp -r "/c/backups/Git" restore` as a git command, so a `Test-GitProgramPosition`
#       predicate was added to keep the token only where the span is dispatched as a PROGRAM -- a
#       command boundary reachable leftward across an allowlist of wrapper words.
#
# WHY IT WAS REVERTED, and it is not the false denies. The predicate bought those back at the price of
# two fail-OPENS on shapes `origin/main` DENIES:
#
#     cmd /c "<...>\Git\bin\git.exe" -C <governed> reset --hard      main=DENY   experiment=ALLOW
#     . "<...>\Git\bin\git.exe" -C <governed> reset --hard           main=DENY   experiment=ALLOW
#         (the second is a PowerShell dot-source, on a PowerShell tool call)
#
# Spending a security gate's DENY to buy a tidier false-deny profile is the wrong direction, so (a) and
# (b) were both withdrawn. RE-MEASURED after the revert, on the same rig and the real hook: both rows
# are DENY again, matching main.
#
# WHAT IS TRUE NOW. Every row below measured over the real hook against `origin/main` and against this
# tree, and IDENTICAL on the two blobs -- so none of it is introduced here and none of it is repaired
# here:
#
#     "<...>\Git\bin\git.exe" -C <governed> reset --hard          DENY   the guard the emit exists for
#     "<...>\Git\bin\GIT.EXE" -C <governed> reset --hard          ALLOW  a residual, pinned below
#     cp -r "/c/backups/Git" restore   (cwd = the governed repo)   ALLOW  the leaf case is what saves it
#     cp -r "/c/backups/git" restore   (cwd = the governed repo)   DENY   a false deny, pinned below
#
# So the case-sensitivity is not a tie-break between two right answers. It is the ONLY thing standing
# between the argument-position family and a daily false deny, and it leaks the uppercase PROGRAM
# spelling in exchange. BOTH ends are pinned as tripwires below rather than left to a comment, because
# a residual that lives only in prose is one nobody notices closing.


# The must-ALLOW half: the case-sensitivity is what keeps this family out of the deny path. Every row
# is the same span in ARGUMENT position, and each carries its own discriminating control that varies
# THE LEAF CASE ALONE -- so no row can pass against a gate that has simply stopped keeping the token,
# and none can pass against one that denies everything.
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
        # A REDIRECT TARGET, a command substitution and a brace expansion left of the span, and an
        # earlier span this same scan already blanked. All four were shapes the reverted predicate had
        # to reason about explicitly; under a case-sensitive emit they need no special handling at all,
        # which is most of the argument for the simpler rule.
        "echo hi > {q} clean",
        "cp -r $(pwd) {q} clean",
        "cp -r ${BACKUP} {q} clean",
        'cp -r "/a/Git" {q} clean',
    ],
)
def test_a_TITLE_CASED_quoted_git_leaf_cannot_supply_a_verb(
    primary: Path, repos_file: Path, argument_shape: str
) -> None:
    """A quoted PATH whose leaf is `Git` is not a git command, and the CWD here is load-bearing.

    THE EARLIER VERSION OF THIS TEST RAN FROM ``primary.parent`` AND COULD NOT FAIL. From there a bare
    ``git restore`` names no governed target, so the row ALLOWs whatever the scanner emitted -- it was
    measuring the target resolver, not the emit. Moving the cwd INTO the governed repo makes the emit
    the only variable, and the leaf case then separates cleanly. Measured, all 14 rows, both blobs::

        cp -r "/c/backups/Git" restore    ALLOW
        cp -r "/c/backups/git" restore    DENY
    """
    quoted = f"{DQ}/c/backups/Git{DQ}"
    # `.replace` rather than `.format`: one row carries a literal `${BACKUP}` and str.format would
    # read those braces as a field name and raise -- turning a probe into a collection error.
    shaped = argument_shape.replace("{q}", quoted)
    assert run_gate(shell(shaped, primary), repos_file) is None, (
        "a quoted PATH whose leaf is `Git` is not a git command, and denying it stops legitimate "
        "work over a directory name (BACKLOG #1229 residual, fourth round)"
    )
    # THE DISCRIMINATING CONTROL, and it varies THE LEAF CASE alone: the identical line with a
    # lowercase leaf really does emit a token and really does deny. This is a FALSE DENY and it is
    # pinned as such below -- it is used here because it is the sharpest available control, not
    # because it is the right answer.
    assert_denied(
        run_gate(
            shell(shaped.replace(f"{DQ}/c/backups/Git{DQ}", f"{DQ}/c/backups/git{DQ}"), primary),
            repos_file,
        )
    )


def test_the_UPPERCASE_quoted_PROGRAM_spelling_is_a_known_open_residual(
    primary: Path, repos_file: Path
) -> None:
    """A TRIPWIRE OVER THE COST OF THE CASE-SENSITIVE EMIT. It asserts ALLOW and that is NOT an
    endorsement -- read this before acting on it.

    ``GIT.EXE`` is a real spelling on Windows and the emit is case-SENSITIVE, so the span blanks
    wholesale and no verb reaches any rule::

        "<...>\\Git\\bin\\GIT.EXE" -C <governed> reset --hard      ALLOW   (origin/main: ALLOW)
        "<...>\\Git\\bin\\Git"     -C <governed> reset --hard      ALLOW   (origin/main: ALLOW)

    PRE-EXISTING, NOT INTRODUCED HERE, and the mechanism on main is worth stating because it looks
    like it should differ: main's collapse regex IS case-insensitive, but it substitutes ``$1``, which
    preserves the original case, and every rule downstream compares case-sensitively. Main therefore
    mints a token nothing recognises and lands on the same verdict by a different route.

    THE ONLY REMEDY TRIED COST MORE THAN IT BOUGHT. Making the emit case-insensitive closes these two
    and re-opens the whole argument-position family above; adding a program-position discriminator to
    hold both ends opened `cmd /c` and PowerShell dot-source as fail-opens that main denies. Do NOT
    re-add the lowercase emit without a discriminator, and do not add a discriminator without
    re-measuring those two.

    WHEN THIS TEST REDS, that is the success signal: somebody closed the hole. Delete the row; do not
    restore the ALLOW.
    """
    for leaf in ("GIT.EXE", "Git", "Git.exe"):
        shape = f"{DQ}C:\\Program Files\\Git\\bin\\{leaf}{DQ} -C {primary} reset --hard"
        assert run_gate(shell(shape, primary.parent), repos_file) is None, (
            f"{shape} now DENIES. If you closed the uppercase program spelling deliberately, that is "
            "the intended outcome -- delete this test. Do NOT restore the ALLOW, and check that "
            "`cmd /c` and PowerShell dot-source still DENY."
        )
    # THE CONTROL that keeps the tripwire attached to the CASE and not to the whole emit: the
    # lowercase spelling in the identical slot must still deny.
    assert_denied(
        run_gate(
            shell(
                f"{DQ}C:\\Program Files\\Git\\bin\\git.exe{DQ} -C {primary} reset --hard",
                primary.parent,
            ),
            repos_file,
        )
    )


def test_a_LOWERCASE_quoted_git_LEAF_in_argument_position_is_a_known_open_FALSE_DENY(
    primary: Path, repos_file: Path
) -> None:
    """THE OTHER END OF THE SAME TRADE, and it asserts the WRONG answer on purpose.

    The emit is unconditional in position, so an ordinary backup directory whose leaf really is
    lowercase ``git`` reads as a git command and its next word becomes a verb::

        cp -r "/c/backups/git" restore    DENY   (origin/main: DENY)
        cp -r "./git" restore             DENY   (origin/main: DENY)

    Both measured from INSIDE the governed repo, on both blobs. This is a FALSE DENY: nothing here is
    a git invocation. It is pinned rather than described because the previous occupant of this slot --
    a test asserting these ALLOW -- passed only because it ran from ``primary.parent``, where no
    governed target resolves and the verdict is decided somewhere else entirely.

    NOT A WEAKENING AND NOT A REGRESSION EITHER WAY: main denies these too, and the reverted predicate
    is what briefly allowed them.

    WHEN THIS TEST REDS, somebody taught the emit to tell a program from an argument without the two
    fail-opens the last attempt cost. Delete the row; do not restore the DENY.
    """
    for shape in (f"cp -r {DQ}/c/backups/git{DQ} restore", f"cp -r {DQ}./git{DQ} restore"):
        # If this reds, the shape now ALLOWs. Delete the row; do not restore the DENY, and re-check
        # that `cmd /c` and PowerShell dot-source of a quoted `git.exe` still DENY.
        assert_denied(run_gate(shell(shape, primary), repos_file))
    # THE CONTROL: a leaf that is not a git token at all never emitted one, so it never denied. It
    # separates "the emit fired" from "this gate denies any `cp`".
    assert run_gate(shell(f"cp -r {DQ}/c/backups/GitHub{DQ} restore", primary), repos_file) is None


@pytest.mark.parametrize(
    "tool,template,why",
    [
        # cmd.exe /c runs the quoted program; the default Git install path contains a space and MUST
        # be quoted, so this is the ordinary spelling and not an exotic one. Executed here:
        # cmd.exe /c '"C:\Program Files\Git\bin\git.exe" --version' printed a git version.
        ("Bash", "cmd /c {prog} -C {gated} reset --hard", "cmd /c dispatches the quoted program"),
        # PowerShell dot-source. Verified on pwsh 7.6.4 that `.` runs the executable, same as `&`.
        ("PowerShell", ". {prog} -C {gated} reset --hard", "dot-source dispatches it too"),
    ],
)
def test_the_two_fail_OPENS_the_reverted_PREDICATE_INTRODUCED_are_DENIED_again(
    primary: Path, repos_file: Path, tool: str, template: str, why: str
) -> None:
    """THE REVERT'S OWN JUSTIFICATION, AS AN ASSERTION RATHER THAN A COMMENT.

    The `Test-GitProgramPosition` predicate was withdrawn because it moved exactly these two shapes
    from DENY to ALLOW while `origin/main` denies both. That reason lived only in prose -- in the
    narrative block above and inside two failure strings -- so nothing would have reported it if the
    predicate came back. Every test that DOES red on the predicate reds on a FALSE-DENY row whose own
    text says to delete it, which means the suite's stated remedy, followed literally, lands both
    fail-opens green. These two rows are the missing half.

    Measured over the real hook, cwd = the governed repo, on `origin/main` and on this tree::

        cmd /c "<...>\\Git\\bin\\git.exe" -C <governed> reset --hard   DENY / DENY
        . "<...>\\Git\\bin\\git.exe" -C <governed> reset --hard        DENY / DENY

    and on the withdrawn predicate blob (`fb93c9ca`), ALLOW for both.

    WHEN THIS TEST REDS, a change has re-opened a hole `origin/main` closes. Do NOT delete the row.
    """
    prog = f"{DQ}C:\\Program Files\\Git\\bin\\git.exe{DQ}"
    gated = template.format(prog=prog, gated=primary)
    (
        assert_denied(
            run_gate(
                {"tool_name": tool, "tool_input": {"command": gated}, "cwd": str(primary)},
                repos_file,
            )
        ),
        f"{tool}: {why} -- this is the fail-open the revert exists to keep shut",
    )
    # THE CONTROL, and it is what stops the row degenerating into "the gate denies any `cmd /c`":
    # the identical line aimed at a path no repos file governs must ALLOW. Measured ALLOW on both
    # blobs, so a gate that denied unconditionally would fail here.
    ungoverned = template.format(prog=prog, gated=primary.parent / "NotGoverned")
    assert (
        run_gate(
            {
                "tool_name": tool,
                "tool_input": {"command": ungoverned},
                "cwd": str(primary.parent),
            },
            repos_file,
        )
        is None
    ), f"{tool}: an UNGOVERNED target must allow, or the deny above proves nothing"


# --- BACKLOG #1229 residual, FOURTH ROUND: the convention belongs to the INTERPRETER --------------
#
# The parametrised test above pins the OUTER host: a Bash tool call gets POSIX escape rules and a
# PowerShell tool call does not. That is right about the line the tool typed, and it was applied to
# something else as well -- the payload EXTRACTED from an interpreter flag on that line. A Bash tool
# call invoking pwsh therefore read a PowerShell payload under POSIX backslash rules, held open a span
# PowerShell had already closed, and blanked the gated command between it and a later quote.
#
# THE PROOF THAT ONE FLAG PER LINE CANNOT EXPRESS THIS is that the SAME CHARACTERS have opposite
# correct answers. Measured on this box with a payload that COMPUTES rather than echoes:
#
#     pwsh -NoProfile -Command '$d = "C:\Temp\" ; 111*3 ; Write-Output "x"'   -> printed 333: it RAN
#     bash -c            '$d = "C:\Temp\" ; expr 111 \* 3 ; echo "x"'        -> unexpected EOF: INERT
#     sh -c              (same)                                              -> unexpected EOF: INERT
#
# So the pwsh row must deny and the bash row must not, from one line, under one tool name. The
# convention now comes from Get-FlagOwner -- the program that owns the matched flag -- and the outer
# line keeps the outer host's rules, because the outer line really is the outer host's.

_INNER_STRADDLE = '$d = "C:\\Temp\\" ; {gated} ; Write-Output "x"'


@pytest.mark.parametrize(
    "tool,invocation,expect_deny,measured",
    [
        # The fail-open. All three read a PowerShell payload under the OUTER host's POSIX rules.
        ("Bash", "pwsh -Command", True, "333 printed: the middle statement RAN"),
        ("Bash", "pwsh -c", True, "333 printed: the middle statement RAN"),
        ("Bash", "powershell -Command", True, "333 printed: the middle statement RAN"),
        # The same characters where POSIX rules are CORRECT. Denying these would be a false deny, and
        # they are what stops the rows above from being satisfied by "always fail closed".
        ("Bash", "bash -c", False, "unexpected EOF: nothing parses, nothing runs"),
        ("Bash", "sh -c", False, "unexpected EOF: nothing parses, nothing runs"),
        # THE CONVERSE DIRECTION, and it is the half that proves the convention is not simply pinned
        # to the payload's own tool name either: a PowerShell tool call invoking bash used to apply
        # PowerShell rules to a POSIX payload, which denied a shape that cannot run.
        ("PowerShell", "bash -c", False, "unexpected EOF: nothing parses, nothing runs"),
        ("PowerShell", "sh -c", False, "unexpected EOF: nothing parses, nothing runs"),
        ("PowerShell", "pwsh -Command", True, "333 printed: the middle statement RAN"),
    ],
)
def test_the_escape_convention_of_an_EXTRACTED_payload_comes_from_its_interpreter(
    primary: Path, repos_file: Path, tool: str, invocation: str, expect_deny: bool, measured: str
) -> None:
    """Every row is pinned to whether the payload RUNS on the interpreter that receives it.

    ``measured`` records the observation rather than a previous verdict, for the reason the sibling
    matrix above gives: a row that asserted only "deny" would be satisfied by a gate that denies
    everything, and a row that asserted only "allow" by one that recurses into nothing.
    """
    payload = _INNER_STRADDLE.format(gated=f"git -C {primary} reset --hard")
    command = f"{invocation} {SQ}{payload}{SQ}"
    result = run_gate(
        {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(primary.parent)},
        repos_file,
    )
    if expect_deny:
        assert_denied(result), f"{tool}/{invocation}: {measured} -- the gate must see it"
    else:
        assert result is None, (
            f"{tool}/{invocation}: {measured} -- denying it would be a FALSE DENY"
        )


def test_the_escape_count_and_not_the_nesting_is_what_triggers_the_straddle(
    primary: Path, repos_file: Path
) -> None:
    """CONTROL for the matrix above: the same nesting with an EVEN backslash run, and with none.

    Both denied before this change and both deny after it, on either reading of the escape -- so a
    row from the matrix that moved has moved because of the ODD trailing run, not because the gate
    started or stopped objecting to ``pwsh -Command`` in general.
    """
    gated = f"git -C {primary} reset --hard"
    for payload in (
        '$d = "C:\\Temp\\\\" ; ' + gated + ' ; Write-Output "x"',  # EVEN run
        '$d = "C:/Temp" ; ' + gated + ' ; Write-Output "x"',  # no backslash at all
    ):
        assert_denied(
            run_gate(shell(f"pwsh -Command {SQ}{payload}{SQ}", primary.parent), repos_file)
        )
