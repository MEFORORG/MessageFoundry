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
