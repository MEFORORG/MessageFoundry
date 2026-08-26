# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Does the gate that is RUNNING match the gate that is in the repo?

Nothing answered this, and that gap is the root cause of every other defect found in the drift machinery.
The gate executes from an installed COPY under ``~/.claude/hooks/``; ``install-gate.ps1`` copies it with no
version, hash or marker, and its ``-Status`` printed an uncalibrated count of hook entries. So:

* Rule 4 was implemented, declared by the installer, and covered by tests -- and was absent from the
  installed script and from every matcher set. 85 tests passed the whole time.
* The reverse is worse and equally invisible: delete a rule from source and the stale installed copy keeps
  enforcing it forever, while every test correctly reports it gone.

These tests are LOCAL-MACHINE tests. On CI there is no installed gate and they skip -- which is honest,
because the drift they detect is a developer-box condition, not a repository one.

**What CI therefore does NOT guard**: installed-vs-source parity, wired-matcher correctness, and
unwired-rule detection. Only the source-only OPT_IN_TOOLS sanity check runs there. Say that plainly rather
than let three green-looking dots imply coverage.

Every test announces what it scanned BEFORE it can skip, so the reason is in the output either way. That
ordering is the whole mitigation and it is easy to undo by accident: a print placed after a skip never
runs, and the repo's pytest config carries no ``-rs``, so the skip reason would not be shown either. It
rendered as a bare ``sss.`` until this was fixed.

Parity is asserted only when the source script is COMMITTED. Mid-change the two are *supposed* to differ,
and a test that nagged on every edit would be re-run with ``-k`` until someone deleted it.

Parity is compared as CONTENT, not as bytes -- see :func:`content_hash`. A byte-exact hash asked a
question adjacent to the one this module exists to answer, and answered it wrongly on every Windows
checkout.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_GATE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
INSTALLED_GATE = Path.home() / ".claude" / "hooks" / "worktree_gate.ps1"

# Rules deliberately shipped unwired. Their ABSENCE from a matcher set is a decision, not drift; their
# presence in the script is not evidence that they fire. Keep this list short and justified -- it is the
# one place a rule may hide from the wiring assertion, so an unexplained entry here is a defect.
#
#   EnterWorktree (rule 4) -- opt-in via `install-gate.ps1 -EnterWorktreeGate`. It compounds with rule 2
#   to leave a primary-resident session no in-session path to isolation, and the transcript-loss defect it
#   guards was addressed upstream. See docs/SESSION-DRIFT-CONTROLS.md §4.
OPT_IN_TOOLS = {"EnterWorktree"}

TOOL_BRANCH = re.compile(r"\$tool\s+-(?:not)?in\s+@\(([^)]*)\)")
QUOTED = re.compile(r'"([^"]+)"')


def content_hash(data: bytes) -> str:
    """SHA-256 of the script's CONTENT: raw bytes with CRLF folded to LF.

    "Are these the same script?" and "are these the same bytes?" are different questions on Windows, and
    this module wants the first. ``core.autocrlf=true`` materialises a checkout with CRLF while git's own
    clean filter stores LF, and ``install-gate.ps1`` lays its copy down with ``Copy-Item``, which
    translates nothing -- so the installed copy carries whatever form the checkout that installed it had.
    A byte-exact hash therefore reported a difference that ``git status`` reported as clean, about one
    file, with neither instrument mentioning the other.

    Measured 2026-08-04: installed 51061 bytes / 0 CRLF / 805 LF, source 51866 bytes / 805 CRLF / 0 LF,
    identical after folding, and ``git hash-object`` agreeing with ``HEAD`` on both. No rule had been
    added, removed or changed -- there was nothing to report. The failure text nonetheless read "The
    RUNNING gate is not this checkout's script" and prescribed a re-install, which would have rewritten a
    machine-global file from whichever checkout happened to be current: the stale-checkout DOWNGRADE
    hazard, fired to fix nothing.

    WHY NOT ``git hash-object``, which would delegate "same content" to git and agree with ``git status``
    by construction: it is CONFIGURATION-DEPENDENT, and reproducing the same defect one level up is not a
    fix. Measured on this box, same file, same commit::

        git -c core.autocrlf=false hash-object scripts/hooks/worktree_gate.ps1 -> f6f87adfc8e1
        git -c core.autocrlf=true  hash-object scripts/hooks/worktree_gate.ps1 -> 58acc19367e0
        git rev-parse HEAD:scripts/hooks/worktree_gate.ps1                     -> 58acc19367e0

    It answers correctly here only because this box sets ``autocrlf=true``; under ``=false`` it reports
    drift for a new non-reason. Making it config-independent needs a ``.gitattributes eol=lf`` pin, which
    does not rewrite files already checked out -- so every one of the ~30 worktrees on this box would keep
    failing, with this same message, until each was renormalised by hand. Folding CRLF here depends on no
    configuration and no subprocess.

    WHAT THIS GIVES UP, stated rather than left to be discovered: a difference of line endings ALONE
    becomes invisible. That is not nothing. Eight ``-Reason @"`` here-strings (openers at 282, 377, 404,
    477, 533, 675, 738, 783) carry their own line endings into the deny text a user sees, so the CRLF and
    LF forms of the gate emit differently-whitespaced messages. Nothing reads those bytes today -- every
    assertion against them is a substring that never spans a line break -- and PowerShell parses both
    forms identically, so no rule can differ. If the gate ever grows an Authenticode block, an embedded
    self-hash, or a consumer that line-anchors a regex on a deny reason, byte-exactness becomes
    load-bearing and this function is where to revisit it.

    ``test_the_parity_check_still_detects_a_content_difference`` is the negative control for exactly this
    weakening; it is not decoration.
    """
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _code_lines(text: str) -> str:
    """``text`` with whole-line ``#`` comments dropped, so a text scan reads CODE and not prose."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def handled_tools(text: str) -> set[str]:
    """Tool names the gate BRANCHES on -- read from its code, never from a comment.

    ``TOOL_BRANCH`` is a text scan, and worktree_gate.ps1 writes rule 4's condition verbatim inside a
    comment as well as in the rule: ``$tool -in @("EnterWorktree")`` appears at :272 (deliberately, and
    it says so at :272-274) and again at :281 as the actual ``if``. A scan over the raw text therefore
    credits the gate with a rule on the strength of PROSE -- delete the ``if`` at :281 and this function
    still reports EnterWorktree handled, so ``test_the_opt_in_list_only_names_tools_the_gate_actually_has``
    goes on excusing an exemption for a rule that is gone. That test exists to make the exemption track
    the script rather than outlive it, and a comment-satisfied match is exactly how it outlives it.

    Measured 2026-08-04, source and installed copy alike: the returned set is unchanged by this filter
    (the same 10 tools, EnterWorktree included), because :281 is code and carries it. The filter costs
    nothing today; it removes the way this could lie tomorrow.

    LIMIT, stated rather than left to be discovered: only whole-line ``#`` comments are dropped. A
    ``<# ... #>`` block (the gate opens one at :1 and closes it at :33) and a trailing ``#`` after code
    on the same line are both invisible here, so a tool branch quoted inside either would still count.
    Neither holds one today -- the five ``$tool -in``/``-notin`` lines are 272, 281, 400, 435 and 701 --
    and a regex taught to recognise PowerShell's comment forms would just be a second, worse parser.
    """
    tools: set[str] = set()
    for group in TOOL_BRANCH.findall(_code_lines(text)):
        tools.update(QUOTED.findall(group))
    return tools


# The NAME shape of a launcher config dir: ~/.claude is the Desktop app, and every VS Code launcher on
# this box points CLAUDE_CONFIG_DIR at ~/.claude-account-<N> with N decimal. That is not inferred from the
# directory listing -- it is how the launchers BUILD the path: ~/claude-launchers/Launch-Claude-{1,2,3,4}
# .ps1 each assign a literal `.claude-account-<N>`, and Setup-GitHub-SignIn.ps1 assigns
# "...\.claude-account-$Account". A suffix after the number is therefore not an account, because nothing
# can launch from one.
#
# \A and \Z are IN THE PATTERN, not left to the call site. The end anchor is the entire predicate here --
# unanchored, `.match()` accepts ".claude-account-2.lock" on its prefix and `.search()` accepts it
# anywhere -- so a later call site written with `match` or `search` instead of `fullmatch` would silently
# re-admit the artifact this filter exists to exclude, and every test would stay green while it did.
# Anchoring here makes all three methods agree; test_the_launcher_name_predicate_* asserts that they do.
_ACCOUNT_DIR_NAME = re.compile(r"\A\.claude-account-\d+\Z")

# What a dir a session has actually launched from carries. Claude Code writes both on first use, so their
# presence is evidence of a LOGIN as opposed to a directory that merely has the right name. Measured
# 2026-08-04: ~/.claude and .claude-account-1/2/3/4 all carry both; .claude-account-2.lock carries
# NEITHER -- its entire contents are settings.json and settings.json.bak.
_LOGIN_MARKERS = (".claude.json", ".credentials.json")


def _account_candidates() -> list[Path]:
    """Everything the ``.claude-account-*`` glob turns up, before any judgement about what it is."""
    return sorted(Path.home().glob(".claude-account-*"))


def config_dirs() -> list[Path]:
    """Config dirs a session can LAUNCH from: ~/.claude plus the ~/.claude-account-<N> VS Code launchers.

    The glob alone was too wide, and the directory it over-matched was manufactured by this machinery
    itself. Measured 2026-08-04 on this box, ``.claude-account-2.lock``:

    * the directory itself was created 07-22 20:09, with nothing inside it predating 07-24 -- so it was
      PROBABLY created empty, which is an inference from the absence of older contents, not a reading;
    * its ``settings.json.bak`` was created 07-24 14:44, so the dir was already being wired at or before
      then. The ``settings.json`` file object dates from 07-29 13:32 and CANNOT date the first write:
      ``Write-Settings`` writes a temp and ``Move-Item``s it into place, replacing the file object on
      every run, so its creation time is always the LAST run. The ``.bak`` is overwritten in place, so
      its creation time is the FIRST run that found a settings.json to back up. The two writes still
      visible are 07-29 13:07 (carried by the ``.bak``'s mtime, which ``Copy-Item`` takes from the
      source) and 13:32 -- the same pair ``.claude-account-2`` carries, because ``install-gate.ps1``
      globs ``.claude-account-*`` too (:91) and wires both dirs in lockstep. Account-2 also holds a
      ``.bak`` from 07-17, so there were earlier runs than the visible pair on both sides;
    * it is 1079 bytes against account-2's 2072, and holds the three gate matcher entries and NOTHING
      else -- no ``.claude.json``, no ``.credentials.json``, no ``sessions/``, no ``projects/``, and no
      SessionStart selfheal hook (``install-selfheal.ps1`` takes ``-ConfigDir`` as a mandatory single
      value, so it never globbed and never reached this dir).

    So the gate wiring the tests were reading back out of it was written INTO it by the installer's own
    glob, and matched only because both globs are wrong in the same way. It passes today; it is a stale
    snapshot the moment real wiring changes, and the suite would then go red pointing at a directory
    nobody launches from -- the reader's next move being a re-install, i.e. the stale-checkout DOWNGRADE
    hazard :func:`content_hash` documents, fired to fix nothing.

    WHY A NAME SHAPE AND NOT ``not name.endswith(".lock")``: a blocklist excludes the one artifact that
    happens to exist and lets the next one through -- ``.bak``, ``.old``, ``.disabled``, ``-copy``, a
    dated backup. The launcher name shape is a positive rule that can be checked against the launchers.

    RISK, stated rather than left to be discovered. Excluding a directory from a wiring check means a
    genuinely UN-WIRED launcher can hide behind a name this filter rejects, and it would hide silently --
    an un-wired gate is exactly the condition this module exists to surface. AT LEAST these shapes are at
    risk -- a named account (``.claude-account-alpha``), a suffixed one (``.claude-account-2b``,
    ``.claude-account-2-work``), or a config dir off the pattern entirely (``.claude-work``, or any
    ``CLAUDE_CONFIG_DIR`` pointing outside ``~``, which neither this predicate nor the glob before it
    ever saw).

    AND ONE MORE THAT IS LIVE ON THIS BOX RIGHT NOW, which is why the enumeration above is written as
    "at least": a RIGHT-shaped name carrying no ``settings.json`` at all. The trailing filter on the
    return below drops it before either instrument here sees it, and that filter predates this change.
    ``.claude-account-4`` is in exactly that state -- both login markers written 2026-08-04 19:37, built
    by ``~/claude-launchers/Launch-Claude-4.ps1``, and NO settings.json, so no gate wiring whatsoever.
    It is a live launcher with no gate, and nothing in this module reports it. :func:`unwired_launchers`
    exists to make that loud rather than leaving it to this docstring.

    That risk is guarded, not just admitted, in two places -- because a shrinking config-dir list makes
    ``test_every_non_optional_rule_is_wired_in_every_config_dir`` vacuously easier to pass, which is the
    green-because-we-stopped-looking failure this suite exists to prevent:

    1. :func:`excluded_config_dirs` is PRINTED by both tests that scan, so an exclusion appears in the
       output of the very run it changed rather than being inferred from a count that got smaller.
    2. ``test_nothing_excluded_from_the_wiring_scan_is_a_live_login`` asserts every exclusion made BY
       NAME is inert, by a signal INDEPENDENT of that name (:data:`_LOGIN_MARKERS`). A wrongly-excluded
       dir that anything actually logs in from fails that test by the evidence it cannot help leaving
       behind. Scoped deliberately: it does NOT cover the settings.json filter above, which is why
       :func:`unwired_launchers` is reported separately.
    """
    home = Path.home()
    found = [home / ".claude"] + [
        d for d in _account_candidates() if _ACCOUNT_DIR_NAME.fullmatch(d.name)
    ]
    return [d for d in found if (d / "settings.json").is_file()]


def excluded_config_dirs() -> list[Path]:
    """Dirs the glob found, that carry a settings.json, and that :func:`config_dirs` refuses to judge.

    Only the ones with a ``settings.json`` -- a name-shape reject with no settings file was never in the
    scanned set and dropping it changes nothing. These are precisely the dirs whose wiring stopped being
    checked, which is the set a reader has to see to audit the exclusion.
    """
    return [
        d
        for d in _account_candidates()
        if not _ACCOUNT_DIR_NAME.fullmatch(d.name) and (d / "settings.json").is_file()
    ]


def unwired_launchers() -> list[Path]:
    """Launcher-shaped dirs something LOGS IN from that carry no ``settings.json`` -- so no gate at all.

    This is the gap the name-shape filter does NOT cause and does NOT cover. :func:`config_dirs` has
    always ended with ``(d / "settings.json").is_file()``, which silently drops a dir that has every
    other mark of a live launcher. Such a dir is not merely unjudged: with no settings.json there is no
    ``PreToolUse`` wiring, so the gate does not run there AT ALL, which is a strictly worse condition
    than the stale-snapshot case this module was changed to fix.

    Measured 2026-08-04: ``.claude-account-4`` is in this state -- ``.claude.json`` and
    ``.credentials.json`` both written 19:37, ``~/claude-launchers/Launch-Claude-4.ps1`` builds it, and
    no settings.json.

    REPORTED, NOT ASSERTED, deliberately. Whether a launcher should be wired is the box owner's decision
    -- an unused profile is a legitimate reason to leave one alone -- and a test that goes red over a
    machine-configuration choice is the crying-wolf failure this suite exists to avoid. Printing it in
    the run that scans makes it impossible to not-know, which is the part that was missing. Promote this
    to an assertion the moment "every launcher is wired" becomes a rule rather than an observation.
    """
    return [
        d
        for d in _account_candidates()
        if _ACCOUNT_DIR_NAME.fullmatch(d.name)
        and not (d / "settings.json").is_file()
        and looks_like_a_live_login(d)
    ]


def looks_like_a_live_login(d: Path) -> bool:
    """Is this a dir something actually launches Claude Code from, judged WITHOUT reference to its name?

    The name is what the exclusion turns on, so re-using the name here would make the guard agree with
    the thing it is guarding by construction. These files are written by Claude Code itself on first use.
    """
    return any((d / marker).is_file() for marker in _LOGIN_MARKERS)


def wired_matchers(settings: Path) -> set[str]:
    """Tool names reachable through a PreToolUse entry whose command names the gate."""
    try:
        data = json.loads(settings.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return set()
    tools: set[str] = set()
    for entry in data.get("hooks", {}).get("PreToolUse", []) or []:
        cmds = " ".join(str(h.get("command", "")) for h in entry.get("hooks", []) or [])
        if "worktree_gate.ps1" not in cmds:
            continue
        tools.update(t for t in str(entry.get("matcher", "")).split("|") if t)
    return tools


def source_is_committed() -> bool:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", str(SOURCE_GATE.relative_to(ROOT))],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and not out.stdout.strip()


def _source_rel() -> str:
    """The gate's repo-relative posix path -- the form ``git show <ref>:<path>`` wants."""
    return SOURCE_GATE.relative_to(ROOT).as_posix()


def drift_verdict(installed: str, source: str, main: str | None) -> str:
    """WHICH copy is the odd one out, decided rather than left to the reader.

    The assertion below already told the reader to work out which copy was older before reinstalling,
    and warned that installing from an older checkout DOWNGRADES a machine-global file. That warning
    was correct and three seats skipped it anyway, because it asks for a `git log` under time pressure.
    One of them reinstalled a gate that was already correct and left 121 worktrees ungoverned for some
    minutes. So this computes the attribution instead of requesting it.

    PURE, and separated from the git read on purpose: the verdict is what needs testing, and a test
    that had to mutate the installed gate to reach it would be taking a machine-global file out from
    under every concurrent session.

    ``main`` is the content hash of the same path at ``origin/main``, or None when it could not be
    read. A None says so in the text -- an attribution that quietly disappears when its input is
    missing would be worse than none, because the message would read as complete.
    """
    if main is None:
        return (
            "ATTRIBUTION UNAVAILABLE: origin/main's copy of this file could not be read, so which "
            "side drifted is NOT established here. Work it out by hand before acting."
        )
    if installed == main and source != main:
        return (
            "ATTRIBUTED: THE INSTALLED GATE MATCHES origin/main. YOUR CHECKOUT IS THE ODD ONE OUT. "
            "Either it is behind (fetch and rebase), or it is legitimately CHANGING the gate, in "
            "which case this is expected until the change lands and is installed. DO NOT REINSTALL "
            "FROM HERE -- the installed copy is current and installing an older one downgrades it "
            "for every session on this box."
        )
    if source == main and installed != main:
        return (
            "ATTRIBUTED: YOUR CHECKOUT MATCHES origin/main AND THE INSTALLED COPY DOES NOT. This is "
            "the case this test exists for: the running gate is not what the repository says it "
            "should be. Diff them, and only then reinstall from a PLAIN terminal."
        )
    if installed != main and source != main:
        return (
            "ATTRIBUTED: NEITHER COPY MATCHES origin/main. Nothing here can say which is intended, "
            "and that is the strongest of the three readings -- treat it as unexplained until you "
            "have diffed both against origin/main by hand."
        )
    # installed == source == main is not a drift at all; the assertion cannot have fired.
    return "NO DRIFT: both copies match origin/main."


def main_content_hash(rel_path: str) -> str | None:
    """``content_hash`` of ``rel_path`` at ``origin/main``, or None if it cannot be read.

    Returns None rather than raising: this is diagnostics attached to a failure, and turning a
    diagnostics problem into a different failure would obscure the one being reported.
    """
    try:
        out = subprocess.run(
            ["git", "show", "origin/main:" + rel_path],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout:
        return None
    return content_hash(out.stdout)


def test_the_installed_gate_matches_the_committed_source() -> None:
    # Announce the target BEFORE any skip. A print after a skip never runs, and with no -rs in the pytest
    # config the reason is not shown either -- the file then renders as a bare "sss." on CI, which is the
    # exact skip-reads-as-pass ambiguity this suite exists to remove.
    print(f"scanning: {INSTALLED_GATE} vs {SOURCE_GATE}")
    if not INSTALLED_GATE.is_file():
        pytest.skip(
            f"SKIP (nothing compared): no gate installed at {INSTALLED_GATE} -- nothing is enforcing"
        )
    if not source_is_committed():
        pytest.skip(
            f"SKIP (nothing compared): {SOURCE_GATE.relative_to(ROOT)} has uncommitted changes -- the "
            f"installed copy is SUPPOSED to differ mid-edit. Re-run after committing."
        )

    installed_bytes = INSTALLED_GATE.read_bytes()
    source_bytes = SOURCE_GATE.read_bytes()
    installed = content_hash(installed_bytes)
    source = content_hash(source_bytes)

    # Print BOTH bases. The content hashes are what the assertion turns on; the raw byte shas and the
    # eol-only flag are diagnostics that keep "differs in content" and "differs in line endings"
    # distinguishable in the output. Collapsing them to one number is how the two got confused.
    print(f"compared (content, CRLF folded): installed={installed[:12]} source={source[:12]}")
    print(
        f"diagnostic raw bytes: installed={hashlib.sha256(installed_bytes).hexdigest()[:12]} "
        f"source={hashlib.sha256(source_bytes).hexdigest()[:12]} "
        f"line-endings-only difference={installed_bytes != source_bytes and installed == source}"
    )

    assert installed == source, (
        f"CONTENT DRIFT: the RUNNING gate is not this checkout's script.\n"
        f"  installed: {INSTALLED_GATE}  content={installed[:12]}\n"
        f"  source   : {SOURCE_GATE}  content={source[:12]}\n"
        # Computed, not requested. The paragraph below already tells the reader to work out which
        # copy is older first; that instruction is correct and was skipped three times in one day,
        # so the answer is worked out here instead. Evaluated only when the assertion fires.
        f"{drift_verdict(installed, source, main_content_hash(_source_rel()))}\n"
        f"Line endings are folded out of this comparison, so CRLF vs LF alone cannot have produced it. "
        f"That is the only difference the fold hides, which is NOT the same as this being a difference "
        f"in rules or logic: the fold rewrites \\r\\n and nothing else, so at least three non-rule "
        f"causes still trip this assertion -- a UTF-8 BOM on one side, a dropped final newline, and "
        f"CR-only (lone \\r) line endings. A re-install would clear any of the three -- install-gate.ps1 "
        f"copies the bytes verbatim -- but it clears a genuine rule difference the same way, so the fact "
        f"that it worked tells you NOTHING about which one you had. Diff the two files and confirm the "
        f"difference is in the rules before you treat this as staleness.\n"
        f"Until the installed copy is replaced, rules added or removed in source have NO EFFECT and the "
        f"rest of the suite still passes.\n"
        f"WORK OUT WHICH COPY IS OLDER FIRST. Installing from a checkout older than the installed gate "
        f"DOWNGRADES a machine-global file for every session on this box:\n"
        f"    git log --oneline -5 -- {SOURCE_GATE.relative_to(ROOT).as_posix()}\n"
        f"Only once THIS checkout is confirmed to be the newer of the two, from a PLAIN terminal:\n"
        f"    pwsh -NoProfile -File scripts\\worktree\\install-gate.ps1"
    )


def test_the_parity_check_still_detects_a_content_difference() -> None:
    """NEGATIVE CONTROL for the assertion above, and the whole justification for weakening it.

    Folding CRLF out of the comparison is precisely the edit that could turn a false RED into a false
    GREEN -- a gate that is genuinely stale, reported in sync. So prove the weakened predicate still
    detects what it exists to detect, and prove the tolerance is not vacuous while doing it.

    Exercised against the REAL gate's bytes, and directly against the predicate rather than by mutating
    the installed copy: that file is machine-global and every PreToolUse hook on this box reads it, so a
    test may not take it out from under a concurrent session. Same reasoning, same shape as
    ``test_installed_coord_hooks.test_the_resolution_check_can_detect_a_missing_script``.
    """
    body = SOURCE_GATE.read_bytes().replace(b"\r\n", b"\n")
    crlf = body.replace(b"\n", b"\r\n")

    # Guard the guard: if these two were the same bytes, the tolerance assertion below would hold for a
    # trivial reason and prove nothing about newline folding.
    assert crlf != body, "the CRLF and LF encodings are identical -- this control would be vacuous"
    print(f"eol probes differ in bytes: LF={len(body)} CRLF={len(crlf)}")
    assert content_hash(crlf) == content_hash(body), (
        "re-encoding line endings changed the content hash -- the tolerance this module documents does "
        "not actually hold"
    )

    # A rule addition is the exact drift the module exists to catch, and the case the owner named.
    added_rule = body + b'\nif ($tool -in @("MFTestOnlyRule")) { Write-Deny -Rule "99" }\n'
    assert content_hash(added_rule) != content_hash(body), (
        "adding a rule did not change the content hash -- the parity check is decoration"
    )

    # And the subtle end of the range: one character inside an existing rule, no line added or removed.
    #
    # Anchor on the whole `if (...) {` line, not on the bare condition. The condition alone occurs TWICE
    # in the gate -- :272 inside a comment that quotes it deliberately, :281 as the rule -- and
    # `replace(..., 1)` takes the FIRST, so this probe used to mutate a comment while its own output
    # called that "an existing rule". The hash moved either way, which is why the control passed and
    # nothing said so. Appending `) {` makes the literal unique to the code, and the count below proves
    # that rather than asserting it in prose.
    rule = b'if ($tool -in @("EnterWorktree")) {'
    occurrences = body.count(rule)
    assert occurrences == 1, (
        f"rule 4's `if` line occurs {occurrences} times in the gate, not once. At 0 the rule syntax "
        f"moved and this probe now mutates nothing; above 1 it cannot say WHICH occurrence it hit, "
        f"which is the ambiguity it was re-anchored to escape. Fix this control."
    )
    flipped = body.replace(rule, b'if ($tool -in @("EnterWorktreX")) {', 1)
    assert content_hash(flipped) != content_hash(body), (
        "a one-character edit to rule 4's `if` condition did not change the content hash"
    )
    print(
        "content differences still detected: rule added, and one character changed inside rule 4's "
        "`if` condition line -- the code, not the comment that quotes it"
    )


def test_every_wired_matcher_names_a_tool_the_gate_handles() -> None:
    """The inverse drift: a matcher for a tool the script ignores burns a pwsh subprocess on every call,
    and -- worse -- reads as coverage that does not exist."""
    dirs = config_dirs()
    print(f"scanning {len(dirs)} config dir(s) against {INSTALLED_GATE}")
    print(
        f"  not judged (not a launcher name): {[d.name for d in excluded_config_dirs()] or 'none'}"
    )
    # A DIFFERENT gap from the one above, printed beside it so the two are never conflated: these carry
    # no settings.json at all, so the gate does not run there. Not caused by the name filter.
    print(
        f"  LAUNCHER WITH NO GATE (no settings.json): {[d.name for d in unwired_launchers()] or 'none'}"
    )
    if not dirs:
        pytest.skip("SKIP (nothing scanned): no Claude config dirs on this box -- nothing is wired")
    if not INSTALLED_GATE.is_file():
        pytest.skip(
            f"SKIP (nothing scanned): no gate at {INSTALLED_GATE} -- matchers have nothing to be judged "
            f"against"
        )

    handled = handled_tools(INSTALLED_GATE.read_text(encoding="utf-8"))
    print(f"compared against {len(handled)} rule(s) in the INSTALLED gate")
    stray: dict[str, set[str]] = {}
    for d in dirs:
        wired = wired_matchers(d / "settings.json")
        print(f"  {d.name}: {sorted(wired) or '(none)'}")
        if extra := wired - handled:
            stray[d.name] = extra
    assert not stray, f"matchers for tools the installed gate never inspects: {stray}"


def test_every_non_optional_rule_is_wired_in_every_config_dir() -> None:
    """A rule the script implements but no matcher names NEVER FIRES, and nothing says so. This is the
    check that would have caught rule 4 on day one -- the repo-side wiring test could not, because it
    compares the installer to the script and never looks at what is actually installed."""
    dirs = config_dirs()
    print(
        f"scanning {len(dirs)} config dir(s); opt-in (absence is not drift): {sorted(OPT_IN_TOOLS)}"
    )
    # An exclusion makes this assertion easier to pass, so it is printed in the same breath as the count
    # it reduced. A number that got smaller looks like an improvement; the names say what was dropped.
    print(
        f"  not judged (not a launcher name): {[d.name for d in excluded_config_dirs()] or 'none'}"
    )
    # A DIFFERENT gap from the one above, printed beside it so the two are never conflated: these carry
    # no settings.json at all, so the gate does not run there. Not caused by the name filter.
    print(
        f"  LAUNCHER WITH NO GATE (no settings.json): {[d.name for d in unwired_launchers()] or 'none'}"
    )
    if not dirs:
        pytest.skip("SKIP (nothing scanned): no Claude config dirs on this box -- nothing is wired")
    if not INSTALLED_GATE.is_file():
        pytest.skip(
            f"SKIP (nothing scanned): no gate at {INSTALLED_GATE} -- no live rule set to wire"
        )

    handled = handled_tools(INSTALLED_GATE.read_text(encoding="utf-8"))
    required = handled - OPT_IN_TOOLS
    print(f"required in every dir: {sorted(required)}")

    unwired: dict[str, list[str]] = {}
    for d in dirs:
        if missing := sorted(required - wired_matchers(d / "settings.json")):
            unwired[d.name] = missing
    assert not unwired, (
        f"rules implemented by the installed gate but wired in no matcher, so they never fire: {unwired}. "
        f"Re-run install-gate.ps1 from a plain terminal, or add the tool to OPT_IN_TOOLS with a reason."
    )


def test_nothing_excluded_from_the_wiring_scan_is_a_live_login() -> None:
    """GUARD ON THE EXCLUSION. Narrowing :func:`config_dirs` shrinks the set the two assertions above
    scan, and a smaller set is easier to pass -- so prove every dir dropped is one nothing launches from.

    The check deliberately does not consult the NAME, which is what the exclusion turns on; it reads the
    files Claude Code writes into a config dir on first use. A dir excluded by name that is nonetheless
    logged into fails here, which is the only way a wrongly-excluded launcher gets to announce itself.

    Passes vacuously when nothing is excluded, and says so in its output rather than leaving a bare dot.
    """
    excluded = excluded_config_dirs()
    print(f"excluded from the wiring scan: {[d.name for d in excluded] or 'none'}")
    print(f"judged as launchers: {[d.name for d in config_dirs()]}")

    live = {d.name: sorted(m for m in _LOGIN_MARKERS if (d / m).is_file()) for d in excluded}
    for name, markers in live.items():
        print(f"  {name}: login markers {markers or '(none -- inert)'}")

    suspects = {name: markers for name, markers in live.items() if markers}
    assert not suspects, (
        f"a directory excluded from the wiring scan by NAME carries the files Claude Code writes into a "
        f"config dir it is logged into: {suspects}. Something may launch from it, in which case its gate "
        f"wiring stopped being checked the moment it was excluded and nothing else looks at it. Either "
        f"it is a real launcher -- widen _ACCOUNT_DIR_NAME to admit its shape -- or it is a stale copy "
        f"of one, in which case say which and delete it. Do NOT relax this assertion to make it quiet."
    )


def test_the_launcher_name_predicate_accepts_launchers_and_rejects_the_artifact() -> None:
    """NEGATIVE CONTROL for the name shape, and the record of what it gives up.

    A filter is only evidence if it has been shown to reject the class it was written for AND to keep the
    class it must not touch. Exercised against name strings, not against ~ -- the real directories are
    machine-global and a test may not create or remove one to make its point.

    The rejected group's second half is the RISK from :func:`config_dirs` written down as a fact instead
    of as prose: these are launcher-ish names this predicate drops. If one of them ever becomes a real
    config dir, this test is the thing that names it, and widening the regex is then the fix -- not
    deleting the case.
    """
    accepted = [".claude-account-1", ".claude-account-2", ".claude-account-3", ".claude-account-42"]
    rejected = [
        ".claude-account-2.lock",  # the measured artifact -- an empty dir the installer's glob wired
        ".claude-account-2.bak",  # the next artifact shape, which a `.lock` blocklist would have missed
        ".claude-account-2-old",
        ".claude-account-alpha",  # KNOWN COST: a named account would be wrongly excluded
        ".claude-account-2b",  # KNOWN COST: a suffixed account would be wrongly excluded
    ]

    for name in accepted:
        assert _ACCOUNT_DIR_NAME.fullmatch(name), f"{name} is a launcher shape and must be judged"
    for name in rejected:
        assert not _ACCOUNT_DIR_NAME.fullmatch(name), f"{name} must not be judged as a launcher"

    # GUARD THE GUARD. Everything above applies the pattern with fullmatch, so it proves nothing about
    # what happens if a future call site reaches for match or search instead -- and on an unanchored
    # pattern both would readmit the artifact through its launcher-shaped prefix. The \A and \Z live in
    # the pattern precisely so the method cannot matter; assert the three agree rather than trust it.
    artifact = ".claude-account-2.lock"
    for method in (_ACCOUNT_DIR_NAME.fullmatch, _ACCOUNT_DIR_NAME.match, _ACCOUNT_DIR_NAME.search):
        assert not method(artifact), (
            f"{method.__name__}({artifact!r}) matched: the pattern lost an anchor, so applying it any "
            f"way other than fullmatch now readmits the artifact on its prefix"
        )
    # And prove that agreement is not the trivial kind, where the pattern matches nothing at all.
    assert _ACCOUNT_DIR_NAME.search(".claude-account-1"), (
        "the pattern matches no launcher name under search either -- the check above is vacuous"
    )
    print(f"accepted {accepted}; rejected {rejected} (last two are the documented cost)")


def test_the_opt_in_list_only_names_tools_the_gate_actually_has() -> None:
    """Guard the exemption. A stale name in OPT_IN_TOOLS would silently excuse a future rule that happened
    to reuse it -- the exemption must track the script, not outlive it."""
    handled = handled_tools(SOURCE_GATE.read_text(encoding="utf-8"))
    print(f"opt-in: {sorted(OPT_IN_TOOLS)}; source handles: {sorted(handled)}")
    assert handled >= OPT_IN_TOOLS, (
        f"OPT_IN_TOOLS names {sorted(OPT_IN_TOOLS - handled)}, which the gate no longer implements"
    )


# --- the drift attribution (BACKLOG #1367) ----------------------------------------
#
# Driven against the PURE verdict function with injected hashes. The alternative -- mutating the
# installed gate to produce each case -- would take a machine-global file out from under every
# concurrent session on this box, which is the same reasoning the negative control above gives for
# testing its predicate directly rather than the installed copy.

_INSTALLED, _CHECKOUT, _MAIN, _THIRD = "aaa", "bbb", "ccc", "ddd"


def test_the_verdict_blames_the_checkout_when_the_installed_copy_matches_main() -> None:
    """The false alarm three seats acted on. A behind checkout, or one legitimately CHANGING the gate,
    both land here -- and both must be told NOT to reinstall, because installing an older copy
    downgrades a machine-global file for every session."""
    text = drift_verdict(installed=_MAIN, source=_CHECKOUT, main=_MAIN)
    assert "YOUR CHECKOUT IS THE ODD ONE OUT" in text
    assert "DO NOT REINSTALL" in text


def test_the_verdict_blames_the_installed_copy_when_the_checkout_matches_main() -> None:
    """The case the test exists for: the running gate is not what the repository says it should be."""
    text = drift_verdict(installed=_INSTALLED, source=_MAIN, main=_MAIN)
    assert "THE INSTALLED COPY DOES NOT" in text
    assert "DO NOT REINSTALL" not in text  # here a reinstall IS the remedy, once diffed


def test_the_verdict_refuses_to_choose_when_neither_side_matches_main() -> None:
    text = drift_verdict(installed=_INSTALLED, source=_CHECKOUT, main=_THIRD)
    assert "NEITHER COPY MATCHES" in text


def test_the_verdict_says_so_rather_than_guessing_when_main_cannot_be_read() -> None:
    """THE BRANCH MOST LIKELY TO BE DROPPED FOR TIDINESS, AND THE ONE THAT MUST NOT BE.

    A missing fetch, a detached ref and a network-less runner all land here. If this degraded into
    silently picking one of the other three readings, the message would look complete while naming a
    culprit nothing established -- which is a worse failure than the one this attribution fixes,
    because a computed-looking verdict is trusted more than a request to go and check.
    """
    text = drift_verdict(installed=_INSTALLED, source=_CHECKOUT, main=None)
    assert "ATTRIBUTION UNAVAILABLE" in text
    assert "NOT established" in text
    # It must not blame either side.
    assert "ODD ONE OUT" not in text
    assert "THE INSTALLED COPY DOES NOT" not in text


def test_the_verdict_branches_are_distinguishable_from_each_other() -> None:
    """A control on the four above: they are only worth asserting if they differ. Four branches that
    returned the same text would pass every test in this block."""
    texts = [
        drift_verdict(_MAIN, _CHECKOUT, _MAIN),
        drift_verdict(_INSTALLED, _MAIN, _MAIN),
        drift_verdict(_INSTALLED, _CHECKOUT, _THIRD),
        drift_verdict(_INSTALLED, _CHECKOUT, None),
    ]
    assert len(set(texts)) == 4, f"branches collapsed: {len(set(texts))} distinct of 4"


def test_the_failure_message_actually_carries_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """WIRING, not verdict. The five tests above prove ``drift_verdict`` is correct; none of them
    proves the assertion CALLS it. A typo in the call site, or a later edit dropping the interpolation,
    leaves every one of them green while the message loses the attribution -- which is the whole fix.

    Drives the real assertion by pointing INSTALLED_GATE at a TEMPORARY copy with altered bytes. The
    machine-global file is never read for this and never written: every PreToolUse hook on this box
    reads that path, and a test may not take it out from under a concurrent session.
    """
    import tests.test_gate_installed_parity as mod

    fake = tmp_path / "worktree_gate.ps1"
    fake.write_bytes(SOURCE_GATE.read_bytes() + b"\n# drift planted by a test\n")
    monkeypatch.setattr(mod, "INSTALLED_GATE", fake)

    with pytest.raises(AssertionError) as caught:
        mod.test_the_installed_gate_matches_the_committed_source()

    text = str(caught.value)
    assert "CONTENT DRIFT" in text, "the assertion fired but the message is not the drift message"
    # The planted copy matches neither side, so the verdict must be one of the attributed readings --
    # asserted as "some verdict is present", because which one depends on this checkout's distance
    # from origin/main, and pinning that would make this test pass or fail on the tree it runs in.
    assert any(
        marker in text for marker in ("ATTRIBUTED:", "ATTRIBUTION UNAVAILABLE", "NO DRIFT:")
    ), f"the failure message carries no attribution at all:\n{text[:400]}"
