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


def config_dirs() -> list[Path]:
    """Every Claude config dir on this box: ~/.claude plus the ~/.claude-account-* VS Code launchers."""
    home = Path.home()
    found = [home / ".claude"] + sorted(home.glob(".claude-account-*"))
    return [d for d in found if (d / "settings.json").is_file()]


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


def test_the_opt_in_list_only_names_tools_the_gate_actually_has() -> None:
    """Guard the exemption. A stale name in OPT_IN_TOOLS would silently excuse a future rule that happened
    to reuse it -- the exemption must track the script, not outlive it."""
    handled = handled_tools(SOURCE_GATE.read_text(encoding="utf-8"))
    print(f"opt-in: {sorted(OPT_IN_TOOLS)}; source handles: {sorted(handled)}")
    assert handled >= OPT_IN_TOOLS, (
        f"OPT_IN_TOOLS names {sorted(OPT_IN_TOOLS - handled)}, which the gate no longer implements"
    )
