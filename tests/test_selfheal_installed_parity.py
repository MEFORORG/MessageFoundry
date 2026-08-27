# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Is the worktree-selfheal payload that RUNS the one in this checkout?

BACKLOG #1019. ``install-selfheal.ps1`` lays the SessionStart backstop down as an installed COPY:
``Copy-Item`` from ``$PSScriptRoot`` to ``$HookPath``, whose default is ``~/.claude-hooks/worktree-
selfheal.ps1``. The installer takes ``-ConfigDir`` as a MANDATORY single value and never globs, so what
it writes per run is the WIRING for one config dir -- the payload itself is one shared, account-agnostic
file that every config dir's SessionStart command names. One copy therefore governs every session on the
box at once, and it is the copy that runs ``git checkout`` on the shared primary unattended.

**Nothing reported drift in it.** That absence is the item. Measured 2026-08-04: the installed payload was
1376 folded bytes adrift of ``scripts/worktree/worktree-selfheal.ps1`` and no instrument on this box said
so -- not the suite, not the installer (it has no ``-Status``), not ``git status``, which only ever sees
the source side. It is in sync as this module lands (folded sha ``c41c70ecf885``, 9891 folded / 10050 raw
on both sides) because the owner re-ran the installer from a plain terminal, which is a one-off human act
and not a control. Drift runs both ways and the quiet direction is the bad one: an edit to the source has
no effect until someone re-installs, and a check DELETED from the source keeps firing until then, with
``tests/test_worktree_selfheal_wiring.py`` correctly green throughout -- it drives the SOURCE script.

WHY A SEPARATE MODULE from ``test_worktree_selfheal_wiring.py``, which already covers this hook. That
module carries a module-level ``skipif(shutil.which("pwsh") is None)`` because MOST of its tests run the
script or the installer as a pwsh subprocess. That gate is right for them and wrong for this test, which
executes nothing -- it reads two files. The over-gating already bites that module's own
``test_both_installers_carry_the_same_refusal`` (:164), a pure two-``read_text`` substring comparison
skipped for want of a shell it never invokes -- so this is an observed cost, not a hypothetical one.
Hosting this test there would attach the same unrelated skip to it, and on any box or CI leg without
PowerShell 7
the parity check would silently stop running while the file still reported green. That is precisely the
skip-reads-as-pass failure this family of tests exists to remove, so it does not get to be introduced by
where the test was filed. The two modules also have opposite postures: that one is hermetic (tmp repos,
synthetic HOME, nothing real touched), this one reads the real ``~/.claude-hooks`` and is a LOCAL-MACHINE
test. ``test_gate_installed_parity.py`` and ``test_installed_coord_hooks.py`` are likewise one module per
installed mechanism; this is the third.

LOCAL-MACHINE TESTS. CI installs nothing, so the parity assertion skips there and says so. **What CI
therefore does not guard is exactly this property** -- installed-vs-source parity is a developer-box
condition, not a repository one. The negative controls below DO run everywhere, because they exercise the
predicate against source bytes.

Every test PRINTS what it compares BEFORE it can skip. A print placed after a skip never runs, and the
repo's pytest config carries no ``-rs`` (``addopts`` is ``--timeout=60 --timeout-method=thread``), so the
reason would not be shown either -- the run renders as a bare ``s`` and "nothing was compared" becomes
indistinguishable from "the comparison passed".

This module NEVER runs ``install-selfheal.ps1`` and never writes to ``~``. The installer refuses under
``CLAUDECODE`` by design, its remedy is a plain-terminal human act, and the payload it manages is read by
every other session on the box.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "worktree" / "worktree-selfheal.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-selfheal.ps1"

# The default install location is PARSED out of the installer, not restated here. A test carrying its own
# copy of a path cannot notice the installer moving away from it: it would go on comparing the file at the
# old location -- which stays in sync forever, because nothing writes to it any more -- and report parity
# for a payload nothing runs. Same reasoning as test_installed_coord_hooks.MARKERS/PAYLOADS.
#
# Line-anchored (``(?m)^\s*``) so a commented-out or illustrative line cannot become the source of truth:
# ``re.search`` takes the first hit anywhere in the file and a ``#`` prefix would otherwise satisfy it.
_HOOK_PATH_DEFAULT = re.search(
    r"(?m)^\s*if \(-not \$HookPath\).*Join-Path \$homeDir '([^']+)'",
    INSTALLER.read_text(encoding="utf-8"),
)
INSTALLER_DEFAULT_REL: str | None = _HOOK_PATH_DEFAULT.group(1) if _HOOK_PATH_DEFAULT else None

# A SessionStart command names its script as a double-quoted, single-quoted, or bare path. All four
# commands wired on this box today are double-quoted and install-selfheal.ps1:96 only ever emits that
# form, so the other two branches are hardening rather than a live need.
#
# The single-quote branch is NOT redundant with the bare branch, which is the trap: without it,
# `-File 'C:\q\worktree-selfheal.ps1'` matches on the BARE alternative and carries the leading
# apostrophe into the path, which then never resolves. A non-existent path is filtered out downstream as
# "nothing installed here" -- so a config dir running a single-quoted, non-default copy would drop out of
# the comparison entirely and the test would pass on the installer default alone, auditing a file that is
# not the one executing. That is exactly the substitution wired_payloads() exists to prevent.
_PAYLOAD_IN_COMMAND = re.compile(
    r'"([^"]*worktree-selfheal\.ps1)"'
    r"|'([^']*worktree-selfheal\.ps1)'"
    r"|(\S*worktree-selfheal\.ps1)"
)


def content_hash(data: bytes) -> str:
    """SHA-256 of the payload's CONTENT: raw bytes with CRLF folded to LF.

    Deliberately the SAME basis as ``test_gate_installed_parity.content_hash`` and
    ``test_installed_coord_hooks.content_hash``. The reasoning and the measurements behind choosing
    content over bytes are stated once, in the first of those; the consequence here is the same
    mechanism -- ``install-selfheal.ps1`` copies the payload with ``Copy-Item`` (:57), which translates
    nothing, so the installed file carries whatever line endings the checkout that installed it had. On a
    box with ``core.autocrlf=true`` a byte-exact digest therefore reports a difference that ``git status``
    reports as clean, about a file with no content change at all, and the prescribed remedy for that false
    red is a re-install -- the downgrade hazard, fired to fix nothing.

    Spelled out rather than imported from either sibling: there is no ``tests/__init__.py``, so importing
    across test modules would bind this file's correctness to pytest's collection import mode. If this
    fold ever diverges from those two, the divergence IS the bug;
    ``test_the_selfheal_parity_check_still_detects_a_content_difference`` is what keeps the copy honest.

    WHAT IT GIVES UP: a difference of line endings ALONE becomes invisible. Nothing in this payload reads
    its own bytes -- no embedded self-hash, no signature block -- and PowerShell parses both forms
    identically, so no branch of the script can differ between them. Revisit here if that stops being
    true.
    """
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _settings_files() -> list[Path]:
    """Every user-scope settings file that could carry a wired SessionStart hook."""
    return sorted(
        p for d in Path.home().glob(".claude*") if d.is_dir() for p in d.glob("settings*.json")
    )


def wired_payloads() -> list[tuple[Path, Path]]:
    """(settings file, payload path) for every SessionStart hook whose command names this script.

    Read from the WIRING rather than assumed from the installer default, because the wiring is what
    actually executes. Deriving the target only from the default would answer an adjacent question -- "is
    the file at the place the installer would write in sync" -- while a config dir pointing somewhere else
    ran an unaudited copy. The installer default is unioned in below so the check still has a target on a
    box where nothing is wired yet.
    """
    found: list[tuple[Path, Path]] = []
    for f in _settings_files():
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        for group in (data.get("hooks") or {}).get("SessionStart") or []:
            for h in group.get("hooks") or []:
                cmd = str(h.get("command") or "")
                for dquoted, squoted, bare in _PAYLOAD_IN_COMMAND.findall(cmd):
                    found.append((f, Path(dquoted or squoted or bare)))
    return found


def installer_default_payload() -> Path | None:
    """Where ``install-selfheal.ps1`` writes when ``-HookPath`` is not passed, i.e. how an operator runs it."""
    return Path.home() / INSTALLER_DEFAULT_REL if INSTALLER_DEFAULT_REL else None


def payload_targets() -> list[Path]:
    """Every distinct payload path worth comparing: what is wired, plus where the installer would write.

    Deduplicated with ``os.path.normcase`` because these paths come from two sources that spell them
    differently -- the wiring carries a literal Windows path with backslashes and whatever case the
    installer interpolated, the default is composed from ``Path.home()``. On Windows those name the same
    file; comparing it twice would double every diagnostic line for no added coverage.
    """
    seen: dict[str, Path] = {}
    for _f, p in wired_payloads():
        seen.setdefault(os.path.normcase(str(p)), p)
    default = installer_default_payload()
    if default is not None:
        seen.setdefault(os.path.normcase(str(default)), default)
    return [seen[k] for k in sorted(seen)]


def source_is_committed() -> bool:
    """Assert parity only against a COMMITTED source.

    Mid-edit the installed copy is *supposed* to differ, and a check that goes red on every keystroke gets
    deselected with ``-k`` and then deleted. Same posture as both sibling parity modules.
    """
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", SOURCE.relative_to(ROOT).as_posix()],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and not out.stdout.strip()


def test_the_payload_target_was_derived_and_not_assumed() -> None:
    """Guard the derivation. If the parse of the installer default breaks AND nothing is wired,
    :func:`payload_targets` returns an empty list, the parity test below skips for want of a target, and
    pytest renders that as a bare ``s`` -- no comparison made, no red, which is the exact ambiguity this
    module exists to end. Fail loudly there instead."""
    print(f"source: {SOURCE}")
    print(f"installer: {INSTALLER}")
    print(f"default -HookPath parsed from the installer: {INSTALLER_DEFAULT_REL or 'PARSE FAILED'}")
    assert INSTALLER_DEFAULT_REL, (
        f"no default -HookPath parsed out of {INSTALLER} -- the parity test then has no target unless a "
        f"config dir happens to be wired, and reports a SKIP that reads like a pass"
    )
    assert INSTALLER_DEFAULT_REL.endswith("worktree-selfheal.ps1"), (
        f"the parsed default points at {INSTALLER_DEFAULT_REL!r}, which is not the payload -- the regex "
        f"matched the wrong line and the parity test would compare the wrong file"
    )
    assert SOURCE.is_file(), (
        f"no committed source at {SOURCE} -- there is nothing to compare against"
    )


def test_the_installed_selfheal_payload_matches_the_committed_source() -> None:
    """The assertion BACKLOG #1019 asked for: the payload that RUNS versus this checkout's source.

    It runs from a shared user-scope copy, so one stale file is stale for every config dir and every
    session on the box at once, while the source-side tests stay green.
    """
    targets = payload_targets()
    # Announce everything scanned BEFORE any skip. The wiring lines are part of that: a config dir that
    # wires nothing, or wires a path that is absent, is visible here and nowhere else in the suite.
    print(f"source: {SOURCE}")
    print(f"settings files scanned: {[str(p) for p in _settings_files()] or 'NONE'}")
    for f, p in wired_payloads():
        print(f"  wired by {f}: {p}")
    for p in targets:
        print(f"comparing: {p}{'' if p.is_file() else '   (ABSENT -- nothing installed here)'}")

    present = [p for p in targets if p.is_file()]
    if not present:
        pytest.skip(
            "SKIP (nothing compared): no selfheal payload installed at any target printed above. The "
            "backstop is installed per box by a human running install-selfheal.ps1 from a plain "
            "terminal, and CI installs none -- so on CI this is honest, and on a developer box it means "
            "the SessionStart backstop is not present at all."
        )
    if not source_is_committed():
        pytest.skip(
            f"SKIP (nothing compared): {SOURCE.relative_to(ROOT).as_posix()} has uncommitted changes -- "
            f"the installed copy is SUPPOSED to differ mid-edit. Re-run after committing."
        )

    source_bytes = SOURCE.read_bytes()
    source_hash = content_hash(source_bytes)
    drifted: list[tuple[Path, str]] = []
    for p in present:
        installed_bytes = p.read_bytes()
        installed_hash = content_hash(installed_bytes)
        # Print BOTH bases. The content hashes are what the assertion turns on; the raw byte digests and
        # the eol-only flag are diagnostics that keep "differs in content" and "differs in line endings"
        # distinguishable in the output. Collapsing them to one number is how the two got confused.
        print(
            f"compared (content, CRLF folded): installed={installed_hash[:12]} "
            f"source={source_hash[:12]}   [{p}]"
        )
        print(
            f"  diagnostic raw bytes: installed={hashlib.sha256(installed_bytes).hexdigest()[:12]} "
            f"source={hashlib.sha256(source_bytes).hexdigest()[:12]} "
            f"line-endings-only difference="
            f"{installed_bytes != source_bytes and installed_hash == source_hash}"
        )
        if installed_hash != source_hash:
            drifted.append((p, installed_hash))

    assert not drifted, (
        f"CONTENT DRIFT: the worktree-selfheal payload that RUNS is not this checkout's.\n"
        f"  source   : {SOURCE}  content={source_hash[:12]}\n"
        + "".join(f"  installed: {p}  content={h[:12]}\n" for p, h in drifted)
        + f"Line endings are folded out of this comparison, so CRLF vs LF alone cannot account for it. "
        f"That does NOT make this a difference in code: the fold rewrites \\r\\n and nothing else, so at "
        f"least a UTF-8 BOM on one side, a dropped final newline, and CR-only (lone \\r) endings all "
        f"still trip this assertion. Diff the two files before concluding anything about which.\n"
        f"Until the installed copy is replaced, edits to the source have NO EFFECT -- the hook keeps "
        f"running the old logic in every config dir on this box -- and the rest of the suite still "
        f"passes, because everything else drives the source. That is ONE direction of the drift. The "
        f"other is an installed copy edited in place -- a fork with no branch, which nothing but this "
        f"assertion will ever report, and which a re-install silently discards.\n"
        f'WORK OUT WHICH COPY CARRIES THE CHANGE. NOT WHICH IS YOUNGER, AND NOT WHICH IS "STALE" -- '
        f"this assertion reports a DIFFERENCE and cannot give it a DIRECTION, so every reader supplies "
        f"one from the prior that the repo is canonical. Measured 2026-08-26, that prior was wrong: the "
        f"installed copy had been hand-patched to carry an owner ruling, the source was a month older "
        f'and lacked it, and the reflex reading of "stale install" prescribed a re-install that '
        f"would have reverted the ruling across every config dir on this box. This is a USER-SCOPE "
        f"file, so that downgrade lands everywhere, for every account, at once. Read the direction off "
        f"the CONTENT -- which side holds something the other does not:\n"
        f"    git diff --no-index -- {SOURCE.relative_to(ROOT).as_posix()} <the installed path above>\n"
        f"A file mtime cannot answer this, and neither can git log on the source: each describes ONE "
        f"side's own history, while the question is about the difference between two.\n"
        f"Only once THIS checkout is confirmed to carry everything the installed copy has, from a PLAIN "
        f"terminal (the installer refuses under CLAUDECODE, deliberately):\n"
        f"    pwsh -NoProfile -File scripts\\worktree\\install-selfheal.ps1 -ConfigDir <a config dir>\n"
        f"-ConfigDir is mandatory and takes ONE dir, but the payload is a single shared file: one run "
        f"re-copies it for every config dir that references it, and further runs are only needed to wire "
        f"a dir that is not wired yet."
    )


def test_the_selfheal_parity_check_still_detects_a_content_difference() -> None:
    """NEGATIVE CONTROL for the assertion above, and the price of folding line endings out of it.

    The parity test is expected to PASS on this box today, and a pass proves nothing unless the predicate
    can also fail. Folding is exactly the edit that can turn a false RED into a false GREEN -- a payload
    that is genuinely stale, reported in sync -- so prove the weakened predicate still detects what it
    exists to detect, and prove the tolerance is not vacuous while doing it.

    Exercised against the predicate on real SOURCE bytes, never by mutating the installed copy: that file
    is user-scope, every config dir's SessionStart hook reads it, and a test may not take it out from
    under a concurrent session. Same reasoning and shape as
    ``test_gate_installed_parity.test_the_parity_check_still_detects_a_content_difference``.
    """
    body = SOURCE.read_bytes().replace(b"\r\n", b"\n")
    crlf = body.replace(b"\n", b"\r\n")

    # Guard the guard: identical encodings would make the tolerance assertion hold for a trivial reason
    # and prove nothing about folding.
    assert crlf != body, "the CRLF and LF encodings are identical -- this control would be vacuous"
    print(f"eol probes differ in bytes: LF={len(body)} CRLF={len(crlf)}")
    assert content_hash(crlf) == content_hash(body), (
        "re-encoding line endings changed the content hash -- the tolerance this module documents does "
        "not actually hold"
    )

    added = body + b'\nWrite-Host "mf parity control probe"\n'
    assert content_hash(added) != content_hash(body), (
        "appending a line did not change the content hash -- the parity check is decoration"
    )

    # The subtle end of the range: one operator inside the condition that decides whether the backstop is
    # allowed to run `git checkout` on the primary. Flipping -eq to -ne turns "repair only a CLEAN tree"
    # into "repair only a DIRTY one", which is the difference between a safe branch switch and running one
    # unattended on a DIRTY tree. (Not "clobbering": `git checkout` refuses a switch that would overwrite
    # conflicting local modifications and carries non-conflicting ones across. The hazard is real without
    # being data loss, and overstating it here would be the same defect this module exists to catch.)
    # It changes no line count and one character, so a size or line check is not a substitute for this.
    #
    # Anchored on `-and ... ) {` rather than the bare condition, and the count is ASSERTED rather than
    # assumed: a raw text scan does not know code from a comment that quotes it, and `replace(..., 1)`
    # silently takes the first hit either way. That is the defect this session fixed in the gate's own
    # control, where the probe was mutating a comment while its output called it a rule.
    guard = b"-and $dirty.Count -eq 0) {"
    occurrences = body.count(guard)
    assert occurrences == 1, (
        f"the clean-tree guard occurs {occurrences} times in the payload, not once. At 0 the condition "
        f"was reworded and this probe now mutates nothing; above 1 it cannot say WHICH occurrence it "
        f"hit. Fix this control."
    )
    flipped = body.replace(guard, b"-and $dirty.Count -ne 0) {", 1)
    assert content_hash(flipped) != content_hash(body), (
        "a one-character edit to the clean-tree guard did not change the content hash"
    )
    print(
        "content differences still detected: line appended, and one character changed in the clean-tree "
        "guard -- the code, not a comment quoting it"
    )


def test_folding_crlf_does_not_hide_a_bom_a_lost_newline_or_cr_only_endings() -> None:
    """The failure text above tells a reader that AT LEAST three non-code causes still trip the
    assertion. That is a claim the reader will act on -- it is what stops them treating every red as
    staleness and reaching for a re-install -- so it is asserted here rather than left as prose.

    Deliberately NOT a completeness claim in either direction: this proves these three are still
    detected, not that they are the only ones.
    """
    body = SOURCE.read_bytes().replace(b"\r\n", b"\n")
    base = content_hash(body)

    cases: list[tuple[str, bytes]] = [
        ("UTF-8 BOM prepended", b"\xef\xbb\xbf" + body),
        ("final newline dropped", body.rstrip(b"\n")),
        ("CR-only line endings", body.replace(b"\n", b"\r")),
    ]
    for label, probe in cases:
        assert probe != body, (
            f"{label}: the probe is identical to the source -- this case is vacuous"
        )
        print(f"{label}: content={content_hash(probe)[:12]} vs source={base[:12]}")
        assert content_hash(probe) != base, (
            f"{label} did not change the content hash -- the failure text claims this case still trips "
            f"the parity assertion, and it does not"
        )
