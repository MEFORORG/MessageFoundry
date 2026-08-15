# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The installer must register a matcher for every tool the gate script actually branches on.

This exists because it went wrong. Rule 3 (git verbs that swap the shared primary's working tree) was
implemented in scripts/hooks/worktree_gate.ps1 and shipped — but install-gate.ps1 registered matchers only
for `Write|Edit|MultiEdit|NotebookEdit` and `Task|Agent|Workflow`. Claude Code therefore never invoked the
hook for a `Bash` or `PowerShell` call, so the rule was DEAD CODE the moment it was installed, and nothing
said so.

The 66 existing gate tests could not catch it: they pipe a payload straight into the script, which
bypasses matcher dispatch entirely. They test the LOGIC. This tests the WIRING — the seam where a rule
that works in isolation silently never runs in production.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-gate.ps1"

# `if ($tool -in @("Bash", "PowerShell")) {` / `if ($tool -notin @("Write", "Edit", ...))`
TOOL_BRANCH = re.compile(r"\$tool\s+-(?:not)?in\s+@\(([^)]*)\)")
QUOTED = re.compile(r'"([^"]+)"')


def tools_the_gate_handles() -> set[str]:
    """Every tool name the gate script dispatches on."""
    text = GATE.read_text(encoding="utf-8")
    tools: set[str] = set()
    for group in TOOL_BRANCH.findall(text):
        tools.update(QUOTED.findall(group))
    return tools


def matcher_block() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    return text.split("$matchers = @(", 1)[1].split("$entries", 1)[0]


def tools_the_installer_registers() -> set[str]:
    """Every tool name the installer CAN register -- including the ones behind an opt-in switch.

    This is deliberately the permissive reading. It answers "did someone add a rule and forget the
    matcher entirely", which is the drift this file exists for. It does NOT answer "does the default
    install wire it" (see below) and it cannot answer "is it wired on this machine" at all -- that needs
    the live settings.json, which is tests/test_gate_installed_parity.py.
    """
    tools: set[str] = set()
    for matcher in QUOTED.findall(matcher_block()):
        tools.update(matcher.split("|"))
    return tools


def tools_registered_by_default() -> set[str]:
    """What a bare `install-gate.ps1` writes: the unconditional array, plus blocks guarded by a NEGATED
    switch (`-not $NoDispatchGate` is on unless you opt out). A block guarded by a plain `if ($Switch)`
    is opt-IN and contributes nothing by default."""
    block = matcher_block()
    tools: set[str] = set()
    unconditional, _, rest = block.partition("if (")
    for matcher in QUOTED.findall(unconditional):
        tools.update(matcher.split("|"))
    for chunk in ("if (" + rest).split("if (")[1:]:
        guard, _, body = chunk.partition(")")
        if "-not" in guard:  # opt-OUT: on unless suppressed
            for matcher in QUOTED.findall(body):
                tools.update(matcher.split("|"))
    return tools


def test_the_gate_handles_the_tools_we_expect() -> None:
    """Guard the guard: if a rule is added or removed, this test should be the thing that notices."""
    assert tools_the_gate_handles() == {
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Task",
        "Agent",
        "Workflow",
        "Bash",
        "PowerShell",
        "EnterWorktree",
    }


def test_every_tool_the_gate_handles_is_registered_by_the_installer() -> None:
    """A rule the hook implements but the installer does not match NEVER FIRES, and nothing says so."""
    handled = tools_the_gate_handles()
    registered = tools_the_installer_registers()
    unwired = handled - registered
    assert not unwired, (
        f"scripts/hooks/worktree_gate.ps1 branches on {sorted(unwired)}, but install-gate.ps1 registers no "
        f"matcher for them — those rules would be silently dead once installed. "
        f"Registered: {sorted(registered)}"
    )


def test_the_installer_does_not_register_tools_the_gate_ignores() -> None:
    """The inverse drift: matching a tool the script does nothing with just burns a subprocess per call."""
    stray = tools_the_installer_registers() - tools_the_gate_handles()
    assert not stray, (
        f"install-gate.ps1 matches {sorted(stray)}, which worktree_gate.ps1 never inspects."
    )


def test_the_default_install_wires_rules_1_2_and_3_and_nothing_else() -> None:
    """Pin what a bare `install-gate.ps1` actually turns on.

    The permissive test above is satisfied by a matcher sitting behind an opt-in switch, which is exactly
    how a rule can be "registered by the installer" and still never fire. Rule 4 (EnterWorktree) is
    deliberately opt-in -- it compounds with rule 2 to leave a primary-resident session no in-session path
    to isolation, so activating it as a side effect of installing an unrelated fix would be a trap. That
    decision belongs in this assertion, where changing it is visible, rather than in a switch nobody reads.
    """
    assert tools_registered_by_default() == {
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Bash",
        "PowerShell",
        "Task",
        "Agent",
        "Workflow",
    }


def test_every_opt_in_tool_is_guarded_by_a_plain_switch() -> None:
    """The opt-in must be real: a tool named outside a guard is on by default whatever the docs say."""
    opt_in = tools_the_installer_registers() - tools_registered_by_default()
    assert opt_in == {"EnterWorktree"}, f"unexpected opt-in set: {sorted(opt_in)}"
    assert re.search(r"if \(\$EnterWorktreeGate\)", matcher_block()), (
        "EnterWorktree must be added inside an `if ($EnterWorktreeGate)` block"
    )


# ----------------------------------------------------------------------------- the -Status audit


def _status_against(home: Path) -> str:
    """Run ``-Status`` with ``USERPROFILE`` pointed at a synthetic home.

    ``-Status`` sits above the CLAUDECODE refusal and above every write path, so this reads the fixture
    and touches nothing machine-global. That constraint is the whole reason #1024 was scored a 3: a
    session must NOT execute this installer for real, because it rewrites user-scope wiring for every
    session on the box. Redirecting HOME is how the writer's own predicate gets exercised anyway.
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER), "-Status"],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "USERPROFILE": str(home), "CLAUDECODE": "1"},
    )
    assert r.returncode == 0, f"-Status must never fail:\n{(r.stderr + r.stdout)[:1200]}"
    print(r.stdout)
    return r.stdout


def _fake_home(root: Path, names: list[str], *, wired: set[str] | None = None) -> Path:
    """A home holding `names` as directories, each with a settings.json carrying gate wiring."""
    home = root / "home"
    home.mkdir()
    settings = json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|PowerShell",
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'pwsh -NoProfile -File "~/worktree_gate.ps1"',
                            }
                        ],
                    }
                ]
            }
        }
    )
    for name in names:
        d = home / name
        d.mkdir()
        if wired is None or name in wired:
            (d / "settings.json").write_text(settings, encoding="utf-8")
    return home


def test_the_writer_wires_exactly_the_dirs_the_reader_agrees_to_judge(tmp_path: Path) -> None:
    """BACKLOG #1024. The installer's config-dir glob was unanchored, so it wired any directory whose
    name merely BEGINS with ``.claude-account-`` -- measured 2026-08-04, ``~/.claude-account-2.lock``
    is a directory and got three gate matchers written into it on every run.

    The reader in ``test_gate_installed_parity`` was anchored by #199 and deliberately left the writer
    alone. This asserts the two predicates now agree, by running the REAL writer over the same name
    corpus the reader's own negative control uses and importing the reader's pattern rather than
    restating it -- a restatement is a third predicate, and this defect was two predicates disagreeing.
    """
    from test_gate_installed_parity import _ACCOUNT_DIR_NAME

    names = [
        ".claude",
        ".claude-account-1",
        ".claude-account-42",
        ".claude-account-2.lock",  # the measured artifact
        ".claude-account-2.bak",  # the next artifact shape a `.lock` blocklist would miss
        ".claude-account-2-old",
        ".claude-account-alpha",  # KNOWN COST: a named account would be wrongly excluded
        ".claude-account-2b",  # KNOWN COST: a suffixed account would be wrongly excluded
    ]
    out = _status_against(_fake_home(tmp_path, names))

    wired_lines = [ln for ln in out.splitlines() if ln.startswith("wiring      :")]
    wired = {Path(ln.split(":", 1)[1].strip()).parent.name for ln in wired_lines}
    reader = {n for n in names if n == ".claude" or _ACCOUNT_DIR_NAME.fullmatch(n)}
    assert wired == reader, (
        f"writer and reader disagree about which config dirs are launchers.\n"
        f"  writer wires : {sorted(wired)}\n"
        f"  reader judges: {sorted(reader)}"
    )
    # Guard the guard: an agreement over an empty set would prove nothing, and neither would one where
    # the corpus contained no rejectable name.
    assert reader, "the corpus contains no accepted name -- this comparison would be vacuous"
    assert set(names) - reader, "the corpus contains no rejected name -- ditto"
    assert ".claude-account-2.lock" not in wired


def test_status_reports_orphan_wiring_in_a_dir_the_installer_no_longer_writes(
    tmp_path: Path,
) -> None:
    """BACKLOG #1024, the half that anchoring alone does not fix.

    Before this, ``-Status`` scanned exactly the set the installer WRITES, so it could only ever confirm
    the installer's own output: both halves used one unanchored glob, so the writer manufactured wiring
    in ``.claude-account-2.lock`` and the reader read it back as evidence the wiring was right. Anchoring
    the writer stops the wiring being re-created, and it also puts the existing artifact permanently out
    of ``-Uninstall``'s reach -- so the audit must NAME it rather than let it fall silent.

    The independent population is the point: enumerated from ``~/.claude*`` and judged by name
    afterwards, rather than selected by the predicate whose correctness it exists to check.
    """
    home = _fake_home(tmp_path, [".claude", ".claude-account-1", ".claude-account-2.lock"])
    out = _status_against(home)

    assert ".claude-account-2.lock" in out, "the audit does not mention the artifact at all"
    assert "ORPHAN GATE WIRING in .claude-account-2.lock" in out
    assert "will neither refresh nor remove it" in out
    # The remedy must be a command that actually reaches it, since -Uninstall no longer does.
    assert '-Uninstall -ConfigDir "' in out
    # PRINT WHAT WAS SCANNED, not just a verdict: the audit's population is stated by name.
    found = next(ln for ln in out.splitlines() if "found    :" in ln)
    assert ".claude-account-2.lock" in found and ".claude-account-1" in found
    # And the audit really is wider than the wire set -- otherwise it is the same loop with a new label.
    assert "scanned 2 config dir(s)" in out


def test_the_audit_stays_quiet_when_no_dir_outside_the_wire_set_carries_wiring(
    tmp_path: Path,
) -> None:
    """NEGATIVE CONTROL for the report above. A line that appears on every run is one readers skip, and
    that is how a real orphan goes unnoticed -- so prove the loud arm is discriminating, not constant.

    The decoy is present as a DIRECTORY here, with no settings.json: right name shape to be excluded,
    nothing wired to report. The audit must say so and must not cry wolf.
    """
    home = _fake_home(
        tmp_path,
        [".claude", ".claude-account-1", ".claude-account-2.lock"],
        wired={".claude", ".claude-account-1"},
    )
    out = _status_against(home)
    assert "ORPHAN GATE WIRING" not in out
    assert "every dir found is in the wire set above; nothing is unjudged" in out
    assert "scanned 2 config dir(s)" in out


def test_an_empty_audit_population_says_nothing_was_examined(tmp_path: Path) -> None:
    """The clean verdict must not be reachable when nothing was measured.

    "I found nothing" and "I found things and they are all fine" print identically the moment a scan
    reports only its verdict, and the second is the only one that is reassurance. This is the same
    distinction presence.ps1 draws between an empty roster and an unavailable one, and the same one
    #1000 is about, applied to this audit's own output.
    """
    home = tmp_path / "home"
    home.mkdir()
    out = _status_against(home)
    assert "NOTHING EXAMINED" in out
    assert "That is not the same as 'no orphans'." in out
    assert "every dir found is in the wire set above" not in out
    assert "no unjudged dir carries gate wiring" not in out


def test_status_prints_a_sha_beside_each_version() -> None:
    """`-Status` is the only way to see whether the RUNNING gate matches this checkout, and nothing
    exercised it. It also shipped a defect worth pinning: `$GateVersion` is bumped by hand, and rules 1a,
    3c and 3d were added without a bump -- so it printed the SAME version on both lines directly above a
    *** STALE *** verdict. The SHA comparison caught the drift, but a label that disagrees with the verdict
    beside it is the ambiguity this whole audit exists to remove.

    Asserting the SHA is printed makes agreement visible rather than asserted. Read-only and safe to run
    anywhere: `-Status` sits above the CLAUDECODE refusal precisely so a session can audit but not install.
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER), "-Status"],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "CLAUDECODE": "1"},
    )
    assert r.returncode == 0, f"-Status must never fail:\n{(r.stderr + r.stdout)[:800]}"
    out = r.stdout
    print(out)
    assert "installed   :" in out and "source      :" in out
    # The source line always resolves (this checkout), so it must always carry a hash.
    src_line = next(ln for ln in out.splitlines() if ln.startswith("source      :"))
    assert re.search(r"\bsha [0-9a-f]{12}\b", src_line), (
        f"the source line must show its hash, not just a hand-bumped version: {src_line!r}"
    )
    assert re.search(r"\bv\d{4}\.\d{2}\.\d{2}\.\d+", src_line), (
        f"version label missing: {src_line!r}"
    )


def test_a_hidden_account_dir_is_still_wired(tmp_path: Path) -> None:
    """BACKLOG #1024, cross-platform arm. The writer's account-dir glob needs ``-Force``, and its
    absence is INVISIBLE ON WINDOWS.

    ``Get-ChildItem`` omits hidden entries without ``-Force``. On Linux the dot prefix *is* the hidden
    convention, so the glob returns nothing and the wire set collapses to the single explicit
    ``~/.claude`` candidate -- which is a ``Join-Path``, not a glob, and so survives. That is what the
    ubuntu CI leg reported while every Windows run stayed green: on Windows a dot-prefixed directory
    carries no hidden ATTRIBUTE, so the omission cannot fire.

    This test makes the class reproducible on Windows by setting the attribute explicitly, so the
    control can go red on the box the code is written on. Without it, the only instrument that can see
    this defect is a CI leg -- and a check that cannot fail where you work is a claim, not a control.
    """
    names = [".claude", ".claude-account-1"]
    home = _fake_home(tmp_path, names)

    hidden = home / ".claude-account-1"
    if os.name == "nt":
        # FILE_ATTRIBUTE_HIDDEN. Fail loudly rather than skipping: a silent no-op here would restore
        # exactly the blindness this test exists to remove.
        rc = subprocess.run(
            ["attrib", "+H", str(hidden)], capture_output=True, text=True, timeout=30
        )
        assert rc.returncode == 0, f"could not hide the fixture dir: {rc.stderr or rc.stdout}"
    # On POSIX the leading dot already makes it hidden to PowerShell; nothing to do.

    out = _status_against(home)
    wired_lines = [ln for ln in out.splitlines() if ln.startswith("wiring      :")]
    wired = {Path(ln.split(":", 1)[1].strip()).parent.name for ln in wired_lines}
    assert ".claude-account-1" in wired, (
        "a HIDDEN ~/.claude-account-N was not wired -- the writer's Get-ChildItem is missing -Force.\n"
        f"  wired: {sorted(wired)}\n"
        "  On Linux every dot-dir is hidden, so this is the whole account population, not an edge case."
    )
