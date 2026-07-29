"""Does the gate that is RUNNING match the gate that is in the repo?

Nothing answered this, and that gap is the root cause of every other defect found in the drift machinery.
The gate executes from an installed COPY under ``~/.claude/hooks/``; ``install-gate.ps1`` copies it with no
version, hash or marker, and its ``-Status`` printed an uncalibrated count of hook entries. So:

* Rule 4 was implemented, declared by the installer, and covered by tests -- and was absent from the
  installed script and from every matcher set. 85 tests passed the whole time.
* The reverse is worse and equally invisible: delete a rule from source and the stale installed copy keeps
  enforcing it forever, while every test correctly reports it gone.

These tests are LOCAL-MACHINE tests. On CI there is no installed gate and they skip -- which is honest,
because the drift they detect is a developer-box condition, not a repository one. They print what they
scanned so a skip can never be mistaken for a pass.

Parity is asserted only when the source script is COMMITTED. Mid-change the two are *supposed* to differ,
and a test that nagged on every edit would be re-run with ``-k`` until someone deleted it.
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


def handled_tools(text: str) -> set[str]:
    tools: set[str] = set()
    for group in TOOL_BRANCH.findall(text):
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
    if not INSTALLED_GATE.is_file():
        pytest.skip(
            f"no gate installed at {INSTALLED_GATE} -- nothing is enforcing; nothing to compare"
        )
    if not source_is_committed():
        pytest.skip(
            f"{SOURCE_GATE.relative_to(ROOT)} has uncommitted changes -- the installed copy is SUPPOSED "
            f"to differ mid-edit. Re-run after committing."
        )

    installed = hashlib.sha256(INSTALLED_GATE.read_bytes()).hexdigest()
    source = hashlib.sha256(SOURCE_GATE.read_bytes()).hexdigest()
    print(f"scanned: {INSTALLED_GATE} ({installed[:12]}) vs {SOURCE_GATE} ({source[:12]})")

    assert installed == source, (
        f"The RUNNING gate is not this checkout's script.\n"
        f"  installed: {INSTALLED_GATE}  sha={installed[:12]}\n"
        f"  source   : {SOURCE_GATE}  sha={source[:12]}\n"
        f"Until it is re-installed, rules added or removed in source have NO EFFECT and the rest of the "
        f"suite still passes. Fix from a PLAIN terminal:\n"
        f"    pwsh -NoProfile -File scripts\\worktree\\install-gate.ps1"
    )


def test_every_wired_matcher_names_a_tool_the_gate_handles() -> None:
    """The inverse drift: a matcher for a tool the script ignores burns a pwsh subprocess on every call,
    and -- worse -- reads as coverage that does not exist."""
    dirs = config_dirs()
    if not dirs:
        pytest.skip("no Claude config dirs on this box -- nothing is wired, so nothing to check")
    if not INSTALLED_GATE.is_file():
        pytest.skip(
            f"no gate installed at {INSTALLED_GATE} -- matchers cannot be judged against it"
        )

    handled = handled_tools(INSTALLED_GATE.read_text(encoding="utf-8"))
    print(f"scanned {len(dirs)} config dir(s) against {len(handled)} rule(s) in the INSTALLED gate")
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
    if not dirs:
        pytest.skip("no Claude config dirs on this box -- nothing is wired, so nothing to check")
    if not INSTALLED_GATE.is_file():
        pytest.skip(f"no gate installed at {INSTALLED_GATE} -- there is no live rule set to wire")

    handled = handled_tools(INSTALLED_GATE.read_text(encoding="utf-8"))
    required = handled - OPT_IN_TOOLS
    print(
        f"scanned {len(dirs)} config dir(s); require {sorted(required)}; opt-in {sorted(OPT_IN_TOOLS)}"
    )

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
