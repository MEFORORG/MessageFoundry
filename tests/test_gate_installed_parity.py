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

    installed = hashlib.sha256(INSTALLED_GATE.read_bytes()).hexdigest()
    source = hashlib.sha256(SOURCE_GATE.read_bytes()).hexdigest()
    print(f"compared: installed={installed[:12]} source={source[:12]}")

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
