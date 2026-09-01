# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`.claude/settings.json` is now a TRACKED control, so its shape gets a test.

Tracking the file (see `tests/test_private_paths_stay_ignored.py` for the boundary half) is what
carries the deny-list, and whatever matchers the file wires, to a fresh clone and to every
`git worktree add`. That only buys anything if the payload still works when it arrives, and the
ways it silently stops working are invisible to review:

CORRECTED, AND THE SENTENCE WAS IN THIS FILE (BACKLOG #1339). This paragraph used to say tracking
the file carries "the deny-list and the `block-blanket-git-stage` guard". It carries the deny-list.
It carried nothing about that guard, because no matcher in it names the script -- so the module
whose job is to catch a control that reads as enforced and is not was itself asserting one. The
third check below is what makes that statement checkable instead of merely rewritten; three earlier
prose corrections on this claim each landed a new false statement, which is why the fix had to be
an instrument.

  * **A hook that cannot start does not block.** Claude Code's hooks reference is explicit that a
    command hook which fails to launch "lands in the same non-blocking bucket" and that for most
    events "the action proceeds". A hook path written bare, as `scripts/hooks/x.ps1`, resolves
    against the session's current directory, not the repo — so in any session started outside the
    repo root it never runs, the guard reads as enforced in the file, and nothing reports it. The
    fix is `${CLAUDE_PROJECT_DIR}` in exec form, and this file pins it.
  * **A deny rule anchored at `./` covers one directory.** Bare patterns follow gitignore semantics
    and match at any depth; `Read(./.env)` matches `<cwd>/.env` and nothing below it. The `./` form
    looks equivalent and is strictly narrower, which is the worst combination for a control whose
    whole job is to be broad.
  * **A matcher that reads as a regex may not be one.** Claude Code evaluates a matcher whose
    characters are only letters, digits, `_`, `-`, spaces, `,` and `|` as a list of EXACT tool
    names. `Task|Agent|Workflow|spawn_task` therefore selects three tools and never the fourth,
    because the real name is `mcp__ccd_session__spawn_task` and an exact-name list cannot see it.
    The row looks like an alternation, behaves like an enumeration, and the hook simply never fires
    on the tool it was written for (BACKLOG #1406).

None of the three is caught by JSON validity, by `pre-commit`, or by reading the diff. All three are
caught here.

The deny-list is also the only half of this file that auto mode cannot touch: permission deny rules
are evaluated before the classifier, and unlike `allow` rules they are not gated on the workspace
trust dialog. That is why the pinned subset below is the deny rules and not the allow rules.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS = _ROOT / ".claude" / "settings.json"

# The rules whose loss would be silent and would matter. Not the whole deny-list: the point is a
# floor under the PHI, secret and local-store rules that CLAUDE.md section 5 and section 9 promise
# are enforced, so prose and mechanism cannot drift apart without a red test.
_REQUIRED_DENIES = frozenset(
    {
        "Read(.env)",
        "Read(secrets/**)",
        "Read(*.db)",
        "Edit(.env)",
        "Edit(secrets/**)",
        "Write(.env)",
        "Write(secrets/**)",
    }
)

_PLACEHOLDER = "${CLAUDE_PROJECT_DIR}"


def _load() -> dict[str, Any]:
    return json.loads(_SETTINGS.read_text(encoding="utf-8"))


def _hook_handlers(settings: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Flatten `hooks.<event>[].hooks[]` into (event, handler) pairs."""
    out: list[tuple[str, dict[str, Any]]] = []
    for event, groups in settings.get("hooks", {}).items():
        for group in groups:
            for handler in group.get("hooks", []):
                out.append((event, handler))
    return out


def _repo_script_refs(handler: dict[str, Any]) -> list[str]:
    """Every token in a handler that names a file under the repo's script trees."""
    tokens = [handler.get("command", ""), *handler.get("args", [])]
    return [t for t in tokens if isinstance(t, str) and (".ps1" in t or ".py" in t)]


def _unanchored_refs(settings: dict[str, Any]) -> list[str]:
    return [
        f"{event}: {ref}"
        for event, handler in _hook_handlers(settings)
        for ref in _repo_script_refs(handler)
        if not ref.startswith(_PLACEHOLDER)
    ]


def _dot_anchored_denies(settings: dict[str, Any]) -> list[str]:
    return [r for r in settings["permissions"]["deny"] if "(./" in r]


# ------------------------------------------------ does a matcher select the tools it appears to?

# HOW CLAUDE CODE READS A MATCHER, TRANSCRIBED FROM THE HOOKS REFERENCE
# (https://code.claude.com/docs/en/hooks.md, read against the 2.1.251 client):
#
#   "Matchers containing only letters, digits, `_`, `-`, spaces, `,`, and `|` are evaluated as
#    exact string matches (or lists of exact strings separated by `|` or `,`). Matchers containing
#    any other character (like `.`, `*`, `^`, `$`, etc.) are evaluated as JavaScript regular
#    expressions."
#   "Regex matching is unanchored search (uses `RegExp.prototype.test()`), not fullmatch."
#   "All matching is case-sensitive."
#
# THE TRAP IS THAT THE TWO FORMS READ IDENTICALLY, AND ONLY ONE OF THEM IS WHAT REVIEW ASSUMES. An
# author writing `A|B|C` means "any of these", which is what an exact list gives; the same author
# writing `A|B|substring` means "any of these OR anything containing that", which it does not. The
# miss is invisible from both ends: a matcher that selects nothing produces no error, no log line
# and no output, so a hook that never fires and a hook that fired and had nothing to say are the
# same observation.
#
# `re.search` stands in for `RegExp.prototype.test`. The two agree on every pattern this repo wires;
# they part company on constructs neither form uses here (JS `$` never matches before a trailing
# newline, Python's does), and a tool name contains no newline.
_SIMPLE_MATCHER_CHARS = re.compile(r"^[A-Za-z0-9_\- ,|]*$")


def matcher_selects(matcher: str, tool: str) -> bool:
    """Would Claude Code run a handler wired under `matcher` for a tool call named `tool`?"""
    if matcher in ("", "*"):
        return True
    if _SIMPLE_MATCHER_CHARS.match(matcher):
        return tool in {name.strip() for name in re.split(r"[|,]", matcher) if name.strip()}
    return re.search(matcher, tool) is not None


_HOOK_SCRIPT = _ROOT / "scripts" / "hooks" / "usage-headroom-inject.ps1"

# MCP tools reach a matcher FULLY QUALIFIED, as `mcp__<server>__<tool>`; the bare tool name never
# appears. That prefix is the one fact here that lives outside this repo, so it is written down
# once. The tool half is measured from the hook's own guard rather than repeated beside it -- the
# whole point of this check is that the settings row and the guard cannot drift apart.
_MCP_SPAWN_PREFIX = "mcp__ccd_session__"

# Names one edit away from a name that MUST be selected. An alternation that lost its anchors takes
# the first three, and a matcher that reached an ordinary tool would pay a process spawn on every
# tool call in the session -- measured at 19.0 tool calls per turn on this repo's transcripts.
_NEAR_MISS_TOOLS = ("TaskOutput", "AgentTool", "Workflows", "SubAgent", "TodoWrite", "Edit", "Bash")


def _guarded_exact_names(script_text: str) -> list[str]:
    """The tool names the hook's own `$SPAWN_TOOLS` guard accepts."""
    block = re.search(r"\$SPAWN_TOOLS\s*=\s*@\(([^)]*)\)", script_text)
    assert block, (
        f"{_HOOK_SCRIPT.name} no longer declares $SPAWN_TOOLS, so this check has lost its subject. "
        "Point it at whatever replaced the guard; do not delete it."
    )
    return re.findall(r'"([^"]+)"', block.group(1))


def _guarded_wildcard_names(script_text: str) -> list[str]:
    """The `-like "*x*"` substrings of the same guard, as the qualified names they were written for.

    The guard says `*spawn_task*` because it expects a fully-qualified MCP name. A matcher has to
    agree with that expectation, so the witness is built from the guard's own substring.
    """
    return [
        _MCP_SPAWN_PREFIX + s for s in re.findall(r'-like\s+"\*([A-Za-z0-9_]+)\*"', script_text)
    ]


def _tools_the_hook_guards() -> list[str]:
    """Every tool name the hook script itself would act on. Measured from it, never hand-listed."""
    text = _HOOK_SCRIPT.read_text(encoding="utf-8")
    return [*_guarded_exact_names(text), *_guarded_wildcard_names(text)]


def _matchers_wiring(settings: dict[str, Any], script: str) -> list[str]:
    """Every matcher whose handler group runs `script`.

    An absent `matcher` key is the documented match-all, so it is read as one rather than as a
    miss: this detector hunts a matcher that is too narrow, and must not invent a finding against
    one that is not there at all.
    """
    return [
        group.get("matcher", "")
        for groups in settings.get("hooks", {}).values()
        for group in groups
        if any(script in ref for h in group.get("hooks", []) for ref in _repo_script_refs(h))
    ]


def _spawn_tools_the_matcher_misses(settings: dict[str, Any]) -> list[str]:
    """Tools the hook guards against that no matcher wiring the hook would ever select."""
    matchers = _matchers_wiring(settings, _HOOK_SCRIPT.name)
    return [
        tool
        for tool in _tools_the_hook_guards()
        if not any(matcher_selects(m, tool) for m in matchers)
    ]


# --------------------------------------------------------- is every hook script wired AT ALL?

# THE HOLE THIS CLOSES (BACKLOG #1339). Every check above walks `hooks.<event>[].hooks[]` -- that
# is, over REFERENCED scripts. A script referenced by NO handler yields an empty reference list, so
# every assertion passes VACUOUSLY over it. `block-blanket-git-stage.ps1` was referenced by nothing,
# on any settings file, while at least eight tracked sites described it as a live control -- and
# nothing here could see that, because the thing to see was an ABSENCE.
#
# WHY THIS IS THREE STATES AND NOT TWO, WHICH IS THE WHOLE DESIGN. A wired/unwired instrument would
# be WRONG and would assert the exact falsehood this test exists to stop. Six scripts are wired at
# USER level by a TRACKED INSTALLER, not by the tracked settings.json:
# `scripts/coord/install-coordination.ps1` wires five, `scripts/worktree/install-gate.ps1` wires
# `worktree_gate.ps1`. Those are installed and live. Under two states they would all land on the
# "deliberately not wired" list, producing a reviewed record claiming six live hooks are switched
# off. So the second state is MEASURED FROM THE INSTALLERS rather than hand-listed, which is also
# what stops it decaying into another enumeration.
_INSTALLERS = (
    Path("scripts/coord/install-coordination.ps1"),
    Path("scripts/worktree/install-gate.ps1"),
    Path("scripts/coord/install-git-hooks.ps1"),
)

# Scripts that are genuinely wired NOWHERE. Each carries its reason, because a bare list is a
# dumping ground and an entry nobody can justify is how this decays back into a false record.
# Keep it SHORT. If it grows, that is the signal, not the workaround.
_KNOWN_UNWIRED: dict[str, str] = {
    "block-blanket-git-stage.ps1": (
        "BACKLOG #1339. Present and fully tested, wired nowhere. Owner ruled 2026-08-25 (relayed "
        "via the Liaison) that it IS a control and is to be wired AFTER the quote-state splitter "
        "repair -- wiring it before that shipped a false-deny class to every seat on every clone, "
        "and that friction is what gets a control disarmed. The repair is BACKLOG #1341."
    ),
    "lane-level.ps1": "Not a PreToolUse guard; invoked directly by coordination scripts.",
    "steer-inject.ps1": "Opt-in steering channel, armed per-session rather than by a matcher.",
    "steer-send.ps1": "The sending half of the same opt-in channel; never a hook handler.",
}


def _hook_scripts() -> list[str]:
    return sorted(p.name for p in (_ROOT / "scripts" / "hooks").glob("*.ps1"))


def _installer_wired(root: Path | None = None) -> set[str]:
    """Hook script basenames a TRACKED installer wires. Measured, never asserted."""
    base = root or _ROOT
    wired: set[str] = set()
    for rel in _INSTALLERS:
        f = base / rel
        if not f.is_file():
            continue
        for name in _hook_scripts():
            if name in f.read_text(encoding="utf-8"):
                wired.add(name)
    return wired


def _unclassified_hook_scripts(settings: dict[str, Any], root: Path | None = None) -> list[str]:
    """Hook scripts that are in NONE of the three states. This is the thing that must be empty."""
    referenced: set[str] = set()
    for _event, handler in _hook_handlers(settings):
        for ref in _repo_script_refs(handler):
            referenced.add(ref.rsplit("/", 1)[-1])
    accounted = referenced | _installer_wired(root) | set(_KNOWN_UNWIRED)
    return [n for n in _hook_scripts() if n not in accounted]


def test_settings_is_valid_json() -> None:
    """A malformed tracked settings file is a repo-wide outage, not a local one."""
    assert _load()["permissions"], "permissions block is missing or empty"


def test_the_phi_and_secret_denies_are_all_present() -> None:
    deny = set(_load()["permissions"]["deny"])
    missing = _REQUIRED_DENIES - deny
    assert not missing, (
        f"{len(missing)} required deny rule(s) are gone: {sorted(missing)}.\n"
        "These are what CLAUDE.md sections 5 and 9 point at when they say secrets and the local "
        "store are off limits. Removing one makes that prose false. Deny rules cost nothing when "
        "unused and are the only permission rules auto mode cannot override."
    )


def test_no_deny_rule_uses_the_narrow_dot_anchor() -> None:
    """`Read(./secrets/**)` matches one directory; `Read(secrets/**)` matches every depth."""
    narrow = _dot_anchored_denies(_load())
    assert not narrow, (
        f"{len(narrow)} deny rule(s) use the `./` anchor and match at one depth only: {narrow}.\n"
        "Drop the prefix. A nested copy of the path -- a vendored tree, a worktree checked out "
        "inside the repo, a fixture directory -- is outside a `./`-anchored rule and inside a bare "
        "one, and the two forms read identically in review."
    )


def test_every_hook_resolves_through_the_project_dir_placeholder() -> None:
    unanchored = _unanchored_refs(_load())
    assert not unanchored, (
        f"{len(unanchored)} hook script reference(s) are not anchored to the project root: "
        f"{unanchored}.\n"
        "A bare path resolves against the session's working directory. When it misses, the hook "
        "fails to start, the action PROCEEDS, and the only trace is a non-blocking notice -- so the "
        f"guard is absent exactly when someone is working somewhere unusual. Use {_PLACEHOLDER} "
        "with `args` (exec form), which is substituted as a plain string with no shell re-parsing."
    )


def test_every_hook_script_actually_exists() -> None:
    """An anchored path that points at nothing fails open just as quietly as an unanchored one."""
    missing = [
        ref
        for _event, handler in _hook_handlers(_load())
        for ref in _repo_script_refs(handler)
        if not (_ROOT / ref.replace(_PLACEHOLDER + "/", "")).is_file()
    ]
    assert not missing, (
        f"hook(s) reference script(s) that are not in the repo: {missing}.\n"
        "Renaming or moving a hook script without updating .claude/settings.json disables the hook "
        "silently in every clone."
    )


@pytest.mark.parametrize(
    ("matcher", "tool", "selected", "rule"),
    [
        ("Edit|Write", "Edit", True, "an exact name in a `|` list"),
        ("Edit|Write", "NotebookEdit", False, "an exact list is not a substring search"),
        ("Edit.*", "NotebookEdit", True, "a regex matcher is an UNANCHORED search"),
        ("^Edit$", "NotebookEdit", False, "anchors are what make a regex exact"),
        ("mcp__memory__.*", "mcp__memory__create_entities", True, "the documented MCP form"),
        ("Bash", "bash", False, "matching is case-sensitive"),
        ("*", "AnythingAtAll", True, "the documented match-all"),
    ],
)
def test_the_matcher_evaluator_agrees_with_the_documented_rule(
    matcher: str, tool: str, selected: bool, rule: str
) -> None:
    """The instrument gets its own control, against the hooks reference's own worked examples.

    Every assertion below rests on `matcher_selects` being right about the exact-list/regex split
    and about search-versus-fullmatch. An evaluator that quietly agreed with the author's intent
    rather than with the client would pass this module and pin nothing, which is the same shape of
    defect it exists to catch one layer down.
    """
    assert matcher_selects(matcher, tool) is selected, (
        f"{matcher!r} against {tool!r}: expected {selected} because {rule}"
    )


def test_the_headroom_matcher_selects_every_tool_the_hook_guards() -> None:
    """The settings row and the hook's own guard must name the same set of tools.

    They are two halves of one control written in two languages, and only one of them is exercised
    by driving the script. `tests/test_usage_headroom_inject.py` pipes a tool name straight into the
    hook, so it proves the GUARD handles the qualified MCP name -- and says nothing about whether
    the matcher ever delivers that call. That gap shipped a green suite over a hook that could not
    fire on one of the four tools it names (BACKLOG #1406).
    """
    missed = _spawn_tools_the_matcher_misses(_load())
    assert not missed, (
        f"the hook guards {len(missed)} tool(s) that its matcher never selects: {missed}.\n"
        "The hook will not run on them at all. A matcher of only letters, digits, `_`, `-`, "
        "spaces, `,` and `|` is a list of EXACT tool names, so a bare `spawn_task` never matches "
        f"the real `{_MCP_SPAWN_PREFIX}spawn_task`. Give the matcher a regex character and anchor "
        "the exact names: `^(Task|Agent|Workflow)$|spawn_task`."
    )


def test_the_headroom_matcher_selects_nothing_it_was_not_meant_to() -> None:
    """Anchors are the whole difference between the fix and a hook wired on half the toolbox."""
    matchers = _matchers_wiring(_load(), _HOOK_SCRIPT.name)
    over = [t for t in _NEAR_MISS_TOOLS if any(matcher_selects(m, t) for m in matchers)]
    assert not over, (
        f"the matcher also selects {len(over)} tool(s) the hook does not guard: {over}.\n"
        "Unanchored alternatives match anywhere in a tool name, so `Task` alone would take "
        "`TaskOutput` too. Keep the bare names inside `^(...)$`."
    )


def test_every_hook_script_is_wired_or_explicitly_named_as_unwired() -> None:
    """A hook script in none of the three states is an UNRECORDED absence, which is the defect.

    This is the assertion the module could not previously make, because every other check walks
    the handler lists and therefore cannot see a script no handler names.
    """
    unclassified = _unclassified_hook_scripts(_load())
    assert not unclassified, (
        f"{len(unclassified)} hook script(s) are wired nowhere and are not named as unwired: "
        f"{unclassified}.\n"
        "Either wire it in .claude/settings.json, or add it to _KNOWN_UNWIRED WITH ITS REASON. "
        "The point is that an unwired hook is a DECISION somebody made and can defend, not a "
        "state the repo drifted into -- BACKLOG #1339 exists because at least eight tracked sites "
        "described a control that was wired nowhere, and nothing could see it."
    )


def test_the_unwired_list_does_not_name_a_script_that_is_actually_wired() -> None:
    """The list must not rot in the other direction either.

    A name left on _KNOWN_UNWIRED after the script gets wired produces a reviewed record asserting
    a live control is switched off -- the same false-record defect, pointing the other way.
    """
    settings = _load()
    referenced = {
        ref.rsplit("/", 1)[-1]
        for _event, handler in _hook_handlers(settings)
        for ref in _repo_script_refs(handler)
    }
    wired = referenced | _installer_wired()
    stale = sorted(set(_KNOWN_UNWIRED) & wired)
    assert not stale, (
        f"{len(stale)} script(s) are named as deliberately unwired but ARE wired: {stale}.\n"
        "Remove them from _KNOWN_UNWIRED. A list that keeps a wired hook is a record claiming a "
        "live control is off."
    )


def test_the_unwired_list_only_names_scripts_that_exist() -> None:
    missing = sorted(set(_KNOWN_UNWIRED) - set(_hook_scripts()))
    assert not missing, (
        f"_KNOWN_UNWIRED names {len(missing)} script(s) that are not in scripts/hooks/: {missing}.\n"
        "A renamed or deleted script leaves an entry that silently excuses nothing."
    )


def _unclassified_for_planted(settings: dict[str, Any]) -> list[str]:
    """Detector shim for the planted-defect row below.

    The planted document is checked against a root with NO installers and NO real hooks directory,
    so `_installer_wired` contributes nothing and the only thing accounting for a script is the
    settings document itself. That isolates what this row is testing.
    """
    return _unclassified_hook_scripts(
        settings, root=Path(__file__).resolve().parent / "_nonexistent"
    )


@pytest.mark.parametrize(
    ("planted", "checker", "label"),
    [
        (
            {
                "permissions": {"deny": []},
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"command": "pwsh", "args": ["-File", "scripts/hooks/x.ps1"]}]}
                    ]
                },
            },
            _unanchored_refs,
            "bare relative hook path",
        ),
        (
            {"permissions": {"deny": ["Read(./.env)"]}, "hooks": {}},
            _dot_anchored_denies,
            "dot-anchored deny rule",
        ),
        (
            # A settings document that wires NOTHING, checked against a root with no installers.
            # Every real hook script is then unaccounted for except the four on _KNOWN_UNWIRED, so
            # the detector must return a non-empty list. If it returns nothing here, it cannot see
            # an unwired script at all and the assertion above is passing for the wrong reason --
            # which is exactly the vacuity BACKLOG #1339 is about.
            {"permissions": {"deny": []}, "hooks": {}},
            _unclassified_for_planted,
            "hook script wired nowhere",
        ),
        (
            # THE DEFECT THIS ROW PLANTS IS THE ONE THAT SHIPPED (BACKLOG #1406). The matcher below
            # is verbatim what `.claude/settings.json` carried, and it selects `Task`, `Agent` and
            # `Workflow` and not `mcp__ccd_session__spawn_task`. The detector must return that one
            # name. If it returns nothing, it cannot see the exact bug it was written for and the
            # assertion above is passing because the matcher is now correct rather than because the
            # check works -- which would leave the next narrowing of that row unguarded.
            {
                "permissions": {"deny": []},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Task|Agent|Workflow|spawn_task",
                            "hooks": [
                                {
                                    "command": "pwsh",
                                    "args": [
                                        "-File",
                                        "${CLAUDE_PROJECT_DIR}/scripts/hooks/"
                                        "usage-headroom-inject.ps1",
                                    ],
                                }
                            ],
                        }
                    ]
                },
            },
            _spawn_tools_the_matcher_misses,
            "matcher that is an exact-name list rather than the regex it resembles",
        ),
    ],
    ids=["unanchored-hook", "dot-anchored-deny", "unwired-hook-script", "exact-list-matcher"],
)
def test_the_checks_can_actually_fail(planted: dict[str, Any], checker: Any, label: str) -> None:
    """A guard that cannot be shown to fail is not a guard.

    Both checks above are absence assertions over a file that is currently correct, which is the
    shape that passes just as well when the check is broken -- the failure mode this repo has
    already recorded twice (`tests/test_feature_map_claims.py`, the `.claude/` link-gate exemption).
    Each detector is run here against a settings document carrying exactly the defect it hunts.
    """
    assert checker(planted), (
        f"the {label} detector returned nothing for a document that contains one. The "
        "corresponding test above is passing for the wrong reason and is not protecting anything."
    )
