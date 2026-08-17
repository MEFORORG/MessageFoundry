# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`.claude/settings.json` is now a TRACKED control, so its shape gets a test.

Tracking the file (see `tests/test_private_paths_stay_ignored.py` for the boundary half) is what
carries the deny-list and the `block-blanket-git-stage` guard to a fresh clone and to every
`git worktree add`. That only buys anything if the payload still works when it arrives, and the two
ways it silently stops working are both invisible to review:

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

Neither is caught by JSON validity, by `pre-commit`, or by reading the diff. Both are caught here.

The deny-list is also the only half of this file that auto mode cannot touch: permission deny rules
are evaluated before the classifier, and unlike `allow` rules they are not gated on the workspace
trust dialog. That is why the pinned subset below is the deny rules and not the allow rules.
"""

from __future__ import annotations

import json
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
    ],
    ids=["unanchored-hook", "dot-anchored-deny"],
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
