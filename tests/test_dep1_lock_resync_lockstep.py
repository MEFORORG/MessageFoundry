# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural guard: the Dependabot lock-resync must re-export exactly what DEP-1 diffs.

``security.yml``'s DEP-1 step re-runs every ``uv export`` and ``git diff --exit-code``s the result;
``dependabot-lock-resync.yml`` runs the *same* exports on a Dependabot branch and pushes them back,
so the gate goes green without a human. The two lists must stay in lockstep.

They did not, once: PR #1193 added the hashless ``constraints.lock`` to the gate but not to the
resync. A Dependabot ``uv`` PR then pushed three refreshed locks, DEP-1 re-exported four, found
``constraints.lock`` stale, and the PR was red with **no bot-reachable path to green** — every future
python-deps PR would have needed a manual export. These tests fail on that class of drift.

Text-level assertions on the shell inside the ``run:`` blocks (the live Actions run is the
integration test), matching the house style of ``test_dependabot_automerge_guardrails.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._workflow_contexts import load_workflow

_WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_GATE = _WORKFLOWS / "security.yml"
_RESYNC = _WORKFLOWS / "dependabot-lock-resync.yml"

# Every `uv export <flags> -o <path>` line, whichever workflow it lives in.
_EXPORT_RE = re.compile(r"^\s*uv export\s+(?P<flags>.*?)\s+-o\s+(?P<path>\S+)\s*$", re.MULTILINE)
# The gate's own verification list.
_DIFF_EXIT_RE = re.compile(r"^\s*git diff --exit-code --\s+(?P<paths>.+?)\s*$", re.MULTILINE)
# The resync's "nothing changed, skip the push" short-circuit (inside `if ...; then`).
_DIFF_QUIET_RE = re.compile(
    r"^\s*if git diff --quiet --\s+(?P<paths>.+?);\s*then\s*$", re.MULTILINE
)
# The resync's staging list.
_GIT_ADD_RE = re.compile(r"^\s*git add\s+(?P<paths>.+?)\s*$", re.MULTILINE)


def _exports(path: Path) -> dict[str, str]:
    """Map each exported lock path to the exact flag string that produces it."""
    text = path.read_text(encoding="utf-8")
    found: dict[str, str] = {}
    for match in _EXPORT_RE.finditer(text):
        target = match.group("path")
        assert target not in found, f"{path.name} exports {target} twice"
        found[target] = match.group("flags")
    assert found, f"no `uv export ... -o <path>` lines found in {path.name}"
    return found


def _paths(pattern: re.Pattern[str], path: Path) -> tuple[str, ...]:
    text = path.read_text(encoding="utf-8")
    matches = pattern.findall(text)
    assert len(matches) == 1, (
        f"expected exactly one {pattern.pattern!r} in {path.name}, got {len(matches)}"
    )
    return tuple(matches[0].split())


def test_the_resync_exports_exactly_what_the_gate_exports() -> None:
    """A lock the gate re-derives but the resync does not is un-fixable by the bot."""
    gate, resync = _exports(_GATE), _exports(_RESYNC)
    assert set(resync) == set(gate), (
        "dependabot-lock-resync.yml and security.yml's DEP-1 step must export the same lock set; "
        f"only in the gate: {sorted(set(gate) - set(resync))}; "
        f"only in the resync: {sorted(set(resync) - set(gate))}"
    )


def test_export_flags_are_identical_per_lock_file() -> None:
    """Same path, different flags = a byte-different file and a permanently red diff."""
    gate, resync = _exports(_GATE), _exports(_RESYNC)
    for target, flags in sorted(gate.items()):
        assert resync.get(target) == flags, (
            f"{target} is exported with different flags in the two workflows — the resync would "
            f"write a file DEP-1 then rejects.\n  gate:   uv export {flags} -o {target}\n"
            f"  resync: uv export {resync.get(target)} -o {target}"
        )


def test_every_exported_lock_is_verified_and_staged() -> None:
    """The gate must diff, and the resync must both short-circuit on and stage, every export."""
    exported = set(_exports(_GATE))
    assert set(_paths(_DIFF_EXIT_RE, _GATE)) == exported, "DEP-1 exports a lock it never diffs"
    assert set(_paths(_DIFF_QUIET_RE, _RESYNC)) == exported, (
        "the resync's `git diff --quiet` short-circuit omits an exported lock — it would report "
        "'already in sync' and skip the push while that lock is stale"
    )
    assert set(_paths(_GIT_ADD_RE, _RESYNC)) == exported, (
        "the resync re-exports a lock it never `git add`s — the push would carry an incomplete set"
    )


def test_constraints_lock_is_in_the_set() -> None:
    """Regression pin for the #1193 incident: the set must not silently shrink to the old three."""
    assert "constraints.lock" in _exports(_GATE), "DEP-1 stopped diffing constraints.lock"
    assert "constraints.lock" in _exports(_RESYNC), (
        "dependabot-lock-resync.yml stopped re-exporting constraints.lock — every Dependabot uv PR "
        "will be red with no bot-reachable path to green (see this module's docstring)"
    )


def test_the_resync_gate_keeps_its_immutable_author_conjunct() -> None:
    """The zizmor ``bot-conditions`` suppression is sound only while clause 1 is present.

    zizmor flags ``github.triggering_actor`` in this job's ``if:``. That is safe ONLY because it is
    conjoined with the immutable PR-author check: a conjunction can only narrow, so a spoofed actor
    makes the job skip, never run. Drop clause 1 -- or turn the ``&&`` into ``||`` -- and the residual
    actor check becomes a SOLE gate, the exploitable shape. ``.github/zizmor.yml``'s bot-conditions
    entry asserts that shape is absent; this is what makes the assertion true rather than asserted.
    """
    condition = load_workflow("dependabot-lock-resync.yml")["jobs"]["resync"]["if"]
    assert "github.event.pull_request.user.login == 'dependabot[bot]'" in condition, (
        "the immutable author gate is gone; the zizmor bot-conditions suppression is now unsound"
    )
    assert "&&" in condition, "the author gate must CONJOIN the actor check, not replace it"
    assert "||" not in condition, (
        "a disjunction lets the spoofable actor check alone open the job — the dominating shape"
    )
