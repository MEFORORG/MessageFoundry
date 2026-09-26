# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import ast
import re
import sys
from pathlib import Path

import yaml

from tests._workflow_contexts import load_workflow

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOWS = _ROOT / ".github" / "workflows"
_GATE = _WORKFLOWS / "security.yml"
_RESYNC = _WORKFLOWS / "dependabot-lock-resync.yml"
#: The file the resync derives from the core-lock export, and the command that derives it.
_CLOSURE = "security/runtime-closure-core.txt"
_REGENERATOR = "python3 scripts/security/runtime_closure.py"

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
        flags = match.group("flags")
        # A REPEATED EXPORT IS ALLOWED ONLY WHEN IT IS THE SAME EXPORT. `security.yml` carries a
        # composite job with a byte-identical copy of the DEP-1 step while the security-job
        # consolidation is in progress, so every lock is exported twice there. Two exports of one
        # lock with DIFFERENT flags is the real defect this guard was written for -- the two would
        # write byte-different files and the second would red the diff gate the first just passed --
        # and that is still refused.
        assert found.get(target, flags) == flags, (
            f"{path.name} exports {target} twice with different flags:\n"
            f"  uv export {found[target]} -o {target}\n  uv export {flags} -o {target}"
        )
        found[target] = flags
    assert found, f"no `uv export ... -o <path>` lines found in {path.name}"
    return found


def _paths(pattern: re.Pattern[str], path: Path) -> tuple[str, ...]:
    text = path.read_text(encoding="utf-8")
    matches = pattern.findall(text)
    assert matches, f"no match for {pattern.pattern!r} in {path.name}"
    # SAME RULE AS `_exports`: repeats are fine while they agree. The verification list is duplicated
    # into the composite job for the duration of the security-job consolidation, and a SECOND,
    # DIFFERENT list is what would actually break -- one step verifying a set the other does not.
    distinct = {tuple(m.split()) for m in matches}
    assert len(distinct) == 1, (
        f"{len(matches)} matches for {pattern.pattern!r} in {path.name} naming "
        f"{len(distinct)} different path sets: {sorted(distinct)}"
    )
    return distinct.pop()


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
    """The gate must diff, and the resync must both short-circuit on and stage, every export.

    The resync also stages the one file it DERIVES from an export, the runtime-closure inventory,
    so its lists are the export set plus that file. DEP-1 does not diff it; the closure test in
    ``tests/test_risky_component_designation.py`` does.
    """
    exported = set(_exports(_GATE))
    staged = exported | {_CLOSURE}
    assert set(_paths(_DIFF_EXIT_RE, _GATE)) == exported, "DEP-1 exports a lock it never diffs"
    assert set(_paths(_DIFF_QUIET_RE, _RESYNC)) == staged, (
        "the resync's `git diff --quiet` short-circuit omits an exported lock or the closure file "
        "-- it would report 'already in sync' and skip the push while that file is stale"
    )
    assert set(_paths(_GIT_ADD_RE, _RESYNC)) == staged, (
        "the resync writes a file it never `git add`s -- the push would carry an incomplete set"
    )


def test_the_resync_regenerates_the_closure_file() -> None:
    """RED when: the resync stops rewriting the closure file from the fresh core lock, or a failed
    rewrite can block the lock push or pass silently.

    ``security/runtime-closure-core.txt`` must equal the pin lines of
    ``docker/locks/requirements-core.lock`` (BACKLOG #1812). A Dependabot PR that moves a core
    package re-exports that lock here. Without this step the closure test would then go red with
    no bot-reachable path to green, the #1193 shape again.

    The step order carries the contract. The rewrite runs after the core export, or it copies the
    stale lock. It runs before the commit step, or its output is never pushed. It may not block the
    commit, or one closure problem strands every re-exported lock. A later step must still fail the
    run when it fails.
    """
    steps = load_workflow(_RESYNC.name)["jobs"]["resync"]["steps"]
    names = [str(step.get("name", "")) for step in steps]

    def index_of(needle: str) -> int:
        found = [i for i, step in enumerate(steps) if needle in str(step.get("run", ""))]
        assert len(found) == 1, f"expected one resync step running {needle!r}, found {found}"
        return found[0]

    export = index_of("-o docker/locks/requirements-core.lock")
    regen = index_of(_REGENERATOR)
    commit = index_of("git commit")
    assert export < regen < commit, (
        f"the closure rewrite must sit between the export and the commit steps: {names}"
    )
    step = steps[regen]
    assert step.get("continue-on-error") is True, (
        "the closure rewrite must not block the commit step, or its failure strands the locks"
    )
    step_id = step.get("id")
    assert step_id, "the closure rewrite step needs an id, so a later step can read its outcome"
    failing = [
        s
        for s in steps[commit + 1 :]
        if f"steps.{step_id}.outcome == 'failure'" in str(s.get("if", ""))
        and "exit 1" in str(s.get("run", ""))
    ]
    assert failing, "no step after the commit fails the run when the closure rewrite fails"
    script = _ROOT / _REGENERATOR.split()[1]
    assert script.is_file(), f"the resync runs {script}, which does not exist"


def test_the_resync_checks_out_the_triggering_sha() -> None:
    """RED when: the resync checks out the moving branch tip instead of the triggering SHA.

    The closure step runs a repository script while the App token sits in the checkout's
    credential config. Pinned to the SHA, a commit pushed after the trigger never runs, and the
    push is refused if the branch has moved.
    """
    steps = load_workflow(_RESYNC.name)["jobs"]["resync"]["steps"]
    checkouts = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 1, f"expected one checkout step, found {len(checkouts)}"
    assert checkouts[0]["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"


def test_the_zizmor_suppression_still_points_at_the_actor_check() -> None:
    """RED when: a line added above the job's ``if:`` moves the actor check off its zizmor anchor.

    ``.github/zizmor.yml`` suppresses the ``bot-conditions`` finding on ONE line of this workflow,
    on purpose (its comment says why). Any edit above that line moves it, zizmor then reports the
    finding on the new line, and the scan goes red. Adding the closure step's comments did exactly
    that (BACKLOG #1812), and nothing local caught it.
    """
    config = yaml.safe_load((_ROOT / ".github" / "zizmor.yml").read_text(encoding="utf-8"))
    ignores = config["rules"]["bot-conditions"]["ignore"]
    anchors = [e for e in ignores if str(e).startswith(f"{_RESYNC.name}:")]
    assert len(anchors) == 1, f"expected one {_RESYNC.name} anchor in zizmor.yml, found {anchors}"
    # `file:line`, or zizmor's `file:line:col`; the line is the second field either way.
    line_no = int(str(anchors[0]).split(":")[1])
    line = _RESYNC.read_text(encoding="utf-8").splitlines()[line_no - 1]
    assert "github.triggering_actor == 'dependabot[bot]'" in line, (
        f"zizmor.yml anchors {anchors[0]}, but that line is now {line.strip()!r}. Re-anchor it to "
        "the line holding the triggering_actor check."
    )


def test_the_regenerator_imports_only_the_standard_library() -> None:
    """RED when: the regenerator imports anything a bare runner python3 does not have.

    The resync installs no project and no packages, on purpose (its SECURITY MODEL block), so a
    third-party import would fail there and leave every Dependabot PR red. The runner's python3 is
    older than this project's (3.12 on ubuntu-24.04), so the grammar is checked at 3.12 as well.
    ``sys.stdlib_module_names`` is this interpreter's list, so a module new since 3.12 still passes
    here; the script-mode run in ``tests/test_risky_component_designation.py`` does not catch that
    either. It is a residual, and a narrow one.
    """
    script = _ROOT / _REGENERATOR.split()[1]
    tree = ast.parse(script.read_text(encoding="utf-8"), feature_version=(3, 12))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.partition(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            # Run as a file, the script has no package, so a relative import cannot resolve.
            assert node.level == 0, f"{script.name} has a relative import, which fails as a script"
            if node.module:
                imported.add(node.module.partition(".")[0])
    assert "re" in imported, "the import walk found nothing it should; the parser has broken"
    outside = sorted(imported - sys.stdlib_module_names - {"__future__"})
    assert not outside, f"{script.name} imports outside the standard library: {outside}"


def test_constraints_lock_is_in_the_set() -> None:
    """Regression pin for the #1193 incident: the set must not silently shrink to the old three."""
    assert "constraints.lock" in _exports(_GATE), "DEP-1 stopped diffing constraints.lock"
    assert "constraints.lock" in _exports(_RESYNC), (
        "dependabot-lock-resync.yml stopped re-exporting constraints.lock — every Dependabot uv PR "
        "will be red with no bot-reachable path to green (see this module's docstring)"
    )


def test_release_tools_lock_is_in_the_set() -> None:
    """The release toolchain's lock must stay a DEP-1 member, for the #1193 reason.

    The three tests above compare the gate's export set to the resync's, so they are satisfied by set
    EQUALITY: drop ``ci/locks/release-tools.lock`` from BOTH workflows and every one of them stays green
    while the lock silently stops being re-derived, diffed and re-synced. ``test_constraints_lock_is_in_
    the_set`` exists for exactly that class; this is its counterpart for the lock that arrived later, in
    ``a9354808e``, without one.

    WHY THIS LOCK NEEDS THE PIN. It is the only DEP-1 artifact whose consumer PR CI never runs —
    ``release.yml`` is tag-push only — so a lock that quietly stopped being refreshed would keep
    existing, keep pinning, keep hashing and keep installing, and the first thing to notice would be a
    release built from a year-old toolchain. That is ADR 0034's *"pinned, stale and unpatched is worse
    than floating"* posture, reached with every check in this repository green. FRESHNESS is what is
    being defended, which is why ``test_the_release_signing_toolchain_is_installed_from_a_hashed_lock``
    does not cover it: that test reads the lock's SHAPE, and a stale lock's shape is perfect.

    WHAT THE GATE HALF DUPLICATES, stated so nobody re-derives it as a finding. Since BACKLOG #332 step 6
    added this lock to ``LOCK_INSTALLED_TOOLCHAINS``,
    ``tests/test_ci_venv_pinning.py::test_lock_installed_toolchain_locks_are_in_the_dep1_set`` covers the
    gate half parametrically and MORE strictly — it pins the ``--only-group`` selector as well as the
    ``-o`` path. The first assertion below is therefore belt-and-braces, and deliberately so: that
    coverage is a side effect of a row in a tuple somebody may remove, and this module is where the
    anti-shrink floor is supposed to live. **The RESYNC half is covered nowhere else**, which is the part
    that turns a Dependabot PR red with no bot-reachable path to green.
    """
    assert "ci/locks/release-tools.lock" in _exports(_GATE), (
        "DEP-1 stopped diffing ci/locks/release-tools.lock — the release signing, build and SBOM "
        "toolchain would drift from uv.lock with nothing to report it until a tag push"
    )
    assert "ci/locks/release-tools.lock" in _exports(_RESYNC), (
        "dependabot-lock-resync.yml stopped re-exporting ci/locks/release-tools.lock — every "
        "Dependabot uv PR touching it will be red with no bot-reachable path to green (see this "
        "module's docstring)"
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
