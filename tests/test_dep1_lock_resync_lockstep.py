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
import functools
import hashlib
import json
import os
import pprint
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests._bash_resolver import require_bash
from tests._workflow_contexts import jobs_of, load_workflow, needs_of

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOWS = _ROOT / ".github" / "workflows"
_GATE = _WORKFLOWS / "security.yml"
_RESYNC = _WORKFLOWS / "dependabot-lock-resync.yml"
#: The files the resync derives from the core, sqlserver, postgres and harness lock exports, and the
#: command that derives them (BACKLOG #1812, #1955, #5933).
_CLOSURES = frozenset(
    {
        "security/runtime-closure-core.txt",
        "security/runtime-closure-sqlserver.txt",
        "security/runtime-closure-postgres.txt",
        "security/runtime-closure-harness.txt",
    }
)
_REGENERATOR = "python3 scripts/security/runtime_closure.py"

# Every `uv export <flags> -o <path>` line, whichever workflow it lives in.
_EXPORT_RE = re.compile(r"^\s*uv export\s+(?P<flags>.*?)\s+-o\s+(?P<path>\S+)\s*$", re.MULTILINE)
# The gate's own verification list.
_DIFF_EXIT_RE = re.compile(r"^\s*git diff --exit-code --\s+(?P<paths>.+?)\s*$", re.MULTILINE)
# The resync's "nothing changed, skip the push" short-circuit (inside `if ...; then`). It compares the
# index, which the staging step writes by content, with HEAD.
_DIFF_QUIET_RE = re.compile(
    r"^\s*if git diff --cached --quiet --\s+(?P<paths>.+?);\s*then\s*$", re.MULTILINE
)


@functools.cache
def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _exports(path: Path) -> dict[str, str]:
    """Map each exported lock path to the exact flag string that produces it."""
    text = _text(path)
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
    text = _text(path)
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

    The resync also stages the files it DERIVES from two exports, the runtime-closure inventories,
    so its lists are the export set plus those files. DEP-1 does not diff them; the closure tests in
    ``tests/test_risky_component_designation.py`` do.
    """
    exported = set(_exports(_GATE))
    staged = exported | _CLOSURES
    assert set(_paths(_DIFF_EXIT_RE, _GATE)) == exported, "DEP-1 exports a lock it never diffs"
    assert set(_paths(_DIFF_QUIET_RE, _RESYNC)) == staged, (
        "the resync's `git diff --cached --quiet` short-circuit omits an exported lock or a closure "
        "file -- it would report 'already in sync' and skip the push while that file is stale"
    )
    # The staging step's list is checked against the same set in
    # test_the_lock_files_cross_jobs_as_one_artifact_of_the_staged_set. A `git add` after it would
    # stage the PR head's working-tree bytes back over the staged content.
    from tests.test_ci_venv_pinning import _executed_shell

    porcelain = re.compile(r"\bgit\s+(?:add|stage|commit)(?![\w-])")
    assert porcelain.search("git commit -a -m x") and porcelain.search("git stage x")
    assert not porcelain.search('git commit-tree "${tree}"')
    adders = [
        (job, step.get("name"))
        for job, step in _all_steps()
        if porcelain.search(_executed_shell(str(step.get("run") or "")))
    ]
    assert not adders, f"the resync stages or commits from the working tree: {adders}"


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

    The export and the rewrite run in the secretless ``export`` job and the commit in the ``push``
    job (BACKLOG #5477), so the rewrite's outcome crosses as an ``export`` job output that a step
    after the commit reads.
    """
    steps = _job_steps("export")
    names = [str(step.get("name", "")) for step in steps]

    def index_of(needle: str, where: list[dict[str, Any]]) -> int:
        found = [i for i, step in enumerate(where) if needle in str(step.get("run", ""))]
        assert len(found) == 1, f"expected one step running {needle!r}, found {found}"
        return found[0]

    export = max(
        index_of("-o docker/locks/requirements-core.lock", steps),
        index_of("-o docker/locks/requirements-sqlserver.lock", steps),
        index_of("-o security/locks/requirements-harness.lock", steps),
    )
    regen = index_of(_REGENERATOR, steps)
    handoff = [i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith(_UPLOAD)]
    assert len(handoff) == 1, f"expected one artifact upload in the export job: {names}"
    assert export < regen < handoff[0], (
        f"the closure rewrite must sit between the export and the artifact upload: {names}"
    )
    step = steps[regen]
    # With no arguments the script rewrites every closure pair. Naming one would silently leave the
    # others stale on every Dependabot PR (BACKLOG #1955).
    calls = [ln.strip() for ln in str(step["run"]).splitlines() if "runtime_closure.py" in ln]
    assert calls == [_REGENERATOR], f"the resync must run {_REGENERATOR!r} bare, found {calls}"
    assert step.get("continue-on-error") is True, (
        "the closure rewrite must not block the commit step, or its failure strands the locks"
    )
    step_id = step.get("id")
    assert step_id, "the closure rewrite step needs an id, so a later step can read its outcome"
    outputs = _job("export").get("outputs") or {}
    output = [k for k, v in outputs.items() if str(v) == f"${{{{ steps.{step_id}.outcome }}}}"]
    assert len(output) == 1, f"the export job must output the closure step's outcome: {outputs}"
    push = _job_steps("push")
    commit = index_of("git commit", push)
    failing = [
        s
        for s in push[commit + 1 :]
        if str(s.get("if", "")).strip() == f"needs.export.outputs.{output[0]} == 'failure'"
        and "exit 1" in str(s.get("run", ""))
    ]
    assert failing, "no step after the commit fails the run when the closure rewrite fails"
    script = _ROOT / _REGENERATOR.split()[1]
    assert script.is_file(), f"the resync runs {script}, which does not exist"


def test_the_resync_checks_out_the_triggering_sha() -> None:
    """RED when: the resync checks out the moving branch tip instead of the triggering SHA.

    The closure step runs a repository script from this checkout. Pinned to the SHA, a commit
    pushed after the trigger never runs, and the push is refused if the branch has moved. The export
    and push jobs each check out, and both must take the same SHA, or the push job would commit the
    export job's files over a different tree.
    """
    checkouts = _steps_using("actions/checkout@")
    assert [job for job, _ in checkouts] == ["export", "push"], (
        f"expected one checkout in each of export and push, found {checkouts}"
    )
    for job, step in checkouts:
        assert step["with"]["ref"] == "${{ github.event.pull_request.head.sha }}", job


def test_the_regenerator_imports_only_the_standard_library() -> None:
    """RED when: the regenerator imports anything a bare runner python3 does not have.

    The resync installs no project and no packages, on purpose (its SECURITY MODEL block), so a
    third-party import would fail there and leave every Dependabot PR red. The runner's python3 is
    older than this project's (3.12 on ubuntu-24.04, the image ubuntu-latest named on 2026-09-26),
    so the grammar is checked at 3.12 as well, on a best-effort basis. This check and the
    script-mode run in ``tests/test_risky_component_designation.py`` both use this interpreter, so
    they miss at least a stdlib module or API newer than the runner's. The Manager accepted that
    residual on 2026-09-26.
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

    zizmor flags ``github.triggering_actor`` in the preflight job's ``if:``. That is safe ONLY because
    it is conjoined with the immutable PR-author check: a conjunction can only narrow, so a spoofed
    actor makes the job skip, never run. Drop clause 1 -- or turn the ``&&`` into ``||`` -- and the
    residual actor check becomes a SOLE gate, the exploitable shape. ``.github/zizmor.yml``'s
    bot-conditions entry asserts that shape is absent; this is what makes the assertion true rather
    than asserted. Every other job repeats the author check beside its need on the preflight job,
    under the same no-``||`` rule, so a job added later is held to it too.
    """
    assert sorted(_jobs()) == sorted(_JOB_IDS), f"the resync jobs are {sorted(_jobs())}"
    for job in _jobs():
        condition = str(_job(job).get("if", ""))
        assert "github.event.pull_request.user.login == 'dependabot[bot]'" in condition, (
            f"{job}: the immutable author gate is gone; the zizmor bot-conditions suppression is now "
            "unsound"
        )
        assert "&&" in condition, f"{job}: the author gate must CONJOIN the other check"
        assert "||" not in condition, (
            f"{job}: a disjunction lets the other check alone open the job — the dominating shape"
        )
    assert "github.triggering_actor == 'dependabot[bot]'" in str(_job("preflight")["if"])


#: The three jobs, split by what they hold (BACKLOG #5477), in the order they run.
_JOB_IDS = ("preflight", "export", "push")
_UPLOAD = "actions/upload-artifact@"
_DOWNLOAD = "actions/download-artifact@"
_MINT = "actions/create-github-app-token@"


@functools.cache
def _jobs() -> dict[str, dict[str, Any]]:
    """The resync workflow's jobs, parsed once. Read-only: every test shares this mapping."""
    jobs = jobs_of(_RESYNC.name)
    assert jobs, "the resync workflow parsed to no jobs"
    return jobs


def _job(name: str) -> dict[str, Any]:
    jobs = _jobs()
    assert name in jobs, f"the resync workflow has no {name!r} job (jobs: {sorted(jobs)})"
    return jobs[name]


def _job_steps(name: str) -> list[dict[str, Any]]:
    steps = _job(name).get("steps")
    assert isinstance(steps, list) and steps, f"the {name} job parsed to no steps"
    return steps


def _all_steps() -> list[tuple[str, dict[str, Any]]]:
    return [(job, s) for job, body in _jobs().items() for s in body.get("steps") or []]


def _steps_using(prefix: str) -> list[tuple[str, dict[str, Any]]]:
    return [(j, s) for j, s in _all_steps() if str(s.get("uses", "")).startswith(prefix)]


# What hands a step the minted token or the App key, in any spelling a step could use: the dotted or
# indexed reference (both name the step id or the secret), or a dump of the whole context.
_TOKEN_NEEDLES = ("steps.app-token", "steps['app-token']", 'steps["app-token"]', "tojson(steps")
_KEY_NEEDLES = ("lock_resync_app_private_key", "tojson(secrets")
# Any secret at all, in any spelling: the dotted or indexed context, or a dump of it.
_SECRET_NEEDLES = ("secrets.", "secrets[", "tojson(secrets", *_TOKEN_NEEDLES, _MINT)


def _strings_in(value: object) -> list[str]:
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _strings_in(k) + _strings_in(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings_in(v)]
    return [str(value)]


def _normalised(value: object) -> str:
    return " | ".join(_strings_in(value)).casefold().replace(" ", "")


def _named(value: object, needles: tuple[str, ...]) -> list[str]:
    """The needles ``value``'s text names, case and spacing ignored."""
    text = _normalised(value)
    return [n for n in needles if n.casefold().replace(" ", "") in text]


def _steps_naming(needles: tuple[str, ...]) -> list[tuple[str, str]]:
    """Steps whose text (their own ``id`` aside) names any needle, case and spacing ignored."""
    return [
        (job, str(s.get("id") or s.get("name") or s.get("uses")))
        for job, s in _all_steps()
        if _named({k: v for k, v in s.items() if k != "id"}, needles)
    ]


def test_the_resync_job_env_hands_out_no_credential() -> None:
    """RED when: the workflow's ``env:`` or any job-level key (``env:``, ``outputs:``, ...) names
    the token or the key, which hands it to every step of that scope or out of the job."""
    workflow = load_workflow(_RESYNC.name)
    scopes = [("workflow env", workflow.get("env"))]
    scopes += [
        (f"{job} job", {k: v for k, v in body.items() if k != "steps"})
        for job, body in _jobs().items()
    ]
    for where, value in scopes:
        assert not _named(value or {}, _TOKEN_NEEDLES + _KEY_NEEDLES), (
            f"the resync {where} names the App token or key"
        )


def test_the_resync_checkout_persists_no_credential() -> None:
    """RED when: a checkout writes a credential into .git/config (BACKLOG #5477).

    uv and a repository script run on the Dependabot-changed tree after the export job's checkout. A
    persisted contents-write App token would sit on disk for both; the push step takes it from its
    own environment instead, and the push job's checkout persists nothing either.
    """
    checkouts = _steps_using("actions/checkout@")
    assert checkouts, "no checkout step found"
    for job, step in checkouts:
        with_ = step.get("with") or {}
        assert isinstance(with_, dict)
        assert with_.get("persist-credentials") is False, (
            f"the {job} checkout must set persist-credentials: false"
        )
        assert "token" not in with_, (
            f"the {job} checkout needs no App token: the run's read-only token fetches the PR head"
        )


def test_only_the_push_step_receives_the_app_token() -> None:
    """RED when: a step other than the push names the minted token's output (BACKLOG #5477).

    This pins the expression reference only, dotted, indexed or as a ``toJSON(steps)`` dump. The token
    is live on the push job's runner from the mint step on; what this holds is that no other step is
    handed it.
    """
    readers = _steps_naming(_TOKEN_NEEDLES)
    assert readers == [("push", "Commit and push the resynced locks")], (
        f"steps reading the App token: {readers}"
    )


# The uv the DEP-1 gate installs, e.g. `pip install --upgrade pip "uv==0.12.0"`.
_GATE_UV_PIN_RE = re.compile(r"\buv==(?P<version>[0-9][0-9A-Za-z.+-]*)")


def test_the_resync_installs_the_uv_the_gate_pins() -> None:
    """RED when: setup-uv is unpinned or pinned to a uv other than DEP-1's (BACKLOG #5477).

    The resync must write the bytes DEP-1 diffs. With no ``version:`` setup-uv installs the latest
    uv, whose export format can move ahead of the gate's, so the bot would push locks the gate then
    finds stale -- or, worse, an unreviewed uv would serialize the locks the project audits.
    """
    gate_pins = set(_GATE_UV_PIN_RE.findall(_text(_GATE)))
    assert len(gate_pins) == 1, f"security.yml pins uv at {sorted(gate_pins)}; expected one version"
    setups = _steps_using("astral-sh/setup-uv@")
    assert len(setups) == 1, f"expected one setup-uv step, found {len(setups)}"
    with_ = setups[0][1].get("with") or {}
    assert isinstance(with_, dict)
    assert str(with_.get("version", "")) == gate_pins.pop(), (
        f"setup-uv installs uv {with_.get('version')!r}, not the uv security.yml's DEP-1 step pins"
    )


def test_the_app_key_is_used_only_by_the_mint_step_of_the_push_job() -> None:
    """RED when: the mint step, which takes the App's long-lived private key, is not the push job's
    step directly before the commit, or another step is handed the key.

    The push job runs no code from the Dependabot-changed tree (pinned below). Minting directly
    before the commit means the token does not exist while the untrusted artifact is fetched and
    staged, and a refused artifact mints nothing. The key is a secret of the push job only; the
    export job, which runs uv and the repository script, references no secret at all (pinned below).
    """
    steps = _job_steps("push")
    position = {str(s.get("id") or s.get("name")): i for i, s in enumerate(steps)}
    assert position["app-token"] + 1 == position["Commit and push the resynced locks"], (
        "the App token must be minted directly before the commit step"
    )
    assert position["app-token"] > position[_COPY_STEP], (
        "the token is minted before the staging step"
    )
    key_readers = _steps_naming(_KEY_NEEDLES)
    assert key_readers == [("push", "app-token")], (
        f"steps handed the App private key: {key_readers}"
    )


#: The actions a job that holds the App key or token may use. None of them runs code from the checkout.
_CREDENTIAL_JOB_ACTIONS = ("actions/checkout@", _DOWNLOAD, _MINT)
#: The commands such a job's run blocks may invoke. An ALLOWLIST, so a command nobody listed is
#: refused; the argument rules in ``_disallowed_commands`` narrow git and find further.
#:
#: BEST-EFFORT, AND NOT THE CONTROL THAT HOLDS THE PUSH JOB. ``_shell_words`` is not a shell parser,
#: so at least these get past it: a ``(`` or ``)`` inside quotes inside a substitution (the body is
#: cut by counting parentheses), a variable assigned by ``printf -v`` or ``read``, a redirect target
#: (skipped, never checked), and the path arguments after ``git diff --cached --quiet --``. What
#: holds the credential jobs is ``test_the_credential_job_steps_are_pinned_by_content``: any edit to
#: one of their steps is red until the same change re-pins it. This screen is kept as a reviewer's
#: aid that names the obvious cases.
_CREDENTIAL_COMMANDS = frozenset(
    {":", "[", "[[", "base64", "echo", "exit", "export", "find", "git", "printf", "pwd"}
    | {"read", "realpath", "set", "test", "true"}
)
#: Words that may stand ahead of a command name without being one.
_SHELL_KEYWORDS = frozenset({"!", "{", "}", "if", "then", "elif", "else", "fi", "while", "until"})
_SHELL_KEYWORDS |= {"do", "done", "esac"}
#: The git subcommands the push may run, and the git config keys it may set. git reads others as
#: programs to run (an alias, a submodule foreach, a rebase --exec, core.fsmonitor, diff drivers).
_GIT_SUBCOMMANDS = frozenset(
    {"commit-tree", "config", "diff", "hash-object", "push", "update-index", "write-tree"}
)
_GIT_CONFIG_SET = frozenset({"user.name", "user.email"})
#: The git subcommands that stage, commit and push, each with the only argument list it may take.
#: hash-object without ``--no-filters`` runs the filter driver the tree's .gitattributes names;
#: update-index has ``--index-info`` and other forms that read arbitrary entries; push has
#: ``--receive-pack`` and ``--exec``, which name a program.
_GIT_EXACT_ARGS = {
    "hash-object": ["hash-object", "-w", "--no-filters", "--", "${src}/${rel}"],
    "update-index": ["update-index", "--add", "--cacheinfo", "100644,${oid},${rel}"],
    "write-tree": ["write-tree"],
    "commit-tree": [
        "commit-tree",
        "${tree}",
        "-p",
        "HEAD",
        "-m",
        "chore(deps): resync exported lock files (DEP-1)",
    ],
    "push": ["push", "origin", "${commit}:refs/heads/${HEAD_REF}"],
}
#: ``git diff`` may take only this prefix, then paths. ``--ext-diff`` or ``--textconv`` run programs.
_GIT_DIFF_PREFIX = ["diff", "--cached", "--quiet", "--"]
#: The git config the push may set through GIT_CONFIG_*, each key with the exact value it must
#: carry. Any other key, or the same key with another value (core.fsmonitor naming a program), is
#: refused.
_GIT_ENV_CONFIG = {
    "core.hooksPath": "/dev/null",
    "core.fsmonitor": "false",
    "http.https://github.com/.extraheader": "AUTHORIZATION: basic ${auth}",
}
_GIT_ENV_PAIR = re.compile(
    r"\bGIT_CONFIG_(?P<kind>KEY|VALUE)_(?P<index>\d+)="
    r"(?:'(?P<sq>[^']*)'|\"(?P<dq>[^\"]*)\"|(?P<bare>\S*))"
)
#: A shell variable a credential job may assign: lower-case script locals, IFS for one read, and the
#: GIT_CONFIG_* triple. Anything else upper-case can change what the shell or git runs (at least
#: BASH_ENV, ENV, PATH, LD_PRELOAD, GIT_EXEC_PATH, GIT_EXTERNAL_DIFF, GIT_SSH_COMMAND).
_ASSIGNABLE = re.compile(r"[a-z_][a-z0-9_]*|IFS|GIT_CONFIG_COUNT|GIT_CONFIG_(?:KEY|VALUE)_\d+")
_ASSIGNMENT = re.compile(r"(?P<name>[A-Za-z_]\w*)=(?P<value>.*)", re.DOTALL)
_REDIRECT = re.compile(r"\d*(?:<|>|>>|&>)")


def _substitutions(text: str) -> tuple[str, list[str]]:
    """``text`` with each ``$(...)``, ``<(...)`` and ``>(...)`` replaced by a placeholder word, and
    the bodies it replaced. Parentheses are matched by count; quotes inside a body are not parsed."""
    outer: list[str] = []
    bodies: list[str] = []
    i = 0
    while i < len(text):
        if text[i] in "$<>" and text[i + 1 : i + 2] == "(":
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[j], 0)
                j += 1
            bodies.append(text[i + 2 : j - 1])
            outer.append(f"__substitution_{len(bodies)}__")
            i = j
        else:
            outer.append(text[i])
            i += 1
    return "".join(outer), bodies


def _assignment_offence(word: str) -> str | None:
    match = _ASSIGNMENT.fullmatch(word)
    assert match
    name, value = match["name"], match["value"]
    if not _ASSIGNABLE.fullmatch(name):
        return f"assigns {name}"
    if name.startswith("GIT_CONFIG_KEY_") and value not in _GIT_ENV_CONFIG:
        return f"sets git config {value!r} through the environment"
    return None


def _disallowed_commands(script: str) -> list[str]:
    """Every simple command in ``script`` that is not on ``_CREDENTIAL_COMMANDS``, every allowed
    command used in a way that runs or plants something else, and every variable assignment off
    ``_ASSIGNABLE``. Substitutions are read too; a backtick substitution is refused outright, and so
    is any mention of $GITHUB_ENV or $GITHUB_PATH, which hand a later step an environment or PATH."""
    from tests.test_ci_venv_pinning import _commands, _executed_shell

    text = _executed_shell(script).replace("\\\n", " ")
    bad = ["a backtick substitution"] if "`" in text else []
    bad += [f"names {v}" for v in ("GITHUB_ENV", "GITHUB_PATH") if v in text]
    outer, bodies = _substitutions(text)
    for body in bodies:
        bad += _disallowed_commands(body)
    pairs: dict[str, dict[str, str]] = {}
    for m in _GIT_ENV_PAIR.finditer(text):
        value = next(v for v in (m["sq"], m["dq"], m["bare"]) if v is not None)
        pairs.setdefault(m["index"], {})[m["kind"]] = value
    for index, pair in sorted(pairs.items()):
        key, value = pair.get("KEY", ""), pair.get("VALUE")
        if _GIT_ENV_CONFIG.get(key) != value:
            bad.append(f"GIT_CONFIG_*_{index} sets {key!r} to {value!r}")
    for line in outer.splitlines():
        for raw in _commands(line):
            words: list[str] = []
            skip_target = False
            for word in raw:
                if skip_target:
                    skip_target = False
                elif _REDIRECT.fullmatch(word):
                    skip_target = True  # `< file`: the next word is the target, not an argument
                elif not _REDIRECT.match(word):
                    words.append(word)
            while words and (words[0] in _SHELL_KEYWORDS or _ASSIGNMENT.fullmatch(words[0])):
                if _ASSIGNMENT.fullmatch(words[0]):
                    offence = _assignment_offence(words[0])
                    if offence:
                        bad.append(f"{offence} in {line.strip()!r}")
                words = words[1:]
            if not words or words[0] == "for":
                continue  # a loop header; its body lines are read on their own
            name, args = words[0], words[1:]
            shown = line.strip()
            if name not in _CREDENTIAL_COMMANDS:
                bad.append(f"{name!r} in {shown!r}")
            elif name == "export":
                for arg in args:
                    offence = _assignment_offence(arg) if _ASSIGNMENT.fullmatch(arg) else None
                    if offence or not _ASSIGNMENT.fullmatch(arg):
                        bad.append(f"export {arg!r} in {shown!r}")
            elif name == "git":
                if not args or args[0] not in _GIT_SUBCOMMANDS:
                    bad.append(f"git {args[:1]} in {shown!r}")
                elif args[0] == "config" and (len(args) != 3 or args[1] not in _GIT_CONFIG_SET):
                    bad.append(f"git config {args[1:2]} in {shown!r}")
                elif args[0] in _GIT_EXACT_ARGS and args != _GIT_EXACT_ARGS[args[0]]:
                    bad.append(f"git {args[0]} with other arguments: {shown!r}")
                elif args[0] == "diff" and (
                    args[:4] != _GIT_DIFF_PREFIX or any(a.startswith("-") for a in args[4:])
                ):
                    bad.append(
                        f"git diff other than `git diff --cached --quiet -- <paths>`: {shown!r}"
                    )
            elif name == "find" and any(a.startswith(("-exec", "-ok", "-delete")) for a in args):
                bad.append(f"find runs or deletes: {shown!r}")
    return bad


def _step_offences(step: dict[str, Any]) -> list[str]:
    """What in ``step`` could run code a job holding the App key or token must not run."""
    uses = str(step.get("uses", ""))
    offences = [f"uses {uses}"] if uses and not uses.startswith(_CREDENTIAL_JOB_ACTIONS) else []
    if "shell" in step:
        offences.append(f"shell: {step['shell']}")
    for name in step.get("env") or {}:
        if str(name) not in _CREDENTIAL_STEP_ENV:
            offences.append(f"env {name}")
    return offences + _disallowed_commands(str(step.get("run") or ""))


#: The step env names a credential job may set. Each carries data, and none is a variable the
#: shell, git or the runner reads as configuration.
_CREDENTIAL_STEP_ENV = frozenset({"APP_ID", "APP_TOKEN", "HEAD_REF"})


def test_the_command_allowlist_refuses_what_it_must() -> None:
    """Positive and negative controls for the allowlist the two job-split tests below rest on."""
    for run in (
        "uv lock --check",
        "set -e\n  python3 scripts/security/runtime_closure.py",
        "FOO=1 python -c pass",
        "FOO='a b' python3 x.py",
        "./run.sh",
        "docker/build.sh",
        "if python3 x.py; then :; fi",
        "if true; then bash x; fi",
        ". ./env.sh",
        "sudo python3 x.py",
        "sudo cp -- evil ${rel}",
        "time python3 scripts/x.py",
        "echo `python3 x.py`",
        'x="$(echo a | python3 -)"',
        ">/dev/null python3 evil.py",
        "</dev/null python3 evil.py",
        "find . -exec python3 {} \\;",
        "git -c alias.x=!sh x",
        "git submodule foreach python3 evil.py",
        "git config alias.x '!python3 evil.py'",
        "git x",
        "GIT_EXTERNAL_DIFF='python3 evil.py' git diff",
        "GIT_EXEC_PATH=./tree git push",
        "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./evil.sh",
        "export BASH_ENV=./evil.sh",
        "PATH=./bin:$PATH git push",
        'echo "BASH_ENV=${PWD}/evil.sh" >> "$GITHUB_ENV"',
        'echo "${PWD}/bin" >> "$GITHUB_PATH"',
        "cp scripts/evil ~/.local/bin/git",
        'cp -- "${src}/${rel}" "${rel}"',
        "git add requirements.lock",
        "git commit -a -m x",
        "git stage requirements.lock",
        'git push --receive-pack=./evil origin "${commit}:refs/heads/${HEAD_REF}"',
        'git push origin "HEAD:refs/heads/${HEAD_REF}"',
        "git diff --ext-diff --cached --quiet -- a",
        "git diff --cached --quiet -- a --textconv",
        'git hash-object -w -- "${src}/${rel}"',
        "git hash-object --stdin-paths -w",
        "git update-index --index-info",
        'git update-index --add --cacheinfo "100755,${oid},${rel}"',
        "awk 1 f",
        "while python3 x.py; do :; done",
    ):
        assert _disallowed_commands(run), run
    assert _step_offences({"uses": "astral-sh/setup-uv@abc"})
    assert _step_offences({"run": "print(1)", "shell": "python {0}"})
    assert _step_offences({"run": "git push", "env": {"BASH_ENV": "scripts/evil.sh"}})
    for run in (
        'git push origin "${commit}:refs/heads/${HEAD_REF}"',
        'tree="$(git write-tree)"',
        "git diff --cached --quiet -- requirements.lock constraints.lock",
        'echo "::error::scripts/security/runtime_closure.py failed"',
        'oid="$(git hash-object -w --no-filters -- "${src}/${rel}")"',
        'git update-index --add --cacheinfo "100644,${oid},${rel}"',
        "# python3 scripts/x.py",
        'root="$(pwd -P)"',
        "export GIT_CONFIG_KEY_0='core.hooksPath' GIT_CONFIG_VALUE_0='/dev/null'",
        "git config user.name 'dependabot[bot]'",
        "done < __substitution_1__",
    ):
        assert not _disallowed_commands(run), (run, _disallowed_commands(run))


def test_the_job_that_runs_pr_tree_code_holds_no_secret() -> None:
    """RED when: a job that runs uv, an interpreter or a repository script on the Dependabot-changed
    tree also references a secret or the minted token, or the workflow's env or defaults reach it
    (BACKLOG #5477, added closing step 1).

    Before the split, one job held the App key and the minted token while uv and the repository
    script ran. Now that code runs in a job whose text names no secret and no token, so no step of
    it is handed either, and the key and token live only in the push job, a separate runner that
    starts after this job ends. Whether the service ever delivers a secret a job does not reference
    to that job's runner is not measured here.
    """
    workflow = load_workflow(_RESYNC.name)
    assert not _named(workflow.get("env") or {}, _SECRET_NEEDLES), "the workflow env names a secret"
    assert "defaults" not in workflow, "a workflow-level defaults block reaches every job"
    tree_jobs = [
        j for j, body in _jobs().items() if any(_step_offences(s) for s in body.get("steps") or [])
    ]
    assert tree_jobs == ["export"], f"jobs running code off the credential allowlist: {tree_jobs}"
    named = _named(_job("export"), _SECRET_NEEDLES)
    assert not named, f"the export job, which runs PR-tree code, names {named}"
    assert _job("export").get("permissions") == {"contents": "read"}, (
        "the export job's GITHUB_TOKEN must be read-only"
    )
    assert _job("export").get("runs-on") == "ubuntu-latest", "the export job must be GitHub-hosted"


def test_the_credential_jobs_run_no_code_from_the_pr_tree() -> None:
    """RED when: a job that references a secret or the minted token runs a command or an action off
    a short allowlist, or sets a shell (BACKLOG #5477, added closing steps 1 and 2).

    The token routes engine PR 3117 named (GITHUB_PATH, BASH_ENV, a filter driver, gpg.program) all
    need code from the Dependabot-changed tree to run on the runner that holds the token, earlier in
    the same job. Each job is a fresh GitHub-hosted runner, so with no such code in the credential
    jobs, nothing that code writes to $GITHUB_ENV, $GITHUB_PATH, .git/config or disk reaches them.
    """
    holders = [j for j, body in _jobs().items() if _named(body, _SECRET_NEEDLES)]
    assert holders == ["preflight", "push"], f"jobs naming a secret or the token: {holders}"
    for job in holders:
        body = _job(job)
        assert body.get("runs-on") == "ubuntu-latest", (
            f"{job} must run on a fresh GitHub-hosted runner, not one a PR-tree job could have used"
        )
        assert not {"defaults", "container", "env", "services"} & set(body), (
            f"{job} sets a job-level defaults, container, env or services"
        )
        for step in _job_steps(job):
            label = step.get("name") or step.get("uses")
            offences = _step_offences(step)
            assert not offences, f"{job}: step {label!r}: {offences}"


def _pinned_form(step: dict[str, Any]) -> dict[str, Any]:
    """``step`` with an action's ``uses:`` cut to its name. A Dependabot SHA bump of that action then
    needs no re-pin; which actions a credential job may use is held by ``_CREDENTIAL_JOB_ACTIONS``."""
    if "uses" not in step:
        return step
    return {**step, "uses": str(step["uses"]).partition("@")[0]}


def _content_hash(value: object) -> str:
    """A sha256 over ``value``'s whole parsed content, every key and value, in a stable spelling."""
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: Each credential job's own keys (everything but ``steps``), then each of its steps in order, by
#: the sha256 of its whole parsed content. RE-PIN ONLY AFTER A REVIEW OF THE EDIT: these jobs hold
#: the App key or the minted token, and a pinned step is how an edit to one is forced past a
#: reviewer rather than past the best-effort command screen above (BACKLOG #5477).
_PINNED_CREDENTIAL_JOBS: dict[str, list[tuple[str, str]]] = {
    "preflight": [
        ("preflight job keys", "16a15909e2be5bd198d7f324dcbeed055d5eda7e2c80cdcf2836b7e1bade574f"),
        (
            "Are the App credentials visible to this run?",
            "85adb327a30b388ea8083c49df0d2189cd90bc8d79af657621684053e6bddd35",
        ),
    ],
    "push": [
        ("push job keys", "2e5e3a208d0ada173fe5ae457147ded7e9626fcd4fa88e9b9a9f758770ead824"),
        (
            "Check out the PR head",
            "6fa7fb3f00652e59f28b00f18630c7055b48d7e1918e873833a30f13d5774c00",
        ),
        (
            "Fetch the re-exported files from the export job",
            "878ce3b1dd270c684ec38c64958955e4828dc186446cafb0b731282403a46aae",
        ),
        (
            "Stage the re-exported files by content",
            "1db538a0bc3e036c0a9fbf9d72e41e03e53c55bb3957f450f4a33ec91f5514b7",
        ),
        (
            "Mint a scoped GitHub App token",
            "87a5155a5cc00447acc0b9c47a68ad90ebfc4d2202ec231240f9753116888d85",
        ),
        (
            "Commit and push the resynced locks",
            "03992f0faf7d08e33b9578e3847192932885184ff50efcc36c63e521680c9012",
        ),
        (
            "Fail if the closure inventory could not be regenerated",
            "1cea2d429629c458fff71587a8943fc7426e9f5afd9d44aae485e8af124ff130",
        ),
    ],
}


def _credential_job_pins() -> dict[str, list[tuple[str, str]]]:
    pins: dict[str, list[tuple[str, str]]] = {}
    for job in _PINNED_CREDENTIAL_JOBS:
        body = _job(job)
        rows = [(f"{job} job keys", _content_hash({k: v for k, v in body.items() if k != "steps"}))]
        rows += [
            (str(s.get("name") or s.get("uses")), _content_hash(_pinned_form(s)))
            for s in _job_steps(job)
        ]
        pins[job] = rows
    return pins


def test_the_credential_job_steps_are_pinned_by_content() -> None:
    """RED when: any step of the preflight or push job changes at all, other than an action's
    pinned SHA, or a step is added, removed or reordered, or either job's own keys (``if:``,
    ``needs``, ``permissions``, ...) change (BACKLOG #5477).

    The command screen above parses shell with a word splitter, so a run block can be written to get
    past it. Pinning each step's whole content (its run body, env, with, if, continue-on-error and
    every other key) holds the jobs that hold the App key or token unchanged since they were last
    pinned: an edit is red until the same change re-pins it, so the re-pin shows in the diff. That is
    reviewed only as the rest of the diff is; the pin does not judge whether the edit is safe. The
    failure prints the new pins as a literal to paste in.
    """
    actual = _credential_job_pins()
    assert actual == _PINNED_CREDENTIAL_JOBS, (
        "a credential job's content changed; review the edit, then re-pin with:\n"
        + pprint.pformat(actual, width=100)
    )


def test_no_workflow_or_job_env_is_set() -> None:
    """RED when: the workflow or any of its jobs sets an ``env:`` block (BACKLOG #5477).

    A workflow-level env reaches every step of the credential jobs, beside the token, and a job-level
    one every step of its job; either could set BASH_ENV, GIT_CONFIG_*, PATH or LD_PRELOAD. No job
    needs one, so none is allowed, rather than a denylist of names to keep complete. Step-level env
    in the credential jobs is held to ``_CREDENTIAL_STEP_ENV`` above, and their steps are pinned.
    """
    workflow = load_workflow(_RESYNC.name)
    assert "env" not in workflow, f"the resync sets a workflow-level env: {workflow.get('env')}"
    with_env = [job for job, body in _jobs().items() if "env" in body]
    assert not with_env, f"these resync jobs set a job-level env: {with_env}"


def test_the_push_job_reads_the_export_job_only_through_the_artifact_and_an_if() -> None:
    """RED when: the push job does not need the export job, or puts anything the export job produced
    into a shell or an environment rather than an ``if:`` (BACKLOG #5477).

    The export job ran code from the Dependabot-changed tree, so its outputs are untrusted. In an
    ``if:`` an output is compared, never executed; interpolated into a ``run:`` or an ``env:`` it is
    template injection beside the token. No ``run:`` of the push job interpolates anything, so its
    inputs reach the shell through ``env:`` alone.
    """
    push = _job("push")
    needs = needs_of(push)
    assert set(needs) == {"preflight", "export"}, f"the push job needs {needs}"
    assert "needs.preflight.outputs.present == 'true'" in str(push.get("if", ""))
    job_level = _normalised({k: v for k, v in push.items() if k not in ("if", "needs", "steps")})
    assert "needs." not in job_level, "the push job reads a job output outside its if:"
    for step in push["steps"]:
        label = step.get("name") or step.get("uses")
        assert "${{" not in str(step.get("run", "")), f"push step {label!r} interpolates in run:"
        rest = _normalised({k: v for k, v in step.items() if k != "if"})
        assert "needs." not in rest, f"push step {label!r} reads a job output outside its if:"
    export = _job("export")
    assert export.get("needs") == "preflight", "the export job must wait on the preflight job"
    assert "needs.preflight.outputs.present == 'true'" in str(export.get("if", ""))


def _copy_step() -> dict[str, Any]:
    steps = [s for s in _job_steps("push") if s.get("name") == _COPY_STEP]
    assert len(steps) == 1, f"expected one {_COPY_STEP!r} step in the push job"
    return steps[0]


_COPY_STEP = "Stage the re-exported files by content"


def _artifact_dir() -> str:
    """Where the push job downloads the artifact, as the staging step's shell spells it."""
    [(_, download)] = _steps_using(_DOWNLOAD)
    path = str(download["with"]["path"])
    assert path.startswith("${{ runner.temp }}/"), f"the artifact downloads to {path}"
    return path.replace("${{ runner.temp }}", "${RUNNER_TEMP}")


_COPY_LIST_RE = re.compile(r"^\s*files='(?P<paths>[^']+)'\s*$", re.MULTILINE)


def test_the_lock_files_cross_jobs_as_one_artifact_of_the_staged_set() -> None:
    """RED when: the export job hands over a set other than what the push job stages, or the push job
    copies anything but that set (BACKLOG #5477).

    The three lists (upload, staging, ``git diff --cached --quiet``) must agree: a file uploaded but
    not staged would be pushed stale, and a path staged from the artifact but not in the list would
    let the export job write anywhere in the commit.
    """
    staged = set(_exports(_GATE)) | _CLOSURES
    uploads, downloads = _steps_using(_UPLOAD), _steps_using(_DOWNLOAD)
    assert [j for j, _ in uploads] == ["export"], f"expected one upload, in export: {uploads}"
    assert [j for j, _ in downloads] == ["push"], f"expected one download, in push: {downloads}"
    up, down = uploads[0][1]["with"], downloads[0][1]["with"]
    # Any other input could fetch another run's artifact (run-id, github-token, repository) or
    # several at once (pattern, merge-multiple), or change what is uploaded.
    assert set(down) == {"name", "path"}, f"the download step takes {sorted(down)}"
    assert set(up) <= {"name", "path", "retention-days", "if-no-files-found", "overwrite"}, (
        f"the upload step takes {sorted(up)}"
    )
    assert up["name"] == down["name"], "the push job downloads a different artifact"
    assert set(str(up["path"]).split()) == staged, "the uploaded set is not the staged set"
    assert up.get("include-hidden-files") in (None, False)
    assert f'src="{_artifact_dir()}"' in str(_copy_step()["run"]), (
        "the staging step reads a directory other than the one the download step writes"
    )
    copy = _COPY_LIST_RE.findall(str(_copy_step()["run"]))
    assert len(copy) == 1 and set(copy[0].split()) == staged, (
        "the staging step's list is not the staged set"
    )
    push = _job_steps("push")
    order = [str(s.get("name") or s.get("uses")) for s in push]
    download_at = next(
        i for i, s in enumerate(push) if str(s.get("uses", "")).startswith(_DOWNLOAD)
    )
    commit_at = next(i for i, s in enumerate(push) if "git commit" in str(s.get("run", "")))
    assert download_at < order.index(_COPY_STEP) < commit_at, f"push job order: {order}"


_GIT_TEST_CONFIG = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "core.symlinks=true",
)


def _scratch_env(**extra: str) -> dict[str, str]:
    """The environment with every GIT_* variable removed. A hook or ``rebase -x`` that runs pytest
    exports GIT_DIR and GIT_INDEX_FILE, which would point these scratch git commands at the live
    repository."""
    return {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")}, **extra}


def _git(workspace: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *_GIT_TEST_CONFIG, "-C", str(workspace), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env=_scratch_env(),
    ).stdout


def _run_copy(
    tmp_path: Path,
    build: Callable[[Path, Path], None],
    staged: list[str],
    script: str,
    bash: str,
) -> subprocess.CompletedProcess[str]:
    """Run the shipped staging step verbatim in a scratch checkout and artifact directory.

    The checkout is a git repository whose HEAD holds whatever ``build`` made of the tree, the way
    actions/checkout would have written a PR head carrying it.
    """
    workspace, temp = tmp_path / "ws", tmp_path / "rt"
    artifact = temp / _artifact_dir().removeprefix("${RUNNER_TEMP}/")
    for rel in staged:
        for base, body in ((workspace, "old\n"), (artifact, "new\n")):
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_text(body, encoding="utf-8")
    build(workspace, artifact)
    _git(workspace, "init", "-q")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-q", "-m", "PR head")
    _git(tmp_path, "init", "-q", "--bare", "origin.git")
    _git(workspace, "remote", "add", "origin", str(tmp_path / "origin.git"))
    return _run_step(workspace, script, bash, RUNNER_TEMP=str(temp))


def _run_step(
    workspace: Path, script: str, bash: str, **env: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [bash, "-c", script],
        cwd=workspace,
        env=_scratch_env(**env),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the step runs on an ubuntu runner; GNU realpath and POSIX symlinks are needed",
)
def test_the_copy_step_refuses_what_the_artifact_or_tree_could_plant(tmp_path: Path) -> None:
    """RED when: the staging step writes through a checkout path, writes outside the checkout, or
    stages anything off its list (BACKLOG #5477).

    Executes the step's own script against a git checkout. A clean artifact stages every file by
    content and leaves the working tree as checked out. An extra artifact entry, a missing file, a
    symlink in the artifact, a lock path the tree made a symlink, a lock path under a symlinked
    directory, and a lock path the tree made a directory holding a same-named symlink each fail the
    step before anything lands outside the checkout. The last case is what a `cp` onto the lock path
    wrote straight through to the symlink's target (review of dffb12aeaaf, measured in WSL).
    """
    staged = sorted(set(_exports(_GATE)) | _CLOSURES)
    script = str(_copy_step()["run"])
    bash = require_bash(tmp_path)
    clean = _run_copy(tmp_path / "clean", lambda ws, art: None, staged, script, bash)
    assert clean.returncode == 0, clean.stdout + clean.stderr
    ws = tmp_path / "clean" / "ws"
    stale = [r for r in staged if _git(ws, "show", f":{r}") != "new\n"]
    assert not stale, f"the staging step left these unstaged: {stale}"
    written = [r for r in staged if (ws / r).read_text(encoding="utf-8") != "old\n"]
    assert not written, f"the staging step wrote through these checkout paths: {written}"
    changed = sorted(_git(ws, "diff", "--cached", "--name-only").split())
    assert changed == staged, f"the index differs from HEAD at {changed}, not the staged set"

    # A runner file the tree or the artifact could point at: it exists, so a write would follow a link.
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_text("victim\n", encoding="utf-8")

    def extra(ws: Path, art: Path) -> None:
        (art / ".github").mkdir()
        (art / ".github" / "evil.yml").write_text("x", encoding="utf-8")

    def missing(ws: Path, art: Path) -> None:
        (art / "constraints.lock").unlink()

    def artifact_link(ws: Path, art: Path) -> None:
        (art / "constraints.lock").unlink()
        (art / "constraints.lock").symlink_to(victim)

    def dest_link(ws: Path, art: Path) -> None:
        (ws / "constraints.lock").unlink()
        (ws / "constraints.lock").symlink_to(victim)

    def dir_link(ws: Path, art: Path) -> None:
        shutil.rmtree(ws / "ci" / "locks")
        (ws / "ci" / "locks").symlink_to(outside, target_is_directory=True)

    def dir_holding_link(ws: Path, art: Path) -> None:
        # `cp -- src constraints.lock` copies INTO a directory, through the same-named link inside.
        (ws / "constraints.lock").unlink()
        (ws / "constraints.lock").mkdir()
        (ws / "constraints.lock" / "constraints.lock").symlink_to(victim)

    def unlisted(ws: Path, art: Path) -> None:
        # A directory find cannot read: the listing fails, and the step must fail with it rather
        # than check part of the artifact. (Root reads it anyway, so the case is skipped there.)
        hidden = art / "hidden"
        hidden.mkdir()
        (hidden / "extra").write_text("x", encoding="utf-8")
        hidden.chmod(0)

    cases = [extra, missing, artifact_link, dest_link, dir_link, dir_holding_link]
    if os.geteuid() != 0:
        cases.append(unlisted)
    for build in cases:
        result = _run_copy(tmp_path / build.__name__, build, staged, script, bash)
        if build is unlisted:
            (tmp_path / build.__name__ / "rt" / "lock-resync-exports" / "hidden").chmod(0o700)
        assert result.returncode != 0, f"{build.__name__}: the staging step accepted it"
        if build is not unlisted:  # find reports its own error; the step prints no annotation
            assert "::error" in result.stdout, f"{build.__name__}: {result.stdout}{result.stderr}"
        assert victim.read_text(encoding="utf-8") == "victim\n", f"{build.__name__} wrote outside"
        assert sorted(p.name for p in outside.iterdir()) == ["victim"], build.__name__
        landed = tmp_path / build.__name__ / "ws" / "constraints.lock"
        assert (
            landed.is_symlink()
            or not landed.is_file()
            or landed.read_text(encoding="utf-8") != "victim\n"
        ), f"{build.__name__}: a file from outside the artifact was written into the checkout"


def _commit_step() -> dict[str, Any]:
    steps = [s for s in _job_steps("push") if "git push" in str(s.get("run", ""))]
    assert len(steps) == 1, "expected one push job step that runs git push"
    return steps[0]


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the steps run on an ubuntu runner; GNU realpath and base64 -w0 are needed",
)
def test_the_commit_step_commits_the_staged_content_or_nothing(tmp_path: Path) -> None:
    """RED when: the commit step does not commit exactly what the staging step put in the index,
    on top of the PR head, or pushes when the artifact already matches the PR head (BACKLOG #5477).

    Executes the staging step and then the commit step verbatim against a local bare ``origin``.
    The file remote ignores the http.extraheader the step sets, so the push needs no token.
    """
    staged = sorted(set(_exports(_GATE)) | _CLOSURES)
    stage, commit = str(_copy_step()["run"]), str(_commit_step()["run"])
    bash = require_bash(tmp_path)
    ref = "refs/heads/dependabot/uv/resync-probe"
    env = {"HEAD_REF": ref.removeprefix("refs/heads/"), "APP_TOKEN": "not-a-token"}

    def in_sync(ws: Path, art: Path) -> None:
        for rel in staged:
            (art / rel).write_text("old\n", encoding="utf-8")

    for build, changes in ((lambda ws, art: None, True), (in_sync, False)):
        case = tmp_path / ("changed" if changes else "in-sync")
        staging = _run_copy(case, build, staged, stage, bash)
        assert staging.returncode == 0, staging.stdout + staging.stderr
        ws, origin = case / "ws", case / "origin.git"
        result = _run_step(ws, commit, bash, **env)
        assert result.returncode == 0, result.stdout + result.stderr
        pushed = _git(origin, "for-each-ref", "--format=%(objectname)", ref).strip()
        if not changes:
            assert not pushed, "the commit step pushed although the artifact matches the PR head"
            assert "already in sync" in result.stdout, result.stdout
            continue
        assert pushed, f"the commit step pushed nothing: {result.stdout}{result.stderr}"
        head = _git(ws, "rev-parse", "HEAD").strip()
        assert _git(origin, "rev-parse", f"{pushed}^").strip() == head, "not committed on the head"
        changed = sorted(_git(origin, "diff", "--name-only", head, pushed).split())
        assert changed == staged, f"the pushed commit changes {changed}, not the staged set"
        stale = [r for r in staged if _git(origin, "show", f"{pushed}:{r}") != "new\n"]
        assert not stale, f"the pushed commit carries the PR head's bytes at {stale}"
