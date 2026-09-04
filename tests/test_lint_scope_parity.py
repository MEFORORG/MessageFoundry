# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The pre-commit hooks and the CI gates must be the SAME linter -- same files, same version.

They did not, and the divergence was silent in the worst direction: the hooks were BROADER than CI.
`ruff check` in CI named six explicit paths while the pre-commit ruff hook has no `exclude` and so
runs on every changed Python file; bandit in CI scanned `-r messagefoundry tee` while its hook scanned
everything but tests/harness/samples. The result was 99 ruff findings in harness/, tee/, samples/ and
docker/ that were gated locally and by nothing in CI — so touching any file there blocked the commit
on errors that no CI run could report, and that no green build had ever been able to reveal.

The direction matters. A hook LOOSER than CI is an annoyance: CI still catches it. A hook STRICTER
than CI is a trap — it blocks work on a standard the project does not actually enforce, which is
what makes people reach for `--no-verify` and lose every other gate with it.

These tests read both configurations and compare them, so the next person to narrow one has to
narrow the other. They assert the CONTRACT, not any particular scope: widen or narrow freely,
provided both sides move together.

SCOPE WAS THE WHOLE CONTRACT UNTIL 2026-08-18, when the ruff hooks moved from ``language: system`` to
the pre-commit-managed ``astral-sh/ruff-pre-commit`` repo. They had to: ``language: system`` resolves
the entry on PATH, ``ruff`` is on no ambient PATH, and the two hooks were unrunnable for anyone who
had not activated a venv in the shell they committed from -- which pushes people at ``--no-verify``,
and that drops the ledger gate and the leak gate too. The fix works and it dissolved the mechanism
that had made version agreement automatic: there are now TWO ruffs, the hook's and the venv/CI one.
So VERSION joined SCOPE here, and RUNNABILITY joined both -- the defect that forced the move was a
hook nobody could execute, and nothing had ever asserted that a hook's entry resolves. Those are at
least three properties this file now holds, and they are one contract: a hook that lints on a
different standard than CI is a trap whether the difference is which FILES, which RULES or whether it
runs at all, and they share one failure shape -- silent, and discovered by whoever it blocks rather
than by whoever caused it.

WHERE THE RUFF SCOPE ACTUALLY LIVES, since the sentence above about "no ``exclude``" describes the
retired arrangement: upstream's entry is ``ruff check --force-exclude``, which makes ruff honour
pyproject's ``[tool.ruff] extend-exclude`` even for filenames pre-commit names explicitly. So the
hook's scope is upstream's ``types_or: [python, pyi, jupyter]`` MINUS pyproject's extend-exclude, and
CI's ``ruff check .`` is the same discovery minus the same extend-exclude. Scope is single-sourced in
pyproject for both sides now, which is a stronger arrangement than the one it replaced -- the old
``language: system`` hooks, lacking that flag, were STRICTER than CI on any excluded path.

The semgrep arm below is CI-vs-CI, not hook-vs-CI, and that asymmetry is deliberate rather than a
forgotten half: there is no semgrep pre-commit hook to compare against, because semgrep has no
supported Windows install (recorded in the maintainer-internal backlog plan) and this is a Windows-first
project. So semgrep's scope is pinned to its sibling CI gate, bandit — the two scan the same
checkout in the same job file for the same reason, and a path excluded from one but not the other
means one of them is enforcing a standard the other is not.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import tomllib
from functools import cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import pytest

# `packaging` is imported HARD while `yaml` below is guarded, and the asymmetry is deliberate rather
# than an oversight. Measured 2026-08-18: pytest 9.1.1 declares `packaging>=22` as an unconditional
# install requirement, so there is no environment in which pytest can collect this module and
# `packaging` is absent -- a `pytest.importorskip` here could never fire, and an unreachable guard
# advertises a degradation path that does not exist. It is also the wrong direction to fail in: an
# importorskip fails SILENTLY GREEN, and this file is the only thing holding the ruff hook and the
# ruff CI gate together, so if pytest ever drops that dependency the right outcome is a loud
# collection error, not this file quietly vanishing from the run. (`yaml` is genuinely different:
# PyYAML is declared by no first-party extra, reaching the lock transitively, so its guard CAN fire
# -- and if it ever does, every assertion below stops running without going red. Watch for a SKIP.)
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]
_PRECOMMIT = _ROOT / ".pre-commit-config.yaml"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_SECURITY = _ROOT / ".github" / "workflows" / "security.yml"
_CONSTRAINTS = _ROOT / "constraints.lock"
_PYPROJECT = _ROOT / "pyproject.toml"


def _config() -> dict[str, Any]:
    """The whole parsed .pre-commit-config.yaml, INCLUDING its top-level keys.

    `_hooks()` flattens away the two levels above a hook, and both of them carry scope. pre-commit's
    CONFIG_SCHEMA (pre_commit/clientlib.py, read 2026-08-18) defines top-level `files:` and
    `exclude:` that filter the file list handed to EVERY hook -- commands/run.py applies them once,
    before any hook is consulted -- so a hook mapping can be perfectly clean while the whole config
    is narrowed above it. Tests that assert about scope must read this, not only `_hooks()`.
    """
    parsed: Any = yaml.safe_load(_PRECOMMIT.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), f"{_PRECOMMIT.name} did not parse to a mapping: {parsed!r}"
    return dict(parsed)


def _hooks() -> dict[str, dict[str, Any]]:
    """Every hook in the file, keyed by id -- and it RAISES on a duplicate id rather than losing one.

    IT WAS A BARE DICT COMPREHENSION over every hook in the file, so a second declaration of one id
    collided and won -- ACROSS TWO REPOS OR TWICE INSIDE ONE, indifferently, because this mapping
    keys on `id` and nothing else. The earlier hook still sat in the file, still ran on every commit,
    and was absent from every assertion that reads this mapping -- while the module reported green.
    The shape that matters: a SECOND repo declaring `id: ruff-check` under any URL not containing
    `ruff-pre-commit` lints every commit on an unpinned, possibly stricter standard than `ruff check
    .`, and the ruff lookup one level up does not see it either -- `_ruff_repo()` asks for exactly
    one repo whose URL matches, and this one deliberately does not match.

    PRE-COMMIT ITSELF DOES NOT MIND, checked by construction rather than assumed. Measured 2026-08-18
    against pre-commit 4.6.1, on an out-of-tree config declaring `id: dup-probe` in two `repo: local`
    blocks with a different `language: system` script each: `validate-config` exits 0, `run
    --all-files` runs both, and `run dup-probe` -- selecting BY the duplicated id -- also runs both,
    printing each script's output in turn. So nothing upstream resolves, warns about or deduplicates
    the collision. Both hooks execute; only this module's view of them collapses to one.

    IT RAISES IN THE HELPER rather than only in a test of its own, and the blast radius is the reason
    -- MEASURED, because the sentence here used to read "every assertion in this file" and that was
    an adjective standing in for a count. Applying one collision (a second `repo: local` block
    declaring `id: ruff-check`) reds 6 of the 14 tests in this module: exactly those that reach this
    mapping, through `_hooks()` or `_hook()`. The other 8 stay green -- they read `_config()`
    directly, or a CI workflow, and never call it.

    Six assertions whose subject may not be the hook that runs is still the case for raising here
    rather than returning a mapping with one declaration silently overwritten: a collision-only test
    would go red beside those six while they reported parity about an unknown subject -- the "green
    test asserting about a hook nobody uses" shape `_ruff_repo()` already refuses one level up. A
    test named for the collision exists too, so the report says WHAT broke rather than only where.
    """
    declared_by: dict[str, list[str]] = {}
    hooks: dict[str, dict[str, Any]] = {}
    for repo in _config()["repos"]:
        origin = str(repo.get("repo", "<a repo entry with no `repo:` key>"))
        for hook in repo["hooks"]:
            hook_id = str(hook["id"])
            declared_by.setdefault(hook_id, []).append(origin)
            hooks[hook_id] = hook

    collisions = {k: v for k, v in sorted(declared_by.items()) if len(v) > 1}
    if collisions:
        raise AssertionError(
            f"{_PRECOMMIT.name} declares one hook id more than once:\n  "
            + "\n  ".join(
                f"`{k}` -- declared {len(v)} times, under {v}" for k, v in collisions.items()
            )
            + "\n\nACROSS TWO REPO ENTRIES OR TWICE INSIDE ONE -- the same defect either way, since "
            "this mapping keys on `id` and nothing else. Keying hooks by id is how the assertions "
            "in this module find their subject, so a collision drops one declaration from every one "
            "of them that reads the mapping -- while pre-commit runs both (measured against 4.6.1: "
            "`validate-config` exits 0, and selecting the duplicated id executes every declaration "
            "carrying it). A second `ruff-check` under a URL this file's ruff lookup does not match "
            "therefore lints every commit on an unpinned standard, with the rev test, the args test "
            "and the scope test all still green about the other one.\n\n"
            "WHICH REMEDY IS AVAILABLE DEPENDS ON WHERE THE DUPLICATE LIVES, and it is not always "
            "both. A `repo: local` hook's id is this repo's to choose, so rename it. A hosted "
            "repo's is NOT -- it has to match that repo's .pre-commit-hooks.yaml or pre-commit "
            "cannot resolve the hook at all -- so there the only move is deleting the duplicate "
            "declaration. `alias:` IS NOT A THIRD OPTION, however precisely it seems to name the "
            "problem: measured 2026-08-18 against pre-commit 4.6.1, two `repo: local` declarations "
            "of one id carrying different `alias:` values both validate, both run, and both report "
            "`hook id: dup-probe`. The key adds a SELECTOR for `pre-commit run <name>` and `SKIP=` "
            "(clientlib.py declares it beside `id`, never in place of it), so the ids stay "
            "identical and this guard reds exactly as it did before."
        )
    return hooks


def _hook(hook_id: str) -> dict[str, Any]:
    """One hook's mapping AS THIS REPO WRITES IT -- not the manifest-merged hook pre-commit runs.

    Every key upstream supplies is therefore ABSENT here, which is the whole reason the assertions
    below are phrased as "this repo adds no override" rather than "the key is not set". Getting that
    backwards produces a test that fails on a correct config: `ruff-check` inherits, among other
    things, `entry: ruff check --force-exclude`, `types_or: [python, pyi, jupyter]`, `args: []` and
    `additional_dependencies: []` from astral-sh/ruff-pre-commit's .pre-commit-hooks.yaml.

    Raises with the available ids rather than KeyError: a DELETED hook is one of the regressions
    worth catching, and `KeyError: 'ruff-format'` names the symptom without naming the contract.
    """
    hooks = _hooks()
    assert hook_id in hooks, (
        f"no {hook_id!r} hook in {_PRECOMMIT.name}; it declares {sorted(hooks)}. Deleting a hook is "
        "the one scope regression that leaves nothing behind to assert about, so it reds here."
    )
    return hooks[hook_id]


def test_no_hook_id_is_declared_twice() -> None:
    """A NAMED red for the collision `_hooks()` raises on, so the report says what broke.

    THE NAME SAYS "TWICE", NOT "TWO REPOS", and the widening is a correction rather than a
    generalisation. `_hooks()` keys on `id` alone, so it raises on a duplicate ANYWHERE in the file
    -- across two repo entries or twice inside one -- while this name and the failure headline both
    used to say "under more than one repo". On the within-one-repo case that message printed
    `['local', 'local']` beneath a headline about a second repo, sending the reader to look for an
    entry that does not exist. A check and the sentence describing it have to be the same sentence.

    `_hooks()` raises rather than returning a mapping with one declaration silently overwritten,
    which reds the 6 tests here that read that mapping -- measured, see `_hooks()`. That is the
    right blast radius for those six: none of them can know which declaration they are describing.
    But six identically-worded failures name no contract, and the first instinct on reading them is
    to look at whichever assertion happens to be printed first. This one puts the contract in the
    test name for the cost of a single call.

    It doubles as the non-vacuity check on `_hooks()` itself: an empty mapping satisfies every
    membership assertion in this file only by way of `_hook()`, which reds -- but nothing otherwise
    states out loud that the file is expected to declare hooks at all.
    """
    assert _hooks(), (
        f"{_PRECOMMIT.name} parsed to a repos list that declares no hooks. Every assertion in this "
        "module reads through that mapping, so they would all be describing an empty file."
    )


#: The ruff hooks this repo has ADOPTED, in config order (format then check). Both are held to the
#: same contract: each mirrors a CI step that runs over the whole repo (`ruff format --check .` /
#: `ruff check .`), so a narrowing on either is the same hook-versus-CI divergence in a different
#: tool.
#:
#: IT IS READ IN BOTH DIRECTIONS, which is what makes it exact rather than merely a loop variable.
#: The per-hook tests below iterate it through `_hook()`, which reds on an adopted id that is
#: MISSING; `test_the_ruff_repo_declares_no_hook_id_this_repo_has_not_adopted` subtracts it from
#: what the pinned repo actually declares, which reds on a declared id that is EXTRA. Together they
#: pin the declared set to exactly this one. So adopting a third ruff hook is a single deliberate
#: edit here -- and that edit subjects it to every ruff assertion in this file in the same line,
#: rather than adding a hook no assertion names.
_RUFF_HOOK_IDS = ("ruff-format", "ruff-check")

#: Hook keys that change WHICH FILES a hook sees, or WHETHER it runs -- so this repo must set none of
#: them on a ruff hook. Taken from pre-commit's MANIFEST_HOOK_DICT (pre_commit/clientlib.py, read
#: 2026-08-18); at least these, and if pre-commit grows another selector, add it here.
#:
#: `stages` is in the set for a reason the others make obvious only in hindsight: it does not narrow
#: the FILES, it narrows the OCCASIONS -- `stages: [manual]` leaves the hook fully configured and
#: correct-looking while removing it from every commit.
#:
#: `language` IS DELIBERATELY ABSENT, and it is guarded a few lines below instead of being folded in
#: here. It selects neither files nor occasions but the ENVIRONMENT the entry resolves in, so a
#: message about dropped files would be the wrong sentence for it -- and this set's message is a
#: single list, so anything added to it inherits that sentence. Its own assertion can say what
#: `language: system` on a pinned hook actually does, which is worth more than one fewer constant.
_RUFF_HOOK_NARROWING_KEYS = frozenset(
    {"files", "exclude", "types", "types_or", "exclude_types", "stages"}
)

#: Top-level keys .pre-commit-config.yaml is allowed to carry. An ALLOWLIST, and the inversion is the
#: entire point of it.
#:
#: THIS WAS A FORBIDDEN-KEY SET, `{"files", "exclude"}`, AND IT WAS ALREADY WRONG. A forbidden-key set
#: is a completeness claim about somebody else's schema -- exactly what CLAUDE.md §11 says to prefer
#: "at least" over -- and it missed `default_stages`. Measured 2026-08-18 against pre-commit 4.6.1:
#: adding ONE top-level line, `default_stages: [manual]`, removes EVERY hook in this file from every
#: commit -- both ruff hooks, ledger-gate, forbidden-content, licence-header, control-char, gitleaks,
#: actionlint, bandit -- while each hook mapping stays byte-identical and correct-looking, and this
#: module reported 12 passed on that config. The same whether-versus-which distinction was already
#: drawn CORRECTLY one level down (`stages` sits in `_RUFF_HOOK_NARROWING_KEYS` above for precisely
#: that reason); the top level simply never got it. Adding `default_stages` to a forbidden set would
#: have reproduced the defect class rather than closed it, so the test asks the opposite question.
#:
#: WHY THE MISS IS STRUCTURAL AND WOULD RECUR. pre-commit's `warn_unknown_keys_root` only WARNS at an
#: unrecognised root key and then ignores it, so a key from a newer schema written today is inert and
#: nearly silent -- until pre-commit is upgraded, at which point it starts applying with nothing
#: reporting a change. Local installs come from a bare `pip install pre-commit` (see the header of
#: .pre-commit-config.yaml), which is unpinned. An allowlist reds when the key is WRITTEN, which is
#: the only moment anybody is looking at it.
#:
#: ONE MEMBER, and it is safe because it is not a filter at all: `repos` IS the content -- the thing
#: every other assertion in this file reads -- and its own narrowing keys are guarded per hook above.
#: Everything else reds, including keys that are harmless in themselves, because "harmless" is a
#: judgement that belongs in a review rather than in a default. Adopting one means editing this set
#: deliberately and saying here what it does to the hook set.
_CONFIG_TOP_LEVEL_ALLOWLIST = frozenset({"repos"})

#: What the root keys known TODAY do, used only to make the failure message concrete. Read from
#: pre-commit 4.6.1's CONFIG_SCHEMA (pre_commit/clientlib.py, its `WarnAdditionalKeys` tuple) on
#: 2026-08-18.
#:
#: ADVISORY, AND IT CANNOT CAUSE A MISS -- which is why it is safe to write an enumeration here at
#: all. The pass/fail decision is `_CONFIG_TOP_LEVEL_ALLOWLIST` alone, so a root key absent from this
#: mapping still reds; it just reds with a generic sentence instead of a specific one. That property
#: is exactly what the forbidden-key set it replaces did not have.
_CONFIG_TOP_LEVEL_EFFECTS = {
    "files": "narrows the file list handed to EVERY hook before any hook mapping is consulted",
    "exclude": "drops files from the list handed to EVERY hook, before any hook mapping is consulted",
    "default_stages": "sets the stages of every hook that does not name its own, so one value can "
    "take the whole file off the commit path while every hook still reads as configured",
    "default_install_hook_types": "decides which git hook files `pre-commit install` writes, so it "
    "can leave a fresh clone with no pre-commit hook installed at all",
    "default_language_version": "picks the interpreter pre-commit builds hook environments with, "
    "which is a runnability change of the same family as the one that forced the ruff move",
    "fail_fast": "stops the run at the first failing hook, so the remaining hooks report nothing",
    "minimum_pre_commit_version": "refuses to load the config on an older pre-commit",
    "ci": "configures pre-commit.ci, whose `skip:` list disables hooks there and nowhere else",
}


def _top_level_effect(key: str) -> str:
    return _CONFIG_TOP_LEVEL_EFFECTS.get(
        key,
        "is a root key this repo has not adopted; pre-commit applies root keys to every hook, and "
        "this guard refuses what it cannot vouch for rather than guessing",
    )


def _ci_step_run(workflow: Path, name_fragment: str) -> str:
    """The `run:` body of the first step whose name contains ``name_fragment``."""
    wf = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for job in wf["jobs"].values():
        for step in job.get("steps") or []:
            if name_fragment.lower() in str(step.get("name", "")).lower() and "run" in step:
                return str(step["run"])
    raise AssertionError(f"no step matching {name_fragment!r} in {workflow.name}")


def test_ruff_lints_the_whole_repo_on_both_sides() -> None:
    """Neither ruff hook may narrow itself past the CI step it mirrors, at any of the three levels.

    THE OLD REASONING HERE IS RETIRED, and saying so matters because it read as the contract: this
    test used to assert "the hook has no `exclude`, so it lints every changed Python file". That
    inference belonged to the `language: system` hooks, which ran a bare `ruff check --fix` and so
    ignored pyproject's [tool.ruff] extend-exclude for any file named on the command line -- "no
    exclude" really did mean "everything". Upstream's entry carries `--force-exclude`, so both sides
    now read pyproject's extend-exclude and scope is single-sourced there. Stronger, not weaker; but
    "no `exclude` key" is no longer the whole story, and it never covered the other narrowing keys.

    THREE LEVELS, because pre-commit filters at three and a check at one of them proves little:

    1. THE HOOK MAPPING, for keys this repo ADDS. Everything upstream supplies is absent from what
       `_hook()` returns, so `types_or` legitimately does not appear -- see `_hook()`. The assertion
       is that this repo overrides none of them, not that the merged hook lacks them.
    2. THE `entry:` AND `language:` OVERRIDES -- what the hook runs, and the environment it resolves
       that in. `--force-exclude` lives in the first; the retired unrunnable-hook defect is one line
       of the second.
    3. THE TOP LEVEL, which acts on every hook before any hook mapping is consulted. Checked as an
       ALLOWLIST, unlike (1): the hook-mapping check names the keys upstream's manifest supplies and
       this repo must not override, which is a bounded set this repo owns, while a root key comes
       from pre-commit's schema and that set grows without asking. See
       `_CONFIG_TOP_LEVEL_ALLOWLIST` for the measurement that forced the inversion.

    An allow-list in CI cannot be kept in step with "everything" by hand -- it was six paths while
    the hook covered the repo. `ruff check .` makes pyproject's extend-exclude the SINGLE definition
    of scope, which is the only arrangement that cannot drift.
    """
    for hook_id in _RUFF_HOOK_IDS:
        hook = _hook(hook_id)
        narrowing = sorted(_RUFF_HOOK_NARROWING_KEYS & hook.keys())
        assert not narrowing, (
            f"the {hook_id} hook adds {narrowing} on top of astral-sh/ruff-pre-commit's manifest. "
            "Every key there either drops files the CI step it mirrors still lints, or (in the "
            "case of `stages`) drops the occasions the hook runs at all -- and the hook keeps "
            "reporting Passed on what is left, so the narrowing is invisible from the outside. "
            "Scope belongs in pyproject [tool.ruff] extend-exclude, where BOTH sides read it."
        )
        assert "entry" not in hook, (
            f"the {hook_id} hook overrides upstream's `entry:`, which is where `--force-exclude` "
            "lives. Without that flag ruff ignores pyproject [tool.ruff] extend-exclude for the "
            "filenames pre-commit passes explicitly, so the hook goes red on files its CI step "
            "never sees -- staging anything under docs/benchmarks/results blocks the commit, on "
            "archived measurement artifacts that pyproject excludes precisely because reformatting "
            "them edits the record. Pass flags with `args:` instead."
        )
        assert "language" not in hook, (
            f"the {hook_id} hook sets `language: {hook['language']!r}`, overriding the one upstream "
            "declares. `language` picks the ENVIRONMENT pre-commit resolves the entry in, so "
            "`language: system` here reinstates the exact defect the move to astral-sh/ruff-pre-"
            "commit retired: `ruff` resolved as a bare program name on PATH, where nothing but an "
            "activated venv puts it. The `rev:` above would then pin nothing that runs, and the "
            "three-way version test next door would keep passing on three declarations that had "
            "stopped describing the executed binary. Nothing else in this file catches it -- the "
            "narrowing set guards which FILES a hook sees, and this changes none of them."
        )

    unadopted = sorted(_config().keys() - _CONFIG_TOP_LEVEL_ALLOWLIST)
    assert not unadopted, (
        f"{_PRECOMMIT.name} carries top-level keys this repo has not adopted:\n  "
        + "\n  ".join(f"`{key}` -- {_top_level_effect(key)}" for key in unadopted)
        + "\n\npre-commit reads root keys ONCE, before it looks at any hook mapping, so each of "
        "them acts on every hook in the file at the same time and none of them appears in the hook "
        "it changes. Measured 2026-08-18 against the pinned hooks: `pre-commit run ruff-check "
        "--files harness/__main__.py` goes from `Passed` to `(no files to check)Skipped` under "
        "EITHER a top-level `exclude: ^harness/` or a top-level `files: ^messagefoundry/`, while "
        "the ruff-check mapping stays byte-identical -- and a top-level `default_stages: [manual]` "
        "takes every hook in the file off the commit path with no hook mapping touched at all. (A "
        "same-named key on the REPO entry is a different thing and is not a vector: pre-commit's "
        "CONFIG_REPO_DICT allows only repo/rev/hooks, and the same probe printed `[WARNING] "
        "Unexpected key(s) present ... exclude` and then `Passed` -- warned and ignored.) Narrow "
        "scope in pyproject [tool.ruff] extend-exclude, where both sides read it. If a root key is "
        "genuinely wanted, add it to _CONFIG_TOP_LEVEL_ALLOWLIST in the same commit and say there "
        "what it does to the hook set."
    )

    run = _ci_step_run(_CI, "Lint (ruff)")
    assert re.search(r"ruff check\s+\.\s*$", run.strip()), (
        f"CI must lint the whole repo (`ruff check .`) to match the hook; got: {run.strip()!r}"
    )


def test_ruff_hook_args_carry_the_autofix_and_nothing_else() -> None:
    """`args:` is the one key this repo DOES override, so it is the one that needs an exact value.

    `--fix` is not decoration: upstream ships `args: []` and puts only `--force-exclude` in the
    entry, so dropping it silently retires the autofix the retired `ruff check --fix` hook did. That
    regression has no red state of its own -- the hook still runs and still passes or fails on the
    same rules, it just stops fixing things, and the loss surfaces weeks later as a vague "it used
    to do that". .pre-commit-config.yaml has said so in prose since the hooks moved; this is the
    assertion that makes the sentence true.

    Asserted as EQUALITY rather than membership, which also closes the other half: `args` is a
    second route to every narrowing `_RUFF_HOOK_NARROWING_KEYS` guards against (`--exclude`,
    `--extend-exclude`) and the only route to a rule-set divergence (`--select`, `--ignore`,
    `--extend-select`), none of which CI's bare `ruff check .` gets. A flag that genuinely belongs
    on both sides belongs in pyproject, where both sides read it; if some flag truly must live here,
    change this expectation deliberately and say why in the config comment.
    """
    check_args = _hook("ruff-check").get("args")
    assert check_args == ["--fix"], (
        f"the ruff-check hook's `args:` is {check_args!r}, not ['--fix']. Dropping `--fix` retires "
        "the autofix without any gate going red; adding anything else makes the hook lint on a "
        "standard `ruff check .` does not enforce, which is the hook-stricter-than-CI trap this "
        "file exists to prevent. Rule and scope changes go in pyproject [tool.ruff]."
    )

    format_args = _hook("ruff-format").get("args", [])
    assert format_args == [], (
        f"the ruff-format hook grew `args: {format_args!r}`. CI runs a bare `ruff format --check .`, "
        "so any flag here formats to a standard the gate does not check -- and a formatter that "
        "disagrees with its own gate rewrites files CI then reds on."
    )


def test_ruff_hooks_do_not_swap_the_pinned_ruff() -> None:
    """`additional_dependencies` is designed to be overridden, and it is the one key that can drive
    the executed ruff away from the `rev:` the version test reads.

    WHAT THIS BUYS, measured rather than assumed, because the obvious story is wrong. Adding
    `additional_dependencies: ["ruff==0.16.3"]` under `- id: ruff-check` at `rev: v0.15.22` does NOT
    quietly install 0.16.3: measured 2026-08-18, pre-commit's env build runs `pip install . ruff==
    0.16.3` and pip refuses -- "ruff-pre-commit 0.0.0 depends on ruff==0.15.22", ResolutionImpossible
    -- so the hook cannot run at all. Meanwhile this file reported 9 passed on that config. THAT is
    the defect: the suite certifies hook-versus-CI parity for a hook that no longer executes, and it
    hands the developer an opaque pip resolver dump instead of the sentence below.

    It also removes a dependency on somebody else's packaging. The loud failure above exists only
    because upstream pins `ruff==<rev>` EXACTLY; nothing in this repo makes that so. If upstream
    ever loosened it to a range, the same edit would install a different ruff in silence and every
    assertion in this file would still be green.
    """
    for hook_id in _RUFF_HOOK_IDS:
        deps = _hook(hook_id).get("additional_dependencies")
        assert not deps, (
            f"the {hook_id} hook declares `additional_dependencies: {deps!r}`. The version test "
            "next door compares the `rev:` against constraints.lock and pyproject -- it reads three "
            "files and executes no binary, so it cannot see what this key installs into the hook's "
            "environment. Keep the rev the single statement of which ruff the hook runs."
        )


def test_ruff_format_and_lint_agree_on_scope() -> None:
    """Format was already repo-wide (`ruff format --check .`) while lint was an allow-list. Two ruff
    invocations disagreeing about which files are 'the project' is the same bug in miniature."""
    lint = _ci_step_run(_CI, "Lint (ruff)").strip()
    fmt = _ci_step_run(_CI, "Format check (ruff)").strip()
    assert lint.endswith("."), lint
    assert fmt.endswith("."), fmt


#: Matched as a SUBSTRING of the repo URL, deliberately. The repos list is reordered freely (ruff
#: sits first today only because its two hooks rewrite files and so must run before the byte-level
#: validators in the local block), and the host half of a URL is the part most likely to be edited --
#: a mirror, a `.git` suffix, http vs https. The project name is the stable part.
_RUFF_PRE_COMMIT = "ruff-pre-commit"


def _ruff_repo() -> dict[str, Any]:
    """The whole .pre-commit-config.yaml repo entry for ruff, found by URL substring.

    Asserts EXACTLY ONE match rather than taking the first. Two ruff entries is the shape that lets
    one rev be checked here while a different one actually runs -- a green test asserting about a
    hook nobody uses -- and it is a plausible merge outcome, so it reds instead of hiding.

    Returns the WHOLE entry rather than one key, because two callers want different parts of it: the
    version test wants `rev`, and the adoption test wants the `hooks:` list AS DECLARED. The second
    cannot go through `_hooks()` -- that mapping is keyed by id across the whole file, so it records
    neither which repo declared an id nor a second declaration of one.
    """
    matches = [r for r in _config()["repos"] if _RUFF_PRE_COMMIT in str(r.get("repo", ""))]
    assert len(matches) == 1, (
        f"expected exactly one .pre-commit-config.yaml repo whose URL contains {_RUFF_PRE_COMMIT!r}; "
        f"found {[r.get('repo') for r in matches]!r}. If ruff moved to a differently-named mirror, "
        "re-point this lookup -- do not delete it."
    )
    return dict(matches[0])


def _ruff_repo_rev() -> str:
    """The `rev:` pinning the ruff hooks."""
    return str(_ruff_repo()["rev"])


def _locked_ruff_version() -> str:
    """The ruff constraints.lock installs -- what CI and every provisioned venv actually get."""
    m = re.search(r"^ruff==(\S+)$", _CONSTRAINTS.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, (
        "no `ruff==<version>` line in constraints.lock, so there is nothing to hold the pre-commit "
        "rev against. constraints.lock is the hashless export of uv.lock; if ruff left the dev "
        "extra, this test goes with it rather than passing vacuously."
    )
    return m.group(1)


def _pyproject_ruff_specifier() -> SpecifierSet:
    """pyproject's allowed version RANGE for ruff, from the `dev` extra.

    Parsed as TOML, not regexed out of the file text: the `<0.16` cap carries a five-line comment
    above it that names 0.16.0 and a finding count, and a regex over the raw text would happily mine
    a version out of that prose -- the same defect `_ci_command` below exists to describe.

    Non-emptiness is asserted because a bare `"ruff"` entry yields an EMPTY SpecifierSet, and every
    version is "in" an empty set: the cap assertion would then pass for exactly the versions the cap
    exists to refuse, while still looking like it ran.
    """
    pyproject = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dev: list[str] = pyproject["project"]["optional-dependencies"]["dev"]
    specifiers = [r.specifier for r in (Requirement(entry) for entry in dev) if r.name == "ruff"]
    assert len(specifiers) == 1, (
        "expected exactly one ruff requirement in pyproject's [project.optional-dependencies] dev "
        f"list; found {[str(s) for s in specifiers]!r}"
    )
    assert str(specifiers[0]), (
        "pyproject's dev extra names ruff with no version bound, so the cap assertion below would "
        "pass for every version -- including the 0.16 line the bound exists to keep out. Restore it."
    )
    return specifiers[0]


def test_ruff_hook_pin_matches_the_lock_and_the_cap() -> None:
    """The `rev:`, constraints.lock's pin and pyproject's cap must all name ONE ruff version.

    WHAT IT PROVES, EXACTLY: that three DECLARATIONS agree. It reads three files and compares
    strings; it executes neither ruff and inspects no installed environment, so it cannot see a hook
    env that ended up with something other than what its rev declares. Observing the binary would
    mean building a pre-commit environment -- a network install measured in minutes -- inside a unit
    test, which this tier does not do. The one config key that can drive the declarations and the
    installed binary apart is guarded separately, by
    `test_ruff_hooks_do_not_swap_the_pinned_ruff`.

    Until 2026-08-18 the hooks were `language: system`, which made version agreement STRUCTURAL: one
    installed ruff served the hook, the terminal and the IDE. They are now pre-commit-managed, so
    pre-commit builds its own environment and installs `ruff==<rev>` from PyPI. That is what makes
    the hook runnable without an activated venv, and it is also what allows two ruffs to exist at
    once. This test stands in for the structure that was lost, and it is at least the main thing
    doing so -- do not delete it on the assumption that something else re-derives the version.

    Three assertions, ordered so that the first to fire is the one that explains the most:

    1. SHAPE. Upstream tags one lightweight `vX.Y.Z` per ruff release. A branch name or a bare
       `0.15.22` either resolves to no tag at all or silently tracks a moving target, and both would
       crash the version parse below with `InvalidVersion` rather than saying what is wrong.
    2. THE CAP, checked against the rev ALONE. This is the `pre-commit autoupdate` case -- the rev
       moves and the locks do not -- and the cap explains why that is wrong far better than a
       mismatch does.
    3. THE LOCK. The plain three-way tie: the rev, constraints.lock and the cap all name one ruff.
    """
    rev = _ruff_repo_rev()
    assert re.fullmatch(r"v\d+\.\d+\.\d+", rev), (
        f"the ruff pre-commit rev is {rev!r}. astral-sh/ruff-pre-commit publishes one `vX.Y.Z` tag "
        "per ruff release and its own packaging declares the matching `ruff==X.Y.Z` -- which is the "
        "entire reason a rev can stand in for a version pin here. A branch, a SHA or a bare number "
        "breaks that link, so pin `v<version>`."
    )

    specifier = _pyproject_ruff_specifier()
    assert Version(rev.removeprefix("v")) in specifier, (
        f"the ruff pre-commit rev {rev!r} installs a ruff that pyproject's `ruff{specifier}` does "
        "not allow. That cap is deliberate -- 0.16.0 turned on stricter defaults (RUF022/RUF100/"
        "BLE001) that flag hundreds of findings in existing code -- and `pre-commit autoupdate` "
        "walks this rev to the newest upstream tag with no idea the cap exists. Revert the rev, or "
        "lift the cap in a deliberate PR that also clears the new findings."
    )

    locked = _locked_ruff_version()
    assert rev == f"v{locked}", (
        f"the ruff pre-commit rev is {rev!r} but constraints.lock pins ruff=={locked}. The hook "
        "installs its own copy from PyPI, so nothing else makes these two agree, and a hook linting "
        "on a standard CI does not enforce is what makes people reach for `--no-verify`. Set "
        f"`rev: v{locked}` -- or, if you are upgrading ruff, move pyproject, uv.lock, "
        "constraints.lock, requirements.lock and this rev in the same commit."
    )


def test_the_ruff_repo_declares_no_hook_id_this_repo_has_not_adopted() -> None:
    """An ALLOWLIST over the pinned repo's hook ids, because upstream declares more than two.

    MEASURED, NOT INFERRED. astral-sh/ruff-pre-commit's .pre-commit-hooks.yaml at the pinned v0.15.22
    -- read 2026-08-18 out of pre-commit's own cache, whose db.db maps that checkout to this repo URL
    and this rev -- declares THREE hook ids, not the two adopted here: `ruff-check`, `ruff-format`,
    and `ruff`, a legacy alias whose `entry: ruff check --force-exclude` is identical to
    `ruff-check`'s.

    THE THIRD ID WAS THE HOLE, and it was unguarded from every direction at once. `- id: ruff` under
    the same pinned repo is upstream-legal; it collides with no id, so `_hooks()` does not raise; and
    it is named by none of the ruff assertions in this module, because they all iterate
    `_RUFF_HOOK_IDS`. Measured 2026-08-18: adding it with `args: [--select, ALL]` passed every one of
    the 13 tests this module then held, while running a stricter-than-CI ruff on every commit -- the
    hook-STRICTER-than-CI trap the whole file exists to prevent, wearing a hook id nobody had named.

    AN ALLOWLIST RATHER THAN NAMING `ruff`, for the reason `_CONFIG_TOP_LEVEL_ALLOWLIST` above had to
    be inverted once already: a forbidden set is a completeness claim about somebody else's file, and
    this file grows without asking. Upstream added the legacy alias without this repo knowing, and
    can add a fourth id in any release `pre-commit autoupdate` walks the rev to. Naming `ruff` would
    close today's instance and leave the class open.

    IT TOLERATES THE ID BEING ABSENT, which is why it is a subtraction from what is DECLARED and not
    a `_hook()` lookup. `ruff` is not in the config and must not be; a lookup would red on the
    correct file, which is the shape that gets a guard deleted rather than obeyed.
    """
    declared = [str(hook["id"]) for hook in _ruff_repo().get("hooks") or []]
    # Non-vacuity, before the subtraction: an empty `hooks:` list contains no unadopted id, so the
    # assertion below would report success for a repo entry that pins a rev and runs nothing.
    assert declared, (
        f"the {_RUFF_PRE_COMMIT} repo entry declares no hooks, so this guard just checked nothing "
        "-- and the rev the version test above holds to the lock pins a ruff that lints on no "
        "commit at all."
    )

    unadopted = sorted(set(declared) - set(_RUFF_HOOK_IDS))
    assert not unadopted, (
        f"the {_RUFF_PRE_COMMIT} repo entry declares {unadopted}, which this repo has not adopted; "
        f"it adopts {list(_RUFF_HOOK_IDS)}. Upstream's manifest at the pinned rev declares a third "
        "hook -- `ruff`, a legacy alias carrying `ruff check --force-exclude`, the same entry as "
        "`ruff-check` -- so declaring it is legal, raises no id collision, and picks up NONE of the "
        "ruff assertions in this module: scope, args, additional_dependencies and language are all "
        "written against _RUFF_HOOK_IDS. A `- id: ruff` with `args: [--select, ALL]` therefore lints "
        "every commit on a standard `ruff check .` never applies, with this file reporting green. If "
        "a further ruff hook is genuinely wanted, add its id to _RUFF_HOOK_IDS in the same commit -- "
        "which subjects it to those four assertions rather than exempting it from them."
    )


#: Programs a `language: system` hook may name in its `entry:`. ONE entry, and it is a deliberate
#: allowlist rather than a "does it look like a path" heuristic, because the failure this guards is
#: precisely that a name LOOKS fine and resolves for the person who wrote it.
#:
#: WHY `python` IS ON IT. Measured 2026-08-18 in a worktree with no .venv at all: the four
#: `language: system` hooks Passed and the two then-`language: system` ruff hooks Failed with
#: "Executable `ruff` not found". `python` resolves on the ambient PATH here via the Windows Python
#: Manager 3.14.6 shim; `ruff` resolves nowhere, because only a venv provides it and the generated
#: .git/hooks/pre-commit execs a venv interpreter directly -- which does not put that venv's Scripts
#: on PATH. `language: system` was never the defect; a `language: system` entry naming a program
#: that only a venv provides is.
#:
#: AND WHY THAT IS STILL IMPERFECT, stated rather than implied. `python` (as distinct from `python3`)
#: is absent by default on Ubuntu without python-is-python3, and no CI job runs pre-commit at all --
#: the workflows mirror each hook with a direct step instead -- so nothing measures these four on
#: Linux. This allowlist encodes what has been measured on the platform the hooks actually run on,
#: not a proof of universal resolvability. Adding a program here means measuring it the same way.
#:
#: THE PROGRAM NAME IS ONLY HALF THE QUESTION, and this set only answers that half -- see
#: `_SYSTEM_PYTHON_MODULE_ALLOWLIST` below for the half that allowing `python` opens up.
_SYSTEM_ENTRY_ALLOWLIST = frozenset({"python"})

#: Modules a `language: system` hook may run as `python -m <module>`. EMPTY, deliberately.
#:
#: WHY THIS EXISTS AT ALL. The entry used to be checked as argv[0] and nothing else, so allowing
#: `python` allowed everything `python` can be pointed at: `entry: python -m ruff check --fix` PASSED
#: that check. The program is `python`, which resolves; the thing actually EXECUTED is ruff, out of
#: whatever environment that python resolves to -- the exact defect the ruff move retired, rewritten
#: under a new hook id and green. Measured 2026-08-18 in this venv-less worktree: `python` resolves to
#: the Windows Python Manager shim (pythoncore-3.14-64, 3.14.6) and `python -m ruff --version` exits 1
#: with "No module named ruff", which is the same unresolvability as bare `ruff`, moved one level down
#: and behind an interpreter that does resolve. So argv[0] passing says nothing.
#:
#: WHY IT IS EMPTY, which is a position rather than an omission. All four `language: system` hooks run
#: a repo script by path, and a repo script is present in every checkout by construction -- nothing
#: here runs `python -m`. A stdlib module (`python -m compileall`) would be fine on the merits, which
#: is why this is a set to add to rather than a blanket ban on `-m`; but no such hook exists, and
#: seeding it with plausible-looking members would assert a resolvability nobody measured. That is the
#: mistake this whole file is about. Add one the way `python` is justified above: measure, then write
#: the measurement down.
_SYSTEM_PYTHON_MODULE_ALLOWLIST: frozenset[str] = frozenset()

#: Interpreter flags that may appear between `python` and its target. Every member is either neutral
#: (`-u`, `-B`) or STRICTLY NARROWING (`-E`, `-s`, `-S`, `-I` each remove a source of imports), so
#: none of them can make an unimportable module importable -- which is the only property this guard
#: needs from them, and it is a property of what the flags DO rather than of a list being complete.
#:
#: An unlisted flag reds rather than being skipped, and that is load-bearing rather than lazy: some
#: interpreter flags CONSUME the next token (`-X importtime`, `-W ignore`, `--check-hash-based-pycs
#: default`), so a parser that skipped what it did not recognise would read that value as the target
#: and reason about the wrong word. Refusing is the only honest answer for a shape it cannot parse.
_PYTHON_INERT_FLAGS = frozenset({"-u", "-B", "-E", "-s", "-S", "-I"})


@cache
def _tracked_files() -> frozenset[str]:
    """Every path `git ls-files` reports for this checkout: repo-root-relative, POSIX-spelled.

    WHY TRACKED, WHEN THE CHECK USED TO BE `(_ROOT / token).is_file()`. `is_file()` answers a
    question about the machine running pytest. The property the guard needs is about every OTHER
    clone -- a hook entry naming a script that exists here and was never `git add`ed is dead for
    everyone else, and it is the likeliest way to write one, because the author's own commit passes
    and nothing tells them. The assertion message already SAID "outside the tracked tree" while
    checking mere existence, so asking git closes the gap between the sentence and the check rather
    than opening a new question.

    THE COST OF SHELLING OUT, measured rather than waved at, because this module ran no subprocess
    before: one `git ls-files -z` over this checkout is 1982 paths in 0.033s (median of five runs,
    2026-08-18), cached for the whole module, against four hook entries. `tests/` already shells out
    to git in dozens of files, so this is a new dependency for this file, not for the suite.

    THAT COUNT READ 1983 UNTIL IT WAS RE-MEASURED, and the gap earns a sentence because it is exactly
    the failure the rest of this docstring argues against. 1983 is the length of the NUL-split list
    INCLUDING the trailing empty string `git ls-files -z` terminates its output with -- which the
    comprehension below then drops. So the number recorded here was the instrument's intermediate
    value while the helper returned one fewer: a transcribed count, off by precisely the thing the
    next line of code removes, in a docstring about measuring rather than assuming.

    Bytes are decoded EXPLICITLY as utf-8 rather than passing `text=True`: text mode decodes as
    cp1252 on this platform, which would turn a non-ASCII tracked path into a mismatch that reads as
    "not tracked" -- a wrong verdict wearing a plausible message.

    A git failure or an empty result RAISES instead of returning an empty set. An empty set rejects
    every hook in the file, which at least reds -- but it reds with the wrong sentence, blaming four
    correct entries, and the remedy that sentence invites is weakening the guard.
    """
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "-C", str(_ROOT), "ls-files", "-z"], capture_output=True, check=False
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise AssertionError(
            f"`git ls-files` exited {proc.returncode} in {_ROOT}, so there is no tracked tree to "
            f"hold hook entries against and this guard cannot answer its own question: {detail!r}"
        )
    tracked = frozenset(path for path in proc.stdout.decode("utf-8").split("\0") if path)
    if not tracked:
        raise AssertionError(
            f"`git ls-files` reported no tracked files in {_ROOT}. Read that as an instrument "
            "failure rather than a checkout with nothing in it: every hook entry below would be "
            "rejected, correct ones included, and for a reason that has nothing to do with them."
        )
    return tracked


def _script_target_defect(token: str) -> str | None:
    """Why `python <token>` names no script every clone is guaranteed to have, or None if it does.

    THE OLD CHECK WAS `(_ROOT / token).is_file()`, and it had two holes that pointed the same way --
    at a file the author has and nobody else does.

    * AN ANCHORED TOKEN IS NOT "INSIDE THE REPO", and joining it to `_ROOT` does not make it so.
      Measured 2026-08-18 on this platform: a drive-absolute token (`C:/Windows/Temp/evil.py`) and a
      UNC one (`//server/share/evil.py`) DROP `_ROOT` entirely, so the existence check was asking
      about a file anywhere on the machine; a rooted-but-driveless `/etc/passwd.py` keeps only the
      drive letter and becomes `C:/etc/passwd.py`. `C:evil.py` is a third shape -- DRIVE-RELATIVE,
      meaning that drive's working directory -- and `is_absolute()` is False for it in BOTH path
      flavours, which is why the rejection below tests `drive` and `root` instead of asking that one
      convenient question.
    * EXISTENCE IS NOT MEMBERSHIP. `../outside.py` resolves to a real file beside the checkout, and
      an untracked `.py` inside it is a real file too. Both pass an existence test and neither is in
      a fresh clone.

    Backslash spellings are refused rather than translated, and the reason is one level lower than it
    looks. pre-commit splits `entry` with `shlex.split` (lang_base.py, read 2026-08-18) and this guard
    does the same, so in POSIX mode a backslash ESCAPES the next character instead of separating path
    components: measured, an unquoted `python scripts\\hooks\\ledger_check.py` splits to the token
    `scriptshooksledger_check.py`. That still ends in `.py`, so it arrives here looking like a path
    and reds as untracked; only a QUOTED spelling reaches the backslash branch below with its
    separators intact. Either way the entry is broken, and translating the separators here would
    repair the spelling while leaving the hook naming a file git does not record under that name.

    WHAT IT STILL DOES NOT SEE, since the point of the rewrite is to stop over-claiming: a tracked
    symlink pointing out of the tree satisfies every rule below, and nothing here reads file
    contents, so a tracked script that imports a third-party package is accepted exactly as before.
    """
    posix = PurePosixPath(token)
    windows = PureWindowsPath(token)
    if windows.drive or windows.root or posix.is_absolute():
        return (
            f"runs `python {token}`, whose target carries a drive, a root or a UNC host and so names "
            f"no file inside the checkout. Measured 2026-08-18: joining the repo root to a "
            f"drive-absolute or UNC token DROPS the repo root outright, and a drive-relative "
            f"`C:script.py` means whatever that drive's working directory happens to be. pre-commit "
            f"runs hooks from the repo root, so only a repo-relative target is one file everywhere"
        )
    if "\\" in token:
        return (
            f"runs `python {token}`, spelling its target with backslashes. git records paths with "
            f"forward slashes, so this matches nothing in the tracked tree -- and pre-commit splits "
            f"the entry with `shlex.split`, where an UNQUOTED backslash escapes the next character "
            f"rather than separating components. Use forward slashes"
        )
    if ".." in posix.parts:
        return (
            f"runs `python {token}`, whose target climbs out of the checkout with `..`. pre-commit "
            f"runs hooks from the repo root, so this names a file BESIDE the repository -- present "
            f"on the machine that wrote the entry and on no other"
        )
    if str(posix) not in _tracked_files():
        return (
            f"runs `python {token}`, which this repository does not TRACK. The file may well exist "
            f"here; `git ls-files` does not list it, so a fresh clone does not get it and the hook "
            f"is dead for everyone but its author -- whose own commit passes, which is what makes "
            f"this the easy one to write by accident. `git add` the script in the same commit"
        )
    return None


def _python_target_defect(args: list[str]) -> str | None:
    """Why `python <args>` cannot be trusted to run with no venv activated, or None if it can.

    Handles the shapes that actually occur: a repo script by path (all four hooks today), `-m module`
    in both spellings (`-m ruff` and `-mruff`), and inert flags in between. Anything else -- `-c`, a
    value-taking flag, a bare target that is not a .py file -- reds, because the alternative is a
    guess, and a guess in this guard reads as a pass.

    IT STOPS AT THE TARGET, deliberately, and that is the honest description rather than "it reads
    the whole entry". Everything up to and including the target is inspected -- the interpreter, its
    flags, then either a `-m` module or a `.py` path. The tokens AFTER a target are that target's own
    argv and cannot change which program executes, so reading them would add no reach; it would only
    let this guard red on a hook that legitimately passes its script a literal argument.
    """
    rest = list(args)
    while rest:
        token = rest.pop(0)
        if token in _PYTHON_INERT_FLAGS:
            continue
        if token.startswith("-m"):
            module = token[2:] or (rest.pop(0) if rest else "")
            if not module:
                return "runs `python -m` with no module after it"
            if module in _SYSTEM_PYTHON_MODULE_ALLOWLIST:
                return None
            return (
                f"runs `python -m {module}`. The INTERPRETER resolves on PATH; the module has to be "
                f"importable by whatever interpreter that is, and only a venv supplies a "
                f"third-party one -- so this is the unrunnable-hook defect one level down, wearing "
                f"an entry whose first word is allowed"
            )
        if token.startswith("-c"):
            return (
                "runs an inline program with `python -c`, which can import anything and states none "
                "of it in the config -- there is nothing here for this guard, or a reviewer, to check"
            )
        if token.startswith("-"):
            return (
                f"carries the interpreter flag `{token}`, which is not in _PYTHON_INERT_FLAGS. Some "
                f"flags consume the next token as a value, so skipping an unrecognised one would "
                f"make this guard reason about the wrong word; it reds instead of guessing"
            )
        if not token.endswith(".py"):
            return f"runs `python {token}`, which is neither a `-m` module nor a .py script path"
        return _script_target_defect(token)
    return "names `python` with nothing after it to run"


def _system_entry_defect(entry: str) -> str | None:
    """Why this whole `language: system` entry cannot be trusted, or None if it can.

    THE WHOLE ENTRY, not argv[0]. See `_SYSTEM_PYTHON_MODULE_ALLOWLIST` for the measurement that
    forced this: a program-name-only check passes `python -m ruff check --fix`.
    """
    argv = shlex.split(entry)
    if not argv:
        return "declares an empty `entry:`"
    if argv[0] not in _SYSTEM_ENTRY_ALLOWLIST:
        return (
            f"names the program `{argv[0]}`, which is not in _SYSTEM_ENTRY_ALLOWLIST -- pre-commit "
            f"resolves it on PATH with no venv in play"
        )
    return _python_target_defect(argv[1:])


def _system_hook_defect(hook: dict[str, Any]) -> str | None:
    """Why this `language: system` hook cannot be trusted, or None if it can.

    IT USED TO CRASH ON THE MOST INTERESTING CASE. The lookup was `hook["entry"]`, which raises
    `KeyError: 'entry'` for a hook that declares `language:` and leaves `entry:` to somebody else's
    manifest -- so the guard's message, the one carrying every remedy a reader needs, never printed.

    And that case is not hypothetical: it is what adding one line, `language: system`, under
    `- id: ruff-check` produces. This file's mapping then has a `language` and no `entry`, while the
    hook pre-commit assembles resolves upstream's `ruff check --force-exclude` as a bare program name
    on PATH -- the retired unrunnable-hook defect, restored under the pinned repo's own hook id. The
    only honest verdict is to red: the entry that would run is declared in a manifest nothing in this
    checkout reads, so no amount of inspection here can vouch for it.
    """
    entry = hook.get("entry")
    if entry is None:
        return (
            "declares `language: system` but states no `entry:` of its own, so what it executes "
            "comes from a third-party manifest this checkout never reads -- and `language: system` "
            "resolves that entry as a bare program name on PATH, in whatever environment the shell "
            "the commit came from happens to have. Whatever the other repo pins stops deciding "
            "anything. Drop the override, or move the hook to `repo: local` and state the entry here"
        )
    return _system_entry_defect(str(entry))


def test_language_system_hook_entries_resolve_without_an_activated_venv() -> None:
    """The ruff move fixed one unrunnable hook; nothing stopped the next one being written.

    The version test next door guards what the fix REPLACED the old arrangement with. This guards
    the defect itself, which was never about ruff: `language: system` resolves `entry:` as a bare
    program name on PATH, and a program that only an activated venv provides is unrunnable for
    anyone committing from a shell that has not activated one -- which an agent session cannot do at
    all, since shell state does not survive between tool calls. The visible symptom is a red hook
    whose only apparent remedy is `--no-verify`, and that does not skip one hook: it drops the
    ledger gate and the leak gate with it. A gate people are pushed to bypass WHOLESALE is worse
    than the narrower one it was meant to be.

    IT READS THE ENTRY AS FAR AS THE TARGET, and the first version stopped at the program name. That
    meant `entry: python -m ruff check --fix` passed it: `python` is allowed, and what that python was
    pointed at was never looked at. The retired defect, rewritten under a new hook id, green. Worse,
    the assertion message here USED TO RECOMMEND that shape as the remedy -- a guard whose printed
    advice reconstructs the defect it exists to catch, at the moment a reader is deciding what to do.
    Both are fixed: `_python_target_defect` reasons about the target, and the message below sends
    people to a pre-commit-managed repo instead. It stops AT the target rather than running to the end
    of the argv, on purpose -- see `_python_target_defect` for why the tokens after one cannot matter.

    A `.py` TARGET MUST BE TRACKED, not merely present. That is the second thing this used to get
    wrong, and it got it wrong in a direction nothing would have reported: `is_file()` is satisfied by
    a script the author has and never committed, so the entry works on exactly one machine and the
    commit that introduces it is green. `_script_target_defect` asks `git ls-files`, and refuses an
    anchored or `..`-climbing token before that, since neither can be a repo-relative path at all.

    TWO LIMITS, KEPT RATHER THAN FIXED, because a guard that overstates its reach is worse than one
    that states its edge:

    * IT ONLY SEES HOOKS WHOSE `language:` THIS CONFIG STATES, which today means the local block. A
      third-party repo shipping a `language: system` hook with exactly this defect is invisible here
      -- that entry lives in the other repo's manifest, and nothing in this checkout reads it. The
      NEAR case is covered rather than the far one: a `language: system` written HERE onto a
      third-party hook leaves an entry this file cannot see, and `_system_hook_defect` reds on it
      instead of crashing with a KeyError the way it once did.
    * IT IS A NAME CHECK, NOT AN EXECUTION. It does not run anything, so it cannot see that a repo
      script it accepts imports a third-party package, nor that a program a venv provides has been
      installed globally on somebody's machine. `pwsh` is the honest example of the second: measured
      2026-08-18, it DOES resolve on the ambient PATH here (WindowsApps), and a hook naming it would
      still red. That is friction on a pytest run rather than on a commit -- pre-commit does not run
      this suite -- and the escape hatch is named in the message: measure it, then add it.

    The four hooks in scope are not being changed by this guard; its job is to stop a NEW one.
    """
    system_hooks = [
        hook
        for repo in _config()["repos"]
        for hook in repo["hooks"]
        if hook.get("language") == "system"
    ]
    # Non-vacuity, before the comparison: an empty list satisfies the loop below trivially, and the
    # ways to empty it -- the local block reorganised, `language` moved to a default -- are edits a
    # reviewer would wave through. An instrument that finds nothing must say so, not report success.
    assert system_hooks, (
        f"no `language: system` hooks found in {_PRECOMMIT.name}, so this guard just checked "
        "nothing. Either they were all migrated (delete this test in the same commit, deliberately) "
        "or the way they declare `language:` changed and this lookup needs re-pointing."
    )

    offenders = {
        str(hook["id"]): defect
        for hook in system_hooks
        if (defect := _system_hook_defect(hook)) is not None
    }
    assert not offenders, (
        "`language: system` hooks that will not run without an activated venv:\n  "
        + "\n  ".join(f"{hook_id}: {defect}" for hook_id, defect in sorted(offenders.items()))
        + "\n\npre-commit resolves the entry on PATH and runs it in whatever environment that "
        "resolves to, so BOTH halves have to hold -- the program has to be on the ambient PATH, and "
        "so does whatever it then executes. A hook that fails this is unrunnable for everyone who "
        "has not activated a venv in the shell they are committing from, which an agent session "
        "cannot do at all, and the only apparent remedy is `--no-verify` -- which drops the ledger "
        "gate and the leak gate along with it.\n\n"
        "`python -m <tool>` IS NOT THE REMEDY, however much it looks like one. It swaps a program "
        "that does not resolve for a module that does not import, leaves the same venv dependency "
        "one level down, and is measurably just as dead: `python -m ruff --version` exits 1 here. "
        "Move the hook to a pre-commit-managed repo the way ruff was moved (a `repo:` + `rev:` "
        "entry, which builds its own environment), or -- if the program or module really does "
        "resolve with no venv on the platform the hooks run on -- measure that and add it to "
        "_SYSTEM_ENTRY_ALLOWLIST or _SYSTEM_PYTHON_MODULE_ALLOWLIST above WITH the measurement, the "
        "way `python` is justified there."
    )


def _bandit_skips(text: str) -> set[str]:
    m = re.search(r"--skip[= ]([A-Z0-9,]+)", text)
    assert m, f"no --skip found in: {text[:200]!r}"
    return set(m.group(1).split(","))


def test_bandit_skips_match() -> None:
    hook_args = " ".join(_hooks()["bandit"].get("args") or [])
    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    assert _bandit_skips(hook_args) == _bandit_skips(ci), (
        "the bandit hook and the CI bandit job disagree about which tests are skipped — one of them "
        "is enforcing a standard the other does not"
    )


def test_bandit_excludes_match() -> None:
    """The hook excludes by regex, CI by comma-separated paths. Compare the PATHS they name.

    CI additionally excludes .venv/node_modules, which pre-commit never passes to a hook (they are
    untracked), so those are ignored rather than required on both sides.
    """
    hook_re = _hooks()["bandit"]["exclude"]
    hook_paths = {p.strip("/") for p in re.findall(r"[\w./-]+/", hook_re)}

    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    m = re.search(r"--exclude[= ]([^\s\\]+)", ci)
    assert m, "CI bandit step has no --exclude"
    # removeprefix, not strip("./"): strip() removes those CHARACTERS from both ends, so "./.venv"
    # would become "venv" and silently fail to match the untracked set below.
    untracked = {".venv", "node_modules"}
    ci_paths = {p.strip().removeprefix("./").rstrip("/") for p in m.group(1).split(",")} - untracked

    assert hook_paths == ci_paths, (
        f"bandit scope drifted: hook excludes {sorted(hook_paths)}, CI excludes {sorted(ci_paths)}. "
        "A path excluded on ONE side only is scanned by one gate and not the other — which is how "
        "scripts/ came to be gated locally and by nothing in CI."
    )


def test_ci_bandit_scans_the_repo_not_an_allow_list() -> None:
    """`-r messagefoundry tee` silently stopped covering scripts/ the moment security tooling moved
    there. Scanning `.` minus explicit excludes cannot go stale that way."""
    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    assert re.search(r"bandit\s+-r\s+\.", ci), (
        f"CI bandit must scan `-r .` with explicit --exclude, not an allow-list of dirs; got: {ci!r}"
    )


_BANDIT_REPO = "PyCQA/bandit"


def _bandit_repo_rev() -> str:
    """The `rev:` pinning the bandit hook, found by URL the way `_ruff_repo` finds ruff's.

    Asserts exactly one match for the same reason: two bandit entries lets this test pin one rev
    while a different one actually runs.
    """
    matches = [r for r in _config()["repos"] if _BANDIT_REPO in str(r.get("repo", ""))]
    assert len(matches) == 1, (
        f"expected exactly one .pre-commit-config.yaml repo whose URL contains {_BANDIT_REPO!r}; "
        f"found {[r.get('repo') for r in matches]!r}."
    )
    return str(matches[0]["rev"]).lstrip("v")


def _ci_scanner_pin(package: str) -> str:
    """The EXACT version `[dependency-groups] ci-scanners` pins for ``package``.

    Parsed as TOML rather than regexed, for the reason `_pyproject_ruff_specifier` gives: the group
    carries a long comment naming versions and findings, and a regex over the raw text would happily
    mine a version out of that prose.

    THE `==` IS ASSERTED HERE rather than borrowed from tests/test_ci_venv_pinning.py's
    `EXACT_GROUP_PINS`. A floor would make the comparison below meaningless in a way that still looks
    green: `uv export` writes a fully `==`-pinned lock from a `>=` spec just as readily, so nothing
    downstream reveals the difference, and this assertion would then be holding the hook's rev
    against a version nobody promised to install.
    """
    pyproject = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    group: list[str] = pyproject["dependency-groups"]["ci-scanners"]
    pins = [r.specifier for r in (Requirement(entry) for entry in group) if r.name == package]
    assert len(pins) == 1, (
        f"expected exactly one {package} requirement in [dependency-groups] ci-scanners; found "
        f"{[str(s) for s in pins]!r}. If it left the group this test goes with it, rather than "
        "passing vacuously."
    )
    spec = str(pins[0])
    assert spec.startswith("=="), (
        f"ci-scanners pins {package} as {spec!r}, not an exact `==`. The comparison below would then "
        "hold the hook's rev against a RANGE, so Dependabot's weekly uv PR could move the installed "
        "version inside uv.lock with no pyproject diff to review, and this test would stay green "
        "while the two halves diverged."
    )
    return spec.removeprefix("==")


def test_bandit_hook_rev_matches_the_version_ci_installs() -> None:
    """The bandit `rev:` and the ci-scanners pin must name ONE bandit.

    SCOPE has been pinned by the two arms above since the hook and CI first drifted. VERSION was not,
    and it is the same divergence one level down: `--skip B101,...` means different findings under
    different bandit releases. The group's own comment records exactly that happening -- an unpinned
    1.9.x upgrade changed `# nosec` parsing and broke a green branch -- so two halves that agree on
    every skip and every exclude can still enforce different standards, with nothing saying so.

    IT MATTERS MOST ON A COMMIT NOBODY GATED. BACKLOG #1395: git does not run pre-commit for a commit
    created by the sequencer, so after a rebase the CI build is the only bandit that ever looked. A
    developer whose commit passed locally has learned nothing about the version that will judge it.

    `pre-commit autoupdate` is the likely author. .pre-commit-config.yaml already warns that a bare
    run walks the RUFF rev past its cap; it walks this one too, and until now nothing objected.
    """
    hook_rev = _bandit_repo_rev()
    installed = _ci_scanner_pin("bandit")
    print(f"[lint-scope] bandit: hook rev {hook_rev}, ci-scanners pin {installed}")
    assert hook_rev == installed, (
        f"the bandit pre-commit hook pins {hook_rev} while [dependency-groups] ci-scanners installs "
        f"{installed}, so the commit-time gate and the REQUIRED CI bandit job are different builds "
        f"of the same scanner. Each can report a finding the other does not, and on a rebase-created "
        f"commit only the CI one runs at all (BACKLOG #1395). Move the rev and the pin together, and "
        f"re-export the lock -- `uv lock` then the export command in ci/locks/ci-scanners.lock's "
        f"header, or DEP-1 goes red."
    )


def _ci_command(run: str, program: str) -> str:
    """The single-line form of the `program ...` command inside a multi-line CI step body.

    Joins backslash continuations and DROPS comment lines, so every assertion below is made against
    the argv that actually runs. That is load-bearing rather than tidiness: the first draft of the
    exclude extractor ran its regex over the whole step body and duly reported an exclude named
    ``matches``, mined out of the English sentence "semgrep's --exclude matches GLOBS" in the comment
    above the command. Prose must never be able to change what a gate test measures.
    """
    joined = run.replace("\\\n", " ")
    line = next(
        (
            ln
            for ln in joined.splitlines()
            if ln.strip().startswith(f"{program} ") and not ln.strip().startswith("#")
        ),
        None,
    )
    assert line is not None, f"no `{program} ...` command found in the step body: {run!r}"
    return line.strip()


def _semgrep_command() -> str:
    """The REPO-WIDE semgrep command, from the step selected by its exact name.

    Two couplings a future editor should know about, both deliberate:

    1. This selects by step NAME, so renaming "Run the MessageFoundry rules" breaks both semgrep
       tests here. A loud failure is the point — the alternative is a test that silently starts
       asserting about some other command.
    2. The semgrep job has TWO `run:` steps, and the second (ADR 0144 Inc 3) deliberately scans an
       ALLOW-LIST (samples/config) with a DIFFERENT rules file. A loose fragment would match the
       wrong invocation and assert the opposite of what is intended. Note that no step name in that
       job contains the string "semgrep", so `_ci_step_run(_SECURITY, "semgrep")` raises rather than
       quietly returning one of them.

    The `--config .semgrep` re-check guards (2): even if the name match were retargeted, a step
    pointing at the packaged handler rules is not the gate these tests are about. It is checked
    against the COMMAND, not the step body, so a passing mention of the rules dir in a comment
    cannot satisfy it.
    """
    command = _ci_command(_ci_step_run(_SECURITY, "Run the MessageFoundry rules"), "semgrep")
    assert "--config .semgrep" in command, (
        "the repo-wide semgrep step no longer points at the .semgrep/ project rules, so these tests "
        f"would be asserting scope against a different rule set entirely; got: {command!r}"
    )
    return command


#: Long flags on the semgrep command that CONSUME the following token as their value.
#:
#: Hand-maintained, and that carries a real maintenance obligation: a NEW value-taking flag added to
#: the command without being added here turns its value into a phantom positional "target" and reds
#: ``test_ci_semgrep_scans_the_repo_not_an_allow_list`` — with a message about SCOPE, for a change
#: that had nothing to do with scope. The direction is deliberate (fail loud, make the next flag a
#: considered edit rather than a silent one), but read this set first when that test reds unexpectedly.
_SEMGREP_VALUE_FLAGS = frozenset({"--config", "--exclude", "--include", "--metrics"})


def _semgrep_targets(command: str) -> list[str]:
    """The POSITIONAL targets of the semgrep invocation — i.e. what it is pointed at.

    Deliberately not a regex on the command text: "does it end in a dot?" is a different question
    from "what is this pointed at?", and only the second is the contract. shlex-splits, then drops
    flags and the values consumed by them.

    NOT the whole scope on its own — see ``_semgrep_includes``. `--include` narrows what a positional
    target expands to, so "targets" and "scope" coincide only while no `--include` is present, which
    is why the test asserts both.
    """
    targets: list[str] = []
    skip_next = False
    for token in shlex.split(command)[1:]:  # [1:] drops the `semgrep` program name
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            flag, sep, _value = token.partition("=")
            skip_next = flag in _SEMGREP_VALUE_FLAGS and not sep
            continue
        targets.append(token)
    return targets


def _semgrep_includes(command: str) -> set[str]:
    """`--include` values, which NARROW the scan to paths matching them.

    Extracted separately because `--include` is the allow-list in disguise: `semgrep ... --include
    messagefoundry --include tee .` scans exactly the two directories BACKLOG #334 exists to retire,
    while the positional target still reads `.`. A targets-only assertion reports green on it.
    """
    return {m.group(1).strip() for m in re.finditer(r"--include[= ]([^\s\\]+)", command)}


def _semgrep_excludes(command: str) -> set[str]:
    """semgrep's excludes are a REPEATED flag taking one glob each; bandit's is one comma list.

    Returns the values VERBATIM. Normalising is left to the caller precisely because a normalisation
    DIFFERENCE between the two gates is one of the things worth asserting — see the `./` check in
    ``test_semgrep_and_bandit_exclude_the_same_paths``, which would be erased by normalising here.
    """
    return {m.group(1).strip() for m in re.finditer(r"--exclude[= ]([^\s\\]+)", command)}


def test_ci_semgrep_scans_the_repo_not_an_allow_list() -> None:
    """`messagefoundry tee` left scripts/ (the security tooling itself), messagefoundry_webconsole/
    and docker/ — 59 tracked .py files the sibling bandit gate already scans — covered by none of the
    project's own dangerous-sink rules. Scanning `.` minus explicit excludes cannot go stale when the
    next package is added."""
    command = _semgrep_command()

    targets = _semgrep_targets(command)
    assert targets == ["."], (
        "CI semgrep must scan `.` with explicit --exclude, not an allow-list of dirs; it scans "
        f"{targets!r}. An allow-list cannot be kept in step with 'the project' by hand — that is "
        "precisely how the old `messagefoundry tee` scope came to miss scripts/."
    )

    # An `--include` re-narrows the scan WITHOUT touching the positional target, so the assertion
    # above stays green through it. That is the whole regression this item exists to prevent, in the
    # one shape a "what is it pointed at?" check cannot see — so it is asserted on its own terms.
    includes = _semgrep_includes(command)
    assert not includes, (
        f"CI semgrep is pointed at `.` but restricted with --include {sorted(includes)}. semgrep's "
        "--include NARROWS the scan to matching paths, so this rebuilds the retired allow-list while "
        "the positional target still reads `.` — the scope regression this test exists to catch, "
        "wearing the argv of the fix."
    )


def test_ci_semgrep_still_fails_the_build_on_a_finding() -> None:
    """Scope is only half the gate: semgrep exits 0 on findings unless `--error` is passed.

    Without it this job reports every match and then goes GREEN — a required context that cannot
    fail, which is strictly worse than the narrow scope it replaced, because the narrow scope at
    least still red on what it did see. `tests/test_security_posture.py`'s neutering scan cannot
    catch this: it matches ADDED idioms (`|| true`, `--exit-zero`), never a REMOVED enforcement flag.
    Widening the scan from 280 to 339 files is what makes this worth its own assertion.
    """
    command = _semgrep_command()
    assert "--error" in command, (
        "the repo-wide semgrep command dropped `--error`, so semgrep exits 0 on findings: every "
        "match across the whole scanned tree would be printed and the required context would still "
        f"report success. Got: {command!r}"
    )


def test_semgrep_and_bandit_exclude_the_same_paths() -> None:
    """The two blocking SAST gates scan the same checkout, so they must agree on what is out of scope.

    Unlike the bandit hook-vs-CI test above, nothing is subtracted here: both sides are CI
    invocations over the identical tree, so .venv/node_modules must appear on BOTH — there is no
    pre-commit "these are untracked anyway" carve-out to grant.

    This does NOT assert that the two excludes have the same MEANING: bandit's are paths, semgrep's
    are globs, and whether semgrep anchors them at the repo root is not settled by reading a string.
    It asserts only that the two gates name the same set, which is the part that drifts — plus the
    one normalisation difference that comparing normalised sets would otherwise hide.
    """
    semgrep_cmd = _semgrep_command()
    semgrep_raw = _semgrep_excludes(semgrep_cmd)

    bandit_cmd = _ci_command(_ci_step_run(_SECURITY, "Scan source for insecure patterns"), "bandit")
    m = re.search(r"--exclude[= ]([^\s\\]+)", bandit_cmd)
    assert m, f"CI bandit step has no --exclude: {bandit_cmd!r}"
    bandit_raw = {p.strip() for p in m.group(1).split(",")}

    # Non-vacuity, BEFORE any comparison: two empty sets compare equal. An extractor that quietly
    # stopped matching — a renamed flag, a reflowed line — would make this test report PASS while
    # comparing nothing at all. Prove each instrument still sees something first.
    assert semgrep_raw, f"the semgrep --exclude extractor matched nothing in: {semgrep_cmd!r}"
    assert bandit_raw, f"the bandit --exclude extractor matched nothing in: {bandit_cmd!r}"

    # The set comparison below normalises `./` off BOTH sides, so on its own it would report parity
    # for `./tests` vs `tests` — two strings that do NOT mean the same thing to the two tools.
    # bandit's --exclude takes PATHS, where `./tests` is fine; semgrep's takes GLOBS, where `./tests`
    # matches nothing and the flag is simply inert. So the most likely way to break this scope is to
    # "fix" the drift by copying bandit's string byte-for-byte. Asserted before the normalisation.
    dot_slash = sorted(p for p in semgrep_raw if p.startswith("./"))
    assert not dot_slash, (
        f"semgrep --exclude values {dot_slash} carry bandit's `./` prefix. semgrep matches --exclude "
        "as a GLOB, so `./tests` excludes nothing and the flag is inert — while the set comparison "
        "in this same test normalises `./` away and would report the two gates in perfect parity."
    )

    semgrep_paths = {p.removeprefix("./").rstrip("/") for p in semgrep_raw}
    bandit_paths = {p.removeprefix("./").rstrip("/") for p in bandit_raw}

    assert semgrep_paths == bandit_paths, (
        f"SAST scope drifted: semgrep excludes {sorted(semgrep_paths)}, bandit excludes "
        f"{sorted(bandit_paths)}. A path excluded from ONE gate only is scanned by one and not the "
        "other, which is the same class of silent divergence that left scripts/ out of CI bandit."
    )
