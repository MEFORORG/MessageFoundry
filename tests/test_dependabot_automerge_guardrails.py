# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Structural AND behavioural regression tests for the Dependabot auto-merge guardrails (SEC-007).

Most of these assert the YAML wiring of ``.github/workflows/dependabot-auto-merge.yml``; the
behavioural ones go further and **execute the shipped ``run:`` bodies under ``bash -e``** — the shell
GitHub Actions applies by default on Linux — because the guardrails are shell logic and "the YAML
names a step" is a much weaker claim than "the step holds what it must hold". That is possible only
because every ``run:`` step takes every input through ``env:`` and interpolates nothing — asserted by
``test_every_run_step_takes_every_input_through_env_not_interpolation``, a precondition for the
behavioural tests as much as it is zizmor template-injection parity.

The guardrail numbers below are DEPENDENCY-POSTURE-REVIEW.md's, carried with two corrections that
document does not yet make — do not read them as claims about its text:
  #3 an ALLOW-SET step holds every PR whose dependencies are not named on their ecosystem's allow row
     (hold-unless-named; the whole group is denied on any single ineligible member). This is
     **INVERTED** from the deny-list the posture review describes, and it gates EVERY track, not only
     the security one.
  #2 a published-GHSA step gates the cooldown-bypassing SECURITY track on a real advisory, and
  #4 a release-age step additionally holds a SECURITY-track PR whose candidate version is younger
     than ``MIN_RELEASE_AGE_HOURS`` — the track the upstream ``cooldown`` cannot age. **#4 is
     introduced in this repository; the posture review does not carry it.**
All three must be wired into the ``Enable auto-merge`` step's ``if`` so a held/un-advisoried/fresh PR
does NOT auto-merge, while an eligible patch still does (``gh pr merge --auto`` preserved).

WARNING: #4 cannot change a merge decision as the workflow ships, and these tests do not pretend otherwise:
``age_ok=true`` is reachable only for uv/pip, ``eligible=true`` only for github-actions, and the merge
``if`` requires both — disjoint sets. It is tested as a FORWARD guard, so that populating a Python
allow row later is a one-line change to a control that already works, not a control to be written
under pressure. ``test_release_age_is_gated_on_the_allow_set`` pins the conjunction that makes this
true, so the day someone widens it, a test has to be edited deliberately.
"""

from __future__ import annotations

import copy
import datetime as dt
import functools
import itertools
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import NamedTuple

import pytest
import yaml
from _bash_resolver import bash_candidates, probe_env, require_bash

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW = _ROOT / ".github" / "workflows" / "dependabot-auto-merge.yml"
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"

# Security-critical packages that must NEVER be auto-merge eligible, even for a patch
# (posture-review #3). These were the 16 names of the former DENY-LIST; the mechanism has inverted to
# an allow-set, but the PROPERTY they encoded is still the thing under test — none of them may appear
# on any allow row. Keeping the tuple keeps that property executable rather than merely intended.
_DENY_PACKAGES = (
    "cryptography",
    "argon2-cffi",
    "argon2-cffi-bindings",
    "paramiko",
    "ldap3",
    "pyspnego",
    "fastapi",
    "starlette",
    "uvicorn",
    "pydantic",
    "pydantic-core",
    "python-jose",
    "pyjwt",
    "passlib",
    "bcrypt",
    "cffi",
)

#: ``$VAR`` / ``${VAR}`` shell references, upper-case only (lower-case names are the scripts' own
#: locals, which are not inputs).
_ENV_REF = re.compile(r"\$\{?([A-Z][A-Z0-9_]*)\}?")

#: Provided by the Actions runner itself, so a step need not declare it in ``env:``.
_RUNNER_PROVIDED = frozenset({"GITHUB_OUTPUT"})


@functools.cache
def _parsed() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def _load() -> dict:
    # Parsed once; each caller gets its own copy, so no test can change what another reads.
    return copy.deepcopy(_parsed())


def _steps() -> list[dict]:
    doc = _load()
    # Every job's steps, the disarm job's first: step ids are unique across the workflow.
    return [s for job in doc["jobs"].values() for s in job["steps"]]


def _step(step_id: str) -> dict:
    """The step with ``id: <step_id>``, failing loudly rather than returning None."""
    found = next((s for s in _steps() if s.get("id") == step_id), None)
    assert found is not None, f"no step with id: {step_id}"
    return found


def _load_dependabot() -> dict:
    """Parse ``.github/dependabot.yml``, ASSERTING it is there rather than skipping when it is not.

    The guard this replaced skipped on the premise that the file is "private-only, deny-listed on the
    OSS mirror". That premise is false, and `.gitignore` says so in as many words: the publish
    deny-list is RETIRED, and `.github/dependabot.yml` is named in the *"DELIBERATELY NOT LISTED"*
    note as content meant to ship. Measured: ``git ls-files --error-unmatch .github/dependabot.yml``
    resolves and ``git check-ignore`` exits 1.

    That matters more after this change than before it. At HEAD the guard sat inline in ONE test;
    three now route through here, including ``test_every_configured_ecosystem_has_a_cooldown`` — the
    test whose whole reason for existing is that a missing cooldown was invisible to CI. A skip keyed
    on a false premise would have made it invisible a second way. tests/test_anon_parity.py:42-45
    records this exact lesson from the other direction: a stale skip path "silently skipped the parity
    assertions below, which are the only thing keeping [the tables] identical".
    """
    assert _DEPENDABOT.exists(), (
        f"{_DEPENDABOT} is a TRACKED file (see .gitignore's 'DELIBERATELY NOT LISTED' note) — its "
        f"absence is the bug, not a reason to skip the cooldown assertions"
    )
    return yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))


def _assert_stubs_win(bash: str, path_prepend: Path, full_env: dict[str, str]) -> None:
    """SELF-CERTIFY THE SHADOWING, in the child, in the same env the body will run under.

    Prepending a stub directory to PATH is not the same as the stub being CHOSEN, and the gap between
    those two is silent: the step runs, the real binary answers, and the row passes or fails on
    whatever the network said. That is not hypothetical -- Git for Windows' ``bin/bash.exe`` rewrites
    the inherited PATH so ``/mingw64/bin`` leads, Git ships ``curl.exe`` there, and a curl stub lost
    while ``gh`` and ``jq`` stubs kept winning, so the damage read as flakiness rather than as one
    defect (BACKLOG #1216).

    ``_bash_resolver`` now refuses that interpreter, and this check exists ANYWAY, because the two
    guard different things. The resolver decides which bash we launch; this decides whether the stub
    actually won in the environment this body is about to execute in. A future shell, a wrapper script
    or a CI image that reorders PATH for its own reasons is caught here without anyone having
    predicted it.

    Asked by RESOLUTION rather than by reading PATH back: ``command -v`` reports what the shell would
    actually execute, which is the question. Reading ``$PATH`` would only confirm the string we just
    set.
    """
    stubs = sorted(p.name for p in path_prepend.iterdir() if p.is_file())
    if not stubs:
        return
    probe = "; ".join(f"command -v {name} || echo MISSING-{name}" for name in stubs)
    out = subprocess.run(
        [bash, "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        env=full_env,
    )
    resolved = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    leaf = path_prepend.name
    bypassed = [ln for ln in resolved if leaf not in ln.replace("\\", "/")]
    assert not bypassed, (
        f"a stub in {path_prepend} did NOT win in the child environment -- these resolved elsewhere: "
        f"{bypassed}. The step body would have run against the REAL binary (and, for curl, the live "
        f"network), so any verdict from it is about nothing. Stubs present: {stubs}. Bash: {bash}."
    )


class StepRun(NamedTuple):
    """What a step body did, INCLUDING what it said (BACKLOG #1312).

    The stdout/stderr fields exist because their absence cost a real diagnosis. This helper used to
    run the child with ``capture_output=True`` and return only ``(rc, outputs)``, so the step's own
    ``::notice::'<name>==<ver>' was published Nh ago`` and every ``::warning::`` were captured and
    then DISCARDED. A failing row therefore reported a wrong boolean and withheld the one sentence
    that says WHY -- the age the step actually computed, and from which payload.

    That is what made the live-PyPI reach on ``windows-2025`` hard to see rather than obvious: the
    harness had the evidence in hand at the moment of failure and threw it away. Whoever debugs a row
    here should read the child's own words BEFORE theorising about PATH interposition.
    """

    rc: int
    outputs: dict[str, str]
    stdout: str
    stderr: str


def _run_step_body(
    step_id: str,
    env: dict[str, str],
    tmp_path: Path,
    path_prepend: Path | None = None,
) -> StepRun:
    """Run a step's shipped ``run:`` body under ``bash -e``; return rc, outputs, stdout and stderr.

    The body is executed VERBATIM — no substitution, no rewriting — which is only sound because the
    step interpolates no ``${{ }}`` expressions. That invariant is asserted separately.

    **The shell is ``bash -e``, mirroring the ``bash -e {0}`` that GitHub Actions applies as its
    default on Linux.** No ``shell:`` is declared anywhere in the workflow, at step, job or workflow
    level — ``test_no_step_overrides_the_default_shell`` pins that, because the moment one is added
    this harness stops mirroring CI. Plain ``bash`` was the wrong shell to assert under: it keeps
    going after a failing command where CI aborts the step, which is a difference these tests would
    have reported as agreement. Measured on the shipped bodies, every row here decides identically
    under both — so this is a fidelity fix, not a behaviour change — but the returncode is now
    RETURNED rather than asserted here, so an abort path can be expressed as an expected outcome
    instead of being indistinguishable from a harness bug.

    Any LITERAL value in the step's own ``env:`` (one carrying no ``${{ }}``) is seeded first, so a
    tuning constant like ``MIN_RELEASE_AGE_HOURS`` is exercised at its SHIPPED value rather than at
    one this test invented. The caller's ``env`` then overlays the PR-derived inputs.
    """
    # NOT ``shutil.which("bash")`` (BACKLOG #1216): that answers whether A bash exists, not whether
    # the one found can read this process's files. On Windows it resolves the WSL launcher, which runs
    # in a different filesystem namespace -- so the callers' skipif never fired and every row failed
    # for a reason unrelated to the shipped body it was checking.
    bash = require_bash(tmp_path)
    step = _step(step_id)
    body = str(step["run"])
    assert "${{" not in body, (
        f"the {step_id} body interpolates an Actions expression, so this test is no longer executing "
        f"what CI executes"
    )
    script = tmp_path / f"{step_id}.sh"
    script.write_text(body, encoding="utf-8")
    out_file = tmp_path / f"{step_id}.githuboutput"
    out_file.write_text("", encoding="utf-8")

    # THE SCRIPT UNDER TEST NEEDS REAL UTILITIES, NOT JUST THE INTERPRETER (BACKLOG #1373). These
    # steps run `tr`, `grep` and `sort`; inheriting a PATH that lacks them -- which is what PowerShell
    # and cmd supply -- fails the CHILD at 127 even once `require_bash` has found a working bash. So
    # the same directory the resolver probes with is appended here. It is APPENDED, so the stub
    # directory prepended below still wins and `_assert_stubs_win` keeps measuring what it measures.
    full_env = probe_env(Path(bash), dict(os.environ))
    for key, value in (step.get("env") or {}).items():
        if "${{" not in str(value):
            full_env[str(key)] = str(value)
    full_env.update(env)
    full_env["GITHUB_OUTPUT"] = out_file.as_posix()
    if path_prepend is not None:
        full_env["PATH"] = f"{path_prepend.as_posix()}{os.pathsep}{full_env.get('PATH', '')}"
        _assert_stubs_win(bash, path_prepend, full_env)

    proc = subprocess.run(
        [bash, "-e", script.as_posix()],
        capture_output=True,
        text=True,
        timeout=120,
        env=full_env,
    )
    parsed: dict[str, str] = {}
    for line in out_file.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            parsed[key.strip()] = value.strip()
    return StepRun(proc.returncode, parsed, proc.stdout, proc.stderr)


def _diagnostic(run: StepRun) -> str:
    """The child's own words, for an assertion message. Empty streams say so explicitly.

    ``(no stdout)`` is not padding: a silent child and a child whose output was dropped by the
    harness are different faults with the same appearance, and this is the line that separates
    them."""
    return (
        f"\n--- step stdout ---\n{run.stdout.strip() or '(no stdout)'}"
        f"\n--- step stderr ---\n{run.stderr.strip() or '(no stderr)'}"
    )


# --------------------------------------------------------------------------------------------------
# Structural: the workflow's wiring
# --------------------------------------------------------------------------------------------------


def test_workflow_is_valid_yaml_and_has_the_automerge_job() -> None:
    doc = _load()
    assert "auto-merge" in doc["jobs"]


def test_no_security_critical_package_is_auto_merge_eligible() -> None:
    """Guardrail #3, as a PROPERTY rather than a mechanism: no security-critical package may be
    reachable through the allow-set. The former deny-list named them to EXCLUDE them; the allow-set
    holds by default, so the equivalent assertion is that none of them appears on any allow row."""
    allowset = _step("allowset")
    body = str(allowset.get("run", ""))
    for pkg in _DENY_PACKAGES:
        assert pkg not in body, (
            f"'{pkg}' appears in the allow-set step — a security-critical package must never be "
            f"auto-merge eligible (posture-review #3)"
        )
    # emits a guard output the merge step can require
    assert "eligible=" in body and "$GITHUB_OUTPUT" in body


def test_ghsa_step_queries_the_advisory_api_and_emits_a_guard() -> None:
    """Guardrail #2: a security-track step must consult the advisory API and emit advisory_ok."""
    body = str(_step("ghsa").get("run", ""))
    # calls the GitHub advisories API (gh api ... /advisories)
    assert "gh api" in body and "/advisories" in body
    # produces the advisory guard output and a security-track discriminator
    assert "advisory_ok=" in body and "$GITHUB_OUTPUT" in body
    assert "security_track=" in body
    # fails CLOSED — an error/no-match must not fall through to auto-merge
    assert "advisory_ok=false" in body


def test_release_age_step_is_security_track_only_and_fails_closed() -> None:
    """Guardrail #4: an ``age`` step must exist AFTER ``ghsa``, consume that step's security-track
    discriminator rather than re-deriving it, and never hard-code a PASS on an early exit."""
    ids = [s.get("id") for s in _steps()]
    assert "age" in ids, "no release-age step (id: age) found"
    assert ids.index("age") > ids.index("ghsa"), (
        "the age step must come AFTER ghsa — it consumes ghsa's security_track output"
    )

    age = _step("age")
    env = age.get("env") or {}
    assert "MIN_RELEASE_AGE_HOURS" in env, "the age threshold must be a declared, visible input"
    assert "steps.ghsa.outputs.security_track" in str(env.get("SECURITY_TRACK", "")), (
        "the security-track discriminator must be CONSUMED from the ghsa step, not re-derived — "
        "one source of truth for what 'security track' means"
    )

    body = str(age.get("run", ""))
    emits = [ln.strip() for ln in body.splitlines() if "$GITHUB_OUTPUT" in ln and "age_ok" in ln]
    assert emits, "the age step emits no age_ok output"
    # Fails closed: every literal emission is a DENY; the only PASS is the computed variable, which
    # can only be true after the loop has consulted a publish date.
    for line in emits:
        assert "age_ok=true" not in line, f"an early exit hard-codes a PASS, failing OPEN: {line}"
    assert any("age_ok=false" in ln for ln in emits), "no fail-closed emission found"
    assert any("age_ok=$age_ok" in ln for ln in emits), "no computed emission found"


def test_release_age_is_gated_on_the_allow_set() -> None:
    """The age step must not run for a PR the allow-set already holds.

    Two distinct reasons, and the weaker one is the one usually noticed. The privacy/egress reason:
    this step makes an UNAUTHENTICATED outbound GET from a job holding ``contents: write``, so making
    it for a PR that was going to be held anyway is gratuitous. The honesty reason, which is why the
    assertion lives here rather than in a comment: this ``if`` is half of the conjunction that makes
    guardrail #4 INERT today (``age_ok=true`` needs uv/pip, ``eligible=true`` needs github-actions).
    Pinning it means widening #4 into a live control has to edit a test, not slip through as prose.
    """
    age = _step("age")
    cond = str(age.get("if", ""))
    assert "steps.allowset.outputs.eligible == 'true'" in cond, (
        "the age step is not gated on the allow-set, so it performs a privileged-job network fetch "
        f"for PRs that hold regardless; if: {cond!r}"
    )


def test_no_step_overrides_the_default_shell() -> None:
    """Nothing may declare ``shell:``, at step, job or workflow level.

    Not style. ``_run_step_body`` executes the shipped bodies under ``bash -e`` on the strength of
    Actions' documented Linux default (``bash -e {0}``). Declare a ``shell:`` anywhere and that
    premise silently stops holding, leaving a behavioural suite that asserts confidently about a
    shell CI no longer uses. This is the tripwire for that.
    """
    doc = _load()
    assert "defaults" not in doc, "a workflow-level defaults: block can change the shell"
    jobs = doc["jobs"].values()
    assert all("defaults" not in job for job in jobs), (
        "a job-level defaults: block can change the shell"
    )
    for step in [s for job in jobs for s in job["steps"]]:
        assert "shell" not in step, (
            f"step {step.get('id') or step.get('name')!r} declares an explicit shell:, so the "
            f"behavioural tests no longer mirror what CI runs — update _run_step_body with it"
        )


def test_enable_automerge_gates_on_all_three_guards_and_preserves_auto_merge() -> None:
    """The merge step's ``if`` must require the allow-set guard AND the two security-track guards,
    while still invoking ``gh pr merge --auto`` for the eligible path."""
    steps = _steps()
    merge = _merge_step()
    cond = str(merge.get("if", ""))
    assert "steps.allowset.outputs.eligible == 'true'" in cond, (
        "merge not gated on the allow-set guard"
    )
    # security-track PRs require a confirmed advisory AND an aged release; version-track patches
    # keep their cooldown-aged auto-merge unchanged
    assert "steps.ghsa.outputs.advisory_ok == 'true'" in cond
    assert "steps.ghsa.outputs.security_track != 'true'" in cond
    assert "steps.age.outputs.age_ok == 'true'" in cond, "merge not gated on the release-age guard"
    assert "steps.authors.outputs.sole_author == 'true'" in cond, (
        "merge not gated on a Dependabot push of one Dependabot commit (BACKLOG #5593)"
    )
    # The sender gate is only as good as its binding: the behavioural rows supply SENDER directly.
    env = _step("authors").get("env") or {}
    assert str(env.get("SENDER", "")).replace(" ", "") == "${{github.event.sender.login}}", env
    assert (
        str(env.get("HEAD_SHA", "")).replace(" ", "") == "${{github.event.pull_request.head.sha}}"
    )
    assert str(env.get("EVENT_ACTION", "")).replace(" ", "") == "${{github.event.action}}"
    # the in-scope update-type gate is still present (any patch / dev-only minor)
    assert "version-update:semver-patch" in cond

    # A half-removal would leave the merge condition referencing a step id that no longer exists —
    # an Actions expression against a missing step evaluates to empty, silently dropping the guard.
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "steps.denylist" not in text, "dangling reference to the removed deny-list step"
    assert not any(s.get("id") == "denylist" for s in steps), "the deny-list step is still present"


# THE SUBSTRING CHECKS ABOVE CANNOT SEE THE OPERATORS BETWEEN THE GUARDS (BACKLOG #5605). Swap one
# `&&` for `||`, drop the dev-only scoping of a minor bump, or move a parenthesis, and every substring
# is still present. So the merge condition is EVALUATED, over every combination of the outputs it
# reads, and compared with the policy stated once in `_merge_policy`. The evaluator covers only the
# expression subset GitHub documents and this workflow uses; anything else fails the parse, so a
# condition rewritten in another form has to extend it here rather than pass unread.

_EXPR_TOKEN = re.compile(
    r"\s*(?:(?P<op>==|!=|&&|\|\||[()!,])|'(?P<str>(?:[^']|'')*)'|(?P<ref>[A-Za-z_][\w.\-]*))"
)


@functools.cache
def _tokenize_expression(text: str) -> tuple[tuple[str, str], ...]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _EXPR_TOKEN.match(text, pos)
        assert m and m.end() > pos, f"unparsed expression text at {text[pos:]!r}"
        pos = m.end()
        if m.group("op"):
            tokens.append(("op", m.group("op")))
        elif m.group("str") is not None:
            tokens.append(("str", m.group("str").replace("''", "'")))
        else:
            ref = m.group("ref")
            assert ref not in {"true", "false", "null"}, f"unsupported literal {ref!r}"
            tokens.append(("ref", ref))
    return tuple(tokens)


def _evaluate_expression(
    text: str,
    context: dict[str, str],
    functions: Mapping[str, Callable[..., str | bool]] | None = None,
) -> bool:
    """Evaluate an Actions ``if:`` as GitHub does for this subset: ``==``/``!=`` compare strings
    case-insensitively, ``&&``/``||`` return an operand as GitHub's do (``a || b`` is ``a`` when
    truthy, else ``b``), ``!`` negates truthiness, context and function names match
    case-insensitively, and an output that is not set (its step was skipped) reads as the empty
    string, which is falsy.

    A function call (``always()``, ``startsWith(a, b)``) is refused unless ``functions`` names it,
    so a caller that passes no table keeps the refusal of every construct outside the subset.
    tests/test_security_posture.py passes one, to show a loosening such as ``|| always()`` reads as
    a run rather than as an error."""
    tokens = _tokenize_expression(text)
    names = {key.casefold(): value for key, value in context.items()}
    calls = {key.casefold(): fn for key, fn in (functions or {}).items()}
    at = 0

    def peek() -> tuple[str, str] | None:
        return tokens[at] if at < len(tokens) else None

    def take(expected: str | None = None) -> tuple[str, str]:
        nonlocal at
        tok = peek()
        assert tok is not None, f"expression ended early: {text!r}"
        if expected is not None:
            assert tok == ("op", expected), f"expected {expected!r}, got {tok!r} in {text!r}"
        at += 1
        return tok

    def primary() -> str | bool:
        tok = take()
        if tok == ("op", "("):
            value = disjunction()
            take(")")
            return value
        if tok == ("op", "!"):
            return not bool(primary())
        if tok[0] == "str":
            return tok[1]
        if tok[0] == "ref" and peek() == ("op", "("):
            take("(")
            args: list[str | bool] = []
            if peek() != ("op", ")"):
                args.append(disjunction())
                while peek() == ("op", ","):
                    take()
                    args.append(disjunction())
            take(")")
            fn = calls.get(tok[1].casefold())
            assert fn is not None, f"unsupported function {tok[1]!r} in {text!r}"
            return fn(*args)
        if tok[0] == "ref":
            return names.get(tok[1].casefold(), "")
        raise AssertionError(f"unexpected token {tok!r} in {text!r}")

    def comparison() -> str | bool:
        left = primary()
        tok = peek()
        if tok in (("op", "=="), ("op", "!=")):
            take()
            right = primary()
            assert isinstance(left, str) and isinstance(right, str), f"non-string compare: {text!r}"
            equal = left.casefold() == right.casefold()
            return equal if tok[1] == "==" else not equal
        return left

    def conjunction() -> str | bool:
        value = comparison()
        while peek() == ("op", "&&"):
            take()
            right = comparison()
            value = right if value else value
        return value

    def disjunction() -> str | bool:
        value = conjunction()
        while peek() == ("op", "||"):
            take()
            right = conjunction()
            value = value if value else right
        return value

    result = disjunction()
    assert at == len(tokens), f"trailing tokens {tokens[at:]!r} in {text!r}"
    return bool(result)


_TRI = ("true", "false", "")


def _merge_policy(c: dict[str, str]) -> bool:
    """The merge policy, stated once: on the allow-set; a Dependabot push of one Dependabot commit
    at the pinned head (BACKLOG #5593); a security-track PR also needs a confirmed advisory AND an
    aged release; any patch, or a minor bump of a DEVELOPMENT dependency only."""
    on_allow_set = c["steps.allowset.outputs.eligible"] == "true"
    sole_author = c["steps.authors.outputs.sole_author"] == "true"
    security_ok = c["steps.ghsa.outputs.security_track"] != "true" or (
        c["steps.ghsa.outputs.advisory_ok"] == "true" and c["steps.age.outputs.age_ok"] == "true"
    )
    update = c["steps.meta.outputs.update-type"]
    in_scope = update == "version-update:semver-patch" or (
        update == "version-update:semver-minor"
        and c["steps.meta.outputs.dependency-type"] == "direct:development"
    )
    return on_allow_set and sole_author and security_ok and in_scope


def _merge_contexts() -> list[dict[str, str]]:
    axes = {
        "steps.allowset.outputs.eligible": _TRI,
        "steps.authors.outputs.sole_author": _TRI,
        "steps.ghsa.outputs.security_track": _TRI,
        "steps.ghsa.outputs.advisory_ok": _TRI,
        "steps.age.outputs.age_ok": _TRI,
        "steps.meta.outputs.update-type": (
            "version-update:semver-patch",
            "version-update:semver-minor",
            "version-update:semver-major",
            "",
        ),
        "steps.meta.outputs.dependency-type": ("direct:development", "direct:production", ""),
    }
    return [dict(zip(axes, combo, strict=True)) for combo in itertools.product(*axes.values())]


_GH_PR_MERGE = re.compile(r"gh pr merge[^;\n]*")

# The two bodies that run `gh pr merge`, pinned WHOLE (BACKLOG #5593, #5605). A check on the
# gh calls alone sees only the spellings it knows, so any edit to either body has to edit this
# text deliberately, as the one-line pin of the arm body this replaced did.
_ARM_BODY = (
    "set -u\n"
    'if gh pr merge --auto --squash --match-head-commit "$HEAD_SHA" "$PR_URL"; then\n'
    "  exit 0\n"
    "fi\n"
    'now="$(gh pr view "$PR_URL" --json headRefOid --jq .headRefOid 2>/dev/null)" || '
    'now="ERR"\n'
    'case "$now" in *[!0-9a-f]*) now_ok=false ;; *) now_ok=true ;; esac\n'
    '[ "${#now}" -eq 40 ] || now_ok=false\n'
    'if [ "$now_ok" != true ]; then\n'
    '  echo "::error::arming failed and the PR head could not be read (got '
    "'${now}').\"\n"
    "  exit 1\n"
    "fi\n"
    'if [ "$now" != "$HEAD_SHA" ]; then\n'
    '  echo "::notice::the head moved from $HEAD_SHA to $now while this run '
    'evaluated; the run for the new head decides."\n'
    "  exit 0\n"
    "fi\n"
    'echo "::error::arming failed on the head this run evaluated."\n'
    "exit 1\n"
)

_DISARM_BODY = (
    "set -u\n"
    "# `||` outside the substitution, for the reason the ghsa step gives: `gh` "
    "writes an error\n"
    "# body to stdout, and the shape check below must see the sentinel, not that "
    "body.\n"
    'armed="$(gh pr view "$PR_URL" --json autoMergeRequest --jq \'.autoMergeRequest '
    '!= null\' 2>/dev/null)" || armed="ERR"\n'
    'case "$armed" in\n'
    "  false)\n"
    '    echo "::notice::no auto-merge request is armed on this PR (a merge-queue '
    'entry is not read here)."\n'
    "    exit 0\n"
    "    ;;\n"
    "  true) ;;\n"
    "  *)\n"
    '    # Unknown is not "not armed": an arm on an earlier head may still be live, '
    "so disarm\n"
    "    # anyway. The read-back below decides whether the job passes.\n"
    "    echo \"::warning::could not read this PR's auto-merge state \u2014 disarming "
    'anyway."\n'
    "    ;;\n"
    "esac\n"
    'gh pr merge --disable-auto "$PR_URL"\n'
    'after="$(gh pr view "$PR_URL" --json autoMergeRequest --jq \'.autoMergeRequest '
    '!= null\' 2>/dev/null)" || after="ERR"\n'
    'if [ "$after" != "false" ]; then\n'
    "  echo \"::error::auto-merge still reads '${after}' after the disarm \u2014 failing "
    'closed, nothing re-arms."\n'
    "  exit 1\n"
    "fi\n"
    'echo "::warning::disarmed auto-merge armed on an earlier head; it re-arms only '
    'if the guardrails admit this head."\n'
)


def _merge_step() -> dict:
    """The one step that ARMS auto-merge, found with its whitespace collapsed."""
    arms = [s for s in _steps() if "gh pr merge --auto" in " ".join(str(s.get("run", "")).split())]
    assert len(arms) == 1, f"expected exactly one arming gh pr merge step, found {len(arms)}"
    return arms[0]


def test_one_step_arms_in_the_arming_job_and_the_disarm_step_only_disarms() -> None:
    """Exactly two steps run ``gh pr merge``: the arm step, in the ``auto-merge`` job, and the
    ``disarm`` job's step (BACKLOG #5593), whose every ``gh pr merge`` call may only DISARM. A third
    ``gh pr merge`` step, or an arm call inside the disarm step, fails here, so neither role can
    hide behind the other."""
    merges = [s for s in _steps() if "gh pr merge" in " ".join(str(s.get("run", "")).split())]
    assert len(merges) == 2, f"expected exactly two gh pr merge steps, found {len(merges)}"
    disarm = _step("disarm")
    assert disarm in merges, "the disarm step no longer runs gh pr merge"
    assert disarm["run"] == _DISARM_BODY, "the disarm body changed; re-read it and edit the pin"
    assert _GH_PR_MERGE.findall(_DISARM_BODY) == ['gh pr merge --disable-auto "$PR_URL"']
    assert _merge_step() in _load()["jobs"]["auto-merge"]["steps"], "the arm step left the job"


def test_the_arming_job_runs_only_its_known_steps() -> None:
    """The job holding ``contents: write`` runs these steps and no others, and the one action it
    uses is fetch-metadata, so a NEW step, an unconditioned third-party arm action for one, cannot
    be added unread. What an existing step's body calls is not limited here."""
    steps = _load()["jobs"]["auto-merge"]["steps"]
    assert [s.get("id") for s in steps] == ["meta", "allowset", "ghsa", "age", "authors", None]
    uses = [str(s["uses"]) for s in steps if "uses" in s]
    assert len(uses) == 1 and uses[0].startswith("dependabot/fetch-metadata@"), uses


def test_the_merge_condition_evaluates_to_the_policy_over_every_input() -> None:
    cond = str(_merge_step().get("if", ""))
    assert cond, "the merge step has no if:, so it merges every Dependabot PR"
    # Five tri-state axes, four update types and three dependency types: 3**5 * 4 * 3. An empty
    # product would leave `wrong` empty and pass the absence assertion below on nothing.
    contexts = _merge_contexts()
    assert len(contexts) >= 2916, f"only {len(contexts)} merge contexts; expected 2916"
    wrong = [c for c in contexts if _evaluate_expression(cond, c) != _merge_policy(c)]
    assert not wrong, (
        f"the merge condition disagrees with the policy on {len(wrong)} input combinations; "
        f"first: {wrong[0]} (condition says {_evaluate_expression(cond, wrong[0])})"
    )


def test_the_expression_evaluator_can_tell_a_loosened_condition_apart() -> None:
    """The instrument check for the test above: each loosening the row names must disagree."""
    cond = str(_merge_step().get("if", ""))
    loosened = {
        "operator swapped": cond.replace(
            "steps.allowset.outputs.eligible == 'true' &&",
            "steps.allowset.outputs.eligible == 'true' ||",
            1,
        ),
        # `>-` keeps the newline before a more-indented line, so match any whitespace.
        "dev-only minor scoping dropped": re.sub(
            r"\s*&&\s*steps\.meta\.outputs\.dependency-type == 'direct:development'",
            "",
            cond,
            count=1,
        ),
        "equality inverted": cond.replace("advisory_ok == 'true'", "advisory_ok != 'true'", 1),
        "Dependabot-push gate dropped": re.sub(
            r"steps\.authors\.outputs\.sole_author == 'true'\s*&&\s*", "", cond, count=1
        ),
    }
    contexts = _merge_contexts()
    for label, variant in loosened.items():
        assert variant != cond, f"the {label} mutation no longer applies to the condition text"
        assert any(_evaluate_expression(variant, c) != _merge_policy(c) for c in contexts), (
            f"the evaluator could not tell the {label} condition from the policy"
        )


def test_the_job_runs_only_for_dependabot_authored_prs() -> None:
    job = _load()["jobs"]["auto-merge"]
    cond = str(job.get("if", ""))
    assert cond, "the auto-merge job has no if:, so it runs for every pull request"
    for login, expected in (("dependabot[bot]", True), ("someone", False), ("", False)):
        got = _evaluate_expression(cond, {"github.event.pull_request.user.login": login})
        assert got is expected, f"job if: {cond!r} gives {got} for author {login!r}"


def test_the_merge_step_squashes_the_triggering_pr_and_nothing_else() -> None:
    """The arm body is the pinned text and nothing else: its one arm call is a head-pinned squash
    of the triggering PR. The env holds only the PR, the evaluated head and the token."""
    merge = _merge_step()
    assert merge["run"] == _ARM_BODY, "the arm body changed; re-read it and edit the pin"
    assert _GH_PR_MERGE.findall(_ARM_BODY) == [
        'gh pr merge --auto --squash --match-head-commit "$HEAD_SHA" "$PR_URL"'
    ]
    env = merge.get("env") or {}
    assert env == {
        "PR_URL": "${{ github.event.pull_request.html_url }}",
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
    }, env


def test_the_token_permissions_are_exactly_what_each_job_needs() -> None:
    """Nothing at workflow level, and each job names its own set: the arming job the three it needs,
    the disarm job (BACKLOG #5593) no write to contents. A job this map does not name fails, so a new
    job cannot inherit or declare a grant unread."""
    doc = _load()
    assert doc.get("permissions") == {}, doc.get("permissions")
    expected = {
        "auto-merge": {"contents": "write", "pull-requests": "write", "security-events": "read"},
        "disarm": {"contents": "read", "pull-requests": "write"},
    }
    got = {name: job.get("permissions") for name, job in doc["jobs"].items()}
    assert got == expected, got


#: ``gh`` as a command word, anywhere in the body, comments included. ``gh`` reads ``GH_TOKEN``
#: without the body ever naming it, so the ``$VAR`` check below cannot see that key go missing. It
#: over-matches on purpose: a step that only mentions gh must still declare the token, which costs
#: one env line, where an under-match would let a real call run without it.
_GH_CALL = re.compile(r"(?<![\w./$-])gh(?![\w./-])")


def _step_label(step: dict) -> str:
    return str(step.get("id") or step.get("name"))


def _assert_inputs_come_through_env(label: str, step: dict) -> None:
    body = str(step.get("run", ""))
    assert "${{" not in body, (
        f"the {label} step interpolates an Actions expression into its shell body; pass it "
        f"through env: instead"
    )
    declared = set((step.get("env") or {}).keys())
    undeclared = set(_ENV_REF.findall(body)) - _RUNNER_PROVIDED - declared
    assert not undeclared, f"{label} reads undeclared env var(s): {sorted(undeclared)}"
    if _GH_CALL.search(body):
        assert "GH_TOKEN" in declared, f"{label} calls gh but declares no GH_TOKEN in env:"


def test_every_run_step_takes_every_input_through_env_not_interpolation() -> None:
    """Every ``run:`` step must read its inputs from ``env:``, never from an inlined ``${{ }}``.

    This is zizmor template-injection parity asserted in-tree — a PR-controlled value pasted into a
    shell body is a code-execution seam — and it is simultaneously the precondition that lets the
    behavioural tests below execute the shipped bodies verbatim.

    RULE (BACKLOG #5503): this iterated a hand-kept list of step ids that left out ``ghsa`` and the
    unnamed merge step, so an interpolation into either body, or a dropped env key there, would have
    passed. The steps are now every ``run:`` step in every job, with a floor naming the ones known
    today so a broken walk cannot pass on nothing.
    """
    run_steps = [s for s in _steps() if "run" in s]
    labelled = {_step_label(s): s for s in run_steps}
    assert len(labelled) == len(run_steps), f"two run steps share a label: {list(labelled)}"
    expected = {"disarm", "allowset", "ghsa", "age", "authors", _step_label(_merge_step())}
    missing = sorted(expected - set(labelled))
    assert not missing, f"run steps {list(labelled)} miss {missing}"
    for label, step in labelled.items():
        _assert_inputs_come_through_env(label, step)


@pytest.mark.parametrize(
    ("body", "env", "message"),
    [
        ('echo "${{ github.event.pull_request.title }}"\n', {}, "interpolates"),
        ('echo "$DEPS_JSON"\n', {"GH_TOKEN": "t"}, "undeclared env var"),
        ("gh api -X GET /advisories\n", {}, "declares no GH_TOKEN"),
        ('gh pr merge --auto "$PR_URL"\n', {"PR_URL": "u"}, "declares no GH_TOKEN"),
        ('gh -R o/r pr merge --auto "$PR_URL"\n', {"PR_URL": "u"}, "declares no GH_TOKEN"),
        ("gh release view v1\n", {}, "declares no GH_TOKEN"),
        ("gh \\\n  api /x\n", {}, "declares no GH_TOKEN"),
        ('n="${#X}"; echo "PR #1" && gh pr view 1\n', {"X": "x"}, "declares no GH_TOKEN"),
        ('"gh" api /x\n', {}, "declares no GH_TOKEN"),
        ("out=$(gh)\n", {}, "declares no GH_TOKEN"),
    ],
)
def test_the_env_check_refuses_each_planted_seam(body: str, env: dict, message: str) -> None:
    """Prove the per-step check fires on each defect the ghsa and merge steps could carry."""
    with pytest.raises(AssertionError, match=message):
        _assert_inputs_come_through_env("planted", {"run": body, "env": env})


@pytest.mark.parametrize("body", ["echo high\n", "./bin/gh-check\n", 'echo "$SIGH"\n'])
def test_the_gh_token_check_does_not_fire_without_a_gh_command(body: str) -> None:
    _assert_inputs_come_through_env("plain", {"run": body, "env": {"SIGH": "s"}})


# --------------------------------------------------------------------------------------------------
# Structural: the upstream cooldown configuration
# --------------------------------------------------------------------------------------------------


def test_cooldown_aging_window_lengthened() -> None:
    """Posture-review step 3: the uv-ecosystem routine cooldown is widened to >= 5 days."""
    doc = _load_dependabot()
    uv = next(u for u in doc["updates"] if u["package-ecosystem"] == "uv")
    assert uv["cooldown"]["default-days"] >= 5


def test_every_configured_ecosystem_has_a_cooldown() -> None:
    """EVERY configured ecosystem must be cooldown-aged, not just uv.

    The sibling test above asserts uv alone, which is precisely why a missing ``cooldown`` on
    ``github-actions`` — the ecosystem whose artifacts execute INSIDE CI — was invisible to CI. This
    is the test that would have caught it."""
    doc = _load_dependabot()
    updates = doc["updates"]
    scanned = [u["package-ecosystem"] for u in updates]
    print(f"ecosystems scanned for a cooldown: {scanned}")
    # Liveness: a pass must mean "checked all of them", never "found none to check".
    assert len(updates) >= 3, (
        f"only {len(updates)} update entries found ({scanned}) — the dependabot.yml walk is probably "
        f"broken, which would make the per-ecosystem assertion below vacuous"
    )
    for entry in updates:
        eco = entry["package-ecosystem"]
        assert "cooldown" in entry, f"ecosystem '{eco}' has no cooldown — a fresh release is unaged"
        days = entry["cooldown"].get("default-days")
        assert isinstance(days, int) and days >= 1, (
            f"ecosystem '{eco}' has a non-positive/absent cooldown default-days: {days!r}"
        )


def test_ci_executing_ecosystem_is_aged_at_least_five_days() -> None:
    """``github-actions`` specifically must age >= 5 days: unlike a Python distribution, a bumped
    action executes INSIDE CI holding whatever token the job carries, so a fresh malicious release is
    an immediate code-execution primitive rather than a dependency to be imported later."""
    doc = _load_dependabot()
    actions = next(u for u in doc["updates"] if u["package-ecosystem"] == "github-actions")
    assert actions["cooldown"]["default-days"] >= 5


# --------------------------------------------------------------------------------------------------
# Behavioural: execute the shipped shell
# --------------------------------------------------------------------------------------------------


# No bash skipif (BACKLOG #1216): _run_step_body resolves via require_bash, which fails LOUDLY
# when no bash can see this process's files rather than skipping on a which() miss.
@pytest.mark.parametrize(
    ("ecosystem", "names", "expected"),
    [
        # The two eligible rows are what make this test non-vacuous: an always-false implementation
        # (or an empty github-actions allow row) FAILS here rather than passing everything else.
        ("github_actions", "actions/checkout", "true"),
        ("github_actions", "actions/checkout,github/codeql-action/init", "true"),
        # Measured PR #75: a five-bump batch carrying a third-party action holds the WHOLE group.
        ("github_actions", "actions/checkout,pypa/gh-action-pypi-publish", "false"),
        # Anchored prefix, not substring: neither of these is actions/.
        ("github_actions", "actionsx/foo", "false"),
        ("github_actions", "evil/actions/checkout", "false"),
        # An empty name list cannot confirm eligibility.
        ("github_actions", "", "false"),
        # uv/npm allow rows ship empty, so every bump on them holds.
        ("uv", "certifi", "false"),
        ("uv", "cryptography", "false"),
        ("npm_and_yarn", "@types/node", "false"),
        ("pip", "requests", "false"),
        # An unrecognised (here: empty) ecosystem token must fall to the hold arm.
        ("", "actions/checkout", "false"),
    ],
)
def test_allowset_holds_everything_not_named(
    ecosystem: str, names: str, expected: str, tmp_path: Path
) -> None:
    """Execute the shipped allow-set body and check what it actually decides."""
    run = _run_step_body(
        "allowset",
        {"DEP_NAMES": names, "DEP_ECOSYSTEM": ecosystem},
        tmp_path,
    )
    assert run.rc == 0, (
        f"the allowset body aborted under `bash -e` (rc={run.rc}) — CI would fail the step"
        f"{_diagnostic(run)}"
    )
    assert run.outputs.get("eligible") == expected, (
        f"ecosystem={ecosystem!r} names={names!r} -> eligible={run.outputs.get('eligible')!r}, "
        f"expected {expected!r}"
    )


# No bash skipif (BACKLOG #1216): _run_step_body resolves via require_bash, which fails LOUDLY
# when no bash can see this process's files rather than skipping on a which() miss.
@pytest.mark.parametrize(
    ("security_track", "ecosystem"),
    [
        # Version track: aged upstream by dependabot.yml's cooldown, so this gate emits false and the
        # merge condition simply does not require it.
        ("false", "uv"),
        ("", "uv"),
        # Security track on an ecosystem with no publish-date source wired.
        ("true", "github_actions"),
        ("true", "npm_and_yarn"),
        ("true", ""),
    ],
)
def test_release_age_holds_the_version_track_and_undatable_ecosystems(
    security_track: str, ecosystem: str, tmp_path: Path
) -> None:
    """The two cheapest fail-closed guards, exercised WITHOUT jq or network.

    Every row here must emit ``age_ok=false``. On its own that is not self-certifying — an
    unconditionally-false step would also pass — so the discriminating ``true`` case is supplied by
    ``test_release_age_passes_an_aged_release_and_holds_a_fresh_one`` below. These two tests are a
    pair; this one runs everywhere, that one needs jq."""
    run = _run_step_body(
        "age",
        {
            "SECURITY_TRACK": security_track,
            "DEP_ECOSYSTEM": ecosystem,
            "DEPS_JSON": '[{"dependencyName":"requests","newVersion":"2.32.3"}]',
        },
        tmp_path,
    )
    assert run.rc == 0, (
        f"the age body aborted under `bash -e` (rc={run.rc}) — CI would fail the step"
        f"{_diagnostic(run)}"
    )
    assert run.outputs.get("age_ok") == "false", (
        f"security_track={security_track!r} ecosystem={ecosystem!r} -> "
        f"age_ok={run.outputs.get('age_ok')!r}, expected 'false'"
        f"{_diagnostic(run)}"
    )


def _gh_stub(tmp_path: Path, count: str | None) -> Path:
    """A ``gh`` on PATH that ignores its arguments.

    ``count=None`` reproduces an HTTP error the way the real client does, and that split is the
    whole point: **``gh api`` writes the JSON error BODY to stdout** and only its ``gh: ... (HTTP
    nnn)`` line to stderr. A stub that merely exits non-zero would pass against the defective code
    and prove nothing — the defect was that the body reached the variable.
    """
    stub_dir = tmp_path / "ghstub"
    stub_dir.mkdir()
    stub = stub_dir / "gh"
    if count is None:
        stub.write_text(
            "#!/usr/bin/env bash\n"
            'echo \'{"message":"API rate limit exceeded","status":"403"}\'\n'
            "echo 'gh: API rate limit exceeded (HTTP 403)' >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
    else:
        stub.write_text(f"#!/usr/bin/env bash\necho '{count}'\n", encoding="utf-8")
    stub.chmod(0o755)
    return stub_dir


@pytest.mark.skipif(
    shutil.which("jq") is None,  # bash via require_bash (BACKLOG #1216)
    reason="needs bash + jq, same runner matrix as the release-age rows below",
)
@pytest.mark.parametrize(
    ("label", "count", "expected"),
    [
        # The discriminating PASS — without it the suite would be satisfied by a step that denies
        # unconditionally, which is the failure mode a fail-closed guard degrades into.
        ("one published advisory", "1", "true"),
        ("no advisory covers the version", "0", "false"),
        # THE REGRESSION ROW. This is the one that was red before the fix: `gh` exits non-zero with
        # a JSON error body on STDOUT, `$(cmd || echo ERR)` APPENDED the sentinel to that body, and
        # the resulting value was neither "ERR" nor empty. The equality sentinel missed, the numeric
        # comparison failed with "integer expression expected" and returned 2, an `if` condition is
        # exempt from `set -e`, and the step printed "advisory confirmed" and emitted
        # advisory_ok=true while exiting 0. The guard inverted to FAIL-OPEN on exactly the
        # rate-limit/API-error class its own header promises routes to manual review.
        ("advisory API errors (rate limit)", None, "false"),
    ],
)
def test_the_advisory_guard_fails_closed_when_the_api_errors(
    label: str, count: str | None, expected: str, tmp_path: Path
) -> None:
    """Guardrail #2 EXECUTED, not string-matched.

    The sibling assertion ``"advisory_ok=false" in body`` cannot distinguish a guard that fails
    closed from one that merely contains the words — the fail-open above lived underneath a passing
    version of exactly that check. Asserting on the emitted OUTPUT is what makes the difference
    visible.
    """
    run = _run_step_body(
        "ghsa",
        {
            "DEP_GROUP": "pip-security",
            "DEPS_JSON": '[{"dependencyName":"requests","prevVersion":"2.19.0"}]',
            "GH_TOKEN": "stub",
        },
        tmp_path,
        path_prepend=_gh_stub(tmp_path, count),
    )
    assert run.rc == 0, (
        f"the ghsa body aborted under `bash -e` (rc={run.rc}) — CI would fail the step"
        f"{_diagnostic(run)}"
    )
    assert run.outputs.get("security_track") == "true", (
        "the fixture should select the security track"
    )
    assert run.outputs.get("advisory_ok") == expected, (
        f"{label} -> advisory_ok={run.outputs.get('advisory_ok')!r}, expected {expected!r}"
        f"{_diagnostic(run)}"
    )


def _curl_journal(tmp_path: Path) -> Path:
    """Where the curl stub records THAT IT RAN, and with what arguments (BACKLOG #1312).

    Deliberately OUTSIDE the stub directory. ``_assert_stubs_win`` probes ``command -v`` for every
    file it finds in the directory it is handed, so a journal sitting beside the stub would be asked
    to resolve as a command, come back ``MISSING-curl.calls``, and be reported as a bypass.
    """
    return tmp_path / "curl.calls"


def _curl_stub(tmp_path: Path, payload: str | None) -> Path:
    """A ``curl`` on PATH that ignores its arguments and RECORDS THAT IT WAS ASKED.

    ``payload=None`` makes it fail like a network or HTTP error would (``--fail`` exits non-zero),
    which must route to manual review.

    **The journal line is BACKLOG #1312's fix.** Prepending this directory to PATH is not the same
    as the step body consulting it, and when it does not, the body reaches pypi.org -- where the
    pinned fixture package genuinely IS old, so the aged row gets back the answer the fixture wanted
    and its assertion passes having measured the package index. The stub therefore writes its own
    argv where the caller can require it, so a verdict can be refused unless this record says the
    fixture is where the answer came from.
    """
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    stub = stub_dir / "curl"
    # The journal write comes FIRST in both arms, so the failing arm still proves it was consulted.
    record = "printf '%s\\n' \"$*\" >> '" + _curl_journal(tmp_path).as_posix() + "'\n"
    answer = "exit 1\n" if payload is None else f"cat <<'JSON'\n{payload}\nJSON\n"
    stub.write_text("#!/usr/bin/env bash\n" + record + answer, encoding="utf-8")
    stub.chmod(0o755)
    return stub_dir


def _assert_the_fixture_answered(tmp_path: Path, run: StepRun, url_fragment: str) -> None:
    """The stub RAN, and ran for the package the fixture names (BACKLOG #1312).

    Without this the aged row is satisfied by a step that never opened the fixture at all: it emits
    ``age_ok=true`` off pypi.org, because the pinned package really is old. That is a fact about the
    package index and not about the guardrail, and **an assertion that cannot fail for the reason it
    names is not a control.**

    Refusing a verdict is the point. A test that renders no verdict when its fixture was bypassed is
    strictly better than one that renders the right verdict for the wrong reason, because the first
    gets investigated.
    """
    journal = _curl_journal(tmp_path)
    calls = journal.read_text(encoding="utf-8").splitlines() if journal.exists() else []
    assert calls, (
        "THE CURL STUB WAS NEVER INVOKED, so whatever answered this step is not the fixture -- on a "
        f"runner, that is live pypi.org. Nothing was recorded at {journal}. Do not read the age_ok "
        f"assertion below as a statement about the guardrail.{_diagnostic(run)}"
    )
    assert any(url_fragment in line for line in calls), (
        f"the stub ran but was never asked for {url_fragment!r}, so the answer the step used did "
        f"not come from this fixture. Recorded calls: {calls}{_diagnostic(run)}"
    )


#: The step prints the age it computed twice over -- as a ``::notice::`` when the release passes the
#: minimum and as a ``::warning::`` when it does not -- so one pattern covers both dated rows.
_AGE_IN_STEP_OUTPUT = re.compile(r"was published (\d+)h ago|is (\d+)h old")


def _fixture_age_hours(payload: str | None) -> int | None:
    """The age the step must compute from ``payload``, or None when the fixture dates nothing.

    Derived FROM the payload rather than passed in beside it, so the expected age and the fixture
    cannot drift apart. ``min()`` mirrors the step's own ``sort | .[0]``.
    """
    if payload is None:
        return None
    stamps = re.findall(r'"upload_time_iso_8601"\s*:\s*"([^"]+)"', payload)
    if not stamps:
        return None
    when = dt.datetime.strptime(min(stamps), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.UTC)
    return int((dt.datetime.now(dt.UTC) - when).total_seconds() // 3600)


def _assert_the_age_is_the_fixtures(run: StepRun, payload: str | None) -> None:
    """The age the step COMPUTED matches the fixture's own timestamp (BACKLOG #1312).

    The second half of the same question, and the half no PATH probe can answer. ``command -v``
    reports which binary the shell WOULD choose; this reports whose CLOCK the verdict actually came
    off. A proxy, a cache, a wrapper, or anything else that answers in the stub's place is caught
    here even when resolution looks correct.
    """
    expected = _fixture_age_hours(payload)
    if expected is None:
        return
    found = _AGE_IN_STEP_OUTPUT.search(run.stdout)
    assert found is not None, (
        f"the step printed no age at all, so there is nothing to hold against the fixture's "
        f"{expected}h{_diagnostic(run)}"
    )
    reported = int(found.group(1) or found.group(2))
    # An hour of slack, because `_iso()` stamps the payload at COLLECTION time while the step
    # divides by 3600 at RUN time -- a slow or xdist-sharded run legitimately reads one hour older.
    assert abs(reported - expected) <= 1, (
        f"the step computed {reported}h but the fixture says {expected}h, so the timestamp it used "
        f"came from somewhere else -- on a runner, live pypi.org{_diagnostic(run)}"
    )


def _iso(hours_ago: float) -> str:
    when = dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@pytest.mark.skipif(
    shutil.which("jq") is None,  # bash via require_bash (BACKLOG #1216)
    reason="needs bash + jq. It runs WHEREVER both exist — the ubuntu leg AND the two REQUIRED "
    "windows-2022/windows-2025 legs, whose runner images ship jq and Git Bash — and skips on the "
    "maintainer's box, where Git Bash carries no jq. A red here is therefore not necessarily a "
    "ubuntu-only red",
)
@pytest.mark.parametrize(
    ("label", "payload", "expected"),
    [
        # The discriminating PASS — without this row the whole release-age suite would be satisfied
        # by a step that denies unconditionally. It discriminates ONLY while the answer provably
        # came from the fixture: `requests==2.32.3` is genuinely old on pypi.org, so a bypassed stub
        # returns `true` here too and the row goes green about the package index (BACKLOG #1312).
        # `_assert_the_fixture_answered` and `_assert_the_age_is_the_fixtures` below are what make
        # the reason as testable as the verdict.
        ("aged 30 days", f'{{"urls":[{{"upload_time_iso_8601":"{_iso(24 * 30)}"}}]}}', "true"),
        ("published 1 hour ago", f'{{"urls":[{{"upload_time_iso_8601":"{_iso(1)}"}}]}}', "false"),
        ("no dateable artifact", '{"urls":[]}', "false"),
        ("PyPI error", None, "false"),
    ],
    # `ids` IS REQUIRED HERE, and not for readability. `_iso()` calls `datetime.now()` at COLLECTION
    # time, so without this the timestamp lands inside the generated test ID and the ID changes on
    # every collection. Under pytest-xdist each worker collects in its OWN process, microseconds
    # apart, so the workers disagree about what the test is called and xdist aborts the whole run
    # with "Different tests were collected between gw0 and gw1" — measured, not theorised. Pinning
    # the ids to the stable `label` keeps the dates relative to now (which is the behaviour under
    # test) while making the NAME reproducible. Any future row whose parameters are derived from the
    # clock, a uuid, or a random value needs the same treatment.
    ids=["aged 30 days", "published 1 hour ago", "no dateable artifact", "PyPI error"],
)
def test_release_age_passes_an_aged_release_and_holds_a_fresh_one(
    label: str, payload: str | None, expected: str, tmp_path: Path
) -> None:
    """The security-track happy path and its three failure modes, against a stubbed PyPI.

    **THE PROVENANCE CHECKS RUN BEFORE THE VERDICT, and the order is the fix (BACKLOG #1312).** A
    row whose fixture was bypassed has nothing to say about the guardrail, so it must refuse to
    report a boolean rather than report one that happens to be right. The `rc` check stays first
    because an aborted body is a harness finding and would leave the journal empty for a reason that
    has nothing to do with PATH.
    """
    run = _run_step_body(
        "age",
        {
            "SECURITY_TRACK": "true",
            "DEP_ECOSYSTEM": "uv",
            "DEPS_JSON": '[{"dependencyName":"requests","newVersion":"2.32.3"}]',
        },
        tmp_path,
        path_prepend=_curl_stub(tmp_path, payload),
    )
    assert run.rc == 0, (
        f"the age body aborted under `bash -e` (rc={run.rc}) — CI would fail the step"
        f"{_diagnostic(run)}"
    )
    _assert_the_fixture_answered(tmp_path, run, "requests/2.32.3/json")
    _assert_the_age_is_the_fixtures(run, payload)
    assert run.outputs.get("age_ok") == expected, (
        f"{label} -> age_ok={run.outputs.get('age_ok')!r}, expected {expected!r}{_diagnostic(run)}"
    )


@pytest.mark.skipif(
    shutil.which("jq") is None,  # bash via require_bash (BACKLOG #1216)
    reason="needs bash + jq, the same runner matrix as the release-age rows above",
)
def test_a_bypassed_curl_stub_is_refused_rather_than_passed_off_the_network(tmp_path: Path) -> None:
    """THE NEGATIVE CONTROL FOR THE ROW ABOVE (BACKLOG #1312), and it reaches no network.

    A guard nobody has watched fail is a guard nobody has tested. This drives the bypass on purpose
    and requires both provenance checks to go red on a run the pre-existing assertion calls green --
    which is the whole of #1312 made executable.

    **The decoy answers the way pypi.org answers**: far older than the fixture's 30 days, because
    ``requests==2.32.3`` really was published long ago. That is what makes the boolean useless here.
    Both the honest fixture and the impostor produce ``age_ok=true``, so ``expected`` cannot separate
    them and only the provenance can.

    **PATH is passed through ``env`` rather than ``path_prepend``, on purpose.** ``path_prepend``
    would run ``_assert_stubs_win``, and the state being reproduced is the one where that probe is
    NOT what fails: it resolves in its own child process, and this asserts about the process that
    actually rendered the verdict. This reproduces the OBSERVABLE -- a fixture that was not consulted
    while the row still read ``true`` -- and makes no claim about which interpreter a runner picks,
    which the item states cannot be measured off the runner.
    """
    aged = f'{{"urls":[{{"upload_time_iso_8601":"{_iso(24 * 30)}"}}]}}'
    fixture_dir = _curl_stub(tmp_path, aged)

    decoy_dir = tmp_path / "decoy"
    decoy_dir.mkdir()
    decoy = decoy_dir / "curl"
    live_like = f'{{"urls":[{{"upload_time_iso_8601":"{_iso(24 * 460)}"}}]}}'
    decoy.write_text(f"#!/usr/bin/env bash\ncat <<'JSON'\n{live_like}\nJSON\n", encoding="utf-8")
    decoy.chmod(0o755)

    bash = require_bash(tmp_path)
    inherited = probe_env(Path(bash), dict(os.environ))["PATH"]
    inputs = {
        "SECURITY_TRACK": "true",
        "DEP_ECOSYSTEM": "uv",
        "DEPS_JSON": '[{"dependencyName":"requests","newVersion":"2.32.3"}]',
    }
    bypassed = _run_step_body(
        "age",
        {
            **inputs,
            "PATH": os.pathsep.join([decoy_dir.as_posix(), fixture_dir.as_posix(), inherited]),
        },
        tmp_path,
    )

    assert bypassed.rc == 0, (
        f"the age body aborted under `bash -e` (rc={bypassed.rc}), so this run says nothing about "
        f"provenance{_diagnostic(bypassed)}"
    )
    # THE FINDING, EXECUTABLE. The assertion that shipped before this item is fully satisfied by a
    # run that never opened the fixture. This line is the hollow pass.
    assert bypassed.outputs.get("age_ok") == "true", (
        "the bypass must still emit the verdict the aged row expects, or this is not the state "
        f"BACKLOG #1312 describes{_diagnostic(bypassed)}"
    )
    with pytest.raises(AssertionError, match="NEVER INVOKED"):
        _assert_the_fixture_answered(tmp_path, bypassed, "requests/2.32.3/json")
    with pytest.raises(AssertionError, match="came from somewhere else"):
        _assert_the_age_is_the_fixtures(bypassed, aged)

    # THE POSITIVE HALF, because a guard that raised for everything would satisfy the negative half
    # on its own -- the same pairing `test_the_stub_self_certification_fires_when_a_stub_loses`
    # makes. Same fixture, same journal, decoy gone.
    honest = _run_step_body("age", inputs, tmp_path, path_prepend=fixture_dir)
    assert honest.rc == 0, f"the age body aborted (rc={honest.rc}){_diagnostic(honest)}"
    _assert_the_fixture_answered(tmp_path, honest, "requests/2.32.3/json")
    _assert_the_age_is_the_fixtures(honest, aged)
    assert honest.outputs.get("age_ok") == "true", (
        f"the aged fixture must still pass when it IS consulted{_diagnostic(honest)}"
    )


def test_the_stub_self_certification_fires_when_a_stub_loses(tmp_path: Path) -> None:
    """EXERCISE THE GUARD ITSELF, because the rows that use it are jq-gated and skip on most boxes.

    MEASURED before this test existed: mutating ``_assert_stubs_win`` to raise unconditionally changed
    nothing in this module -- 27 passed, 7 skipped, identical. The guard was shipped UNREACHED here,
    which is the same defect it was written to catch, one layer up.

    The discriminating pair is free on Windows: Git's ``bin/bash.exe`` wrapper rewrites PATH so
    ``/mingw64/bin`` leads and Git ships ``curl.exe`` there, so the same stub directory WINS under the
    real shell and LOSES under the wrapper. Both halves are asserted -- a guard that raised for
    everything would satisfy the negative half alone.
    """
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    stub = stub_dir / "curl"
    stub.write_text("#!/bin/sh\necho STUB\n", encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{stub_dir.as_posix()}{os.pathsep}{env.get('PATH', '')}"

    good = require_bash(tmp_path)
    _assert_stubs_win(good, stub_dir, env)  # must not raise: the stub wins under the resolved bash

    wrapper = next(
        (
            c
            for c in bash_candidates()
            # `.exe` IS THE PLATFORM TEST, deliberately not sys.platform. The wrapper is
            # `bin/bash.exe` by construction, so the suffix identifies it without a second
            # condition the docstring does not name. MEASURED: without the suffix this matches
            # /bin/bash AND /usr/local/bin/bash on Linux -- parent `bin`, grandparent not
            # `usr` -- so the skip never fired and the test asserted that an ordinary Linux
            # bash rewrites PATH. The assertion was right and the SUBJECT was wrong.
            if (
                c.is_file()
                and c.suffix == ".exe"
                and c.parent.name == "bin"
                and c.parent.parent.name != "usr"
            )
        ),
        None,
    )
    if wrapper is None:
        pytest.skip("no Git-for-Windows bin/bash.exe wrapper here to lose against")
    if not (wrapper.parent.parent / "mingw64" / "bin" / "curl.exe").is_file():
        pytest.skip("this Git install ships no mingw64 curl, so the wrapper cannot shadow the stub")
    with pytest.raises(AssertionError, match="did NOT win"):
        _assert_stubs_win(str(wrapper), stub_dir, env)


# --------------------------------------------------------------------------------------------------
# BACKLOG #5593: disarm on a later push, and arm only on the head this run evaluated
# --------------------------------------------------------------------------------------------------


def test_merge_step_pins_the_evaluated_head() -> None:
    """The arm call must carry ``--match-head-commit`` bound to the event's head SHA.

    Without it GitHub arms auto-merge on whatever the head is when the call lands, which can be a
    commit pushed after the guardrails evaluated the earlier one.
    """
    merge = _merge_step()
    run = str(merge["run"])
    assert '--match-head-commit "$HEAD_SHA"' in run, f"the arm call is not head-pinned: {run!r}"
    assert "${{" not in run, "the merge body interpolates an Actions expression; pass it via env:"
    assert str((merge.get("env") or {}).get("HEAD_SHA", "")).replace(" ", "") == (
        "${{github.event.pull_request.head.sha}}"
    ), "HEAD_SHA must be the head the triggering event carried, the one this run evaluated"


def test_every_run_disarms_in_its_own_ungrouped_job_before_any_arm() -> None:
    """The disarm is its own job, in NO concurrency group, on every event the workflow takes, and the
    arming job needs it. GitHub keeps one pending entry per group and cancels the older pending one,
    so a disarm inside the group could be cancelled by a later run (a re-run of an `opened` run, say)
    and an arm on an earlier head would survive. Outside the group every run's disarm runs."""
    doc = _load()
    jobs = doc["jobs"]
    assert "concurrency" not in doc, "a workflow-level group would put the disarm job in it too"
    # Least privilege per job: the disarm job may not complete a merge.
    assert doc.get("permissions") == {}, doc.get("permissions")
    assert (jobs.get("disarm") or {}).get("permissions") == {
        "contents": "read",
        "pull-requests": "write",
    }
    disarm_job = jobs.get("disarm")
    assert disarm_job is not None, "no `disarm` job"
    assert "concurrency" not in disarm_job, "the disarm job must not be in a cancellable group"
    # Only the author gate: no event-action filter, so opened, synchronize and reopened all disarm.
    assert str(disarm_job.get("if", "")).replace(" ", "") == (
        "github.event.pull_request.user.login=='dependabot[bot]'"
    ), disarm_job.get("if")
    assert [s.get("id") for s in disarm_job["steps"]] == ["disarm"]
    arm_job = jobs["auto-merge"]
    needs = arm_job.get("needs")
    assert needs == "disarm" or needs == ["disarm"], (
        f"the arming job must need the disarm job: {needs!r}"
    )
    assert "group" in (arm_job.get("concurrency") or {}), "the arming job lost its per-PR group"
    assert not any(s.get("id") == "disarm" for s in arm_job["steps"]), (
        "a second disarm in the arm job"
    )
    disarm = _step("disarm")
    assert "if" not in disarm, f"the disarm step must not be skippable: {disarm.get('if')!r}"
    for owner in (disarm, disarm_job):
        assert "continue-on-error" not in owner, "a disarm failure must stop the arming job"
    body = str(disarm["run"])
    assert "${{" not in body
    assert "gh pr merge --disable-auto" in body
    declared = set((disarm.get("env") or {}).keys())
    undeclared = set(_ENV_REF.findall(body)) - _RUNNER_PROVIDED - declared
    assert not undeclared, f"disarm reads undeclared env var(s): {sorted(undeclared)}"
    assert "stale" not in _WORKFLOW.read_text(encoding="utf-8").split("jobs:", 1)[1], (
        "a stale guard is back; the ungrouped disarm job replaced it"
    )


def _gh_disarm_stub(tmp_path: Path) -> Path:
    """A ``gh`` that keeps the PR's auto-merge state in ``$GH_STATE`` and logs each call to ``$GH_LOG``.

    ``VIEW_FAIL=1`` makes ``pr view`` behave like an HTTP error (JSON body on stdout, non-zero exit),
    ``DISARM_FAIL=1`` makes ``pr merge --disable-auto`` exit non-zero, and ``DISARM_NOOP=1`` makes it
    exit 0 while leaving the state armed.
    """
    stub_dir = tmp_path / "ghstub"
    stub_dir.mkdir()
    stub = stub_dir / "gh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'echo "$*" >> "$GH_LOG"\n'
        'case "$1 $2" in\n'
        '  "pr view")\n'
        '    if [ "${VIEW_FAIL:-0}" = 1 ]; then echo \'{"message":"Bad credentials"}\'; exit 1; fi\n'
        '    cat "$GH_STATE" ;;\n'
        '  "pr merge")\n'
        '    if [ "${DISARM_FAIL:-0}" = 1 ]; then echo "gh: refused" >&2; exit 1; fi\n'
        '    if [ "${DISARM_NOOP:-0}" != 1 ]; then echo false > "$GH_STATE"; fi ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub_dir


@pytest.mark.parametrize(
    ("label", "armed", "extra", "rc", "disarm_called", "end_state"),
    [
        ("armed on an earlier head is disarmed", "true", {}, 0, True, "false"),
        ("not armed: nothing to do", "false", {}, 0, False, "false"),
        # The body reads no event or head, so these two races reduce to the same row: whatever run
        # executes it (a re-run of `opened` after an arm on the older head, or a run whose arming job
        # the group then cancels) leaves the PR disarmed.
        ("re-run of opened after an arm on the older head", "true", {}, 0, True, "false"),
        ("a run whose arming job is later cancelled", "true", {}, 0, True, "false"),
        # Unknown is not "not armed": it disarms anyway, and the read-back decides.
        ("state unreadable: disarms anyway", "true", {"VIEW_FAIL": "1"}, 1, True, "false"),
        ("a refused disarm fails closed", "true", {"DISARM_FAIL": "1"}, 1, True, "true"),
        ("a disarm that did not take", "true", {"DISARM_NOOP": "1"}, 1, True, "true"),
    ],
)
def test_disarm_step_behaviour(
    label: str,
    armed: str,
    extra: dict[str, str],
    rc: int,
    disarm_called: bool,
    end_state: str,
    tmp_path: Path,
) -> None:
    """The disarm body EXECUTED. A non-zero exit is the fail-closed outcome: Actions then skips every
    later step, the arm step included, so nothing re-arms on a head whose state is unknown."""
    state = tmp_path / "state"
    state.write_text(f"{armed}\n", encoding="utf-8")
    log = tmp_path / "gh.log"
    log.write_text("", encoding="utf-8")
    env = {
        "PR_URL": "https://github.com/example/example/pull/1",
        "GH_TOKEN": "stub",
        "GH_STATE": state.as_posix(),
        "GH_LOG": log.as_posix(),
        **extra,
    }
    run = _run_step_body("disarm", env, tmp_path, path_prepend=_gh_disarm_stub(tmp_path))
    assert run.rc == rc, f"{label}: rc={run.rc}, expected {rc}{_diagnostic(run)}"
    called = any("--disable-auto" in ln for ln in log.read_text(encoding="utf-8").splitlines())
    assert called is disarm_called, f"{label}: disarm called={called}{_diagnostic(run)}"
    assert state.read_text(encoding="utf-8").strip() == end_state, label


def _gh_rows_stub(tmp_path: Path, rows: str | None) -> Path:
    """A ``gh`` that prints ``rows`` (already the ``--jq`` result), or fails like an HTTP error."""
    stub_dir = tmp_path / "ghstub"
    stub_dir.mkdir()
    stub = stub_dir / "gh"
    if rows is None:
        body = '#!/usr/bin/env bash\necho \'{"message":"Not Found"}\'\nexit 1\n'
    else:
        (stub_dir / "rows.txt").write_text(rows, encoding="utf-8", newline="\n")
        body = '#!/usr/bin/env bash\ncat "$(dirname "$0")/rows.txt"\n'
    stub.write_text(body, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    return stub_dir


_BOT = "dependabot[bot]"
_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


_PASS = f"{_HEAD} true login=dependabot[bot]\n"


@pytest.mark.parametrize(
    ("label", "action", "sender", "rows", "expected"),
    [
        # The discriminating PASS: a Dependabot push of one verified Dependabot commit at the head.
        ("Dependabot pushed one Dependabot commit", "synchronize", _BOT, _PASS, "true"),
        # A human or the Lander pushed: the sender is that person, whatever the commits say.
        ("a human sender", "synchronize", "someone", _PASS, "false"),
        ("two commits", "synchronize", _BOT, _PASS + _PASS, "false"),
        (
            "a Dependabot sender, human-authored commit",
            "synchronize",
            _BOT,
            f"{_HEAD} true login=someone\n",
            "false",
        ),
        # An empty login is its own visible field, so it fails the whole-line test, not a shift.
        ("an author with no GitHub login", "synchronize", _BOT, f"{_HEAD} true login=\n", "false"),
        (
            "an unverified commit",
            "synchronize",
            _BOT,
            f"{_HEAD} false login=dependabot[bot]\n",
            "false",
        ),
        (
            "the commit is not the pinned head",
            "synchronize",
            _BOT,
            f"{'b' * 40} true login=dependabot[bot]\n",
            "false",
        ),
        # On reopen the sender is the reopener, which can be Dependabot after someone else's push.
        ("a reopen", "reopened", _BOT, _PASS, "false"),
        ("no commits", "synchronize", _BOT, "", "false"),
        ("the API errors", "synchronize", _BOT, None, "false"),
    ],
)
def test_authors_step_rearms_only_a_dependabot_push_of_one_dependabot_commit(
    label: str, action: str, sender: str, rows: str | None, expected: str, tmp_path: Path
) -> None:
    """fetch-metadata reads only the first commit, so re-arming needs the sender, the commit count
    and the single commit's author to all be Dependabot's."""
    run = _run_step_body(
        "authors",
        {
            "EVENT_ACTION": action,
            "SENDER": sender,
            "HEAD_SHA": _HEAD,
            "REPO": "example/example",
            "PR_NUMBER": "1",
            "GH_TOKEN": "stub",
        },
        tmp_path,
        path_prepend=_gh_rows_stub(tmp_path, rows),
    )
    assert run.rc == 0, f"{label}: rc={run.rc}{_diagnostic(run)}"
    assert run.outputs.get("sole_author") == expected, f"{label}{_diagnostic(run)}"
    if label == "an author with no GitHub login":
        assert "true login=', not" in run.stdout, f"failed for the wrong reason{_diagnostic(run)}"


def _gh_arm_stub(tmp_path: Path, arm_ok: bool, head: str | None) -> Path:
    stub_dir = tmp_path / "ghstub"
    stub_dir.mkdir()
    stub = stub_dir / "gh"
    view = "exit 1" if head is None else f"echo {head}"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$1 $2" in\n'
        f'  "pr merge") exit {0 if arm_ok else 1} ;;\n'
        f'  "pr view") {view} ;;\n'
        "esac\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(0o755)
    return stub_dir


_EVALUATED = "a" * 40


@pytest.mark.parametrize(
    ("label", "arm_ok", "head", "rc"),
    [
        ("armed", True, _EVALUATED, 0),
        ("refused because the head moved", False, "b" * 40, 0),
        ("refused on the evaluated head", False, _EVALUATED, 1),
        ("refused and the head is unreadable", False, None, 1),
        # A short hex read is not proof the head moved, so it must not pass green.
        ("refused and the head read is short", False, "abc", 1),
        ("refused and the head read is uppercase", False, "B" * 40, 1),
        ("refused and the head read is 41 characters", False, "b" * 41, 1),
        ("refused and the head read is garbled", False, "g" * 40, 1),
    ],
)
def test_merge_step_passes_only_a_head_moved_refusal(
    label: str, arm_ok: bool, head: str | None, rc: int, tmp_path: Path
) -> None:
    """The benign race (a push while this run evaluated) is not a red run; anything else is."""
    merge = _merge_step()
    bash = require_bash(tmp_path)
    script = tmp_path / "merge.sh"
    script.write_text(str(merge["run"]), encoding="utf-8", newline="\n")
    stub_dir = _gh_arm_stub(tmp_path, arm_ok, head)
    env = probe_env(Path(bash), dict(os.environ))
    env.update({"PR_URL": "https://github.com/example/example/pull/1", "HEAD_SHA": _EVALUATED})
    env["PATH"] = f"{stub_dir.as_posix()}{os.pathsep}{env.get('PATH', '')}"
    _assert_stubs_win(bash, stub_dir, env)
    proc = subprocess.run(
        [bash, "-e", script.as_posix()], capture_output=True, text=True, timeout=120, env=env
    )
    assert proc.returncode == rc, f"{label}: rc={proc.returncode}\n{proc.stdout}{proc.stderr}"
