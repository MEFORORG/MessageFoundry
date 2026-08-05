# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural AND behavioural regression tests for the Dependabot auto-merge guardrails (SEC-007).

Most of these assert the YAML wiring of ``.github/workflows/dependabot-auto-merge.yml``; the last
three go further and **execute the shipped ``run:`` bodies under ``bash -e``** — the shell GitHub
Actions applies by default on Linux — because the guardrails are shell logic and "the YAML names a
step" is a much weaker claim than "the step holds what it must hold". That is possible only because
both new steps take every input through ``env:`` and interpolate
nothing — asserted by ``test_new_steps_take_every_input_through_env_not_interpolation``, which is a
precondition for the behavioural tests as much as it is zizmor template-injection parity.

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

⚠️ #4 cannot change a merge decision as the workflow ships, and these tests do not pretend otherwise:
``age_ok=true`` is reachable only for uv/pip, ``eligible=true`` only for github-actions, and the merge
``if`` requires both — disjoint sets. It is tested as a FORWARD guard, so that populating a Python
allow row later is a one-line change to a control that already works, not a control to be written
under pressure. ``test_release_age_is_gated_on_the_allow_set`` pins the conjunction that makes this
true, so the day someone widens it, a test has to be edited deliberately.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

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


def _load() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def _steps() -> list[dict]:
    doc = _load()
    return doc["jobs"]["auto-merge"]["steps"]


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


def _run_step_body(
    step_id: str,
    env: dict[str, str],
    tmp_path: Path,
    path_prepend: Path | None = None,
) -> tuple[int, dict[str, str]]:
    """Run a step's shipped ``run:`` body under ``bash -e``; return ``(rc, $GITHUB_OUTPUT map)``.

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
    bash = shutil.which("bash")
    assert bash is not None  # narrowed by the caller's skipif; keeps mypy honest
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

    full_env = dict(os.environ)
    for key, value in (step.get("env") or {}).items():
        if "${{" not in str(value):
            full_env[str(key)] = str(value)
    full_env.update(env)
    full_env["GITHUB_OUTPUT"] = out_file.as_posix()
    if path_prepend is not None:
        full_env["PATH"] = f"{path_prepend.as_posix()}{os.pathsep}{full_env.get('PATH', '')}"

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
    return proc.returncode, parsed


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
    job = doc["jobs"]["auto-merge"]
    assert "defaults" not in job, "a job-level defaults: block can change the shell"
    for step in job["steps"]:
        assert "shell" not in step, (
            f"step {step.get('id') or step.get('name')!r} declares an explicit shell:, so the "
            f"behavioural tests no longer mirror what CI runs — update _run_step_body with it"
        )


def test_enable_automerge_gates_on_all_three_guards_and_preserves_auto_merge() -> None:
    """The merge step's ``if`` must require the allow-set guard AND the two security-track guards,
    while still invoking ``gh pr merge --auto`` for the eligible path."""
    steps = _steps()
    merge = next((s for s in steps if "gh pr merge --auto" in str(s.get("run", ""))), None)
    assert merge is not None, (
        "the gh pr merge --auto step was removed (auto-merge must be preserved)"
    )
    cond = str(merge.get("if", ""))
    assert "steps.allowset.outputs.eligible == 'true'" in cond, (
        "merge not gated on the allow-set guard"
    )
    # security-track PRs require a confirmed advisory AND an aged release; version-track patches
    # keep their cooldown-aged auto-merge unchanged
    assert "steps.ghsa.outputs.advisory_ok == 'true'" in cond
    assert "steps.ghsa.outputs.security_track != 'true'" in cond
    assert "steps.age.outputs.age_ok == 'true'" in cond, "merge not gated on the release-age guard"
    # the in-scope update-type gate is still present (any patch / dev-only minor)
    assert "version-update:semver-patch" in cond

    # A half-removal would leave the merge condition referencing a step id that no longer exists —
    # an Actions expression against a missing step evaluates to empty, silently dropping the guard.
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "steps.denylist" not in text, "dangling reference to the removed deny-list step"
    assert not any(s.get("id") == "denylist" for s in steps), "the deny-list step is still present"


def test_new_steps_take_every_input_through_env_not_interpolation() -> None:
    """Both new steps must read their inputs from ``env:``, never from an inlined ``${{ }}``.

    This is zizmor template-injection parity asserted in-tree — a PR-controlled value pasted into a
    shell body is a code-execution seam — and it is simultaneously the precondition that lets the
    behavioural tests below execute the shipped bodies verbatim."""
    for step_id in ("allowset", "age"):
        step = _step(step_id)
        body = str(step.get("run", ""))
        assert "${{" not in body, (
            f"the {step_id} step interpolates an Actions expression into its shell body; pass it "
            f"through env: instead"
        )
        declared = set((step.get("env") or {}).keys())
        referenced = set(_ENV_REF.findall(body)) - _RUNNER_PROVIDED
        undeclared = referenced - declared
        assert not undeclared, f"{step_id} reads undeclared env var(s): {sorted(undeclared)}"


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


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash to execute the run: body")
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
    rc, out = _run_step_body(
        "allowset",
        {"DEP_NAMES": names, "DEP_ECOSYSTEM": ecosystem},
        tmp_path,
    )
    assert rc == 0, f"the allowset body aborted under `bash -e` (rc={rc}) — CI would fail the step"
    assert out.get("eligible") == expected, (
        f"ecosystem={ecosystem!r} names={names!r} -> eligible={out.get('eligible')!r}, "
        f"expected {expected!r}"
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash to execute the run: body")
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
    rc, out = _run_step_body(
        "age",
        {
            "SECURITY_TRACK": security_track,
            "DEP_ECOSYSTEM": ecosystem,
            "DEPS_JSON": '[{"dependencyName":"requests","newVersion":"2.32.3"}]',
        },
        tmp_path,
    )
    assert rc == 0, f"the age body aborted under `bash -e` (rc={rc}) — CI would fail the step"
    assert out.get("age_ok") == "false", (
        f"security_track={security_track!r} ecosystem={ecosystem!r} -> "
        f"age_ok={out.get('age_ok')!r}, expected 'false'"
    )


def _curl_stub(tmp_path: Path, payload: str | None) -> Path:
    """A ``curl`` on PATH that ignores its arguments. ``payload=None`` makes it fail like a network
    or HTTP error would (``--fail`` exits non-zero), which must route to manual review."""
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    stub = stub_dir / "curl"
    if payload is None:
        stub.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
    else:
        stub.write_text(f"#!/usr/bin/env bash\ncat <<'JSON'\n{payload}\nJSON\n", encoding="utf-8")
    stub.chmod(0o755)
    return stub_dir


def _iso(hours_ago: float) -> str:
    when = dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="needs bash + jq. It runs WHEREVER both exist — the ubuntu leg AND the two REQUIRED "
    "windows-2022/windows-2025 legs, whose runner images ship jq and Git Bash — and skips on the "
    "maintainer's box, where Git Bash carries no jq. A red here is therefore not necessarily a "
    "ubuntu-only red",
)
@pytest.mark.parametrize(
    ("label", "payload", "expected"),
    [
        # The discriminating PASS — without this row the whole release-age suite would be satisfied
        # by a step that denies unconditionally.
        ("aged 30 days", f'{{"urls":[{{"upload_time_iso_8601":"{_iso(24 * 30)}"}}]}}', "true"),
        ("published 1 hour ago", f'{{"urls":[{{"upload_time_iso_8601":"{_iso(1)}"}}]}}', "false"),
        ("no dateable artifact", '{"urls":[]}', "false"),
        ("PyPI error", None, "false"),
    ],
)
def test_release_age_passes_an_aged_release_and_holds_a_fresh_one(
    label: str, payload: str | None, expected: str, tmp_path: Path
) -> None:
    """The security-track happy path and its three failure modes, against a stubbed PyPI."""
    rc, out = _run_step_body(
        "age",
        {
            "SECURITY_TRACK": "true",
            "DEP_ECOSYSTEM": "uv",
            "DEPS_JSON": '[{"dependencyName":"requests","newVersion":"2.32.3"}]',
        },
        tmp_path,
        path_prepend=_curl_stub(tmp_path, payload),
    )
    assert rc == 0, f"the age body aborted under `bash -e` (rc={rc}) — CI would fail the step"
    assert out.get("age_ok") == expected, (
        f"{label} -> age_ok={out.get('age_ok')!r}, expected {expected!r}"
    )
