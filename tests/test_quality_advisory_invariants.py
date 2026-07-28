"""Pin the advisory guarantees of .github/workflows/quality-advisory.yml.

Every safety property of that workflow is a string in a YAML file: one edit can grant a write
scope, drop an `--exit-zero`, or add a SARIF upload, and nothing else in the repo would notice.
This repo already parses workflow YAML in tests for exactly that reason (see
test_dependabot_automerge_guardrails.py, test_release_pipeline.py, test_lint_scope_parity.py).

What actually keeps these jobs advisory is that their contexts are not in the required-checks set on
`main`, and that every analysis step is non-failing (`continue-on-error` + `--exit-zero` /
`--fail-under=0` / `|| true`). Only the second half is assertable from inside the repo, so that is
what test_every_analysis_step_cannot_fail_its_job pins.

The no-write-scope assertion is a separate, narrower claim: least privilege. It does NOT by itself
prevent merge gating -- permissions and branch protection are unrelated mechanisms -- but it is
worth pinning because two of these jobs execute third-party code fetched at run time, and it is
only holdable because the jobs surface findings via workflow commands rather than SARIF upload.
"""

import re
from pathlib import Path

import pytest
import yaml

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "quality-advisory.yml"

# Steps that actually run a quality tool. Setup steps (checkout, setup-python, apt-get, the tool
# installs) are deliberately NOT required to be continue-on-error: masking an infrastructure failure
# would produce confusing downstream errors, and a red ADVISORY job blocks nothing anyway -- these
# contexts are not in the required-checks set.
_ANALYSIS_MARKERS = (
    "ruff check",
    "npx --yes jscpd",
    "diff-cover coverage.xml",
    "mutmut run",
    "mutmut results",
    "c901_delta.py",
    "pytest -q --cov",
)

# An analysis command must be incapable of failing its step.
_NON_FAILING_IDIOMS = ("--exit-zero", "--fail-under=0", "|| true")

_SHA_PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def workflow() -> dict:
    assert _WORKFLOW.is_file(), f"workflow not found at {_WORKFLOW}"
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def raw() -> str:
    return _WORKFLOW.read_text(encoding="utf-8")


def _strip_comments(text: str) -> str:
    """Drop YAML comments.

    The header deliberately EXPLAINS why there is no SARIF upload, so a naive substring search for
    "sarif" matches the very comment that documents its absence. Assert against code instead.
    """
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split(" #", 1)[0] if " #" in line else line)
    return "\n".join(out)


@pytest.fixture(scope="module")
def code(raw: str) -> str:
    return _strip_comments(raw)


def _steps(workflow: dict) -> list[tuple[str, dict]]:
    return [(name, step) for name, job in workflow["jobs"].items() for step in job["steps"]]


def _analysis_steps(workflow: dict) -> list[tuple[str, dict]]:
    return [
        (job, step)
        for job, step in _steps(workflow)
        if any(marker in (step.get("run") or "") for marker in _ANALYSIS_MARKERS)
    ]


# --------------------------------------------------------------------------------------------
# The advisory guarantee.
# --------------------------------------------------------------------------------------------


def test_workflow_grants_no_permissions_by_default(workflow: dict) -> None:
    assert workflow["permissions"] == {}, "workflow-level permissions must stay deny-by-default"


def test_no_job_holds_any_write_scope(workflow: dict) -> None:
    """Least privilege. Both the clone and complexity jobs execute third-party code fetched at run
    time (`npx --yes jscpd`, `pipx install ruff`) with no integrity pin, so handing them a
    write-scoped repository token would be a real regression. This does NOT by itself stop the jobs
    gating a merge -- see the module docstring -- it just keeps their blast radius at zero."""
    for name, job in workflow["jobs"].items():
        permissions = job.get("permissions")
        assert permissions is not None, f"job {name!r} must declare explicit permissions"
        for scope, level in permissions.items():
            assert level == "read", f"job {name!r} grants {scope}: {level} -- must be read"


def test_no_sarif_upload_and_no_security_events(code: str) -> None:
    """Measured, not stylistic: all 122 C901 findings anchor on a single `def` line, jscpd emits one
    scan-order location per clone pair, and a PR-only upload never builds a baseline -- so every PR
    would report every finding as new, forever. See the workflow header for the full reasoning
    (which is why this asserts against comment-stripped code, not the raw text)."""
    assert "sarif" not in code.lower(), (
        "no SARIF surface in this workflow -- see the header comment"
    )
    assert "security-events" not in code


def test_no_pull_request_target(raw: str) -> None:
    """pull_request_target grants a read/write token even from a public fork."""
    assert "pull_request_target" not in raw


def test_every_analysis_step_cannot_fail_its_job(workflow: dict) -> None:
    steps = _analysis_steps(workflow)
    assert len(steps) >= 6, f"expected the quality tool steps to be found, got {len(steps)}"
    for job, step in steps:
        name = step.get("name", "<unnamed>")
        assert step.get("continue-on-error") is True, (
            f"{job}/{name!r} runs a quality tool without continue-on-error: true"
        )
        body = step["run"]
        assert any(idiom in body for idiom in _NON_FAILING_IDIOMS), (
            f"{job}/{name!r} has no non-failing idiom ({_NON_FAILING_IDIOMS})"
        )


# --------------------------------------------------------------------------------------------
# Supply chain.
# --------------------------------------------------------------------------------------------


def test_every_action_is_sha_pinned_with_a_version_comment(workflow: dict, raw: str) -> None:
    uses = [step["uses"] for _, step in _steps(workflow) if "uses" in step]
    assert uses, "expected at least one action"
    for ref in uses:
        assert _SHA_PINNED.match(ref), f"{ref} is not pinned to a 40-hex SHA"
    for line in raw.splitlines():
        if "uses:" in line:
            assert re.search(r"#\s*v", line), f"missing version comment: {line.strip()}"


def test_jscpd_stays_on_4x(raw: str) -> None:
    """npm `latest` is a 5.x Rust rewrite shipped as platform binaries with a different CLI."""
    assert re.search(r"jscpd@4\.\d+\.\d+", raw), "jscpd must stay pinned to a 4.x release"


def test_diff_cover_is_pinned_exactly(raw: str) -> None:
    """The annotation surface depends on this version's `--format github-annotations:<level>`."""
    assert re.search(r'"diff-cover==\d+\.\d+\.\d+"', raw), "diff-cover must be pinned with =="


def test_the_ruff_version_is_derived_from_the_lock_not_hardcoded(workflow: dict, code: str) -> None:
    """The delta script parses ruff's human-readable C901 message, so a version skew can change the
    wording under the parser -- but the fix must NOT be a hardcoded pin asserted against the lock.

    This test file runs in the ordinary pytest suite, which IS a required check. Asserting equality
    between a workflow string and constraints.lock would mean a routine Dependabot ruff bump reds a
    BLOCKING context over a purely advisory concern. Deriving the version at run time removes the
    drift and the coupling at once, so assert the derivation instead of the value.
    """
    step = next(
        s
        for job, s in _steps(workflow)
        if job == "complexity" and "pipx install" in (s.get("run") or "")
    )
    body = step["run"]
    assert "constraints.lock" in body, (
        "the complexity job must read ruff's version from constraints.lock at run time"
    )
    assert not re.search(r"pipx install ruff==\d", code), (
        "do not hardcode the ruff version here -- it couples a required check to this workflow"
    )


# --------------------------------------------------------------------------------------------
# The surfacing mechanisms themselves.
# --------------------------------------------------------------------------------------------


def test_diff_coverage_emits_inline_github_annotations(code: str) -> None:
    assert "github-annotations:" in code, "diff-cover must emit inline annotations"


def test_the_complexity_delta_is_wired_and_pr_gated(workflow: dict) -> None:
    steps = [s for job, s in _steps(workflow) if "c901_delta.py" in (s.get("run") or "")]
    assert len(steps) == 1, "expected exactly one complexity delta step"
    assert steps[0].get("if") == "github.event_name == 'pull_request'", (
        "the delta needs a base ref; it must not run on the cron or workflow_dispatch"
    )
    assert "--summary-file" in steps[0]["run"]


def test_the_delta_script_exists(workflow: dict) -> None:
    script = _WORKFLOW.parents[2] / "scripts" / "quality" / "c901_delta.py"
    assert script.is_file(), "the complexity job references a script that is not in the repo"


def test_the_complexity_job_fetches_full_history(workflow: dict) -> None:
    """`git merge-base` cannot work against a shallow clone."""
    checkout = next(
        step
        for job, step in _steps(workflow)
        if job == "complexity" and "checkout" in (step.get("uses") or "")
    )
    assert checkout.get("with", {}).get("fetch-depth") == 0, (
        "the complexity job needs full history -- git merge-base cannot work on a shallow clone"
    )


def test_checkouts_do_not_persist_credentials(workflow: dict) -> None:
    """quality-advisory.yml is not in .github/zizmor.yml's artipacked ignore list."""
    for job, step in _steps(workflow):
        if "checkout" in (step.get("uses") or ""):
            assert step.get("with", {}).get("persist-credentials") is False, (
                f"{job} checkout must set persist-credentials: false"
            )


def test_the_coverage_job_does_not_reshallow_its_own_full_clone(code: str) -> None:
    """`fetch-depth: 0` then `git fetch --depth=1` writes .git/shallow and grafts away the history
    behind the base tip, so diff-cover's three-dot range loses its merge base the moment the base
    branch advances. It then fails in the worst way: the markdown reporter truncates diff-cover.md
    on open before raising, `|| true` swallows the error, and the summary shows a clean-looking
    empty section while zero annotations are emitted."""
    assert "--depth" not in code, "a shallow fetch here defeats diff-cover's merge base"


def test_report_guards_test_for_content_not_mere_existence(code: str) -> None:
    """diff-cover creates and truncates its report before it can fail, so `-f` passes on a 0-byte
    file and would append an empty section that reads as 'nothing uncovered'."""
    assert "[ -s diff-cover.md ]" in code
    assert "[ -f diff-cover.md ]" not in code


def test_step_summary_writes_are_size_guarded(code: str) -> None:
    """An oversized $GITHUB_STEP_SUMMARY write is dropped ENTIRELY, losing the whole surface.

    Asserts on the COUNT of truncation idioms rather than one magic constant: the blocks legitimately
    use different limits (a survivor list needs less room than a coverage report), and pinning the
    exact byte count made this fail on a change that was still correctly guarded.
    """
    appends = code.count('>> "$GITHUB_STEP_SUMMARY"')
    assert appends >= 3, f"expected the summary blocks to be present, found {appends}"
    truncations = code.count("head -c ") + code.count("tail -c ")
    assert truncations >= appends, (
        f"{appends} summary blocks but only {truncations} truncation guards -- an oversized write "
        "is dropped entirely, silently losing the whole surface"
    )


def test_mutmut_is_pinned_to_3x_with_pytest_timeout(code: str) -> None:
    """mutmut 2.5.1 crashes on Python 3.14 before generating a mutant, and `|| true` made that look
    green for months. pytest-timeout is not optional: mutmut 3 always passes `--timeout` to pytest,
    and without the plugin every invocation dies inside BadTestExecutionCommandsException."""
    assert re.search(r'"mutmut==3\.\d+\.\d+"', code), "mutmut must be pinned to an exact 3.x"
    assert "mutmut<3" not in code, "mutmut 2.x does not run on Python 3.14"
    assert "pytest-timeout" in code, "mutmut 3 requires pytest-timeout"


def test_mutmut_copies_the_package_not_just_the_mutated_file(code: str) -> None:
    """mutmut 3 copies `source_paths` into mutants/ and runs pytest there. With a single FILE as the
    source path, conftest.py cannot import the rest of the package and every mutant comes back
    'not checked' -- a green job measuring nothing. Copy the package, mutate one module."""
    # The config is emitted by `printf`, so the separators are literal backslash-n in the YAML.
    assert r"source_paths=messagefoundry\n" in code, (
        "source_paths must be the package, not one file"
    )
    assert "only_mutate=" in code, "the bounded scope must come from only_mutate"
    assert "paths_to_mutate" not in code, "deprecated in mutmut 3"
    assert "runner=" not in code, "mutmut 3 uses pytest_add_cli_args_test_selection"


def test_every_measurement_job_emits_a_liveness_receipt(workflow: dict) -> None:
    """A gate that reports a conclusion without recording that it measured anything is the exact
    failure this workflow produced three times. Every measurement job must own a receipt."""
    measurement_jobs = {"complexity", "clone", "coverage", "mutation"}
    for name in measurement_jobs:
        job = workflow["jobs"][name]
        assert (job.get("outputs") or {}).get("receipt"), (
            f"{name} exposes no liveness receipt output"
        )
        steps = [s for s in job["steps"] if s.get("id") == "receipt"]
        assert len(steps) == 1, f"{name} must have exactly one step with id: receipt"
        assert steps[0].get("if") == "always()", (
            f"{name}'s receipt step must run even when the analysis step failed -- otherwise a dead "
            "gate produces no receipt AND no explanation"
        )


def test_the_liveness_job_is_allowed_to_fail(workflow: dict) -> None:
    """Every other job here is built so it cannot fail. This one is built so it CAN -- that is the
    whole point. Adding continue-on-error would silently neuter it."""
    job = workflow["jobs"]["liveness"]
    assert job.get("if") == "always()", "liveness must rule even when a gate job died"
    assert set(job["needs"]) == {"complexity", "clone", "coverage", "mutation"}
    for step in job["steps"]:
        assert step.get("continue-on-error") is not True, (
            "the liveness step must be able to redden its job -- that is its only way to be loud"
        )
        body = step.get("run") or ""
        if "liveness.py" in body:
            assert "|| true" not in body, "swallowing the exit code defeats the entire check"


def test_the_mutation_other_count_is_not_a_remainder(code: str) -> None:
    """If `other` were computed as LISTED - SURVIVED - NOTESTS, the liveness reconciliation would be
    true by construction and could never fire -- an identity-confirmation check that only looks like
    a control. Counting each category independently is what keeps the sum meaningful."""
    assert re.search(r"OTHER=.*grep -cE", code), "other must be counted independently, not derived"
    assert "OTHER=$((LISTED" not in code, (
        "deriving other as a remainder makes the check tautological"
    )


def test_the_killed_count_is_derived_not_grepped(code: str) -> None:
    """`mutmut results` lists ONLY the mutants worth looking at (survived / no tests / timeout /
    suspicious). Killed mutants are never listed, so counting `': killed'` returns 0 on a perfectly
    healthy run -- which is exactly what shipped in #18: CI reported `killed=0 survived=19` for a run
    mutmut itself scored at 87 killed. Derive it from total-minus-listed instead.

    Verified against the real artifact from run 30308667584: 461 total - 374 listed = 87, matching
    mutmut's own counter.
    """
    assert "grep -c ': killed'" not in code, (
        "mutmut never lists killed mutants -- this grep always yields 0"
    )
    assert "TOTAL - LISTED" in code, "the killed count must be derived from the run total"


def test_mutmut_artifact_includes_hidden_files(workflow: dict) -> None:
    """.mutmut-cache is a dotfile and upload-artifact skips hidden files by default -- without this
    the step logs 'No files were found', uploads nothing, and still reports success."""
    upload = next(
        step for _, step in _steps(workflow) if "upload-artifact" in (step.get("uses") or "")
    )
    with_ = upload.get("with", {})
    assert with_.get("include-hidden-files") is True, (
        "the mutmut cache is a dotfile; without include-hidden-files this step uploads nothing "
        "and still reports success"
    )
    assert with_.get("if-no-files-found") == "warn"


def test_no_expression_interpolation_inside_run_bodies(workflow: dict) -> None:
    """Template injection: untrusted `${{ }}` expanded into a shell body. Values must be routed
    through `env:` instead (zizmor enforces this in CI; assert it here too)."""
    for job, step in _steps(workflow):
        body = step.get("run")
        if body:
            assert "${{" not in body, f"{job}/{step.get('name')!r} interpolates into a run body"
