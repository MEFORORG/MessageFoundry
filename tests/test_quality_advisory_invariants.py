"""Pin the advisory guarantees of .github/workflows/quality-advisory.yml.

Every safety property of that workflow is a string in a YAML file: one edit can grant a write
scope, drop an `--exit-zero`, or add a SARIF upload, and nothing else in the repo would notice.
This repo already parses workflow YAML in tests for exactly that reason (see
test_dependabot_automerge_guardrails.py, test_release_pipeline.py, test_lint_scope_parity.py).

The single strongest assertion here is that the workflow holds NO write permission on any job.
That -- not "it is absent from branch protection" -- is what makes it structurally incapable of
gating a merge, and it is only assertable because these jobs surface findings via workflow-command
annotations rather than by uploading SARIF to code scanning.
"""

import re
from pathlib import Path

import pytest
import yaml

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "quality-advisory.yml"

# Steps that actually run a quality tool. Setup steps (checkout, setup-python, apt-get, the tool
# installs) are deliberately NOT required to be continue-on-error: masking an infrastructure failure
# would produce confusing downstream errors, and the merge-blocking guarantee comes from the absent
# write scopes plus the workflow's absence from branch protection, not from those steps.
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
    """The load-bearing assertion. A write scope anywhere here is a merge-gating capability in
    disguise, and both the clone and complexity jobs execute third-party code fetched at run time
    (`npx --yes jscpd`, `pipx install ruff`) with no integrity pin -- handing those a write-scoped
    repository token would be a least-privilege regression."""
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


def test_ruff_pin_matches_the_lock(raw: str) -> None:
    """The delta script parses ruff's human-readable C901 message, so a version skew can change the
    wording under the parser. DEP-1 byte-diffs the exported locks and cannot see this one."""
    match = re.search(r"pipx install ruff==(\S+)", raw)
    assert match, "the complexity job must pin ruff"
    workflow_pin = match.group(1)

    lock = (_WORKFLOW.parents[2] / "constraints.lock").read_text(encoding="utf-8")
    locked = re.search(r"^ruff==(\S+?)(?:\s|$)", lock, re.MULTILINE)
    assert locked, "ruff not found in constraints.lock"
    assert workflow_pin == locked.group(1), (
        f"workflow pins ruff=={workflow_pin} but constraints.lock has {locked.group(1)}"
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


def test_step_summary_writes_are_size_guarded(raw: str) -> None:
    """An oversized $GITHUB_STEP_SUMMARY write is dropped ENTIRELY, losing the whole surface."""
    appends = raw.count('>> "$GITHUB_STEP_SUMMARY"')
    assert appends >= 3, f"expected the summary blocks to be present, found {appends}"
    assert raw.count("head -c 900000") >= 3, "each summary block must be truncated"


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
