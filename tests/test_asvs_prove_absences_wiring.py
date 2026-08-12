# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pin the guarantees of .github/workflows/asvs-prove-absences.yml and scripts/asvs/prove_report.py.

`--prove-absences` shipped on 2026-08-07 and ran in no workflow in either repo until this wiring
landed. The wiring's own safety properties are strings in a YAML file plus policy in one script:
one edit can grant a write scope, turn the no-input path green, or make advisory the only behaviour,
and nothing else in the repo would notice. Same reason
`tests/test_quality_advisory_invariants.py` exists for its workflow.

Two claims are pinned here that are easy to state and easy to lose:

* **Advisory applies to FINDINGS, never to the INSTRUMENT.** A claim that will not prove is reported;
  a run that could not obtain a scorecard exits non-zero. If those two ever collapse into one
  outcome, a run that scanned nothing reads exactly like a clean record -- the failure mode the whole
  ASVS proving exercise exists to end.
* **Per-claim problem lines stay out of a public run log by default.** They name the cell and the
  control that would not prove, which is a ranked list of the weakest controls on the record.

The wiring's *behaviour* is proved by `prove_report.py selftest`, which drives nine limbs through
real prover subprocesses; `test_selftest_all_limbs_pass` runs it so the CI suite covers it too.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPO / ".github" / "workflows" / "asvs-prove-absences.yml"
_SCRIPT = _REPO / "scripts" / "asvs" / "prove_report.py"
_REQUIRED_CONTEXTS = _REPO / ".github" / "required-contexts.txt"


@pytest.fixture(scope="module")
def raw() -> str:
    return _WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow(raw: str) -> dict:
    # `on:` is the YAML 1.1 boolean `True` once parsed -- a well-known Actions/PyYAML collision.
    return yaml.safe_load(raw)


def test_the_workflow_exists_and_invokes_the_prover(raw: str) -> None:
    """The point of the whole exercise: something must actually run the mode.

    Falsified by deleting the invocation -- the mode returns to being wired to nothing, which is the
    state this file was written to end.
    """
    assert "prove_report.py run" in raw
    assert "prove_report.py selftest" in raw


def test_the_workflow_grants_no_permissions_by_default(workflow: dict) -> None:
    assert workflow["permissions"] == {}


def test_no_job_holds_any_write_scope(workflow: dict) -> None:
    for name, job in workflow["jobs"].items():
        perms = job.get("permissions", {})
        assert perms == {"contents": "read"}, f"job {name} holds {perms!r}, wanted contents: read"


def test_neither_job_is_a_required_context() -> None:
    """Advisory is only real if these contexts cannot gate a merge. Branch protection is server-side,
    so the checked-in claim is what is assertable from here."""
    declared = _REQUIRED_CONTEXTS.read_text(encoding="utf-8")
    for context in ("prove absence claims", "prove-absences wiring selftest"):
        assert context not in declared


def test_every_action_is_sha_pinned_with_a_version_comment(raw: str) -> None:
    uses = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("- uses:")]
    uses += [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("uses:")]
    assert uses, "no actions found -- the assertion below would pass vacuously"
    for line in uses:
        ref = line.split("uses:")[1].strip()
        assert "@" in ref, line
        sha = ref.split("@")[1].split()[0]
        assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha), line
        assert "#" in ref, f"{line} -- a bare SHA with no version comment is unreviewable"


def test_checkouts_do_not_persist_credentials(workflow: dict) -> None:
    """The vault checkout carries a read token for the vault, which is private. Persisting it into
    .git/config would leave it available to every later step in the job for no reason -- only the
    files are wanted."""
    found = 0
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "checkout" in str(step.get("uses", "")):
                found += 1
                assert step.get("with", {}).get("persist-credentials") is False, step
    assert found >= 3, f"expected at least 3 checkouts, saw {found}"


def test_the_vault_checkout_is_sparse_to_the_scorecard_alone(workflow: dict) -> None:
    """A vault-read credential in a public repo is a boundary cost taken deliberately and minimised.
    A cone-mode checkout, or a widened path, would materialise the maintainer-internal
    `docs/security` corpus on a runner whose logs are world-readable."""
    steps = [s for j in workflow["jobs"].values() for s in j["steps"]]
    vault = [s for s in steps if "vault" in str(s.get("with", {}).get("path", ""))]
    assert len(vault) == 1, "expected exactly one vault checkout"
    with_ = vault[0]["with"]
    assert with_["sparse-checkout"].strip() == "docs/security/asvs-scorecard.toml"
    assert with_["sparse-checkout-cone-mode"] is False


def test_strict_and_detail_are_variables_and_default_off(raw: str) -> None:
    """The ratchet and the disclosure control are both one repository variable, both unset, so the
    committed default is advisory-with-counts-only. Anything that hardcodes `--strict` or `--detail`
    into the run body takes the choice away from the owner."""
    assert "vars.ASVS_PROVE_STRICT" in raw
    assert "vars.ASVS_PROVE_DETAIL" in raw
    run_bodies = "\n".join(
        str(s.get("run", "")) for j in yaml.safe_load(raw)["jobs"].values() for s in j["steps"]
    )
    assert "flags+=(--strict)" in run_bodies
    assert "--strict --root" not in run_bodies and "--root . --strict" not in run_bodies


def test_no_expression_interpolation_inside_run_bodies(workflow: dict) -> None:
    """Workflow expressions are hoisted into `env:`, never expanded into a shell body -- the
    template-injection shape zizmor exists to catch. Same rule the vault's ASVS job states for its
    anchor SHA."""
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            assert "${{" not in str(step.get("run", "")), step.get("name")


def test_the_prove_job_is_dispatch_only(workflow: dict) -> None:
    """On a PR there is no credential, so the prove job would fail for a reason unrelated to the PR.
    The PR-time question is the wiring's, and `selftest` answers it without a secret.

    DISPATCH-ONLY as of the 2026-08-09 location decision: the scheduled pass runs in the vault, which
    is the only repo that can feed it. Both halves are asserted, and the second is the load-bearing
    one -- a `schedule` arm here would be red every day for a reason nobody can act on from this
    repository, which is how a gate gets switched off.
    """
    gate = workflow["jobs"]["prove"]["if"]
    assert "workflow_dispatch" in gate
    assert "schedule" not in gate
    assert "pull_request" not in gate


def test_the_workflow_has_no_schedule_trigger(raw: str) -> None:
    """The decision is a property of the TRIGGER, not only of the job gate, and the two can drift
    apart: a cron could be re-added above while the job's `if:` still excludes it (a workflow that
    runs nightly to do nothing), or the `if:` widened while no cron exists. Assert the trigger
    directly so neither half can move alone.
    """
    parsed = yaml.safe_load(raw)
    on = parsed[True] if True in parsed else parsed["on"]
    assert "schedule" not in on, (
        "the scheduled prove pass lives in the vault -- a cron here is red every day by construction"
    )
    assert "workflow_dispatch" in on


def test_the_prove_job_depends_on_the_selftest(workflow: dict) -> None:
    """A report from wiring that was never proved able to go red is a decoration."""
    assert workflow["jobs"]["prove"]["needs"] == "selftest"


def test_the_workflow_triggers_on_changes_to_itself(raw: str) -> None:
    """A gate excluded from its own trigger cannot observe changes to itself -- written up at length
    on the vault's asvs-scorecard.yml after a broken gate merged green."""
    parsed = yaml.safe_load(raw)
    on = parsed[True] if True in parsed else parsed["on"]
    for event in ("pull_request", "push"):
        paths = on[event]["paths"]
        assert ".github/workflows/asvs-prove-absences.yml" in paths
        assert "scripts/asvs/**" in paths


# --- the policy claims, asserted against the script rather than the YAML --------------------------


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )


def test_a_missing_scorecard_is_an_instrument_failure_not_a_pass(tmp_path: Path) -> None:
    """The no-input limb, which is the state this repo is in TODAY and will stay in until the
    credential question is answered. Exit 2, never 0.

    Falsified by returning EXIT_OK from that branch: the assertion below goes red, and a daily run
    that obtained nothing would report success. Confirmed by injection.
    """
    proc = _run("run", "--scorecard", str(tmp_path / "absent.toml"), "--root", str(tmp_path))
    assert proc.returncode == 2, proc.stderr
    assert "scanned nothing" in proc.stderr


def test_selftest_all_limbs_pass() -> None:
    """Run the nine-limb harness in the suite so a regression in the wiring surfaces on any PR, not
    only on the workflow's own paths filter."""
    proc = _run("selftest")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ALL LIMBS PASS" in proc.stdout
    # Naming the limbs here, not just the verdict: a harness that silently stopped running six of
    # them would still print ALL LIMBS PASS.
    for limb in ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"):
        assert f"[PASS] {limb}" in proc.stdout, f"{limb} did not run"
    assert proc.stdout.count("[PASS]") == 9, proc.stdout
