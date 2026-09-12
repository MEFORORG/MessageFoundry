# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin where ``.github/workflows/net-helper.yml`` reads its code-signing secrets (BACKLOG #1537).

A secret read in a job that names no environment can only be a repository or organization secret, and
any branch can run its own copy of a workflow that reads one. The key is safe only in a job that names
the ``net-helper-signing`` environment, once a repository administrator restricts that environment's
deployment branches to ``main``. No test here can see that setting. These tests see the file, where one
honest edit could move a secret back into the build job, give the signing job a token scope, or let it
run for pull requests. Each test fails on one such edit.

They do not stop a hostile branch, which can edit this file too. The environment's branch rule does.
"""

from __future__ import annotations

from typing import Any

from tests._workflow_contexts import jobs_of

_WORKFLOW = "net-helper.yml"
_ENVIRONMENT = "net-helper-signing"
_ON_MAIN = "github.ref == 'refs/heads/main'"


def _reads_a_secret(node: Any) -> bool:
    # Parsed YAML carries no comments, so prose that mentions the secrets context cannot match.
    return "secrets." in repr(node)


def test_only_the_sign_job_reads_a_secret() -> None:
    readers = {key for key, job in jobs_of(_WORKFLOW).items() if _reads_a_secret(job)}
    assert readers == {"sign"}, (
        f"jobs reading a secret: {sorted(readers)}. A job with no environment can only read a "
        f"repository or organization secret, which any branch can read too."
    )


def test_the_sign_job_names_the_environment_and_runs_only_on_main() -> None:
    sign = jobs_of(_WORKFLOW)["sign"]
    assert sign.get("environment") == _ENVIRONMENT
    # Skipped rather than failed elsewhere: a job naming a branch-restricted environment on another ref
    # fails, which would turn every pull request touching the helper red.
    assert str(sign.get("if", "")).strip() == _ON_MAIN
    assert sign.get("needs") == "build"


def test_the_sign_job_holds_no_token_scope_and_checks_out_nothing() -> None:
    sign = jobs_of(_WORKFLOW)["sign"]
    assert sign.get("permissions") == {}
    uses = [str(step.get("uses", "")) for step in sign.get("steps", [])]
    assert uses, "the sign job has no steps, so the checkout assertion below would pass vacuously"
    assert not any(u.startswith("actions/checkout@") for u in uses), uses


def test_the_sign_step_keeps_its_own_ref_guard() -> None:
    steps = [s for s in jobs_of(_WORKFLOW)["sign"].get("steps", []) if s.get("id") == "sign"]
    assert len(steps) == 1, "expected exactly one step with id: sign"
    assert _ON_MAIN in str(steps[0].get("if", ""))


def test_the_build_job_names_no_environment() -> None:
    # Once the environment admits only main, naming it here would fail every pull request run.
    assert "environment" not in jobs_of(_WORKFLOW)["build"]
