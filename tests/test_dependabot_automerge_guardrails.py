# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural regression tests for the Dependabot auto-merge security-track guardrails (SEC-007).

These assert the YAML wiring of ``.github/workflows/dependabot-auto-merge.yml`` — the live GitHub
Actions run is the integration test. They close DEPENDENCY-POSTURE-REVIEW.md guardrails:
  #3 a DENY-LIST step keeps the auth/token/crypto stack off the auto-merge path (manual review), and
  #2 a published-GHSA step gates the cooldown-bypassing SECURITY track on a real advisory.
Both must be wired into the ``Enable auto-merge`` step's ``if`` so a denied/un-advisoried PR does NOT
auto-merge, while a non-sensitive patch still does (``gh pr merge --auto`` preserved).
"""

from __future__ import annotations

from pathlib import Path

import yaml

_WORKFLOW = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "dependabot-auto-merge.yml"
)

# Security-critical packages that must NEVER auto-merge, even for a patch (posture-review #3).
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
)


def _load() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def _steps() -> list[dict]:
    doc = _load()
    return doc["jobs"]["auto-merge"]["steps"]


def test_workflow_is_valid_yaml_and_has_the_automerge_job() -> None:
    doc = _load()
    assert "auto-merge" in doc["jobs"]


def test_denylist_step_names_every_security_critical_package() -> None:
    """Guardrail #3: the deny-list step body must hard-code each security-critical package."""
    steps = _steps()
    deny = next((s for s in steps if s.get("id") == "denylist"), None)
    assert deny is not None, "no deny-list step (id: denylist) found"
    body = deny.get("run", "")
    for pkg in _DENY_PACKAGES:
        assert pkg in body, f"deny-list missing security-critical package: {pkg}"
    # emits a guard output the merge step can require
    assert "deny=" in body and "$GITHUB_OUTPUT" in body


def test_ghsa_step_queries_the_advisory_api_and_emits_a_guard() -> None:
    """Guardrail #2: a security-track step must consult the advisory API and emit advisory_ok."""
    steps = _steps()
    ghsa = next((s for s in steps if s.get("id") == "ghsa"), None)
    assert ghsa is not None, "no published-GHSA step (id: ghsa) found"
    body = ghsa.get("run", "")
    # calls the GitHub advisories API (gh api ... /advisories)
    assert "gh api" in body and "/advisories" in body
    # produces the advisory guard output and a security-track discriminator
    assert "advisory_ok=" in body and "$GITHUB_OUTPUT" in body
    assert "security_track=" in body
    # fails CLOSED — an error/no-match must not fall through to auto-merge
    assert "advisory_ok=false" in body


def test_enable_automerge_gates_on_both_guards_and_preserves_auto_merge() -> None:
    """The merge step's ``if`` must require deny != 'true' AND the security-track advisory guard,
    while still invoking ``gh pr merge --auto`` for the non-sensitive path."""
    steps = _steps()
    merge = next((s for s in steps if "gh pr merge --auto" in s.get("run", "")), None)
    assert merge is not None, (
        "the gh pr merge --auto step was removed (auto-merge must be preserved)"
    )
    cond = merge.get("if", "")
    assert "steps.denylist.outputs.deny != 'true'" in cond, "merge not gated on the deny-list guard"
    # security-track PRs require a confirmed advisory; version-track patches stay unchanged
    assert "steps.ghsa.outputs.advisory_ok == 'true'" in cond
    assert "steps.ghsa.outputs.security_track != 'true'" in cond
    # the in-scope update-type gate is still present (any patch / dev-only minor)
    assert "version-update:semver-patch" in cond


def test_cooldown_aging_window_lengthened() -> None:
    """Posture-review step 3: the uv-ecosystem routine cooldown is widened to >= 5 days."""
    dependabot = Path(__file__).resolve().parent.parent / ".github" / "dependabot.yml"
    doc = yaml.safe_load(dependabot.read_text(encoding="utf-8"))
    uv = next(u for u in doc["updates"] if u["package-ecosystem"] == "uv")
    assert uv["cooldown"]["default-days"] >= 5
