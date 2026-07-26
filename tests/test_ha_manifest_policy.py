# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural policy tests for the active-passive HA k8s manifest (ADR 0047, DEPLOY-26).

These parse ``docker/k8s/ha-postgres.yaml`` with PyYAML and assert the ADR 0047 AC-4/AC-5
invariants purely in Python — a drift guard that stands INDEPENDENT of the path-filtered,
non-required ``.github/workflows/manifest-lint.yml`` grep leg (which also handles the
network-bound kubeconform schema step that cannot run off-CI):

  AC-4 (continuous failover) — the Deployment carries ``replicas: 3`` and a
    PodDisruptionBudget with ``maxUnavailable: 1`` selecting the HA app, and the pod spec's
    ``terminationGracePeriodSeconds`` is STRICTLY GREATER than the LIVE
    ``ClusterSettings().leader_lease_ttl_seconds`` default (imported, not a hardcoded 30) so a
    drained leader releases its lease before SIGKILL even if the code default changes.
  AC-5 (never autoscale, never L7) — no HorizontalPodAutoscaler and no Ingress doc is present.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from messagefoundry.config.settings import ClusterSettings

_MANIFEST = Path(__file__).resolve().parent.parent / "docker" / "k8s" / "ha-postgres.yaml"
_HA_APP = "mefor-engine-ha"


def _docs() -> list[dict]:
    """Every non-empty document in the multi-doc manifest."""
    return [d for d in yaml.safe_load_all(_MANIFEST.read_text(encoding="utf-8")) if d]


def _one(kind: str) -> dict:
    matches = [d for d in _docs() if d.get("kind") == kind]
    assert len(matches) == 1, f"expected exactly one {kind}, found {len(matches)}"
    return matches[0]


def test_manifest_parses_as_multidoc_yaml() -> None:
    docs = _docs()
    assert docs, "manifest yielded no YAML documents"
    kinds = {d.get("kind") for d in docs}
    assert {"Deployment", "PodDisruptionBudget"} <= kinds


def test_deployment_replicas_is_three() -> None:
    # ADR 0047 AC-4: 1 leader + 2 warm standbys. NOT scaled by an HPA.
    assert _one("Deployment")["spec"]["replicas"] == 3


def test_pdb_max_unavailable_one_selecting_ha_app() -> None:
    # ADR 0047 AC-4: a voluntary disruption may take at most ONE replica at a time.
    pdb = _one("PodDisruptionBudget")
    assert pdb["spec"]["maxUnavailable"] == 1
    assert pdb["spec"]["selector"]["matchLabels"]["app"] == _HA_APP


def test_grace_period_strictly_exceeds_live_lease_ttl_default() -> None:
    # ADR 0047 AC-4: a drained leader must release/expire its lease BEFORE SIGKILL, so
    # terminationGracePeriodSeconds must stay > leader_lease_ttl_seconds. Read the ceiling from
    # the LIVE code default (import, not a literal 30) so the manifest cannot silently drift below
    # whatever that default becomes.
    ttl = ClusterSettings().leader_lease_ttl_seconds
    grace = _one("Deployment")["spec"]["template"]["spec"]["terminationGracePeriodSeconds"]
    assert grace > ttl, f"grace {grace}s must exceed leader_lease_ttl {ttl}s"


def test_no_horizontal_pod_autoscaler() -> None:
    # ADR 0047 AC-5: HA replicas are for FAILOVER, not load-spreading — never an HPA.
    assert not [d for d in _docs() if d.get("kind") == "HorizontalPodAutoscaler"]


def test_no_ingress() -> None:
    # ADR 0047 AC-5: MLLP is L4/NLB only — never behind an L7/HTTP ingress.
    assert not [d for d in _docs() if d.get("kind") == "Ingress"]


@pytest.mark.parametrize("kind", ["Deployment", "PodDisruptionBudget"])
def test_ha_objects_carry_the_ha_app_label(kind: str) -> None:
    assert _one(kind)["metadata"]["name"] == _HA_APP
