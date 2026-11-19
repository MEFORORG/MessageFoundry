# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The deploy docs name the revocation attestation ConfigMap the k8s manifests require (BACKLOG #5400).

Both manifests read ``MEFOR_TLS_REVOCATION_ATTESTED`` from a required, non-optional ConfigMap
reference. A deployer following docs that never mention it would hit ``CreateContainerConfigError``
on the first apply, so each deploy doc a k8s deployer reads must name the ConfigMap and key the
manifests read, give the create command, and say that a false value still crash-loops there. The
compose one-shot check must also not inherit the image HEALTHCHECK, which probes an API it never
serves."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV

_REPO = Path(__file__).resolve().parents[1]
_K8S = _REPO / "docker" / "k8s"
_DOCS = (
    _REPO / "docs" / "CLOUD-DEPLOYMENT.md",
    _REPO / "docker" / "README.md",
    _K8S / "secret.example.yaml",
)


def _configmap_refs() -> set[tuple[str, str]]:
    """Every (name, key) ConfigMap reference that feeds the attestation in a k8s manifest."""
    refs: set[tuple[str, str]] = set()
    for path in sorted(_K8S.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            spec: dict[str, Any] = ((doc or {}).get("spec") or {}).get("template", {}).get(
                "spec"
            ) or {}
            for container in spec.get("containers") or []:
                for entry in container.get("env") or []:
                    if entry.get("name") != TLS_REVOCATION_ATTESTED_ENV:
                        continue
                    ref = (entry.get("valueFrom") or {}).get("configMapKeyRef") or {}
                    if ref:
                        refs.add((str(ref["name"]), str(ref["key"])))
    return refs


def test_the_manifests_read_one_configmap() -> None:
    # Positive control: the doc test below is vacuous if no manifest reads a ConfigMap.
    assert len(_configmap_refs()) == 1


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_each_deploy_doc_names_the_required_configmap(doc: Path) -> None:
    text = " ".join(doc.read_text(encoding="utf-8").split())
    for name, key in _configmap_refs():
        assert name in text, f"{doc.name} never names the ConfigMap {name}"
        assert f"kubectl create configmap {name} --from-literal={key}=1" in text, (
            f"{doc.name} does not give the create command for {name}/{key}"
        )
    assert "CreateContainerConfigError" in text
    assert "crash-loop" in text, f"{doc.name} does not say a false value still crash-loops"


def test_the_compose_check_disables_the_image_healthcheck() -> None:
    compose = yaml.safe_load((_REPO / "docker" / "compose.yaml").read_text(encoding="utf-8"))
    check = compose["services"]["revocation-attestation-check"]
    assert check.get("healthcheck") == {"disable": True}
