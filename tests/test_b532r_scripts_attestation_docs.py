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


_HEADLINE = "**A revocation attestation that does not read as true"


def _changelog_entry() -> str:
    """The #5400 compose entry, wherever it lives: its fragment until a release folds it, then
    CHANGELOG.md. No fragment path is named, because the fold deletes the file."""
    sources = [*sorted((_REPO / "changelog.d").glob("*.md")), _REPO / "CHANGELOG.md"]
    for path in sources:
        if not path.is_file():
            continue
        text = " ".join(path.read_text(encoding="utf-8").split())
        at = text.find(_HEADLINE)
        if at >= 0:
            # The entry ends at the next bullet or heading, so a neighbour's text cannot pass.
            ends = [e for e in (text.find(m, at + 1) for m in (" - **", " ## ", " ### ")) if e >= 0]
            return text[at : min(ends, default=len(text))]
    raise AssertionError("no changelog entry starts with " + _HEADLINE)


def test_the_check_comment_names_both_no_deps_skips() -> None:
    # `up --no-deps <engine>` skips the check as `run --no-deps` does, and would start a serving
    # engine that restarts forever on a false value, so the check's own comment must name both.
    compose = (_REPO / "docker" / "compose.yaml").read_text(encoding="utf-8")
    start = compose.index("# One-shot check that the attestation reads as TRUE")
    words = compose[start : compose.index("revocation-attestation-check:", start)].split()
    comment = " ".join(w for w in words if w != "#")
    assert "`docker compose run --no-deps`" in comment
    assert "`docker compose up --no-deps <engine>`" in comment
    # "At least", not a count: a third skip found later must not turn this red.
    assert "At least" in comment


def test_the_changelog_claims_only_a_default_up_and_names_the_skips() -> None:
    entry = _changelog_entry()
    headline = entry[: entry.index("**", len(_HEADLINE))]
    # The headline must not claim every `up`; `up --no-deps <engine>` skips the check.
    assert "stops a default `docker compose up`" in headline, headline
    assert "At least `docker compose up --no-deps <engine>` and `docker compose run --no-deps`" in (
        entry
    ), entry


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _check_comment() -> str:
    compose = (_REPO / "docker" / "compose.yaml").read_text(encoding="utf-8")
    start = compose.index("# One-shot check that the attestation reads as TRUE")
    words = compose[start : compose.index("revocation-attestation-check:", start)].split()
    return " ".join(w for w in words if w != "#")


_SKIPS = (
    "at least `docker compose up --no-deps <engine>` and `docker compose run --no-deps` skip it"
)
# The unqualified claims BACKLOG #5400 removed: each said a false value is refused before any
# engine starts, which at least the two `--no-deps` commands and every k8s manifest contradict.
_STALE = (
    "is refused by the `revocation-attestation-check` service before any engine starts",
    "`docker/compose.yaml` does, with its `revocation-attestation-check` service",
    "as `compose.yaml` does with its `revocation-attestation-check` service",
)


@pytest.mark.parametrize("doc", _DOCS[:2], ids=lambda p: p.name)
def test_no_deploy_doc_carries_the_unqualified_refusal_claim(doc: Path) -> None:
    text = _flat(doc)
    for stale in _STALE:
        assert stale not in text, f"{doc.name} still carries the unqualified claim: {stale}"


def test_cloud_deployment_says_no_manifest_checks_the_value() -> None:
    text = _flat(_REPO / "docs" / "CLOUD-DEPLOYMENT.md")
    assert "Neither Kubernetes manifest checks the value before the engine starts." in text


def test_the_readme_k8s_bullet_points_at_the_compose_comment() -> None:
    text = _flat(_REPO / "docker" / "README.md")
    start = text.index("**Both Kubernetes manifests need a ConfigMap you create:**")
    bullet = text[start : text.index(" - **", start + 1)]
    assert "neither manifest checks the value before the engine starts" in bullet, bullet
    assert "says which compose commands skip it" in bullet, bullet


def test_the_readme_topology_a_bullet_names_the_skips() -> None:
    # The sentence a compose user acts on: pinned inside the Topology A bullet, so another
    # section's copy cannot satisfy it.
    text = _flat(_REPO / "docker" / "README.md")
    start = text.index("**(A) In-process TLS")
    bullet = text[start : text.index(" - **(B)", start)]
    assert "stops `docker compose up`, with or without `--profile ha`, at the" in bullet, bullet
    assert _SKIPS in bullet, bullet


def test_the_check_comment_opens_with_a_default_up() -> None:
    comment = _check_comment()
    assert comment.startswith(
        "One-shot check that the attestation reads as TRUE, run by a default `up` before it starts"
        " any serving engine; at least two commands skip it"
    ), comment[:200]
