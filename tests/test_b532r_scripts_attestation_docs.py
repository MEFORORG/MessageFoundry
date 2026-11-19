# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The deploy docs name the revocation attestation ConfigMap the k8s manifests require (BACKLOG #5400).

Both manifests read ``MEFOR_TLS_REVOCATION_ATTESTED`` from a required, non-optional ConfigMap
reference. A deployer following docs that never mention it would hit ``CreateContainerConfigError``
on the first apply, so each deploy doc a k8s deployer reads must name the ConfigMap and key the
manifests read, give the create command, and say that a false value still crash-loops there. The
compose one-shot check must also not inherit the image HEALTHCHECK, which probes an API it never
serves. No doc may claim, unqualified, that a false value is refused before any engine starts: at
least two compose commands skip the check, and no k8s manifest checks the value."""

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


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _check_comment() -> str:
    compose = (_REPO / "docker" / "compose.yaml").read_text(encoding="utf-8")
    start = compose.index("# One-shot check that the attestation reads as TRUE")
    words = compose[start : compose.index("revocation-attestation-check:", start)].split()
    return " ".join(w for w in words if w != "#")


def test_the_manifests_read_one_configmap() -> None:
    # Positive control: the doc test below is vacuous if no manifest reads a ConfigMap.
    assert len(_configmap_refs()) == 1


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_each_deploy_doc_names_the_required_configmap(doc: Path) -> None:
    text = _flat(doc)
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
    comment = _check_comment()
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


_SKIPS = (
    "at least `docker compose up --no-deps <engine>` and `docker compose run --no-deps` skip it"
)
_README = _REPO / "docker" / "README.md"
_CLOUD = _REPO / "docs" / "CLOUD-DEPLOYMENT.md"


@pytest.mark.parametrize("doc", (_CLOUD, _README), ids=lambda p: p.name)
def test_no_deploy_doc_carries_the_unqualified_refusal_claim(doc: Path) -> None:
    # The unqualified claims BACKLOG #5400 removed. Each matched the docs at 6bb34f135c4 (checked
    # by hand); the positive tests below pin the replacement wording, so this list only stops a
    # revert.
    text = _flat(doc)
    for stale in (
        "is refused by the `revocation-attestation-check` service before any engine starts",
        "`docker/compose.yaml` does, with its `revocation-attestation-check` service",
        "as `compose.yaml` does with its `revocation-attestation-check` service",
    ):
        assert stale not in text, f"{doc.name} still carries the unqualified claim: {stale}"


@pytest.mark.parametrize(
    ("doc", "anchor"),
    [
        (_CLOUD, "**Create the revocation attestation ConfigMap"),
        (_README, "**Both Kubernetes manifests need a ConfigMap you create:**"),
    ],
    ids=["CLOUD-DEPLOYMENT.md", "README.md"],
)
def test_each_k8s_section_says_no_manifest_checks_the_value(doc: Path, anchor: str) -> None:
    text = _flat(doc)
    start = text.index(anchor)
    section = text[start : start + 1500]
    assert "anifest checks the value before the engine starts." in section, section


def test_the_readme_topology_a_bullet_names_the_skips() -> None:
    # The sentence a compose user acts on, pinned inside the Topology A bullet so another
    # section's copy cannot satisfy it.
    text = _flat(_README)
    start = text.index("**(A) In-process TLS")
    bullet = text[start : text.index(" - **(B)", start)]
    assert (
        "`docker compose up` and `docker compose --profile ha up` run that check before they start"
        " any serving engine" in bullet
    ), bullet
    assert _SKIPS in bullet, bullet
    assert "Never start a serving engine with `--no-deps`" in bullet, bullet


def test_the_check_comment_opens_with_what_runs_it() -> None:
    comment = _check_comment()
    assert comment.startswith(
        "One-shot check that the attestation reads as TRUE. `up`, with or without the ha profile,"
        " runs it before it starts any serving engine; the commands that skip it are below."
    ), comment[:200]
