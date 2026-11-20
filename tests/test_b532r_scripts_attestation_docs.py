# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The deploy docs name the revocation attestation Secret key the k8s manifests require (BACKLOG #5400).

Both manifests read ``MEFOR_TLS_REVOCATION_ATTESTED`` from a required, non-optional Secret key
reference, exactly once per container. A deployer following docs that never mention it would hit
``CreateContainerConfigError`` on the first apply, so each deploy doc a k8s deployer reads must name
the key the manifests read and say that a false value still crash-loops there. The compose one-shot
check must also not inherit the image HEALTHCHECK, which probes an API it never serves. No doc may
claim, unqualified, that a false value is refused before any engine starts: at least two compose
commands skip the check, and no k8s manifest checks the value."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV

_REPO = Path(__file__).resolve().parents[1]
_K8S = _REPO / "docker" / "k8s"
_README = _REPO / "docker" / "README.md"
_CLOUD = _REPO / "docs" / "CLOUD-DEPLOYMENT.md"
_DOCS = (_CLOUD, _README, _K8S / "secret.example.yaml")


_SECRET = ("mefor-secrets", "tls-revocation-attested")


def _attestation_entries() -> list[tuple[str, str, list[dict[str, Any]]]]:
    """(manifest, container, env entries naming the attestation) for every container setting it."""
    found: list[tuple[str, str, list[dict[str, Any]]]] = []
    for path in sorted(_K8S.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            spec: dict[str, Any] = ((doc or {}).get("spec") or {}).get("template", {}).get(
                "spec"
            ) or {}
            for container in [*(spec.get("initContainers") or []), *(spec.get("containers") or [])]:
                entries = [
                    e
                    for e in container.get("env") or []
                    if e.get("name") == TLS_REVOCATION_ATTESTED_ENV
                ]
                if entries:
                    found.append((path.name, str(container.get("name")), entries))
    return found


def _flat(path: Path) -> str:
    # A bare "#" is a YAML comment marker, so a sentence wrapped across comment lines reads whole.
    return " ".join(w for w in path.read_text(encoding="utf-8").split() if w != "#")


def _check_comment() -> str:
    compose = (_REPO / "docker" / "compose.yaml").read_text(encoding="utf-8")
    start = compose.index("# One-shot check that the attestation reads as TRUE")
    words = compose[start : compose.index("revocation-attestation-check:", start)].split()
    return " ".join(w for w in words if w != "#")


def test_each_container_reads_the_attestation_once_from_the_secret() -> None:
    found = _attestation_entries()
    # Positive control: the doc tests below are vacuous if neither manifest wires the variable.
    assert {manifest for manifest, _, _ in found} == {"ha-postgres.yaml", "statefulset.yaml"}, found
    for manifest, container, entries in found:
        where = f"{manifest}/{container}"
        assert len(entries) == 1, f"{where} sets {TLS_REVOCATION_ATTESTED_ENV} {len(entries)} times"
        source = entries[0].get("valueFrom") or {}
        assert set(source) == {"secretKeyRef"}, f"{where}: not one Secret source: {source}"
        ref = source["secretKeyRef"]
        assert (ref.get("name"), ref.get("key")) == _SECRET, f"{where}: {ref}"
        assert ref.get("optional") is not True, f"{where}: the attestation must not be optional"


def _k8s_section(doc: Path) -> str:
    """The part of ``doc`` that tells a k8s deployer about the Secret key, bounded so that another
    section's copy of a sentence cannot satisfy a pin. secret.example.yaml is that part whole."""
    text = _flat(doc)
    if doc == _CLOUD:
        start = text.index("**Create the Secret**")
        return text[start : text.index(" 4. **Apply**", start)]
    if doc == _README:
        start = text.index("**Kubernetes (single-node):**")
        return text[start : text.index(" - **", start)]
    return text


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_each_deploy_doc_names_the_required_secret_key(doc: Path) -> None:
    section = _k8s_section(doc)
    assert _SECRET[1] in section, f"{doc.name} never names the Secret key {_SECRET[1]}"
    assert "CreateContainerConfigError" in section, doc.name
    assert "crash-loop" in section, f"{doc.name} does not say a false value still crash-loops"
    # The caveat itself, beside the key: a value such as 0 passes the kubelet.
    assert re.search(r"such as `?0`?,? passes the kubelet", section), (
        f"{doc.name} does not say a value such as 0 passes the kubelet"
    )


@pytest.mark.parametrize("doc", (_CLOUD, _README), ids=lambda p: p.name)
def test_each_deploy_doc_links_the_secret_example(doc: Path) -> None:
    # The create command lives in secret.example.yaml, so each doc must send the reader there.
    assert "k8s/secret.example.yaml" in _k8s_section(doc), doc.name


def test_the_secret_example_creates_the_key() -> None:
    text = _flat(_K8S / "secret.example.yaml")
    assert f"kubectl create secret generic {_SECRET[0]}" in text
    assert f"--from-literal={_SECRET[1]}=" in text
    assert f"name: {_SECRET[0]}" in text


@pytest.mark.parametrize(
    "path", (*_DOCS, *sorted(_K8S.glob("*.yaml"))), ids=lambda p: f"{p.parent.name}/{p.name}"
)
def test_no_deploy_file_names_the_retired_configmap(path: Path) -> None:
    # The attestation once came from a ConfigMap; a reverted merge must not tell deployers to
    # create one that no manifest reads.
    text = _flat(path)
    for stale in ("mefor-revocation-attestation", "configMapKeyRef", "kubectl create configmap"):
        assert stale not in text, f"{path.name} still names {stale}"


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


def test_the_changelog_claims_only_an_up_without_no_deps_and_names_the_skips() -> None:
    entry = _changelog_entry()
    headline = entry[: entry.index("**", len(_HEADLINE))]
    # The headline must not claim every `up`; `up --no-deps <engine>` skips the check.
    assert "stops a `docker compose up` run without `--no-deps`" in headline, headline
    assert "At least `docker compose up --no-deps <engine>` and `docker compose run --no-deps`" in (
        entry
    ), entry


_SKIPS = (
    "at least `docker compose up --no-deps <engine>` and `docker compose run --no-deps` skip it"
)


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


@pytest.mark.parametrize("doc", (_CLOUD, _README), ids=lambda p: p.name)
def test_each_k8s_section_says_no_manifest_checks_the_value(doc: Path) -> None:
    section = _k8s_section(doc)
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
        "One-shot check that the attestation reads as TRUE. An `up` without `--no-deps`, with or"
        " without the ha profile, runs it before it starts any serving engine; at least the commands"
        " listed below skip it."
    ), comment[:200]
