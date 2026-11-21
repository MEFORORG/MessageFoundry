# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The k8s manifests refuse a false attestation before the engine starts, and the example Secret
starts nothing unedited (BACKLOG #5400 items 4 to 6).

Both manifests take ``MEFOR_TLS_REVOCATION_ATTESTED`` from a required Secret key, so the kubelet
refuses a missing key. A value the engine reads as false, such as ``0``, passed the kubelet and
crash-looped the engine at the revocation gate (item 4). Each manifest now runs a
``revocation-attestation-check`` initContainer, the command ``docker/compose.yaml``'s one-shot
service runs, in the engine's image, so the engine never starts on such a value (item 6).

``secret.example.yaml`` shipped placeholder strings for every key, so applying it unedited, with
the TLS files it leaves out added, created a Secret the kubelet accepted, and the engine started
and crash-looped on its placeholders (item 5). Its values now ship commented: an unedited apply
creates a Secret holding no key a manifest reads, and the kubelet refuses the pod.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV
from tests.test_compose_revocation_attestation import _all_services
from tests.test_k8s_enforce_start_inputs import _pod_spec

_DOCKER = Path(__file__).resolve().parents[1] / "docker"
_K8S = _DOCKER / "k8s"
_MANIFESTS = ("ha-postgres.yaml", "statefulset.yaml")
_CHECK = "revocation-attestation-check"
_SECRET = "mefor-secrets"


_pod = functools.cache(_pod_spec)


def _init(name: str) -> dict[str, Any]:
    found = [c for c in _pod(name).get("initContainers") or [] if c["name"] == _CHECK]
    assert len(found) == 1, f"{name}: expected one {_CHECK} initContainer, found {len(found)}"
    return found[0]


def _compose_check_argv() -> list[str]:
    return [str(a) for a in _all_services()[_CHECK]["entrypoint"]]


# --- items 4 and 6: the initContainer --------------------------------------------------------------


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_check_runs_first_in_the_engines_image(name: str) -> None:
    pod = _pod(name)
    inits = pod.get("initContainers") or []
    assert inits and inits[0]["name"] == _CHECK, f"{name}: {_CHECK} is not the first initContainer"
    [engine] = [c for c in pod["containers"] if c["name"] == "engine"]
    # Another image would read the value with another version's parser.
    assert _init(name)["image"] == engine["image"], name


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_check_reads_the_required_secret_key(name: str) -> None:
    entries = [e for e in _init(name).get("env") or [] if e["name"] == TLS_REVOCATION_ATTESTED_ENV]
    assert len(entries) == 1, f"{name}: {_CHECK} does not read {TLS_REVOCATION_ATTESTED_ENV}"
    ref = entries[0]["valueFrom"]["secretKeyRef"]
    assert (ref["name"], ref["key"]) == (_SECRET, "tls-revocation-attested"), name
    assert ref.get("optional") is not True, name


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_check_is_the_compose_command(name: str) -> None:
    # One command for both, so tests/test_compose_revocation_attestation.py's run of the compose
    # argv under 1 and 0 (test_the_shipped_check_command_runs) covers this one too.
    assert [str(a) for a in _init(name)["command"]] == _compose_check_argv(), name


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_refusal_reaches_kubectl_describe(name: str) -> None:
    assert _init(name).get("terminationMessagePolicy") == "FallbackToLogsOnError", name


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_check_is_locked_down(name: str) -> None:
    # The engine's own hardening; test_k8s_tls_key_copy holds every initContainer to it too.
    [engine] = [c for c in _pod(name)["containers"] if c["name"] == "engine"]
    assert _init(name).get("securityContext") == engine["securityContext"], name
    assert not _init(name).get("volumeMounts"), f"{name}: the check needs no volume"


# --- item 5: the example Secret --------------------------------------------------------------------


def _example_secret() -> dict[str, Any]:
    [doc] = [d for d in yaml.safe_load_all((_K8S / "secret.example.yaml").read_text("utf-8")) if d]
    assert (doc["kind"], doc["metadata"]["name"]) == ("Secret", _SECRET)
    return doc


@functools.cache
def _required_keys(name: str) -> frozenset[str]:
    """Every mefor-secrets key the pod cannot start without: a non-optional env reference, or an
    item of a Secret volume."""
    pod = _pod(name)
    keys: set[str] = set()
    for c in [*(pod.get("initContainers") or []), *pod["containers"]]:
        for e in c.get("env") or []:
            ref = (e.get("valueFrom") or {}).get("secretKeyRef")
            if ref and ref["name"] == _SECRET and ref.get("optional") is not True:
                keys.add(ref["key"])
    for v in pod.get("volumes") or []:
        secret = v.get("secret")
        if secret and secret["secretName"] == _SECRET and secret.get("optional") is not True:
            keys.update(item["key"] for item in secret.get("items") or [])
    return frozenset(keys)


def test_each_manifest_requires_keys() -> None:
    # Positive control: the refusal test below is vacuous if no key is required.
    for name in _MANIFESTS:
        assert {"tls-revocation-attested", "store-encryption-key", "api.key"} <= _required_keys(
            name
        )
    assert "store-password" in _required_keys("ha-postgres.yaml")


@pytest.mark.parametrize("name", _MANIFESTS)
def test_an_unedited_example_secret_is_refused_by_the_kubelet(name: str) -> None:
    doc = _example_secret()
    shipped = {**(doc.get("data") or {}), **(doc.get("stringData") or {})}
    held = sorted(_required_keys(name) & set(shipped))
    assert not held, f"applied unedited, the example Secret gives {name} a placeholder for {held}"


def test_the_example_secret_still_names_every_key() -> None:
    # The values ship commented, not deleted: a deployer still reads which keys to create.
    text = (_K8S / "secret.example.yaml").read_text(encoding="utf-8")
    for key in set().union(*(_required_keys(n) for n in _MANIFESTS)) | {"api-tls-key-password"}:
        if key in {"api.crt", "api.key"}:
            assert f"--from-file={key}=" in text, key
            continue
        assert f"--from-literal={key}=" in text, key
        assert f'  # {key}: "REPLACE' in text, f"no commented REPLACE entry for {key}"
