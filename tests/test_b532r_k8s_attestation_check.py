# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Each k8s manifest checks the revocation attestation before the engine starts (BACKLOG #5400,
added items 4 to 6).

The manifests take ``MEFOR_TLS_REVOCATION_ATTESTED`` from a required Secret key, which refuses only
a missing value. A value the engine reads as false, such as 0, passed the kubelet and the engine
exited 2 at the revocation gate, restarting forever. Each manifest now runs compose's one-shot check
as its first init container, so the engine container never starts on such a value. And the example
Secret ships no placeholder value, so applying it unedited is refused by the kubelet rather than
starting an engine on a placeholder.
"""

from __future__ import annotations

import functools
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV

_DOCKER = Path(__file__).resolve().parents[1] / "docker"
_MANIFESTS = ("ha-postgres.yaml", "statefulset.yaml")
_CHECK = "revocation-attestation-check"


@functools.cache
def _pod_spec(name: str) -> dict[str, Any]:
    docs = [
        d for d in yaml.safe_load_all((_DOCKER / "k8s" / name).read_text(encoding="utf-8")) if d
    ]
    specs = [
        d["spec"]["template"]["spec"]
        for d in docs
        if d.get("kind") in {"Deployment", "StatefulSet"}
    ]
    assert len(specs) == 1, name
    spec: dict[str, Any] = specs[0]
    return spec


def _compose_check() -> dict[str, Any]:
    doc = yaml.safe_load((_DOCKER / "compose.yaml").read_text(encoding="utf-8"))
    check: dict[str, Any] = doc["services"][_CHECK]
    return check


def _program_argv(command: list[str]) -> list[str]:
    """The argv after the image's interpreter, to run with this one."""
    return command[command.index("/opt/venv/bin/python") + 1 :]


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_check_is_the_first_init_container_and_runs_composes_program(name: str) -> None:
    inits = _pod_spec(name)["initContainers"]
    assert inits[0]["name"] == _CHECK, f"{name}: the check must run before anything else"
    ours = _program_argv([str(a) for a in inits[0]["command"]])
    theirs = _program_argv([str(a) for a in _compose_check()["entrypoint"]])
    assert ours == theirs, f"{name}: the check's program differs from compose.yaml's"


@pytest.mark.parametrize("name", _MANIFESTS)
def test_the_check_reads_the_engines_secret_key_in_the_engines_image(name: str) -> None:
    spec = _pod_spec(name)
    check = spec["initContainers"][0]
    engine = next(c for c in spec["containers"] if c["name"] == "engine")
    assert check["image"] == engine["image"], f"{name}: another image reads another parser"

    def ref(container: dict[str, Any]) -> dict[str, Any]:
        found = [e for e in container["env"] if e["name"] == TLS_REVOCATION_ATTESTED_ENV]
        assert len(found) == 1, f"{name}/{container['name']}"
        secret: dict[str, Any] = found[0]["valueFrom"]["secretKeyRef"]
        return secret

    assert ref(check) == ref(engine), f"{name}: the check and the engine read different keys"
    assert ref(check).get("optional") is not True


@pytest.mark.parametrize(("value", "passes"), [("1", True), ("on", True), ("0", False)])
def test_the_shipped_init_program_runs(value: str, passes: bool) -> None:
    """The manifest's own program, run with this interpreter, against serve's parser."""
    argv = _program_argv([str(a) for a in _pod_spec(_MANIFESTS[0])["initContainers"][0]["command"]])
    env = {k: v for k, v in os.environ.items() if k != TLS_REVOCATION_ATTESTED_ENV}
    env[TLS_REVOCATION_ATTESTED_ENV] = value
    done = subprocess.run(
        [sys.executable, *argv], env=env, capture_output=True, text=True, timeout=120
    )
    if passes:
        assert done.returncode == 0, done.stderr
    else:
        assert done.returncode == 1, done.stderr
        assert "API revocation gate" in done.stderr


def test_the_example_secret_ships_no_placeholder_value() -> None:
    """Applied unedited, it holds no key, so the kubelet refuses each container that reads a
    required one, rather than an engine starting on a placeholder."""
    docs = [
        d
        for d in yaml.safe_load_all(
            (_DOCKER / "k8s" / "secret.example.yaml").read_text(encoding="utf-8")
        )
        if d
    ]
    assert len(docs) == 1 and docs[0]["kind"] == "Secret"
    assert not docs[0].get("stringData") and not docs[0].get("data"), docs[0]
