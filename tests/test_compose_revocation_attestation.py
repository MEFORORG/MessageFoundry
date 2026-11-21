# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every compose engine that serves in-process API TLS off loopback carries the revocation
attestation as a required substitution (BACKLOG #5400).

``serve`` refuses that bind until ``MEFOR_TLS_REVOCATION_ATTESTED`` is truthy (docs/SECURITY.md, API
revocation gate), and a container reached on a published port cannot bind loopback. Before this, the
compose engines left the variable unset, so the engine would exit 2 and ``restart: unless-stopped``
would restart it forever. The variable must reach the engine, and the value must stay the operator's:
a ``${VAR:?...}`` substitution with no default, never a literal this file attests on their behalf.

A value the engine reads as false passes that substitution, so each engine also waits on a one-shot
check that reads the value with the engine's own parser. The k8s manifests take the value from a
required, non-optional reference for the same reason."""

from __future__ import annotations

import functools
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.settings import _LOOPBACK_HOSTS
from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV

_COMPOSE = Path(__file__).resolve().parents[1] / "docker" / "compose.yaml"
_FALSE = {"false", "0", "no", "off", "n", "f"}
_REQUIRED = re.compile(r"^\$\{" + TLS_REVOCATION_ATTESTED_ENV + r":\?[^}]+\}$")


@functools.cache
def _compose_doc() -> dict[str, Any]:
    """The whole compose file, merge keys resolved. Shared: deep-copy it before mutating."""
    return dict(yaml.safe_load(_COMPOSE.read_text(encoding="utf-8")))


@functools.cache
def _all_services() -> dict[str, dict[str, Any]]:
    """Every compose service, merge keys resolved."""
    return dict(_compose_doc().get("services") or {})


def _serving_engines() -> dict[str, dict[str, Any]]:
    """Every service whose command is ``serve``."""
    return {n: s for n, s in _all_services().items() if (s.get("command") or [])[:1] == ["serve"]}


def _env(svc: dict[str, Any]) -> dict[str, Any]:
    return dict(svc.get("environment") or {})


def _off_loopback(value: object) -> bool:
    return bool(value) and str(value) not in _LOOPBACK_HOSTS


def _gated(svc: dict[str, Any]) -> bool:
    """Whether the revocation gate would read this service's bind: in-process TLS off loopback.

    It errs toward gated. The API leaves loopback when local_access_only reads false beside a
    non-loopback listen address, or when MEFOR_API_HOST or ``serve --host`` names one; a service
    with none of those stays on 127.0.0.1 and needs no attestation."""
    env = _env(svc)
    command = [str(a) for a in svc.get("command") or []]
    host_arg = command[command.index("--host") + 1] if "--host" in command[:-1] else None
    local_only = str(env.get("MEFOR_SECURITY_LOCAL_ACCESS_ONLY", "true")).strip().lower()
    return bool(env.get("MEFOR_API_TLS_CERT_FILE")) and (
        (local_only in _FALSE and _off_loopback(env.get("MEFOR_SECURITY_LISTEN_ADDRESS")))
        or _off_loopback(env.get("MEFOR_API_HOST"))
        or _off_loopback(host_arg)
    )


def test_the_compose_file_has_gated_engines() -> None:
    # Positive control: the default engine and both ha engines serve in-process TLS off loopback,
    # so the per-service test below has something to check.
    gated = {name for name, svc in _serving_engines().items() if _gated(svc)}
    assert {"engine", "engine-ha", "engine-standby"} <= gated


def test_the_checks_refuse_what_they_must() -> None:
    # Negative controls: a literal or a defaulted substitution is not a required one, and a
    # service with no off-loopback lever is not gated.
    assert _REQUIRED.match("${MEFOR_TLS_REVOCATION_ATTESTED:?say why}")
    assert not _REQUIRED.match("1")
    assert not _REQUIRED.match("${MEFOR_TLS_REVOCATION_ATTESTED:-1}")
    assert not _REQUIRED.match("${MEFOR_TLS_REVOCATION_ATTESTED}")
    cert = {"MEFOR_API_TLS_CERT_FILE": "/etc/mefor/tls/api.crt"}
    assert not _gated({"command": ["serve"], "environment": cert})
    assert _gated({"command": ["serve", "--host", "0.0.0.0"], "environment": cert})
    assert _gated({"command": ["serve"], "environment": {**cert, "MEFOR_API_HOST": "0.0.0.0"}})


@pytest.mark.parametrize("service", sorted(_serving_engines()))
def test_a_gated_engine_requires_the_operators_attestation(service: str) -> None:
    svc = _serving_engines()[service]
    if not _gated(svc):
        pytest.skip(f"{service} does not bind in-process TLS off loopback")
    value = _env(svc).get(TLS_REVOCATION_ATTESTED_ENV)
    assert value is not None, f"{service} never passes {TLS_REVOCATION_ATTESTED_ENV}; serve exits 2"
    assert _REQUIRED.match(str(value)), (
        f"{service} sets {TLS_REVOCATION_ATTESTED_ENV} to {value!r}. It must be a required compose "
        "substitution with no default, so the attestation stays the operator's own act."
    )


# --- a value the engine reads as false (BACKLOG #5400 item 3) ------------------------------------

_CHECK = "revocation-attestation-check"


def _check_argv() -> list[str]:
    """The check service's argv after the image's interpreter, to run with this interpreter."""
    entry = [str(a) for a in _all_services()[_CHECK]["entrypoint"]]
    return entry[entry.index("/opt/venv/bin/python") + 1 :]


@pytest.mark.parametrize("service", sorted(_serving_engines()))
def test_a_gated_engine_waits_on_the_attestation_check(service: str) -> None:
    # The required substitution refuses only unset or empty, so 0 would start an engine that exits
    # 2 at the gate and restarts forever. Each gated engine must not start until the check passed.
    svc = _serving_engines()[service]
    if not _gated(svc):
        pytest.skip(f"{service} does not bind in-process TLS off loopback")
    dep = (svc.get("depends_on") or {}).get(_CHECK)
    assert dep == {"condition": "service_completed_successfully"}, (
        f"{service} does not wait on {_CHECK}, so a false attestation restarts it forever"
    )


def test_the_check_reads_the_same_required_value_and_never_restarts() -> None:
    check = _all_services()[_CHECK]
    assert _REQUIRED.match(str(_env(check).get(TLS_REVOCATION_ATTESTED_ENV)))
    assert str(check.get("restart")) == "no"
    assert not check.get("profiles"), "a profiled check would not run for every engine"


def test_the_check_runs_the_engines_image() -> None:
    # A check in another image would read the value with another version's parser, or fail to
    # pull an image the operator never built.
    image = _all_services()[_CHECK]["image"]
    for name, svc in _serving_engines().items():
        assert svc["image"] == image, f"{name} runs {svc['image']!r}, the check {image!r}"


@pytest.mark.parametrize(("value", "passes"), [("1", True), ("0", False)])
def test_the_shipped_check_command_runs(value: str, passes: bool) -> None:
    # Run the check's own command with this interpreter, so the shipped text is what is tested.
    # It must call serve's parser; tests/test_tls_policy.py holds that parser's value table.
    assert "tls_revocation_attested" in " ".join(_check_argv())
    env = {k: v for k, v in os.environ.items() if k != TLS_REVOCATION_ATTESTED_ENV}
    env[TLS_REVOCATION_ATTESTED_ENV] = value
    done = subprocess.run(
        [sys.executable, *_check_argv()], env=env, capture_output=True, text=True, timeout=120
    )
    if passes:
        assert done.returncode == 0, done.stderr
    else:
        assert done.returncode == 1, done.stderr
        assert "API revocation gate" in done.stderr


# --- the env-file guidance (BACKLOG #5400 item 2) ------------------------------------------------

_SUBSTITUTION = re.compile(r"\$\{(?P<var>[A-Z0-9_]+):\?(?P<msg>[^}]*)\}")


def test_every_required_substitution_names_the_same_sources() -> None:
    # Two messages that disagree on where compose reads a value send an operator to split them,
    # and --env-file then leaves the .env holding the other one unread.
    text = _COMPOSE.read_text(encoding="utf-8")
    found = {m["var"]: m["msg"] for m in _SUBSTITUTION.finditer(text)}
    assert {TLS_REVOCATION_ATTESTED_ENV, "MEFOR_STORE_PASSWORD"} <= set(found)
    for var, msg in found.items():
        for phrase in (".env beside compose.yaml", "--env-file", "env_file: does NOT feed it"):
            assert phrase in msg, f"{var}'s message omits {phrase!r}"


# --- the k8s manifests (BACKLOG #5400 item 1) ----------------------------------------------------

_K8S = _COMPOSE.parent / "k8s"


@functools.cache
def _k8s_engine_containers() -> dict[str, dict[str, Any]]:
    """Every container whose args are ``serve``, keyed ``<file>:<container>``."""
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(_K8S.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            spec = ((doc or {}).get("spec") or {}).get("template", {}).get("spec") or {}
            for c in spec.get("containers") or []:
                if (c.get("args") or [])[:1] == ["serve"]:
                    out[f"{path.name}:{c['name']}"] = c
    return out


def _k8s_gated(container: dict[str, Any]) -> bool:
    env = {e["name"]: e.get("value") for e in container.get("env") or []}
    return _gated({"command": container.get("args"), "environment": env})


def test_the_k8s_manifests_have_gated_engines() -> None:
    # Positive control for the per-container test below.
    files = {n.split(":")[0] for n, c in _k8s_engine_containers().items() if _k8s_gated(c)}
    assert {"statefulset.yaml", "ha-postgres.yaml"} <= files


@pytest.mark.parametrize("name", sorted(_k8s_engine_containers()))
def test_a_gated_k8s_engine_requires_the_operators_attestation(name: str) -> None:
    container = _k8s_engine_containers()[name]
    if not _k8s_gated(container):
        pytest.skip(f"{name} does not bind in-process TLS off loopback")
    entries = [e for e in container.get("env") or [] if e["name"] == TLS_REVOCATION_ATTESTED_ENV]
    assert len(entries) == 1, f"{name} never passes {TLS_REVOCATION_ATTESTED_ENV}; the pod loops"
    entry = entries[0]
    assert "value" not in entry, "a literal attests on the operator's behalf"
    source = entry.get("valueFrom") or {}
    ref = source.get("configMapKeyRef") or source.get("secretKeyRef") or {}
    assert ref.get("name") and ref.get("key"), f"{name} reads the value from nowhere"
    assert not ref.get("optional"), "an optional ref starts the engine unset, and it loops"
