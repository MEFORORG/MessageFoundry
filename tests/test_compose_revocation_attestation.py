# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every compose engine that serves in-process API TLS off loopback carries the revocation
attestation as a required substitution (BACKLOG #5400).

``serve`` refuses that bind until ``MEFOR_TLS_REVOCATION_ATTESTED`` is truthy (docs/SECURITY.md, API
revocation gate), and a container reached on a published port cannot bind loopback. Before this, the
compose engines left the variable unset, so the engine would exit 2 and ``restart: unless-stopped``
would restart it forever. The variable must reach the engine, and the value must stay the operator's:
a ``${VAR:?...}`` substitution with no default, never a literal this file attests on their behalf."""

from __future__ import annotations

import functools
import re
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
def _serving_engines() -> dict[str, dict[str, Any]]:
    """Every service whose command is ``serve``, merge keys resolved."""
    doc = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    services = doc.get("services") or {}
    return {n: s for n, s in services.items() if (s.get("command") or [])[:1] == ["serve"]}


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
