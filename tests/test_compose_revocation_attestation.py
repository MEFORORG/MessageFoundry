# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every compose engine that serves in-process API TLS off loopback carries the revocation
attestation as a required substitution (BACKLOG #5400).

``serve`` refuses that bind until ``MEFOR_TLS_REVOCATION_ATTESTED`` is truthy (docs/SECURITY.md, API
revocation gate), and a container reached on a published port cannot bind loopback. Before this, the
compose engines left the variable unset, so the engine exited 2 and ``restart: unless-stopped``
restarted it forever. The variable must reach the engine, and the value must stay the operator's:
a ``${VAR:?...}`` substitution with no default, never a literal this file attests on their behalf."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    in_process_tls_revocation_refused,
    tls_revocation_attested,
)

_COMPOSE = Path(__file__).resolve().parents[1] / "docker" / "compose.yaml"
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_REQUIRED = re.compile(r"^\$\{" + TLS_REVOCATION_ATTESTED_ENV + r":\?[^}]+\}$")


def _serving_engines() -> dict[str, dict[str, Any]]:
    """The environment of every service whose command is ``serve``, merge keys resolved."""
    doc = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for name, svc in (doc.get("services") or {}).items():
        command = svc.get("command") or []
        if command[:1] == ["serve"]:
            out[name] = dict(svc.get("environment") or {})
    return out


def _gated(env: dict[str, Any]) -> bool:
    """Whether the revocation gate reads this service's bind: in-process TLS off loopback."""
    return (
        bool(env.get("MEFOR_API_TLS_CERT_FILE"))
        and env.get("MEFOR_SECURITY_LISTEN_ADDRESS") not in _LOOPBACK
    )


def test_the_compose_file_has_gated_engines() -> None:
    # Positive control: the default engine and both ha engines serve in-process TLS off loopback,
    # so the per-service test below has something to check.
    gated = {name for name, env in _serving_engines().items() if _gated(env)}
    assert {"engine", "engine-ha", "engine-standby"} <= gated


@pytest.mark.parametrize("service", sorted(_serving_engines()))
def test_a_gated_engine_requires_the_operators_attestation(service: str) -> None:
    env = _serving_engines()[service]
    if not _gated(env):
        pytest.skip(f"{service} does not bind in-process TLS off loopback")
    value = env.get(TLS_REVOCATION_ATTESTED_ENV)
    assert value is not None, f"{service} never passes {TLS_REVOCATION_ATTESTED_ENV}; serve exits 2"
    assert _REQUIRED.match(str(value)), (
        f"{service} sets {TLS_REVOCATION_ATTESTED_ENV} to {value!r}. It must be a required compose "
        "substitution with no default, so the attestation stays the operator's own act."
    )


def test_the_gate_refuses_unset_and_passes_an_operator_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # What the substitution protects: unset, the gate refuses (the old crash-loop); with the
    # operator's 1, it passes. The gate itself is unchanged.
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    assert in_process_tls_revocation_refused(
        tls_enabled=True, is_loopback=False, attested=tls_revocation_attested()
    )
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    assert not in_process_tls_revocation_refused(
        tls_enabled=True, is_loopback=False, attested=tls_revocation_attested()
    )
