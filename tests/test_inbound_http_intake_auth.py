# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Inbound HTTP intake authentication (ADR 0154 increment A) — the per-inbound peer control.

Deliberately NOT ``tests/test_http_auth.py`` (the existing *outbound* OAuth2/Digest suite) and NOT
``tests/test_inbound_http_source.py`` (which pins the shipped 202 slice).

This module starts with the offline half: every refusal here is raised by the ``Http()`` factory, so it
fires with **no store and no posture** — in ``messagefoundry check``, in dry-run, and identically
through the ``connections.toml`` desugar, which routes through the very same factory. Each case is a
configuration whose failure mode would otherwise be silent or total.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.wiring import Http, WiringError, env


def test_valid_configurations_build() -> None:
    Http(port=8080)  # the default: intake_auth="none", byte-identical to every shipped config
    Http(port=8080, intake_auth="api_key", intake_api_key=env("acme_intake_key"))
    Http(port=8080, intake_auth="bearer", intake_api_key=env("acme_intake_key"))
    Http(
        port=8080,
        intake_auth="api_key",
        intake_api_key=env("acme_intake_key"),
        intake_api_key_next=env("acme_intake_key_next"),  # mid-rotation: both live
    )
    Http(
        port=8443,
        tls=True,
        tls_cert_file="/tmp/server.pem",
        tls_key_file="/tmp/server.key",
        tls_ca_file="/tmp/ca.pem",
        intake_auth="mtls_subject",
        intake_client_subjects=["CN:partner.example", "SAN:DNS:partner.example"],
    )


def test_intake_auth_offline_validation_refuses() -> None:
    """AC-7 (intake arm): every unworkable intake-auth shape is refused with no store."""
    # A key mode with no credential would refuse 100 % of traffic. An unset value is not an
    # env-resolution failure, so resolve_env_settings does not catch it — nothing else would.
    for mode in ("api_key", "bearer"):
        with pytest.raises(WiringError, match="needs intake_api_key"):
            Http(port=8080, intake_auth=mode)

    # mtls_subject without tls / without a CA: the SSLContext never REQUESTS a client certificate, so
    # getpeercert() is empty and deny-by-default 403s everything, with no start-time error.
    with pytest.raises(WiringError, match="needs tls=True and tls_ca_file"):
        Http(port=8443, intake_auth="mtls_subject", intake_client_subjects=["CN:p.example"])
    with pytest.raises(WiringError, match="needs tls=True and tls_ca_file"):
        Http(
            port=8443,
            tls=True,
            tls_cert_file="/tmp/server.pem",
            intake_auth="mtls_subject",
            intake_client_subjects=["CN:p.example"],
        )

    # A CA with no subject list is "any certificate this CA ever signed" — no subject binding at all.
    with pytest.raises(WiringError, match="needs a non-empty intake_client_subjects"):
        Http(
            port=8443,
            tls=True,
            tls_cert_file="/tmp/server.pem",
            tls_ca_file="/tmp/ca.pem",
            intake_auth="mtls_subject",
        )

    # An unqualified subject matches nothing, so it would 403 the very partner it names.
    with pytest.raises(WiringError, match="must be qualified"):
        Http(
            port=8443,
            tls=True,
            tls_cert_file="/tmp/server.pem",
            tls_ca_file="/tmp/ca.pem",
            intake_auth="mtls_subject",
            intake_client_subjects=["partner.example"],
        )

    with pytest.raises(WiringError, match="must be one of"):
        Http(port=8080, intake_auth="basic")  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="intake_auth_health"):
        Http(port=8080, intake_auth_health="skip")  # type: ignore[arg-type]


def test_intake_credential_must_be_an_env_reference() -> None:
    # Mirrors File(credential_password=...) (ADR 0132): a secret is never inline, and a fallback
    # credential is a silent credential.
    with pytest.raises(WiringError, match="must be an env\\(\\) reference"):
        Http(port=8080, intake_auth="api_key", intake_api_key="literal-key")  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="must not carry a default="):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k", default="fallback"))
    with pytest.raises(WiringError, match="must not carry a cast="):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k", cast=str))
    # The rotation slot is held to the same rule — it is the same credential class.
    with pytest.raises(WiringError, match="must be an env\\(\\) reference"):
        Http(
            port=8080,
            intake_auth="api_key",
            intake_api_key=env("k"),
            intake_api_key_next="literal-next",  # type: ignore[arg-type]
        )


def test_credential_configured_without_a_mode_is_refused() -> None:
    # Not in the ADR's enumerated list, but the same defect class the gate exists for: a control that
    # is configured but never consulted reads as protection that does not exist. An operator who sets
    # a key and forgets the mode has an unauthenticated listener and a config that says otherwise.
    with pytest.raises(WiringError, match="intake_auth='none'"):
        Http(port=8080, intake_api_key=env("acme_intake_key"))
    with pytest.raises(WiringError, match="intake_auth='none'"):
        Http(port=8080, intake_client_subjects=["CN:partner.example"])


def test_settings_are_carried_onto_the_spec() -> None:
    spec = Http(
        port=8080,
        intake_auth="api_key",
        intake_api_key=env("acme_intake_key"),
        intake_api_key_header="x-acme-key",
        intake_auth_rate_limit=25,
    )
    assert spec.settings["intake_auth"] == "api_key"
    assert spec.settings["intake_api_key_header"] == "x-acme-key"
    assert spec.settings["intake_auth_rate_limit"] == 25
    assert spec.settings["intake_auth_rate_limit_global"] == 60  # default
    assert spec.settings["intake_auth_health"] == "require"  # probes are inside the gate by default
    assert spec.settings["intake_api_key_next"] is None  # rotation is opt-in


def test_intake_credentials_are_redacted_and_rotatable() -> None:
    # The secrets must reach /metadata redaction AND the ASVS 13.3.4 rotation fingerprinter. Being in
    # _SECRET_SETTING_KEYS and NOT in _NON_ROTATABLE_SECRET_SETTING_KEYS is what does both; the header
    # NAME is neither a secret nor rotatable.
    from messagefoundry.config.wiring import (
        _NON_ROTATABLE_SECRET_SETTING_KEYS,
        _SECRET_SETTING_KEYS,
    )

    assert "intake_api_key" in _SECRET_SETTING_KEYS
    assert "intake_api_key_next" in _SECRET_SETTING_KEYS
    assert "intake_api_key_header" not in _SECRET_SETTING_KEYS
    assert not {"intake_api_key", "intake_api_key_next"} & _NON_ROTATABLE_SECRET_SETTING_KEYS
