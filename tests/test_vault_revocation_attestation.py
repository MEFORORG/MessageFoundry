# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Vault hops' revocation attestation (vault BACKLOG #2983, owner ruling 2026-10-13).

Each of the engine's three Vault hops (the store key provider, the Transit cipher and the connector
secret provider) verifies the Vault server's certificate and checks no revocation. The ruling: each
hop refuses under an enforcing posture unless its own settings pair attests that revocation is
covered outside the engine. ``[store].vault_revocation_attested`` covers the two store hops and
``[secrets].vault_revocation_attested`` the secret provider. Each needs a reason. No CRL lever is
built, and the process-wide ``MEFOR_TLS_REVOCATION_ATTESTED`` does not cross an enforcing hop.

Synthetic data only: every host, token, key name and reason here is made up.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecretsSettings,
    SecuritySettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)

_REASON = "the Vault server certificate lives 24 hours (synthetic)"
_SECTIONS = pytest.mark.parametrize(
    ("section", "model"), [("store", StoreSettings), ("secrets", SecretsSettings)]
)


# --- the settings pair ------------------------------------------------------------------------


@_SECTIONS
def test_the_pair_loads_and_the_default_is_off(
    section: str, model: type[StoreSettings] | type[SecretsSettings]
) -> None:
    assert model().vault_revocation_attested is False
    assert model().vault_revocation_attested_reason is None
    attested = model(vault_revocation_attested=True, vault_revocation_attested_reason=_REASON)
    assert attested.vault_revocation_attested is True


@_SECTIONS
@pytest.mark.parametrize(
    ("values", "refusal"),
    [
        ({"vault_revocation_attested": True}, "requires [{s}].vault_revocation_attested_reason"),
        (
            {"vault_revocation_attested_reason": _REASON},
            "is set without [{s}].vault_revocation_attested=true",
        ),
        (
            {"vault_revocation_attested": True, "vault_revocation_attested_reason": " \t"},
            "[{s}].vault_revocation_attested_reason must be non-empty",
        ),
        (
            {"vault_revocation_attested": True, "vault_revocation_attested_reason": "a\r\nb"},
            "[{s}].vault_revocation_attested_reason must not contain control characters",
        ),
        # The string "false" is truthy to a lax reader. Here it reads as false, so the reason
        # beside it is a reason without the flag.
        (
            {"vault_revocation_attested": "false", "vault_revocation_attested_reason": _REASON},
            "is set without [{s}].vault_revocation_attested=true",
        ),
    ],
)
def test_a_pair_that_is_not_whole_refuses_at_the_model(
    section: str,
    model: type[StoreSettings] | type[SecretsSettings],
    values: dict[str, object],
    refusal: str,
) -> None:
    """Mutation: drop the ``_vault_revocation_attestation_pair`` validator from either section and
    every case for that section loads."""
    with pytest.raises(ValidationError) as caught:
        model.model_validate(values)
    assert refusal.format(s=section) in str(caught.value)


@pytest.mark.parametrize("section", ["STORE", "SECRETS"])
def test_a_flag_with_no_reason_refuses_at_settings_load(section: str) -> None:
    """The load every command runs. The environment overlay reaches the typed field, so the
    variable needs no entry in ``_OUT_OF_BAND_ENV``."""
    flag = f"MEFOR_{section}_VAULT_REVOCATION_ATTESTED"
    with pytest.raises(ValueError, match="vault_revocation_attested=true requires"):
        load_settings(environ={flag: "true"}, default_file=False)
    # The control: the same load with the reason beside the flag succeeds and sets the field.
    settings = load_settings(environ={flag: "true", f"{flag}_REASON": _REASON}, default_file=False)
    loaded = settings.store if section == "STORE" else settings.secrets
    assert loaded.vault_revocation_attested is True
    assert loaded.vault_revocation_attested_reason == _REASON


# --- the loosening report ---------------------------------------------------------------------


def _loosenings(
    *, store: StoreSettings | None = None, secrets: SecretsSettings | None = None
) -> dict[str, str]:
    return dict(
        security_loosenings(
            SecuritySettings(),
            store or StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=secrets or SecretsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_each_attestation_is_a_named_loosening_that_carries_its_reason() -> None:
    """Mutation: delete the ``out.extend`` in ``security_loosenings`` and neither name appears."""
    names = ("store.vault_revocation_attested", "secrets.vault_revocation_attested")
    # The control: the shipped defaults name neither.
    assert not set(names) & set(_loosenings())

    store_only = _loosenings(
        store=StoreSettings(
            vault_revocation_attested=True, vault_revocation_attested_reason=_REASON
        )
    )
    assert names[0] in store_only and names[1] not in store_only
    assert f"(reason: {_REASON})" in store_only[names[0]]
    assert "the key provider and the Transit cipher" in store_only[names[0]]

    secrets_only = _loosenings(
        secrets=SecretsSettings(
            vault_revocation_attested=True, vault_revocation_attested_reason=_REASON
        )
    )
    assert names[1] in secrets_only and names[0] not in secrets_only
    assert f"(reason: {_REASON})" in secrets_only[names[1]]
    assert "the connector secret provider's Vault hop" in secrets_only[names[1]]
    # The wording the review asked for: the lever is not built, which is not "cannot exist".
    assert "No CRL lever is built" in secrets_only[names[1]]
