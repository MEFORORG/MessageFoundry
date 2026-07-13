# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the connector **SecretProvider** seam (config/secretprovider.py + the ``vault`` backend,
ADR 0019 §5, BACKLOG #196 residual).

Mirrors tests/test_keyprovider_vault.py: the default env-sourced path is byte-identical (no provider is
built/consulted); a configured provider resolves a NAMED connector secret from a MOCKED Vault KV (no live
Vault); every fail-closed path (a reference with no provider, a missing hvac extra, a KV/transport failure,
an absent/empty field, an unknown provider name) raises :class:`SecretProviderError` — never a silent blank
credential, and never with the secret value in the message. It also proves the two wired credential points
(AD LDAP bind password, SMTP password) consume the resolved value.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from messagefoundry.config import secretprovider_vault
from messagefoundry.config.secretprovider import (
    EnvSecretProvider,
    SecretProvider,
    SecretProviderError,
    resolve_connector_secret,
    resolve_secret_provider,
)
from messagefoundry.config.settings import AlertsSettings, AuthSettings, SecretsSettings

# --- fakes -------------------------------------------------------------------


class _FakeProvider:
    """A minimal in-memory :class:`SecretProvider` for the wiring tests."""

    def __init__(self, mapping: dict[str, str]) -> None:
        self._m = mapping
        self.calls: list[str] = []

    def resolve(self, ref: str) -> str:
        self.calls.append(ref)
        if ref not in self._m:
            raise SecretProviderError(f"no such secret {ref!r}")
        return self._m[ref]


class _FakeKvV2:
    """Stands in for ``client.secrets.kv.v2``; records the read + returns a KV v2 shaped response."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        self.calls: list[tuple[str, str]] = []

    def read_secret_version(self, *, path: str, mount_point: str) -> dict[str, Any]:
        self.calls.append((path, mount_point))
        return {"data": {"data": self._data, "metadata": {"version": 1}}}


class _FakeKv:
    def __init__(self, v2: _FakeKvV2) -> None:
        self.v2 = v2


class _FakeSecrets:
    def __init__(self, kv: _FakeKv) -> None:
        self.kv = kv


class _FakeClient:
    def __init__(self, kv_v2: _FakeKvV2) -> None:
        self.secrets = _FakeSecrets(_FakeKv(kv_v2))


def _patch_vault(monkeypatch: pytest.MonkeyPatch, kv_v2: _FakeKvV2) -> None:
    monkeypatch.setattr(
        secretprovider_vault, "_build_client", lambda addr, token: _FakeClient(kv_v2)
    )


# --- default (no provider) path: byte-identical ------------------------------


def test_default_provider_is_none_and_env_literal_is_used() -> None:
    # [secrets].provider unset/'none' → no provider is built; resolve_connector_secret with no reference
    # returns the env-sourced literal unchanged (the pre-seam behaviour).
    assert resolve_secret_provider(SecretsSettings()) is None
    assert resolve_secret_provider(SecretsSettings(provider="none")) is None
    assert (
        resolve_connector_secret(None, ref=None, literal="env-pw", label="[auth].ad_bind_password")
        == "env-pw"
    )
    # An unset literal stays None (a credential point that treats None as "not configured" still does).
    assert (
        resolve_connector_secret(None, ref=None, literal=None, label="[alerts].email_password")
        is None
    )


def test_reference_without_provider_fails_closed() -> None:
    # A per-credential *_secret reference is meaningless without a provider — fail closed rather than
    # silently using the (possibly blank) literal, which would mask the misconfiguration.
    with pytest.raises(SecretProviderError, match="ad_bind_password"):
        resolve_connector_secret(
            None, ref="mefor/ad#bind", literal="ignored", label="[auth].ad_bind_password"
        )


# --- env built-in provider ---------------------------------------------------


def test_env_provider_resolves_and_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = resolve_secret_provider(SecretsSettings(provider="env"))
    assert isinstance(provider, EnvSecretProvider)
    monkeypatch.setenv("MEFOR_VALUE_PARTNER_PW", "hunter2")
    assert provider.resolve("MEFOR_VALUE_PARTNER_PW") == "hunter2"
    # An unset/blank env var is a misconfiguration, not a blank credential.
    monkeypatch.delenv("MEFOR_VALUE_MISSING", raising=False)
    with pytest.raises(SecretProviderError, match="MEFOR_VALUE_MISSING"):
        provider.resolve("MEFOR_VALUE_MISSING")


def test_unknown_provider_name_fails_closed() -> None:
    with pytest.raises(SecretProviderError, match="unknown"):
        resolve_secret_provider(SecretsSettings(provider="nope"))


# --- vault backend: mocked KV ------------------------------------------------


def test_vault_resolves_kv_secret_default_field(monkeypatch: pytest.MonkeyPatch) -> None:
    kv = _FakeKvV2({"value": "s3cret-bind"})
    _patch_vault(monkeypatch, kv)
    provider = secretprovider_vault.build_provider(SecretsSettings())
    # No '#field' → the default field 'value'; default mount 'secret'.
    assert provider.resolve("mefor/ad") == "s3cret-bind"
    assert kv.calls == [("mefor/ad", "secret")]


def test_vault_resolves_explicit_field_and_mount(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_KV_MOUNT", "kv")
    kv = _FakeKvV2({"bind_password": "abc", "other": "z"})
    _patch_vault(monkeypatch, kv)
    provider = secretprovider_vault.build_provider(SecretsSettings())
    assert provider.resolve("mefor/ad#bind_password") == "abc"
    assert kv.calls == [("mefor/ad", "kv")]


def test_resolve_secret_provider_wires_the_vault_module(monkeypatch: pytest.MonkeyPatch) -> None:
    # The base dispatch imports config.secretprovider_vault by name and calls build_provider — no edit
    # to secretprovider.py.
    kv = _FakeKvV2({"value": "wired"})
    _patch_vault(monkeypatch, kv)
    provider = resolve_secret_provider(SecretsSettings(provider="vault"))
    assert isinstance(provider, secretprovider_vault.VaultSecretProvider)
    assert provider.resolve("p") == "wired"


# --- vault fail-closed paths -------------------------------------------------


def test_vault_missing_hvac_fails_closed_naming_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # None in sys.modules makes `import hvac` raise ImportError — the fail-closed path when the [vault]
    # extra is not installed.
    monkeypatch.setitem(sys.modules, "hvac", None)
    provider = secretprovider_vault.build_provider(SecretsSettings())
    with pytest.raises(SecretProviderError, match="vault"):
        provider.resolve("mefor/ad")


def test_vault_kv_failure_fails_closed_without_leaking(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BoomKv:
        def read_secret_version(self, *, path: str, mount_point: str) -> dict[str, Any]:
            # A backend error can echo secret material — the provider must not surface it.
            raise RuntimeError("denied: value=topsecret")

    monkeypatch.setattr(
        secretprovider_vault,
        "_build_client",
        lambda addr, token: _FakeClient(_BoomKv()),  # type: ignore[arg-type]
    )
    provider = secretprovider_vault.build_provider(SecretsSettings())
    with pytest.raises(SecretProviderError) as excinfo:
        provider.resolve("mefor/ad")
    msg = str(excinfo.value)
    assert "topsecret" not in msg  # no key-material oracle
    assert "RuntimeError" in msg


def test_vault_absent_field_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_vault(monkeypatch, _FakeKvV2({"value": "x"}))
    provider = secretprovider_vault.build_provider(SecretsSettings())
    with pytest.raises(SecretProviderError, match="no field"):
        provider.resolve("mefor/ad#missing")


def test_vault_empty_value_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_vault(monkeypatch, _FakeKvV2({"value": ""}))
    provider = secretprovider_vault.build_provider(SecretsSettings())
    with pytest.raises(SecretProviderError, match="empty"):
        provider.resolve("mefor/ad")


def test_vault_malformed_reference_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_vault(monkeypatch, _FakeKvV2({"value": "x"}))
    provider = secretprovider_vault.build_provider(SecretsSettings())
    with pytest.raises(SecretProviderError, match="malformed"):
        provider.resolve("#field-only")


# --- wired credential point 1: AD LDAP bind password -------------------------


def _ad_settings(**over: Any) -> AuthSettings:
    base: dict[str, Any] = dict(
        ad_enabled=True,
        ad_server="ldaps://dc.example.com",
        ad_domain="example.com",
        ad_user_search_base="OU=Users,DC=example,DC=com",
        ad_bind_dn="CN=svc,DC=example,DC=com",
    )
    base.update(over)
    return AuthSettings(**base)


def test_auth_settings_accepts_secret_reference_without_env_password() -> None:
    # The validator now accepts a service-account password supplied via a [secrets] reference INSTEAD of
    # ad_bind_password — but still requires one of the two.
    s = _ad_settings(ad_bind_password_secret="mefor/ad#bind")
    assert s.ad_bind_password is None and s.ad_bind_password_secret == "mefor/ad#bind"
    with pytest.raises(ValueError, match="service-account password"):
        _ad_settings()  # neither the env password nor a reference


def test_ldap_authenticator_uses_resolved_bind_password() -> None:
    from messagefoundry.auth.ldap import LdapAuthenticator

    provider = _FakeProvider({"mefor/ad#bind": "resolved-bind-pw"})
    auth = LdapAuthenticator(
        _ad_settings(ad_bind_password_secret="mefor/ad#bind"), secret_provider=provider
    )
    assert auth._bind_password == "resolved-bind-pw"
    assert provider.calls == ["mefor/ad#bind"]


def test_ldap_authenticator_default_env_password_is_byte_identical() -> None:
    from messagefoundry.auth.ldap import LdapAuthenticator

    # No reference, no provider → the env-sourced ad_bind_password is used unchanged.
    auth = LdapAuthenticator(_ad_settings(ad_bind_password="env-bind-pw"))
    assert auth._bind_password == "env-bind-pw"


def test_ldap_authenticator_unresolvable_reference_fails_closed() -> None:
    from messagefoundry.auth.ldap import LdapAuthenticator

    provider = _FakeProvider({})  # the reference resolves to nothing
    with pytest.raises(SecretProviderError):
        LdapAuthenticator(
            _ad_settings(ad_bind_password_secret="mefor/ad#bind"), secret_provider=provider
        )


# --- wired credential point 2: SMTP password ---------------------------------


def _smtp_settings(**over: Any) -> AlertsSettings:
    base: dict[str, Any] = dict(
        email_smtp_host="smtp.example.com",
        email_from="alerts@example.com",
        email_to=["ops@example.com"],
        email_username="alerts@example.com",
    )
    base.update(over)
    return AlertsSettings(**base)


def test_notifier_uses_resolved_smtp_password() -> None:
    from messagefoundry.pipeline.alert_sinks import EmailTransport, notifier_from_settings

    provider = _FakeProvider({"mefor/smtp#password": "resolved-smtp-pw"})
    sink = notifier_from_settings(
        _smtp_settings(email_password_secret="mefor/smtp#password"), secret_provider=provider
    )
    assert sink is not None
    email = next(t for t in sink._transports if isinstance(t, EmailTransport))
    assert email.password == "resolved-smtp-pw"
    assert provider.calls == ["mefor/smtp#password"]


def test_notifier_default_env_password_is_byte_identical() -> None:
    from messagefoundry.pipeline.alert_sinks import EmailTransport, notifier_from_settings

    sink = notifier_from_settings(_smtp_settings(email_password="env-smtp-pw"))
    assert sink is not None
    email = next(t for t in sink._transports if isinstance(t, EmailTransport))
    assert email.password == "env-smtp-pw"


def test_security_notifier_uses_resolved_smtp_password() -> None:
    from messagefoundry.pipeline.security_notify import security_notifier_from_settings

    provider = _FakeProvider({"mefor/smtp#password": "resolved-smtp-pw"})
    notifier = security_notifier_from_settings(
        _smtp_settings(email_password_secret="mefor/smtp#password"), secret_provider=provider
    )
    assert notifier is not None
    assert notifier._password == "resolved-smtp-pw"


def test_secret_provider_is_runtime_checkable() -> None:
    # The protocol is @runtime_checkable, mirroring KeyProvider — the fakes satisfy it structurally.
    assert isinstance(_FakeProvider({}), SecretProvider)
    assert isinstance(EnvSecretProvider(), SecretProvider)
