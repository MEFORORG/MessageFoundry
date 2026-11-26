# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import logging
import sys
from typing import Any

import pytest

from messagefoundry.config import secretprovider_vault
from messagefoundry.config.secretprovider import (
    EnvSecretProvider,
    SecretProvider,
    SecretProviderError,
    log_import_failure,
    resolve_connector_secret,
    resolve_secret_provider,
)
from messagefoundry.config.settings import AlertsSettings, AuthSettings, SecretsSettings
from messagefoundry.config.tls_policy import HopPosture
from tests._vault_hop_env import SECRETS, supply_vault_hop

#: The [alerts] revocation guards count no posture as enforcing (ADR 0173 section 12), so an
#: off-box hop built here to test something else is built on a warn posture.
_NOT_ENFORCING = HopPosture(enforcing=False)


@pytest.fixture(autouse=True)
def _secrets_vault_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    """The KV provider refuses an unset address or token before any client is built (BACKLOG
    #2851), so every test here names both."""
    supply_vault_hop(monkeypatch, SECRETS)


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
        secretprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(kv_v2)
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
    with pytest.raises(SecretProviderError, match="unset, empty or whitespace-only") as exc:
        provider.resolve("MEFOR_VALUE_MISSING")
    assert "MEFOR_VALUE_MISSING" not in str(exc.value)


@pytest.mark.parametrize("blank", ["", " ", "\t\r\n "])
def test_env_provider_refuses_a_whitespace_only_value(
    monkeypatch: pytest.MonkeyPatch, blank: str
) -> None:
    """BACKLOG #5326: a whitespace-only variable is no credential, so it is refused like an unset
    one. Before the fix only the empty string was refused, and ``" "`` came back as the secret."""
    monkeypatch.setenv("MEFOR_VALUE_BLANK_PW", blank)
    with pytest.raises(SecretProviderError, match="unset, empty or whitespace-only"):
        EnvSecretProvider().resolve("MEFOR_VALUE_BLANK_PW")


def test_env_provider_refusal_never_repeats_the_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5326: a secret pasted where its variable name belongs must not reach the error
    text. Before the fix the refusal quoted the reference verbatim, through the credential point's
    resolver too. That resolver puts the credential's label in front instead, so the operator
    still knows which credential's reference to correct."""
    pasted = "s3cret-pasted-by-mistake 0451"
    monkeypatch.delenv(pasted, raising=False)
    with pytest.raises(SecretProviderError) as direct:
        EnvSecretProvider().resolve(pasted)
    assert "0451" not in str(direct.value)
    with pytest.raises(SecretProviderError) as wired:
        resolve_connector_secret(
            EnvSecretProvider(), ref=pasted, literal=None, label="[auth].ad_bind_password"
        )
    assert "0451" not in str(wired.value)
    assert str(wired.value).startswith("[auth].ad_bind_password, its *_secret or *_ref reference: ")


def test_unknown_provider_name_fails_closed() -> None:
    with pytest.raises(SecretProviderError, match="unknown"):
        resolve_secret_provider(SecretsSettings(provider="nope"))


#: Synthetic text a broken import might carry: a path and a marker string. Neither may reach
#: the refusal's own text.
_BROKEN_IMPORT_TEXT = "DLL load failed: C:/synthetic/site-packages/_sdk.pyd marker zz0451"


#: Errors a present-but-broken import can raise, each built fresh per raise.
_BROKEN_IMPORTS = [
    pytest.param(lambda: ImportError(_BROKEN_IMPORT_TEXT), id="broken-c-extension"),
    pytest.param(
        lambda: ImportError(f"cannot import name 'Client' ({_BROKEN_IMPORT_TEXT})"),
        id="missing-symbol",
    ),
    pytest.param(lambda: OSError(_BROKEN_IMPORT_TEXT), id="os-error"),
    pytest.param(lambda: AttributeError(_BROKEN_IMPORT_TEXT), id="attribute-error"),
    pytest.param(lambda: SyntaxError(_BROKEN_IMPORT_TEXT), id="syntax-error"),
    pytest.param(lambda: ValueError(_BROKEN_IMPORT_TEXT), id="value-error"),
]


@pytest.mark.parametrize("make_error", _BROKEN_IMPORTS)
def test_an_external_provider_whose_import_breaks_fails_closed_with_a_fixed_text(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, make_error: Any
) -> None:
    caplog.set_level(logging.WARNING)
    # Vault BACKLOG #6709 item 1: an SDK that is installed but broken raises a plain ImportError (or
    # another error from the module's top-level code), not ModuleNotFoundError. The
    # dispatch must refuse with SecretProviderError, naming the extra and the error's type, and
    # must not repeat the error's text, in its own text or through a chain.
    raised: list[BaseException] = []

    def _import(_name: str) -> Any:
        error = make_error()
        raised.append(error)
        raise error

    monkeypatch.setattr("messagefoundry.config.secretprovider.importlib.import_module", _import)
    with pytest.raises(SecretProviderError) as caught:
        resolve_secret_provider(SecretsSettings(provider="vault"))
    text = str(caught.value)
    assert "[secrets].provider='vault'" in text
    assert "messagefoundry[vault]" in text
    assert f"import failed: {type(raised[0]).__name__}" in text
    assert "synthetic" not in text and "0451" not in text and "Client" not in text
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    _assert_one_class_only_warning(
        caplog, type(raised[0]).__name__, "messagefoundry.config.secretprovider"
    )


def _assert_one_class_only_warning(
    caplog: pytest.LogCaptureFixture, type_name: str, logger_name: str
) -> None:
    """Round-3 finding 2 on BACKLOG #6709: the dropped cause is logged at WARNING, by its class,
    with none of its text (a path, a source line or a secret). Counted on ``logger_name`` only,
    so a WARNING from another module neither satisfies nor breaks the count (#6709 items 9, 12)."""
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == logger_name]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert type_name in message
    assert "synthetic" not in message and "0451" not in message and "Client" not in message
    assert warnings[0].exc_info is None


@pytest.mark.parametrize("make_error", _BROKEN_IMPORTS)
def test_vault_lazy_hvac_import_that_breaks_fails_closed_with_a_fixed_text(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, make_error: Any
) -> None:
    # Vault BACKLOG #6709: the vault provider imports hvac lazily, at its first read, so a broken
    # hvac fails there rather than at the dispatch. That import must refuse the same way.
    import builtins

    real_import = builtins.__import__
    type_name = type(make_error()).__name__

    def _import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "hvac":
            raise make_error()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import)
    provider = secretprovider_vault.build_provider(SecretsSettings())
    caplog.set_level(logging.WARNING)
    with pytest.raises(SecretProviderError) as caught:
        provider.resolve("mefor/ad")
    text = str(caught.value)
    # A broken hvac is told apart from a missing one: it names the class and says reinstall.
    assert f"hvac is installed but did not import ({type_name})" in text
    assert "reinstall 'messagefoundry[vault]'" in text
    assert "synthetic" not in text and "0451" not in text and "Client" not in text
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    _assert_one_class_only_warning(caplog, type_name, "messagefoundry.config.secretprovider_vault")


@pytest.mark.parametrize(
    ("missing", "remedy"),
    [
        pytest.param("hvac", "install 'messagefoundry[vault]'", id="hvac-itself-missing"),
        # Round-3 finding 3 on BACKLOG #6709: a missing hvac submodule is a broken install of an
        # hvac that is present, so pip's install would do nothing; it must say reinstall.
        pytest.param("hvac.v1", "reinstall 'messagefoundry[vault]'", id="hvac-submodule-missing"),
    ],
)
def test_vault_lazy_hvac_import_tells_missing_from_broken_by_module_name(
    monkeypatch: pytest.MonkeyPatch, missing: str, remedy: str
) -> None:
    import builtins

    real_import = builtins.__import__

    def _import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "hvac":
            raise ModuleNotFoundError(f"No module named {missing!r}", name=missing)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import)
    provider = secretprovider_vault.build_provider(SecretsSettings())
    with pytest.raises(SecretProviderError) as caught:
        provider.resolve("mefor/ad")
    text = str(caught.value)
    assert remedy in text
    if missing == "hvac":
        assert "reinstall" not in text


@pytest.mark.parametrize(
    ("module", "logged"),
    [
        pytest.param("hvac.v1", "module 'hvac.v1'", id="dotted-name-logged"),
        pytest.param("C:/synthetic/zz0451", None, id="path-shaped-name-withheld"),
    ],
)
def test_log_import_failure_names_a_plain_module_and_withholds_any_other(
    caplog: pytest.LogCaptureFixture, module: str, logged: str | None
) -> None:
    # Vault BACKLOG #6709 item 7: the logged module name had no test.
    caplog.set_level(logging.WARNING)
    log_import_failure("label", ImportError("synthetic", name=module))
    (record,) = [r for r in caplog.records if r.name == "messagefoundry.config.secretprovider"]
    message = record.getMessage()
    if logged is None:
        assert "module" not in message and "zz0451" not in message
    else:
        assert logged in message


def test_an_external_provider_whose_build_fails_is_refused_by_class(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Vault BACKLOG #6709: build_provider ran outside the dispatch's try, so an error from a
    # provider's construction escaped raw. It is refused by class, with no text and no chain.
    caplog.set_level(logging.WARNING)

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise ValueError(_BROKEN_IMPORT_TEXT)

    monkeypatch.setattr(secretprovider_vault, "build_provider", _boom)
    with pytest.raises(SecretProviderError) as caught:
        resolve_secret_provider(SecretsSettings(provider="vault"))
    text = str(caught.value)
    assert "could not be built (ValueError)" in text
    assert "synthetic" not in text and "0451" not in text
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    _assert_one_class_only_warning(caplog, "ValueError", "messagefoundry.config.secretprovider")


def test_an_external_providers_own_refusal_from_its_build_keeps_its_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _refuse(*_a: Any, **_k: Any) -> Any:
        raise SecretProviderError("the provider's own refusal")

    monkeypatch.setattr(secretprovider_vault, "build_provider", _refuse)
    with pytest.raises(SecretProviderError, match="^the provider's own refusal$"):
        resolve_secret_provider(SecretsSettings(provider="vault"))


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
        lambda addr, token, **_: _FakeClient(_BoomKv()),  # type: ignore[arg-type]
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
    base: dict[str, Any] = dict(  # noqa: C408
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
    base: dict[str, Any] = dict(  # noqa: C408
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
        _smtp_settings(email_password_secret="mefor/smtp#password"),
        secret_provider=provider,
        posture=_NOT_ENFORCING,
    )
    assert sink is not None
    email = next(t for t in sink._transports if isinstance(t, EmailTransport))
    assert email.password == "resolved-smtp-pw"
    assert provider.calls == ["mefor/smtp#password"]


def test_notifier_default_env_password_is_byte_identical() -> None:
    from messagefoundry.pipeline.alert_sinks import EmailTransport, notifier_from_settings

    sink = notifier_from_settings(
        _smtp_settings(email_password="env-smtp-pw"), posture=_NOT_ENFORCING
    )
    assert sink is not None
    email = next(t for t in sink._transports if isinstance(t, EmailTransport))
    assert email.password == "env-smtp-pw"


def test_security_notifier_uses_resolved_smtp_password() -> None:
    from messagefoundry.pipeline.security_notify import security_notifier_from_settings

    provider = _FakeProvider({"mefor/smtp#password": "resolved-smtp-pw"})
    notifier = security_notifier_from_settings(
        _smtp_settings(email_password_secret="mefor/smtp#password"),
        secret_provider=provider,
        posture=_NOT_ENFORCING,
    )
    assert notifier is not None
    assert notifier._password == "resolved-smtp-pw"


def test_secret_provider_is_runtime_checkable() -> None:
    # The protocol is @runtime_checkable, mirroring KeyProvider — the fakes satisfy it structurally.
    assert isinstance(_FakeProvider({}), SecretProvider)
    assert isinstance(EnvSecretProvider(), SecretProvider)


# --- SMTP fail-closed symmetry: both notifier entrypoints (ADR 0019 §5) --------
# The AD LDAP consumer has a fail-closed-through-the-real-consumer test
# (test_ldap_authenticator_unresolvable_reference_fails_closed); these give the two SMTP consumers
# the same coverage. Both notifier_from_settings and security_notifier_from_settings call
# resolve_connector_secret before they build the SMTP side, so a bad
# [alerts].email_password_secret reference must propagate SecretProviderError (no blank-credential
# sink).


def test_notifier_unresolvable_reference_fails_closed() -> None:
    from messagefoundry.pipeline.alert_sinks import notifier_from_settings

    # Provider present but missing the key → the resolve raises before any EmailTransport is built.
    provider = _FakeProvider({})
    with pytest.raises(SecretProviderError):
        notifier_from_settings(
            _smtp_settings(email_password_secret="mefor/smtp#password"), secret_provider=provider
        )
    assert provider.calls == ["mefor/smtp#password"]


def test_security_notifier_unresolvable_reference_fails_closed() -> None:
    from messagefoundry.pipeline.security_notify import security_notifier_from_settings

    provider = _FakeProvider({})
    with pytest.raises(SecretProviderError):
        security_notifier_from_settings(
            _smtp_settings(email_password_secret="mefor/smtp#password"), secret_provider=provider
        )
    assert provider.calls == ["mefor/smtp#password"]


def test_notifier_webhook_refusal_is_not_hidden_by_a_secret_store_outage() -> None:
    # Vault BACKLOG #3533 item 18: the webhook URL's checks that log nothing run before the SMTP
    # password is read, so a store that cannot resolve the reference does not hide the cleartext
    # webhook's refusal.
    from messagefoundry.pipeline.alert_sinks import notifier_from_settings

    def settings(url: str) -> AlertsSettings:
        return _smtp_settings(email_password_secret="mefor/smtp#password", webhook_url=url)

    provider = _FakeProvider({})
    # Settings load refuses this URL first (item 14), so the section is built with model_construct
    # to reach the notifier's own refusal, before the SMTP secret read.
    cleartext = AlertsSettings.model_construct(
        **{
            **settings("https://hooks.example/x").model_dump(),
            "webhook_url": "http://hooks.example/x",
        }
    )
    with pytest.raises(ValueError, match="cleartext http"):
        notifier_from_settings(cleartext, secret_provider=provider, posture=_NOT_ENFORCING)
    assert provider.calls == []
    # The control: with an https URL the read is reached, and its failure is what refuses.
    with pytest.raises(SecretProviderError):
        notifier_from_settings(
            settings("https://hooks.example/x"), secret_provider=provider, posture=_NOT_ENFORCING
        )
    assert provider.calls == ["mefor/smtp#password"]


def test_notifiers_reference_without_provider_fail_closed() -> None:
    # A [alerts].email_password_secret reference with no [secrets].provider is a misconfiguration —
    # both notifier entrypoints must fail closed rather than silently fall back to the (blank) literal.
    from messagefoundry.pipeline.alert_sinks import notifier_from_settings
    from messagefoundry.pipeline.security_notify import security_notifier_from_settings

    settings = _smtp_settings(email_password_secret="mefor/smtp#password")
    with pytest.raises(SecretProviderError, match="email_password"):
        notifier_from_settings(settings)  # secret_provider defaults to None
    with pytest.raises(SecretProviderError, match="email_password"):
        security_notifier_from_settings(settings)


@pytest.mark.parametrize("error", [MemoryError, RecursionError])
def test_the_processs_own_limits_pass_the_provider_module_import(
    monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    # Vault BACKLOG #6709 item 11: the dispatch's import arm refused out of memory or stack as a
    # broken install, which its build arm no longer does.
    import importlib

    real_import = importlib.import_module

    def _import(name: str, *args: Any) -> Any:
        if name == "messagefoundry.config.secretprovider_vault":
            raise error()
        return real_import(name, *args)

    monkeypatch.setattr("messagefoundry.config.secretprovider.importlib.import_module", _import)
    with pytest.raises(error):
        resolve_secret_provider(SecretsSettings(provider="vault"))
