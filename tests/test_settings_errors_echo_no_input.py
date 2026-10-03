# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No settings validation error carries the value it refused (BACKLOG #296).

Pydantic gives every error an ``input``. For an ``after``-mode model validator that is the whole
section's input mapping, and for a cross-section check on :class:`ServiceSettings` it is every
section's. ``str(exc)``, ``repr(exc)``, ``exc.errors()`` and ``exc.json()`` all render it, so any
caller that printed or logged a refusal would disclose the secrets that mapping holds. Measured on
PR 1956: an ``http://`` token endpoint echoed the OIDC signing key and its passphrase.

The fix is one wrap around each settings model (``_InputHidingModel``), not a helper at each raise,
so the next plain ``ValueError`` added to a validator stays covered. These tests are written so
they cannot be outrun the same way:

* every case carries every sentinel, in a real secret field where the case allows one and in an
  ignored extra key where it does not, so each case would show a leak of any of them;
* the cases enumerate the refusals in ``_require_ad_fields``, ``_require_oidc_fields`` and the
  ``ServiceSettings`` cross-section checks, plus generic field, type and section-shape errors;
* a sweep refuses every section with a non-mapping value, so a section added later is covered
  without anyone adding a case for it;
* the control runs on a test-only model, so it stays green after the leak is gone.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError, model_validator

from messagefoundry.__main__ import main
from messagefoundry.config import settings as settings_module
from messagefoundry.config.settings import (
    HIDDEN_INPUT,
    AuthSettings,
    ServiceSettings,
    _InputHidingModel,
    _Section,
    load_settings,
    settings_error_detail,
)

#: Split so a secret scanner does not read the fake, keyless PEM bodies below as a key.
_BEGIN = "-----BEGIN "
_KEY = _BEGIN + "PRIVATE KEY-----\nSENTINELKEYBODY0123456789\n-----END PRIVATE KEY-----"
_PASSPHRASE = "SENTINEL-PASSPHRASE-0123456789abcdef"
_CLIENT_SECRET = "SENTINEL-CLIENT-SECRET-0123456789abcdef"
_CERT = _BEGIN + "CERTIFICATE-----\nSENTINELCERTBODY0123456789\n-----END CERTIFICATE-----"
_BIND_PASSWORD = "SENTINEL-BIND-PASSWORD-0123456789abcdef"

#: What a rendering must not contain. Short, distinctive cores: pydantic abbreviates a long
#: ``input_value`` from the middle, so a test for a whole value would miss a leaked tail.
_SENTINELS = (
    "SENTINELKEYBODY",
    "SENTINEL-PASSPHRASE",
    "SENTINEL-CLIENT-SECRET",
    "SENTINELCERTBODY",
    "SENTINEL-BIND-PASSWORD",
)

#: An extra key every section ignores, so a case whose own fields cannot hold a secret still
#: carries all of them in the mapping its refusal is about.
_CARRIER = {"zz_carrier": " ".join((_KEY, _PASSPHRASE, _CLIENT_SECRET, _CERT, _BIND_PASSWORD))}

_PKJWT = "private_key_jwt"


def _auth(method: str = _PKJWT, **over: Any) -> dict[str, Any]:
    """A valid ``[auth]`` with AD and OIDC on, every secret it can hold set to a sentinel."""
    base: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.corp.example",
        "ad_user_search_base": "DC=corp,DC=example",
        "ad_bind_dn": "CN=svc,DC=corp,DC=example",
        "ad_bind_password": _BIND_PASSWORD,
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
        **_CARRIER,
    }
    if method == _PKJWT:
        base.update(
            oidc_token_endpoint_auth_method=_PKJWT,
            oidc_client_private_key=_KEY,
            oidc_client_private_key_password=_PASSPHRASE,
            oidc_client_certificate=_CERT,
            oidc_client_assertion_algorithm="ES256",
        )
    else:
        base["oidc_client_secret"] = _CLIENT_SECRET
    for key, value in over.items():
        if value is _DROP:
            base.pop(key, None)
        else:
            base[key] = value
    return base


_DROP = object()
_SECRET_POST = "client_secret_post"
_POSTGRES = {"backend": "postgres", "server": "db.example", "database": "mf", "username": "svc"}


def _service(auth: dict[str, Any], **sections: dict[str, Any]) -> dict[str, Any]:
    """A fresh ``ServiceSettings`` input; every section mapping also carries the sentinels."""
    data: dict[str, Any] = {"auth": auth, "api": {"public_origin": "https://ops.example"}}
    data.update(sections)
    return {k: {**v, **_CARRIER} if isinstance(v, dict) else v for k, v in data.items()}


#: ``case id -> (the [auth] mapping, the other sections, a fragment of the refusal it must hit)``.
#: The fragment is what keeps a case honest: one that failed for some other reason cannot pass.
_AUTH_CASES: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {
    # _require_ad_fields
    "ad_missing_server": (_auth(ad_server=_DROP), {}, "ad_enabled requires: ad_server"),
    "ad_plain_ldap": (_auth(ad_server="ldap://dc.corp.example"), {}, "requires an ldaps://"),
    "ad_missing_bind_dn": (_auth(ad_bind_dn=_DROP), {}, "a service account: ad_bind_dn"),
    "ad_missing_bind_password": (
        _auth(ad_bind_password=_DROP),
        {},
        "requires a service-account password",
    ),
    "kerberos_without_ad": (
        {"kerberos_enabled": True, "ad_bind_password": _BIND_PASSWORD, **_CARRIER},
        {},
        "kerberos_enabled requires ad_enabled",
    ),
    "recheck_without_ad": (
        {"ad_session_recheck_seconds": 60, "ad_bind_password": _BIND_PASSWORD, **_CARRIER},
        {},
        "ad_session_recheck_seconds requires ad_enabled",
    ),
    # _require_oidc_fields, in the order it refuses
    "oidc_without_ad": (
        _auth(ad_enabled=False, ad_server=_DROP),
        {},
        "oidc_enabled requires ad_enabled",
    ),
    "oidc_missing_endpoint": (_auth(oidc_jwks_uri=" "), {}, "oidc_enabled requires: oidc_jwks_uri"),
    "no_key": (_auth(oidc_client_private_key=_DROP), {}, "NON-EMPTY signing key"),
    "blank_kid": (_auth(oidc_client_assertion_key_id=" "), {}, "assertion_key_id is blank"),
    "blank_certificate": (_auth(oidc_client_certificate="  "), {}, "certificate is set but blank"),
    "blank_key_ref": (_auth(oidc_client_private_key_ref="  "), {}, "key_ref is set but blank"),
    "key_and_ref": (_auth(oidc_client_private_key_ref="kv/mf#oidc-key"), {}, "not both"),
    "secret_beside_key": (
        _auth(oidc_client_secret=_CLIENT_SECRET),
        {},
        "never sends the client secret",
    ),
    "missing_secret": (
        _auth(_SECRET_POST, oidc_client_secret=_DROP),
        {},
        "NON-EMPTY client secret",
    ),
    "blank_secret_ref": (
        _auth(_SECRET_POST, oidc_client_secret_ref="   "),
        {},
        "oidc_client_secret_ref is set but blank",
    ),
    "secret_and_ref": (
        _auth(_SECRET_POST, oidc_client_secret_ref="kv/mf#oidc"),
        {},
        "set oidc_client_secret or oidc_client_secret_ref, not both",
    ),
    "stray_assertion_settings": (
        _auth(_SECRET_POST, oidc_client_private_key_password=_PASSPHRASE),
        {},
        "apply only with",
    ),
    "empty_allow_list": (_auth(oidc_allowed_endpoints=[]), {}, "non-empty oidc_allowed_endpoints"),
    # The reproduction from the PR 1956 review: key and passphrase echoed through this one.
    "http_token_endpoint": (
        _auth(oidc_token_endpoint="http://idp.example/token"),
        {},
        "must be an https URL",
    ),
    "host_not_allowed": (
        _auth(oidc_jwks_uri="https://other.example/jwks"),
        {},
        "is not in oidc_allowed_endpoints",
    ),
    "mfa_gate_never_matches": (
        _auth(oidc_require_mfa_claim=True, oidc_mfa_amr_values=[], oidc_required_acr_values=[]),
        {},
        "oidc_require_mfa_claim=true needs",
    ),
    "acr_requested_unchecked": (
        _auth(oidc_acr_values="urn:mfa"),
        {},
        "nothing checks the acr",
    ),
    "redirect_path": (_auth(oidc_redirect_path="/elsewhere"), {}, "oidc_redirect_path is fixed"),
    "strip_domain_unchecked": (
        _auth(oidc_username_strip_domain=True, ad_domain=_DROP),
        {},
        "requires oidc_allowed_username_domains",
    ),
    "signing_algorithm": (
        _auth(oidc_signing_algorithms=["none"]),
        {},
        "oidc_signing_algorithms must all be supported",
    ),
    # ServiceSettings cross-section checks
    "oidc_without_public_origin": (_auth(), {"api": {}}, "requires an external origin"),
    "plain_ldap_under_enforce": (
        _auth(ad_server="ldap://dc.corp.example", ad_allow_insecure_ldap=True),
        {"security": {"enforcement": "enforce"}},
        "is inert under [security].enforcement = enforce",
    ),
    "allow_list_broad_proxy": (
        _auth(),
        {
            "security": {"allowed_client_networks": ["10.0.0.0/8"]},
            "api": {
                "public_origin": "https://ops.example",
                "trusted_proxies": ["10.0.0.0/24"],
                "tls_terminated_upstream": True,
            },
        },
        "every trusted proxy must be a single host",
    ),
    "cluster_on_sqlite": (_auth(), {"cluster": {"enabled": True}}, "[cluster].enabled requires"),
    "dr_and_cluster": (
        _auth(),
        {"cluster": {"enabled": True}, "dr": {"activate": True}, "store": dict(_POSTGRES)},
        "[dr].activate cannot be combined",
    ),
    # Generic: a type error, a field validator, and a section that is not a mapping.
    "type_error_in_a_field": (
        _auth(ad_connect_timeout=_BIND_PASSWORD),
        {},
        "ad_connect_timeout",
    ),
    "field_validator": (
        _auth(password_extra_context_words='["' + _PASSPHRASE),
        {},
        "does not parse",
    ),
    "section_not_a_mapping": (_auth(), {"store": _CLIENT_SECRET}, "store"),
}


def _renderings(exc: ValidationError) -> list[str]:
    """Every way a caller renders the error, the ``ctx`` included through ``repr(errors())``."""
    return [str(exc), repr(exc), repr(exc.errors()), exc.json(), settings_error_detail(exc)]


def _assert_clean(exc: ValidationError, case: str) -> None:
    for text in _renderings(exc):
        for sentinel in _SENTINELS:
            assert sentinel not in text, (case, sentinel, text)
    for err in exc.errors():
        assert err["input"] == HIDDEN_INPUT, (case, err["loc"])
    # pydantic abbreviates a long input repr from the middle, so a scan of ``str`` alone could miss
    # a leak; every input it renders must be the placeholder.
    text = str(exc)
    assert text.count("input_value=") == text.count(f"input_value={HIDDEN_INPUT!r}"), (case, text)


def _validate_service(case: str) -> ValidationError:
    auth, sections, fragment = _AUTH_CASES[case]
    data = _service(auth, **sections)
    with pytest.raises(ValidationError) as caught:
        ServiceSettings.model_validate(data)
    assert fragment in str(caught.value), (case, str(caught.value))
    return caught.value


@pytest.mark.parametrize("case", sorted(_AUTH_CASES))
def test_a_refusal_nested_in_service_settings_echoes_no_secret(case: str) -> None:
    _assert_clean(_validate_service(case), case)


#: The cases ``AuthSettings`` refuses on its own, without another section.
_DIRECT_CASES = sorted(
    case
    for case, (_, sections, _) in _AUTH_CASES.items()
    if not sections and case != "section_not_a_mapping"
)


@pytest.mark.parametrize("case", _DIRECT_CASES)
def test_a_refusal_from_auth_settings_directly_echoes_no_secret(case: str) -> None:
    auth, _, fragment = _AUTH_CASES[case]
    with pytest.raises(ValidationError, match=fragment.replace("[", r"\[")) as caught:
        AuthSettings.model_validate(auth)
    _assert_clean(caught.value, case)
    with pytest.raises(ValidationError) as constructed:
        AuthSettings(**auth)
    _assert_clean(constructed.value, case)


def _section_models() -> dict[str, type[BaseModel]]:
    out: dict[str, type[BaseModel]] = {}
    for name, field in ServiceSettings.model_fields.items():
        assert isinstance(field.annotation, type), name
        out[name] = field.annotation
    return out


@pytest.mark.parametrize("section", sorted(_section_models()))
def test_every_section_refuses_a_non_mapping_without_echoing_it(section: str) -> None:
    """The sweep that covers a section added later, with no case written for it."""
    model = _section_models()[section]
    assert issubclass(model, _InputHidingModel), section
    with pytest.raises(ValidationError) as direct:
        model.model_validate(_CLIENT_SECRET)
    _assert_clean(direct.value, section)
    with pytest.raises(ValidationError) as nested:
        ServiceSettings.model_validate({section: _CLIENT_SECRET})
    _assert_clean(nested.value, section)


#: Settings-module models that validate on their own and are not settings sections. Each is nested
#: under a section, whose wrap hides its errors there; validated directly (the ``alert`` command)
#: it refuses JSON the operator just typed, and echoing that back is that command's question.
_NOT_SECTIONS = {"AlertRule", "EscalationTier"}


def test_every_settings_model_hides_its_input() -> None:
    """A new model in the settings module is either input-hiding or named here with its reason."""
    models = {
        name
        for name, obj in vars(settings_module).items()
        if inspect.isclass(obj)
        and issubclass(obj, BaseModel)
        and obj.__module__ == settings_module.__name__
    }
    assert {"AuthSettings", "ServiceSettings"} <= models  # the control: the walk found models
    hiding = {
        name for name in models if issubclass(getattr(settings_module, name), _InputHidingModel)
    }
    assert models - hiding == _NOT_SECTIONS


# --- the control, on test-only models so it outlives the leak -------------------------------------


class _Echoing(BaseModel):
    secret: str = ""

    @model_validator(mode="after")
    def _refuse(self) -> _Echoing:
        raise ValueError("refused")


class _Hiding(_Section):
    secret: str = ""

    @model_validator(mode="after")
    def _refuse(self) -> _Hiding:
        raise ValueError("refused")


class _PlainOuter(BaseModel):
    inner: _Hiding


@pytest.mark.parametrize(
    ("validate", "echoes"),
    [
        # Short, so pydantic's middle abbreviation of a long input repr cannot hide it from ``str``.
        pytest.param(lambda: _Echoing(secret="SENTINEL-CLIENT-SECRET"), True, id="plain-model"),
        pytest.param(lambda: _Hiding(secret=_CLIENT_SECRET), False, id="hiding-model"),
        pytest.param(
            lambda: _PlainOuter.model_validate({"inner": {"secret": _CLIENT_SECRET}}),
            False,
            id="hiding-model-nested-in-a-plain-one",
        ),
    ],
)
def test_the_sentinel_scan_can_fail(validate: Callable[[], object], echoes: bool) -> None:
    """A plain model's refusal DOES carry the sentinel in every rendering, so the scans above are
    live, and the same refusal through ``_InputHidingModel`` does not, nested or not."""
    with pytest.raises(ValidationError) as caught:
        validate()
    renderings = _renderings(caught.value)
    found = ["SENTINEL-CLIENT-SECRET" in text for text in renderings]
    assert found[:4] == [echoes] * 4, found
    assert "refused" in renderings[0]


def test_the_error_keeps_its_location_type_message_and_ctx() -> None:
    """Hiding the input loses nothing else an operator or a caller reads."""
    with pytest.raises(ValidationError) as caught:
        ServiceSettings.model_validate({"auth": {"ad_connect_timeout": "soon"}})
    (err,) = caught.value.errors()
    assert err["loc"] == ("auth", "ad_connect_timeout")
    assert err["type"] == "float_parsing"
    assert "valid number" in err["msg"]
    with pytest.raises(ValidationError) as refused:
        AuthSettings.model_validate({"password_extra_context_words": '["acme",'})
    ctx = refused.value.errors()[0]["ctx"]
    assert isinstance(ctx["error"], ValueError)


# --- through load_settings and the CLI ----------------------------------------------------------


def _env(**over: str) -> dict[str, str]:
    env = {
        "MEFOR_AUTH_AD_ENABLED": "true",
        "MEFOR_AUTH_AD_SERVER": "ldaps://dc.corp.example",
        "MEFOR_AUTH_AD_USER_SEARCH_BASE": "DC=corp,DC=example",
        "MEFOR_AUTH_AD_BIND_DN": "CN=svc,DC=corp,DC=example",
        "MEFOR_AUTH_AD_BIND_PASSWORD": _BIND_PASSWORD,
        "MEFOR_AUTH_AD_DOMAIN": "corp.example",
        "MEFOR_AUTH_OIDC_ENABLED": "true",
        "MEFOR_AUTH_OIDC_ISSUER": "https://idp.example",
        "MEFOR_AUTH_OIDC_CLIENT_ID": "mefor-console",
        "MEFOR_AUTH_OIDC_AUTHORIZATION_ENDPOINT": "https://idp.example/authorize",
        "MEFOR_AUTH_OIDC_TOKEN_ENDPOINT": "https://idp.example/token",
        "MEFOR_AUTH_OIDC_JWKS_URI": "https://idp.example/jwks",
        "MEFOR_AUTH_OIDC_ALLOWED_ENDPOINTS": "idp.example",
        "MEFOR_AUTH_OIDC_TOKEN_ENDPOINT_AUTH_METHOD": _PKJWT,
        "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY": _KEY,
        "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY_PASSWORD": _PASSPHRASE,
        "MEFOR_AUTH_OIDC_CLIENT_CERTIFICATE": _CERT,
        "MEFOR_AUTH_OIDC_CLIENT_ASSERTION_ALGORITHM": "ES256",
        "MEFOR_SECURITY_WEB_CONSOLE_PUBLIC_ADDRESS": "https://ops.example",
    }
    env.update(over)
    return env


@pytest.mark.parametrize(
    ("over", "fragment"),
    [
        pytest.param(
            {"MEFOR_AUTH_OIDC_TOKEN_ENDPOINT": "http://idp.example/token"},
            "must be an https URL",
            id="http-token-endpoint",
        ),
        pytest.param(
            {"MEFOR_AUTH_OIDC_CLIENT_ASSERTION_KEY_ID": " "},
            "assertion_key_id is blank",
            id="blank-kid",
        ),
        pytest.param(
            {
                "MEFOR_AUTH_OIDC_TOKEN_ENDPOINT_AUTH_METHOD": _SECRET_POST,
                "MEFOR_AUTH_OIDC_CLIENT_SECRET": _CLIENT_SECRET,
            },
            "apply only with",
            id="stray-assertion-settings",
        ),
        pytest.param({"MEFOR_CLUSTER_ENABLED": "true"}, "[cluster].enabled", id="cross-section"),
    ],
)
def test_a_refusal_through_load_settings_echoes_no_secret(
    over: dict[str, str], fragment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Env vars, as NSSM passes them, in a directory with no ``messagefoundry.toml`` to read."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValidationError) as caught:
        load_settings(environ=_env(**over))
    assert fragment in str(caught.value)
    _assert_clean(caught.value, fragment)


def test_a_cli_command_that_prints_str_exc_echoes_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``audit-verify`` prints ``str(exc)`` for a settings failure, not ``settings_error_detail``.

    ``serve`` and ``supervise`` render through ``settings_error_detail`` already; commands like this
    one were the remaining exposure, and the model-level wrap is what covers them.
    """
    monkeypatch.chdir(tmp_path)
    for name, value in _env(MEFOR_AUTH_OIDC_TOKEN_ENDPOINT="http://idp.example/token").items():
        monkeypatch.setenv(name, value)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("", encoding="utf-8")

    assert main(["audit-verify", "--service-config", str(cfg)]) == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "must be an https URL" in output  # the control: this run reached the refusal
    for sentinel in _SENTINELS:
        assert sentinel not in output, sentinel
